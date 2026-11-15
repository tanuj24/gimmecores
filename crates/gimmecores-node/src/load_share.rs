//! A lender's whole-machine load, for the devices it lends to (docs/design/activity.md, stage 3).
//!
//! It tells a borrower when the lender's owner is using their computer, so it is the owner's
//! choice: off unless they turn it on (which needs presence), answered only to a device that
//! holds a live grant from them, numbers only (no programs, no other borrowers' tasks), and the
//! machine reads itself at most about once a second however many ask. On the borrower every
//! figure is the lender's claim, bounded on arrival, and asked for only while a listing is
//! being read.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use gimmecores_core::{GrantId, GrantState, PeerKey};
use gimmecores_proto::local::v1 as api;
use gimmecores_proto::peer::v1 as pb;
use gimmecores_proto::peer::v1::peer_message::Body;
use iroh::endpoint::SendStream;

use crate::node::Node;
use crate::node::PresenceRefused;
use crate::wire;

/// A borrower asks a lender again once its last answer is this old (while a listing is read).
pub const ASK_AGAIN_AFTER: Duration = Duration::from_secs(2);
/// An answer older than this is not shown.
pub const SHOW_FOR: Duration = Duration::from_secs(10);
/// How long a listing waits for the first answer from a lender it has none from yet.
pub const FIRST_ANSWER_WAIT: Duration = Duration::from_millis(1500);
/// GPUs reported at most.
const MAX_GPUS: usize = 8;
/// Larger than any real machine: figures beyond these are not believed.
const MAX_CORES: u32 = 4096;
const MAX_BYTES: u64 = 1 << 46;

/// Bounds a lender's answer: impossible figures are dropped, names cleaned and cut.
pub fn accept_load(r: &pb::LoadReport) -> api::LenderLoad {
    if !r.shared {
        return api::LenderLoad {
            shared: false,
            ..Default::default()
        };
    }
    let cores = if (1..=MAX_CORES).contains(&r.cpu_cores) {
        r.cpu_cores
    } else {
        0
    };
    let total = if r.memory_total_bytes <= MAX_BYTES {
        r.memory_total_bytes
    } else {
        0
    };
    api::LenderLoad {
        shared: true,
        cpu_cores: cores,
        cpu_busy_millis: r
            .cpu_busy_millis
            .filter(|b| cores > 0 && *b <= cores.saturating_mul(1000)),
        memory_total_bytes: total,
        memory_used_bytes: r.memory_used_bytes.filter(|u| total > 0 && *u <= total),
        gpus: r
            .gpus
            .iter()
            .take(MAX_GPUS)
            .map(|g| api::GpuLoad {
                name: {
                    let n = wire::clean_text(&g.name, 64).trim().to_string();
                    if n.is_empty() { "GPU".into() } else { n }
                },
                kind: pb::GpuKind::Unspecified as i32,
                memory_bytes: 0,
                busy_percent: g.busy_percent.filter(|p| *p <= 100),
            })
            .collect(),
        age_ms: 0,
    }
}

impl Node {
    pub fn share_load(&self) -> bool {
        self.state().share_load
    }

    /// Lets devices holding a live grant from this one see how busy this whole computer is
    /// (saved, audited). Turning it on needs presence; turning it off never does.
    pub async fn set_share_load(&self, enabled: bool) -> Result<(), PresenceRefused> {
        if enabled && !self.share_load() {
            self.require_presence("let devices you lend to see how busy this whole computer is")
                .await?;
        }
        {
            let mut s = self.state();
            s.share_load = enabled;
            self.save_settings(&s)
                .map_err(|e| PresenceRefused::Unavailable(format!("{e:#}")))?;
        }
        self.audit_best_effort(
            "lending",
            None,
            if enabled {
                "devices with a grant may now see how busy this computer is".to_string()
            } else {
                "devices no longer see how busy this computer is".to_string()
            },
            serde_json::json!({ "share_load": enabled }),
        );
        Ok(())
    }

    /// As the lender: figures only if the owner shares them and `remote` holds `grant`, live.
    pub(crate) async fn handle_load_request(
        &self,
        remote: PeerKey,
        req: pb::LoadRequest,
        mut send: SendStream,
    ) -> Result<()> {
        let allowed = <[u8; 16]>::try_from(req.grant_id.as_slice())
            .ok()
            .is_some_and(|id| {
                let id = GrantId(id);
                let s = self.state();
                s.share_load
                    && s.grants.borrower(id) == Some(remote)
                    && matches!(
                        s.grants.state(id),
                        Some(GrantState::Active | GrantState::Paused)
                    )
                    && s.grants
                        .terms(id)
                        .is_some_and(|t| t.not_after > crate::now())
            });
        let report = if allowed {
            let load = self.inner.machine.sample().await;
            pb::LoadReport {
                shared: true,
                cpu_cores: load.cpu_cores,
                cpu_busy_millis: load.cpu_busy_millis,
                memory_total_bytes: load.memory_total_bytes,
                memory_used_bytes: load.memory_used_bytes,
                gpus: load
                    .gpus
                    .into_iter()
                    .map(|(g, busy)| pb::GpuBusy {
                        name: g.name,
                        busy_percent: busy,
                    })
                    .collect(),
            }
        } else {
            pb::LoadReport {
                shared: false,
                ..Default::default()
            }
        };
        wire::send(&mut send, Body::LoadReport(report)).await?;
        send.finish()?;
        Ok(())
    }

    /// As the borrower: one question to the lender of `grant`.
    async fn ask_load(&self, lender: PeerKey, grant: GrantId) -> Result<pb::LoadReport> {
        let conn = self.dial(&lender).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        wire::send(
            &mut send,
            Body::LoadRequest(pb::LoadRequest {
                grant_id: grant.0.to_vec(),
            }),
        )
        .await?;
        send.finish()?;
        match wire::recv(&mut recv).await.context("no answer")? {
            Body::LoadReport(r) => Ok(r),
            _ => bail!("unexpected answer"),
        }
    }

    /// Asks each lender whose last answer is old (one question per lender at a time), and
    /// waits a little for lenders never heard from, so a one-off listing shows them too.
    pub async fn refresh_lender_loads(&self) {
        let mut first = tokio::task::JoinSet::new();
        let due: Vec<(GrantId, PeerKey, bool)> = {
            let mut s = self.state();
            let grants: Vec<(GrantId, PeerKey)> =
                s.borrowed.iter().map(|(g, b)| (*g, b.lender)).collect();
            let mut due = Vec::new();
            for (grant, lender) in grants {
                let last = s.lender_loads.get(&grant).map(|(at, _)| *at);
                if last.is_some_and(|at| at.elapsed() < ASK_AGAIN_AFTER)
                    || !s.load_asking.insert(grant)
                {
                    continue;
                }
                due.push((grant, lender, last.is_none()));
            }
            due
        };
        for (grant, lender, never) in due {
            let node = self.clone();
            let ask = async move {
                let answer =
                    tokio::time::timeout(Duration::from_secs(5), node.ask_load(lender, grant))
                        .await;
                let mut s = node.state();
                s.load_asking.remove(&grant);
                // An older lender, or unreachable: nothing new to show.
                if let Ok(Ok(r)) = answer {
                    s.lender_loads
                        .insert(grant, (Instant::now(), accept_load(&r)));
                }
            };
            if never {
                first.spawn(ask);
            } else {
                tokio::spawn(ask);
            }
        }
        let _ = tokio::time::timeout(FIRST_ANSWER_WAIT, async {
            while first.join_next().await.is_some() {}
        })
        .await;
        // Unfinished first questions keep running and fill the next listing.
        first.detach_all();
    }

    /// The last answer about `grant`, if recent enough to show.
    pub(crate) fn lender_load(s: &crate::node::State, grant: GrantId) -> Option<api::LenderLoad> {
        let (at, load) = s.lender_loads.get(&grant)?;
        let age = at.elapsed();
        (age <= SHOW_FOR).then(|| api::LenderLoad {
            age_ms: u64::try_from(age.as_millis()).unwrap_or(u64::MAX),
            ..load.clone()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lenders_load_is_bounded() {
        let honest = pb::LoadReport {
            shared: true,
            cpu_cores: 12,
            cpu_busy_millis: Some(9_800),
            memory_total_bytes: 32 << 30,
            memory_used_bytes: Some(20 << 30),
            gpus: vec![pb::GpuBusy {
                name: "Apple M2 Max".into(),
                busy_percent: Some(12),
            }],
        };
        let l = accept_load(&honest);
        assert!(l.shared);
        assert_eq!((l.cpu_cores, l.cpu_busy_millis), (12, Some(9_800)));
        assert_eq!(l.memory_used_bytes, Some(20 << 30));
        assert_eq!(l.gpus[0].name, "Apple M2 Max");
        assert_eq!(l.gpus[0].busy_percent, Some(12));

        let lie = pb::LoadReport {
            shared: true,
            cpu_cores: u32::MAX,
            cpu_busy_millis: Some(u32::MAX),
            memory_total_bytes: u64::MAX,
            memory_used_bytes: Some(u64::MAX),
            gpus: (0..100)
                .map(|_| pb::GpuBusy {
                    name: format!("\u{202e}evil\u{1b}[2J{}", "x".repeat(500)),
                    busy_percent: Some(1000),
                })
                .collect(),
        };
        let l = accept_load(&lie);
        assert_eq!((l.cpu_cores, l.cpu_busy_millis), (0, None));
        assert_eq!((l.memory_total_bytes, l.memory_used_bytes), (0, None));
        assert_eq!(l.gpus.len(), MAX_GPUS);
        let name = &l.gpus[0].name;
        assert!(
            name.chars().count() <= 64 && !name.contains('\u{202e}') && !name.contains('\u{1b}')
        );
        assert_eq!(l.gpus[0].busy_percent, None);
        // More busy than it has cores, more used than it has: not believed.
        let l = accept_load(&pb::LoadReport {
            cpu_busy_millis: Some(13_000),
            memory_used_bytes: Some(33 << 30),
            ..honest.clone()
        });
        assert_eq!((l.cpu_busy_millis, l.memory_used_bytes), (None, None));
        // Not shared: nothing else is kept, whatever came with it.
        let l = accept_load(&pb::LoadReport {
            shared: false,
            ..honest
        });
        assert!(!l.shared);
        assert_eq!((l.cpu_cores, l.cpu_busy_millis, l.gpus.len()), (0, None, 0));
    }
}
