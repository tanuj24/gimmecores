//! Grant requests that wait for the lender's owner without holding up the borrower (#23).
//!
//! `gmc grants request --no-wait` (and `RequestGrant` with `no_wait`) sends the request with
//! `queue` set. The lender keeps it for its owner for up to a day and says so at once
//! (`GrantQueued`); its owner sees it like any request. When the owner answers (or nobody
//! does), the lender sends the answer to the borrower if it can reach it, and keeps it for a
//! day for the borrower to ask about (`GrantPoll`, every minute while it waits). The borrower
//! keeps its waiting requests in `requests.json` (owner-only), so they survive a restart; the
//! lender keeps them in memory only, so after a lender restart the borrower is told to ask
//! again. Lenders older than this (0.1.0) would hold such a request open and answer nobody, so
//! the borrower does not send one to them.

use anyhow::{Context, Result, bail};
use gimmecores_core::{PeerKey, TrustLevel, UnixSeconds};
use gimmecores_proto::peer::v1 as pb;
use gimmecores_proto::peer::v1::peer_message::Body;
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::grants_flow::{GrantOutcome, verify_signed};
use crate::node::Node;
use crate::{now, wire};

/// The first version that keeps queued requests.
const QUEUE_SINCE: (u64, u64, u64) = (0, 1, 1);

/// A request a lender keeps for its owner.
#[derive(Clone, Debug)]
pub struct Waiting {
    pub lender: PeerKey,
    pub request: pb::GrantRequest,
    pub asked_at: UnixSeconds,
    pub expires_at: UnixSeconds,
}

#[derive(Serialize, Deserialize)]
struct Saved {
    lender: String,
    request: String,
    asked_at: UnixSeconds,
    expires_at: UnixSeconds,
}

/// "0.1.1 (abc1234 2026-11-16)" as (0, 1, 1).
fn semver(v: &str) -> Option<(u64, u64, u64)> {
    let mut parts = v.split_whitespace().next()?.split('.');
    Some((
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.split('-').next()?.parse().ok()?,
    ))
}

fn trust_of(req: &pb::GrantRequest) -> TrustLevel {
    if req.trust == pb::TrustLevel::Trusted as i32 {
        TrustLevel::Trusted
    } else {
        TrustLevel::Standard
    }
}

impl Node {
    /// Refuses to queue a request with a lender that cannot keep it.
    pub(crate) fn ensure_can_queue(&self, lender: &PeerKey) -> Result<()> {
        let v = self.peer_version(lender).map(|v| v.0);
        match v.as_deref().and_then(semver) {
            Some(have) if have >= QUEUE_SINCE => Ok(()),
            _ => bail!(
                "{:?} runs GimmeCores {}, which cannot keep a request for later: ask without \
                 --no-wait, or update it",
                self.peer_name(lender),
                v.unwrap_or_else(|| "older than 0.1.1".into())
            ),
        }
    }

    /// The lender keeps `req` for its owner: remember it (saved) and say so.
    pub(crate) fn now_waiting(
        &self,
        lender: &PeerKey,
        req: pb::GrantRequest,
        q: &pb::GrantQueued,
    ) -> Result<GrantOutcome> {
        let expires_at = q
            .expires_at
            .and_then(|t| u64::try_from(t.seconds).ok())
            .unwrap_or(now() + crate::grants_flow::QUEUE_TIMEOUT.as_secs());
        let request_id = req.request_id.clone();
        self.state().waiting.insert(
            request_id.clone(),
            Waiting {
                lender: *lender,
                request: req,
                asked_at: now(),
                expires_at,
            },
        );
        self.save_waiting();
        self.audit_best_effort(
            "grant",
            Some(lender),
            format!(
                "asked {} without waiting; kept for its owner",
                self.peer_name(lender)
            ),
            serde_json::json!({ "request": hex::encode(&request_id) }),
        );
        Ok(GrantOutcome::Queued {
            request_id,
            expires_at,
        })
    }

    /// Requests this device is waiting on.
    pub fn waiting_requests(&self) -> Vec<Waiting> {
        self.state().waiting.values().cloned().collect()
    }

    /// Takes the answer to waiting request `request_id` from `lender`: the grant is kept, or the
    /// request is forgotten; both are audited.
    async fn settle(&self, lender: &PeerKey, request_id: &[u8], answer: Body) {
        let Some(w) = self.state().waiting.remove(request_id) else {
            return;
        };
        self.save_waiting();
        let name = self.peer_name(lender);
        let what = match self
            .receive_answer(lender, trust_of(&w.request), answer)
            .await
        {
            Ok(GrantOutcome::Granted { .. }) => format!("{name} accepted the request it kept"),
            Ok(GrantOutcome::Declined(why)) => format!("{name} declined the request: {why}"),
            Ok(GrantOutcome::NoAnswer) => format!("{name}'s owner did not answer the request"),
            Ok(GrantOutcome::Queued { .. }) => return,
            Err(e) => format!("{name}'s answer could not be used: {e:#}"),
        };
        self.audit_best_effort(
            "grant",
            Some(lender),
            what,
            serde_json::json!({ "request": hex::encode(request_id) }),
        );
    }

    /// A lender sent the answer to one of this device's waiting requests.
    pub(crate) async fn handle_pushed_answer(&self, lender: PeerKey, body: Body) {
        let request_id = match &body {
            Body::GrantOffer(o) => o
                .grant
                .as_ref()
                .and_then(|g| verify_signed(g, &lender, &self.key()).ok())
                .map(|g| g.request_id),
            Body::GrantDecline(d) => Some(d.request_id.clone()),
            _ => None,
        };
        let Some(request_id) = request_id else { return };
        let ours = self
            .state()
            .waiting
            .get(&request_id)
            .is_some_and(|w| w.lender == lender);
        if ours {
            self.settle(&lender, &request_id, body).await;
        }
    }

    /// Asks each lender about the requests it keeps for this device (every minute), and
    /// forgets those that lapsed. Returns how many were settled.
    pub async fn poll_waiting(&self) -> usize {
        let t = now();
        let mut settled = 0;
        let list: Vec<(Vec<u8>, Waiting)> = self
            .state()
            .waiting
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (request_id, w) in list {
            if t > w.expires_at + 120 {
                self.state().waiting.remove(&request_id);
                self.save_waiting();
                self.audit_best_effort(
                    "grant",
                    Some(&w.lender),
                    format!(
                        "{}'s owner did not answer the request in time",
                        self.peer_name(&w.lender)
                    ),
                    serde_json::json!({ "request": hex::encode(&request_id) }),
                );
                settled += 1;
                continue;
            }
            let ask = async {
                let conn = self.dial(&w.lender).await?;
                let (mut send, mut recv) = conn.open_bi().await?;
                wire::send(
                    &mut send,
                    Body::GrantPoll(pb::GrantPoll {
                        request_id: request_id.clone(),
                    }),
                )
                .await?;
                send.finish()?;
                anyhow::Ok(wire::recv(&mut recv).await?)
            };
            match tokio::time::timeout(std::time::Duration::from_secs(10), ask).await {
                Ok(Ok(Body::GrantQueued(_))) => {}
                Ok(Ok(answer @ (Body::GrantOffer(_) | Body::GrantDecline(_)))) => {
                    self.settle(&w.lender, &request_id, answer).await;
                    settled += 1;
                }
                _ => {}
            }
        }
        settled
    }

    pub(crate) fn save_waiting(&self) {
        let saved: Vec<Saved> = self
            .state()
            .waiting
            .values()
            .map(|w| Saved {
                lender: w.lender.to_hex(),
                request: hex::encode(w.request.encode_to_vec()),
                asked_at: w.asked_at,
                expires_at: w.expires_at,
            })
            .collect();
        let write = || -> Result<()> {
            crate::fsutil::write_private(
                &self.paths().requests_file(),
                &serde_json::to_vec_pretty(&saved)?,
            )
        };
        if let Err(e) = write() {
            tracing::warn!("could not save waiting requests: {e:#}");
        }
    }

    /// Reads the requests this device was waiting on before it restarted (lapsed ones and
    /// those to devices no longer paired are dropped).
    pub(crate) fn load_waiting(&self) -> Result<()> {
        let path = self.paths().requests_file();
        if !path.exists() {
            return Ok(());
        }
        crate::fsutil::check_private(&path)?;
        let saved: Vec<Saved> = serde_json::from_slice(&std::fs::read(&path)?)?;
        let t = now();
        let mut s = self.state();
        for w in saved {
            let lender = PeerKey(
                hex::decode(&w.lender)?
                    .try_into()
                    .ok()
                    .context("bad lender key in requests.json")?,
            );
            if w.expires_at + 120 < t || !s.trust.is_paired(&lender) {
                continue;
            }
            let request = pb::GrantRequest::decode(hex::decode(&w.request)?.as_slice())?;
            s.waiting.insert(
                request.request_id.clone(),
                Waiting {
                    lender,
                    request,
                    asked_at: w.asked_at,
                    expires_at: w.expires_at,
                },
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_by_number() {
        assert_eq!(semver("0.1.1 (abc1234 2026-11-16)"), Some((0, 1, 1)));
        assert_eq!(semver("0.1.0"), Some((0, 1, 0)));
        assert_eq!(semver("0.10.2-beta"), Some((0, 10, 2)));
        assert!(semver("0.1.0").unwrap() < QUEUE_SINCE);
        assert!(semver("0.2.0").unwrap() > QUEUE_SINCE);
        assert_eq!(semver("garbage"), None);
    }
}
