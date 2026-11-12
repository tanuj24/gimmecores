//! Grants over the network (docs/design/consent-and-grants.md).
//!
//! The borrower sends `GrantRequest` and waits on the same stream. The lender records it in its
//! grant book and waits for its user. On accept, the lender signs the grant and replies with
//! `GrantOffer { final: true }`; on decline or timeout it replies `GrantDecline`.
//!
//! v1 simplification: the lender may accept as asked or with *reduced* terms (never more than
//! requested), so no second round-trip for borrower approval is needed.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use gimmecores_core::{
    Gpu, GrantId, GrantState, GrantTerms, Limits, NetworkPolicy, PeerKey, TaskId, TrustLevel,
    UnixSeconds,
};
use gimmecores_proto::peer::v1 as pb;
use gimmecores_proto::peer::v1::peer_message::Body;
use iroh::endpoint::SendStream;
use prost::Message;
use tokio::sync::oneshot;

use crate::node::Node;
use crate::{now, wire};

const SIGNATURE_LABEL: &[u8] = b"gimmecores-grant-v1";
/// How long a request waits for the lender's user.
pub const DECISION_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// The lender user's answer.
#[derive(Debug, Clone)]
pub enum Decision {
    /// Accept as requested, or with reduced terms.
    Accept(Option<GrantTerms>),
    Decline(String),
}

pub(crate) struct Pending {
    pub borrower: PeerKey,
    pub requested: GrantTerms,
    pub reason: String,
    pub decide: Option<oneshot::Sender<Decision>>,
}

/// A grant another device gave this one.
#[derive(Clone, Debug)]
pub struct Borrowed {
    pub lender: PeerKey,
    pub terms: GrantTerms,
    pub signed: pb::SignedGrant,
}

/// What the lender's UI shows for an incoming request.
#[derive(Clone, Debug)]
pub struct RequestView {
    pub id: GrantId,
    pub borrower: PeerKey,
    pub borrower_name: String,
    pub requested: GrantTerms,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub enum GrantOutcome {
    Granted { id: GrantId, terms: GrantTerms },
    Declined(String),
}

// ---------------------------------------------------------------------- conversions

fn gpu_to(g: Gpu) -> i32 {
    match g {
        Gpu::None => pb::GpuKind::None as i32,
        Gpu::Cuda => pb::GpuKind::Cuda as i32,
        Gpu::Metal => pb::GpuKind::Metal as i32,
    }
}

fn gpu_from(v: i32) -> Gpu {
    match pb::GpuKind::try_from(v) {
        Ok(pb::GpuKind::Cuda) => Gpu::Cuda,
        Ok(pb::GpuKind::Metal) => Gpu::Metal,
        _ => Gpu::None,
    }
}

fn limits_to(l: &Limits) -> pb::Limits {
    pb::Limits {
        cpu_millis: l.cpu_millis,
        memory_bytes: l.memory_bytes,
        disk_bytes: l.disk_bytes,
        gpu: gpu_to(l.gpu),
        max_concurrent_tasks: l.max_concurrent_tasks,
    }
}

fn limits_from(l: Option<&pb::Limits>) -> Result<Limits> {
    let l = l.context("missing limits")?;
    Ok(Limits {
        cpu_millis: l.cpu_millis,
        memory_bytes: l.memory_bytes,
        disk_bytes: l.disk_bytes,
        gpu: gpu_from(l.gpu),
        max_concurrent_tasks: l.max_concurrent_tasks,
    })
}

fn modes_to(allow_native: bool) -> Vec<i32> {
    let mut m = vec![pb::ExecutionMode::Container as i32];
    if allow_native {
        m.push(pb::ExecutionMode::Native as i32);
    }
    m
}

fn network_to(n: NetworkPolicy) -> i32 {
    match n {
        NetworkPolicy::None => pb::NetworkPolicy::None as i32,
        NetworkPolicy::Internet => pb::NetworkPolicy::Internet as i32,
    }
}

fn network_from(v: i32) -> NetworkPolicy {
    if v == pb::NetworkPolicy::Internet as i32 {
        NetworkPolicy::Internet
    } else {
        NetworkPolicy::None
    }
}

fn trust_to(t: TrustLevel) -> i32 {
    match t {
        TrustLevel::Standard => pb::TrustLevel::Standard as i32,
        TrustLevel::Trusted => pb::TrustLevel::Trusted as i32,
    }
}

fn trust_from(v: i32) -> TrustLevel {
    if v == pb::TrustLevel::Trusted as i32 {
        TrustLevel::Trusted
    } else {
        TrustLevel::Standard
    }
}

fn ts(secs: UnixSeconds) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: i64::try_from(secs).unwrap_or(i64::MAX),
        nanos: 0,
    }
}

fn secs(t: Option<&prost_types::Timestamp>) -> Result<UnixSeconds> {
    let t = t.context("missing timestamp")?;
    u64::try_from(t.seconds).context("negative timestamp")
}

/// Builds the request a borrower sends.
pub fn request_proto(
    terms: &GrantTerms,
    reason: &str,
    now: UnixSeconds,
) -> Result<pb::GrantRequest> {
    ensure!(terms.not_after > now, "expiry must be in the future");
    Ok(pb::GrantRequest {
        request_id: wire::random32()?[..16].to_vec(),
        limits: Some(limits_to(&terms.limits)),
        modes: modes_to(terms.allow_native),
        network: network_to(terms.network),
        duration: Some(prost_types::Duration {
            seconds: i64::try_from(terms.not_after - now)?,
            nanos: 0,
        }),
        trust: trust_to(terms.trust),
        reason: reason.chars().take(280).collect(),
    })
}

pub fn terms_from_request(req: &pb::GrantRequest, now: UnixSeconds) -> Result<GrantTerms> {
    let d = req.duration.as_ref().context("missing duration")?;
    let d = u64::try_from(d.seconds).context("negative duration")?;
    Ok(GrantTerms {
        limits: limits_from(req.limits.as_ref())?,
        not_after: now.saturating_add(d),
        allow_native: req.modes.contains(&(pb::ExecutionMode::Native as i32)),
        network: network_from(req.network),
        trust: trust_from(req.trust),
    })
}

pub fn terms_from_grant(g: &pb::Grant) -> Result<GrantTerms> {
    Ok(GrantTerms {
        limits: limits_from(g.limits.as_ref())?,
        not_after: secs(g.not_after.as_ref())?,
        allow_native: g.modes.contains(&(pb::ExecutionMode::Native as i32)),
        network: network_from(g.network),
        trust: trust_from(g.trust),
    })
}

/// `offered` never grants more than `asked` (v1 reduce-only acceptance).
pub fn within(offered: &GrantTerms, asked: &GrantTerms) -> bool {
    let (o, a) = (&offered.limits, &asked.limits);
    o.cpu_millis <= a.cpu_millis
        && o.memory_bytes <= a.memory_bytes
        && o.disk_bytes <= a.disk_bytes
        && o.max_concurrent_tasks <= a.max_concurrent_tasks
        && (o.gpu == a.gpu || o.gpu == Gpu::None)
        && offered.not_after <= asked.not_after
        && (!offered.allow_native || asked.allow_native)
        && (offered.network == NetworkPolicy::None || asked.network == NetworkPolicy::Internet)
        && (offered.trust == TrustLevel::Standard || asked.trust == TrustLevel::Trusted)
}

/// Verifies a signed grant from `lender` issued to `me`; returns the decoded grant.
pub fn verify_signed(
    signed: &pb::SignedGrant,
    lender: &PeerKey,
    me: &PeerKey,
) -> Result<pb::Grant> {
    let pk = iroh::PublicKey::from_bytes(&lender.0)?;
    let sig = iroh::Signature::try_from(signed.signature.as_slice())
        .map_err(|_| anyhow!("malformed signature"))?;
    pk.verify(&[SIGNATURE_LABEL, &signed.grant].concat(), &sig)
        .map_err(|_| anyhow!("grant signature is invalid"))?;
    let grant = pb::Grant::decode(signed.grant.as_slice())?;
    ensure!(
        grant.lender_key == lender.0,
        "grant was not issued by this lender"
    );
    ensure!(
        grant.borrower_key == me.0,
        "grant was issued to a different device"
    );
    Ok(grant)
}

fn grant_id(bytes: &[u8]) -> Result<GrantId> {
    Ok(GrantId(
        bytes
            .try_into()
            .map_err(|_| anyhow!("grant id must be 16 bytes"))?,
    ))
}

impl Node {
    // ------------------------------------------------------------------ lender side

    pub(crate) async fn handle_grant_request(
        &self,
        borrower: PeerKey,
        req: pb::GrantRequest,
        mut send: SendStream,
    ) -> Result<()> {
        let t = now();
        if !self.lending_enabled() {
            return decline(
                &mut send,
                &req.request_id,
                "lending is turned off on that device",
            )
            .await;
        }
        let id = grant_id(&wire::random32()?[..16])?;
        let requested = match terms_from_request(&req, t) {
            Ok(terms) => terms,
            Err(e) => return decline(&mut send, &req.request_id, &e.to_string()).await,
        };
        let (tx, rx) = oneshot::channel();
        let recorded = {
            let mut s = self.state();
            let r = s.grants.request(id, borrower, requested.clone(), t);
            if r.is_ok() {
                s.incoming.insert(
                    id,
                    Pending {
                        borrower,
                        requested: requested.clone(),
                        reason: req
                            .reason
                            .chars()
                            .filter(|c| !c.is_control())
                            .take(280)
                            .collect(),
                        decide: Some(tx),
                    },
                );
            }
            r
        };
        if let Err(e) = recorded {
            return decline(&mut send, &req.request_id, &e.to_string()).await;
        }
        let who = self.peer_name(&borrower);
        self.audit_best_effort(
            "grant",
            Some(&borrower),
            format!(
                "{who} asked for {} cores and {} MiB",
                f64::from(requested.limits.cpu_millis) / 1000.0,
                requested.limits.memory_bytes >> 20
            ),
            serde_json::json!({ "grant": hex::encode(id.0), "reason": req.reason }),
        );
        let decision = tokio::time::timeout(DECISION_TIMEOUT, rx)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_else(|| Decision::Decline("no answer from the lender".into()));
        self.state().incoming.remove(&id);
        match decision {
            Decision::Accept(edited) => {
                let terms = edited.unwrap_or(requested);
                // The decision is recorded before it takes effect (strict).
                self.audit(
                    "grant",
                    Some(&borrower),
                    format!(
                        "accepted: {} cores, {} MiB until {}",
                        f64::from(terms.limits.cpu_millis) / 1000.0,
                        terms.limits.memory_bytes >> 20,
                        terms.not_after
                    ),
                    serde_json::json!({
                        "grant": hex::encode(id.0),
                        "cpu_millis": terms.limits.cpu_millis,
                        "memory_bytes": terms.limits.memory_bytes,
                        "not_after": terms.not_after,
                    }),
                )?;
                let signed = {
                    let mut s = self.state();
                    s.grants.lender_accept(id, terms.clone(), now())?;
                    self.sign_grant(id, borrower, &terms, &req.request_id)?
                };
                wire::send(
                    &mut send,
                    Body::GrantOffer(pb::GrantOffer {
                        grant: Some(signed),
                        r#final: true,
                    }),
                )
                .await?;
                send.finish()?;
                Ok(())
            }
            Decision::Decline(reason) => {
                let _ = self.state().grants.decline(id);
                self.audit_best_effort(
                    "grant",
                    Some(&borrower),
                    format!("declined: {reason}"),
                    serde_json::json!({ "grant": hex::encode(id.0) }),
                );
                decline(&mut send, &req.request_id, &reason).await
            }
        }
    }

    fn sign_grant(
        &self,
        id: GrantId,
        borrower: PeerKey,
        terms: &GrantTerms,
        request_id: &[u8],
    ) -> Result<pb::SignedGrant> {
        let grant = self.grant_proto(id, borrower, terms, request_id);
        let bytes = grant.encode_to_vec();
        let sig = self.inner.secret.sign(&[SIGNATURE_LABEL, &bytes].concat());
        Ok(pb::SignedGrant {
            grant: bytes,
            signature: sig.to_bytes().to_vec(),
        })
    }

    /// The protocol form of a grant this device issued (unsigned).
    pub fn grant_proto(
        &self,
        id: GrantId,
        borrower: PeerKey,
        terms: &GrantTerms,
        request_id: &[u8],
    ) -> pb::Grant {
        pb::Grant {
            grant_id: id.0.to_vec(),
            lender_key: self.key().0.to_vec(),
            borrower_key: borrower.0.to_vec(),
            issued_at: Some(ts(now())),
            not_after: Some(ts(terms.not_after)),
            limits: Some(limits_to(&terms.limits)),
            modes: modes_to(terms.allow_native),
            network: network_to(terms.network),
            env_build_network: false, // offline environment builds until M4
            schedule: pb::Schedule::Always as i32,
            pause_on_battery: true,
            pause_when_hot: true,
            trust: trust_to(terms.trust),
            request_id: request_id.to_vec(),
        }
    }

    /// Every grant this device issued as a lender (any state).
    pub fn lent_grants(&self) -> Vec<(GrantId, PeerKey, GrantState, GrantTerms, usize)> {
        self.state().grants.list()
    }

    /// Requests waiting for this user's decision.
    pub fn incoming_requests(&self) -> Vec<RequestView> {
        let s = self.state();
        s.incoming
            .iter()
            .map(|(id, p)| RequestView {
                id: *id,
                borrower: p.borrower,
                borrower_name: s
                    .trust
                    .get(&p.borrower)
                    .map_or_else(|| "Unknown device".into(), |t| t.name.clone()),
                requested: p.requested.clone(),
                reason: p.reason.clone(),
            })
            .collect()
    }

    /// The lender's user answers a request. [I13: the daemon's Control API must verify user
    /// presence before calling this with `Accept`.]
    pub fn respond_to_request(&self, id: GrantId, decision: Decision) -> Result<()> {
        let mut s = self.state();
        let pending = s.incoming.get_mut(&id).context("no such request")?;
        if let Decision::Accept(Some(edited)) = &decision
            && !within(edited, &pending.requested)
        {
            bail!("the lender may reduce the requested terms but not exceed them");
        }
        let tx = pending.decide.take().context("already answered")?;
        let _ = tx.send(decision);
        Ok(())
    }

    pub fn grant_state(&self, id: GrantId) -> Option<GrantState> {
        self.state().grants.state(id)
    }

    /// Lender revokes a grant: returns tasks to kill (I3) and tells the borrower (best effort).
    pub async fn revoke_grant(&self, id: GrantId) -> Result<Vec<TaskId>> {
        let borrower = self.state().grants.borrower(id);
        let killed = self.state().grants.revoke(id)?;
        self.cancel_tasks(&killed);
        if let Some(peer) = borrower {
            self.audit_best_effort(
                "grant",
                Some(&peer),
                format!(
                    "revoked grant {}; {} running task(s) stopped",
                    hex::encode(id.0),
                    killed.len()
                ),
                serde_json::json!({}),
            );
        }
        self.sweep_blobs();
        // Local enforcement is already done; telling the borrower must never delay it.
        if let Some(peer) = borrower {
            let node = self.clone();
            tokio::spawn(async move {
                let _ = node.notify_revoke(&peer, id).await;
            });
        }
        Ok(killed)
    }

    /// "Stop all lending" (I3).
    pub fn stop_all_lending(&self) -> Vec<TaskId> {
        let killed = self.state().grants.stop_all();
        self.cancel_tasks(&killed);
        self.sweep_blobs();
        killed
    }

    async fn notify_revoke(&self, peer: &PeerKey, id: GrantId) -> Result<()> {
        let conn = self.dial(peer).await?;
        let (mut send, _recv) = conn.open_bi().await?;
        wire::send(
            &mut send,
            Body::GrantRevoke(pb::GrantRevoke {
                grant_id: id.0.to_vec(),
                reason: "revoked by the lender".into(),
            }),
        )
        .await?;
        send.finish()?;
        send.stopped().await.ok();
        Ok(())
    }

    /// Either side may revoke: a lender's revoke removes the borrower's copy; a borrower's
    /// revoke ends the grant in the lender's book.
    pub(crate) fn handle_remote_revoke(&self, remote: PeerKey, r: pb::GrantRevoke) -> Result<()> {
        let id = grant_id(&r.grant_id)?;
        let mut s = self.state();
        if s.borrowed.get(&id).is_some_and(|b| b.lender == remote) {
            s.borrowed.remove(&id);
        }
        let killed = if s.grants.borrower(id) == Some(remote) {
            s.grants.revoke(id).unwrap_or_default()
        } else {
            Vec::new()
        };
        drop(s);
        self.cancel_tasks(&killed);
        self.sweep_blobs();
        Ok(())
    }

    // ------------------------------------------------------------------ borrower side

    /// Ask a paired lender for resources; waits for its user's decision.
    pub async fn request_grant(
        &self,
        lender: &PeerKey,
        terms: &GrantTerms,
        reason: &str,
    ) -> Result<GrantOutcome> {
        let req = request_proto(terms, reason, now())?;
        let conn = self.dial(lender).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        wire::send(&mut send, Body::GrantRequest(req)).await?;
        let reply = tokio::time::timeout(
            DECISION_TIMEOUT + Duration::from_secs(30),
            wire::recv(&mut recv),
        )
        .await
        .context("no answer from the lender")??;
        match reply {
            Body::GrantOffer(offer) => {
                ensure!(offer.r#final, "unexpected non-final offer");
                let signed = offer.grant.context("offer without grant")?;
                let grant = verify_signed(&signed, lender, &self.key())?;
                let id = grant_id(&grant.grant_id)?;
                let terms = terms_from_grant(&grant)?;
                self.audit_best_effort(
                    "grant",
                    Some(lender),
                    format!(
                        "received grant {}: {} cores",
                        hex::encode(id.0),
                        f64::from(terms.limits.cpu_millis) / 1000.0
                    ),
                    serde_json::json!({ "grant": hex::encode(id.0) }),
                );
                self.state().borrowed.insert(
                    id,
                    Borrowed {
                        lender: *lender,
                        terms: terms.clone(),
                        signed,
                    },
                );
                Ok(GrantOutcome::Granted { id, terms })
            }
            Body::GrantDecline(d) => Ok(GrantOutcome::Declined(d.reason)),
            _ => bail!("unexpected reply to a grant request"),
        }
    }

    /// Grants this device currently holds from other devices.
    pub fn borrowed_grants(&self) -> Vec<(GrantId, Borrowed)> {
        self.state()
            .borrowed
            .iter()
            .map(|(id, b)| (*id, b.clone()))
            .collect()
    }
}

async fn decline(send: &mut SendStream, request_id: &[u8], reason: &str) -> Result<()> {
    wire::send(
        send,
        Body::GrantDecline(pb::GrantDecline {
            request_id: request_id.to_vec(),
            reason: reason.to_string(),
        }),
    )
    .await?;
    send.finish()?;
    Ok(())
}

/// Convenience for callers building a request.
pub fn standard_terms(cpu_cores: u32, memory_gib: u64, hours: u64, now: UnixSeconds) -> GrantTerms {
    GrantTerms {
        limits: Limits {
            cpu_millis: cpu_cores * 1000,
            memory_bytes: memory_gib << 30,
            disk_bytes: 10 << 30,
            gpu: Gpu::None,
            max_concurrent_tasks: cpu_cores.max(1),
        },
        not_after: now + hours * 3600,
        allow_native: false,
        network: NetworkPolicy::None,
        trust: TrustLevel::Standard,
    }
}
