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
    ExecutionMode, Gpu, GrantId, GrantState, GrantTerms, Limits, Modes, NetworkPolicy, PeerKey,
    Speed, TaskId, TrustLevel, UnixSeconds,
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
/// How long a queued request (`--no-wait`) waits for the lender's user.
pub const QUEUE_TIMEOUT: Duration = Duration::from_secs(24 * 3600);
/// At most this many queued requests from one device wait at once.
pub const MAX_QUEUED_PER_DEVICE: usize = 5;
/// What versions before the `no_answer` flag send when nobody answered.
const LEGACY_NO_ANSWER: &str = "no answer from the lender";

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
    /// The borrower's id for it, and, for a queued request, when it lapses (#23).
    pub request_id: Vec<u8>,
    pub queued_until: Option<UnixSeconds>,
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
    Granted {
        id: GrantId,
        terms: GrantTerms,
    },
    Declined(String),
    /// Nobody answered on the lender in time; nothing was granted or declined.
    NoAnswer,
    /// Kept for the lender's owner (`--no-wait`); the answer comes later. `request_id` names it.
    Queued {
        request_id: Vec<u8>,
        expires_at: UnixSeconds,
    },
}

/// A decline as the borrower reads it: older lenders flag "no answer" only in the text.
fn outcome_of_decline(d: pb::GrantDecline) -> GrantOutcome {
    if d.no_answer || d.reason == LEGACY_NO_ANSWER {
        GrantOutcome::NoAnswer
    } else {
        GrantOutcome::Declined(d.reason)
    }
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

pub(crate) fn limits_to(l: &Limits) -> pb::Limits {
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

pub fn speed_to(s: Option<Speed>) -> pb::TaskSpeed {
    match s {
        None => pb::TaskSpeed::Unspecified,
        Some(Speed::Full) => pb::TaskSpeed::Full,
        Some(Speed::AppsFirst) => pb::TaskSpeed::AppsFirst,
        Some(Speed::Background) => pb::TaskSpeed::Background,
    }
}

/// 0 is "not stated". A value this device does not know reads as the slowest: an unknown
/// level never runs a task faster than its owner chose.
pub fn speed_from(v: i32) -> Option<Speed> {
    match pb::TaskSpeed::try_from(v) {
        Ok(pb::TaskSpeed::Unspecified) => None,
        Ok(pb::TaskSpeed::Full) => Some(Speed::Full),
        Ok(pb::TaskSpeed::AppsFirst) => Some(Speed::AppsFirst),
        Ok(pb::TaskSpeed::Background) | Err(_) => Some(Speed::Background),
    }
}

pub fn mode_to(m: ExecutionMode) -> pb::ExecutionMode {
    match m {
        ExecutionMode::Container => pb::ExecutionMode::Container,
        ExecutionMode::Sandbox => pb::ExecutionMode::Sandbox,
        ExecutionMode::Native => pb::ExecutionMode::Native,
    }
}

/// Unknown or unspecified values are not a mode (fail closed).
pub fn mode_from(v: i32) -> Option<ExecutionMode> {
    match pb::ExecutionMode::try_from(v) {
        Ok(pb::ExecutionMode::Container) => Some(ExecutionMode::Container),
        Ok(pb::ExecutionMode::Sandbox) => Some(ExecutionMode::Sandbox),
        Ok(pb::ExecutionMode::Native) => Some(ExecutionMode::Native),
        _ => None,
    }
}

pub fn modes_to(m: Modes) -> Vec<i32> {
    m.iter().map(|m| mode_to(m) as i32).collect()
}

/// An empty list means containers only (what every earlier version meant).
pub fn modes_from(v: &[i32]) -> Modes {
    if v.is_empty() {
        return Modes::CONTAINER;
    }
    v.iter()
        .filter_map(|m| mode_from(*m))
        .fold(Modes::NONE, Modes::with)
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
        modes: modes_to(terms.modes),
        network: network_to(terms.network),
        duration: Some(prost_types::Duration {
            seconds: i64::try_from(terms.not_after - now)?,
            nanos: 0,
        }),
        trust: trust_to(terms.trust),
        reason: reason.chars().take(280).collect(),
        speed: speed_to(terms.speed) as i32,
        images_bytes: terms.images_bytes,
        renews: Vec::new(),
        queue: false,
    })
}

pub fn terms_from_request(req: &pb::GrantRequest, now: UnixSeconds) -> Result<GrantTerms> {
    let d = req.duration.as_ref().context("missing duration")?;
    let d = u64::try_from(d.seconds).context("negative duration")?;
    Ok(GrantTerms {
        limits: limits_from(req.limits.as_ref())?,
        not_after: now.saturating_add(d),
        modes: modes_from(&req.modes),
        network: network_from(req.network),
        trust: trust_from(req.trust),
        speed: speed_from(req.speed),
        images_bytes: req.images_bytes,
    })
}

pub fn terms_from_grant(g: &pb::Grant) -> Result<GrantTerms> {
    Ok(GrantTerms {
        limits: limits_from(g.limits.as_ref())?,
        not_after: secs(g.not_after.as_ref())?,
        modes: modes_from(&g.modes),
        network: network_from(g.network),
        trust: trust_from(g.trust),
        speed: speed_from(g.speed),
        images_bytes: g.images_bytes,
    })
}

/// `offered` never grants more than `asked` (v1 reduce-only acceptance).
pub fn within(offered: &GrantTerms, asked: &GrantTerms) -> bool {
    let (o, a) = (&offered.limits, &asked.limits);
    o.cpu_millis <= a.cpu_millis
        && o.memory_bytes <= a.memory_bytes
        && o.disk_bytes <= a.disk_bytes
        && o.max_concurrent_tasks <= a.max_concurrent_tasks
        && offered.images_bytes <= asked.images_bytes
        && (o.gpu == a.gpu || o.gpu == Gpu::None)
        && offered.not_after <= asked.not_after
        && offered.modes.is_subset_of(asked.modes)
        && (offered.network == NetworkPolicy::None || asked.network == NetworkPolicy::Internet)
        && (offered.trust == TrustLevel::Standard || asked.trust == TrustLevel::Trusted)
        // A named speed may only be lowered. A request that names none gets a grant that names
        // none (its tasks follow the lender's setting).
        && match (offered.speed, asked.speed) {
            (None, None) => true,
            (Some(o), Some(a)) => o <= a,
            _ => false,
        }
}

/// Signs grant bytes as a lender does (for fuzzing and tests of verification).
#[doc(hidden)]
pub fn sign_grant_bytes(secret: &iroh::SecretKey, grant: Vec<u8>) -> pb::SignedGrant {
    let sig = secret.sign(&[SIGNATURE_LABEL, &grant].concat());
    pb::SignedGrant {
        grant,
        signature: sig.to_bytes().to_vec(),
    }
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
        let mut requested = match terms_from_request(&req, t) {
            Ok(terms) => terms,
            Err(e) => return decline(&mut send, &req.request_id, &e.to_string()).await,
        };
        // Only the ways this user chose to lend; the request screen shows the result.
        let lent = self.lend_modes().0;
        requested.modes = requested.modes.intersect(lent);
        if requested.modes.is_empty() {
            let names: Vec<&str> = lent.iter().map(crate::exec::mode_name).collect();
            let why = if names.is_empty() {
                "that device lends no way of running tasks right now".to_string()
            } else {
                format!("that device lends only: {}", names.join(", "))
            };
            return decline(&mut send, &req.request_id, &why).await;
        }
        // Trusted grants only where this device's user turned Trusted mode on for the borrower.
        if requested.trust == TrustLevel::Trusted && !self.is_trusted(&borrower) {
            return decline(
                &mut send,
                &req.request_id,
                "Trusted mode is not turned on for this device there",
            )
            .await;
        }
        let reason = wire::clean_text(&req.reason, 280);
        // A standing grant the owner created for this device may accept it without asking
        // (standing.rs); anything it does not cover goes to the owner as before.
        // A renewal is for the standing grant alone: never a prompt for the owner.
        let renews = if req.renews.is_empty() {
            None
        } else {
            let old = grant_id(&req.renews)?;
            if !self.renewable(&borrower, old) {
                return decline(
                    &mut send,
                    &req.request_id,
                    "that grant was not given by a standing grant, or has ended",
                )
                .await;
            }
            Some(old)
        };
        let accepted = self.try_accept_by_rule(
            id,
            borrower,
            &requested,
            &req.request_id,
            &reason,
            t,
            renews,
        )?;
        if accepted.is_none() && renews.is_some() {
            return decline(
                &mut send,
                &req.request_id,
                "its standing grant does not cover this renewal (ended, lapsed or narrowed): \
                 ask again with `gmc grants request`",
            )
            .await;
        }
        if let Some(signed) = accepted {
            self.save_grants();
            wire::send(
                &mut send,
                Body::GrantOffer(pb::GrantOffer {
                    grant: Some(signed),
                    r#final: true,
                }),
            )
            .await?;
            send.finish()?;
            return Ok(());
        }
        if req.queue {
            let queued = self
                .state()
                .incoming
                .values()
                .filter(|p| p.borrower == borrower && p.queued_until.is_some())
                .count();
            if queued >= MAX_QUEUED_PER_DEVICE {
                return decline(
                    &mut send,
                    &req.request_id,
                    "too many of this device's requests are already waiting there",
                )
                .await;
            }
        }
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
                        reason: reason.clone(),
                        decide: Some(tx),
                        request_id: req.request_id.clone(),
                        // Marked queued from the start, so the per-device cap counts it.
                        queued_until: req.queue.then(|| t + self.queue_timeout().as_secs()),
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
            serde_json::json!({ "grant": hex::encode(id.0), "reason": reason }),
        );
        if req.queue {
            // Kept for the owner; the borrower goes on and hears the answer later (#23).
            let wait = self.queue_timeout();
            let expires = t + wait.as_secs();
            wire::send(
                &mut send,
                Body::GrantQueued(pb::GrantQueued {
                    request_id: req.request_id.clone(),
                    expires_at: Some(ts(expires)),
                }),
            )
            .await?;
            send.finish()?;
            let node = self.clone();
            tokio::spawn(async move {
                let answer = node
                    .decide(id, borrower, requested, &req.request_id, rx, wait)
                    .await
                    .unwrap_or_else(|e| {
                        Body::GrantDecline(pb::GrantDecline {
                            request_id: req.request_id.clone(),
                            reason: format!("the request could not be answered: {e:#}"),
                            no_answer: false,
                        })
                    });
                node.deliver_answer(borrower, req.request_id.clone(), answer)
                    .await;
            });
            return Ok(());
        }
        let answer = self
            .decide(
                id,
                borrower,
                requested,
                &req.request_id,
                rx,
                self.decision_timeout(),
            )
            .await?;
        wire::send(&mut send, answer).await?;
        send.finish()?;
        Ok(())
    }

    /// Waits up to `wait` for the owner's decision on request `id` and carries it out: the
    /// answer for the borrower (a signed grant or a decline).
    async fn decide(
        &self,
        id: GrantId,
        borrower: PeerKey,
        requested: GrantTerms,
        request_id: &[u8],
        rx: oneshot::Receiver<Decision>,
        wait: Duration,
    ) -> Result<Body> {
        let decision = tokio::time::timeout(wait, rx)
            .await
            .ok()
            .and_then(Result::ok);
        self.state().incoming.remove(&id);
        let declined = |reason: String, no_answer: bool| {
            Body::GrantDecline(pb::GrantDecline {
                request_id: request_id.to_vec(),
                reason,
                no_answer,
            })
        };
        match decision {
            // Nobody answered: the request lapses. Nothing was declined, so it is not said to be.
            None => {
                let _ = self.state().grants.lapse(id);
                let mins = wait.as_secs().div_ceil(60);
                let span = if mins >= 120 {
                    format!("{} hours", mins.div_ceil(60))
                } else {
                    format!("{mins} minutes")
                };
                self.audit_best_effort(
                    "grant",
                    Some(&borrower),
                    format!("no answer within {span}: nothing granted"),
                    serde_json::json!({ "grant": hex::encode(id.0), "outcome": "no_answer" }),
                );
                Ok(declined(
                    format!("nobody answered on that device within {span}, so nothing was granted"),
                    true,
                ))
            }
            Some(Decision::Accept(edited)) => {
                let terms = edited.unwrap_or(requested);
                // It may have been turned off while the request waited.
                if terms.trust == TrustLevel::Trusted && !self.is_trusted(&borrower) {
                    let _ = self.state().grants.decline(id);
                    return Ok(declined(
                        "Trusted mode was turned off on that device".into(),
                        false,
                    ));
                }
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
                let setting = self.task_speed();
                let tools = self.tools_for(&terms);
                let signed = {
                    let mut s = self.state();
                    s.grants.lender_accept(id, terms.clone(), now())?;
                    let signed =
                        self.sign_grant(id, borrower, &terms, request_id, setting, false, tools)?;
                    s.issued.insert(id, signed.clone());
                    signed
                };
                self.save_grants();
                Ok(Body::GrantOffer(pb::GrantOffer {
                    grant: Some(signed),
                    r#final: true,
                }))
            }
            Some(Decision::Decline(reason)) => {
                let _ = self.state().grants.decline(id);
                self.audit_best_effort(
                    "grant",
                    Some(&borrower),
                    format!("declined: {reason}"),
                    serde_json::json!({ "grant": hex::encode(id.0) }),
                );
                Ok(declined(reason, false))
            }
        }
    }

    /// How long a queued request waits for the owner (tests shorten it with the decision wait).
    fn queue_timeout(&self) -> Duration {
        if self.decision_timeout() < DECISION_TIMEOUT {
            self.decision_timeout()
        } else {
            QUEUE_TIMEOUT
        }
    }

    /// Keeps the answer to a queued request for the borrower to ask about, and sends it now
    /// if the borrower can be reached.
    async fn deliver_answer(&self, borrower: PeerKey, request_id: Vec<u8>, answer: Body) {
        self.state()
            .answered
            .insert(request_id, (borrower, answer.clone(), now()));
        let push = async {
            let conn = self.dial(&borrower).await?;
            let (mut send, _recv) = conn.open_bi().await?;
            wire::send(&mut send, answer).await?;
            send.finish()?;
            send.stopped().await.ok();
            anyhow::Ok(())
        };
        if let Err(e) = push.await {
            tracing::debug!("answer not delivered now (it will ask): {e:#}");
        }
    }

    /// As the lender: a borrower asks about its queued request.
    pub(crate) async fn handle_grant_poll(
        &self,
        borrower: PeerKey,
        p: pb::GrantPoll,
        mut send: SendStream,
    ) -> Result<()> {
        let answer = {
            let s = self.state();
            if let Some((b, body, _)) = s
                .answered
                .get(&p.request_id)
                .filter(|(b, ..)| *b == borrower)
            {
                let _ = b;
                body.clone()
            } else if let Some(pending) = s
                .incoming
                .values()
                .find(|q| q.borrower == borrower && q.request_id == p.request_id)
            {
                Body::GrantQueued(pb::GrantQueued {
                    request_id: p.request_id.clone(),
                    expires_at: pending.queued_until.map(ts),
                })
            } else {
                Body::GrantDecline(pb::GrantDecline {
                    request_id: p.request_id.clone(),
                    reason: "that device no longer knows this request (it may have restarted): \
                             ask again"
                        .into(),
                    no_answer: false,
                })
            }
        };
        wire::send(&mut send, answer).await?;
        send.finish()?;
        Ok(())
    }

    /// Accepts a request its borrower's standing grant covers, in one step under the standing
    /// lock, so two requests at once cannot together exceed the rule: checks it against what
    /// the grants it already accepted hold, records, audits (strict) and signs. `None`: the
    /// owner decides, as before.
    #[allow(clippy::too_many_arguments)]
    fn try_accept_by_rule(
        &self,
        id: GrantId,
        borrower: PeerKey,
        requested: &GrantTerms,
        request_id: &[u8],
        reason: &str,
        t: UnixSeconds,
        renews: Option<GrantId>,
    ) -> Result<Option<pb::SignedGrant>> {
        let _one_at_a_time = self
            .inner
            .standing_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(terms) = self.standing_covers(&borrower, requested, renews) else {
            return Ok(None);
        };
        self.state()
            .grants
            .request(id, borrower, requested.clone(), t)?;
        let who = self.peer_name(&borrower);
        let accepted = (|| -> Result<pb::SignedGrant> {
            // The decision is recorded before it takes effect (strict).
            self.audit(
                "grant",
                Some(&borrower),
                format!(
                    "{who} asked for {} cores and {} MiB{}: accepted by standing grant until {}",
                    f64::from(terms.limits.cpu_millis) / 1000.0,
                    terms.limits.memory_bytes >> 20,
                    renews.map_or(String::new(), |r| format!(
                        " (renewal of {})",
                        hex::encode(r.0)
                    )),
                    terms.not_after
                ),
                serde_json::json!({
                    "grant": hex::encode(id.0),
                    "reason": reason,
                    "cpu_millis": terms.limits.cpu_millis,
                    "memory_bytes": terms.limits.memory_bytes,
                    "not_after": terms.not_after,
                    "by_standing_rule": true,
                }),
            )?;
            let setting = self.task_speed();
            let tools = self.tools_for(&terms);
            let mut s = self.state();
            s.grants.lender_accept(id, terms.clone(), now())?;
            let signed = self.sign_grant(id, borrower, &terms, request_id, setting, true, tools)?;
            s.issued.insert(id, signed.clone());
            Ok(signed)
        })();
        if accepted.is_err() {
            let _ = self.state().grants.decline(id);
        }
        accepted.map(Some)
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_grant(
        &self,
        id: GrantId,
        borrower: PeerKey,
        terms: &GrantTerms,
        request_id: &[u8],
        setting: Speed,
        by_rule: bool,
        tools: Vec<pb::ToolVersion>,
    ) -> Result<pb::SignedGrant> {
        let grant = grant_proto_with(
            self.key(),
            id,
            borrower,
            terms,
            request_id,
            Some(now()),
            setting,
            by_rule,
            tools,
        );
        let bytes = grant.encode_to_vec();
        let sig = self.inner.secret.sign(&[SIGNATURE_LABEL, &bytes].concat());
        Ok(pb::SignedGrant {
            grant: bytes,
            signature: sig.to_bytes().to_vec(),
        })
    }

    /// The protocol form of a grant this device issued (unsigned). `issued_at` is the time it
    /// was signed (`None` for a request not yet answered): never the time of the call, or every
    /// listing would differ from the last and look like a change.
    pub fn grant_proto(
        &self,
        id: GrantId,
        borrower: PeerKey,
        terms: &GrantTerms,
        request_id: &[u8],
        issued_at: Option<u64>,
    ) -> pb::Grant {
        grant_proto_with(
            self.key(),
            id,
            borrower,
            terms,
            request_id,
            issued_at,
            self.task_speed(),
            self.issued_by_rule(id),
            Vec::new(),
        )
    }

    /// Whether a standing grant accepted grant `id` (from the signed copy this device keeps).
    pub fn issued_by_rule(&self, id: GrantId) -> bool {
        let Some(signed) = self.state().issued.get(&id).cloned() else {
            return false;
        };
        <pb::Grant as prost::Message>::decode(signed.grant.as_slice())
            .is_ok_and(|g| g.by_standing_rule)
    }

    /// When this device signed grant `id` (from the signed copy it keeps), if it did.
    pub fn issued_at(&self, id: GrantId) -> Option<u64> {
        let signed = self.state().issued.get(&id).cloned()?;
        let grant = <pb::Grant as prost::Message>::decode(signed.grant.as_slice()).ok()?;
        grant.issued_at.and_then(|t| u64::try_from(t.seconds).ok())
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

    /// How long a request waits for this device's owner before it lapses.
    pub fn decision_timeout(&self) -> Duration {
        Duration::from_millis(
            self.inner
                .decision_timeout_ms
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// Test-only: a shorter wait, so a test can see a request lapse.
    #[cfg(feature = "insecure-test-executor")]
    pub fn set_decision_timeout(&self, d: Duration) {
        self.inner.decision_timeout_ms.store(
            u64::try_from(d.as_millis()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    pub fn grant_state(&self, id: GrantId) -> Option<GrantState> {
        self.state().grants.state(id)
    }

    /// Lender revokes a grant: returns tasks to kill (I3) and tells the borrower (best effort).
    pub async fn revoke_grant(&self, id: GrantId) -> Result<Vec<TaskId>> {
        let borrower = self.state().grants.borrower(id);
        let killed = self.state().grants.revoke(id)?;
        self.cancel_tasks(&killed, crate::activity::EndCause::GrantRevoked);
        self.save_grants();
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
        self.cancel_tasks(&killed, crate::activity::EndCause::LendingOff);
        self.save_grants();
        self.sweep_blobs();
        killed
    }

    pub(crate) async fn notify_revoke(&self, peer: &PeerKey, id: GrantId) -> Result<()> {
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
        self.cancel_tasks(&killed, crate::activity::EndCause::GrantRevoked);
        self.save_grants();
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
        self.request_grant_with(lender, terms, reason, None).await
    }

    /// [`Self::request_grant`], optionally renewing a grant a standing grant gave this device
    /// (`renews`): the lender then accepts only by its standing grant, or declines at once.
    pub async fn request_grant_with(
        &self,
        lender: &PeerKey,
        terms: &GrantTerms,
        reason: &str,
        renews: Option<GrantId>,
    ) -> Result<GrantOutcome> {
        self.request_grant_inner(lender, terms, reason, renews, false)
            .await
    }

    /// Asks without waiting: the lender keeps the request for its owner (up to a day) and the
    /// answer comes later (queued.rs). A standing grant may still answer at once.
    pub async fn request_grant_queued(
        &self,
        lender: &PeerKey,
        terms: &GrantTerms,
        reason: &str,
    ) -> Result<GrantOutcome> {
        self.request_grant_inner(lender, terms, reason, None, true)
            .await
    }

    async fn request_grant_inner(
        &self,
        lender: &PeerKey,
        terms: &GrantTerms,
        reason: &str,
        renews: Option<GrantId>,
        queue: bool,
    ) -> Result<GrantOutcome> {
        let asked_trust = terms.trust;
        if asked_trust == TrustLevel::Trusted {
            ensure!(
                self.is_trusted(lender),
                "turn on Trusted mode for that device first (`gmc trust <device> on`)"
            );
        }
        let mut req = request_proto(terms, reason, now())?;
        req.renews = renews.map(|r| r.0.to_vec()).unwrap_or_default();
        req.queue = queue;
        let conn = self.dial_waking(lender).await?;
        // Each side learns the other's version, so a mismatch can be seen (`gmc peers`).
        self.exchange_hello(lender, &conn).await;
        if queue {
            // A lender older than queued requests would keep this one open and answer nobody.
            self.ensure_can_queue(lender)?;
        }
        let (mut send, mut recv) = conn.open_bi().await?;
        wire::send(&mut send, Body::GrantRequest(req.clone())).await?;
        // The lender answers "no answer" itself when its owner does not decide; this covers a
        // lender that went quiet (asleep, gone) while its owner was deciding.
        let Ok(reply) = tokio::time::timeout(
            DECISION_TIMEOUT + Duration::from_secs(30),
            wire::recv(&mut recv),
        )
        .await
        else {
            return Ok(GrantOutcome::NoAnswer);
        };
        match reply? {
            Body::GrantQueued(q) if queue => self.now_waiting(lender, req, &q),
            other => self.receive_answer(lender, asked_trust, other).await,
        }
    }

    /// A lender's answer to a request of this device: the grant it signed (checked and kept),
    /// or why not.
    pub(crate) async fn receive_answer(
        &self,
        lender: &PeerKey,
        asked_trust: TrustLevel,
        reply: Body,
    ) -> Result<GrantOutcome> {
        match reply {
            Body::GrantOffer(offer) => {
                ensure!(offer.r#final, "unexpected non-final offer");
                let signed = offer.grant.context("offer without grant")?;
                let grant = verify_signed(&signed, lender, &self.key())?;
                let id = grant_id(&grant.grant_id)?;
                let terms = terms_from_grant(&grant)?;
                // A Trusted grant only if asked for and Trusted mode is on here for this lender.
                if terms.trust == TrustLevel::Trusted
                    && (asked_trust != TrustLevel::Trusted || !self.is_trusted(lender))
                {
                    let _ = self.notify_revoke(lender, id).await;
                    bail!("the lender offered a Trusted grant this device did not agree to");
                }
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
                self.save_grants();
                Ok(GrantOutcome::Granted { id, terms })
            }
            Body::GrantDecline(d) => Ok(outcome_of_decline(d)),
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

/// A grant as signed and shown; `setting` is the owner's own level at that moment.
#[allow(clippy::too_many_arguments)]
fn grant_proto_with(
    lender: PeerKey,
    id: GrantId,
    borrower: PeerKey,
    terms: &GrantTerms,
    request_id: &[u8],
    issued_at: Option<u64>,
    setting: Speed,
    by_rule: bool,
    tools: Vec<pb::ToolVersion>,
) -> pb::Grant {
    pb::Grant {
        grant_id: id.0.to_vec(),
        lender_key: lender.0.to_vec(),
        borrower_key: borrower.0.to_vec(),
        issued_at: issued_at.map(ts),
        not_after: Some(ts(terms.not_after)),
        limits: Some(limits_to(&terms.limits)),
        modes: modes_to(terms.modes),
        network: network_to(terms.network),
        env_build_network: false, // offline environment builds until M4
        schedule: pb::Schedule::Always as i32,
        pause_on_battery: true,
        pause_when_hot: true,
        trust: trust_to(terms.trust),
        request_id: request_id.to_vec(),
        speed: speed_to(terms.speed) as i32,
        images_bytes: terms.images_bytes,
        lender_speed: speed_to(Some(setting)) as i32,
        by_standing_rule: by_rule,
        tools,
    }
}

async fn decline(send: &mut SendStream, request_id: &[u8], reason: &str) -> Result<()> {
    wire::send(
        send,
        Body::GrantDecline(pb::GrantDecline {
            request_id: request_id.to_vec(),
            reason: reason.to_string(),
            no_answer: false,
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
        // Ask for every sandboxed way; the lender grants only what it lends.
        modes: Modes::CONTAINER.with(ExecutionMode::Sandbox),
        network: NetworkPolicy::None,
        trust: TrustLevel::Standard,
        speed: None,
        images_bytes: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decline(reason: &str, no_answer: bool) -> pb::GrantDecline {
        pb::GrantDecline {
            request_id: vec![],
            reason: reason.into(),
            no_answer,
        }
    }

    #[test]
    fn no_answer_is_not_a_refusal_from_new_or_old_lenders() {
        assert!(matches!(
            outcome_of_decline(decline("nobody answered", true)),
            GrantOutcome::NoAnswer
        ));
        // 0.1.0 lenders said it only in the text.
        assert!(matches!(
            outcome_of_decline(decline("no answer from the lender", false)),
            GrantOutcome::NoAnswer
        ));
        assert!(matches!(
            outcome_of_decline(decline("busy", false)),
            GrantOutcome::Declined(r) if r == "busy"
        ));
    }
}
