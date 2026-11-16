//! Standing grants (docs/design/standing-grants.md, issue #22).
//!
//! The lender's owner creates one, with presence, for one paired device: requests from that
//! device within its limits are then accepted without asking. Owner's decisions (2026-11-16):
//! Standard grants only; each accepted grant lasts at most 8 hours; the rule lapses after 30
//! days unless renewed; the owner is told of every grant it accepts (audit log, app
//! notification); turning it off revokes the grants it accepted.
//!
//! A request it does not cover goes to the owner exactly as before: nothing is cut down to fit,
//! except the ways of running tasks, which a request lists as alternatives (it gets the ones
//! the rule allows). The rule is kept with the paired device in `peers.json` and signed with
//! this device's key, so an edited file cannot widen it; a rule that fails verification is
//! ignored and removed.

use anyhow::{Context, Result, bail, ensure};
use gimmecores_core::{
    Gpu, GrantTerms, Modes, NetworkPolicy, PeerKey, Speed, TrustLevel, UnixSeconds,
};
use serde::{Deserialize, Serialize};

use crate::node::Node;
use crate::now;

/// How long one creation or renewal lasts.
pub const STANDING_DAYS: u64 = 30;
/// The longest grant a standing grant accepts.
pub const MAX_HOURS: u32 = 8;
/// A request's end is computed on the borrower a moment before it arrives.
const CLOCK_SLACK: u64 = 120;
const SIGNATURE_LABEL: &[u8] = b"gimmecores-standing-v1";

/// What the owner approved for one device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingRule {
    pub cpu_millis: u32,
    pub memory_bytes: u64,
    pub disk_bytes: u64,
    pub container: bool,
    pub sandbox: bool,
    /// The fastest level it approves ("full", "apps-first", "background"); `None`: none faster
    /// than the owner's own setting at the time of the request.
    pub speed: Option<String>,
    pub images_bytes: u64,
    pub max_hours: u32,
    pub created_at: UnixSeconds,
    pub until: UnixSeconds,
}

/// A rule with this device's signature over it (hex), as kept on disk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRule {
    pub rule: StandingRule,
    pub sig: String,
}

impl StandingRule {
    /// A rule for `terms` as the owner approves it now: same limits, each grant at most
    /// `hours` (1 to 8), for 30 days.
    pub fn new(terms: &GrantTerms, hours: u32, now: UnixSeconds) -> Result<Self> {
        ensure!(
            terms.trust == TrustLevel::Standard,
            "standing grants cover Standard grants only (Trusted ones always ask you)"
        );
        ensure!(
            terms.limits.cpu_millis > 0 && terms.limits.memory_bytes > 0,
            "a standing grant needs some cores and memory"
        );
        ensure!(
            terms.modes.container || terms.modes.sandbox,
            "a standing grant needs a way to run tasks: container or sandbox"
        );
        ensure!(
            terms.limits.gpu == Gpu::None && terms.network == NetworkPolicy::None,
            "standing grants cover tasks without GPU or network only"
        );
        Ok(Self {
            cpu_millis: terms.limits.cpu_millis,
            memory_bytes: terms.limits.memory_bytes,
            disk_bytes: terms.limits.disk_bytes,
            container: terms.modes.container,
            sandbox: terms.modes.sandbox,
            speed: terms.speed.map(|s| s.name().to_string()),
            images_bytes: terms.images_bytes,
            max_hours: hours.clamp(1, MAX_HOURS),
            created_at: now,
            until: now + STANDING_DAYS * 86_400,
        })
    }

    pub fn modes(&self) -> Modes {
        Modes {
            container: self.container,
            sandbox: self.sandbox,
            native: false,
        }
    }

    /// The fastest level it approves, given the owner's setting now.
    pub fn fastest(&self, setting: Speed) -> Speed {
        self.speed
            .as_deref()
            .and_then(Speed::from_name)
            .unwrap_or(setting)
    }

    /// The terms to grant for `asked` without asking the owner, or `None` when the owner must
    /// decide. Only the ways of running tasks may be narrowed (a request lists alternatives).
    pub fn covers(
        &self,
        asked: &GrantTerms,
        setting: Speed,
        now: UnixSeconds,
    ) -> Option<GrantTerms> {
        if now >= self.until || asked.trust != TrustLevel::Standard {
            return None;
        }
        let l = &asked.limits;
        let cores = self.cpu_millis.div_ceil(1000).max(1);
        let within = l.cpu_millis <= self.cpu_millis
            && l.memory_bytes <= self.memory_bytes
            && l.disk_bytes <= self.disk_bytes
            && l.gpu == Gpu::None
            && l.max_concurrent_tasks <= cores
            && asked.network == NetworkPolicy::None
            && asked.images_bytes <= self.images_bytes
            && asked.speed.is_none_or(|s| s <= self.fastest(setting))
            && asked.not_after <= now + u64::from(self.max_hours) * 3600 + CLOCK_SLACK;
        let modes = asked.modes.intersect(self.modes());
        (within && !modes.is_empty()).then(|| GrantTerms {
            modes,
            ..asked.clone()
        })
    }

    /// "up to 4 cores, 8.0 GiB memory, 10.0 GiB disk, in a container or this computer's
    /// sandbox, each time for up to 8 hours".
    pub fn describe(&self) -> String {
        let gib = |b: u64| b as f64 / f64::from(1u32 << 30);
        let mut ways = Vec::new();
        if self.container {
            ways.push("in a container");
        }
        if self.sandbox {
            ways.push("in this computer's sandbox");
        }
        let speed = self
            .speed
            .as_deref()
            .map_or(String::new(), |s| format!(", speed up to {s}"));
        let images = if self.images_bytes > 0 {
            format!(
                ", sending its own images up to {:.1} GiB",
                gib(self.images_bytes)
            )
        } else {
            String::new()
        };
        format!(
            "up to {} cores, {:.1} GiB memory, {:.1} GiB disk, {}{speed}{images}, each time for \
             up to {} hours",
            f64::from(self.cpu_millis) / 1000.0,
            gib(self.memory_bytes),
            gib(self.disk_bytes),
            ways.join(" or "),
            self.max_hours
        )
    }
}

fn message(lender: &PeerKey, borrower: &PeerKey, rule: &StandingRule) -> Result<Vec<u8>> {
    Ok([
        SIGNATURE_LABEL,
        &lender.0,
        &borrower.0,
        &serde_json::to_vec(rule)?,
    ]
    .concat())
}

impl Node {
    fn sign_rule(&self, borrower: &PeerKey, rule: StandingRule) -> Result<SignedRule> {
        let sig = self
            .inner
            .secret
            .sign(&message(&self.key(), borrower, &rule)?);
        Ok(SignedRule {
            rule,
            sig: hex::encode(sig.to_bytes()),
        })
    }

    fn verify_rule(&self, borrower: &PeerKey, signed: &SignedRule) -> bool {
        let check = || -> Result<()> {
            let pk = iroh::PublicKey::from_bytes(&self.key().0)?;
            let bytes = hex::decode(&signed.sig)?;
            let sig = iroh::Signature::try_from(bytes.as_slice())
                .map_err(|_| anyhow::anyhow!("malformed signature"))?;
            pk.verify(&message(&self.key(), borrower, &signed.rule)?, &sig)
                .map_err(|_| anyhow::anyhow!("bad signature"))
        };
        check().is_ok()
    }

    /// This device's standing grant for `borrower`, if there is a valid one that has not lapsed.
    pub fn standing_rule(&self, borrower: &PeerKey) -> Option<StandingRule> {
        let signed = self.state().trust.get(borrower)?.standing.clone()?;
        (self.verify_rule(borrower, &signed) && now() < signed.rule.until).then_some(signed.rule)
    }

    /// The terms a request from `borrower` gets without asking, if its standing grant covers it.
    pub(crate) fn standing_covers(
        &self,
        borrower: &PeerKey,
        asked: &GrantTerms,
    ) -> Option<GrantTerms> {
        let rule = self.standing_rule(borrower)?;
        rule.covers(asked, self.task_speed(), now())
    }

    /// Creates, renews or changes the standing grant for `borrower` as `terms` describe, each
    /// grant at most `hours`. Needs presence; the prompt says exactly what it allows.
    pub async fn set_standing_rule(
        &self,
        borrower: &PeerKey,
        terms: &GrantTerms,
        hours: u32,
    ) -> Result<StandingRule> {
        let rule = StandingRule::new(terms, hours, now())?;
        self.require_presence(&format!(
            "let {:?} use this computer {} without asking you, for {STANDING_DAYS} days",
            self.peer_name(borrower),
            rule.describe()
        ))
        .await?;
        self.store_standing_rule(borrower, rule)
    }

    /// Keeps a rule the owner approved in a presence prompt that already said so.
    pub(crate) fn store_standing_rule(
        &self,
        borrower: &PeerKey,
        rule: StandingRule,
    ) -> Result<StandingRule> {
        let signed = self.sign_rule(borrower, rule.clone())?;
        self.state()
            .trust
            .set_standing(borrower, Some(signed))
            .context("saving the standing grant")?;
        self.audit_best_effort(
            "grant",
            Some(borrower),
            format!(
                "standing grant for {}: {} until {}",
                self.peer_name(borrower),
                rule.describe(),
                rule.until
            ),
            serde_json::json!({
                "standing": true,
                "cpu_millis": rule.cpu_millis,
                "memory_bytes": rule.memory_bytes,
                "disk_bytes": rule.disk_bytes,
                "max_hours": rule.max_hours,
                "until": rule.until,
            }),
        );
        Ok(rule)
    }

    /// Ends the standing grant for `borrower` (no presence: it reduces access) and revokes the
    /// grants it accepted. Returns how many were revoked.
    pub async fn remove_standing_rule(&self, borrower: &PeerKey) -> Result<usize> {
        let had = self
            .state()
            .trust
            .get(borrower)
            .is_some_and(|p| p.standing.is_some());
        if !had {
            bail!("there is no standing grant for that device");
        }
        self.state().trust.set_standing(borrower, None)?;
        let revoked = self.revoke_standing_grants(borrower).await;
        self.audit_best_effort(
            "grant",
            Some(borrower),
            format!(
                "standing grant for {} ended; {revoked} grant(s) it accepted revoked",
                self.peer_name(borrower)
            ),
            serde_json::json!({ "standing": false, "revoked": revoked }),
        );
        Ok(revoked)
    }

    /// Revokes the live grants to `borrower` that a standing grant accepted.
    async fn revoke_standing_grants(&self, borrower: &PeerKey) -> usize {
        let ids: Vec<gimmecores_core::GrantId> = self
            .lent_grants()
            .into_iter()
            .filter(|(id, b, st, ..)| {
                b == borrower
                    && matches!(
                        st,
                        gimmecores_core::GrantState::Active | gimmecores_core::GrantState::Paused
                    )
                    && self.issued_by_rule(*id)
            })
            .map(|(id, ..)| id)
            .collect();
        let mut n = 0;
        for id in ids {
            if self.revoke_grant(id).await.is_ok() {
                n += 1;
            }
        }
        n
    }

    /// Drops rules that lapsed or no longer verify (every 2 s). Grants they accepted run until
    /// their own end (at most 8 hours).
    pub(crate) fn standing_sweep(&self) {
        let t = now();
        let stale: Vec<(PeerKey, bool)> = {
            let s = self.state();
            s.trust
                .list()
                .filter_map(|(k, p)| p.standing.as_ref().map(|r| (*k, r.clone())))
                .filter_map(|(k, r)| {
                    let valid = self.verify_rule(&k, &r);
                    (!valid || r.rule.until <= t).then_some((k, valid))
                })
                .collect()
        };
        for (peer, valid) in stale {
            let _ = self.state().trust.set_standing(&peer, None);
            self.audit_best_effort(
                "grant",
                Some(&peer),
                if valid {
                    format!("standing grant for {} lapsed", self.peer_name(&peer))
                } else {
                    format!(
                        "standing grant for {} removed: its signature does not verify",
                        self.peer_name(&peer)
                    )
                },
                serde_json::json!({ "standing": false }),
            );
        }
    }

    /// Test-only: moves a standing grant's lapse time (re-signed), to see it lapse.
    #[cfg(feature = "insecure-test-executor")]
    pub fn set_standing_until(&self, borrower: &PeerKey, until: UnixSeconds) -> Result<()> {
        let mut rule = self
            .state()
            .trust
            .get(borrower)
            .and_then(|p| p.standing.clone())
            .context("no standing grant")?
            .rule;
        rule.until = until;
        let signed = self.sign_rule(borrower, rule)?;
        self.state().trust.set_standing(borrower, Some(signed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gimmecores_core::Limits;

    const NOW: UnixSeconds = 1_800_000_000;

    fn terms(cores: u32, gib: u64, hours: u64) -> GrantTerms {
        GrantTerms {
            limits: Limits {
                cpu_millis: cores * 1000,
                memory_bytes: gib << 30,
                disk_bytes: 10 << 30,
                gpu: Gpu::None,
                max_concurrent_tasks: cores,
            },
            not_after: NOW + hours * 3600,
            modes: Modes::CONTAINER.with(gimmecores_core::ExecutionMode::Sandbox),
            network: NetworkPolicy::None,
            trust: TrustLevel::Standard,
            speed: None,
            images_bytes: 0,
        }
    }

    fn rule() -> StandingRule {
        let mut t = terms(4, 8, 8);
        t.modes = Modes::NONE.with(gimmecores_core::ExecutionMode::Sandbox);
        StandingRule::new(&t, 8, NOW).unwrap()
    }

    #[test]
    fn requests_within_every_limit_are_covered_and_get_only_the_allowed_ways() {
        let got = rule()
            .covers(&terms(2, 4, 2), Speed::AppsFirst, NOW)
            .unwrap();
        assert_eq!(
            got.modes,
            Modes::NONE.with(gimmecores_core::ExecutionMode::Sandbox)
        );
        assert_eq!(got.limits, terms(2, 4, 2).limits, "nothing else changes");
        assert!(
            rule()
                .covers(&terms(4, 8, 8), Speed::AppsFirst, NOW)
                .is_some()
        );
    }

    #[test]
    fn anything_beyond_a_limit_goes_to_the_owner() {
        let r = rule();
        let s = Speed::AppsFirst;
        assert!(r.covers(&terms(5, 4, 2), s, NOW).is_none(), "cores");
        assert!(r.covers(&terms(2, 9, 2), s, NOW).is_none(), "memory");
        assert!(
            r.covers(&terms(2, 4, 9), s, NOW).is_none(),
            "longer than 8 h"
        );
        let mut t = terms(2, 4, 2);
        t.limits.disk_bytes = 11 << 30;
        assert!(r.covers(&t, s, NOW).is_none(), "disk");
        let mut t = terms(2, 4, 2);
        t.trust = TrustLevel::Trusted;
        assert!(r.covers(&t, s, NOW).is_none(), "Trusted always asks");
        let mut t = terms(2, 4, 2);
        t.images_bytes = 1;
        assert!(r.covers(&t, s, NOW).is_none(), "images not included");
        let mut t = terms(2, 4, 2);
        t.speed = Some(Speed::Full);
        assert!(
            r.covers(&t, s, NOW).is_none(),
            "faster than the owner's setting"
        );
        t.speed = Some(Speed::AppsFirst);
        assert!(r.covers(&t, s, NOW).is_some(), "the owner's own level");
        let mut t = terms(2, 4, 2);
        t.modes = Modes::CONTAINER;
        assert!(r.covers(&t, s, NOW).is_none(), "no way of running left");
        let mut t = terms(2, 4, 2);
        t.limits.gpu = Gpu::Metal;
        assert!(r.covers(&t, s, NOW).is_none(), "GPU");
        let mut t = terms(2, 4, 2);
        t.limits.max_concurrent_tasks = 9;
        assert!(
            r.covers(&t, s, NOW).is_none(),
            "more tasks at once than cores"
        );
    }

    #[test]
    fn a_rule_lapses_after_30_days_and_never_grants_more_than_8_hours() {
        let r = rule();
        assert_eq!(r.until, NOW + 30 * 86_400);
        let late = r.until;
        let mut t = terms(2, 4, 1);
        t.not_after = late + 3600;
        assert!(r.covers(&t, Speed::AppsFirst, late).is_none());
        assert_eq!(
            StandingRule::new(&terms(1, 1, 1), 24, NOW)
                .unwrap()
                .max_hours,
            8
        );
        assert_eq!(
            StandingRule::new(&terms(1, 1, 1), 0, NOW)
                .unwrap()
                .max_hours,
            1
        );
    }

    #[test]
    fn a_rule_naming_full_speed_approves_it() {
        let mut t = terms(4, 8, 8);
        t.speed = Some(Speed::Full);
        let r = StandingRule::new(&t, 8, NOW).unwrap();
        let mut asked = terms(2, 4, 2);
        asked.speed = Some(Speed::Full);
        assert!(r.covers(&asked, Speed::Background, NOW).is_some());
    }

    #[test]
    fn no_rule_for_trusted_grants() {
        let mut t = terms(1, 1, 1);
        t.trust = TrustLevel::Trusted;
        assert!(StandingRule::new(&t, 8, NOW).is_err());
    }
}
