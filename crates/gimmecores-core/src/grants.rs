//! The lender's grant book: grant lifecycle plus the checks every task and blob transfer must
//! pass (threat model I1, I3, I14).
//!
//! Only the lender's own book is authoritative. Consent-increasing calls (`lender_accept`,
//! `lender_offer`, `resume`) must only be reachable from the Control API after OS-verified user
//! presence (I13); that check lives in the daemon, not here.

use std::collections::{BTreeMap, BTreeSet};

use crate::types::{
    Denied, ExecutionMode, Gpu, GrantId, GrantState, GrantTerms, NetworkPolicy, PeerKey, TaskId,
    TaskRequest, UnixSeconds,
};

/// Longest a grant may last (30 days).
pub const MAX_GRANT_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    #[error("unknown grant")]
    Unknown,
    #[error("grant id already used")]
    Duplicate,
    #[error("cannot {action} a grant in state {from:?}")]
    InvalidTransition {
        action: &'static str,
        from: GrantState,
    },
    #[error("invalid grant terms: {0}")]
    InvalidTerms(&'static str),
}

#[derive(Debug)]
struct Entry {
    borrower: PeerKey,
    state: GrantState,
    terms: GrantTerms,
    running: BTreeMap<TaskId, TaskRequest>,
}

/// All grants this device has issued as a lender.
#[derive(Debug, Default)]
pub struct GrantBook {
    grants: BTreeMap<GrantId, Entry>,
    task_owner: BTreeMap<TaskId, GrantId>,
    /// Task IDs are single-use for the lifetime of the book (replay protection).
    seen_tasks: BTreeSet<TaskId>,
}

fn validate(terms: &GrantTerms, now: UnixSeconds) -> Result<(), GrantError> {
    let l = &terms.limits;
    if l.cpu_millis == 0 || l.memory_bytes == 0 || l.max_concurrent_tasks == 0 {
        return Err(GrantError::InvalidTerms(
            "cpu, memory and concurrency must be positive",
        ));
    }
    if terms.not_after <= now {
        return Err(GrantError::InvalidTerms("expiry must be in the future"));
    }
    if terms.not_after - now > MAX_GRANT_SECONDS {
        return Err(GrantError::InvalidTerms("grants may last at most 30 days"));
    }
    if terms.modes.is_empty() {
        return Err(GrantError::InvalidTerms(
            "a grant must allow at least one way to run tasks",
        ));
    }
    if l.gpu == Gpu::Metal && !terms.modes.native {
        return Err(GrantError::InvalidTerms(
            "Metal GPU access requires native mode",
        ));
    }
    Ok(())
}

impl GrantBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state(&self, id: GrantId) -> Option<GrantState> {
        self.grants.get(&id).map(|e| e.state)
    }

    /// Every grant in the book: id, borrower, state, terms, running task count.
    pub fn list(&self) -> Vec<(GrantId, PeerKey, GrantState, GrantTerms, usize)> {
        self.grants
            .iter()
            .map(|(id, e)| (*id, e.borrower, e.state, e.terms.clone(), e.running.len()))
            .collect()
    }

    /// The terms of a grant (used for quotas and timeouts).
    pub fn terms(&self, id: GrantId) -> Option<&GrantTerms> {
        self.grants.get(&id).map(|e| &e.terms)
    }

    /// Who a grant was issued to.
    pub fn borrower(&self, id: GrantId) -> Option<PeerKey> {
        self.grants.get(&id).map(|e| e.borrower)
    }

    pub fn running_tasks(&self, id: GrantId) -> usize {
        self.grants.get(&id).map_or(0, |e| e.running.len())
    }

    /// A borrower asked for resources. Nothing is usable yet.
    pub fn request(
        &mut self,
        id: GrantId,
        borrower: PeerKey,
        wanted: GrantTerms,
        now: UnixSeconds,
    ) -> Result<(), GrantError> {
        if self.grants.contains_key(&id) {
            return Err(GrantError::Duplicate);
        }
        validate(&wanted, now)?;
        self.grants.insert(
            id,
            Entry {
                borrower,
                state: GrantState::Requested,
                terms: wanted,
                running: BTreeMap::new(),
            },
        );
        Ok(())
    }

    fn entry_mut(&mut self, id: GrantId) -> Result<&mut Entry, GrantError> {
        self.grants.get_mut(&id).ok_or(GrantError::Unknown)
    }

    /// Lender accepts a request, possibly with reduced terms. [I13: user presence required]
    pub fn lender_accept(
        &mut self,
        id: GrantId,
        terms: GrantTerms,
        now: UnixSeconds,
    ) -> Result<(), GrantError> {
        validate(&terms, now)?;
        let e = self.entry_mut(id)?;
        if e.state != GrantState::Requested {
            return Err(GrantError::InvalidTransition {
                action: "accept",
                from: e.state,
            });
        }
        e.terms = terms;
        e.state = GrantState::Active;
        Ok(())
    }

    /// Lender proposes different terms; the borrower must accept them. [I13]
    pub fn lender_offer(
        &mut self,
        id: GrantId,
        terms: GrantTerms,
        now: UnixSeconds,
    ) -> Result<(), GrantError> {
        validate(&terms, now)?;
        let e = self.entry_mut(id)?;
        if e.state != GrantState::Requested {
            return Err(GrantError::InvalidTransition {
                action: "offer",
                from: e.state,
            });
        }
        e.terms = terms;
        e.state = GrantState::Offered;
        Ok(())
    }

    /// The borrower accepted the lender's offer.
    pub fn borrower_accept_offer(
        &mut self,
        id: GrantId,
        from: PeerKey,
        now: UnixSeconds,
    ) -> Result<(), GrantError> {
        let e = self.entry_mut(id)?;
        if e.borrower != from {
            return Err(GrantError::Unknown);
        }
        if e.state != GrantState::Offered || e.terms.not_after <= now {
            return Err(GrantError::InvalidTransition {
                action: "accept offer",
                from: e.state,
            });
        }
        e.state = GrantState::Active;
        Ok(())
    }

    pub fn decline(&mut self, id: GrantId) -> Result<(), GrantError> {
        let e = self.entry_mut(id)?;
        if !matches!(e.state, GrantState::Requested | GrantState::Offered) {
            return Err(GrantError::InvalidTransition {
                action: "decline",
                from: e.state,
            });
        }
        e.state = GrantState::Declined;
        Ok(())
    }

    /// Lender busy, on battery or too hot. New tasks are refused; running ones are frozen by
    /// the executor.
    pub fn pause(&mut self, id: GrantId) -> Result<(), GrantError> {
        let e = self.entry_mut(id)?;
        if e.state != GrantState::Active {
            return Err(GrantError::InvalidTransition {
                action: "pause",
                from: e.state,
            });
        }
        e.state = GrantState::Paused;
        Ok(())
    }

    pub fn resume(&mut self, id: GrantId, now: UnixSeconds) -> Result<(), GrantError> {
        let e = self.entry_mut(id)?;
        if e.state != GrantState::Paused || e.terms.not_after <= now {
            return Err(GrantError::InvalidTransition {
                action: "resume",
                from: e.state,
            });
        }
        e.state = GrantState::Active;
        Ok(())
    }

    fn end(e: &mut Entry, to: GrantState) -> Vec<TaskId> {
        e.state = to;
        std::mem::take(&mut e.running).into_keys().collect()
    }

    /// Revoke one grant (either side may). Returns tasks the executor must kill (I3).
    pub fn revoke(&mut self, id: GrantId) -> Result<Vec<TaskId>, GrantError> {
        let e = self.grants.get_mut(&id).ok_or(GrantError::Unknown)?;
        if e.state.is_terminal() {
            return Err(GrantError::InvalidTransition {
                action: "revoke",
                from: e.state,
            });
        }
        let killed = Self::end(e, GrantState::Revoked);
        self.forget_tasks(&killed);
        Ok(killed)
    }

    /// "Stop all lending": revoke every live grant. Returns every task to kill (I3).
    pub fn stop_all(&mut self) -> Vec<TaskId> {
        self.end_where(|e| !e.state.is_terminal(), GrantState::Revoked)
    }

    /// Unpairing a device revokes everything it holds.
    pub fn revoke_peer(&mut self, peer: PeerKey) -> Vec<TaskId> {
        self.end_where(
            |e| e.borrower == peer && !e.state.is_terminal(),
            GrantState::Revoked,
        )
    }

    /// Revoke a peer's Trusted grants (Trusted mode was turned off or lapsed). Returns tasks
    /// to kill.
    pub fn revoke_trusted(&mut self, peer: PeerKey) -> Vec<TaskId> {
        self.end_where(
            |e| {
                e.borrower == peer
                    && !e.state.is_terminal()
                    && e.terms.trust == crate::types::TrustLevel::Trusted
            },
            GrantState::Revoked,
        )
    }

    /// Expire grants whose time is up. Returns tasks to kill.
    pub fn expire_due(&mut self, now: UnixSeconds) -> Vec<TaskId> {
        self.end_where(
            |e| {
                matches!(e.state, GrantState::Active | GrantState::Paused)
                    && e.terms.not_after <= now
            },
            GrantState::Expired,
        )
    }

    fn end_where(&mut self, pred: impl Fn(&Entry) -> bool, to: GrantState) -> Vec<TaskId> {
        let mut killed = Vec::new();
        for e in self.grants.values_mut().filter(|e| pred(e)) {
            killed.extend(Self::end(e, to));
        }
        self.forget_tasks(&killed);
        killed
    }

    fn forget_tasks(&mut self, tasks: &[TaskId]) {
        for t in tasks {
            self.task_owner.remove(t);
        }
    }

    fn active_entry(&self, peer: PeerKey, id: GrantId, now: UnixSeconds) -> Result<&Entry, Denied> {
        // Same answer for "no such grant" and "someone else's grant" (no ID probing).
        let e = self
            .grants
            .get(&id)
            .filter(|e| e.borrower == peer)
            .ok_or(Denied::NoGrant)?;
        if e.state == GrantState::Active && e.terms.not_after <= now {
            return Err(Denied::GrantInactive(GrantState::Expired));
        }
        if e.state != GrantState::Active {
            return Err(Denied::GrantInactive(e.state));
        }
        Ok(e)
    }

    /// I1: authorize and record a task start. Nothing runs unless this returns `Ok`.
    pub fn start_task(
        &mut self,
        peer: PeerKey,
        id: GrantId,
        task: TaskId,
        req: TaskRequest,
        now: UnixSeconds,
    ) -> Result<(), Denied> {
        let e = self.active_entry(peer, id, now)?;
        if self.seen_tasks.contains(&task) {
            return Err(Denied::Invalid);
        }
        if req.cpu_millis == 0 || req.memory_bytes == 0 {
            return Err(Denied::Invalid);
        }
        let t = &e.terms;
        if !t.modes.contains(req.mode) {
            return Err(Denied::ExceedsGrant);
        }
        if req.network == NetworkPolicy::Internet && t.network != NetworkPolicy::Internet {
            return Err(Denied::ExceedsGrant);
        }
        if req.gpu != Gpu::None
            && (req.gpu != t.limits.gpu
                || (req.gpu == Gpu::Metal && req.mode != ExecutionMode::Native))
        {
            return Err(Denied::ExceedsGrant);
        }
        if e.running.len() >= t.limits.max_concurrent_tasks as usize {
            return Err(Denied::ExceedsGrant);
        }
        let cpu_in_use: u64 = e.running.values().map(|r| u64::from(r.cpu_millis)).sum();
        let mem_in_use: u64 = e.running.values().map(|r| r.memory_bytes).sum();
        let cpu_ok = cpu_in_use + u64::from(req.cpu_millis) <= u64::from(t.limits.cpu_millis);
        let mem_ok = mem_in_use
            .checked_add(req.memory_bytes)
            .is_some_and(|m| m <= t.limits.memory_bytes);
        if !cpu_ok || !mem_ok || req.disk_bytes > t.limits.disk_bytes {
            return Err(Denied::ExceedsGrant);
        }

        self.seen_tasks.insert(task);
        self.task_owner.insert(task, id);
        if let Some(e) = self.grants.get_mut(&id) {
            e.running.insert(task, req);
        }
        Ok(())
    }

    /// The executor reports a task ended (any outcome).
    pub fn finish_task(&mut self, task: TaskId) {
        if let Some(id) = self.task_owner.remove(&task)
            && let Some(e) = self.grants.get_mut(&id)
        {
            e.running.remove(&task);
        }
    }

    /// I14: blob transfer requires a live grant `id` from this lender to `peer` (active, or
    /// paused by laptop protections: the grant is still valid, only computing is paused). The
    /// blobs count against that grant's disk quota (enforced by the blob store).
    /// Brings back an active grant saved before a restart. The terms are validated like a new
    /// grant's (expired or over-long grants are refused). Running tasks are not restored: they
    /// ended with the old process.
    pub fn restore(
        &mut self,
        id: GrantId,
        borrower: PeerKey,
        terms: GrantTerms,
        now: UnixSeconds,
    ) -> Result<(), GrantError> {
        validate(&terms, now)?;
        if self.grants.contains_key(&id) {
            return Err(GrantError::Duplicate);
        }
        self.grants.insert(
            id,
            Entry {
                borrower,
                state: GrantState::Active,
                terms,
                running: BTreeMap::new(),
            },
        );
        Ok(())
    }

    /// Whether `peer` holds a grant that may still use stored blobs (Active or Paused and not
    /// expired). When none is left, the lender deletes that borrower's blobs.
    pub fn has_live_grant(&self, peer: PeerKey, now: UnixSeconds) -> bool {
        self.grants.values().any(|e| {
            e.borrower == peer
                && e.terms.not_after > now
                && matches!(e.state, GrantState::Active | GrantState::Paused)
        })
    }

    pub fn authorize_blobs(
        &self,
        peer: PeerKey,
        id: GrantId,
        now: UnixSeconds,
    ) -> Result<(), Denied> {
        let e = self
            .grants
            .get(&id)
            .filter(|e| e.borrower == peer)
            .ok_or(Denied::NoGrant)?;
        if e.terms.not_after <= now {
            return Err(Denied::GrantInactive(GrantState::Expired));
        }
        match e.state {
            GrantState::Active | GrantState::Paused => Ok(()),
            other => Err(Denied::GrantInactive(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Limits, Modes, TrustLevel};

    const NOW: UnixSeconds = 1_800_000_000;
    const HOUR: u64 = 3600;
    const GIB: u64 = 1 << 30;
    const MAYA: PeerKey = PeerKey([1; 32]);
    const EVE: PeerKey = PeerKey([9; 32]);
    const G1: GrantId = GrantId([1; 16]);
    const G2: GrantId = GrantId([2; 16]);

    fn terms() -> GrantTerms {
        GrantTerms {
            limits: Limits {
                cpu_millis: 4000,
                memory_bytes: 8 * GIB,
                disk_bytes: 10 * GIB,
                gpu: Gpu::None,
                max_concurrent_tasks: 2,
            },
            not_after: NOW + 2 * HOUR,
            modes: Modes::CONTAINER,
            network: NetworkPolicy::None,
            trust: TrustLevel::Standard,
        }
    }

    fn req(cpu: u32, mem_gib: u64) -> TaskRequest {
        TaskRequest {
            cpu_millis: cpu,
            memory_bytes: mem_gib * GIB,
            disk_bytes: GIB,
            gpu: Gpu::None,
            mode: ExecutionMode::Container,
            network: NetworkPolicy::None,
        }
    }

    fn task(n: u8) -> TaskId {
        TaskId([n; 16])
    }

    fn active_book() -> GrantBook {
        let mut b = GrantBook::new();
        b.request(G1, MAYA, terms(), NOW).unwrap();
        b.lender_accept(G1, terms(), NOW).unwrap();
        b
    }

    // ---- I1: nothing runs without a valid, accepted, unexpired grant for that exact key ----

    #[test]
    fn i1_requested_but_not_accepted_grant_cannot_run_tasks() {
        let mut b = GrantBook::new();
        b.request(G1, MAYA, terms(), NOW).unwrap();
        assert_eq!(
            b.start_task(MAYA, G1, task(1), req(1000, 1), NOW),
            Err(Denied::GrantInactive(GrantState::Requested))
        );
    }

    #[test]
    fn i1_unknown_and_foreign_grants_look_identical() {
        let mut b = active_book();
        assert_eq!(
            b.start_task(MAYA, G2, task(1), req(1000, 1), NOW),
            Err(Denied::NoGrant)
        );
        assert_eq!(
            b.start_task(EVE, G1, task(1), req(1000, 1), NOW),
            Err(Denied::NoGrant)
        );
    }

    #[test]
    fn i1_expired_grant_is_refused_even_before_expiry_sweep() {
        let mut b = active_book();
        let late = NOW + 2 * HOUR;
        assert_eq!(
            b.start_task(MAYA, G1, task(1), req(1000, 1), late),
            Err(Denied::GrantInactive(GrantState::Expired))
        );
    }

    #[test]
    fn i1_paused_revoked_declined_grants_are_refused() {
        let mut b = active_book();
        b.pause(G1).unwrap();
        assert_eq!(
            b.start_task(MAYA, G1, task(1), req(1000, 1), NOW),
            Err(Denied::GrantInactive(GrantState::Paused))
        );
        b.revoke(G1).unwrap();
        assert_eq!(
            b.start_task(MAYA, G1, task(2), req(1000, 1), NOW),
            Err(Denied::GrantInactive(GrantState::Revoked))
        );
        let mut d = GrantBook::new();
        d.request(G2, MAYA, terms(), NOW).unwrap();
        d.decline(G2).unwrap();
        assert!(d.start_task(MAYA, G2, task(3), req(1000, 1), NOW).is_err());
    }

    #[test]
    fn i1_requests_beyond_the_grant_are_refused() {
        let mut b = active_book();
        let mut native = req(1000, 1);
        native.mode = ExecutionMode::Native;
        let mut sandbox = req(1000, 1);
        sandbox.mode = ExecutionMode::Sandbox;
        let mut online = req(1000, 1);
        online.network = NetworkPolicy::Internet;
        let mut gpu = req(1000, 1);
        gpu.gpu = Gpu::Cuda;
        let mut disk = req(1000, 1);
        disk.disk_bytes = 11 * GIB;
        for (name, r) in [
            ("native", native),
            ("sandbox in a container-only grant", sandbox),
            ("internet", online),
            ("gpu", gpu),
            ("disk", disk),
            ("cpu", req(5000, 1)),
            ("memory", req(1000, 9)),
        ] {
            assert_eq!(
                b.start_task(MAYA, G1, task(1), r, NOW),
                Err(Denied::ExceedsGrant),
                "{name}"
            );
        }
    }

    #[test]
    fn i1_limits_are_totals_across_concurrent_tasks() {
        let mut b = active_book();
        b.start_task(MAYA, G1, task(1), req(3000, 6), NOW).unwrap();
        // 3000 + 2000 > 4000 millicores
        assert_eq!(
            b.start_task(MAYA, G1, task(2), req(2000, 1), NOW),
            Err(Denied::ExceedsGrant)
        );
        // 6 + 3 > 8 GiB
        assert_eq!(
            b.start_task(MAYA, G1, task(3), req(500, 3), NOW),
            Err(Denied::ExceedsGrant)
        );
        b.start_task(MAYA, G1, task(4), req(1000, 2), NOW).unwrap();
        b.finish_task(task(1));
        b.start_task(MAYA, G1, task(6), req(3000, 6), NOW).unwrap();
    }

    #[test]
    fn i1_concurrency_cap_applies_even_when_resources_remain() {
        let mut b = active_book(); // max_concurrent_tasks = 2, 4 cores, 8 GiB
        b.start_task(MAYA, G1, task(1), req(500, 1), NOW).unwrap();
        b.start_task(MAYA, G1, task(2), req(500, 1), NOW).unwrap();
        assert_eq!(
            b.start_task(MAYA, G1, task(3), req(500, 1), NOW),
            Err(Denied::ExceedsGrant)
        );
        b.finish_task(task(2));
        b.start_task(MAYA, G1, task(4), req(500, 1), NOW).unwrap();
    }

    #[test]
    fn zero_sized_task_requests_are_invalid() {
        let mut b = active_book();
        assert_eq!(
            b.start_task(MAYA, G1, task(1), req(0, 1), NOW),
            Err(Denied::Invalid)
        );
        assert_eq!(
            b.start_task(MAYA, G1, task(2), req(1000, 0), NOW),
            Err(Denied::Invalid)
        );
    }

    #[test]
    fn task_ids_are_single_use() {
        let mut b = active_book();
        b.start_task(MAYA, G1, task(1), req(1000, 1), NOW).unwrap();
        b.finish_task(task(1));
        assert_eq!(
            b.start_task(MAYA, G1, task(1), req(1000, 1), NOW),
            Err(Denied::Invalid)
        );
    }

    // ---- I3: revoke / stop all / expiry / unpair end every running task ----

    #[test]
    fn i3_revoke_returns_every_running_task_and_frees_capacity() {
        let mut b = active_book();
        b.start_task(MAYA, G1, task(1), req(1000, 1), NOW).unwrap();
        b.start_task(MAYA, G1, task(2), req(1000, 1), NOW).unwrap();
        let mut killed = b.revoke(G1).unwrap();
        killed.sort();
        assert_eq!(killed, vec![task(1), task(2)]);
        assert_eq!(b.running_tasks(G1), 0);
        assert_eq!(b.state(G1), Some(GrantState::Revoked));
        assert!(b.revoke(G1).is_err(), "revoked is terminal");
    }

    #[test]
    fn i3_stop_all_lending_revokes_everything_live() {
        let mut b = active_book();
        b.request(G2, EVE, terms(), NOW).unwrap();
        b.start_task(MAYA, G1, task(1), req(1000, 1), NOW).unwrap();
        assert_eq!(b.stop_all(), vec![task(1)]);
        assert_eq!(b.state(G1), Some(GrantState::Revoked));
        assert_eq!(b.state(G2), Some(GrantState::Revoked));
    }

    #[test]
    fn i3_expiry_and_unpair_end_running_tasks() {
        let mut b = active_book();
        b.start_task(MAYA, G1, task(1), req(1000, 1), NOW).unwrap();
        assert!(b.expire_due(NOW + HOUR).is_empty());
        assert_eq!(b.expire_due(NOW + 2 * HOUR), vec![task(1)]);
        assert_eq!(b.state(G1), Some(GrantState::Expired));

        let mut c = active_book();
        c.start_task(MAYA, G1, task(2), req(1000, 1), NOW).unwrap();
        assert_eq!(c.revoke_peer(MAYA), vec![task(2)]);
        assert_eq!(c.state(G1), Some(GrantState::Revoked));
    }

    // ---- I14: blobs need an active grant for that exact peer ----

    #[test]
    fn i14_blob_transfer_requires_an_active_grant() {
        let mut b = GrantBook::new();
        b.request(G1, MAYA, terms(), NOW).unwrap();
        assert!(b.authorize_blobs(MAYA, G1, NOW).is_err(), "requested only");
        b.lender_accept(G1, terms(), NOW).unwrap();
        assert!(b.authorize_blobs(MAYA, G1, NOW).is_ok());
        assert_eq!(b.authorize_blobs(EVE, G1, NOW), Err(Denied::NoGrant));
        assert!(
            b.authorize_blobs(MAYA, G1, NOW + 2 * HOUR).is_err(),
            "expired"
        );
        b.pause(G1).unwrap();
        assert!(
            b.authorize_blobs(MAYA, G1, NOW).is_ok(),
            "paused grants stay valid for uploads"
        );
        b.revoke(G1).unwrap();
        assert!(b.authorize_blobs(MAYA, G1, NOW).is_err(), "revoked");
    }

    // ---- lifecycle and term validation ----

    #[test]
    fn offers_need_the_borrower_to_accept() {
        let mut b = GrantBook::new();
        b.request(G1, MAYA, terms(), NOW).unwrap();
        b.lender_offer(G1, terms(), NOW).unwrap();
        assert!(b.start_task(MAYA, G1, task(1), req(1000, 1), NOW).is_err());
        assert_eq!(
            b.borrower_accept_offer(G1, EVE, NOW),
            Err(GrantError::Unknown)
        );
        b.borrower_accept_offer(G1, MAYA, NOW).unwrap();
        b.start_task(MAYA, G1, task(1), req(1000, 1), NOW).unwrap();
    }

    #[test]
    fn invalid_terms_are_rejected() {
        let mut b = GrantBook::new();
        let mut t = terms();
        t.not_after = NOW + MAX_GRANT_SECONDS + 1;
        assert!(b.request(G1, MAYA, t, NOW).is_err(), "too long");
        let mut t = terms();
        t.not_after = NOW;
        assert!(b.request(G1, MAYA, t, NOW).is_err(), "already expired");
        let mut t = terms();
        t.limits.gpu = Gpu::Metal;
        assert!(b.request(G1, MAYA, t, NOW).is_err(), "metal without native");
        let mut t = terms();
        t.limits.cpu_millis = 0;
        assert!(b.request(G1, MAYA, t, NOW).is_err(), "zero cpu");
        b.request(G1, MAYA, terms(), NOW).unwrap();
        assert_eq!(
            b.request(G1, MAYA, terms(), NOW),
            Err(GrantError::Duplicate)
        );
    }

    #[test]
    fn live_grant_means_active_or_paused_and_unexpired() {
        let mut b = GrantBook::new();
        b.request(G1, MAYA, terms(), NOW).unwrap();
        assert!(!b.has_live_grant(MAYA, NOW), "a request is not live");
        b.lender_accept(G1, terms(), NOW).unwrap();
        assert!(b.has_live_grant(MAYA, NOW));
        assert!(
            !b.has_live_grant(EVE, NOW),
            "only the borrower's own grants count"
        );
        b.pause(G1).unwrap();
        assert!(
            b.has_live_grant(MAYA, NOW),
            "paused grants keep their files"
        );
        assert!(
            !b.has_live_grant(MAYA, NOW + 2 * HOUR),
            "expired, even before the sweep"
        );
        b.revoke(G1).unwrap();
        assert!(!b.has_live_grant(MAYA, NOW));
    }

    #[test]
    fn tasks_run_only_in_a_mode_the_grant_allows() {
        let mut t = terms();
        t.modes = Modes::only(ExecutionMode::Sandbox);
        let mut b = GrantBook::new();
        b.request(G1, MAYA, t.clone(), NOW).unwrap();
        b.lender_accept(G1, t, NOW).unwrap();
        let mut sandbox = req(1000, 1);
        sandbox.mode = ExecutionMode::Sandbox;
        b.start_task(MAYA, G1, task(1), sandbox, NOW).unwrap();
        assert_eq!(
            b.start_task(MAYA, G1, task(2), req(1000, 1), NOW),
            Err(Denied::ExceedsGrant),
            "container task in a sandbox-only grant"
        );
    }

    #[test]
    fn a_grant_must_allow_some_mode() {
        let mut t = terms();
        t.modes = Modes::NONE;
        assert!(GrantBook::new().request(G1, MAYA, t, NOW).is_err());
    }

    #[test]
    fn restored_grants_are_active_and_validated() {
        let mut b = GrantBook::new();
        b.restore(G1, MAYA, terms(), NOW).unwrap();
        assert_eq!(b.state(G1), Some(GrantState::Active));
        b.start_task(MAYA, G1, task(1), req(1000, 1), NOW).unwrap();
        assert_eq!(
            b.restore(G1, MAYA, terms(), NOW),
            Err(GrantError::Duplicate)
        );
        assert!(
            b.restore(G2, MAYA, terms(), NOW + 2 * HOUR).is_err(),
            "an expired grant is not restored"
        );
    }

    #[test]
    fn modes_set_operations() {
        let both = Modes::CONTAINER.with(ExecutionMode::Sandbox);
        assert!(Modes::CONTAINER.is_subset_of(both));
        assert!(!both.is_subset_of(Modes::CONTAINER));
        assert_eq!(
            both.intersect(Modes::only(ExecutionMode::Sandbox)),
            Modes::only(ExecutionMode::Sandbox)
        );
        assert_eq!(
            both.iter().collect::<Vec<_>>(),
            [ExecutionMode::Container, ExecutionMode::Sandbox]
        );
        assert!(Modes::NONE.is_empty());
    }

    #[test]
    fn paused_grant_cannot_resume_after_expiry() {
        let mut b = active_book();
        b.pause(G1).unwrap();
        assert!(b.resume(G1, NOW + 2 * HOUR).is_err());
        b.resume(G1, NOW).unwrap();
        assert_eq!(b.state(G1), Some(GrantState::Active));
    }
}
