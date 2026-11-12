//! Core value types.

use std::fmt;

/// A device's Ed25519 public key (its identity on every connection).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerKey(pub [u8; 32]);

impl fmt::Debug for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PeerKey({:02x}{:02x}{:02x}{:02x}…)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

/// Random 128-bit grant identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GrantId(pub [u8; 16]);

/// Random 128-bit, single-use task identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TaskId(pub [u8; 16]);

/// Seconds since the Unix epoch. Always supplied by the caller.
pub type UnixSeconds = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gpu {
    None,
    Cuda,
    Metal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionMode {
    Container,
    Native,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// No network while running (default).
    None,
    /// Internet egress only; lender LAN and localhost blocked (from M4).
    Internet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustLevel {
    Standard,
    Trusted,
}

/// Resource amounts. In a grant they are totals across all concurrent tasks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// 1000 = one CPU core.
    pub cpu_millis: u32,
    /// Hard RAM cap, no swap.
    pub memory_bytes: u64,
    pub disk_bytes: u64,
    pub gpu: Gpu,
    pub max_concurrent_tasks: u32,
}

/// What a lender agreed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantTerms {
    pub limits: Limits,
    pub not_after: UnixSeconds,
    pub allow_native: bool,
    pub network: NetworkPolicy,
    pub trust: TrustLevel,
}

/// Lifecycle of a grant (docs/design/consent-and-grants.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantState {
    Requested,
    Offered,
    Active,
    Paused,
    Expired,
    Revoked,
    Declined,
}

impl GrantState {
    /// Expired, revoked and declined grants can never become usable again.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Expired | Self::Revoked | Self::Declined)
    }
}

/// What a borrower asks to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskRequest {
    pub cpu_millis: u32,
    pub memory_bytes: u64,
    pub disk_bytes: u64,
    pub gpu: Gpu,
    pub mode: ExecutionMode,
    pub network: NetworkPolicy,
}

/// Why a request was refused. Maps onto `peer.v1.Error.Code`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denied {
    /// Sender is not paired with this device.
    NotPaired,
    /// Sender is not paired and pairing mode is closed.
    PairingClosed,
    /// No grant with that ID was issued to this sender. Deliberately the same answer whether
    /// the grant does not exist or belongs to someone else, so IDs cannot be probed.
    NoGrant,
    /// The grant exists but is not active (paused, expired, revoked, …).
    GrantInactive(GrantState),
    /// The request asks for more than the grant allows.
    ExceedsGrant,
    /// The message is not valid in this context.
    Invalid,
}
