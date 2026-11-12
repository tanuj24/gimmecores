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

impl PeerKey {
    /// Human-readable fingerprint: first 16 bytes of `SHA-256(key)`, base32 (RFC 4648, no
    /// padding), grouped by four: `K7QX-2M4P-…`. Shown on pairing and consent screens.
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(self.0).into();
        let b32 = base32(&digest[..16]);
        b32.as_bytes()
            .chunks(4)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("-")
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

fn base32(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_matches_rfc4648_vectors() {
        // RFC 4648 section 10 (without padding).
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"fo"), "MZXQ");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn fingerprint_shape() {
        let fp = PeerKey([7; 32]).fingerprint();
        // 16 bytes -> 26 base32 chars -> 7 groups.
        assert_eq!(fp.len(), 26 + 6);
        assert_eq!(fp.split('-').count(), 7);
        assert_ne!(fp, PeerKey([8; 32]).fingerprint());
        // Cross-checked with Python: base64.b32encode(sha256(bytes([7]*32))[:16])
        assert_eq!(fp, "JOYG-7DSO-HJ3R-LUQB-2VZ5-BKSC-G4");
    }
}
