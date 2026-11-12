//! Pairing: commit-then-reveal short authentication string (docs/design/pairing.md).
//!
//! Pure logic only. The caller supplies nonces (from the OS random generator), the current
//! time, and both public keys as authenticated by the TLS connection. Device A ("initiator")
//! starts pairing; device B ("responder") must have its pairing window open (I2).

use std::fmt;

use sha2::{Digest, Sha256};

use crate::types::{PeerKey, UnixSeconds};

pub const COMMIT_LABEL: &[u8] = b"gimmecores-pair-commit-v1";
pub const SAS_LABEL: &[u8] = b"gimmecores-pair-sas-v1";
/// How long pairing mode stays open after the user opens it.
pub const WINDOW_SECONDS: u64 = 120;
/// Pairing attempts allowed per window.
pub const MAX_ATTEMPTS: u8 = 3;

pub type Nonce = [u8; 32];

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// `SHA-256("gimmecores-pair-commit-v1" ‖ nonce)`.
pub fn commitment(nonce: &Nonce) -> [u8; 32] {
    sha256(&[COMMIT_LABEL, nonce])
}

/// The 6-digit code both users compare.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ShortCode(u32);

impl ShortCode {
    pub fn value(self) -> u32 {
        self.0
    }
}

impl fmt::Display for ShortCode {
    /// Always six digits, grouped for reading aloud: `004 894`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:03} {:03}", self.0 / 1000, self.0 % 1000)
    }
}

/// `SHA-256("gimmecores-pair-sas-v1" ‖ pkA ‖ pkB ‖ nA ‖ nB)`, first 4 bytes big-endian, mod 10⁶.
pub fn short_code(
    initiator: &PeerKey,
    responder: &PeerKey,
    initiator_nonce: &Nonce,
    responder_nonce: &Nonce,
) -> ShortCode {
    let d = sha256(&[
        SAS_LABEL,
        &initiator.0,
        &responder.0,
        initiator_nonce,
        responder_nonce,
    ]);
    ShortCode(u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000)
}

/// Secret shared by two paired devices for discovery (never sent; both compute it):
/// `SHA-256("gimmecores-discovery-v1" ‖ pkA ‖ pkB ‖ nA ‖ nB)`. The nonces travel only inside
/// the encrypted pairing connection, and a man in the middle would have failed the code check.
pub fn discovery_key(
    initiator: &PeerKey,
    responder: &PeerKey,
    initiator_nonce: &Nonce,
    responder_nonce: &Nonce,
) -> [u8; 32] {
    sha256(&[
        b"gimmecores-discovery-v1",
        &initiator.0,
        &responder.0,
        initiator_nonce,
        responder_nonce,
    ])
}

/// Length of one rotating-identifier window (seconds).
pub const ROTATION_SECONDS: u64 = 15 * 60;

/// The identifier a device advertises to one paired peer during the window holding `now`:
/// 16 bytes that look random to everyone else and change every [`ROTATION_SECONDS`].
/// `advertiser` tells the two directions apart.
pub fn rotating_id(key: &[u8; 32], advertiser: &PeerKey, now: UnixSeconds) -> [u8; 16] {
    let window = (now / ROTATION_SECONDS).to_be_bytes();
    let d = sha256(&[b"gimmecores-rid-v1", key, &advertiser.0, &window]);
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PairingError {
    #[error("pairing mode is not open on this device")]
    WindowClosed,
    #[error("too many pairing attempts; reopen pairing mode")]
    TooManyAttempts,
    #[error("pairing message out of order")]
    UnexpectedMessage,
    #[error("the revealed nonce does not match the commitment")]
    CommitmentMismatch,
    #[error("pairing was rejected")]
    Rejected,
}

/// The responder's pairing mode, opened explicitly by the local user (I2).
#[derive(Debug, Default)]
pub struct PairingWindow {
    opened_at: Option<UnixSeconds>,
    attempts: u8,
}

impl PairingWindow {
    pub fn closed() -> Self {
        Self::default()
    }

    /// The local user opened pairing mode.
    pub fn open(&mut self, now: UnixSeconds) {
        self.opened_at = Some(now);
        self.attempts = 0;
    }

    pub fn close(&mut self) {
        self.opened_at = None;
    }

    pub fn is_open(&self, now: UnixSeconds) -> bool {
        self.opened_at
            .is_some_and(|t| now < t.saturating_add(WINDOW_SECONDS))
            && self.attempts < MAX_ATTEMPTS
    }

    fn begin_attempt(&mut self, now: UnixSeconds) -> Result<(), PairingError> {
        if self
            .opened_at
            .is_none_or(|t| now >= t.saturating_add(WINDOW_SECONDS))
        {
            return Err(PairingError::WindowClosed);
        }
        if self.attempts >= MAX_ATTEMPTS {
            return Err(PairingError::TooManyAttempts);
        }
        self.attempts += 1;
        Ok(())
    }
}

/// Device A: starts pairing with a device it discovered or was given an address for.
#[derive(Debug)]
pub struct Initiator {
    me: PeerKey,
    peer: PeerKey,
    nonce: Nonce,
    revealed: bool,
    responder_nonce: Option<Nonce>,
}

impl Initiator {
    /// Returns the session and the commitment to send in `PairRequest`.
    pub fn start(me: PeerKey, peer: PeerKey, nonce: Nonce) -> (Self, [u8; 32]) {
        let c = commitment(&nonce);
        (
            Self {
                me,
                peer,
                nonce,
                revealed: false,
                responder_nonce: None,
            },
            c,
        )
    }

    /// On `PairChallenge`: returns the nonce to send in `PairReveal` and the code to show.
    pub fn on_challenge(
        &mut self,
        responder_nonce: &Nonce,
    ) -> Result<(Nonce, ShortCode), PairingError> {
        if self.revealed {
            return Err(PairingError::UnexpectedMessage);
        }
        self.revealed = true;
        self.responder_nonce = Some(*responder_nonce);
        let code = short_code(&self.me, &self.peer, &self.nonce, responder_nonce);
        Ok((self.nonce, code))
    }

    /// The pair's discovery key, once the challenge was answered.
    pub fn discovery_key(&self) -> Option<[u8; 32]> {
        self.responder_nonce
            .map(|rn| discovery_key(&self.me, &self.peer, &self.nonce, &rn))
    }
}

/// Device B: answers a pairing request while its window is open.
#[derive(Debug)]
pub struct Responder {
    me: PeerKey,
    peer: PeerKey,
    nonce: Nonce,
    commitment: [u8; 32],
    done: bool,
    initiator_nonce: Option<Nonce>,
}

impl Responder {
    /// On `PairRequest`: returns the session and the nonce to send in `PairChallenge`.
    /// Counts as one attempt against the window.
    pub fn on_request(
        window: &mut PairingWindow,
        now: UnixSeconds,
        me: PeerKey,
        peer: PeerKey,
        commitment: [u8; 32],
        nonce: Nonce,
    ) -> Result<(Self, Nonce), PairingError> {
        window.begin_attempt(now)?;
        Ok((
            Self {
                me,
                peer,
                nonce,
                commitment,
                done: false,
                initiator_nonce: None,
            },
            nonce,
        ))
    }

    /// On `PairReveal`: checks the commitment and returns the code to show.
    /// A mismatch closes the window, so the user must reopen pairing mode.
    pub fn on_reveal(
        &mut self,
        window: &mut PairingWindow,
        initiator_nonce: &Nonce,
    ) -> Result<ShortCode, PairingError> {
        if self.done {
            return Err(PairingError::UnexpectedMessage);
        }
        self.done = true;
        if commitment(initiator_nonce) != self.commitment {
            window.close();
            return Err(PairingError::CommitmentMismatch);
        }
        self.initiator_nonce = Some(*initiator_nonce);
        // Key order is always (initiator, responder) on both sides.
        Ok(short_code(
            &self.peer,
            &self.me,
            initiator_nonce,
            &self.nonce,
        ))
    }
}

impl Responder {
    /// The pair's discovery key, once the initiator's nonce was revealed and checked.
    pub fn discovery_key(&self) -> Option<[u8; 32]> {
        self.initiator_nonce
            .map(|n| discovery_key(&self.peer, &self.me, &n, &self.nonce))
    }
}

/// Both users must confirm that the codes match. One "no" from either side rejects.
#[derive(Debug, Default)]
pub struct Confirmation {
    local: Option<bool>,
    remote: Option<bool>,
}

impl Confirmation {
    pub fn set_local(&mut self, codes_match: bool) {
        self.local = Some(codes_match);
    }

    pub fn set_remote(&mut self, accepted: bool) {
        self.remote = Some(accepted);
    }

    /// `None` while waiting; `Some(Ok(()))` only when both sides confirmed.
    pub fn outcome(&self) -> Option<Result<(), PairingError>> {
        match (self.local, self.remote) {
            (Some(false), _) | (_, Some(false)) => Some(Err(PairingError::Rejected)),
            (Some(true), Some(true)) => Some(Ok(())),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shared test vectors (also in docs/design/pairing.md), computed independently in Python.
    fn pk_a() -> PeerKey {
        PeerKey(std::array::from_fn(|i| i as u8))
    }
    fn pk_b() -> PeerKey {
        PeerKey(std::array::from_fn(|i| (i + 32) as u8))
    }
    const N_A: Nonce = [0xA1; 32];
    const N_B: Nonce = [0xB2; 32];
    const T0: UnixSeconds = 1_800_000_000;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn vector_commitment() {
        assert_eq!(
            hex(&commitment(&N_A)),
            "39fdad7668f8c557b9557b9c0e98db8aa7996ec2668c9e1d9832e10a7f89b2ce"
        );
    }

    #[test]
    fn vector_short_code_keeps_leading_zeros() {
        let code = short_code(&pk_a(), &pk_b(), &N_A, &N_B);
        assert_eq!(code.value(), 4894);
        assert_eq!(code.to_string(), "004 894");
    }

    #[test]
    fn vector_key_order_matters() {
        assert_eq!(short_code(&pk_b(), &pk_a(), &N_A, &N_B).value(), 309_733);
    }

    #[test]
    fn both_sides_derive_the_same_discovery_key_and_ids_rotate() {
        let mut window = PairingWindow::closed();
        window.open(0);
        let (mut a, c) = Initiator::start(pk_a(), pk_b(), [1; 32]);
        let (mut b, bn) =
            Responder::on_request(&mut window, 0, pk_b(), pk_a(), c, [2; 32]).unwrap();
        assert!(a.discovery_key().is_none());
        let (an, _) = a.on_challenge(&bn).unwrap();
        b.on_reveal(&mut window, &an).unwrap();
        let k = a.discovery_key().unwrap();
        assert_eq!(Some(k), b.discovery_key());
        let t = 1_800_000_000;
        assert_eq!(rotating_id(&k, &pk_a(), t), rotating_id(&k, &pk_a(), t + 1));
        assert_ne!(
            rotating_id(&k, &pk_a(), t),
            rotating_id(&k, &pk_a(), t + ROTATION_SECONDS),
            "changes every window"
        );
        assert_ne!(
            rotating_id(&k, &pk_a(), t),
            rotating_id(&k, &pk_b(), t),
            "each direction differs"
        );
        assert_ne!(
            rotating_id(&k, &pk_a(), t),
            rotating_id(&[9; 32], &pk_a(), t),
            "unrelated without the key"
        );
    }

    #[test]
    fn happy_path_both_sides_show_the_same_code() {
        let mut window = PairingWindow::closed();
        window.open(T0);
        let (mut a, c) = Initiator::start(pk_a(), pk_b(), N_A);
        let (mut b, n_b) = Responder::on_request(&mut window, T0 + 5, pk_b(), pk_a(), c, N_B)
            .expect("window open");
        let (n_a, code_a) = a.on_challenge(&n_b).unwrap();
        let code_b = b.on_reveal(&mut window, &n_a).unwrap();
        assert_eq!(code_a, code_b);
        assert_eq!(code_a.to_string(), "004 894");
    }

    #[test]
    fn i2_closed_or_expired_window_refuses_pairing() {
        let mut window = PairingWindow::closed();
        let c = commitment(&N_A);
        assert_eq!(
            Responder::on_request(&mut window, T0, pk_b(), pk_a(), c, N_B).unwrap_err(),
            PairingError::WindowClosed
        );
        window.open(T0);
        assert!(window.is_open(T0 + WINDOW_SECONDS - 1));
        assert_eq!(
            Responder::on_request(&mut window, T0 + WINDOW_SECONDS, pk_b(), pk_a(), c, N_B)
                .unwrap_err(),
            PairingError::WindowClosed
        );
    }

    #[test]
    fn at_most_three_attempts_per_window() {
        let mut window = PairingWindow::closed();
        window.open(T0);
        let c = commitment(&N_A);
        for _ in 0..MAX_ATTEMPTS {
            Responder::on_request(&mut window, T0, pk_b(), pk_a(), c, N_B).unwrap();
        }
        assert_eq!(
            Responder::on_request(&mut window, T0, pk_b(), pk_a(), c, N_B).unwrap_err(),
            PairingError::TooManyAttempts
        );
        assert!(!window.is_open(T0));
        window.open(T0 + 10); // the user reopens pairing mode
        assert!(window.is_open(T0 + 10));
    }

    #[test]
    fn a_changed_nonce_after_seeing_the_challenge_is_caught_and_closes_the_window() {
        // A man-in-the-middle cannot pick its nonce after seeing nB: the commitment binds it.
        let mut window = PairingWindow::closed();
        window.open(T0);
        let (mut b, _) =
            Responder::on_request(&mut window, T0, pk_b(), pk_a(), commitment(&N_A), N_B).unwrap();
        let forged = [0x00; 32];
        assert_eq!(
            b.on_reveal(&mut window, &forged).unwrap_err(),
            PairingError::CommitmentMismatch
        );
        assert!(!window.is_open(T0), "mismatch must close pairing mode");
    }

    #[test]
    fn messages_cannot_be_replayed_within_a_session() {
        let mut window = PairingWindow::closed();
        window.open(T0);
        let (mut a, c) = Initiator::start(pk_a(), pk_b(), N_A);
        let (mut b, n_b) = Responder::on_request(&mut window, T0, pk_b(), pk_a(), c, N_B).unwrap();
        let (n_a, _) = a.on_challenge(&n_b).unwrap();
        assert_eq!(
            a.on_challenge(&n_b).unwrap_err(),
            PairingError::UnexpectedMessage
        );
        b.on_reveal(&mut window, &n_a).unwrap();
        assert_eq!(
            b.on_reveal(&mut window, &n_a).unwrap_err(),
            PairingError::UnexpectedMessage
        );
    }

    #[test]
    fn both_users_must_confirm() {
        let mut c = Confirmation::default();
        assert_eq!(c.outcome(), None);
        c.set_local(true);
        assert_eq!(c.outcome(), None, "one confirmation is not enough");
        c.set_remote(true);
        assert_eq!(c.outcome(), Some(Ok(())));

        let mut r = Confirmation::default();
        r.set_remote(true);
        r.set_local(false);
        assert_eq!(r.outcome(), Some(Err(PairingError::Rejected)));
    }
}
