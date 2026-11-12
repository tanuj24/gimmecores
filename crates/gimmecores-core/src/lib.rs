//! Pure decision logic for GimmeCores: who may send what, and the lender's grant book.
//!
//! This crate does no I/O and never reads the clock: callers pass `now`. That keeps every
//! security decision deterministic and unit-testable. Invariant IDs refer to
//! `docs/design/threat-model.md`.

pub mod access;
pub mod grants;
pub mod pairing;
pub mod types;

pub use access::{MessageKind, PeerStatus, admit};
pub use grants::{GrantBook, GrantError};
pub use types::*;
