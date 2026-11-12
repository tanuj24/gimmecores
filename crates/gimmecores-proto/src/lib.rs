//! Generated protocol types and length-prefixed framing for GimmeCores.
//!
//! The protocol is defined in `spec/proto` (language-neutral); this crate only generates Rust
//! types from it and adds framing with strict size limits.

pub mod framing;

/// Peer protocol (machine to machine), `gimmecores.peer.v1`.
pub mod peer {
    pub mod v1 {
        #![allow(clippy::all, clippy::pedantic, missing_docs)]
        include!(concat!(env!("OUT_DIR"), "/gimmecores.peer.v1.rs"));
    }
}

/// Local control API messages, `gimmecores.local.v1`.
pub mod local {
    pub mod v1 {
        #![allow(clippy::all, clippy::pedantic, missing_docs)]
        include!(concat!(env!("OUT_DIR"), "/gimmecores.local.v1.rs"));
    }
}
