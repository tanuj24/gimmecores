//! Networking for GimmeCores: LAN-only iroh endpoints.
//!
//! v1 is LAN-only by design (threat model 5.3):
//! - no relay servers (`RelayMode::Disabled`, the builder default),
//! - no global address publishing (no Pkarr/DNS address lookup; we never apply the `N0` preset),
//! - no router port mapping (iroh's `portmapper` feature is not compiled in; see Cargo.toml).

use std::net::SocketAddr;

use anyhow::Result;
use iroh::{Endpoint, RelayMode, SecretKey, endpoint::presets};

/// ALPN for the GimmeCores peer protocol, version 1 (`spec/proto/gimmecores/peer/v1`).
pub const PEER_ALPN: &[u8] = b"gimmecores/peer/1";

/// Builds a LAN-only endpoint bound to `bind`, identified by `secret_key`.
///
/// Only `PEER_ALPN` is accepted; connections for any other protocol are refused during the
/// TLS handshake.
pub async fn lan_only_endpoint(secret_key: SecretKey, bind: SocketAddr) -> Result<Endpoint> {
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .secret_key(secret_key)
        .alpns(vec![PEER_ALPN.to_vec()])
        .bind_addr(bind)?
        .bind()
        .await?;
    Ok(endpoint)
}
