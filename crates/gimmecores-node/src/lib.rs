//! A GimmeCores node: state on disk, identity, trust list, and (later) the running daemon.

pub mod blobs;
pub mod exec;
pub mod fsutil;
pub mod grants_flow;
pub mod identity;
pub mod node;
pub mod paths;
pub mod tree;
pub mod trust;
pub mod wire;

/// Current time in seconds since the Unix epoch (the only clock read in the node).
pub fn now() -> gimmecores_core::UnixSeconds {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
