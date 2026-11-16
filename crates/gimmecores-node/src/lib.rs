//! A GimmeCores node: state on disk, identity, trust list, and (later) the running daemon.

pub mod activity;
mod activity_api;
pub mod api;
pub mod audit;
pub mod awake;
pub mod blobs;
pub mod caches;
pub mod caps;
pub mod deps;
pub mod discovery;
pub mod exec;
#[cfg(unix)]
pub mod fsafe;
pub mod fsutil;
pub mod fuzzing;
pub mod grants_flow;
pub mod identity;
pub mod images;
mod images_flow;
pub mod linktest;
pub mod load_share;
pub mod machine;
pub mod node;
pub mod paths;
pub mod persist;
pub mod power;
pub mod presence;
pub mod queued;
pub mod remote;
pub mod sandbox;
pub mod secrets;
pub mod speed;
pub mod standing;
pub mod tasks_flow;
pub mod tools;
pub mod tree;
pub mod trust;
pub mod usage;
pub mod wake;
pub mod wire;

static SOFTWARE_VERSION: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();

/// Sets the version this service reports, with its build ("0.1.1 (943d37b 2026-11-16)"); the
/// binaries call it at start. Paired devices and `gmc status` see it.
pub fn set_software_version(v: &'static str) {
    let _ = SOFTWARE_VERSION.set(v);
}

/// The version this service reports (the crate version when no build was set).
pub fn software_version() -> &'static str {
    SOFTWARE_VERSION
        .get()
        .copied()
        .unwrap_or(env!("CARGO_PKG_VERSION"))
}

/// Current time in seconds since the Unix epoch (the only clock read in the node).
pub fn now() -> gimmecores_core::UnixSeconds {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
