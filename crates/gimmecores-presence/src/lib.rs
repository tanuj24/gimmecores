//! OS-verified user presence (threat model I13).
//!
//! Before the daemon performs an action that lets other devices do more (accept a grant,
//! confirm a pairing, turn lending on, ...), it asks the operating system to confirm that the
//! machine's owner is physically there: Touch ID or the login password on macOS, polkit (the
//! user's own password) on Linux. A script, an SDK dependency or an AI agent with shell access
//! can reach the daemon's socket, but cannot pass this check.
//!
//! This is the only GimmeCores crate allowed to use `unsafe`, and only inside `macos.rs`, to call
//! Apple's LocalAuthentication framework.

use std::time::Duration;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

/// Result of asking the OS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The owner confirmed.
    Verified,
    /// The owner refused, cancelled, or failed to authenticate.
    Denied(String),
    /// This machine cannot verify presence (no Touch ID/password prompt possible, no polkit
    /// agent, headless session, ...). The reason says why.
    Unavailable(String),
}

/// How long the owner has to respond before the request counts as denied.
pub const TIMEOUT: Duration = Duration::from_secs(120);

/// The mechanism this build uses, for status displays.
pub fn method() -> &'static str {
    if cfg!(target_os = "macos") {
        "Touch ID or login password"
    } else if cfg!(target_os = "linux") {
        "polkit (your password)"
    } else {
        "none"
    }
}

/// Asks the OS to verify that the owner is present and approves `reason`, a short phrase that
/// completes "GimmeCores is trying to ..." (for example "allow Laptop to use 2 cores for 1 hour").
pub async fn verify(reason: &str) -> Outcome {
    let reason = reason.trim();
    if reason.is_empty() {
        return Outcome::Denied("no reason given".into());
    }
    match tokio::time::timeout(TIMEOUT, platform(reason.to_string())).await {
        Ok(o) => o,
        Err(_) => Outcome::Denied("no response in time".into()),
    }
}

#[cfg(target_os = "macos")]
async fn platform(reason: String) -> Outcome {
    tokio::task::spawn_blocking(move || macos::verify(&reason))
        .await
        .unwrap_or_else(|e| Outcome::Unavailable(format!("presence check crashed: {e}")))
}

#[cfg(target_os = "linux")]
async fn platform(reason: String) -> Outcome {
    linux::verify(&reason).await
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
async fn platform(_reason: String) -> Outcome {
    Outcome::Unavailable("user presence is not supported on this platform yet".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_empty_reason_is_refused_without_asking() {
        assert!(matches!(verify("  ").await, Outcome::Denied(_)));
    }
}
