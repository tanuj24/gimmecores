//! User presence for consent actions (threat model I13). The daemon's Control API calls
//! [`crate::node::Node::require_presence`] before any action that lets other devices do more.

pub use gimmecores_presence::Outcome;

use crate::exec::BoxFuture;

/// How the daemon asks whether the owner is present.
pub trait Presence: Send + Sync {
    /// Human-readable mechanism, for `gmc status`.
    fn method(&self) -> &'static str;
    /// Asks the owner to approve `reason` ("GimmeCores is trying to <reason>").
    fn verify<'a>(&'a self, reason: &'a str) -> BoxFuture<'a, Outcome>;
}

/// The operating system's own check: Touch ID / login password on macOS, polkit on Linux.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsPresence;

impl Presence for OsPresence {
    fn method(&self) -> &'static str {
        gimmecores_presence::method()
    }

    fn verify<'a>(&'a self, reason: &'a str) -> BoxFuture<'a, Outcome> {
        Box::pin(gimmecores_presence::verify(reason))
    }
}

/// Always answers the same way. Test-only: compiled solely with the `insecure-test-executor`
/// feature (enabled by the dev-dependency), so shipped builds cannot bypass the OS check.
#[cfg(feature = "insecure-test-executor")]
#[derive(Clone, Debug)]
pub struct FixedPresence(pub Outcome);

#[cfg(feature = "insecure-test-executor")]
impl Presence for FixedPresence {
    fn method(&self) -> &'static str {
        "fixed (test)"
    }

    fn verify<'a>(&'a self, _reason: &'a str) -> BoxFuture<'a, Outcome> {
        let o = self.0.clone();
        Box::pin(async move { o })
    }
}
