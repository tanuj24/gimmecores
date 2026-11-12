//! macOS: LocalAuthentication, policy "device owner authentication" (Touch ID, or the login
//! password when Touch ID is unavailable or the user chooses it).
#![allow(unsafe_code)]

use std::sync::mpsc;

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};

use crate::{Outcome, TIMEOUT};

// LAError codes (LAError.h).
const AUTHENTICATION_FAILED: isize = -1;
const USER_CANCEL: isize = -2;
const USER_FALLBACK: isize = -3;
const SYSTEM_CANCEL: isize = -4;
const APP_CANCEL: isize = -9;

fn describe(e: &NSError) -> String {
    e.localizedDescription().to_string()
}

/// Blocks until the owner answers (call from a blocking thread).
pub(crate) fn verify(reason: &str) -> Outcome {
    let policy = LAPolicy::DeviceOwnerAuthentication;
    // SAFETY: plain Objective-C object creation.
    let ctx = unsafe { LAContext::new() };
    // SAFETY: `ctx` is a valid context; the call only reads it.
    if let Err(e) = unsafe { ctx.canEvaluatePolicy_error(policy) } {
        return Outcome::Unavailable(describe(&e));
    }
    let (tx, rx) = mpsc::channel::<Outcome>();
    let reply = RcBlock::new(move |ok: Bool, err: *mut NSError| {
        let outcome = if ok.as_bool() {
            Outcome::Verified
        } else {
            // SAFETY: LocalAuthentication passes either null or a valid NSError that lives for
            // the duration of this call.
            match unsafe { err.as_ref() } {
                None => Outcome::Denied("not approved".into()),
                Some(e) => match e.code() {
                    USER_CANCEL | USER_FALLBACK | SYSTEM_CANCEL | APP_CANCEL => {
                        Outcome::Denied("cancelled".into())
                    }
                    AUTHENTICATION_FAILED => Outcome::Denied("authentication failed".into()),
                    _ => Outcome::Unavailable(describe(e)),
                },
            }
        };
        let _ = tx.send(outcome);
    });
    let reason = NSString::from_str(reason);
    // SAFETY: `ctx` stays alive until we return (it is invalidated below), `reason` is a valid
    // non-empty string, and the reply block only moves a Send value into a channel.
    unsafe { ctx.evaluatePolicy_localizedReason_reply(policy, &reason, &reply) };
    let outcome = rx
        .recv_timeout(TIMEOUT)
        .unwrap_or_else(|_| Outcome::Denied("no response in time".into()));
    // SAFETY: ends any prompt still showing; valid on a live context.
    unsafe { ctx.invalidate() };
    outcome
}
