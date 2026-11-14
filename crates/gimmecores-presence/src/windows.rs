//! Windows Hello (PIN, face or fingerprint) through `UserConsentVerifier`. The prompt is owned
//! by the foreground window, so it opens in front of what the owner is looking at. Only an
//! explicit "verified" from Windows counts; every other answer is a refusal or "unavailable".
#![allow(unsafe_code)]

use windows::Security::Credentials::UI::{
    UserConsentVerificationResult as Answer, UserConsentVerifier,
    UserConsentVerifierAvailability as Availability,
};
use windows::Win32::System::WinRT::{
    IUserConsentVerifierInterop, RO_INIT_MULTITHREADED, RoInitialize,
};
use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
use windows::core::{HSTRING, factory};
use windows_future::IAsyncOperation;

use crate::Outcome;

const SET_UP: &str = "Windows Hello is not set up for this account: add a PIN in Settings > \
                      Accounts > Sign-in options (it needs the account to have a password)";

/// Blocks until the owner answers (the caller runs it off the async runtime, with a timeout).
pub fn verify(reason: &str) -> Outcome {
    // SAFETY: initialises WinRT for this thread (a blocking-pool thread); a second call on the
    // same thread only returns an error, which is ignored.
    let _ = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
    if let Err(no) = available() {
        return no;
    }
    let message = HSTRING::from(format!("GimmeCores is trying to {reason}."));
    let asked = match ask(&message) {
        Ok(op) => op,
        Err(e) => return Outcome::Unavailable(format!("Windows Hello could not ask: {e}")),
    };
    match asked.join() {
        Ok(Answer::Verified) => Outcome::Verified,
        Ok(Answer::Canceled) => Outcome::Denied("cancelled".into()),
        Ok(Answer::RetriesExhausted) => Outcome::Denied("too many attempts".into()),
        Ok(Answer::DeviceBusy) => Outcome::Denied("Windows Hello is busy; try again".into()),
        Ok(Answer::DisabledByPolicy) => {
            Outcome::Unavailable("Windows Hello is turned off by policy".into())
        }
        Ok(Answer::DeviceNotPresent | Answer::NotConfiguredForUser) => {
            Outcome::Unavailable(SET_UP.into())
        }
        Ok(other) => Outcome::Denied(format!("Windows Hello answered {}", other.0)),
        Err(e) => Outcome::Unavailable(format!("Windows Hello failed: {e}")),
    }
}

/// Whether Windows Hello can verify this user at all.
fn available() -> Result<(), Outcome> {
    let a = UserConsentVerifier::CheckAvailabilityAsync()
        .and_then(|op| op.join())
        .map_err(|e| Outcome::Unavailable(format!("Windows Hello is not available: {e}")))?;
    match a {
        Availability::Available => Ok(()),
        Availability::DeviceBusy => Err(Outcome::Denied("Windows Hello is busy; try again".into())),
        Availability::DisabledByPolicy => Err(Outcome::Unavailable(
            "Windows Hello is turned off by policy".into(),
        )),
        _ => Err(Outcome::Unavailable(SET_UP.into())),
    }
}

fn ask(message: &HSTRING) -> windows::core::Result<IAsyncOperation<Answer>> {
    let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
    // SAFETY: returns the foreground window's handle, or null when there is none; Windows
    // Hello uses it only to place its prompt.
    let owner = unsafe { GetForegroundWindow() };
    // SAFETY: `owner` is a window handle or null (both accepted), `message` a valid HSTRING
    // alive for the call; the result is a new reference to the asynchronous operation.
    unsafe { interop.RequestVerificationForWindowAsync(owner, message) }
}
