//! Owner presence on Windows.
//!
//! Windows Hello (PIN, face or fingerprint) through `UserConsentVerifier` when this account has
//! it. Otherwise the Windows password, entered on the secure desktop that Windows opens after
//! Ctrl+Alt+Delete (other programs cannot see that screen, read its keys or type into it).
//! GimmeCores never reads the password: Windows seals it, and Windows' own sign-in check
//! (`LsaLogonUser`) opens it and must accept it for exactly the account `gmcd` runs as. A blank
//! password never counts: Windows refuses it outside its sign-in screen, and where that rule is
//! turned off the password is not offered at all. Every other answer is a refusal or
//! "unavailable", and prompts open only on a desktop the owner can see.
#![allow(unsafe_code)]

use core::ffi::c_void;

use windows::Security::Credentials::UI::{
    UserConsentVerificationResult as Answer, UserConsentVerifier,
    UserConsentVerifierAvailability as Availability,
};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND, LUID, NTSTATUS};
use windows::Win32::Graphics::Gdi::HBITMAP;
use windows::Win32::Security::Authentication::Identity::{
    LSA_STRING, LsaConnectUntrusted, LsaDeregisterLogonProcess, LsaFreeReturnBuffer, LsaLogonUser,
    LsaNtStatusToWinError, SECURITY_LOGON_TYPE,
};
use windows::Win32::Security::Credentials::{
    CREDUI_INFOW, CREDUIWIN_ENUMERATE_CURRENT_USER, CREDUIWIN_SECURE_PROMPT,
    CredUIPromptForWindowsCredentialsW,
};
use windows::Win32::Security::{
    AllocateLocallyUniqueId, EqualSid, GetTokenInformation, PSID, QUOTA_LIMITS, TOKEN_QUERY,
    TOKEN_SOURCE, TOKEN_USER, TokenUser,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW};
use windows::Win32::System::StationsAndDesktops::{
    GetProcessWindowStation, GetUserObjectInformationW, UOI_FLAGS, USEROBJECTFLAGS,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::WinRT::{
    IUserConsentVerifierInterop, RO_INIT_MULTITHREADED, RoInitialize,
};
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, WSF_VISIBLE};
use windows::core::{HSTRING, PCWSTR, PSTR, factory, w};
use windows_future::IAsyncOperation;

use crate::Outcome;

const NO_PASSWORD: &str = "this Windows account has no password, so it cannot approve \
                           GimmeCores requests: add a password and a PIN in Settings > \
                           Accounts > Sign-in options";
const NO_DESKTOP: &str = "no desktop to ask on: approvals need GimmeCores running in your \
                          signed-in Windows session (start it from the app, not over SSH or \
                          as a service)";
const BLANK_ALLOWED: &str = "this PC lets programs sign in with blank passwords (\"Limit local \
                             account use of blank passwords to console logon only\" is off), so \
                             a password cannot prove who is there: set up Windows Hello in \
                             Settings > Accounts > Sign-in options";
const ERROR_CANCELLED: u32 = 1223;
const ERROR_LOGON_FAILURE: u32 = 1326;
const ERROR_ACCOUNT_RESTRICTION: u32 = 1327;
const ERROR_ACCOUNT_LOCKED_OUT: u32 = 1909;
const STATUS_ACCOUNT_RESTRICTION: i32 = 0xC000_006E_u32 as i32;

/// Blocks until the owner answers (the caller runs it off the async runtime, with a timeout).
pub fn verify(reason: &str) -> Outcome {
    if !on_visible_desktop() {
        return Outcome::Unavailable(NO_DESKTOP.into());
    }
    // SAFETY: initialises WinRT for this thread (a blocking-pool thread); a second call on the
    // same thread only returns an error, which is ignored.
    let _ = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
    match hello_available() {
        Ok(()) => hello(reason),
        // Only when Windows Hello cannot ask at all; a refusal never leads to a second prompt.
        Err(Outcome::Unavailable(_)) => password(reason),
        Err(no) => no,
    }
}

/// Whether this process can show a window the signed-in user sees. `gmcd` started over SSH or
/// as a service runs in a hidden window station, where a prompt would wait unseen.
fn on_visible_desktop() -> bool {
    // SAFETY: returns this process's window station handle, which must not be closed.
    let Ok(station) = (unsafe { GetProcessWindowStation() }) else {
        return false;
    };
    let mut flags = USEROBJECTFLAGS::default();
    // SAFETY: `flags` is a USEROBJECTFLAGS of the size given, written by the call.
    let read = unsafe {
        GetUserObjectInformationW(
            HANDLE(station.0),
            UOI_FLAGS,
            Some((&raw mut flags).cast()),
            size_of::<USEROBJECTFLAGS>() as u32,
            None,
        )
    };
    read.is_ok() && flags.dwFlags & WSF_VISIBLE as u32 != 0
}

// ---------------------------------------------------------------------------------------------
// Windows Hello

fn hello(reason: &str) -> Outcome {
    let message = HSTRING::from(format!("GimmeCores is trying to {reason}."));
    let asked = match ask_hello(&message) {
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
            Outcome::Unavailable("Windows Hello is not set up for this account".into())
        }
        Ok(other) => Outcome::Denied(format!("Windows Hello answered {}", other.0)),
        Err(e) => Outcome::Unavailable(format!("Windows Hello failed: {e}")),
    }
}

/// Whether Windows Hello can verify this user at all.
fn hello_available() -> Result<(), Outcome> {
    let a = UserConsentVerifier::CheckAvailabilityAsync()
        .and_then(|op| op.join())
        .map_err(|e| Outcome::Unavailable(format!("Windows Hello is not available: {e}")))?;
    match a {
        Availability::Available => Ok(()),
        Availability::DeviceBusy => Err(Outcome::Denied("Windows Hello is busy; try again".into())),
        other => Err(Outcome::Unavailable(format!(
            "Windows Hello is not available ({})",
            other.0
        ))),
    }
}

fn ask_hello(message: &HSTRING) -> windows::core::Result<IAsyncOperation<Answer>> {
    let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
    // SAFETY: returns the foreground window's handle, or null when there is none; Windows
    // Hello uses it only to place its prompt.
    let owner = unsafe { GetForegroundWindow() };
    // SAFETY: `owner` is a window handle or null (both accepted), `message` a valid HSTRING
    // alive for the call; the result is a new reference to the asynchronous operation.
    unsafe { interop.RequestVerificationForWindowAsync(owner, message) }
}

// ---------------------------------------------------------------------------------------------
// The Windows password, when Windows Hello is not set up

fn password(reason: &str) -> Outcome {
    // Who must answer is this process's account. Whatever account the answer names, Windows
    // must sign in exactly this one, so another account's password cannot approve.
    let me = match Token::this_process().and_then(|t| t.user()) {
        Ok(sid) => sid,
        Err(e) => return Outcome::Unavailable(format!("cannot tell which account this is: {e}")),
    };
    if !windows_refuses_blank_passwords() {
        // GimmeCores never sees the password, so it relies on Windows to refuse a blank one.
        return Outcome::Unavailable(BLANK_ALLOWED.into());
    }
    let answer = match Sealed::ask(reason) {
        Ok(a) => a,
        Err(no) => return no,
    };
    let token = match answer.sign_in() {
        Ok(t) => t,
        Err(no) => return no,
    };
    drop(answer);
    match token.user() {
        Ok(sid) if same_sid(&sid, &me) => Outcome::Verified,
        Ok(_) => Outcome::Denied("that password is for another account".into()),
        Err(e) => Outcome::Denied(format!("cannot check the account: {e}")),
    }
}

/// Why Windows refused the answer. `sub` is the sub-status LsaLogonUser reports.
fn refused(code: u32, sub: i32) -> String {
    match code {
        ERROR_LOGON_FAILURE => "wrong password".into(),
        ERROR_ACCOUNT_LOCKED_OUT => {
            "this account is locked after too many wrong passwords; try again later".into()
        }
        // The same status twice is Windows refusing a blank password outside its sign-in screen.
        ERROR_ACCOUNT_RESTRICTION if sub == STATUS_ACCOUNT_RESTRICTION => NO_PASSWORD.into(),
        ERROR_ACCOUNT_RESTRICTION => format!(
            "Windows does not let this account sign in now (status {sub:#x}): it may be \
             disabled, expired, or outside its allowed hours"
        ),
        other => format!("Windows refused the password (error {other})"),
    }
}

/// Whether Windows refuses blank passwords everywhere but its own sign-in screen ("Accounts:
/// Limit local account use of blank passwords to console logon only", on unless turned off).
fn windows_refuses_blank_passwords() -> bool {
    let mut value = 1u32;
    let mut size = size_of::<u32>() as u32;
    // SAFETY: reads one DWORD into `value`, whose size is given.
    let r = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!("SYSTEM\\CurrentControlSet\\Control\\Lsa"),
            w!("LimitBlankPasswordUse"),
            RRF_RT_REG_DWORD,
            None,
            Some((&raw mut value).cast()),
            Some(&mut size),
        )
    };
    // Missing means Windows' default: refused.
    r.is_err() || value != 0
}

/// The prompt's answer as Windows packed it, the password sealed so that only Windows can read
/// it. Wiped and freed when dropped.
struct Sealed {
    ptr: *mut c_void,
    len: u32,
    package: u32,
}

impl Sealed {
    /// Shows Windows' credential prompt for the signed-in user on the secure desktop.
    fn ask(reason: &str) -> Result<Self, Outcome> {
        let caption = HSTRING::from("GimmeCores");
        let message = HSTRING::from(format!(
            "GimmeCores is trying to {reason}. Enter your Windows password to allow it."
        ));
        let info = CREDUI_INFOW {
            cbSize: size_of::<CREDUI_INFOW>() as u32,
            // No owner: a prompt owned by another program's window (the Start menu, say) is
            // hidden with it, and the request would wait unseen.
            hwndParent: HWND::default(),
            pszMessageText: PCWSTR(message.as_ptr()),
            pszCaptionText: PCWSTR(caption.as_ptr()),
            hbmBanner: HBITMAP::default(),
        };
        let mut package = 0u32;
        let mut ptr: *mut c_void = core::ptr::null_mut();
        let mut len = 0u32;
        // SAFETY: `info` and the strings it points to outlive the call; the out pointers are
        // valid locals. On success Windows allocates `ptr`, owned by the returned Sealed.
        let r = unsafe {
            CredUIPromptForWindowsCredentialsW(
                Some(&info),
                0,
                &mut package,
                None,
                0,
                &mut ptr,
                &mut len,
                None,
                CREDUIWIN_ENUMERATE_CURRENT_USER | CREDUIWIN_SECURE_PROMPT,
            )
        };
        match r {
            0 => Ok(Self { ptr, len, package }),
            ERROR_CANCELLED => Err(Outcome::Denied("cancelled".into())),
            other => Err(Outcome::Unavailable(format!(
                "the Windows password prompt could not open (error {other})"
            ))),
        }
    }

    /// Hands the answer to Windows' own sign-in check, as at the sign-in screen. Returns the
    /// signed-in account's token.
    fn sign_in(&self) -> Result<Token, Outcome> {
        let lsa = Lsa::connect()?;
        let mut origin_name = *b"GimmeCores";
        let origin = LSA_STRING {
            Length: origin_name.len() as u16,
            MaximumLength: origin_name.len() as u16,
            Buffer: PSTR(origin_name.as_mut_ptr()),
        };
        let mut source = TOKEN_SOURCE {
            SourceName: b"GimmeCrs".map(|b| b as i8),
            SourceIdentifier: LUID::default(),
        };
        // SAFETY: writes a new locally unique id into `source`.
        unsafe { AllocateLocallyUniqueId(&mut source.SourceIdentifier) }
            .map_err(|e| Outcome::Unavailable(format!("cannot ask Windows to check: {e}")))?;
        let mut profile: *mut c_void = core::ptr::null_mut();
        let mut profile_len = 0u32;
        let mut logon_id = LUID::default();
        let mut token = HANDLE::default();
        let mut quotas = QUOTA_LIMITS::default();
        let mut sub_status = 0i32;
        // SAFETY: every pointer is to a valid local or to the packed answer (`ptr`/`len`)
        // Windows returned; on success Windows allocates `profile` (freed below) and a new token.
        let status = unsafe {
            LsaLogonUser(
                lsa.0,
                &origin,
                SECURITY_LOGON_TYPE::Interactive,
                self.package,
                self.ptr,
                self.len,
                None,
                &source,
                &mut profile,
                &mut profile_len,
                &mut logon_id,
                &mut token,
                &mut quotas,
                &mut sub_status,
            )
        };
        if !profile.is_null() {
            // SAFETY: allocated by LsaLogonUser, freed once.
            let _ = unsafe { LsaFreeReturnBuffer(profile) };
        }
        if status.is_err() {
            return Err(Outcome::Denied(refused(win_error(status), sub_status)));
        }
        Ok(Token(token))
    }
}

impl Drop for Sealed {
    fn drop(&mut self) {
        if self.ptr.is_null() {
            return;
        }
        // SAFETY: `ptr` points to `len` bytes Windows allocated for us; they are wiped, then
        // freed exactly once.
        unsafe {
            wipe(core::slice::from_raw_parts_mut(
                self.ptr.cast::<u8>(),
                self.len as usize,
            ));
            CoTaskMemFree(Some(self.ptr));
        }
    }
}

fn win_error(status: NTSTATUS) -> u32 {
    // SAFETY: a pure conversion of a status code.
    unsafe { LsaNtStatusToWinError(status) }
}

/// An untrusted connection to Windows' security service, closed when dropped.
struct Lsa(HANDLE);

impl Lsa {
    fn connect() -> Result<Self, Outcome> {
        let mut h = HANDLE::default();
        // SAFETY: `h` receives a new connection handle on success.
        let status = unsafe { LsaConnectUntrusted(&mut h) };
        if status.is_err() {
            return Err(Outcome::Unavailable(format!(
                "cannot reach Windows' sign-in check (error {})",
                win_error(status)
            )));
        }
        Ok(Self(h))
    }
}

impl Drop for Lsa {
    fn drop(&mut self) {
        // SAFETY: the handle came from LsaConnectUntrusted and is closed once.
        let _ = unsafe { LsaDeregisterLogonProcess(self.0) };
    }
}

/// Overwrites `b` with zeros in a way the compiler cannot skip.
fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        // SAFETY: `x` is a valid, exclusive reference.
        unsafe { core::ptr::write_volatile(x, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

// ---------------------------------------------------------------------------------------------
// Accounts and tokens

/// A token handle, closed when dropped.
struct Token(HANDLE);

impl Token {
    fn this_process() -> windows::core::Result<Self> {
        let mut h = HANDLE::default();
        // SAFETY: the current-process pseudo handle needs no closing; `h` receives a new token
        // handle on success, owned by the returned Token.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h)? };
        Ok(Self(h))
    }

    /// The token's user SID, copied into an aligned buffer (a TOKEN_USER followed by its SID).
    fn user(&self) -> windows::core::Result<Sid> {
        let mut len = 0u32;
        // SAFETY: asks only for the size needed (the call fails with "insufficient buffer").
        let _ = unsafe { GetTokenInformation(self.0, TokenUser, None, 0, &mut len) };
        let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
        // SAFETY: `buf` holds at least `len` bytes, 8-byte aligned for TOKEN_USER.
        unsafe {
            GetTokenInformation(
                self.0,
                TokenUser,
                Some(buf.as_mut_ptr().cast()),
                len,
                &mut len,
            )?
        };
        Ok(Sid(buf))
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: the handle was opened for this Token and is closed once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// A TOKEN_USER and the SID it points into, in one buffer.
struct Sid(Vec<u64>);

impl Sid {
    fn psid(&self) -> PSID {
        // SAFETY: the buffer was filled by GetTokenInformation(TokenUser), so it starts with a
        // TOKEN_USER whose SID pointer points inside this same buffer.
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
}

fn same_sid(a: &Sid, b: &Sid) -> bool {
    // SAFETY: both are valid SIDs inside their buffers, alive for the call.
    unsafe { EqualSid(a.psid(), b.psid()) }.is_ok()
}
