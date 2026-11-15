//! The Win32 calls behind `ipc` and `private`, each wrapped in a small safe function. This is
//! the only module of the crate allowed to use `unsafe`; every block says why it is sound.
//!
//! - The current user, and the user a pipe's server runs as: process token, `TokenUser`.
//! - Owner-only access lists from SDDL strings: `D:P(A;..;FA;;;<user>)(A;..;FA;;;SY)`
//!   (P: protected, nothing inherited from parent folders).
//! - Who may read a file: every "allow" entry of its list that grants reading (or changing the
//!   list or its owner, which leads to reading) must be this user, SYSTEM or Administrators.
#![allow(unsafe_code)]

use std::ffi::{OsStr, c_void};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr::null_mut;

use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, PipeMode, ServerOptions};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid,
    GetAce, GetLengthSid, GetSecurityDescriptorDacl, GetTokenInformation, IsValidSid,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid,
    WinLocalSystemSid,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Rights that let an account read a file's contents, or give itself that right.
const READS: u32 = 0x0000_0001 // FILE_READ_DATA
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x1000_0000 // GENERIC_ALL
    | 0x8000_0000; // GENERIC_READ

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

/// A handle this code opened; closed when dropped.
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle was returned open by OpenProcess/OpenProcessToken and is closed
        // exactly once, here.
        unsafe { CloseHandle(self.0) };
    }
}

/// Memory Windows allocated for us with LocalAlloc; freed when dropped.
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an API documented to be freed with LocalFree, and
            // is freed exactly once, here.
            unsafe { LocalFree(self.0) };
        }
    }
}
// SAFETY: the memory is only read after creation (a security descriptor), never mutated, and
// LocalFree may be called from any thread.
unsafe impl Send for Local {}
unsafe impl Sync for Local {}

/// A security identifier, copied into memory we own (aligned for the SID structure).
pub(crate) struct Sid(Vec<u64>);

impl Sid {
    fn psid(&self) -> PSID {
        self.0.as_ptr() as PSID
    }

    /// Copies a valid SID that Windows owns.
    ///
    /// SAFETY (for callers): `psid` must point to a valid SID that stays alive for this call.
    unsafe fn copy(psid: PSID) -> io::Result<Self> {
        // SAFETY: the caller guarantees `psid` is a live SID; IsValidSid/GetLengthSid only read it.
        let len = unsafe {
            if IsValidSid(psid) == 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SID"));
            }
            GetLengthSid(psid) as usize
        };
        let mut buf = vec![0u64; len.div_ceil(8)];
        // SAFETY: `buf` holds at least `len` bytes and does not overlap the source.
        unsafe {
            std::ptr::copy_nonoverlapping(psid as *const u8, buf.as_mut_ptr() as *mut u8, len)
        };
        Ok(Self(buf))
    }

    fn well_known(kind: i32) -> io::Result<Self> {
        let mut buf = vec![0u64; (SECURITY_MAX_SID_SIZE as usize).div_ceil(8)];
        let mut size = SECURITY_MAX_SID_SIZE;
        // SAFETY: `buf` has SECURITY_MAX_SID_SIZE bytes, the size Windows documents as enough
        // for any SID, and `size` says so.
        let ok =
            unsafe { CreateWellKnownSid(kind, null_mut(), buf.as_mut_ptr() as PSID, &mut size) };
        if ok == 0 {
            return Err(last_error());
        }
        Ok(Self(buf))
    }

    fn equals_ptr(&self, other: PSID) -> bool {
        // SAFETY: both point to valid SIDs (ours is owned; `other` comes from a live ACL).
        unsafe { EqualSid(self.psid(), other) != 0 }
    }

    fn equals(&self, other: &Sid) -> bool {
        self.equals_ptr(other.psid())
    }

    pub(crate) fn string(&self) -> io::Result<String> {
        let mut out = null_mut();
        // SAFETY: our SID is valid; on success `out` is a LocalAlloc'd, NUL-terminated string.
        if unsafe { ConvertSidToStringSidW(self.psid(), &mut out) } == 0 {
            return Err(last_error());
        }
        let _free = Local(out as *mut c_void);
        // SAFETY: `out` is NUL-terminated; we read up to the terminator.
        let len = (0..).take_while(|&i| unsafe { *out.add(i) } != 0).count();
        // SAFETY: `len` u16s are initialised and alive until `_free` drops.
        let chars = unsafe { std::slice::from_raw_parts(out, len) };
        Ok(String::from_utf16_lossy(chars))
    }
}

/// The user a process runs as.
fn process_user(process: HANDLE) -> io::Result<Sid> {
    let mut token: HANDLE = null_mut();
    // SAFETY: `process` is a valid process handle with query rights; `token` receives a new
    // handle that we close.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(last_error());
    }
    let token = Handle(token);
    let mut len = 0u32;
    // SAFETY: a size query (null buffer, zero length) only writes `len`.
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut len) };
    if len == 0 {
        return Err(last_error());
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` has at least `len` bytes, 8-byte aligned (TOKEN_USER needs pointer
    // alignment).
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buf.as_mut_ptr() as *mut c_void,
            len,
            &mut len,
        )
    } == 0
    {
        return Err(last_error());
    }
    // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points inside `buf`,
    // which is alive during the copy.
    unsafe {
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        Sid::copy(user.User.Sid)
    }
}

pub(crate) fn current_user() -> io::Result<Sid> {
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing.
    process_user(unsafe { GetCurrentProcess() })
}

/// A security descriptor built from an SDDL string, freed when dropped.
struct SecurityDescriptor(Local);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let text = wide(OsStr::new(sddl));
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `text` is NUL-terminated; on success `sd` is LocalAlloc'd and freed by Local.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        Ok(Self(Local(sd)))
    }

    fn dacl(&self) -> io::Result<*mut ACL> {
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl: *mut ACL = null_mut();
        // SAFETY: the descriptor is valid; the outputs are plain locals.
        if unsafe { GetSecurityDescriptorDacl(self.0.0, &mut present, &mut dacl, &mut defaulted) }
            == 0
        {
            return Err(last_error());
        }
        if present == 0 || dacl.is_null() {
            return Err(io::Error::other("the access list is missing"));
        }
        Ok(dacl)
    }
}

/// `D:P(...)`: only this user and SYSTEM, full control; `inherit` passes it on to everything
/// created inside a folder.
fn owner_only(inherit: bool) -> io::Result<SecurityDescriptor> {
    let user = current_user()?.string()?;
    let flags = if inherit { "OICI" } else { "" };
    SecurityDescriptor::from_sddl(&format!("D:P(A;{flags};FA;;;{user})(A;{flags};FA;;;SY)"))
}

/// Replaces a file's or folder's access list with an owner-only, protected one.
pub(crate) fn make_owner_only(path: &Path, inherit: bool) -> io::Result<()> {
    let sd = owner_only(inherit)?;
    let dacl = sd.dacl()?;
    let name = wide(path.as_os_str());
    // SAFETY: `name` is NUL-terminated; `dacl` points into `sd`, alive for the call.
    let err = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null_mut(),
        )
    };
    if err != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    Ok(())
}

/// The accounts other than this user, SYSTEM and Administrators that may read `path` (as SID
/// strings). A missing access list means everyone may.
pub(crate) fn readers_besides_owner(path: &Path) -> io::Result<Vec<String>> {
    let allowed = [
        current_user()?,
        Sid::well_known(WinLocalSystemSid)?,
        Sid::well_known(WinBuiltinAdministratorsSid)?,
    ];
    let name = wide(path.as_os_str());
    let mut dacl: *mut ACL = null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `name` is NUL-terminated; on success `sd` is LocalAlloc'd (freed by Local) and
    // `dacl` points into it.
    let err = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut sd,
        )
    };
    if err != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    let _free = Local(sd);
    if dacl.is_null() {
        return Ok(vec!["Everyone (no access list)".into()]);
    }
    let mut others = Vec::new();
    // SAFETY: `dacl` is a valid ACL inside `sd`, alive until `_free` drops.
    let count = unsafe { (*dacl).AceCount };
    for i in 0..u32::from(count) {
        let mut ace: *mut c_void = null_mut();
        // SAFETY: `i` is below the ACL's entry count.
        if unsafe { GetAce(dacl, i, &mut ace) } == 0 {
            return Err(last_error());
        }
        // SAFETY: every entry starts with an ACE_HEADER.
        let kind = u32::from(unsafe { (*(ace as *const ACE_HEADER)).AceType });
        if kind != ACCESS_ALLOWED_ACE_TYPE && kind != ACCESS_ALLOWED_CALLBACK_ACE_TYPE {
            // Deny entries only take rights away; object entries do not apply to files.
            continue;
        }
        // SAFETY: both allow types share ACCESS_ALLOWED_ACE's layout: header, mask, then the
        // SID starting at `SidStart`, inside the entry.
        let (mask, sid) = unsafe {
            let a = ace as *const ACCESS_ALLOWED_ACE;
            ((*a).Mask, std::ptr::addr_of!((*a).SidStart) as PSID)
        };
        if mask & READS != 0 && !allowed.iter().any(|s| s.equals_ptr(sid)) {
            // SAFETY: `sid` is a valid SID inside the live ACL.
            let s = unsafe { Sid::copy(sid) }?;
            others.push(s.string()?);
        }
    }
    Ok(others)
}

/// Test helper: lets everyone read `path`.
#[cfg(test)]
pub(crate) fn grant_everyone_read(path: &Path) -> io::Result<()> {
    let user = current_user()?.string()?;
    let sd = SecurityDescriptor::from_sddl(&format!("D:P(A;;FA;;;{user})(A;;FR;;;WD)"))?;
    let dacl = sd.dacl()?;
    let name = wide(path.as_os_str());
    // SAFETY: as in make_owner_only.
    let err = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null_mut(),
        )
    };
    if err != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    Ok(())
}

/// Random bytes as hex, from the system's generator.
pub(crate) fn random_hex(bytes: usize) -> io::Result<String> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// A pipe name and the owner-only descriptor every one of its instances is created with.
pub(crate) struct OwnerOnlyPipe {
    name: String,
    sd: SecurityDescriptor,
}

impl OwnerOnlyPipe {
    pub(crate) fn new(name: &str) -> io::Result<Self> {
        let user = current_user()?.string()?;
        // Only this user, full control; nothing inherited.
        let sd = SecurityDescriptor::from_sddl(&format!("D:P(A;;GA;;;{user})"))?;
        Ok(Self {
            name: name.to_string(),
            sd,
        })
    }

    /// One more instance. `first`: fail if the name already exists (another program got there
    /// first). Remote clients are always refused.
    pub(crate) fn create(&self, first: bool) -> io::Result<NamedPipeServer> {
        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.sd.0.0,
            bInheritHandle: 0,
        };
        let mut opts = ServerOptions::new();
        opts.first_pipe_instance(first)
            .reject_remote_clients(true)
            .pipe_mode(PipeMode::Byte)
            .access_inbound(true)
            .access_outbound(true);
        // SAFETY: `attrs` is a valid SECURITY_ATTRIBUTES whose descriptor (in `self.sd`) lives
        // for this call; Windows copies it into the new pipe.
        unsafe {
            opts.create_with_security_attributes_raw(
                &self.name,
                &mut attrs as *mut _ as *mut c_void,
            )
        }
    }
}

// SAFETY: the descriptor is read-only after creation (see `Local`).
unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

/// Whether the program serving the pipe this client opened runs as the same user.
pub(crate) fn pipe_server_is_this_user(client: &NamedPipeClient) -> io::Result<bool> {
    let mut pid = 0u32;
    // SAFETY: the client's handle is a valid, open pipe handle; `pid` is a plain output.
    if unsafe { GetNamedPipeServerProcessId(client.as_raw_handle() as HANDLE, &mut pid) } == 0 {
        return Err(last_error());
    }
    // SAFETY: OpenProcess returns a new handle (closed by Handle) or null.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(last_error());
    }
    let process = Handle(process);
    Ok(process_user(process.0)?.equals(&current_user()?))
}

/// On battery, from GetSystemPowerStatus.
pub(crate) fn on_battery() -> Option<bool> {
    let mut status = windows_sys::Win32::System::Power::SYSTEM_POWER_STATUS::default();
    // SAFETY: `status` is a plain struct Windows fills in.
    if unsafe { windows_sys::Win32::System::Power::GetSystemPowerStatus(&mut status) } == 0 {
        return None;
    }
    crate::power::battery_from_status(status.ACLineStatus, status.BatteryFlag)
}

/// Seconds since the last keyboard or mouse input in this session, from GetLastInputInfo.
pub(crate) fn idle_secs() -> Option<u64> {
    use windows_sys::Win32::System::SystemInformation::GetTickCount;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    let mut info = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    // SAFETY: `info` is sized as Windows requires and only written to.
    if unsafe { GetLastInputInfo(&mut info) } == 0 {
        return None;
    }
    // SAFETY: GetTickCount has no preconditions.
    let now = unsafe { GetTickCount() };
    Some(crate::power::idle_ms(now, info.dwTime) / 1000)
}

/// See `console::output_for_background`.
pub(crate) fn output_for_background(log: &Path, max_bytes: u64) {
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::{
        ATTACH_PARENT_PROCESS, AttachConsole, GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
        SetStdHandle,
    };
    // SAFETY: GetStdHandle only reads the process's standard handles.
    let out = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    if !out.is_null() && out != INVALID_HANDLE_VALUE {
        return; // redirected by whoever started us
    }
    let target = if unsafe {
        // SAFETY: attaching to the parent's console, if it has one, has no other effect.
        AttachConsole(ATTACH_PARENT_PROCESS)
    } != 0
    {
        std::fs::OpenOptions::new().write(true).open("CONOUT$")
    } else {
        if std::fs::metadata(log).is_ok_and(|m| m.len() > max_bytes) {
            let _ = std::fs::remove_file(log);
        }
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
    };
    let Ok(file) = target else { return };
    let handle = file.into_raw_handle() as HANDLE;
    // SAFETY: `handle` is an open handle we own and hand over to stdout and stderr for the
    // rest of the process's life (never closed).
    unsafe {
        SetStdHandle(STD_OUTPUT_HANDLE, handle);
        SetStdHandle(STD_ERROR_HANDLE, handle);
    }
}
