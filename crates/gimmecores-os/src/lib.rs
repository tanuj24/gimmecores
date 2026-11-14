//! What GimmeCores needs from the operating system to keep the local daemon owner-only, on
//! macOS, Linux and Windows (threat model I10, I13):
//!
//! - [`ipc`]: the local API's two endpoints (Client and Control). Unix sockets with mode 0600
//!   on macOS and Linux; on Windows, named pipes that only this user may open, never from the
//!   network, which another program cannot take over, and whose server the client checks runs
//!   as the same user before saying anything.
//! - [`private`]: folders and files only this user may read (identity key, trust list, grants,
//!   audit log), and a check that refuses ones others can read.
//! - [`power`]: the laptop protections' readings that need the OS's API (Windows).
//!
//! Nothing here becomes a no-op on a platform: where a protection is not implemented, the
//! function fails.

pub mod ipc;
pub mod power;
pub mod private;

#[cfg(windows)]
mod windows;
