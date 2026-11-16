//! GimmeCores desktop app. [`daemon`] talks to the local `gmcd` (no Tauri types, so it is
//! tested against a real daemon); `main.rs` wires it to the window, tray and notifications.
//!
//! The app never starts the daemon or creates its state; it only connects to a running one.
//! Every approval still goes through the daemon's own presence check (Touch ID / password).

pub mod applog;
pub mod daemon;
pub mod service;
pub mod update;
