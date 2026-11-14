//! Where a background program's output goes on Windows, where `gmcd` is a windowed program (so
//! starting it at login opens no console window). macOS and Linux need nothing here.

use std::path::Path;

/// Call first thing in `gmcd` on Windows. Output already redirected (`> log`) stays where it
/// is; started from a terminal, output goes to that terminal; otherwise (at login) it is
/// appended to `log`, kept under `max_bytes` by starting the file over.
pub fn output_for_background(log: &Path, max_bytes: u64) {
    #[cfg(windows)]
    crate::windows::output_for_background(log, max_bytes);
    #[cfg(not(windows))]
    let _ = (log, max_bytes);
}
