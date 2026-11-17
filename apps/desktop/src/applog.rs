//! A short record of what the app did, kept where it survives the app itself (#20: an app
//! that disappeared from Applications could not be explained afterwards): each start with its
//! version and location, update checks and installs with their outcome, and the background
//! service being started or stopped from the app.
//!
//! macOS: ~/Library/Logs/GimmeCores/app.log; Linux: $XDG_STATE_HOME/gimmecores/app.log
//! (default ~/.local/state); Windows: %LOCALAPPDATA%\GimmeCores\logs\app.log. Kept under
//! 256 KiB: when full, it becomes app.log.1 (one older file is kept). Nothing private is
//! written: no device names, keys, requests or task contents. Writing never fails the app.

use std::io::Write as _;
use std::path::PathBuf;

const MAX_BYTES: u64 = 256 << 10;

fn dir() -> Option<PathBuf> {
    let env = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    if cfg!(target_os = "macos") {
        env("HOME").map(|h| h.join("Library/Logs/GimmeCores"))
    } else if cfg!(windows) {
        env("LOCALAPPDATA").map(|d| d.join("GimmeCores").join("logs"))
    } else {
        env("XDG_STATE_HOME")
            .or_else(|| env("HOME").map(|h| h.join(".local/state")))
            .map(|d| d.join("gimmecores"))
    }
}

/// Where the log is kept (None when there is no home folder).
pub fn path() -> Option<PathBuf> {
    dir().map(|d| d.join("app.log"))
}

/// Adds one line, stamped with the time (UTC).
pub fn note(line: &str) {
    let Some(path) = path() else { return };
    if let Some(d) = path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_BYTES) {
        let _ = std::fs::rename(&path, path.with_extension("log.1"));
    }
    let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    else {
        return;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let line: String = line.chars().filter(|c| *c != '\n' && *c != '\r').collect();
    let _ = writeln!(f, "{} UTC  {line}", stamp(now));
}

/// "2026-11-16 07:22:03".
pub fn stamp(unix: u64) -> String {
    let secs = i64::try_from(unix).unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let t = secs.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        t / 3600,
        t % 3600 / 60,
        t % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_read_as_utc_dates_and_times() {
        assert_eq!(stamp(0), "1970-01-01 00:00:00");
        // 2026-11-16 07:22:03 UTC
        assert_eq!(stamp(1_794_813_723), "2026-11-16 07:22:03");
        assert_eq!(stamp(951_782_400), "2000-02-29 00:00:00");
    }
}
