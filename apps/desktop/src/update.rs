//! Updating the app from the app itself (docs/RELEASING.md, threat model "update channel").
//!
//! Every update is a signed archive of the whole app bundle. The app builds in the public half
//! of one key, which only the maintainer holds; the updater (tauri-plugin-updater) refuses
//! anything not signed with it, refuses a version that is not newer, and (requireSignedVersion)
//! refuses an announced version that differs from the one the maintainer signed, so an old
//! genuine release cannot be replayed as an update. On top of that, this module:
//!
//! - offers updates only to an app installed in /Applications or ~/Applications (not one run
//!   from a build folder or Homebrew's own folder, which Homebrew updates);
//! - accepts a download only from this project's GitHub release files, over https;
//! - reads the version and bundle identifier inside the signed archive itself and requires
//!   them to be GimmeCores' and the announced version, before anything is replaced;
//! - shows release notes as plain text, cut short.
//!
//! The `update-test` feature (never in a shipped build: CI checks it) points all this at a
//! local test server and key, and never touches the real background service.

use std::path::{Path, PathBuf};

use anyhow::{Result, ensure};
use serde::Serialize;

/// Where installed copies look for updates.
pub const ENDPOINT: &str =
    "https://github.com/tanuj24/gimmecores/releases/latest/download/latest.json";
/// The only place an update may be downloaded from.
pub const DOWNLOAD_PREFIX: &str = "https://github.com/tanuj24/gimmecores/releases/download/";
pub use gimmecores_bundle::{BUNDLE_ID, check_archive};
/// Release notes shown, at most.
pub const NOTES_CHARS: usize = 2000;

/// The update key's public half this app was built with (`packaging/release/update-key.pub`);
/// empty in a build made without it, which then cannot update itself.
pub fn built_in_pubkey() -> &'static str {
    env!("GMC_UPDATE_PUBKEY")
}

/// Built with the `update-test` feature: a local test server and key, never a shipped build.
pub const TEST_BUILD: bool = cfg!(feature = "update-test");

/// The key updates must be signed with.
pub fn pubkey() -> String {
    #[cfg(feature = "update-test")]
    if let Ok(key) = std::env::var("GMC_UPDATE_TEST_PUBKEY") {
        return key;
    }
    built_in_pubkey().to_string()
}

/// Where to look for updates.
pub fn endpoint() -> String {
    #[cfg(feature = "update-test")]
    if let Ok(url) = std::env::var("GMC_UPDATE_TEST_ENDPOINT") {
        return url;
    }
    ENDPOINT.to_string()
}

/// This app's executable, with links resolved (the update replaces the bundle it is in), or
/// why this copy cannot update itself.
pub fn this_app() -> std::result::Result<PathBuf, String> {
    let key = pubkey();
    let exe = std::env::current_exe().map_err(|e| format!("cannot find this app: {e}"))?;
    if let Some(bundle) = bundle_of(&exe)
        && std::fs::symlink_metadata(&bundle).is_ok_and(|m| m.file_type().is_symlink())
    {
        return Err(LINKED.into());
    }
    let exe = std::fs::canonicalize(&exe).map_err(|e| format!("cannot find this app: {e}"))?;
    if TEST_BUILD {
        return if key.is_empty() {
            Err("no test key".into())
        } else {
            Ok(exe)
        };
    }
    let home = std::env::var_os("HOME").map(|h| std::fs::canonicalize(&h).unwrap_or(h.into()));
    match why_not(&exe, home.as_deref(), &key) {
        Some(reason) => Err(reason),
        None => Ok(exe),
    }
}

const LINKED: &str = HOMEBREW;
const HOMEBREW: &str =
    "Homebrew built this copy and updates it: brew upgrade --fetch-HEAD gimmecores";

/// What the Settings view shows before anything is downloaded.
#[derive(Clone, Debug, Default, Serialize)]
pub struct UpdateStatus {
    /// This app's version.
    pub current: String,
    /// The app can install updates itself.
    pub can_update: bool,
    /// Why not, in words, when it cannot.
    pub why_not: String,
    /// Set after a check: the newer version on offer.
    pub available: Option<Available>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Available {
    pub version: String,
    /// Plain text, at most [`NOTES_CHARS`] characters.
    pub notes: String,
    pub date: String,
}

/// The `.app` bundle this executable runs from (`…/GimmeCores.app/Contents/MacOS/<exe>`).
pub fn bundle_of(exe: &Path) -> Option<PathBuf> {
    let bundle = exe.parent()?.parent()?.parent()?;
    (bundle.extension()? == "app").then(|| bundle.to_path_buf())
}

/// Why this copy cannot update itself, if it cannot: only an app the user installed in
/// Applications updates itself. A build folder is rebuilt, not updated, and Homebrew updates
/// the copy in its own folder (`brew upgrade`).
pub fn why_not(exe: &Path, home: Option<&Path>, pubkey: &str) -> Option<String> {
    if pubkey.is_empty() {
        return Some(
            "This copy was built without the update key, so it cannot update itself.".into(),
        );
    }
    let Some(bundle) = bundle_of(exe) else {
        return Some("This copy does not run from an app bundle.".into());
    };
    if bundle.components().any(|c| c.as_os_str() == "Cellar") {
        return Some(HOMEBREW.into());
    }
    let inside = |dir: &Path| bundle.parent() == Some(dir);
    let applications =
        inside(Path::new("/Applications")) || home.is_some_and(|h| inside(&h.join("Applications")));
    if !applications {
        return Some(
            "To update GimmeCores from here, move it to your Applications folder and open it \
             from there."
                .into(),
        );
    }
    let linked = std::fs::symlink_metadata(&bundle).is_ok_and(|m| m.file_type().is_symlink());
    if linked {
        return Some(LINKED.into());
    }
    None
}

/// The download must be one of this project's release files, over https.
pub fn check_download_url(url: &str, test_server: bool) -> Result<()> {
    let ok =
        url.starts_with(DOWNLOAD_PREFIX) || (test_server && url.starts_with("http://127.0.0.1:"));
    ensure!(
        ok && !url.contains(".."),
        "the update is not hosted where GimmeCores releases are ({url})"
    );
    Ok(())
}

/// Release notes as shown: control characters removed (new lines kept), cut short.
pub fn clean_notes(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| *c == '\n' || !c.is_control())
        .filter(
            |c| !matches!(*c as u32, 0x200B..=0x200F | 0x202A..=0x202E | 0x2066..=0x2069 | 0xFEFF),
        )
        .collect();
    if cleaned.chars().count() > NOTES_CHARS {
        let mut s: String = cleaned.chars().take(NOTES_CHARS).collect();
        s.push('…');
        s
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn only_an_app_in_applications_updates_itself() {
        let key = "a-key";
        let home = Path::new("/Users/someone");
        let exe = |p: &str| {
            PathBuf::from(format!(
                "{p}/GimmeCores.app/Contents/MacOS/gimmecores-desktop"
            ))
        };
        assert_eq!(why_not(&exe("/Applications"), Some(home), key), None);
        assert_eq!(
            why_not(&exe("/Users/someone/Applications"), Some(home), key),
            None
        );
        for p in [
            "/Users/someone/github/offload/dist",
            "/opt/homebrew/Cellar/gimmecores/HEAD-1/",
            "/Volumes/GimmeCores",
            "/Applications/Utilities",
        ] {
            assert!(why_not(&exe(p), Some(home), key).is_some(), "{p}");
        }
        assert!(
            why_not(
                &exe("/opt/homebrew/Cellar/gimmecores/HEAD-1"),
                Some(home),
                key
            )
            .unwrap()
            .contains("brew upgrade")
        );
        assert!(
            why_not(&exe("/Applications"), Some(home), "")
                .unwrap()
                .contains("update key")
        );
        assert!(
            why_not(
                Path::new("/usr/local/bin/gimmecores-desktop"),
                Some(home),
                key
            )
            .is_some()
        );
    }

    #[test]
    fn downloads_come_only_from_the_projects_releases_over_https() {
        check_download_url(
            "https://github.com/tanuj24/gimmecores/releases/download/v0.2.0/GimmeCores.app.tar.gz",
            false,
        )
        .unwrap();
        for bad in [
            "http://github.com/tanuj24/gimmecores/releases/download/v0.2.0/x",
            "https://github.com/someone/else/releases/download/v1/x",
            "https://github.com/tanuj24/gimmecores/releases/download/../../../other/x",
            "https://evil.example/tanuj24/gimmecores/releases/download/x",
            "http://127.0.0.1:8000/x",
        ] {
            assert!(check_download_url(bad, false).is_err(), "{bad}");
        }
        check_download_url("http://127.0.0.1:8000/x.tar.gz", true).unwrap();
    }

    #[test]
    fn the_shipped_configuration_keeps_the_updater_strict() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        // The version comes from Cargo.toml alone (Info.plist is written from it too): a
        // second copy that drifts would offer the same update forever.
        assert!(conf.get("version").is_none());
        let updater = &conf["plugins"]["updater"];
        assert_eq!(updater["requireSignedVersion"], true);
        assert_eq!(updater["allowDowngrades"], false);
        assert_eq!(updater["endpoints"], serde_json::json!([]));
        for (key, _) in updater.as_object().unwrap() {
            assert!(!key.to_lowercase().contains("dangerous"), "{key}");
        }
    }

    #[test]
    fn notes_are_plain_short_text() {
        let n = clean_notes("Fixes\n\u{1b}[31mred\u{202e}x");
        assert_eq!(n, "Fixes\n[31mredx");
        let long = clean_notes(&"x".repeat(5000));
        assert_eq!(long.chars().count(), NOTES_CHARS + 1);
    }
}
