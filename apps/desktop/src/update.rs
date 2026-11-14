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

use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

/// Where installed copies look for updates.
pub const ENDPOINT: &str =
    "https://github.com/tanuj24/gimmecores/releases/latest/download/latest.json";
/// The only place an update may be downloaded from.
pub const DOWNLOAD_PREFIX: &str = "https://github.com/tanuj24/gimmecores/releases/download/";
/// This app's bundle identifier (Info.plist).
pub const BUNDLE_ID: &str = "dev.gimmecores.desktop";
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

const LINKED: &str = "This app is a link to Homebrew's copy: update it with `brew upgrade`.";

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
    let inside = |dir: &Path| bundle.parent() == Some(dir);
    let applications =
        inside(Path::new("/Applications")) || home.is_some_and(|h| inside(&h.join("Applications")));
    if !applications {
        return Some(
            "Updates install into the Applications folder: move GimmeCores there (or install it \
             with Homebrew and update with `brew upgrade`)."
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

/// The most an update may unpack to, and hold files.
const MAX_UNPACKED: u64 = 1 << 30;
const MAX_ENTRIES: usize = 20_000;
/// Programs an update must hold (a copy without them could never update itself again).
const PROGRAMS: [&str; 3] = ["gimmecores-desktop", "gmcd", "gmc"];

/// Checks a downloaded, signature-verified archive before it replaces this app.
///
/// The updater unpacks every entry below the archive's first folder without checking paths
/// itself, so this refuses anything but plain files and folders inside `GimmeCores.app/`: no
/// `..`, absolute paths, links or devices, no setuid bits. The app inside must be GimmeCores
/// (bundle identifier), exactly the version that was announced (and signed), and hold its
/// programs.
pub fn check_archive(archive: &[u8], announced: &str) -> Result<()> {
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    let mut identity = None;
    let mut programs = Vec::new();
    let (mut total, mut count) = (0u64, 0usize);
    for entry in tar.entries()? {
        let mut entry = entry?;
        count += 1;
        ensure!(count <= MAX_ENTRIES, "the update holds too many files");
        let path = entry.path()?.into_owned();
        let parts: Vec<_> = path.components().collect();
        let inside = parts.iter().all(|c| matches!(c, Component::Normal(_)))
            && parts
                .first()
                .is_some_and(|c| c.as_os_str() == "GimmeCores.app");
        ensure!(
            inside,
            "the update holds a file outside GimmeCores.app ({})",
            path.display()
        );
        let kind = entry.header().entry_type();
        ensure!(
            kind.is_file() || kind.is_dir(),
            "the update holds a link or special file ({})",
            path.display()
        );
        let mode = entry.header().mode()?;
        ensure!(
            mode & 0o7000 == 0,
            "the update asks for special permissions ({})",
            path.display()
        );
        total = total.saturating_add(entry.size());
        ensure!(total <= MAX_UNPACKED, "the update is too large");
        let name = |i: usize| parts.get(i).map(|c| c.as_os_str());
        if parts.len() == 4
            && name(1) == Some("Contents".as_ref())
            && name(2) == Some("MacOS".as_ref())
            && kind.is_file()
            && mode & 0o111 != 0
        {
            programs.extend(name(3).and_then(|n| n.to_str()).map(str::to_string));
        }
        if parts.len() == 3
            && name(1) == Some("Contents".as_ref())
            && name(2) == Some("Info.plist".as_ref())
        {
            ensure!(entry.size() <= 64 << 10, "Info.plist is too large");
            let mut text = String::new();
            entry.read_to_string(&mut text)?;
            let id = plist_string(&text, "CFBundleIdentifier").context("no bundle identifier")?;
            let version =
                plist_string(&text, "CFBundleShortVersionString").context("no bundle version")?;
            identity = Some((id, version));
        }
    }
    let (id, version) = identity.context("the update holds no GimmeCores.app")?;
    ensure!(id == BUNDLE_ID, "the update is not GimmeCores ({id})");
    ensure!(
        version == announced,
        "the update holds version {version}, not the announced {announced}"
    );
    for p in PROGRAMS {
        ensure!(
            programs.iter().any(|x| x == p),
            "the update is missing the program {p}"
        );
    }
    Ok(())
}

/// `<key>name</key><string>value</string>` in an XML property list.
fn plist_string(text: &str, key: &str) -> Option<String> {
    let at = text.find(&format!("<key>{key}</key>"))? + key.len() + 11;
    let rest = text[at..].trim_start().strip_prefix("<string>")?;
    Some(rest[..rest.find("</string>")?].trim().to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn plist(id: &str, version: &str) -> String {
        format!(
            "<?xml version=\"1.0\"?><plist><dict>\n  <key>CFBundleIdentifier</key><string>{id}</string>\n  \
             <key>CFBundleShortVersionString</key><string>{version}</string>\n</dict></plist>"
        )
    }

    enum E<'a> {
        File(&'a str, &'a str, u32),
        Link(&'a str, &'a str),
        /// A raw name, written past the tar crate's own path checks.
        Raw(&'a str),
    }

    fn archive(entries: &[E]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let gz = flate2::write::GzEncoder::new(&mut out, flate2::Compression::default());
            let mut tar = tar::Builder::new(gz);
            for e in entries {
                let mut h = tar::Header::new_gnu();
                match e {
                    E::File(path, body, mode) => {
                        h.set_size(body.len() as u64);
                        h.set_mode(*mode);
                        h.set_cksum();
                        tar.append_data(&mut h, path, body.as_bytes()).unwrap();
                    }
                    E::Link(path, target) => {
                        h.set_entry_type(tar::EntryType::Symlink);
                        h.set_size(0);
                        h.set_mode(0o755);
                        tar.append_link(&mut h, path, target).unwrap();
                    }
                    E::Raw(path) => {
                        let name = &mut h.as_old_mut().name;
                        name[..path.len()].copy_from_slice(path.as_bytes());
                        h.set_size(1);
                        h.set_mode(0o644);
                        h.set_cksum();
                        tar.append(&h, &b"x"[..]).unwrap();
                    }
                }
            }
            tar.into_inner().unwrap().finish().unwrap();
        }
        out
    }

    /// A well-formed update with this Info.plist, plus `extra` entries.
    fn app<'a>(plist_text: &'a str, extra: Vec<E<'a>>) -> Vec<u8> {
        let mut entries = vec![
            E::File(
                "GimmeCores.app/Contents/MacOS/gimmecores-desktop",
                "bin",
                0o755,
            ),
            E::File("GimmeCores.app/Contents/MacOS/gmcd", "bin", 0o755),
            E::File("GimmeCores.app/Contents/MacOS/gmc", "bin", 0o755),
            E::File("GimmeCores.app/Contents/Info.plist", plist_text, 0o644),
        ];
        entries.extend(extra);
        archive(&entries)
    }

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
    fn the_archive_must_be_gimmecores_at_the_announced_version() {
        let ours = plist(BUNDLE_ID, "0.2.0");
        let good = app(&ours, vec![]);
        check_archive(&good, "0.2.0").unwrap();
        let err = check_archive(&good, "0.3.0").unwrap_err().to_string();
        assert!(err.contains("holds version 0.2.0"), "{err}");
        let theirs = plist("com.evil", "0.2.0");
        let other = app(&theirs, vec![]);
        let err = check_archive(&other, "0.2.0").unwrap_err().to_string();
        assert!(err.contains("not GimmeCores"), "{err}");
        let elsewhere = archive(&[E::File("Other.app/Contents/Info.plist", &ours, 0o644)]);
        assert!(check_archive(&elsewhere, "0.2.0").is_err());
        assert!(check_archive(b"not an archive", "0.2.0").is_err());
    }

    #[test]
    fn the_archive_holds_only_plain_files_inside_the_app() {
        let ours = plist(BUNDLE_ID, "0.2.0");
        let refused = |extra: Vec<E>, why: &str| {
            let err = check_archive(&app(&ours, extra), "0.2.0")
                .unwrap_err()
                .to_string();
            assert!(err.contains(why), "{why}: {err}");
        };
        refused(vec![E::Raw("GimmeCores.app/../../.zshrc")], "outside");
        refused(vec![E::Raw("/etc/hosts")], "outside");
        refused(vec![E::Raw("./GimmeCores.app/x")], "outside");
        refused(vec![E::File("._GimmeCores.app", "x", 0o644)], "outside");
        refused(
            vec![E::Link("GimmeCores.app/Contents/home", "/Users/someone")],
            "link",
        );
        refused(
            vec![E::File("GimmeCores.app/Contents/MacOS/helper", "x", 0o4755)],
            "special permissions",
        );
        // Every program must be there, and runnable.
        let missing = archive(&[
            E::File(
                "GimmeCores.app/Contents/MacOS/gimmecores-desktop",
                "b",
                0o755,
            ),
            E::File("GimmeCores.app/Contents/MacOS/gmcd", "b", 0o755),
            E::File("GimmeCores.app/Contents/MacOS/gmc", "b", 0o644),
            E::File("GimmeCores.app/Contents/Info.plist", &ours, 0o644),
        ]);
        let err = check_archive(&missing, "0.2.0").unwrap_err().to_string();
        assert!(err.contains("missing the program gmc"), "{err}");
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
