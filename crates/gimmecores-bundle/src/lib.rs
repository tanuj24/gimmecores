//! What a GimmeCores app update must hold. The app checks every downloaded update with
//! [`check_archive`] before it replaces itself, and `gmc-release` runs the same check before
//! the maintainer signs one, so a release that installed copies would refuse is never signed.

use std::io::Read as _;
use std::path::Component;

use anyhow::{Context, Result, ensure};

/// The app's bundle identifier (Info.plist).
pub const BUNDLE_ID: &str = "dev.gimmecores.desktop";

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
}
