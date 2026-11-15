//! Signing GimmeCores app updates (the `gmc-release` tool, and the self-update test).
//!
//! The signature is minisign's, as the app's updater (tauri-plugin-updater) verifies it: the
//! signature text, base64-encoded, in the update manifest. Its trusted comment (covered by the
//! signature) carries the version, and the app refuses an update whose signed version differs
//! from the one announced: an old, genuinely signed release cannot be replayed as a new one.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;

pub const KEY_FILE: &str = "gimmecores-update.key";
pub const PUB_FILE: &str = "gimmecores-update.pub";

/// Creates the password-protected key pair in `dir` (the password is asked for twice), never
/// overwriting one.
pub fn keygen(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let (key, public) = (dir.join(KEY_FILE), dir.join(PUB_FILE));
    ensure!(
        !key.exists() && !public.exists(),
        "{} already holds a key: refusing to overwrite it",
        dir.display()
    );
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let sk_file = opts.open(&key)?;
    let mut pk_bytes = Vec::new();
    // `None`: the password is asked for interactively, twice; never on the command line.
    let made = minisign::KeyPair::generate_and_write_encrypted_keypair(
        &mut pk_bytes,
        sk_file,
        Some("GimmeCores update key: keep this file and its password private"),
        None,
    );
    if let Err(e) = made {
        let _ = std::fs::remove_file(&key);
        bail!("{e}");
    }
    std::fs::write(&public, &pk_bytes)?;
    let line = base64::engine::general_purpose::STANDARD.encode(&pk_bytes);
    let mut out = std::io::stdout();
    writeln!(
        out,
        "Secret key: {} (keep it, with an offline backup)",
        key.display()
    )?;
    writeln!(out, "Public key: {}", public.display())?;
    writeln!(
        out,
        "\nThe line the app is built with (save it as packaging/release/update-key.pub):\n{line}"
    )?;
    Ok(())
}

/// The minisign signature text for `archive`, binding `version` in the trusted comment the way
/// the app reads it (`version:` among tab-separated fields).
pub fn sign(sk: &minisign::SecretKey, version: &str, archive: &Path) -> Result<String> {
    check_version(version)?;
    let name = archive
        .file_name()
        .and_then(|n| n.to_str())
        .context("archive name")?;
    let file = std::fs::File::open(archive)?;
    let trusted = format!("timestamp:{}\tfile:{name}\tversion:{version}", unix_now());
    let sig = minisign::sign(None, sk, file, Some(&trusted), Some("GimmeCores update"))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(sig.to_string())
}

pub fn check_version(v: &str) -> Result<()> {
    let parts: Vec<&str> = v.split('.').collect();
    ensure!(
        parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())),
        "the version must look like 1.2.3 (no leading v): {v:?}"
    );
    Ok(())
}

pub fn base64_of(text: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(text.as_bytes())
}

/// The update manifest (tauri-plugin-updater's static format).
pub fn manifest(
    version: &str,
    notes: &str,
    url: &str,
    sig: &str,
    target: &str,
    pub_date: &str,
) -> Result<String> {
    check_version(version)?;
    ensure!(
        url.starts_with("https://"),
        "the download URL must be https: {url}"
    );
    let mut platforms = serde_json::Map::new();
    platforms.insert(
        target.to_string(),
        serde_json::json!({ "url": url, "signature": base64_of(sig) }),
    );
    Ok(serde_json::to_string_pretty(&serde_json::json!({
        "version": version,
        "notes": notes.trim(),
        "pub_date": pub_date,
        "platforms": platforms,
    }))?)
}

/// What the app does with a downloaded update (tauri-plugin-updater 2.14,
/// `verify_signature` with `requireSignedVersion`): decode the base64 public key and signature,
/// check the signature (legacy and prehashed both allowed), then require the trusted comment's
/// version to equal the announced one.
pub fn verify_as_the_app_does(
    pubkey_b64: &str,
    sig_b64: &str,
    version: &str,
    data: &[u8],
) -> Result<()> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let pk_text = String::from_utf8(b64.decode(pubkey_b64)?)?;
    let sig_text = String::from_utf8(b64.decode(sig_b64)?)?;
    let pk = minisign::PublicKeyBox::from_string(&pk_text)
        .and_then(minisign::PublicKeyBox::into_public_key)
        .map_err(|e| anyhow::anyhow!("public key: {e}"))?;
    let sig = minisign::SignatureBox::from_string(&sig_text).map_err(|e| anyhow::anyhow!("{e}"))?;
    minisign::verify(&pk, &sig, std::io::Cursor::new(data), true, false, true)
        .map_err(|e| anyhow::anyhow!("signature: {e}"))?;
    let trusted = sig.trusted_comment().map_err(|e| anyhow::anyhow!("{e}"))?;
    let signed = trusted
        .split('\t')
        .find_map(|f| f.strip_prefix("version:"))
        .context("the signature carries no version")?;
    ensure!(
        signed == version,
        "signed for version {signed}, announced as {version}"
    );
    Ok(())
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// RFC 3339, UTC, from the Unix clock (no time-zone database needed).
pub fn rfc3339_now() -> String {
    let secs = i64::try_from(unix_now()).unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
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
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

pub fn sig_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_owned();
    s.push(".sig");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// A key pair for tests (unencrypted: tests cannot type a password).
    fn keys() -> (minisign::KeyPair, String) {
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let pk_line = base64_of(&kp.pk.to_box().unwrap().to_string());
        (kp, pk_line)
    }

    fn archive(dir: &Path, bytes: &[u8]) -> PathBuf {
        let p = dir.join("GimmeCores.app.tar.gz");
        std::fs::write(&p, bytes).unwrap();
        p
    }

    /// The exact check of the app's updater (minisign-verify 0.3, as the plugin uses it), not
    /// our own re-implementation.
    fn plugin_verifies(pk_line: &str, sig_text: &str, data: &[u8]) -> bool {
        let b64 = base64::engine::general_purpose::STANDARD;
        let pk = String::from_utf8(b64.decode(pk_line).unwrap()).unwrap();
        let sig = String::from_utf8(b64.decode(base64_of(sig_text)).unwrap()).unwrap();
        let pk = minisign_verify::PublicKey::decode(&pk).unwrap();
        let sig = minisign_verify::Signature::decode(&sig).unwrap();
        pk.verify(data, &sig, true).is_ok()
            && sig
                .trusted_comment()
                .split('\t')
                .any(|f| f.starts_with("version:"))
    }

    #[test]
    fn a_signed_update_verifies_as_the_app_does_and_carries_its_version() {
        let d = tempfile::tempdir().unwrap();
        let (kp, pk) = keys();
        let a = archive(d.path(), b"the new app");
        let sig = sign(&kp.sk, "0.2.0", &a).unwrap();
        assert!(plugin_verifies(&pk, &sig, b"the new app"));
        verify_as_the_app_does(&pk, &base64_of(&sig), "0.2.0", b"the new app").unwrap();
        assert!(sig.contains("version:0.2.0"));
    }

    #[test]
    fn tampering_another_key_or_a_replayed_version_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let (kp, pk) = keys();
        let (_, other_pk) = keys();
        let a = archive(d.path(), b"the new app");
        let sig = sign(&kp.sk, "0.2.0", &a).unwrap();
        // A changed archive.
        assert!(!plugin_verifies(&pk, &sig, b"the new app, changed"));
        assert!(verify_as_the_app_does(&pk, &base64_of(&sig), "0.2.0", b"tampered").is_err());
        // Someone else's key.
        assert!(!plugin_verifies(&other_pk, &sig, b"the new app"));
        // A genuine old release announced as a newer version.
        let err = verify_as_the_app_does(&pk, &base64_of(&sig), "9.9.9", b"the new app")
            .unwrap_err()
            .to_string();
        assert!(err.contains("signed for version 0.2.0"), "{err}");
    }

    #[test]
    fn manifests_are_https_with_a_valid_version_and_the_signature_as_the_app_reads_it() {
        let m = manifest(
            "0.2.0",
            "  notes  ",
            "https://github.com/x/y/releases/download/v0.2.0/GimmeCores.app.tar.gz",
            "untrusted comment: x\nABC\ntrusted comment: t\nDEF\n",
            "darwin-aarch64",
            "2026-11-14T00:00:00Z",
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&m).unwrap();
        assert_eq!(v["version"], "0.2.0");
        assert_eq!(v["notes"], "notes");
        let sig = v["platforms"]["darwin-aarch64"]["signature"]
            .as_str()
            .unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(sig)
            .unwrap();
        assert!(
            String::from_utf8(decoded)
                .unwrap()
                .starts_with("untrusted comment")
        );
        assert!(manifest("0.2.0", "", "http://x/y", "s", "t", "d").is_err());
        for bad in ["v0.2.0", "0.2", "0.2.0-rc1", "0.2.x", ""] {
            assert!(
                manifest(bad, "", "https://x/y", "s", "t", "d").is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn keygen_never_overwrites_a_key() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(KEY_FILE), "existing").unwrap();
        let err = keygen(d.path()).unwrap_err().to_string();
        assert!(err.contains("refusing to overwrite"), "{err}");
        assert_eq!(
            std::fs::read_to_string(d.path().join(KEY_FILE)).unwrap(),
            "existing"
        );
    }

    #[test]
    fn dates_are_rfc3339() {
        let s = rfc3339_now();
        assert_eq!(s.len(), 20, "{s}");
        assert!(s.ends_with('Z') && s.as_bytes()[10] == b'T', "{s}");
    }
}
