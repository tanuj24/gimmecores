//! For scripts/test-self-update.sh only: throwaway, UNENCRYPTED update keys and signatures, and
//! manifests that may point at a local test server. A release key is made with
//! `gmc-release keygen` (password-protected) and nothing here can read one.
//!
//!   sign-for-tests keygen <dir>                       -> <dir>/test.key, <dir>/test.pub.b64
//!   sign-for-tests sign <dir> <version> <archive>     -> <archive>.sig
//!   sign-for-tests sign-unversioned <dir> <archive>   -> <archive>.sig, no version in it
//!   sign-for-tests manifest <version> <url> <sig> <out>

use anyhow::{Context, Result, bail};
use std::path::Path;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["keygen", dir] => {
            let dir = Path::new(dir);
            std::fs::create_dir_all(dir)?;
            let kp = minisign::KeyPair::generate_unencrypted_keypair()?;
            let sk = kp.sk.to_box(Some("THROWAWAY TEST KEY"))?.to_string();
            std::fs::write(dir.join("test.key"), sk)?;
            let pk = kp.pk.to_box()?.to_string();
            std::fs::write(dir.join("test.pub.b64"), gimmecores_release::base64_of(&pk))?;
        }
        ["sign", dir, version, archive] => {
            let text = std::fs::read_to_string(Path::new(dir).join("test.key"))?;
            let sk = minisign::SecretKeyBox::from_string(&text)?
                .into_unencrypted_secret_key()
                .context("not a test key")?;
            let sig = gimmecores_release::sign(&sk, version, Path::new(archive))?;
            std::fs::write(gimmecores_release::sig_path(Path::new(archive)), sig)?;
        }
        ["sign-unversioned", dir, archive] => {
            let text = std::fs::read_to_string(Path::new(dir).join("test.key"))?;
            let sk = minisign::SecretKeyBox::from_string(&text)?
                .into_unencrypted_secret_key()
                .context("not a test key")?;
            let file = std::fs::File::open(archive)?;
            let sig = minisign::sign(None, &sk, file, Some("timestamp:0\tfile:x"), None)?;
            std::fs::write(
                gimmecores_release::sig_path(Path::new(archive)),
                sig.to_string(),
            )?;
        }
        ["manifest", version, url, sig, out] => {
            let sig = std::fs::read_to_string(sig)?;
            let json = serde_json::json!({
                "version": version,
                "notes": "Test update.",
                "pub_date": gimmecores_release::rfc3339_now(),
                "platforms": { "darwin-aarch64": {
                    "url": url,
                    "signature": gimmecores_release::base64_of(&sig),
                }},
            });
            std::fs::write(out, serde_json::to_string_pretty(&json)?)?;
        }
        _ => bail!("usage: see the top of examples/sign-for-tests.rs"),
    }
    Ok(())
}
