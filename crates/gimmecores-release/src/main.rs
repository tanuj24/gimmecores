//! `gmc-release`: signs GimmeCores app updates on the maintainer's own Mac.
//!
//! Every installed GimmeCores trusts exactly one update key (its public half is built into the
//! app). Whoever holds the private half can make every installed copy run new code, so it is
//! created here, password-protected, kept on the maintainer's machine, and never given to CI or
//! anyone else (docs/RELEASING.md).
//!
//! How updates are signed and checked: src/lib.rs.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use gimmecores_release::{
    base64_of, check_version, keygen, manifest, rfc3339_now, sig_path, sign, verify_as_the_app_does,
};

#[derive(Parser)]
#[command(
    name = "gmc-release",
    about = "Sign GimmeCores app updates (maintainer only)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the update key pair (asks for a password twice). Keep the secret key file and an
    /// offline backup of it: without it, installed copies can never be updated again.
    Keygen {
        /// Folder for `gimmecores-update.key` (secret, mode 0600) and `gimmecores-update.pub`.
        #[arg(long)]
        dir: PathBuf,
    },
    /// Sign an update archive for one version (asks for the key's password). Writes
    /// `<archive>.sig`. Refuses an archive the app would refuse (gimmecores-bundle).
    Sign {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        version: String,
        archive: PathBuf,
    },
    /// Check an update exactly as the app will: the signature with the public key built into
    /// the app, then what the archive holds.
    Verify {
        /// File holding the app's public key line (base64), e.g. packaging/release/update-key.pub
        #[arg(long)]
        pubkey: PathBuf,
        #[arg(long)]
        version: String,
        archive: PathBuf,
        sig: PathBuf,
    },
    /// Write the update manifest (latest.json) the app reads.
    Manifest {
        #[arg(long)]
        version: String,
        /// Plain-text release notes (shown in the app; cut to 2000 characters there).
        #[arg(long)]
        notes: PathBuf,
        /// Where the signed archive will be downloaded from (must be https).
        #[arg(long)]
        url: String,
        #[arg(long)]
        sig: PathBuf,
        /// Platform key, e.g. darwin-aarch64.
        #[arg(long, default_value = "darwin-aarch64")]
        target: String,
        /// Where to write the manifest.
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen { dir } => keygen(&dir),
        Cmd::Sign {
            key,
            version,
            archive,
        } => {
            check_version(&version)?;
            gimmecores_bundle::check_archive(&std::fs::read(&archive)?, &version)
                .context("the app would refuse this archive: not signing it")?;
            let sk = minisign::SecretKey::from_file(&key, None)
                .map_err(|e| anyhow::anyhow!("{e}"))
                .context("reading the secret key (wrong password?)")?;
            let sig = sign(&sk, &version, &archive)?;
            let out = sig_path(&archive);
            std::fs::write(&out, &sig)?;
            println!(
                "Signed {} for version {version}: {}",
                archive.display(),
                out.display()
            );
            Ok(())
        }
        Cmd::Verify {
            pubkey,
            version,
            archive,
            sig,
        } => {
            let pubkey = std::fs::read_to_string(&pubkey)?;
            let sig = std::fs::read_to_string(&sig)?;
            let data = std::fs::read(&archive)?;
            verify_as_the_app_does(pubkey.trim(), &base64_of(&sig), &version, &data)?;
            gimmecores_bundle::check_archive(&data, &version)
                .context("the app would refuse this archive")?;
            println!("OK: {} is signed for version {version}", archive.display());
            Ok(())
        }
        Cmd::Manifest {
            version,
            notes,
            url,
            sig,
            target,
            out,
        } => {
            let notes = std::fs::read_to_string(&notes)?;
            let sig = std::fs::read_to_string(&sig)?;
            let json = manifest(&version, &notes, &url, &sig, &target, &rfc3339_now())?;
            std::fs::write(&out, json)?;
            println!("Wrote {}", out.display());
            Ok(())
        }
    }
}
