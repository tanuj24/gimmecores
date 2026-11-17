//! Dependencies for npm, Cargo and Go without network access on the lender (#27).
//!
//! Tasks have no network (I5), so `npm ci`, `cargo build` with crates.io dependencies or `go
//! build` with modules could not fetch anything there. Python already works this way (the SDK
//! installs from the lockfile here and sends the packages). `gmc run --deps cargo|npm|go`
//! (or `auto`) does the same for these: the *borrower* fetches the dependencies its lockfile
//! names, with its own network, into a cache of its own (never into the project), and sends
//! them with the task; the tool on the lender then finds them offline. Nothing changes on the
//! lender, and the no-network guarantee holds.
//!
//! - Cargo: `cargo vendor --locked` into the cache; sent under `.gmc-sdk/deps/cargo`, with a
//!   generated Cargo home (`CARGO_HOME=.gmc-sdk/deps/cargo-home`, `CARGO_NET_OFFLINE=true`)
//!   whose config replaces crates.io with those sources. Run cargo from the project's root.
//!   Git dependencies are not supported yet.
//! - Go: `go mod vendor -o` into the cache; sent as the task's `vendor/` (only when the project
//!   has none of its own), with `GOFLAGS=-mod=vendor`, `GOPROXY=off`, `GOTOOLCHAIN=local`.
//! - npm: `npm ci --ignore-scripts` on a copy of `package.json` and `package-lock.json`, with
//!   a cache of its own; that cache is sent under `.gmc-sdk/deps/npm`, with
//!   `npm_config_cache` pointing there and `npm_config_offline=true`, so `npm ci` works there.
//!   Packages with prebuilt binaries for one platform need the same OS and CPU on both sides.
//!
//! Files matching the checksums the package manager records (each crate's
//! `.cargo-checksum.json`, an npm cache's content names) are published content and sent as
//! they are; anything else gets the default excludes and the secret scan, as the project does.
//! The cache is keyed by the lockfile's hash, so an unchanged lockfile is fetched once.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest as _, Sha256};

use crate::tree::{Attachment, Published};

/// A package manager whose dependencies can be sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Cargo,
    Npm,
    Go,
}

impl Kind {
    pub fn parse(s: &str) -> Result<Vec<Self>> {
        Ok(match s {
            "cargo" => vec![Self::Cargo],
            "npm" => vec![Self::Npm],
            "go" => vec![Self::Go],
            other => bail!("--deps must be cargo, npm, go or auto, not {other:?}"),
        })
    }

    /// The kinds whose lockfile the project has.
    pub fn detect(project: &Path) -> Vec<Self> {
        let mut out = Vec::new();
        if project.join("Cargo.lock").is_file() {
            out.push(Self::Cargo);
        }
        if project.join("package-lock.json").is_file() {
            out.push(Self::Npm);
        }
        if project.join("go.sum").is_file() || project.join("go.mod").is_file() {
            out.push(Self::Go);
        }
        out
    }

    fn name(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::Npm => "npm",
            Self::Go => "go",
        }
    }
}

/// What a task needs for its dependencies: files to send and variables to set.
#[derive(Debug, Default)]
pub struct Prepared {
    pub attachments: Vec<Attachment>,
    pub env: Vec<(String, String)>,
}

/// Where fetched dependencies are kept on this computer (never in the project).
pub fn cache_root() -> PathBuf {
    let env = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let base = if cfg!(target_os = "macos") {
        env("HOME").map(|h| h.join("Library/Caches"))
    } else if cfg!(windows) {
        env("LOCALAPPDATA")
    } else {
        env("XDG_CACHE_HOME").or_else(|| env("HOME").map(|h| h.join(".cache")))
    };
    base.unwrap_or_else(std::env::temp_dir)
        .join("GimmeCores")
        .join("deps")
}

fn hash_files(files: &[PathBuf]) -> Result<String> {
    let mut h = Sha256::new();
    for f in files {
        h.update(
            f.file_name()
                .map(|n| n.as_encoded_bytes())
                .unwrap_or_default(),
        );
        h.update(b"\0");
        if f.is_file() {
            h.update(std::fs::read(f).with_context(|| format!("reading {}", f.display()))?);
        }
        h.update(b"\0");
    }
    Ok(hex::encode(&h.finalize()[..16]))
}

fn run(cmd: &mut Command, what: &str) -> Result<()> {
    let out = cmd
        .output()
        .with_context(|| format!("{what}: is it installed and on your PATH?"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let lines: Vec<&str> = err.lines().collect();
        let tail = lines[lines.len().saturating_sub(6)..].join("\n");
        bail!("{what} failed:\n{tail}");
    }
    Ok(())
}

/// Fetches into `dir` (made whole or not at all: a partly fetched cache is never used).
fn fetch_once(dir: &Path, fetch: impl FnOnce(&Path) -> Result<()>) -> Result<()> {
    if dir.join(".complete").is_file() {
        return Ok(());
    }
    let tmp = dir.with_extension("partial");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    fetch(&tmp)?;
    std::fs::write(tmp.join(".complete"), b"")?;
    let _ = std::fs::remove_dir_all(dir);
    std::fs::rename(&tmp, dir)?;
    Ok(())
}

/// The Cargo home a task gets: crates.io replaced by the vendored sources next to it.
pub const CARGO_CONFIG: &str = "[source.crates-io]\nreplace-with = \"gmc-vendored\"\n\n\
                                [source.gmc-vendored]\ndirectory = \"cargo\"\n";

/// Fetches `kind`'s dependencies for `project` (with this computer's network) and says how to
/// send them. `offline`: only from what this computer already has (tests).
pub fn prepare(kind: Kind, project: &Path, cache: &Path, offline: bool) -> Result<Prepared> {
    let mut p = Prepared::default();
    match kind {
        Kind::Cargo => {
            let lock = project.join("Cargo.lock");
            ensure!(
                lock.is_file(),
                "--deps cargo needs a Cargo.lock in this folder"
            );
            let text = std::fs::read_to_string(&lock)?;
            ensure!(
                !text.contains("source = \"git+"),
                "--deps cargo does not support git dependencies yet"
            );
            // The generated config replaces crates.io only: other registries would be fetched
            // there, without network, and fail.
            for line in text.lines().filter(|l| l.starts_with("source = ")) {
                ensure!(
                    line.contains("registry+https://github.com/rust-lang/crates.io-index")
                        || line.contains("sparse+https://index.crates.io/"),
                    "--deps cargo supports crates.io only, not {}",
                    line.trim_start_matches("source = ")
                );
            }
            let dir = cache
                .join("cargo")
                .join(hash_files(&[project.join("Cargo.toml"), lock])?);
            fetch_once(&dir, |tmp| {
                let mut c = Command::new("cargo");
                c.current_dir(project)
                    .args(["vendor", "--locked", "--versioned-dirs", "-q"])
                    .arg(tmp.join("vendor"));
                if offline {
                    c.arg("--offline");
                }
                run(&mut c, "cargo vendor")?;
                std::fs::create_dir_all(tmp.join("cargo-home"))?;
                std::fs::write(tmp.join("cargo-home/config.toml"), CARGO_CONFIG)?;
                Ok(())
            })?;
            p.attachments.push(Attachment {
                local: dir.join("vendor"),
                path: ".gmc-sdk/deps/cargo".into(),
                published: Published::Cargo,
                ..Default::default()
            });
            p.attachments.push(Attachment {
                local: dir.join("cargo-home"),
                path: ".gmc-sdk/deps/cargo-home".into(),
                ..Default::default()
            });
            p.env
                .push(("CARGO_HOME".into(), ".gmc-sdk/deps/cargo-home".into()));
            p.env.push(("CARGO_NET_OFFLINE".into(), "true".into()));
        }
        Kind::Go => {
            ensure!(
                project.join("go.mod").is_file(),
                "--deps go needs a go.mod in this folder"
            );
            p.env.push(("GOFLAGS".into(), "-mod=vendor".into()));
            p.env.push(("GOPROXY".into(), "off".into()));
            p.env.push(("GOTOOLCHAIN".into(), "local".into()));
            // A project that vendors its modules already sends them.
            if project.join("vendor").exists() {
                return Ok(p);
            }
            let dir = cache.join("go").join(hash_files(&[
                project.join("go.mod"),
                project.join("go.sum"),
            ])?);
            fetch_once(&dir, |tmp| {
                let mut c = Command::new("go");
                c.current_dir(project)
                    .args(["mod", "vendor", "-o"])
                    .arg(tmp.join("vendor"));
                if offline {
                    c.env("GOFLAGS", "-mod=mod").env("GOPROXY", "off");
                }
                run(&mut c, "go mod vendor")
            })?;
            p.attachments.push(Attachment {
                local: dir.join("vendor"),
                path: "vendor".into(),
                at_project_path: true,
                ..Default::default()
            });
        }
        Kind::Npm => {
            let lock = project.join("package-lock.json");
            ensure!(
                lock.is_file(),
                "--deps npm needs a package-lock.json in this folder"
            );
            let manifest = project.join("package.json");
            let dir = cache
                .join("npm")
                .join(hash_files(&[manifest.clone(), lock.clone()])?);
            fetch_once(&dir, |tmp| {
                // On a copy of the two files: the project's own node_modules is not touched,
                // and no install script runs here.
                let work = tmp.join("work");
                std::fs::create_dir_all(&work)?;
                std::fs::copy(&manifest, work.join("package.json"))?;
                std::fs::copy(&lock, work.join("package-lock.json"))?;
                let mut c = Command::new("npm");
                c.current_dir(&work)
                    .args(["ci", "--ignore-scripts", "--no-audit", "--no-fund"])
                    .arg("--cache")
                    .arg(tmp.join("cache"));
                if offline {
                    c.arg("--offline");
                }
                run(&mut c, "npm ci")?;
                std::fs::remove_dir_all(&work)?;
                // A project with no packages leaves no cache: an empty one then.
                std::fs::create_dir_all(tmp.join("cache/_cacache"))?;
                Ok(())
            })?;
            // The cache itself only (not npm's logs).
            p.attachments.push(Attachment {
                local: dir.join("cache/_cacache"),
                path: ".gmc-sdk/deps/npm/_cacache".into(),
                published: Published::Npm,
                ..Default::default()
            });
            for (k, v) in [
                ("npm_config_cache", ".gmc-sdk/deps/npm"),
                ("npm_config_offline", "true"),
                ("npm_config_audit", "false"),
                ("npm_config_fund", "false"),
                ("npm_config_update_notifier", "false"),
            ] {
                p.env.push((k.into(), v.into()));
            }
        }
    }
    tracing::debug!("{} dependencies ready", kind.name());
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_are_named_or_found_from_lockfiles() {
        assert_eq!(Kind::parse("cargo").unwrap(), [Kind::Cargo]);
        assert!(Kind::parse("pip").is_err());
        let d = tempfile::tempdir().unwrap();
        assert!(Kind::detect(d.path()).is_empty());
        std::fs::write(d.path().join("Cargo.lock"), "").unwrap();
        std::fs::write(d.path().join("package-lock.json"), "{}").unwrap();
        assert_eq!(Kind::detect(d.path()), [Kind::Cargo, Kind::Npm]);
    }

    #[test]
    fn git_dependencies_and_missing_lockfiles_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        assert!(prepare(Kind::Cargo, d.path(), cache.path(), true).is_err());
        std::fs::write(
            d.path().join("Cargo.lock"),
            "[[package]]\nname = \"x\"\nsource = \"git+https://example.com/x\"\n",
        )
        .unwrap();
        let e = prepare(Kind::Cargo, d.path(), cache.path(), true).unwrap_err();
        assert!(format!("{e:#}").contains("git"), "{e:#}");
        assert!(prepare(Kind::Npm, d.path(), cache.path(), true).is_err());
        assert!(prepare(Kind::Go, d.path(), cache.path(), true).is_err());
    }

    #[test]
    fn a_failed_fetch_leaves_nothing_to_use() {
        let cache = tempfile::tempdir().unwrap();
        let dir = cache.path().join("x");
        assert!(fetch_once(&dir, |_| bail!("no network")).is_err());
        assert!(!dir.exists());
        fetch_once(&dir, |t| Ok(std::fs::write(t.join("f"), "ok")?)).unwrap();
        assert!(dir.join(".complete").is_file());
        // Already complete: not fetched again.
        fetch_once(&dir, |_| bail!("fetched twice")).unwrap();
    }
}
