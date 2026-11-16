//! Build caches kept on the lender between a borrower's tasks (#26): `gmc run --cache target/`.
//!
//! Owner's decision (2026-11-16): a cache lives only while the borrower holds a live grant. It
//! is kept in the borrower's own namespace (`blobs/<borrower>/caches/<key>`, the key from the
//! borrower's project and the cache's path), so it counts against the grant's disk quota, is
//! never visible to another borrower, and is deleted with the namespace when the last grant
//! ends (I14 unchanged).
//!
//! No sandbox gains a new opening: before a task runs, its cache folder is *moved* into the
//! task folder at its path (one rename on the same disk), and moved back after the task, once
//! its outputs are collected. The task only ever writes inside its own folder, as before.
//! Moving back goes through real folders only: if the task turned the cache's path or any
//! folder above it into a link (to reach the lender's files), the cache is dropped instead, so
//! nothing outside the task folder is ever moved. One task holds a cache at a time; another
//! that wants it meanwhile starts cold. The borrower does not upload a cache's path.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use gimmecores_core::{GrantId, PeerKey, TaskId};
use sha2::{Digest as _, Sha256};

use crate::node::Node;
use crate::tree;

/// At most this many caches per task.
pub const MAX_CACHES: usize = 8;
/// A project's scope (from the borrower) is at most this long.
pub const MAX_SCOPE: usize = 64;

/// Checks a cache path a task names: relative, inside the project, not the SDK's own folder.
pub fn validate(path: &str) -> Result<String> {
    let p = path.trim_end_matches('/');
    ensure!(!p.is_empty(), "a cache path cannot be empty");
    let checked = tree::validate_output_path(p)?;
    ensure!(
        !checked.starts_with(tree::SDK_DIR),
        "{path:?} is GimmeCores' own folder, not a cache"
    );
    Ok(p.to_string())
}

/// Checks a task's caches (count, paths, no repeats).
pub fn validate_all(paths: &[String]) -> Result<Vec<String>> {
    ensure!(
        paths.len() <= MAX_CACHES,
        "at most {MAX_CACHES} caches per task"
    );
    let mut out: Vec<String> = Vec::new();
    for p in paths {
        let p = validate(p)?;
        ensure!(!out.contains(&p), "cache {p:?} named twice");
        out.push(p);
    }
    Ok(out)
}

/// The cache's folder name: from the borrower's project scope, the way the task runs (a
/// sandbox's build is not a container's) and the path.
fn key(scope: &[u8], runtime: &str, path: &str) -> String {
    let h = Sha256::new()
        .chain_update(b"gimmecores-cache-v1\0")
        .chain_update(scope)
        .chain_update(b"\0")
        .chain_update(runtime.as_bytes())
        .chain_update(b"\0")
        .chain_update(path.as_bytes());
    hex::encode(&h.finalize()[..16])
}

/// The borrower's scope for a project folder (not its path: a hash of it).
pub fn scope_of(dir: &Path) -> Vec<u8> {
    let canonical = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    Sha256::new()
        .chain_update(b"gimmecores-cache-scope-v1\0")
        .chain_update(canonical.to_string_lossy().as_bytes())
        .finalize()[..16]
        .to_vec()
}

/// `rel` under `root` names only real folders all the way (no link anywhere), and `rel`
/// itself is a real folder.
fn real_dir_under(root: &Path, rel: &Path) -> bool {
    let mut at = root.to_path_buf();
    for part in rel.components() {
        at.push(part);
        match std::fs::symlink_metadata(&at) {
            Ok(m) if m.file_type().is_dir() => {}
            _ => return false,
        }
    }
    true
}

/// A cache moved into a task's folder, to move back after it.
#[derive(Clone, Debug)]
pub(crate) struct CheckedOut {
    pub rel: PathBuf,
    pub dir: PathBuf,
    /// The times the task's files were given ([`Times`]), kept with the cache.
    pub times: std::sync::Arc<Times>,
}

/// When each file and folder of a task folder last got its content, by this computer's clock, kept beside
/// a cache (`<key>.times`, written and read by the daemon only). A task folder is made anew
/// for each task, so every file in it would look just edited, and build tools that compare
/// times (Cargo, make) would rebuild everything despite the cache. With these, a file whose
/// content is what the cache's last build saw gets that time back; any other file gets the
/// time the task starts. Only this computer's clock is used, so a borrower's clock that is
/// behind cannot make a changed file look older than the build.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct Times(std::collections::HashMap<String, Stamp>);

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Stamp {
    hash: String,
    size: u64,
    secs: i64,
    nanos: u32,
}

/// A times file larger than this is not read (the cache's files then all look changed).
const MAX_TIMES_FILE: u64 = 64 << 20;

fn times_file(cache_dir: &Path) -> PathBuf {
    let mut name = cache_dir.as_os_str().to_owned();
    name.push(".times");
    PathBuf::from(name)
}

fn load_times(cache_dir: &Path) -> Option<Times> {
    let path = times_file(cache_dir);
    let m = std::fs::symlink_metadata(&path).ok()?;
    if !m.is_file() || m.len() > MAX_TIMES_FILE {
        return None;
    }
    serde_json::from_slice(&std::fs::read(&path).ok()?).ok()
}

fn save_times(cache_dir: &Path, times: &Times) -> Result<()> {
    let path = times_file(cache_dir);
    let tmp = times_file(&cache_dir.with_extension("tmp"));
    std::fs::write(&tmp, serde_json::to_vec(times)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Now, as the file system records it in `dir`: Linux stamps files from a coarser clock that
/// can be a few milliseconds behind the system's, so a file the task writes right after it
/// starts could otherwise look older than the time given to its inputs.
fn fs_now(dir: &Path) -> (i64, u32) {
    let marker = dir.join(format!(
        ".gmc-now-{}",
        crate::wire::random32().map_or_else(|_| "0".into(), |r| hex::encode(&r[..8]))
    ));
    let made = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
        .and_then(|f| f.metadata())
        .and_then(|m| m.modified());
    let _ = std::fs::remove_file(&marker);
    let now = made
        .unwrap_or_else(|_| std::time::SystemTime::now())
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (
        i64::try_from(now.as_secs()).unwrap_or(i64::MAX),
        now.subsec_nanos(),
    )
}

/// Sets a file's modification time, never through a link.
#[cfg(unix)]
fn set_time(path: &Path, secs: i64, nanos: u32) -> Result<()> {
    let t = rustix::fs::Timespec {
        tv_sec: secs as _,
        tv_nsec: nanos as _,
    };
    rustix::fs::utimensat(
        rustix::fs::CWD,
        path,
        &rustix::fs::Timestamps {
            last_access: t,
            last_modification: t,
        },
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )?;
    Ok(())
}

#[cfg(not(unix))]
fn set_time(_: &Path, _: i64, _: u32) -> Result<()> {
    bail!("not on this platform")
}

impl Node {
    /// Bytes a borrower keeps on this computer (stored files, kept packages, caches).
    pub fn blob_usage(&self, borrower: &PeerKey) -> u64 {
        self.inner.blobs.usage(borrower)
    }

    /// Moves `remote`'s caches for this task into its folder (just made from the upload of
    /// `root`, without the folder at `skip`), and gives the folder's files their times
    /// ([`Times`]). A cache another task holds is left to it (this one starts cold).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn check_out_caches(
        &self,
        remote: PeerKey,
        task: TaskId,
        scope: &[u8],
        runtime: &str,
        paths: &[String],
        workspace: &Path,
        root: &crate::blobs::Digest,
        skip: Option<&Path>,
    ) -> Result<()> {
        if paths.is_empty() {
            return Ok(());
        }
        ensure!(scope.len() <= MAX_SCOPE, "cache scope too long");
        let paths = validate_all(paths)?;
        let base = self.inner.blobs.caches_dir(&remote);
        let mut out = Vec::new();
        // The times each cache's last build saw (None: a new cache).
        let mut seen: Vec<Option<Times>> = Vec::new();
        for p in paths {
            let rel = PathBuf::from(&p);
            let dir = base.join(key(scope, runtime, &p));
            // Uploaded files at that path win; the borrower does not send a cache's path.
            if std::fs::symlink_metadata(workspace.join(&rel)).is_ok() {
                continue;
            }
            if !self.state().caches_out.insert(dir.clone()) {
                continue;
            }
            let had = dir.is_dir();
            if had {
                let target = workspace.join(&rel);
                let moved = target
                    .parent()
                    .map_or(Ok(()), std::fs::create_dir_all)
                    .and_then(|()| {
                        // The folders just made must be real ones (the upload has no links).
                        if real_dir_under(workspace, rel.parent().unwrap_or(Path::new(""))) {
                            std::fs::rename(&dir, &target)
                        } else {
                            Err(std::io::Error::other("not a real folder"))
                        }
                    });
                if let Err(e) = moved {
                    tracing::warn!("cache not used ({e})");
                    self.state().caches_out.remove(&dir);
                    continue;
                }
            }
            seen.push(if had { load_times(&dir) } else { None });
            out.push((rel, dir));
        }
        self.inner.blobs.dirs_changed(&remote);
        if out.is_empty() {
            return Ok(());
        }
        let times = std::sync::Arc::new(self.give_times(remote, root, skip, workspace, &seen)?);
        let out = out
            .into_iter()
            .map(|(rel, dir)| CheckedOut {
                rel,
                dir,
                times: times.clone(),
            })
            .collect();
        self.state().caches_checked.insert(task, out);
        Ok(())
    }

    /// Gives every file and folder of the task folder its time: the one every cache's last
    /// build saw if its content is the same (for a folder: everything in it), else now.
    /// Folders come last, as giving a file its time leaves its folder's alone.
    fn give_times(
        &self,
        remote: PeerKey,
        root: &crate::blobs::Digest,
        skip: Option<&Path>,
        workspace: &Path,
        seen: &[Option<Times>],
    ) -> Result<Times> {
        let (now_secs, now_nanos) = fs_now(workspace);
        let mut entries = tree::entries_of(&self.inner.blobs, &remote, root, skip)?;
        // Files first, then folders deepest first.
        entries.sort_by_key(|e| (e.dir, std::cmp::Reverse(e.path.components().count())));
        let mut times = Times::default();
        for e in entries {
            // A folder's name ends in `/` (the root is `/`), so it never meets a file's.
            let mut name = e.path.to_string_lossy().into_owned();
            if e.dir {
                name.push('/');
            }
            let hash = e.digest.hex();
            let earlier = seen
                .iter()
                .map(|t| t.as_ref().and_then(|t| t.0.get(&name)).cloned())
                .collect::<Option<Vec<Stamp>>>()
                .filter(|s| s.windows(2).all(|w| w[0] == w[1]))
                .and_then(|s| s.into_iter().next())
                .filter(|s| s.hash == hash && s.size == e.digest.size);
            let mut stamp = Stamp {
                hash,
                size: e.digest.size,
                secs: now_secs,
                nanos: now_nanos,
            };
            let path = workspace.join(&e.path);
            if let Some(old) = earlier
                && set_time(&path, old.secs, old.nanos).is_ok()
            {
                stamp = old;
            } else {
                let _ = set_time(&path, now_secs, now_nanos);
            }
            times.0.insert(name, stamp);
        }
        Ok(times)
    }

    /// After the task (outputs collected): moves its caches back, through real folders only
    /// and by file descriptor (fsafe.rs). A cache is dropped instead when the task made a link
    /// of it, the task was stopped on the disk limit (`keep` false), keeping it would go over
    /// the grant's disk limit, or `remote` no longer holds a live grant. Returns the folder to
    /// remove now.
    pub(crate) fn check_in_caches(
        &self,
        remote: PeerKey,
        grant: GrantId,
        task: TaskId,
        workspace: &Path,
        keep: bool,
    ) -> PathBuf {
        let Some(list) = self.state().caches_checked.remove(&task) else {
            return workspace.to_path_buf();
        };
        let (live, limit) = {
            let s = self.state();
            (
                s.grants.has_live_grant(remote, crate::now()),
                s.grants.terms(grant).map_or(0, |t| t.limits.disk_bytes),
            )
        };
        for c in list {
            let back = || -> Result<()> {
                if !live {
                    bail!("no live grant");
                }
                if !keep {
                    bail!("the task was stopped on its disk limit");
                }
                self.move_back(remote, workspace, &c, limit)?;
                save_times(&c.dir, &c.times)
            };
            if let Err(e) = back() {
                tracing::debug!("cache not kept: {e:#}");
                let _ = std::fs::remove_file(times_file(&c.dir));
            }
            self.state().caches_out.remove(&c.dir);
        }
        self.inner.blobs.dirs_changed(&remote);
        workspace.to_path_buf()
    }

    /// Moves one cache back from the task folder, through file descriptors only (fsafe.rs): a
    /// process the task left behind cannot swap a folder for a link between the checks and
    /// the move, and folders the task locked are opened up again (so the next task's folder
    /// can be measured). Kept only if it fits in the grant's disk limit.
    #[cfg(unix)]
    fn move_back(
        &self,
        remote: PeerKey,
        workspace: &Path,
        c: &CheckedOut,
        limit: u64,
    ) -> Result<()> {
        use std::os::fd::AsFd;
        let from = crate::fsafe::open_real(workspace, &c.rel)?;
        let size =
            crate::fsafe::open_up_and_measure(from.dir.as_fd(), tree::MAX_WORKSPACE_ENTRIES)?;
        let used = self.inner.blobs.usage(&remote);
        if used.saturating_add(size) > limit {
            bail!("keeping it would go over the grant's disk limit");
        }
        let parent = c.dir.parent().context("no parent")?;
        std::fs::create_dir_all(parent)?;
        let name = c
            .dir
            .file_name()
            .context("no name")?
            .to_string_lossy()
            .into_owned();
        crate::fsafe::move_checked(&from, parent, &name)
    }

    #[cfg(not(unix))]
    fn move_back(&self, _: PeerKey, _: &Path, _: &CheckedOut, _: u64) -> Result<()> {
        bail!("caches are kept on Linux and macOS lenders only")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_paths_stay_inside_the_project() {
        assert_eq!(validate("target/").unwrap(), "target");
        assert_eq!(validate(".cache/npm").unwrap(), ".cache/npm");
        for bad in [
            "",
            "/",
            "/etc",
            "../up",
            "a/../../b",
            ".gmc-sdk",
            ".gmc-sdk/x",
        ] {
            assert!(validate(bad).is_err(), "{bad:?}");
        }
        assert!(validate_all(&["a".into(), "a/".into()]).is_err(), "twice");
        let many: Vec<String> = (0..=MAX_CACHES).map(|i| format!("c{i}")).collect();
        assert!(validate_all(&many).is_err());
    }

    #[test]
    fn keys_differ_by_project_and_path() {
        assert_ne!(
            key(b"p1", "sandbox", "target"),
            key(b"p2", "sandbox", "target")
        );
        assert_ne!(
            key(b"p1", "sandbox", "target"),
            key(b"p1", "sandbox", "build")
        );
        assert_ne!(
            key(b"p1", "sandbox", "target"),
            key(b"p1", "container", "target")
        );
        assert_eq!(
            key(b"p1", "sandbox", "target"),
            key(b"p1", "sandbox", "target")
        );
    }

    #[test]
    fn links_anywhere_on_the_way_are_refused() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("a/b")).unwrap();
        assert!(real_dir_under(d.path(), Path::new("a/b")));
        let out = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(out.path().join("b")).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(out.path(), d.path().join("l")).unwrap();
            assert!(!real_dir_under(d.path(), Path::new("l/b")));
            std::os::unix::fs::symlink(out.path().join("b"), d.path().join("a/c")).unwrap();
            assert!(!real_dir_under(d.path(), Path::new("a/c")));
        }
        assert!(!real_dir_under(d.path(), Path::new("missing")));
    }
}
