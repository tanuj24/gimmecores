//! Walking and moving folders a task wrote, without ever following a link it planted, even
//! while a process it left behind keeps changing them (caches.rs).
//!
//! On macOS a process can detach from its task and outlive it, and the sandbox keeps letting
//! it write in a folder it holds open wherever that folder is moved (tested in
//! `sandbox_hostile`). A check followed by an operation on the same *path* can therefore be
//! raced: the folder checked is replaced by a link to the owner's files before the operation.
//! Here every step goes through file descriptors instead: each folder is opened with
//! `O_NOFOLLOW` from the one above it, permissions are set on what was opened, and a move is
//! kept only if the destination is the very folder that was checked (same device and inode).

use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use rustix::fs::{AtFlags, CWD, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;

fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// On macOS a mode change can refuse links itself; Linux has no such flag (and no process
/// outlives a Linux sandbox's task, so nothing races it there).
fn chmod_flags() -> AtFlags {
    if cfg!(target_os = "macos") {
        AtFlags::SYMLINK_NOFOLLOW
    } else {
        AtFlags::empty()
    }
}

/// Opens folder `name` in `parent`, never through a link; a folder the task locked (mode 000)
/// is opened up first.
fn open_dir_at(parent: BorrowedFd<'_>, name: &CStr) -> Result<OwnedFd> {
    match rustix::fs::openat(parent, name, dir_flags(), Mode::empty()) {
        Ok(fd) => Ok(fd),
        Err(Errno::ACCESS) => {
            rustix::fs::chmodat(parent, name, Mode::from_raw_mode(0o700), chmod_flags())?;
            Ok(rustix::fs::openat(
                parent,
                name,
                dir_flags(),
                Mode::empty(),
            )?)
        }
        Err(e) => Err(e.into()),
    }
}

fn c_name(part: &std::ffi::OsStr) -> Result<CString> {
    Ok(CString::new(part.as_encoded_bytes())?)
}

/// A folder opened through real folders only, with the folder it is in.
pub struct Opened {
    pub parent: OwnedFd,
    pub name: CString,
    pub dir: OwnedFd,
}

/// Opens `rel` under `root` through real folders only: a link anywhere on the way (or at
/// `root` itself) is refused.
pub fn open_real(root: &Path, rel: &Path) -> Result<Opened> {
    let mut parent = rustix::fs::openat(CWD, root, dir_flags(), Mode::empty())
        .with_context(|| format!("{} is not a real folder", root.display()))?;
    let parts: Vec<_> = rel.components().collect();
    ensure!(!parts.is_empty(), "empty path");
    for (i, part) in parts.iter().enumerate() {
        let std::path::Component::Normal(part) = part else {
            bail!("not a plain path");
        };
        let name = c_name(part)?;
        let dir = open_dir_at(parent.as_fd(), &name)
            .with_context(|| format!("{} is not a real folder", rel.display()))?;
        if i + 1 == parts.len() {
            return Ok(Opened { parent, name, dir });
        }
        parent = dir;
    }
    unreachable!("the loop returns on the last part")
}

/// Makes every folder in `dir` the owner's (0700) and adds up what it holds, never following
/// a link; refuses more than `max` entries.
pub fn open_up_and_measure(dir: BorrowedFd<'_>, max: usize) -> Result<u64> {
    let mut entries = 0usize;
    walk(dir, max, &mut entries, 0)
}

fn walk(dir: BorrowedFd<'_>, max: usize, entries: &mut usize, depth: usize) -> Result<u64> {
    ensure!(depth < 256, "folders nested too deep");
    rustix::fs::fchmod(dir, Mode::from_raw_mode(0o700))?;
    let mut total = 0u64;
    // Read the names first: the folder is not changed while it is being read.
    let mut names: Vec<(CString, FileType)> = Vec::new();
    for e in Dir::read_from(dir)? {
        let e = e?;
        let name = e.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        *entries += 1;
        ensure!(*entries <= max, "more than {max} files");
        names.push((name.to_owned(), e.file_type()));
    }
    for (name, ft) in names {
        // The type is checked again on the entry itself (never through a link).
        let st = match rustix::fs::statat(dir, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(Errno::NOENT) => continue,
            Err(e) => return Err(e.into()),
        };
        let is_dir = FileType::from_raw_mode(st.st_mode) == FileType::Directory;
        if is_dir || ft == FileType::Directory {
            match open_dir_at(dir, &name) {
                Ok(child) => {
                    total = total.saturating_add(walk(child.as_fd(), max, entries, depth + 1)?)
                }
                // Replaced by something else meanwhile: not followed, not counted.
                Err(_) => continue,
            }
        } else {
            total = total.saturating_add(u64::try_from(st.st_size).unwrap_or(0).max(512));
        }
    }
    Ok(total)
}

/// Moves the folder `from` was opened at to `dest_parent`/`dest_name`, and keeps the move only
/// if what arrived there is that very folder: anything swapped in meanwhile (a link, another
/// folder) is removed again and the move refused.
pub fn move_checked(from: &Opened, dest_parent: &Path, dest_name: &str) -> Result<()> {
    let dest = rustix::fs::openat(CWD, dest_parent, dir_flags(), Mode::empty())?;
    let want = rustix::fs::fstat(&from.dir)?;
    rustix::fs::renameat(&from.parent, &from.name, &dest, dest_name)?;
    let got = rustix::fs::statat(&dest, dest_name, AtFlags::SYMLINK_NOFOLLOW)?;
    if (got.st_dev, got.st_ino) != (want.st_dev, want.st_ino) {
        let path = dest_parent.join(dest_name);
        if FileType::from_raw_mode(got.st_mode) == FileType::Directory {
            // std's remove_dir_all never follows links (it works through descriptors too).
            let _ = std::fs::remove_dir_all(&path);
        } else {
            let _ = rustix::fs::unlinkat(&dest, dest_name, AtFlags::empty());
        }
        bail!("the folder was swapped while it was moved");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_are_never_followed_on_the_way_or_inside() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(outside.path().join("c")).unwrap();
        std::fs::write(outside.path().join("c/owner.txt"), "the owner's").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("sub")).unwrap();
        assert!(open_real(root.path(), Path::new("sub/c")).is_err());
        std::os::unix::fs::symlink(outside.path().join("c"), root.path().join("c")).unwrap();
        assert!(open_real(root.path(), Path::new("c")).is_err());

        // Inside: a link is counted as itself, never walked or changed.
        std::fs::create_dir_all(root.path().join("real/locked")).unwrap();
        std::fs::write(root.path().join("real/locked/f"), vec![7u8; 4096]).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("real/out")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let before = std::fs::metadata(outside.path())
            .unwrap()
            .permissions()
            .mode();
        std::fs::set_permissions(
            root.path().join("real/locked"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        let o = open_real(root.path(), Path::new("real")).unwrap();
        let size = open_up_and_measure(o.dir.as_fd(), 1000).unwrap();
        assert!(size >= 4096, "{size}");
        assert_eq!(
            std::fs::metadata(outside.path())
                .unwrap()
                .permissions()
                .mode(),
            before,
            "the owner's folder was not touched"
        );
        assert!(
            std::fs::read_dir(root.path().join("real/locked")).is_ok(),
            "opened up"
        );
    }

    #[test]
    fn a_move_keeps_only_the_folder_that_was_checked() {
        let root = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("c")).unwrap();
        std::fs::write(root.path().join("c/f"), "mine").unwrap();
        let o = open_real(root.path(), Path::new("c")).unwrap();
        move_checked(&o, dest.path(), "kept").unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.path().join("kept/f")).unwrap(),
            "mine"
        );

        // Swapped for a link after the check: the link is not kept.
        std::fs::create_dir_all(root.path().join("d")).unwrap();
        let o = open_real(root.path(), Path::new("d")).unwrap();
        std::fs::rename(root.path().join("d"), root.path().join("d.real")).unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("d")).unwrap();
        assert!(move_checked(&o, dest.path(), "swapped").is_err());
        assert!(std::fs::symlink_metadata(dest.path().join("swapped")).is_err());
        assert!(outside.path().exists());
    }

    #[test]
    fn too_many_files_are_refused() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("d")).unwrap();
        for i in 0..20 {
            std::fs::write(root.path().join(format!("d/{i}")), "x").unwrap();
        }
        let o = open_real(root.path(), Path::new("d")).unwrap();
        assert!(open_up_and_measure(o.dir.as_fd(), 10).is_err());
    }
}
