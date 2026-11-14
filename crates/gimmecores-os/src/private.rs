//! Owner-only folders and files.
//!
//! macOS and Linux: mode 0700 / 0600, and files with group or other bits are refused.
//! Windows: a protected access list (nothing inherited) that lets in only this user and the
//! system account; files that any other account may read are refused. (On both, an
//! administrator or root can still take a file: the operating system allows that.)

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

/// Makes `dir` reachable only by this user.
pub fn restrict_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting {}", dir.display()))
    }
    #[cfg(windows)]
    {
        crate::windows::make_owner_only(dir, true)
            .with_context(|| format!("restricting {}", dir.display()))
    }
}

/// Writes `data` atomically (temp file + rename), readable only by this user.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&tmp)
        .with_context(|| format!("writing {}", tmp.display()))?;
    // Windows: the file starts with its folder's (owner-only) list; it is made explicitly
    // owner-only before anything is written to it.
    #[cfg(windows)]
    crate::windows::make_owner_only(&tmp, false)
        .with_context(|| format!("restricting {}", tmp.display()))?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

/// Refuses files that other users could read (secrets must be owner-only).
pub fn check_private(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        anyhow::ensure!(
            mode & 0o077 == 0,
            "{} is accessible by other users (mode {:o}); fix with: chmod 600 {}",
            path.display(),
            mode & 0o777,
            path.display()
        );
        Ok(())
    }
    #[cfg(windows)]
    {
        let others = crate::windows::readers_besides_owner(path)
            .with_context(|| format!("reading who may open {}", path.display()))?;
        anyhow::ensure!(
            others.is_empty(),
            "{} may be read by other accounts ({}); fix with: icacls \"{}\" /inheritance:r /grant:r \"%USERNAME%:F\"",
            path.display(),
            others.join(", "),
            path.display()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn private_files_pass_and_shared_ones_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        restrict_dir(dir.path()).unwrap();
        let secret = dir.path().join("key");
        write_private(&secret, b"secret").unwrap();
        assert_eq!(std::fs::read(&secret).unwrap(), b"secret");
        check_private(&secret).unwrap();

        let shared = dir.path().join("shared");
        std::fs::write(&shared, b"x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        #[cfg(windows)]
        crate::windows::grant_everyone_read(&shared).unwrap();
        let err = check_private(&shared).unwrap_err().to_string();
        assert!(err.contains("other"), "{err}");
    }
}
