//! Where a node keeps its state. One root directory, overridable with `GMC_HOME`, so two
//! nodes can run side by side on one machine (tests, demos).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

#[derive(Clone, Debug)]
pub struct Paths {
    root: PathBuf,
}

impl Paths {
    /// `GMC_HOME` if set, else the platform data directory
    /// (macOS: `~/Library/Application Support/GimmeCores`, Linux: `~/.local/share/gimmecores`).
    pub fn from_env() -> Result<Self> {
        Ok(Self::at(gimmecores_client::home()?))
    }

    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn identity_key(&self) -> PathBuf {
        self.root.join("identity.key")
    }
    pub fn peers_file(&self) -> PathBuf {
        self.root.join("peers.json")
    }
    pub fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs")
    }
    pub fn work_dir(&self) -> PathBuf {
        self.root.join("work")
    }
    pub fn run_dir(&self) -> PathBuf {
        self.root.join("run")
    }
    pub fn client_socket(&self) -> PathBuf {
        gimmecores_client::client_socket(&self.root)
    }
    pub fn control_socket(&self) -> PathBuf {
        gimmecores_client::control_socket(&self.root)
    }
    pub fn settings_file(&self) -> PathBuf {
        self.root.join("settings.json")
    }
    pub fn grants_file(&self) -> PathBuf {
        self.root.join("grants.json")
    }
    /// As a borrower: requests a lender keeps for its owner (queued.rs).
    pub fn requests_file(&self) -> PathBuf {
        self.root.join("requests.json")
    }
    /// Container images loaded here for borrowers (docs/design/container-images.md).
    pub fn images_file(&self) -> PathBuf {
        self.root.join("images.json")
    }
    /// Held (an exclusive lock) by the running daemon: one gmcd per state directory.
    pub fn lock_file(&self) -> PathBuf {
        self.root.join("gmcd.lock")
    }
    pub fn audit_log(&self) -> PathBuf {
        self.root.join("audit.log")
    }

    /// Creates every directory, readable only by the owner.
    pub fn ensure(&self) -> Result<()> {
        for dir in [
            self.root.clone(),
            self.blobs_dir(),
            self.work_dir(),
            self.run_dir(),
        ] {
            std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
            crate::fsutil::restrict_dir(&dir)?;
        }
        Ok(())
    }
}
