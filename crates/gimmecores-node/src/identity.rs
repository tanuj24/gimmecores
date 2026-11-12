//! The device identity key.
//!
//! M1 stores it in an owner-only file. The OS keychain backend (macOS Keychain, Windows
//! Credential Manager, Linux Secret Service) plugs in behind [`KeyStore`]; tests always use the
//! file backend so they never touch a real keychain.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use gimmecores_core::PeerKey;
use iroh::SecretKey;

use crate::fsutil;

pub trait KeyStore {
    /// Loads the device key, creating it on first run.
    fn load_or_create(&self) -> Result<SecretKey>;
}

pub struct FileKeyStore {
    path: PathBuf,
}

impl FileKeyStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl KeyStore for FileKeyStore {
    fn load_or_create(&self) -> Result<SecretKey> {
        if self.path.exists() {
            fsutil::check_private(&self.path)?;
            let bytes = std::fs::read(&self.path)
                .with_context(|| format!("reading {}", self.path.display()))?;
            let Ok(bytes) = <[u8; 32]>::try_from(bytes.as_slice()) else {
                bail!("{} is not a 32-byte key", self.path.display());
            };
            return Ok(SecretKey::from_bytes(&bytes));
        }
        let key = SecretKey::generate();
        fsutil::write_private(&self.path, &key.to_bytes())?;
        Ok(key)
    }
}

pub fn peer_key(key: &iroh::PublicKey) -> PeerKey {
    PeerKey(*key.as_bytes())
}
