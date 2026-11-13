//! The device identity key.
//!
//! By default it is an owner-only file. On macOS it can live in the login Keychain instead
//! (`gmcd --identity-store keychain`, opt-in): the item's access list then names only the
//! `gmcd` binary that created it, so other programs running as the same user get a Keychain
//! prompt instead of the key, and it cannot quietly be copied to pose as this device elsewhere.
//! macOS identifies that binary by the hash of its code; until releases are Developer ID signed
//! (a stable identity), every rebuild or upgrade of `gmcd` asks once more, which is why this is
//! opt-in for now. A marker file, `identity.keychain`, records that the key is in the Keychain;
//! once there it never leaves it (no export, so the trusted `gmcd` binary cannot be used to read
//! it out).

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use gimmecores_core::PeerKey;
use iroh::SecretKey;

use crate::fsutil;
use crate::paths::Paths;

/// Where the device key is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityStore {
    /// An owner-only file in the state folder.
    File,
    /// The macOS login Keychain.
    Keychain,
}

impl IdentityStore {
    pub fn describe(self) -> &'static str {
        match self {
            Self::File => "an owner-only file",
            Self::Keychain => "the login Keychain",
        }
    }
}

/// Keychain service name of device keys (the account is the state folder).
pub const KEYCHAIN_SERVICE: &str = "GimmeCores device identity";

fn marker(paths: &Paths) -> PathBuf {
    paths.root().join("identity.keychain")
}

fn account(paths: &Paths) -> Result<String> {
    let root = std::fs::canonicalize(paths.root())?;
    root.to_str()
        .map(String::from)
        .context("state folder path is not UTF-8")
}

/// Where this state folder's key is now.
pub fn current_store(paths: &Paths) -> IdentityStore {
    if marker(paths).exists() {
        IdentityStore::Keychain
    } else {
        IdentityStore::File
    }
}

/// `gmcd` at start: makes sure the key is in `want`. Moving a key file into the Keychain reads
/// it back to check before the file is deleted; a new install creates its key there. Asking
/// for the file when the key is in the Keychain is refused: the key never leaves the Keychain.
pub fn prepare(paths: &Paths, want: IdentityStore) -> Result<()> {
    paths.ensure()?;
    // The daemon's own single-instance lock, so two starting at once cannot both move the key.
    let _lock = crate::node::acquire_instance_lock(paths)?;
    match (current_store(paths), want) {
        (IdentityStore::Keychain, IdentityStore::File) => bail!(
            "this device's identity is in the login Keychain and is never moved out of it; \
             start without --identity-store file (to start over as a new device, delete the \
             Keychain item \"{KEYCHAIN_SERVICE}\" and {})",
            marker(paths).display()
        ),
        (_, IdentityStore::File) | (IdentityStore::Keychain, IdentityStore::Keychain) => Ok(()),
        (IdentityStore::File, IdentityStore::Keychain) => {
            let file = paths.identity_key();
            let key = if file.exists() {
                FileKeyStore::new(file.clone()).load_or_create()?
            } else {
                SecretKey::generate()
            };
            keychain::store(&account(paths)?, &key.to_bytes())?;
            let back = keychain::load(&account(paths)?)?;
            if back != key.to_bytes() {
                bail!("the Keychain did not return the key it was given; the key file is kept");
            }
            fsutil::write_private(&marker(paths), KEYCHAIN_SERVICE.as_bytes())?;
            if file.exists() {
                // Best effort: overwrite before deleting (copy-on-write disks may keep old
                // blocks, but the file is gone from the folder).
                let _ = std::fs::write(&file, [0u8; 32]);
                std::fs::remove_file(&file)?;
            }
            Ok(())
        }
    }
}

/// Loads the device key from wherever it is (Node::start), creating a key file on first run
/// when no store was prepared.
pub fn load(paths: &Paths) -> Result<SecretKey> {
    match current_store(paths) {
        IdentityStore::Keychain => {
            let bytes = keychain::load(&account(paths)?)?;
            let bytes: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .ok()
                .context("the Keychain's device key is not 32 bytes")?;
            Ok(SecretKey::from_bytes(&bytes))
        }
        IdentityStore::File => FileKeyStore::new(paths.identity_key()).load_or_create(),
    }
}

/// The Keychain could not be used right now (locked, no one there to answer its prompt, or
/// access denied). `gmcd` exits without an error code for this, so a service manager does not
/// restart it into prompt after prompt.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct KeychainUnavailable(pub String);

#[cfg(target_os = "macos")]
mod keychain {
    use anyhow::{Result, anyhow};

    use super::KeychainUnavailable;
    use security_framework::passwords::{get_generic_password, set_generic_password};

    use super::KEYCHAIN_SERVICE;

    fn explain(e: security_framework::base::Error) -> anyhow::Error {
        match e.code() {
            -25300 => anyhow!(
                "this device's identity is missing from the login Keychain (item \"{KEYCHAIN_SERVICE}\")"
            ),
            -25308 => KeychainUnavailable(
                "the login Keychain is locked or cannot ask you here (no one logged in to this \
                 Mac's screen?); unlock it with `security unlock-keychain` and start gmcd again"
                    .into(),
            )
            .into(),
            -128 | -25293 => KeychainUnavailable(
                "access to this device's identity in the Keychain was denied; start gmcd again \
                 and choose Always Allow to let it use its identity"
                    .into(),
            )
            .into(),
            _ => anyhow!("the Keychain refused: {e}"),
        }
    }

    pub fn store(account: &str, key: &[u8]) -> Result<()> {
        set_generic_password(KEYCHAIN_SERVICE, account, key).map_err(explain)
    }

    pub fn load(account: &str) -> Result<Vec<u8>> {
        get_generic_password(KEYCHAIN_SERVICE, account).map_err(explain)
    }
}

#[cfg(not(target_os = "macos"))]
mod keychain {
    use anyhow::{Result, bail};

    pub fn store(_account: &str, _key: &[u8]) -> Result<()> {
        bail!("the Keychain identity store is available on macOS only")
    }

    pub fn load(_account: &str) -> Result<Vec<u8>> {
        bail!("this device's identity is marked as in a Keychain, which this system lacks")
    }
}

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
