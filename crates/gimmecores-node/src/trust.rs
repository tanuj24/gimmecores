//! The trust list: devices this one has paired with.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use gimmecores_core::{PeerKey, UnixSeconds};
use serde::{Deserialize, Serialize};

use crate::fsutil;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedPeer {
    /// Hex-encoded Ed25519 public key.
    pub key: String,
    pub name: String,
    pub paired_at: UnixSeconds,
    /// Trusted mode enabled on this device for this peer (one side of the two-sided step).
    #[serde(default)]
    pub trusted_mode_local: bool,
    /// Last known direct addresses, used to reconnect without discovery.
    #[serde(default)]
    pub last_addrs: Vec<SocketAddr>,
    /// Hex secret shared with this peer at pairing, for rotating discovery identifiers.
    /// Absent for devices paired by earlier versions (they are not discovered automatically).
    #[serde(default)]
    pub discovery_key: Option<String>,
}

pub struct TrustList {
    path: PathBuf,
    peers: BTreeMap<PeerKey, TrustedPeer>,
}

fn parse_key(hex_key: &str) -> Option<PeerKey> {
    let bytes = hex::decode(hex_key).ok()?;
    Some(PeerKey(bytes.try_into().ok()?))
}

impl TrustList {
    pub fn load(path: PathBuf) -> Result<Self> {
        let mut peers = BTreeMap::new();
        if path.exists() {
            fsutil::check_private(&path)?;
            let data = std::fs::read(&path)?;
            let list: Vec<TrustedPeer> = serde_json::from_slice(&data)
                .with_context(|| format!("parsing {}", path.display()))?;
            for p in list {
                let key = parse_key(&p.key).context("invalid key in trust list")?;
                peers.insert(key, p);
            }
        }
        Ok(Self { path, peers })
    }

    fn save(&self) -> Result<()> {
        let list: Vec<&TrustedPeer> = self.peers.values().collect();
        fsutil::write_private(&self.path, &serde_json::to_vec_pretty(&list)?)
    }

    pub fn is_paired(&self, key: &PeerKey) -> bool {
        self.peers.contains_key(key)
    }

    pub fn get(&self, key: &PeerKey) -> Option<&TrustedPeer> {
        self.peers.get(key)
    }

    pub fn list(&self) -> impl Iterator<Item = (&PeerKey, &TrustedPeer)> {
        self.peers.iter()
    }

    /// Finds a paired peer by name or fingerprint (CLI convenience).
    pub fn find(&self, name_or_fingerprint: &str) -> Option<PeerKey> {
        self.peers
            .iter()
            .find(|(k, p)| p.name == name_or_fingerprint || k.fingerprint() == name_or_fingerprint)
            .map(|(k, _)| *k)
    }

    /// Warning for the pairing screen: was this name used before by a different key?
    pub fn name_used_by_other_key(&self, name: &str, key: &PeerKey) -> bool {
        self.peers.iter().any(|(k, p)| p.name == name && k != key)
    }

    pub fn add(&mut self, key: PeerKey, name: String, now: UnixSeconds) -> Result<()> {
        self.peers.insert(
            key,
            TrustedPeer {
                key: key.to_hex(),
                name,
                paired_at: now,
                trusted_mode_local: false,
                last_addrs: Vec::new(),
                discovery_key: None,
            },
        );
        self.save()
    }

    pub fn set_discovery_key(&mut self, key: &PeerKey, secret: &[u8; 32]) -> Result<()> {
        if let Some(p) = self.peers.get_mut(key) {
            p.discovery_key = Some(hex::encode(secret));
            self.save()?;
        }
        Ok(())
    }

    pub fn remove(&mut self, key: &PeerKey) -> Result<bool> {
        let removed = self.peers.remove(key).is_some();
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    pub fn set_addrs(&mut self, key: &PeerKey, addrs: Vec<SocketAddr>) -> Result<()> {
        if let Some(p) = self.peers.get_mut(key) {
            p.last_addrs = addrs;
            self.save()?;
        }
        Ok(())
    }
}
