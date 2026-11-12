//! Hash-chained audit log (threat model I11).
//!
//! One JSON object per line in `audit.log` (owner-only). Each entry stores the hash of the
//! previous entry and its own hash over `previous_hash ‖ canonical entry`, so editing, removing
//! or reordering past entries breaks the chain and [`verify`] reports where.
//!
//! The chain detects tampering; it cannot stop someone with the user's own privileges from
//! deleting the whole file (threat model T4 residual risk).

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use gimmecores_core::{PeerKey, UnixSeconds};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub at: UnixSeconds,
    /// pair, unpair, lending, grant, task
    pub kind: String,
    /// Fingerprint of the other device, if any.
    pub peer: Option<String>,
    pub summary: String,
    pub details: serde_json::Value,
    pub prev: String,
    pub hash: String,
}

fn entry_hash(e: &Entry) -> String {
    // Canonical form: the entry with an empty hash field, serialized by serde_json (fields in
    // declaration order, details as given).
    let mut copy = e.clone();
    copy.hash = String::new();
    let body = serde_json::to_vec(&copy).unwrap_or_default();
    hex::encode(Sha256::digest([e.prev.as_bytes(), &body].concat()))
}

pub struct AuditLog {
    path: PathBuf,
    seq: u64,
    last: String,
}

impl AuditLog {
    /// Opens (or creates) the log and checks the existing chain.
    pub fn open(path: PathBuf) -> Result<Self> {
        if path.exists() {
            crate::fsutil::check_private(&path)?;
            let entries = read(&path)?;
            verify_entries(&entries)?;
            let (seq, last) = entries
                .last()
                .map_or((0, GENESIS.to_string()), |e| (e.seq, e.hash.clone()));
            return Ok(Self { path, seq, last });
        }
        crate::fsutil::write_private(&path, b"")?;
        Ok(Self {
            path,
            seq: 0,
            last: GENESIS.to_string(),
        })
    }

    pub fn append(
        &mut self,
        at: UnixSeconds,
        kind: &str,
        peer: Option<&PeerKey>,
        summary: impl Into<String>,
        details: serde_json::Value,
    ) -> Result<Entry> {
        let mut e = Entry {
            seq: self.seq + 1,
            at,
            kind: kind.to_string(),
            peer: peer.map(PeerKey::fingerprint),
            summary: summary.into(),
            details,
            prev: self.last.clone(),
            hash: String::new(),
        };
        e.hash = entry_hash(&e);
        let mut line = serde_json::to_vec(&e)?;
        line.push(b'\n');
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .with_context(|| format!("opening {}", self.path.display()))?;
        f.write_all(&line)?;
        f.sync_data()?;
        self.seq = e.seq;
        self.last = e.hash.clone();
        Ok(e)
    }
}

pub fn read(path: &Path) -> Result<Vec<Entry>> {
    let f = std::fs::File::open(path)?;
    let mut out = Vec::new();
    for (i, line) in std::io::BufReader::new(f).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        out.push(
            serde_json::from_str(&line)
                .with_context(|| format!("audit log line {} is not valid", i + 1))?,
        );
    }
    Ok(out)
}

fn verify_entries(entries: &[Entry]) -> Result<()> {
    let mut prev = GENESIS.to_string();
    for (i, e) in entries.iter().enumerate() {
        let expected_seq = i as u64 + 1;
        if e.seq != expected_seq {
            bail!("audit log broken at entry {expected_seq}: an entry is missing or out of order");
        }
        if e.prev != prev {
            bail!(
                "audit log broken at entry {}: it does not follow the previous entry",
                e.seq
            );
        }
        if entry_hash(e) != e.hash {
            bail!(
                "audit log broken at entry {}: its content was changed",
                e.seq
            );
        }
        prev = e.hash.clone();
    }
    Ok(())
}

/// Checks the whole chain. `Ok(n)` = all `n` entries intact.
pub fn verify(path: &Path) -> Result<usize> {
    let entries = read(path)?;
    verify_entries(&entries)?;
    Ok(entries.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn log() -> (AuditLog, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path().join("audit.log")).unwrap();
        (log, dir)
    }

    #[test]
    fn appended_entries_verify_and_survive_reopen() {
        let (mut l, dir) = log();
        let peer = PeerKey([1; 32]);
        l.append(10, "pair", Some(&peer), "paired with Laptop", json!({}))
            .unwrap();
        l.append(
            20,
            "grant",
            Some(&peer),
            "accepted 2 cores",
            json!({"cpus": 2}),
        )
        .unwrap();
        let path = dir.path().join("audit.log");
        assert_eq!(verify(&path).unwrap(), 2);
        let mut l2 = AuditLog::open(path.clone()).unwrap();
        l2.append(30, "lending", None, "lending off", json!({}))
            .unwrap();
        assert_eq!(verify(&path).unwrap(), 3);
        assert_eq!(read(&path).unwrap()[2].seq, 3);
    }

    #[test]
    fn i11_editing_a_past_entry_is_detected() {
        let (mut l, dir) = log();
        l.append(10, "grant", None, "accepted 2 cores", json!({"cpus": 2}))
            .unwrap();
        l.append(20, "task", None, "ran pytest", json!({})).unwrap();
        let path = dir.path().join("audit.log");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            text.replacen("accepted 2 cores", "accepted 1 core", 1),
        )
        .unwrap();
        let err = verify(&path).unwrap_err().to_string();
        assert!(err.contains("entry 1") && err.contains("changed"), "{err}");
    }

    #[test]
    fn i11_deleting_or_reordering_entries_is_detected() {
        let (mut l, dir) = log();
        for i in 0..3 {
            l.append(i, "task", None, format!("task {i}"), json!({}))
                .unwrap();
        }
        let path = dir.path().join("audit.log");
        let lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        std::fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert!(
            verify(&path)
                .unwrap_err()
                .to_string()
                .contains("missing or out of order")
        );
        std::fs::write(&path, format!("{}\n{}\n{}\n", lines[1], lines[0], lines[2])).unwrap();
        assert!(verify(&path).is_err());
    }

    #[test]
    fn opening_a_tampered_log_fails_instead_of_extending_it() {
        let (mut l, dir) = log();
        l.append(1, "pair", None, "x", json!({})).unwrap();
        let path = dir.path().join("audit.log");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("\"x\"", "\"y\"")).unwrap();
        assert!(AuditLog::open(path).is_err());
    }
}
