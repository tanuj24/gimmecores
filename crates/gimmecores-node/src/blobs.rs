//! Content-addressed blob store with per-borrower namespaces (threat model I14).
//!
//! Layout: `blobs/<namespace-hex>/<sha256-hex>`. Writes stream to a temporary file while hashing,
//! so a peer can never make us hold a large blob in memory; the blob is published only after its
//! size and SHA-256 match the declared digest.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use gimmecores_core::PeerKey;
use gimmecores_proto::peer::v1 as pb;
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest {
    pub hash: [u8; 32],
    pub size: u64,
}

impl Digest {
    pub fn of(data: &[u8]) -> Self {
        Self {
            hash: Sha256::digest(data).into(),
            size: data.len() as u64,
        }
    }

    pub fn hex(&self) -> String {
        hex::encode(self.hash)
    }

    pub fn to_proto(self) -> pb::Digest {
        pb::Digest {
            hash: self.hash.to_vec(),
            size_bytes: self.size,
            function: pb::DigestFunction::Sha256 as i32,
        }
    }

    pub fn from_proto(d: &pb::Digest) -> Result<Self> {
        ensure!(
            d.function == pb::DigestFunction::Sha256 as i32,
            "unsupported digest function"
        );
        Ok(Self {
            hash: d
                .hash
                .as_slice()
                .try_into()
                .context("digest must be 32 bytes")?,
            size: d.size_bytes,
        })
    }
}

#[derive(Clone, Debug)]
pub struct BlobStore {
    root: PathBuf,
    /// Bytes promised to blobs being written, per namespace (I14): parallel uploads cannot
    /// together go over the quota, each having checked it alone.
    reserved: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<PeerKey, u64>>>,
}

impl BlobStore {
    /// Opens the store, removing blobs left half-written by a crash.
    pub fn new(root: PathBuf) -> Self {
        let store = Self {
            root,
            reserved: Default::default(),
        };
        for ns in store.namespaces() {
            if let Ok(rd) = std::fs::read_dir(store.ns_dir(&ns)) {
                for e in rd.flatten() {
                    if e.file_name().to_string_lossy().contains(".part") {
                        let _ = std::fs::remove_file(e.path());
                    }
                }
            }
        }
        store
    }

    fn reservations(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<PeerKey, u64>> {
        self.reserved.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn ns_dir(&self, ns: &PeerKey) -> PathBuf {
        self.root.join(ns.to_hex())
    }

    /// Copies a stored blob to `dest` (a clone on file systems that support it), checking its
    /// content first: hashed once, then remembered until the file changes (tree's digest
    /// cache), so a corrupted store is still caught.
    pub fn copy_out(&self, ns: &PeerKey, d: &Digest, dest: &std::path::Path) -> Result<()> {
        let src = self.path(ns, d);
        let meta = std::fs::metadata(&src).context("blob not found")?;
        if meta.len() != d.size || crate::tree::digest_of_file(&src, &meta)? != *d {
            // Gone, so the borrower's next upload sends it again.
            let _ = std::fs::remove_file(&src);
            bail!("stored blob is corrupt");
        }
        std::fs::copy(&src, dest)?;
        Ok(())
    }

    fn path(&self, ns: &PeerKey, d: &Digest) -> PathBuf {
        self.ns_dir(ns).join(d.hex())
    }

    pub fn has(&self, ns: &PeerKey, d: &Digest) -> bool {
        std::fs::metadata(self.path(ns, d)).is_ok_and(|m| m.len() == d.size)
    }

    /// Bytes stored in a namespace, kept packages included (counted against the grant's disk
    /// quota).
    pub fn usage(&self, ns: &PeerKey) -> u64 {
        let reserved = self.reservations().get(ns).copied().unwrap_or(0);
        self.usage_unlocked(ns).saturating_add(reserved)
    }

    /// Stored bytes (finished blobs and kept packages), without blobs being written.
    fn usage_unlocked(&self, ns: &PeerKey) -> u64 {
        // Blobs being written count through their reservations, not their partial files.
        let blobs: u64 = std::fs::read_dir(self.ns_dir(ns))
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .filter(|e| !e.file_name().to_string_lossy().contains(".part"))
                    .filter_map(|e| e.metadata().ok())
                    .filter(std::fs::Metadata::is_file)
                    .map(|m| m.len())
                    .sum()
            })
            .unwrap_or(0);
        let kept = self.kept_dir(ns);
        let kept = if kept.exists() {
            // Unmeasurable counts as full: the quota check then refuses more.
            crate::tree::disk_usage(&kept).unwrap_or(u64::MAX)
        } else {
            0
        };
        blobs.saturating_add(kept)
    }

    /// A borrower's packages kept unpacked between tasks (macOS sandbox; see tasks_flow). Part
    /// of the namespace: counted in its usage and deleted with it.
    pub fn kept_dir(&self, ns: &PeerKey) -> PathBuf {
        self.ns_dir(ns).join("pkgs")
    }

    pub fn get(&self, ns: &PeerKey, d: &Digest) -> Result<Vec<u8>> {
        let data = std::fs::read(self.path(ns, d)).context("blob not found")?;
        if Digest::of(&data) != *d {
            let _ = std::fs::remove_file(self.path(ns, d));
            bail!("stored blob is corrupt");
        }
        Ok(data)
    }

    pub fn put(&self, ns: &PeerKey, d: &Digest, data: &[u8], quota: u64) -> Result<()> {
        let mut w = self.writer(ns, *d, quota)?;
        w.write(0, data)?;
        w.finish()
    }

    /// Stores a file's content without reading it into memory (task outputs can be large).
    pub fn put_file(
        &self,
        ns: &PeerKey,
        d: &Digest,
        path: &std::path::Path,
        quota: u64,
    ) -> Result<()> {
        use std::io::Read;
        if self.has(ns, d) {
            return Ok(());
        }
        let mut w = self.writer(ns, *d, quota)?;
        let mut f =
            std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
        let mut buf = vec![0u8; 1 << 20];
        let mut offset = 0u64;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            w.write(offset, &buf[..n])?;
            offset += n as u64;
        }
        w.finish()
    }

    /// Starts a streamed write of one blob. Fails early if it cannot fit in the quota.
    pub fn writer(&self, ns: &PeerKey, d: Digest, quota: u64) -> Result<BlobWriter> {
        let dir = self.ns_dir(ns);
        std::fs::create_dir_all(&dir)?;
        crate::fsutil::restrict_dir(&dir)?;
        let reservation = if self.has(ns, &d) {
            None
        } else {
            // Checked and reserved under one lock, so concurrent uploads see each other.
            let mut r = self.reservations();
            let used = self.usage_unlocked(ns) + r.get(ns).copied().unwrap_or(0);
            if used.saturating_add(d.size) > quota {
                bail!("disk quota for this grant would be exceeded");
            }
            *r.entry(*ns).or_insert(0) += d.size;
            Some(Reservation {
                reserved: self.reserved.clone(),
                ns: *ns,
                bytes: d.size,
            })
        };
        let final_path = self.path(ns, &d);
        // Unique per writer: two tasks may upload the same blob at the same time.
        let tmp = dir.join(format!(
            "{}.part{}",
            d.hex(),
            hex::encode(&crate::wire::random32()?[..8])
        ));
        let file = std::fs::File::create(&tmp)?;
        Ok(BlobWriter {
            digest: d,
            final_path,
            tmp,
            file: Some(file),
            hasher: Sha256::new(),
            written: 0,
            _reservation: reservation,
        })
    }

    /// Borrowers that have a namespace on disk. Directories that are not namespaces are ignored.
    pub fn namespaces(&self) -> Vec<PeerKey> {
        let Ok(rd) = std::fs::read_dir(&self.root) else {
            return Vec::new();
        };
        rd.filter_map(Result::ok)
            .filter_map(|e| {
                let name = e.file_name();
                let bytes = hex::decode(name.to_str()?).ok()?;
                Some(PeerKey(bytes.try_into().ok()?))
            })
            .collect()
    }

    /// Deletes every blob of a namespace ("forget everything").
    pub fn clear(&self, ns: &PeerKey) -> Result<()> {
        let dir = self.ns_dir(ns);
        if dir.exists() {
            std::fs::remove_dir_all(dir)?;
        }
        Ok(())
    }
}

pub struct BlobWriter {
    digest: Digest,
    final_path: PathBuf,
    tmp: PathBuf,
    file: Option<std::fs::File>,
    hasher: Sha256,
    written: u64,
    _reservation: Option<Reservation>,
}

/// Bytes held for a blob being written; released when the writer finishes or is dropped.
struct Reservation {
    reserved: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<PeerKey, u64>>>,
    ns: PeerKey,
    bytes: u64,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut r = self.reserved.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(v) = r.get_mut(&self.ns) {
            *v = v.saturating_sub(self.bytes);
            if *v == 0 {
                r.remove(&self.ns);
            }
        }
    }
}

impl BlobWriter {
    /// Appends a chunk. Chunks must arrive in order and never exceed the declared size.
    pub fn write(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        ensure!(offset == self.written, "out-of-order blob chunk");
        let end = self.written.saturating_add(data.len() as u64);
        ensure!(end <= self.digest.size, "blob is larger than declared");
        self.file
            .as_mut()
            .context("writer finished")?
            .write_all(data)?;
        self.hasher.update(data);
        self.written = end;
        Ok(())
    }

    /// Verifies size and hash, then publishes the blob.
    pub fn finish(mut self) -> Result<()> {
        // No fsync: a blob lost or damaged in a crash is caught by its hash when used, deleted,
        // and sent again (syncing every file made uploading thousands of small ones slow).
        let file = self.file.take().context("writer finished")?;
        drop(file);
        let hash: [u8; 32] = std::mem::take(&mut self.hasher).finalize().into();
        if self.written != self.digest.size || hash != self.digest.hash {
            bail!("blob content does not match its digest");
        }
        std::fs::rename(&self.tmp, &self.final_path)?;
        Ok(())
    }
}

impl Drop for BlobWriter {
    fn drop(&mut self) {
        if self.file.is_some() || self.tmp.exists() {
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: PeerKey = PeerKey([1; 32]);
    const OTHER: PeerKey = PeerKey([2; 32]);

    fn store() -> (BlobStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (BlobStore::new(dir.path().to_path_buf()), dir)
    }

    #[test]
    fn put_get_and_namespaces_are_separate() {
        let (s, _d) = store();
        let d = Digest::of(b"hello");
        s.put(&NS, &d, b"hello", 1 << 20).unwrap();
        assert!(s.has(&NS, &d));
        assert_eq!(s.get(&NS, &d).unwrap(), b"hello");
        assert!(
            !s.has(&OTHER, &d),
            "I14: another borrower cannot see this blob"
        );
        assert!(s.get(&OTHER, &d).is_err());
    }

    #[test]
    fn wrong_content_or_size_is_rejected_and_nothing_is_published() {
        let (s, _d) = store();
        let d = Digest::of(b"hello");
        assert!(s.put(&NS, &d, b"HELLO", 1 << 20).is_err());
        assert!(!s.has(&NS, &d));
        let mut w = s.writer(&NS, d, 1 << 20).unwrap();
        assert!(w.write(0, b"hello world").is_err(), "larger than declared");
        drop(w);
        assert_eq!(s.usage(&NS), 0, "temporary file cleaned up");
    }

    #[test]
    fn chunks_must_be_in_order() {
        let (s, _d) = store();
        let d = Digest::of(b"abcdef");
        let mut w = s.writer(&NS, d, 1 << 20).unwrap();
        w.write(0, b"abc").unwrap();
        assert!(w.write(4, b"ef").is_err());
        w.write(3, b"def").unwrap();
        w.finish().unwrap();
        assert!(s.has(&NS, &d));
    }

    #[test]
    fn namespaces_lists_borrowers_and_clear_removes_one() {
        let (s, dir) = store();
        let d = Digest::of(b"x");
        s.put(&NS, &d, b"x", 1 << 20).unwrap();
        s.put(&OTHER, &d, b"x", 1 << 20).unwrap();
        std::fs::create_dir(dir.path().join("not-a-namespace")).unwrap();
        let mut ns = s.namespaces();
        ns.sort();
        assert_eq!(ns, [NS, OTHER]);
        s.clear(&NS).unwrap();
        assert_eq!(s.namespaces(), [OTHER]);
        assert!(s.has(&OTHER, &d));
    }

    #[test]
    fn put_file_streams_and_verifies() {
        let (s, dir) = store();
        let data = vec![7u8; (1 << 20) + 5];
        let src = dir.path().join("src.bin");
        std::fs::write(&src, &data).unwrap();
        let d = Digest::of(&data);
        s.put_file(&NS, &d, &src, 4 << 20).unwrap();
        assert_eq!(s.get(&NS, &d).unwrap(), data);
        std::fs::write(&src, b"changed").unwrap();
        let other = Digest::of(&[1u8; 7]);
        assert!(
            s.put_file(&NS, &other, &src, 4 << 20).is_err(),
            "content must match"
        );
    }

    #[test]
    fn the_same_blob_can_be_written_twice_at_once() {
        let (s, _d) = store();
        let d = Digest::of(b"same");
        let mut w1 = s.writer(&NS, d, 1 << 20).unwrap();
        let mut w2 = s.writer(&NS, d, 1 << 20).unwrap();
        w1.write(0, b"same").unwrap();
        w2.write(0, b"same").unwrap();
        w1.finish().unwrap();
        w2.finish().unwrap();
        assert_eq!(s.get(&NS, &d).unwrap(), b"same");
    }

    #[test]
    fn quota_is_enforced_per_namespace() {
        let (s, _d) = store();
        let a = Digest::of(&[1u8; 600]);
        let b = Digest::of(&[2u8; 600]);
        s.put(&NS, &a, &[1u8; 600], 1000).unwrap();
        assert!(
            s.put(&NS, &b, &[2u8; 600], 1000).is_err(),
            "would exceed 1000 bytes"
        );
        s.put(&OTHER, &b, &[2u8; 600], 1000).unwrap();
        // Re-storing an existing blob does not count twice.
        s.put(&NS, &a, &[1u8; 600], 1000).unwrap();
    }

    #[test]
    fn concurrent_writers_cannot_together_exceed_the_quota() {
        let (s, _dir) = store();
        let quota = 10 << 20;
        let blob = |n: u8| Digest {
            hash: [n; 32],
            size: 4 << 20,
        };
        // Eight uploads start at once (parallel streams), each fitting the quota alone.
        let started: Vec<_> = (0..8u8).map(|n| s.writer(&NS, blob(n), quota)).collect();
        let ok = started.iter().filter(|w| w.is_ok()).count();
        assert_eq!(ok, 2, "only what fits together is accepted");
        assert_eq!(s.usage(&NS), 8 << 20, "reserved bytes count");
        // A writer that ends (finished or abandoned) frees its share.
        drop(started);
        assert_eq!(s.usage(&NS), 0);
        assert!(s.writer(&NS, blob(9), quota).is_ok());
    }

    #[test]
    fn half_written_blobs_left_by_a_crash_are_removed_on_open() {
        let (s, dir) = store();
        let w = s.writer(&NS, Digest::of(b"abc"), 1 << 20).unwrap();
        std::mem::forget(w); // as if the process died mid-write
        let ns_dir = dir.path().join(NS.to_hex());
        assert!(std::fs::read_dir(&ns_dir).unwrap().count() > 0);
        let _reopened = BlobStore::new(dir.path().to_path_buf());
        assert_eq!(std::fs::read_dir(&ns_dir).unwrap().count(), 0);
    }

    #[test]
    fn a_corrupt_blob_is_deleted_so_it_is_sent_again() {
        let (s, dir) = store();
        let d = Digest::of(b"hello");
        s.put(&NS, &d, b"hello", 1 << 20).unwrap();
        std::fs::write(dir.path().join(NS.to_hex()).join(d.hex()), b"HELLO").unwrap();
        assert!(s.get(&NS, &d).is_err());
        assert!(!s.has(&NS, &d), "gone: FindMissing asks for it again");
    }
}
