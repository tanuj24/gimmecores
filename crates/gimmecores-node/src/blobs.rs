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
    /// What each namespace holds, kept as blobs come and go (see [`Counted`]).
    counted: Counts,
}

type Counts = std::sync::Arc<std::sync::Mutex<std::collections::HashMap<PeerKey, Counted>>>;

/// A namespace's bytes as last counted. Uploading a project of thousands of files must not
/// list the namespace (and walk its caches) once per file: that made a large upload slow
/// down with every file until the connection gave up.
#[derive(Debug, Default)]
struct Counted {
    /// Finished blobs: listed once, then kept exact as each blob is added or deleted (under
    /// this lock, so a count and the files never disagree).
    blobs: Option<u64>,
    /// Kept packages and caches, as measured at that moment. They change only when a task
    /// keeps packages or a cache comes back ([`BlobStore::dirs_changed`]); a quota check
    /// during an upload measures them again after [`DIRS_FRESH`] anyway.
    dirs: Option<(u64, std::time::Instant)>,
}

/// How long an upload's quota check trusts the last measure of kept packages and caches.
const DIRS_FRESH: std::time::Duration = std::time::Duration::from_secs(10);

impl BlobStore {
    /// Opens the store, removing blobs left half-written by a crash.
    pub fn new(root: PathBuf) -> Self {
        let store = Self {
            root,
            reserved: Default::default(),
            counted: Default::default(),
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

    fn counts(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<PeerKey, Counted>> {
        lock_counts(&self.counted)
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
            self.remove(ns, d);
            bail!("stored blob is corrupt");
        }
        std::fs::copy(&src, dest)?;
        Ok(())
    }

    fn path(&self, ns: &PeerKey, d: &Digest) -> PathBuf {
        self.ns_dir(ns).join(d.hex())
    }

    /// Where a stored blob is (to stream it whole, e.g. an image layer into `docker load`).
    pub(crate) fn file_of(&self, ns: &PeerKey, d: &Digest) -> PathBuf {
        self.path(ns, d)
    }

    /// Deletes one blob (an image layer once Docker holds it, or a corrupt one).
    pub fn remove(&self, ns: &PeerKey, d: &Digest) {
        let path = self.path(ns, d);
        let mut counts = self.counts();
        let len = std::fs::symlink_metadata(&path).map_or(0, |m| m.len());
        if std::fs::remove_file(&path).is_ok()
            && let Some(c) = counts.get_mut(ns)
        {
            // A file changed behind the store's back (damaged): counted again from disk.
            c.blobs = c
                .blobs
                .filter(|_| len == d.size)
                .map(|b| b.saturating_sub(len));
        }
    }

    pub fn has(&self, ns: &PeerKey, d: &Digest) -> bool {
        std::fs::metadata(self.path(ns, d)).is_ok_and(|m| m.len() == d.size)
    }

    /// Bytes stored in a namespace, kept packages and caches included (counted against the
    /// grant's disk quota). Kept packages and caches are measured now.
    pub fn usage(&self, ns: &PeerKey) -> u64 {
        let reserved = self.reservations().get(ns).copied().unwrap_or(0);
        self.stored(ns, true).saturating_add(reserved)
    }

    /// Kept packages or caches of `ns` changed: the next quota check measures them again.
    pub fn dirs_changed(&self, ns: &PeerKey) {
        if let Some(c) = self.counts().get_mut(ns) {
            c.dirs = None;
        }
    }

    /// Stored bytes (finished blobs, kept packages and caches), without blobs being written
    /// (those count through their reservations, not their partial files). `fresh` measures
    /// kept packages and caches now; otherwise a measure younger than [`DIRS_FRESH`] is used.
    fn stored(&self, ns: &PeerKey, fresh: bool) -> u64 {
        let blobs = {
            let mut counts = self.counts();
            let c = counts.entry(*ns).or_default();
            *c.blobs.get_or_insert_with(|| self.list_blobs(ns))
        };
        let known = self
            .counts()
            .get(ns)
            .and_then(|c| c.dirs)
            .filter(|(_, at)| !fresh && at.elapsed() < DIRS_FRESH)
            .map(|(b, _)| b);
        let dirs = known.unwrap_or_else(|| {
            let b = self.measure_dirs(ns);
            self.counts().entry(*ns).or_default().dirs = Some((b, std::time::Instant::now()));
            b
        });
        blobs.saturating_add(dirs)
    }

    /// Finished blobs on disk, listed (once per namespace; then kept by [`Counted`]).
    fn list_blobs(&self, ns: &PeerKey) -> u64 {
        std::fs::read_dir(self.ns_dir(ns))
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .filter(|e| !e.file_name().to_string_lossy().contains(".part"))
                    .filter_map(|e| e.metadata().ok())
                    .filter(std::fs::Metadata::is_file)
                    .map(|m| m.len())
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Kept packages and build caches, measured without following links. Unmeasurable
    /// counts as full: the quota check then refuses more.
    fn measure_dirs(&self, ns: &PeerKey) -> u64 {
        let measure = |dir: PathBuf| {
            if dir.exists() {
                crate::tree::disk_usage(&dir).unwrap_or(u64::MAX)
            } else {
                0
            }
        };
        measure(self.kept_dir(ns)).saturating_add(self.caches_usage(ns))
    }

    /// What a borrower's caches hold, measured by file descriptor (a process a task left
    /// behind may still be changing them; fsafe.rs). Unmeasurable counts as full.
    fn caches_usage(&self, ns: &PeerKey) -> u64 {
        let dir = self.caches_dir(ns);
        if !dir.exists() {
            return 0;
        }
        #[cfg(unix)]
        {
            use std::os::fd::AsFd;
            crate::fsafe::open_real(&self.ns_dir(ns), std::path::Path::new("caches"))
                .and_then(|o| {
                    crate::fsafe::open_up_and_measure(
                        o.dir.as_fd(),
                        crate::tree::MAX_WORKSPACE_ENTRIES,
                    )
                })
                .unwrap_or(u64::MAX)
        }
        #[cfg(not(unix))]
        {
            crate::tree::disk_usage(&dir).unwrap_or(u64::MAX)
        }
    }

    /// A borrower's build caches kept between tasks (caches.rs). Part of the namespace:
    /// counted in its usage and deleted with it.
    pub fn caches_dir(&self, ns: &PeerKey) -> PathBuf {
        self.ns_dir(ns).join("caches")
    }

    /// A borrower's packages kept unpacked between tasks (macOS sandbox; see tasks_flow). Part
    /// of the namespace: counted in its usage and deleted with it.
    pub fn kept_dir(&self, ns: &PeerKey) -> PathBuf {
        self.ns_dir(ns).join("pkgs")
    }

    pub fn get(&self, ns: &PeerKey, d: &Digest) -> Result<Vec<u8>> {
        let data = std::fs::read(self.path(ns, d)).context("blob not found")?;
        if Digest::of(&data) != *d {
            self.remove(ns, d);
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
            let used = self
                .stored(ns, false)
                .saturating_add(r.get(ns).copied().unwrap_or(0));
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
            ns: *ns,
            counted: self.counted.clone(),
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
        // Caches hold what tasks wrote (folders they may have locked): opened up, never
        // following links, before the rest goes.
        let caches = self.caches_dir(ns);
        if caches.exists() {
            crate::tasks_flow::remove_workspace(&caches);
        }
        let mut counts = self.counts();
        counts.remove(ns);
        if dir.exists() {
            std::fs::remove_dir_all(dir)?;
        }
        Ok(())
    }
}

fn lock_counts(
    c: &Counts,
) -> std::sync::MutexGuard<'_, std::collections::HashMap<PeerKey, Counted>> {
    c.lock().unwrap_or_else(|p| p.into_inner())
}

pub struct BlobWriter {
    digest: Digest,
    ns: PeerKey,
    counted: Counts,
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
        // Counted under the same lock as the rename: a blob written twice at once (or over a
        // damaged copy) is counted once, at its real size.
        let mut counts = lock_counts(&self.counted);
        let before = std::fs::symlink_metadata(&self.final_path)
            .ok()
            .filter(std::fs::Metadata::is_file)
            .map_or(0, |m| m.len());
        std::fs::rename(&self.tmp, &self.final_path)?;
        if let Some(c) = counts.get_mut(&self.ns) {
            let size = self.digest.size;
            // Replacing a damaged copy: counted again from disk.
            c.blobs = c
                .blobs
                .filter(|_| before == 0 || before == size)
                .map(|b| b.saturating_sub(before).saturating_add(size));
        }
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
    fn the_count_stays_exact_as_blobs_come_and_go() {
        let (s, dir) = store();
        let on_disk = |s: &BlobStore| s.list_blobs(&NS);
        let a = Digest::of(&[1u8; 300]);
        let b = Digest::of(&[2u8; 500]);
        s.put(&NS, &a, &[1u8; 300], 1 << 20).unwrap();
        assert_eq!(s.usage(&NS), 300, "counted from disk the first time");
        s.put(&NS, &b, &[2u8; 500], 1 << 20).unwrap();
        s.put(&NS, &a, &[1u8; 300], 1 << 20).unwrap();
        // Written twice at once: counted once.
        let c = Digest::of(b"twice");
        let mut w1 = s.writer(&NS, c, 1 << 20).unwrap();
        let mut w2 = s.writer(&NS, c, 1 << 20).unwrap();
        w1.write(0, b"twice").unwrap();
        w2.write(0, b"twice").unwrap();
        w1.finish().unwrap();
        w2.finish().unwrap();
        assert_eq!(s.usage(&NS), on_disk(&s));
        assert_eq!(s.usage(&NS), 805);
        s.remove(&NS, &b);
        assert_eq!(s.usage(&NS), 305);
        // A damaged copy found on use is deleted and no longer counted.
        std::fs::write(dir.path().join(NS.to_hex()).join(a.hex()), [9u8; 10]).unwrap();
        assert!(s.get(&NS, &a).is_err());
        assert_eq!(s.usage(&NS), on_disk(&s));
        s.clear(&NS).unwrap();
        assert_eq!(s.usage(&NS), 0);
        s.put(&NS, &b, &[2u8; 500], 1 << 20).unwrap();
        assert_eq!(s.usage(&NS), 500, "counted again after clearing");
    }

    #[test]
    fn caches_and_kept_packages_are_seen_by_the_next_quota_check() {
        let (s, _dir) = store();
        let a = Digest::of(&[1u8; 400]);
        s.put(&NS, &a, &[1u8; 400], 1000).unwrap();
        // A cache comes back (caches.rs tells the store).
        std::fs::create_dir_all(s.caches_dir(&NS).join("k")).unwrap();
        std::fs::write(s.caches_dir(&NS).join("k/f"), vec![0u8; 700]).unwrap();
        s.dirs_changed(&NS);
        let b = Digest::of(&[2u8; 100]);
        assert!(
            s.put(&NS, &b, &[2u8; 100], 1000).is_err(),
            "the cache counts at once"
        );
        assert!(s.usage(&NS) >= 1100);
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
