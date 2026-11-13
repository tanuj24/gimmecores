//! Content-addressed directory trees (`Directory` blobs in `peer.proto`).
//!
//! - [`build`]: the borrower packs a folder, honouring `.gitignore`/`.gmcignore` and the default
//!   secret excludes (threat model I7). Symlinks are skipped (not supported in v1).
//! - [`materialize`]: the lender unpacks an input tree into a task workspace.
//! - [`extract`]: the borrower writes returned outputs, only inside the declared paths (I8).
//!
//! Every name is validated on both sides: no separators, no `.`/`..`, no control characters,
//! no Windows reserved names, no case-insensitive duplicates.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use gimmecores_core::PeerKey;
use gimmecores_proto::peer::v1 as pb;
use globset::{Glob, GlobSet, GlobSetBuilder};
use prost::Message;

use crate::blobs::{BlobStore, Digest};

/// Always excluded unless named explicitly (spec/gmc-toml.md).
pub const DEFAULT_EXCLUDES: &[&str] = &[
    ".git",
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
    ".ssh",
    ".aws",
    ".azure",
    ".gcloud",
    ".kube",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "*.keystore",
    "credentials*.json",
    "service-account*.json",
    ".docker",
];

/// Largest tree we will unpack or extract (defence against decompression-style abuse).
pub const MAX_TREE_BYTES: u64 = 8 << 30;
const MAX_DEPTH: usize = 64;
const MAX_ENTRIES: usize = 200_000;

const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

pub fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && name != "." && name != "..",
        "invalid file name {name:?}"
    );
    ensure!(
        !name
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control()),
        "invalid characters in file name {name:?}"
    );
    ensure!(
        !name.ends_with('.') && !name.ends_with(' '),
        "file name {name:?} ends with a dot or space"
    );
    let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    ensure!(
        !WINDOWS_RESERVED.contains(&stem.as_str()),
        "file name {name:?} is reserved on Windows"
    );
    Ok(())
}

fn validate_siblings<'a>(names: impl Iterator<Item = &'a str>) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for n in names {
        validate_name(n)?;
        ensure!(
            seen.insert(n.to_lowercase()),
            "names differing only in case: {n:?}"
        );
    }
    Ok(())
}

/// Bytes a directory occupies, for the lender's disk limit. Regular files count their length
/// (at least [`ENTRY_OVERHEAD`]); directories, links and other entries count
/// [`ENTRY_OVERHEAD`], so millions of empty files are not free. Symlinks are not followed.
/// Entries that vanish during the walk (build tools create and delete files all the time) are
/// skipped. Fails if the root or any directory cannot be read, or there are more than
/// [`MAX_WORKSPACE_ENTRIES`] entries, so the caller can fail closed.
pub fn disk_usage(dir: &Path) -> Result<u64> {
    use std::io::ErrorKind::NotFound;
    let mut total = 0u64;
    let mut entries = 0usize;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let rd = match std::fs::read_dir(&d) {
            Ok(rd) => rd,
            Err(e) if e.kind() == NotFound && d != dir => continue,
            Err(e) => return Err(e).with_context(|| format!("cannot inspect {}", d.display())),
        };
        for e in rd {
            // `DirEntry::metadata` does not follow symlinks.
            let (path, meta) = match e.and_then(|e| Ok((e.path(), e.metadata()?))) {
                Ok(pm) => pm,
                Err(e) if e.kind() == NotFound => continue,
                Err(e) => return Err(e).with_context(|| format!("cannot inspect {}", d.display())),
            };
            entries += 1;
            ensure!(
                entries <= MAX_WORKSPACE_ENTRIES,
                "more than {MAX_WORKSPACE_ENTRIES} files"
            );
            let charge = if meta.is_file() {
                meta.len().max(ENTRY_OVERHEAD)
            } else {
                ENTRY_OVERHEAD
            };
            total = total.saturating_add(charge);
            if meta.is_dir() {
                stack.push(path);
            }
        }
    }
    Ok(total)
}

/// Minimum bytes charged per file, directory or link by [`disk_usage`].
pub const ENTRY_OVERHEAD: u64 = 512;
/// A workspace with more entries than this cannot be measured cheaply and stops its task.
pub const MAX_WORKSPACE_ENTRIES: usize = 500_000;

/// Source of a blob on the borrower side.
#[derive(Clone, Debug)]
pub enum Source {
    Bytes(Vec<u8>),
    File(PathBuf),
}

impl Source {
    pub fn read(&self) -> Result<Vec<u8>> {
        match self {
            Source::Bytes(b) => Ok(b.clone()),
            Source::File(p) => std::fs::read(p).with_context(|| format!("reading {}", p.display())),
        }
    }
}

#[derive(Debug, Default)]
pub struct Tree {
    pub root: Option<Digest>,
    pub blobs: BTreeMap<Digest, Source>,
    pub file_count: usize,
    pub total_bytes: u64,
    /// Paths skipped because they are symlinks or other special files.
    pub skipped: Vec<PathBuf>,
    /// Files packed by [`build`]: (absolute path, path relative to the root).
    pub files: Vec<(PathBuf, PathBuf)>,
}

#[derive(Default)]
struct DirNode {
    files: BTreeMap<String, (Digest, bool)>,
    dirs: BTreeMap<String, DirNode>,
}

fn excludes(extra: &[String]) -> Result<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for pat in DEFAULT_EXCLUDES
        .iter()
        .copied()
        .chain(extra.iter().map(String::as_str))
    {
        b.add(Glob::new(pat)?);
    }
    Ok(b.build()?)
}

#[cfg(unix)]
fn is_executable(m: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    m.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_m: &std::fs::Metadata) -> bool {
    false
}

/// Digests of files hashed before, keyed by what changes whenever a file is written: device,
/// inode, size, modification and status-change times (the status-change time cannot be set back
/// by a user). Projects and package folders are re-sent task after task; this saves hashing them
/// again. A file changed between hashing and upload still fails: the lender verifies each blob.
static DIGESTS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<PathBuf, (FileStamp, Digest)>>,
> = std::sync::LazyLock::new(Default::default);
const MAX_CACHED_DIGESTS: usize = 1_000_000;

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp([i128; 5]);

fn stamp(m: &std::fs::Metadata) -> Option<FileStamp> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(FileStamp([
            i128::from(m.dev()),
            i128::from(m.ino()),
            i128::from(m.size()),
            i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()),
            i128::from(m.ctime()) * 1_000_000_000 + i128::from(m.ctime_nsec()),
        ]))
    }
    #[cfg(not(unix))]
    {
        let _ = m;
        None // no status-change time: always hash
    }
}

/// The file's digest, from the cache when it has not changed since it was last hashed.
fn digest_file(path: &Path, meta: &std::fs::Metadata) -> Result<Digest> {
    let st = stamp(meta);
    if let Some(st) = st
        && let Ok(cache) = DIGESTS.lock()
        && let Some((s, d)) = cache.get(path)
        && *s == st
    {
        return Ok(*d);
    }
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let d = Digest::of(&data);
    // Stamp again after reading: a write during the read must not be cached.
    let after = std::fs::metadata(path).ok().as_ref().and_then(stamp);
    if let Some(st) = st
        && after == Some(st)
        && let Ok(mut cache) = DIGESTS.lock()
    {
        if cache.len() >= MAX_CACHED_DIGESTS {
            cache.clear();
        }
        cache.insert(path.to_path_buf(), (st, d));
    }
    Ok(d)
}

/// Packs `root` into a content-addressed tree.
pub fn build(root: &Path, extra_excludes: &[String]) -> Result<Tree> {
    build_with(root, extra_excludes, &[])
}

/// Files an SDK adds to a task's inputs without writing them into the project (its worker
/// payload). They live under this folder, which a project may not use itself.
pub const SDK_DIR: &str = ".gmc-sdk";

/// [`build`], plus `extra` files (relative paths under [`SDK_DIR`]) given as bytes.
pub fn build_with(
    root: &Path,
    extra_excludes: &[String],
    extra: &[(String, Vec<u8>)],
) -> Result<Tree> {
    build_full(root, extra_excludes, extra, &[])
}

/// A local file or folder an SDK sends under `.gmc-sdk/`, next to the project but not part of
/// it (installed packages, files passed as arguments).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    /// Absolute path on this machine.
    pub local: PathBuf,
    /// Where it appears in the task folder, under `.gmc-sdk/`.
    pub path: String,
    /// An installed-packages folder (site-packages). A file in it that matches the hash its
    /// package's `RECORD` lists is published package content and is sent as it is (packages
    /// carry example keys and CA bundles that the secret scan and the `*.pem` exclude would
    /// otherwise stop). Every other file gets the default excludes and the secret scan.
    pub packages: bool,
}

fn under_sdk_dir(rel: &str) -> Result<()> {
    validate_output_path(rel)?;
    ensure!(
        Path::new(rel).starts_with(SDK_DIR) && Path::new(rel) != Path::new(SDK_DIR),
        "SDK files must be under {SDK_DIR}/"
    );
    Ok(())
}

fn insert_file(top: &mut DirNode, rel: &str, d: Digest, exec: bool) -> Result<()> {
    let parts: Vec<String> = Path::new(rel)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let (file, dirs) = parts.split_last().context("empty path")?;
    let mut node = top;
    for dir in dirs {
        ensure!(!node.files.contains_key(dir), "{rel} given twice");
        node = node.dirs.entry(dir.clone()).or_default();
    }
    ensure!(
        !node.dirs.contains_key(file) && node.files.insert(file.clone(), (d, exec)).is_none(),
        "{rel} given twice"
    );
    Ok(())
}

/// `RECORD` hashes of every package installed in `dir`: relative path -> (sha256, size).
/// Entries pointing outside the folder are ignored.
fn package_records(dir: &Path) -> BTreeMap<PathBuf, ([u8; 32], Option<u64>)> {
    let mut out = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".dist-info") {
            continue;
        }
        let record = e.path().join("RECORD");
        // Never follow a symlinked RECORD; it is read only to recognise package files.
        if !std::fs::symlink_metadata(&record).is_ok_and(|m| m.file_type().is_file()) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&record) else {
            continue;
        };
        for line in text.lines() {
            if let Some((path, hash, size)) = record_line(line) {
                out.insert(path, (hash, size));
            }
        }
    }
    out
}

/// One `RECORD` line: `path,sha256=<urlsafe base64>,size` (path CSV-quoted when needed).
fn record_line(line: &str) -> Option<(PathBuf, [u8; 32], Option<u64>)> {
    let (path, rest) = if let Some(q) = line.strip_prefix('"') {
        let mut path = String::new();
        let mut chars = q.char_indices().peekable();
        let mut end = None;
        while let Some((i, c)) = chars.next() {
            if c == '"' {
                if chars.peek().is_some_and(|(_, n)| *n == '"') {
                    chars.next();
                    path.push('"');
                } else {
                    end = Some(i + 1);
                    break;
                }
            } else {
                path.push(c);
            }
        }
        (path, q[end?..].strip_prefix(',')?)
    } else {
        let (p, r) = line.split_once(',')?;
        (p.to_string(), r)
    };
    let (hash, size) = rest.split_once(',').unwrap_or((rest, ""));
    let b64 = hash.strip_prefix("sha256=")?;
    let bytes = b64url_decode(b64)?;
    let hash: [u8; 32] = bytes.try_into().ok()?;
    let rel = validate_output_path(&path).ok()?;
    Some((rel, hash, size.trim().parse().ok()))
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Adds one attachment to the tree.
fn attach(tree: &mut Tree, top: &mut DirNode, ex: &GlobSet, a: &Attachment) -> Result<()> {
    under_sdk_dir(&a.path)?;
    ensure!(a.local.is_absolute(), "attachments need an absolute path");
    let meta = std::fs::symlink_metadata(&a.local)
        .with_context(|| format!("{} not found", a.local.display()))?;
    ensure!(
        !meta.file_type().is_symlink(),
        "{} is a symlink; attach the file itself",
        a.local.display()
    );
    let mut add = |abs: &Path, d: Digest, dest: String, exec: bool, scan: bool| -> Result<()> {
        tree.total_bytes += d.size;
        tree.file_count += 1;
        ensure!(tree.file_count <= MAX_ENTRIES, "too many files to send");
        tree.blobs.insert(d, Source::File(abs.to_path_buf()));
        if scan {
            tree.files.push((abs.to_path_buf(), PathBuf::from(&dest)));
        }
        insert_file(top, &dest, d, exec)
    };
    if meta.is_file() {
        // A single file passed by name: chosen explicitly, so no name exclude, but its
        // content is still scanned.
        ensure!(!a.packages, "a packages attachment must be a folder");
        let d = digest_file(&a.local, &std::fs::metadata(&a.local)?)?;
        return add(&a.local, d, a.path.clone(), is_executable(&meta), true);
    }
    ensure!(
        meta.is_dir(),
        "{} is not a file or folder",
        a.local.display()
    );
    let records = if a.packages {
        package_records(&a.local)
    } else {
        BTreeMap::new()
    };
    let mut skipped = Vec::new();
    let walker = ignore::WalkBuilder::new(&a.local)
        .standard_filters(false)
        .follow_links(false)
        .build();
    for entry in walker {
        let entry = entry?;
        let rel = entry.path().strip_prefix(&a.local)?.to_path_buf();
        let ft = entry.file_type().context("unknown file type")?;
        if rel.as_os_str().is_empty() || ft.is_dir() {
            continue;
        }
        if !ft.is_file() {
            skipped.push(rel);
            continue;
        }
        let meta = entry.metadata()?;
        let d = digest_file(entry.path(), &meta)?;
        let verified = records
            .get(&rel)
            .is_some_and(|(hash, size)| d.hash == *hash && size.is_none_or(|s| s == d.size));
        // Name excludes (keys, .env, ...) apply to anything that is not a verified package
        // file, inside attachments as everywhere else.
        if !verified && rel.components().any(|c| ex.is_match(c.as_os_str())) {
            skipped.push(rel);
            continue;
        }
        let exec = is_executable(&meta);
        let dest = format!("{}/{}", a.path, rel.to_string_lossy());
        add(entry.path(), d, dest, exec, !verified)?;
    }
    tree.skipped.extend(skipped);
    Ok(())
}

/// [`build_with`] plus attachments (see [`Attachment`]).
pub fn build_full(
    root: &Path,
    extra_excludes: &[String],
    extra: &[(String, Vec<u8>)],
    attachments: &[Attachment],
) -> Result<Tree> {
    for (rel, _) in extra {
        under_sdk_dir(rel)?;
    }
    let ex = excludes(extra_excludes)?;
    let mut tree = Tree::default();
    let mut top = DirNode::default();
    let walker = ignore::WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(false)
        .require_git(false)
        .follow_links(false)
        .add_custom_ignore_filename(".gmcignore")
        .filter_entry(move |e| !ex.is_match(e.file_name()))
        .build();
    for entry in walker {
        let entry = entry?;
        let rel = entry.path().strip_prefix(root)?.to_path_buf();
        if rel.as_os_str().is_empty() {
            continue;
        }
        let ft = entry.file_type().context("unknown file type")?;
        if ft.is_dir() {
            continue;
        }
        if !ft.is_file() {
            tree.skipped.push(rel);
            continue;
        }
        let meta = entry.metadata()?;
        let d = digest_file(entry.path(), &meta)?;
        tree.total_bytes += d.size;
        tree.file_count += 1;
        ensure!(tree.file_count <= MAX_ENTRIES, "too many files to send");
        tree.blobs
            .insert(d, Source::File(entry.path().to_path_buf()));
        tree.files.push((entry.path().to_path_buf(), rel.clone()));

        let mut node = &mut top;
        let parts: Vec<String> = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        let (file, dirs) = parts.split_last().context("empty path")?;
        for dir in dirs {
            node = node.dirs.entry(dir.clone()).or_default();
        }
        node.files.insert(file.clone(), (d, is_executable(&meta)));
    }
    if !extra.is_empty() || !attachments.is_empty() {
        ensure!(
            !top.dirs.contains_key(SDK_DIR) && !top.files.contains_key(SDK_DIR),
            "the project has its own {SDK_DIR}, which GimmeCores needs for its own files"
        );
    }
    for (rel, data) in extra {
        let d = Digest::of(data);
        tree.total_bytes += d.size;
        tree.file_count += 1;
        ensure!(tree.file_count <= MAX_ENTRIES, "too many files to send");
        tree.blobs.insert(d, Source::Bytes(data.clone()));
        insert_file(&mut top, rel, d, false)?;
    }
    let ex_all = excludes(extra_excludes)?;
    for a in attachments {
        attach(&mut tree, &mut top, &ex_all, a)?;
    }
    tree.root = Some(encode(&top, &mut tree.blobs)?);
    Ok(tree)
}

fn encode(node: &DirNode, blobs: &mut BTreeMap<Digest, Source>) -> Result<Digest> {
    validate_siblings(
        node.files
            .keys()
            .chain(node.dirs.keys())
            .map(String::as_str),
    )?;
    let mut dir = pb::Directory::default();
    for (name, (d, exec)) in &node.files {
        dir.files.push(pb::FileNode {
            name: name.clone(),
            digest: Some(d.to_proto()),
            executable: *exec,
        });
    }
    for (name, child) in &node.dirs {
        let d = encode(child, blobs)?;
        dir.directories.push(pb::DirectoryNode {
            name: name.clone(),
            digest: Some(d.to_proto()),
        });
    }
    let bytes = dir.encode_to_vec();
    let d = Digest::of(&bytes);
    blobs.insert(d, Source::Bytes(bytes));
    Ok(d)
}

/// Reads a directory blob and checks its entries.
pub fn decode_dir(bytes: &[u8]) -> Result<pb::Directory> {
    let dir = pb::Directory::decode(bytes)?;
    validate_siblings(
        dir.files
            .iter()
            .map(|f| f.name.as_str())
            .chain(dir.directories.iter().map(|d| d.name.as_str())),
    )?;
    Ok(dir)
}

#[cfg(unix)]
fn set_executable(path: &Path, exec: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if exec { 0o755 } else { 0o644 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path, _exec: bool) -> Result<()> {
    Ok(())
}

/// Lender: unpacks the tree `root` from namespace `ns` into `dest` (which must be empty/new).
pub fn materialize(store: &BlobStore, ns: &PeerKey, root: &Digest, dest: &Path) -> Result<u64> {
    materialize_except(store, ns, root, dest, None)
}

/// Where an SDK's installed packages arrive in a task folder.
pub const PACKAGES_DIR: &str = ".gmc-sdk/env";

/// Lender: [`materialize`], leaving out the folder at `skip` (relative to the root).
pub fn materialize_except(
    store: &BlobStore,
    ns: &PeerKey,
    root: &Digest,
    dest: &Path,
    skip: Option<&Path>,
) -> Result<u64> {
    std::fs::create_dir_all(dest)?;
    let mut total = 0u64;
    let mut count = 0usize;
    let mut fetch = |d: &Digest| store.get(ns, d);
    let mut w = Walk {
        fetch: &mut fetch,
        total: &mut total,
        count: &mut count,
        skip,
    };
    w.out(root, dest, Path::new(""), 0)?;
    Ok(total)
}

/// Lender: the digest of the folder at `rel` in the tree `root`, if there is one.
pub fn subtree(
    store: &BlobStore,
    ns: &PeerKey,
    root: &Digest,
    rel: &str,
) -> Result<Option<Digest>> {
    let mut at = *root;
    for name in Path::new(rel).components() {
        let name = name.as_os_str().to_string_lossy();
        let dir = decode_dir(&store.get(ns, &at)?)?;
        let Some(node) = dir.directories.iter().find(|d| d.name == name) else {
            return Ok(None);
        };
        at = Digest::from_proto(node.digest.as_ref().context("dir without digest")?)?;
    }
    Ok(Some(at))
}

/// Borrower: writes a returned output tree under `dest`, fetching blobs with `fetch`.
pub fn extract(
    fetch: &mut dyn FnMut(&Digest) -> Result<Vec<u8>>,
    root: &Digest,
    dest: &Path,
) -> Result<u64> {
    std::fs::create_dir_all(dest)?;
    let mut total = 0u64;
    let mut count = 0usize;
    let mut w = Walk {
        fetch,
        total: &mut total,
        count: &mut count,
        skip: None,
    };
    w.out(root, dest, Path::new(""), 0)?;
    Ok(total)
}

struct Walk<'a> {
    fetch: &'a mut dyn FnMut(&Digest) -> Result<Vec<u8>>,
    total: &'a mut u64,
    count: &'a mut usize,
    skip: Option<&'a Path>,
}

impl Walk<'_> {
    fn out(&mut self, dir_digest: &Digest, dest: &Path, rel: &Path, depth: usize) -> Result<()> {
        ensure!(depth <= MAX_DEPTH, "directory tree too deep");
        let dir = decode_dir(&(self.fetch)(dir_digest)?)?;
        for f in &dir.files {
            let d = Digest::from_proto(f.digest.as_ref().context("file without digest")?)?;
            *self.total = self.total.saturating_add(d.size);
            *self.count += 1;
            ensure!(
                *self.total <= MAX_TREE_BYTES && *self.count <= MAX_ENTRIES,
                "tree too large"
            );
            let data = (self.fetch)(&d)?;
            let path = dest.join(&f.name);
            // Never follow or replace a symlink planted at the destination.
            if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
                bail!("refusing to write through a symlink at {}", path.display());
            }
            std::fs::write(&path, &data)?;
            set_executable(&path, f.executable)?;
        }
        for sub in &dir.directories {
            let sub_rel = rel.join(&sub.name);
            if self.skip == Some(sub_rel.as_path()) {
                continue;
            }
            let d = Digest::from_proto(sub.digest.as_ref().context("dir without digest")?)?;
            let path = dest.join(&sub.name);
            if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
                bail!("refusing to write through a symlink at {}", path.display());
            }
            std::fs::create_dir_all(&path)?;
            self.out(&d, &path, &sub_rel, depth + 1)?;
        }
        Ok(())
    }
}

/// Checks a declared output path: relative, no `..`, no root or prefix components.
pub fn validate_output_path(p: &str) -> Result<PathBuf> {
    let path = PathBuf::from(p);
    ensure!(!p.is_empty(), "empty output path");
    for c in path.components() {
        match c {
            Component::Normal(n) => validate_name(&n.to_string_lossy())?,
            _ => bail!("output path {p:?} must be relative and must not contain '..'"),
        }
    }
    Ok(path)
}

/// What one returned directory contains, after checking it against the declared outputs.
#[derive(Debug, Default)]
pub struct OutputLevel {
    pub dirs: Vec<(PathBuf, Digest)>,
    pub files: Vec<(PathBuf, Digest)>,
}

/// I8 (borrower side): checks one directory of a lender-returned output tree.
///
/// A returned file must sit at or under a declared output path; a directory must be inside one
/// or be an ancestor needed to reach one. Anything else (e.g. `.git/hooks/pre-commit` or
/// `conftest.py` when only `reports/` was declared) fails the whole run. `budget` is the number
/// of bytes still allowed; it shrinks by every file's declared size before anything is fetched.
pub fn inspect_output_dir(
    path: &Path,
    dir_bytes: &[u8],
    outputs: &[PathBuf],
    budget: &mut u64,
) -> Result<OutputLevel> {
    let dir = decode_dir(dir_bytes)?;
    let mut level = OutputLevel::default();
    for sub in &dir.directories {
        let p = path.join(&sub.name);
        let inside = outputs.iter().any(|o| p.starts_with(o));
        let ancestor = outputs.iter().any(|o| o.starts_with(&p));
        ensure!(
            inside || ancestor,
            "the lender returned {} which is not a declared output; nothing was written",
            p.display()
        );
        let d = Digest::from_proto(sub.digest.as_ref().context("dir without digest")?)?;
        level.dirs.push((p, d));
    }
    for f in &dir.files {
        let p = path.join(&f.name);
        ensure!(
            outputs.iter().any(|o| p.starts_with(o)),
            "the lender returned {} which is not a declared output; nothing was written",
            p.display()
        );
        let d = Digest::from_proto(f.digest.as_ref().context("file without digest")?)?;
        *budget = budget
            .checked_sub(d.size)
            .context("the returned outputs are larger than allowed; nothing was written")?;
        level.files.push((p, d));
    }
    Ok(level)
}

/// Lender: packs the declared outputs of a finished task into a tree.
pub fn collect_outputs(workspace: &Path, outputs: &[String]) -> Result<Tree> {
    let mut tree = Tree::default();
    let mut top = DirNode::default();
    for out in outputs {
        let rel = validate_output_path(out)?;
        let abs = workspace.join(&rel);
        let meta = match std::fs::symlink_metadata(&abs) {
            Ok(m) => m,
            Err(_) => continue, // declared but not produced
        };
        if meta.file_type().is_symlink() {
            tree.skipped.push(rel);
            continue;
        }
        let files: Vec<(PathBuf, PathBuf)> = if meta.is_file() {
            vec![(abs.clone(), rel.clone())]
        } else {
            let mut v = Vec::new();
            for e in ignore::WalkBuilder::new(&abs)
                .standard_filters(false)
                .follow_links(false)
                .build()
            {
                let e = e?;
                if e.file_type().is_some_and(|t| t.is_file()) {
                    v.push((
                        e.path().to_path_buf(),
                        e.path().strip_prefix(workspace)?.to_path_buf(),
                    ));
                } else if e.file_type().is_some_and(|t| t.is_symlink()) {
                    tree.skipped
                        .push(e.path().strip_prefix(workspace)?.to_path_buf());
                }
            }
            v
        };
        for (abs, rel) in files {
            let data = std::fs::read(&abs)?;
            let d = Digest::of(&data);
            tree.total_bytes += d.size;
            tree.file_count += 1;
            ensure!(tree.total_bytes <= MAX_TREE_BYTES, "outputs too large");
            tree.blobs.insert(d, Source::Bytes(data));
            let parts: Vec<String> = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            let (file, dirs) = parts.split_last().context("empty path")?;
            let mut node = &mut top;
            for dir in dirs {
                node = node.dirs.entry(dir.clone()).or_default();
            }
            node.files
                .insert(file.clone(), (d, is_executable(&std::fs::metadata(&abs)?)));
        }
    }
    tree.root = Some(encode(&top, &mut tree.blobs)?);
    Ok(tree)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_usage_counts_files_and_entries_without_following_links() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("sub")).unwrap();
        std::fs::write(d.path().join("sub/big"), vec![0u8; 10_000]).unwrap();
        std::fs::write(d.path().join("empty"), b"").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/", d.path().join("root")).unwrap();
        let used = disk_usage(d.path()).unwrap();
        // sub/ and the link count ENTRY_OVERHEAD whatever the file system reports; the empty
        // file counts ENTRY_OVERHEAD as its minimum.
        let small = if cfg!(unix) { 3 } else { 2 };
        assert_eq!(used, 10_000 + small * ENTRY_OVERHEAD);
        assert!(
            disk_usage(&d.path().join("missing")).is_err(),
            "a missing root fails"
        );
    }

    fn write(root: &Path, rel: &str, data: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }

    #[test]
    fn names_are_validated() {
        for bad in [
            "", ".", "..", "a/b", "a\\b", "CON", "nul.txt", "x.", "x ", "a\u{0}b",
        ] {
            assert!(validate_name(bad).is_err(), "{bad:?}");
        }
        for good in ["main.rs", ".gitignore", "Cargo.toml", "con_tents.txt"] {
            assert!(validate_name(good).is_ok(), "{good:?}");
        }
        assert!(validate_siblings(["Readme.md", "README.md"].into_iter()).is_err());
    }

    #[test]
    fn i7_secrets_and_ignored_files_are_never_packed() {
        let src = tempfile::tempdir().unwrap();
        let r = src.path();
        write(r, "src/main.rs", "fn main() {}");
        write(r, ".env", "API_KEY=secret");
        write(r, ".env.local", "X=1");
        write(r, "keys/server.pem", "-----BEGIN");
        write(r, ".ssh/id_ed25519", "private");
        write(r, ".aws/credentials", "aws");
        write(r, "target/big.bin", "build output");
        write(r, ".gitignore", "target/\n");
        write(r, "local.log", "x");
        write(r, ".gmcignore", "*.log\n");
        let tree = build(r, &[]).unwrap();
        let packed: Vec<String> = tree
            .blobs
            .values()
            .filter_map(|s| match s {
                Source::File(p) => Some(p.strip_prefix(r).unwrap().display().to_string()),
                Source::Bytes(_) => None,
            })
            .collect();
        assert!(packed.contains(&"src/main.rs".to_string()), "{packed:?}");
        for secret in [
            ".env",
            ".env.local",
            "keys/server.pem",
            ".ssh/id_ed25519",
            ".aws/credentials",
            "target/big.bin",
            "local.log",
        ] {
            assert!(
                !packed.iter().any(|p| p == secret),
                "{secret} was packed: {packed:?}"
            );
        }
    }

    #[test]
    fn build_then_materialize_round_trips() {
        let src = tempfile::tempdir().unwrap();
        write(src.path(), "a.txt", "alpha");
        write(src.path(), "dir/b.txt", "beta");
        write(src.path(), "dir/deeper/c.txt", "gamma");
        let tree = build(src.path(), &[]).unwrap();
        assert_eq!(tree.file_count, 3);

        let store_dir = tempfile::tempdir().unwrap();
        let store = BlobStore::new(store_dir.path().to_path_buf());
        let ns = PeerKey([3; 32]);
        for (d, s) in &tree.blobs {
            store.put(&ns, d, &s.read().unwrap(), 1 << 30).unwrap();
        }
        let dest = tempfile::tempdir().unwrap();
        materialize(&store, &ns, &tree.root.unwrap(), &dest.path().join("ws")).unwrap();
        let ws = dest.path().join("ws");
        assert_eq!(
            std::fs::read_to_string(ws.join("dir/deeper/c.txt")).unwrap(),
            "gamma"
        );
        assert_eq!(std::fs::read_to_string(ws.join("a.txt")).unwrap(), "alpha");
    }

    #[test]
    fn i8_output_paths_must_stay_inside_the_project() {
        for bad in ["../escape", "/etc/passwd", "a/../../b", ""] {
            assert!(validate_output_path(bad).is_err(), "{bad:?}");
        }
        assert!(validate_output_path("reports/junit.xml").is_ok());
    }

    #[test]
    fn i8_malicious_directory_blob_names_are_rejected_on_extract() {
        let evil = pb::Directory {
            files: vec![pb::FileNode {
                name: "../../.bashrc".into(),
                digest: Some(Digest::of(b"x").to_proto()),
                executable: false,
            }],
            directories: vec![],
        };
        let bytes = evil.encode_to_vec();
        let root = Digest::of(&bytes);
        let dest = tempfile::tempdir().unwrap();
        let mut fetch = |d: &Digest| -> Result<Vec<u8>> {
            if *d == root {
                Ok(bytes.clone())
            } else {
                Ok(b"x".to_vec())
            }
        };
        assert!(extract(&mut fetch, &root, dest.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn i8_extract_refuses_to_write_through_symlinks() {
        let dest = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dest.path().join("reports")).unwrap();
        let leaf = pb::Directory {
            files: vec![pb::FileNode {
                name: "x.txt".into(),
                digest: Some(Digest::of(b"pwned").to_proto()),
                executable: false,
            }],
            directories: vec![],
        };
        let leaf_bytes = leaf.encode_to_vec();
        let top = pb::Directory {
            files: vec![],
            directories: vec![pb::DirectoryNode {
                name: "reports".into(),
                digest: Some(Digest::of(&leaf_bytes).to_proto()),
            }],
        };
        let top_bytes = top.encode_to_vec();
        let root = Digest::of(&top_bytes);
        let mut fetch = |d: &Digest| -> Result<Vec<u8>> {
            if *d == root {
                Ok(top_bytes.clone())
            } else if *d == Digest::of(&leaf_bytes) {
                Ok(leaf_bytes.clone())
            } else {
                Ok(b"pwned".to_vec())
            }
        };
        assert!(extract(&mut fetch, &root, dest.path()).is_err());
        assert!(
            !outside.path().join("x.txt").exists(),
            "nothing written outside"
        );
    }

    fn dir_with(files: &[(&str, &[u8])], dirs: &[(&str, Digest)]) -> Vec<u8> {
        pb::Directory {
            files: files
                .iter()
                .map(|(n, data)| pb::FileNode {
                    name: (*n).into(),
                    digest: Some(Digest::of(data).to_proto()),
                    executable: true,
                })
                .collect(),
            directories: dirs
                .iter()
                .map(|(n, d)| pb::DirectoryNode {
                    name: (*n).into(),
                    digest: Some(d.to_proto()),
                })
                .collect(),
        }
        .encode_to_vec()
    }

    #[test]
    fn i8_forged_outputs_outside_the_declared_paths_are_refused() {
        let outputs = vec![PathBuf::from("reports")];
        let mut budget = 1 << 20;
        // A hostile lender returns a git hook and a pytest plugin next to the real report.
        let git = dir_with(&[], &[("hooks", Digest::of(b"h"))]);
        let root = dir_with(
            &[("conftest.py", b"import os")],
            &[(".git", Digest::of(&git))],
        );
        let err = inspect_output_dir(Path::new(""), &root, &outputs, &mut budget).unwrap_err();
        assert!(err.to_string().contains("not a declared output"), "{err}");

        let root = dir_with(&[], &[(".git", Digest::of(&git))]);
        assert!(inspect_output_dir(Path::new(""), &root, &outputs, &mut budget).is_err());
    }

    #[test]
    fn i8_declared_outputs_and_their_ancestors_are_accepted() {
        let outputs = vec![PathBuf::from("build/out")];
        let mut budget = 1 << 20;
        let root = dir_with(&[], &[("build", Digest::of(b"b"))]);
        let level = inspect_output_dir(Path::new(""), &root, &outputs, &mut budget).unwrap();
        assert_eq!(
            level.dirs[0].0,
            PathBuf::from("build"),
            "ancestor needed to reach build/out"
        );
        let build = dir_with(&[("stray.txt", b"x")], &[]);
        assert!(inspect_output_dir(Path::new("build"), &build, &outputs, &mut budget).is_err());
        let out = dir_with(&[("app", b"binary")], &[]);
        let level =
            inspect_output_dir(Path::new("build/out"), &out, &outputs, &mut budget).unwrap();
        assert_eq!(level.files[0].0, PathBuf::from("build/out/app"));
    }

    #[test]
    fn i8_returned_outputs_are_size_capped_before_download() {
        let outputs = vec![PathBuf::from("out")];
        let mut budget = 10;
        let big = dir_with(&[("huge.bin", &[0u8; 64])], &[]);
        let err = inspect_output_dir(Path::new("out"), &big, &outputs, &mut budget).unwrap_err();
        assert!(err.to_string().contains("larger than allowed"), "{err}");
    }

    fn b64url(bytes: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for c in bytes.chunks(3) {
            let n = c
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
            for i in 0..=c.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            }
        }
        out
    }

    fn record(entries: &[(&str, &str)]) -> String {
        let mut s = String::new();
        for (path, data) in entries {
            let d = Digest::of(data.as_bytes());
            s.push_str(&format!("{path},sha256={},{}\n", b64url(&d.hash), d.size));
        }
        s.push_str("pkg-1.0.dist-info/RECORD,,\n");
        s
    }

    const FAKE_KEY: &str = "aws = 'AKIAABCDEFGHIJKLMNOP'\n";

    /// Paths in the tree (blobs) and the paths that will be secret-scanned.
    fn sent_and_scanned(tree: &Tree) -> (Vec<String>, Vec<String>) {
        let mut sent = Vec::new();
        fn walk(blobs: &BTreeMap<Digest, Source>, d: &Digest, at: &str, out: &mut Vec<String>) {
            let Source::Bytes(b) = &blobs[d] else {
                panic!()
            };
            let dir = decode_dir(b).unwrap();
            for f in &dir.files {
                out.push(format!("{at}{}", f.name));
            }
            for s in &dir.directories {
                let d = Digest::from_proto(s.digest.as_ref().unwrap()).unwrap();
                walk(blobs, &d, &format!("{at}{}/", s.name), out);
            }
        }
        walk(&tree.blobs, tree.root.as_ref().unwrap(), "", &mut sent);
        sent.sort();
        let mut scanned: Vec<String> = tree
            .files
            .iter()
            .map(|(_, r)| r.to_string_lossy().into_owned())
            .collect();
        scanned.sort();
        (sent, scanned)
    }

    #[test]
    fn verified_package_files_skip_the_scan_and_name_excludes_but_nothing_else_does() {
        let project = tempfile::tempdir().unwrap();
        write(project.path(), "main.py", "print(1)\n");
        let env = tempfile::tempdir().unwrap();
        let e = env.path();
        write(e, "pkg/__init__.py", FAKE_KEY); // like botocore's example keys
        write(e, "pkg/cacert.pem", "CERTS\n"); // like certifi's CA bundle
        write(e, "pkg/edited.py", FAKE_KEY); // listed, but changed after install
        write(e, "pkg/server.pem", "-----BEGIN PRIVATE KEY-----\n"); // listed, changed
        write(e, "pkg/notes.txt", "hello\n"); // not listed: scanned like any file
        write(e, "pkg/.env", "TOKEN=x\n"); // not listed: excluded by name
        write(e, "INSTALLER", "uv\n");
        write(
            e,
            "pkg-1.0.dist-info/RECORD",
            &record(&[
                ("pkg/__init__.py", FAKE_KEY),
                ("pkg/cacert.pem", "CERTS\n"),
                ("pkg/edited.py", "original\n"),
                ("pkg/server.pem", "original\n"),
                ("../../outside.py", "x"),
            ]),
        );
        let a = Attachment {
            local: e.to_path_buf(),
            path: ".gmc-sdk/env".into(),
            packages: true,
        };
        let tree = build_full(project.path(), &[], &[], std::slice::from_ref(&a)).unwrap();
        let (sent, scanned) = sent_and_scanned(&tree);
        assert_eq!(
            sent,
            [
                ".gmc-sdk/env/INSTALLER",
                ".gmc-sdk/env/pkg-1.0.dist-info/RECORD",
                ".gmc-sdk/env/pkg/__init__.py",
                ".gmc-sdk/env/pkg/cacert.pem",
                ".gmc-sdk/env/pkg/edited.py",
                ".gmc-sdk/env/pkg/notes.txt",
                "main.py",
            ]
        );
        assert_eq!(
            scanned,
            [
                ".gmc-sdk/env/INSTALLER",
                ".gmc-sdk/env/pkg-1.0.dist-info/RECORD",
                ".gmc-sdk/env/pkg/edited.py",
                ".gmc-sdk/env/pkg/notes.txt",
                "main.py",
            ]
        );
        assert!(tree.skipped.iter().any(|p| p.ends_with("pkg/server.pem")));
        assert!(tree.skipped.iter().any(|p| p.ends_with("pkg/.env")));

        // The same folder not marked as packages: everything is checked.
        let plain = Attachment {
            packages: false,
            ..a
        };
        let tree = build_full(project.path(), &[], &[], &[plain]).unwrap();
        let (sent, scanned) = sent_and_scanned(&tree);
        assert!(!sent.iter().any(|p| p.ends_with(".pem")), "{sent:?}");
        assert_eq!(scanned.len(), sent.len());
    }

    #[test]
    fn attachments_are_checked() {
        let project = tempfile::tempdir().unwrap();
        write(project.path(), "main.py", "x\n");
        let other = tempfile::tempdir().unwrap();
        write(other.path(), "secret.pem", "data\n");
        write(other.path(), "dir/a.txt", "a\n");
        let file = other.path().join("secret.pem");
        let at = |local: PathBuf, path: &str| Attachment {
            local,
            path: path.into(),
            packages: false,
        };
        let ok = |a: &[Attachment]| build_full(project.path(), &[], &[], a);

        // A file named explicitly is sent (no name exclude) and scanned.
        let tree = ok(&[at(file.clone(), ".gmc-sdk/files/1/secret.pem")]).unwrap();
        assert!(
            tree.files
                .iter()
                .any(|(_, r)| r == Path::new(".gmc-sdk/files/1/secret.pem"))
        );
        for bad in [
            at(file.clone(), "secret.pem"),
            at(file.clone(), ".gmc-sdk"),
            at(file.clone(), ".gmc-sdk/../x"),
            at(file.clone(), "/.gmc-sdk/x"),
            at(PathBuf::from("relative/file"), ".gmc-sdk/x"),
            at(other.path().join("missing"), ".gmc-sdk/x"),
        ] {
            assert!(ok(std::slice::from_ref(&bad)).is_err(), "{bad:?}");
        }
        // Two things at one place, or a file where a folder is.
        assert!(
            ok(&[
                at(file.clone(), ".gmc-sdk/x"),
                at(file.clone(), ".gmc-sdk/x")
            ])
            .is_err()
        );
        assert!(
            ok(&[
                at(file.clone(), ".gmc-sdk/d"),
                at(other.path().join("dir"), ".gmc-sdk/d")
            ])
            .is_err()
        );
        assert!(
            ok(&[at(file.clone(), ".gmc-sdk/f/a.txt")])
                .and_then(|_| ok(&[
                    at(other.path().join("dir"), ".gmc-sdk/f"),
                    at(file.clone(), ".gmc-sdk/f/a.txt")
                ]))
                .is_err()
        );
        // A packages attachment must be a folder; a symlink is not followed.
        assert!(
            ok(&[Attachment {
                packages: true,
                ..at(file.clone(), ".gmc-sdk/env")
            }])
            .is_err()
        );
        #[cfg(unix)]
        {
            let link = other.path().join("link");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            assert!(ok(&[at(link, ".gmc-sdk/l")]).is_err());
        }
        // The project may not have its own .gmc-sdk when attachments are used.
        write(project.path(), ".gmc-sdk/mine", "x\n");
        assert!(ok(&[at(file, ".gmc-sdk/x")]).is_err());
    }

    #[test]
    fn record_lines_are_parsed_strictly() {
        let h = b64url(&[7u8; 32]);
        let (p, hash, size) = record_line(&format!("a/b.py,sha256={h},12")).unwrap();
        assert_eq!(
            (p, hash, size),
            (PathBuf::from("a/b.py"), [7u8; 32], Some(12))
        );
        let (p, _, size) = record_line(&format!("\"a,\"\"b\"\".py\",sha256={h},")).unwrap();
        assert_eq!((p, size), (PathBuf::from("a,\"b\".py"), None));
        for bad in [
            format!("../x.py,sha256={h},1"),
            format!("/abs.py,sha256={h},1"),
            format!("a.py,md5={h},1"),
            "a.py,sha256=AAAA,1".to_string(),
            "a.py,,".to_string(),
            "a.py".to_string(),
        ] {
            assert!(record_line(&bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn a_rewritten_file_is_hashed_again_even_with_its_old_size_and_time() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("a.txt");
        std::fs::write(&f, "aaaa").unwrap();
        let first = digest_file(&f, &std::fs::metadata(&f).unwrap()).unwrap();
        assert_eq!(first, Digest::of(b"aaaa"));
        let mtime = std::fs::metadata(&f).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&f, "bbbb").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&f)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        let again = digest_file(&f, &std::fs::metadata(&f).unwrap()).unwrap();
        assert_eq!(again, Digest::of(b"bbbb"));
    }
}
