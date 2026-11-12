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

/// Packs `root` into a content-addressed tree.
pub fn build(root: &Path, extra_excludes: &[String]) -> Result<Tree> {
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
        let data = std::fs::read(entry.path())?;
        let d = Digest::of(&data);
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
fn decode_dir(bytes: &[u8]) -> Result<pb::Directory> {
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
    std::fs::create_dir_all(dest)?;
    let mut total = 0u64;
    let mut count = 0usize;
    walk_out(
        &mut |d| store.get(ns, d),
        root,
        dest,
        0,
        &mut total,
        &mut count,
    )?;
    Ok(total)
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
    walk_out(fetch, root, dest, 0, &mut total, &mut count)?;
    Ok(total)
}

fn walk_out(
    fetch: &mut dyn FnMut(&Digest) -> Result<Vec<u8>>,
    dir_digest: &Digest,
    dest: &Path,
    depth: usize,
    total: &mut u64,
    count: &mut usize,
) -> Result<()> {
    ensure!(depth <= MAX_DEPTH, "directory tree too deep");
    let dir = decode_dir(&fetch(dir_digest)?)?;
    for f in &dir.files {
        let d = Digest::from_proto(f.digest.as_ref().context("file without digest")?)?;
        *total = total.saturating_add(d.size);
        *count += 1;
        ensure!(
            *total <= MAX_TREE_BYTES && *count <= MAX_ENTRIES,
            "tree too large"
        );
        let data = fetch(&d)?;
        let path = dest.join(&f.name);
        // Never follow or replace a symlink planted at the destination.
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            bail!("refusing to write through a symlink at {}", path.display());
        }
        std::fs::write(&path, &data)?;
        set_executable(&path, f.executable)?;
    }
    for sub in &dir.directories {
        let d = Digest::from_proto(sub.digest.as_ref().context("dir without digest")?)?;
        let path = dest.join(&sub.name);
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            bail!("refusing to write through a symlink at {}", path.display());
        }
        std::fs::create_dir_all(&path)?;
        walk_out(fetch, &d, &path, depth + 1, total, count)?;
    }
    Ok(())
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
}
