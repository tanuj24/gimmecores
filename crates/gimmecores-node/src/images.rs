//! Container images a borrower sends (docs/design/container-images.md).
//!
//! An image is its config (a JSON document) and its layers (tar files the config lists by
//! SHA-256 as `rootfs.diff_ids`, bottom first). Layers travel uncompressed, as ordinary blobs
//! under a grant, so a blob's digest is the layer's diff id and the lender checks everything by
//! hashing alone. The lender identifies an image by its config's SHA-256; Docker's own id for
//! it differs between its image stores (the config's digest in the classic store, a manifest's
//! in the containerd store), so each side keeps what its own Docker says.
//!
//! The lender loads an image under a name of its own
//! (`gimmecores.local/<lender>/from-<borrower>:<config>`):
//! `docker load` silently re-points a tag that already exists, so the borrower's names are never
//! used. A loaded image belongs to the borrower that sent it; other borrowers are told it is not
//! there. It is removed (its tag) when the borrower's last grant ends.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use gimmecores_core::PeerKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::process::Command;

/// At most this many layers in an image (Docker's own limit on overlay2 is 125).
pub const MAX_LAYERS: usize = 128;
/// An image config larger than this is refused (real ones are a few KiB).
pub const MAX_CONFIG_BYTES: u64 = 4 << 20;
/// Where every tag GimmeCores adds lives (names under it are refused to tasks).
pub const LOCAL_REGISTRY: &str = "gimmecores.local/";

/// The start of the tags lender `lender` gives the images it loads: each service on a machine
/// keeps to its own, and sweeps only its own.
pub fn sent_prefix(lender: &PeerKey) -> String {
    format!("{LOCAL_REGISTRY}{}/from-", lender.to_hex())
}

/// `sha256:` and 64 lowercase hex digits: an image id or a layer's diff id.
pub fn is_sha256_id(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|h| {
        h.len() == 64
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// The hash of a `sha256:` id.
pub fn id_hash(id: &str) -> Result<[u8; 32]> {
    ensure!(is_sha256_id(id), "not an image or layer id: {id:?}");
    let mut out = [0u8; 32];
    hex::decode_to_slice(&id[7..], &mut out)?;
    Ok(out)
}

pub fn id_of_hash(hash: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(hash))
}

pub fn sha256_id(data: &[u8]) -> String {
    id_of_hash(&Sha256::digest(data).into())
}

/// The tag `lender` gives the image with config `config` loaded for `borrower`. Whole keys and
/// digests, so no two images can be made to share one.
pub fn tag_for(lender: &PeerKey, borrower: &PeerKey, config: &str) -> String {
    format!(
        "{}{}:{}",
        sent_prefix(lender),
        borrower.to_hex(),
        config.trim_start_matches("sha256:")
    )
}

/// The borrower a tag of `lender`'s was for, if it is one.
pub fn borrower_of_tag(lender: &PeerKey, tag: &str) -> Option<PeerKey> {
    let rest = tag.strip_prefix(&sent_prefix(lender))?;
    let (hex_key, config) = rest.split_once(':')?;
    let mut k = [0u8; 32];
    hex::decode_to_slice(hex_key, &mut k).ok()?;
    (config.len() == 64).then_some(PeerKey(k))
}

/// What the lender checks in an image's config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageConfig {
    pub os: String,
    pub architecture: String,
    pub diff_ids: Vec<String>,
}

/// Reads the parts of an image config the lender relies on, refusing anything unusual.
pub fn parse_config(bytes: &[u8]) -> Result<ImageConfig> {
    ensure!(
        bytes.len() as u64 <= MAX_CONFIG_BYTES,
        "the image's config is too large"
    );
    #[derive(Deserialize)]
    struct RootFs {
        #[serde(rename = "type")]
        kind: String,
        diff_ids: Vec<String>,
    }
    #[derive(Deserialize)]
    struct Config {
        os: String,
        architecture: String,
        rootfs: RootFs,
    }
    let c: Config = serde_json::from_slice(bytes).context("the image's config is not valid")?;
    ensure!(c.rootfs.kind == "layers", "the image's config is not valid");
    ensure!(
        !c.rootfs.diff_ids.is_empty() && c.rootfs.diff_ids.len() <= MAX_LAYERS,
        "an image has 1 to {MAX_LAYERS} layers"
    );
    for d in &c.rootfs.diff_ids {
        ensure!(is_sha256_id(d), "the image's config names a layer {d:?}");
    }
    Ok(ImageConfig {
        os: c.os,
        architecture: c.architecture,
        diff_ids: c.rootfs.diff_ids,
    })
}

/// Docker's name for a processor (`docker info`'s `Architecture`) as images name it.
pub fn image_architecture(docker_arch: &str) -> String {
    match docker_arch {
        "x86_64" | "amd64" => "amd64",
        "aarch64" | "arm64" => "arm64",
        "armv7l" | "arm" => "arm",
        other => other,
    }
    .to_string()
}

/// An image the lender loaded for a borrower (kept in `images.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Loaded {
    /// The borrower's key, hex.
    pub borrower: String,
    /// The ids the borrower's Docker gave it (how the borrower asks for it again).
    pub keys: Vec<String>,
    /// Its config's SHA-256: what the lender checked.
    pub config: String,
    /// What this lender's Docker calls it.
    pub docker_id: String,
    pub tag: String,
    pub diff_ids: Vec<String>,
    /// Each layer's size, uncompressed (as `diff_ids`).
    pub sizes: Vec<u64>,
    pub config_bytes: u64,
    pub loaded_at: u64,
    pub used_at: u64,
}

/// The images loaded for borrowers, saved after every change.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Registry {
    pub images: Vec<Loaded>,
}

impl Registry {
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        crate::fsutil::write_private(path, &serde_json::to_vec_pretty(self)?)
    }

    pub fn of<'a>(&'a self, borrower: &PeerKey) -> impl Iterator<Item = &'a Loaded> + use<'a> {
        let hex = borrower.to_hex();
        self.images.iter().filter(move |l| l.borrower == hex)
    }

    /// The image `borrower` names `key`.
    pub fn find(&self, borrower: &PeerKey, key: &str) -> Option<&Loaded> {
        self.of(borrower).find(|l| l.keys.iter().any(|k| k == key))
    }

    /// Bytes held for `borrower`: each distinct layer once (Docker stores a layer its images
    /// share once), and each config.
    pub fn held(&self, borrower: &PeerKey) -> u64 {
        held_by(self.of(borrower))
    }

    /// The size of layer `diff_id` as recorded for any of `borrower`'s images.
    pub fn layer_size(&self, borrower: &PeerKey, diff_id: &str) -> Option<u64> {
        self.of(borrower).find_map(|l| {
            l.diff_ids
                .iter()
                .position(|d| d == diff_id)
                .and_then(|i| l.sizes.get(i).copied())
        })
    }

    /// What this lender's Docker calls the images loaded for other borrowers and not for
    /// `borrower`: a task of `borrower` naming one is told it is not there.
    pub fn others(&self, borrower: &PeerKey) -> Vec<String> {
        let mine: std::collections::BTreeSet<&str> =
            self.of(borrower).map(|l| l.docker_id.as_str()).collect();
        let hex = borrower.to_hex();
        let mut v: Vec<String> = self
            .images
            .iter()
            .filter(|l| l.borrower != hex && !mine.contains(l.docker_id.as_str()))
            .map(|l| l.docker_id.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    }
}

/// Bytes `images` take together: each distinct layer once, and each config.
pub fn held_by<'a>(images: impl IntoIterator<Item = &'a Loaded>) -> u64 {
    let mut layers = BTreeMap::new();
    let mut configs = BTreeMap::new();
    for l in images {
        configs.insert(l.config.as_str(), l.config_bytes);
        for (d, size) in l.diff_ids.iter().zip(&l.sizes) {
            layers.insert(d.as_str(), *size);
        }
    }
    layers
        .values()
        .chain(configs.values())
        .fold(0u64, |a, b| a.saturating_add(*b))
}

/// How many of `diff_ids`, from the bottom, Docker already has from an image loaded for this
/// borrower (`loaded`): the archive may leave those out (Docker reuses a layer only with the
/// same layers beneath it). A layer whose size is not known ends the run: the archive's
/// manifest must give every layer's size.
pub fn shared_prefix<'a>(
    diff_ids: &[String],
    loaded: impl IntoIterator<Item = &'a Loaded>,
) -> usize {
    loaded
        .into_iter()
        .map(|l| {
            diff_ids
                .iter()
                .zip(l.diff_ids.iter().zip(&l.sizes))
                .take_while(|(a, (b, size))| a == b && **size > 0)
                .count()
        })
        .max()
        .unwrap_or(0)
}

/// One layer for the archive: its diff id, where its blob is, and its size.
#[derive(Clone, Debug)]
pub struct LayerFile {
    pub diff_id: String,
    pub path: PathBuf,
    pub size: u64,
}

/// Writes the archive `docker load` reads, in both layouts Docker knows: OCI (`index.json`,
/// read by Docker's containerd image store) and the classic `manifest.json`. Both name only
/// `tag`. It holds the config, a manifest written here (giving every layer's size, `sizes`),
/// and each layer in `files` once; the layers not in `files` must already be in Docker, beneath
/// (`shared_prefix`). Returns the writer and the manifest's digest (the image's id in the
/// containerd store).
pub fn write_archive<W: Write>(
    w: W,
    config: &[u8],
    diff_ids: &[String],
    sizes: &[u64],
    files: &[LayerFile],
    tag: &str,
) -> Result<(W, String)> {
    ensure!(
        diff_ids.len() == sizes.len(),
        "every layer's size is needed"
    );
    let config_id = sha256_id(config);
    let blob = |d: &str| format!("blobs/sha256/{}", d.trim_start_matches("sha256:"));
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_id,
            "size": config.len(),
        },
        "layers": diff_ids.iter().zip(sizes).map(|(d, s)| serde_json::json!({
            "mediaType": "application/vnd.oci.image.layer.v1.tar",
            "digest": d,
            "size": s,
        })).collect::<Vec<_>>(),
    }))?;
    let manifest_id = sha256_id(&manifest);
    let index = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": manifest_id,
            "size": manifest.len(),
            "annotations": {
                "io.containerd.image.name": tag,
                "org.opencontainers.image.ref.name": tag.rsplit(':').next().unwrap_or(tag),
            },
        }],
    }))?;
    let classic = serde_json::to_vec(&serde_json::json!([{
        "Config": blob(&config_id),
        "RepoTags": [tag],
        "Layers": diff_ids.iter().map(|d| blob(d)).collect::<Vec<_>>(),
    }]))?;
    let mut b = tar::Builder::new(w);
    let header = |size: u64| {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_mode(0o644);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(0);
        h.set_size(size);
        h
    };
    let layout = br#"{"imageLayoutVersion":"1.0.0"}"#;
    b.append_data(&mut header(layout.len() as u64), "oci-layout", &layout[..])?;
    b.append_data(
        &mut header(index.len() as u64),
        "index.json",
        index.as_slice(),
    )?;
    b.append_data(
        &mut header(classic.len() as u64),
        "manifest.json",
        classic.as_slice(),
    )?;
    b.append_data(
        &mut header(manifest.len() as u64),
        blob(&manifest_id),
        manifest.as_slice(),
    )?;
    b.append_data(&mut header(config.len() as u64), blob(&config_id), config)?;
    // Each layer once, even when the image lists it twice (empty layers often repeat).
    let mut written = std::collections::BTreeSet::new();
    for l in files {
        ensure!(
            diff_ids.contains(&l.diff_id),
            "{} is not a layer of the image",
            l.diff_id
        );
        if !written.insert(l.diff_id.as_str()) {
            continue;
        }
        let f = std::fs::File::open(&l.path)
            .with_context(|| format!("layer {} is missing", l.diff_id))?;
        ensure!(
            f.metadata()?.len() == l.size,
            "layer {} has the wrong size",
            l.diff_id
        );
        b.append_data(&mut header(l.size), blob(&l.diff_id), f)?;
    }
    Ok((b.into_inner()?, manifest_id))
}

// ------------------------------------------------------------------ Docker, on the lender

/// Docker on the lender, for images.
#[derive(Clone, Debug)]
pub struct DockerImages {
    pub docker: String,
}

impl Default for DockerImages {
    fn default() -> Self {
        Self {
            docker: crate::exec::locate_docker(),
        }
    }
}

/// What Docker says when an image is not there (its wording differs between versions).
fn no_such_image(stderr: &str) -> bool {
    let e = stderr.to_ascii_lowercase();
    e.contains("no such image") || e.contains("no such object") || e.contains("not found")
}

impl DockerImages {
    async fn output(&self, args: &[&str], secs: u64) -> Result<std::process::Output> {
        let run = Command::new(&self.docker)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output();
        tokio::time::timeout(Duration::from_secs(secs), run)
            .await
            .context("Docker did not answer")?
            .context("running docker")
    }

    /// The images this Docker runs (`linux`, and `amd64` or `arm64`).
    pub async fn platform(&self) -> Result<(String, String)> {
        let o = self
            .output(&["info", "--format", "{{.OSType}} {{.Architecture}}"], 10)
            .await?;
        ensure!(o.status.success(), "Docker is not running");
        let s = String::from_utf8_lossy(&o.stdout);
        let mut it = s.split_whitespace();
        let os = it.next().context("Docker did not say its OS")?.to_string();
        let arch = image_architecture(it.next().context("Docker did not say its processor")?);
        Ok((os, arch))
    }

    /// The id `reference` points to here: `Ok(None)` only when Docker says it is not there,
    /// an error when Docker did not answer (so nothing is forgotten because Docker was busy).
    pub async fn lookup(&self, reference: &str) -> Result<Option<String>> {
        let o = self
            .output(
                &["image", "inspect", "--format", "{{.Id}}", "--", reference],
                30,
            )
            .await?;
        if !o.status.success() {
            let err = String::from_utf8_lossy(&o.stderr);
            if no_such_image(&err) {
                return Ok(None);
            }
            bail!(
                "Docker could not say whether it has {reference}: {}",
                err.trim()
            );
        }
        let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
        ensure!(is_sha256_id(&id), "Docker gave {id:?} for {reference}");
        Ok(Some(id))
    }

    /// The diff ids of `reference`'s layers.
    async fn layers_of(&self, reference: &str) -> Result<Vec<String>> {
        let o = self
            .output(
                &[
                    "image",
                    "inspect",
                    "--format",
                    "{{json .RootFS.Layers}}",
                    "--",
                    reference,
                ],
                30,
            )
            .await?;
        ensure!(o.status.success(), "Docker could not describe {reference}");
        Ok(serde_json::from_slice(o.stdout.trim_ascii())?)
    }

    /// Loads an archive from [`write_archive`], streamed to `docker load`, and checks the tag
    /// then names exactly that image. Returns Docker's id for it. Dropping the future stops
    /// `docker load` (a revoke during a long load).
    pub async fn load(
        &self,
        config: Vec<u8>,
        diff_ids: Vec<String>,
        sizes: Vec<u64>,
        files: Vec<LayerFile>,
        tag: &str,
    ) -> Result<String> {
        let mut child = Command::new(&self.docker)
            .args(["load", "--quiet"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("starting docker load")?;
        let stdin = child.stdin.take().context("docker load's input")?;
        #[cfg(unix)]
        let pipe = std::fs::File::from(stdin.into_owned_fd()?);
        #[cfg(windows)]
        let pipe = std::fs::File::from(stdin.into_owned_handle()?);
        let config_id = sha256_id(&config);
        let (tag2, want) = (tag.to_string(), diff_ids.clone());
        // Written on its own thread; ends (broken pipe) if `docker load` is stopped.
        let writer = tokio::task::spawn_blocking(move || -> Result<String> {
            let (mut w, manifest) = write_archive(pipe, &config, &diff_ids, &sizes, &files, &tag2)?;
            w.flush()?;
            Ok(manifest)
        });
        let out = child.wait_with_output().await?;
        let wrote = writer.await?;
        let err = String::from_utf8_lossy(&out.stderr);
        // The containerd store can report a broken unpack after "Loaded image".
        if !out.status.success() || err.to_ascii_lowercase().contains("error") {
            bail!("Docker could not load the image: {}", err.trim());
        }
        let manifest = wrote?;
        let id = self
            .lookup(tag)
            .await?
            .context("Docker did not keep the image")?;
        ensure!(
            id == config_id || id == manifest,
            "Docker named another image {tag} ({id})"
        );
        ensure!(
            self.layers_of(tag).await? == want,
            "Docker loaded other layers than the image sent"
        );
        Ok(id)
    }

    /// The tags here that start with `prefix` (a lender's [`sent_prefix`]).
    pub async fn tags_with(&self, prefix: &str) -> Result<Vec<String>> {
        let o = self
            .output(&["images", "--format", "{{.Repository}}:{{.Tag}}"], 30)
            .await?;
        ensure!(
            o.status.success(),
            "Docker could not list its images: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        );
        Ok(String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter(|l| l.starts_with(prefix))
            .map(String::from)
            .collect())
    }

    /// Removes a tag the lender added (Docker removes the image with it unless another tag or
    /// a container still uses it). Never by id, never forced. Already gone is fine.
    pub async fn untag(&self, tag: &str) -> Result<()> {
        ensure!(
            tag.starts_with(LOCAL_REGISTRY) && tag.contains("/from-"),
            "not a tag GimmeCores added"
        );
        let o = self.output(&["image", "rm", "--", tag], 60).await?;
        if !o.status.success() {
            let err = String::from_utf8_lossy(&o.stderr);
            if !no_such_image(&err) {
                bail!("could not remove {tag}: {}", err.trim());
            }
        }
        Ok(())
    }
}

// ------------------------------------------------------------------ Docker, on the borrower

/// An image on the borrower's own Docker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalImage {
    /// What the borrower's Docker calls it.
    pub id: String,
    pub diff_ids: Vec<String>,
    pub os: String,
    pub architecture: String,
    /// Docker's estimate of the whole image, uncompressed; 0 when it has none worth sending.
    pub size: u64,
}

/// Reads `reference` from the borrower's Docker; `None` when it is not there (or Docker is not
/// running), in which case the task names the image and the lender must have it.
pub async fn inspect_local(docker: &str, reference: &str) -> Option<LocalImage> {
    let o = Command::new(docker)
        .args([
            "image",
            "inspect",
            "--format",
            "{{json .Id}} {{json .RootFS.Layers}} {{json .Os}} {{json .Architecture}} {{json .Size}}",
            "--",
            reference,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .ok()?;
    if !o.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&o.stdout);
    let mut parts = s.split_whitespace();
    let id: String = serde_json::from_str(parts.next()?).ok()?;
    let diff_ids: Vec<String> = serde_json::from_str(parts.next()?).ok()?;
    let os: String = serde_json::from_str(parts.next()?).ok()?;
    let architecture: String = serde_json::from_str(parts.next()?).ok()?;
    let size: u64 = parts
        .next()
        .and_then(|p| serde_json::from_str(p).ok())
        .unwrap_or(0);
    // The containerd image store counts the compressed download and the unpacked copy (up to
    // twice the layers): no estimate then, and the lender checks the exact size before loading.
    let size = if containerd_store(docker).await {
        0
    } else {
        size
    };
    (is_sha256_id(&id) && !diff_ids.is_empty() && diff_ids.iter().all(|d| is_sha256_id(d)))
        .then_some(LocalImage {
            id,
            diff_ids,
            os,
            architecture,
            size,
        })
}

/// Whether this Docker keeps images in containerd (Docker 29's default for new installs).
async fn containerd_store(docker: &str) -> bool {
    Command::new(docker)
        .args(["info", "--format", "{{json .DriverStatus}}"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("io.containerd.snapshotter"))
}

/// What [`export`] produced: the config, and each layer from the asked index on, uncompressed
/// and checked against the config (a layer the image lists twice appears twice).
#[derive(Debug)]
pub struct Exported {
    pub config: Vec<u8>,
    pub layers: Vec<LayerFile>,
}

/// Exports `image` with `docker save` into `dir` and extracts its config and the layers from
/// `from` on, decompressing them (Docker's containerd image store keeps them gzipped) and
/// checking each against the config's diff ids.
pub async fn export(docker: &str, image: &LocalImage, from: usize, dir: &Path) -> Result<Exported> {
    let archive = dir.join("image.tar");
    let save = |platform: bool| {
        let mut c = Command::new(docker);
        c.arg("save");
        // Only this computer's variant of a multi-platform image (Docker 28 and later).
        if platform {
            c.arg("--platform")
                .arg(format!("{}/{}", image.os, image.architecture));
        }
        c.arg("--output")
            .arg(&archive)
            .arg(&image.id)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output()
    };
    let mut o = save(true).await.context("running docker save")?;
    if !o.status.success() && String::from_utf8_lossy(&o.stderr).contains("--platform") {
        o = save(false).await.context("running docker save")?;
    }
    ensure!(
        o.status.success(),
        "docker save: {}",
        String::from_utf8_lossy(&o.stderr).trim()
    );
    let (image, dir) = (image.clone(), dir.to_path_buf());
    tokio::task::spawn_blocking(move || extract(&archive, &image, from, &dir)).await?
}

/// Entries of a `docker save` archive: regular files and the links older Dockers use for a
/// layer that appears twice.
fn index(archive: &Path) -> Result<BTreeMap<String, Option<String>>> {
    let mut entries = BTreeMap::new();
    let mut ar = tar::Archive::new(std::fs::File::open(archive)?);
    for e in ar.entries()? {
        let e = e?;
        let path = e
            .path()?
            .to_string_lossy()
            .trim_start_matches("./")
            .to_string();
        match e.header().entry_type() {
            tar::EntryType::Regular => {
                entries.insert(path, None);
            }
            tar::EntryType::Symlink => {
                let target = e
                    .link_name()?
                    .map(|l| l.to_string_lossy().into_owned())
                    .unwrap_or_default();
                // Relative to the link's folder.
                let base = Path::new(&path).parent().unwrap_or(Path::new(""));
                let mut joined = PathBuf::new();
                for c in base.join(&target).components() {
                    match c {
                        std::path::Component::ParentDir => {
                            joined.pop();
                        }
                        std::path::Component::Normal(n) => joined.push(n),
                        _ => {}
                    }
                }
                entries.insert(path, Some(joined.to_string_lossy().into_owned()));
            }
            _ => {}
        }
    }
    Ok(entries)
}

fn extract(archive: &Path, image: &LocalImage, from: usize, dir: &Path) -> Result<Exported> {
    let entries = index(archive)?;
    let resolve = |p: &str| -> String {
        let mut p = p.trim_start_matches("./").to_string();
        for _ in 0..8 {
            match entries.get(&p) {
                Some(Some(t)) => p = t.clone(),
                _ => break,
            }
        }
        p
    };
    #[derive(Deserialize)]
    struct Manifest {
        #[serde(rename = "Config")]
        config: String,
        #[serde(rename = "Layers")]
        layers: Vec<String>,
    }
    let read = |want: &str, limit: u64| -> Result<Vec<u8>> {
        let mut ar = tar::Archive::new(std::fs::File::open(archive)?);
        for e in ar.entries()? {
            let e = e?;
            if e.path()?.to_string_lossy().trim_start_matches("./") == want {
                ensure!(e.size() <= limit, "{want} is too large");
                let mut v = Vec::new();
                e.take(limit).read_to_end(&mut v)?;
                return Ok(v);
            }
        }
        bail!("{want} is missing from docker save's archive")
    };
    let manifests: Vec<Manifest> = serde_json::from_slice(&read("manifest.json", 16 << 20)?)
        .context("docker save's manifest")?;
    // The entry whose config lists the layers this computer's Docker reported.
    let mut found = None;
    for m in manifests {
        let config = read(&resolve(&m.config), MAX_CONFIG_BYTES)?;
        let parsed = parse_config(&config)?;
        if parsed.diff_ids == image.diff_ids && m.layers.len() == parsed.diff_ids.len() {
            found = Some((m, config, parsed));
            break;
        }
    }
    let (m, config, parsed) = found.context("docker save's archive does not hold the image")?;
    // Which archive entry holds which layer, from `from` on.
    let mut want: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, p) in m.layers.iter().enumerate().skip(from) {
        want.entry(resolve(p)).or_default().push(i);
    }
    let mut layers: Vec<Option<LayerFile>> = vec![None; parsed.diff_ids.len()];
    let mut ar = tar::Archive::new(std::fs::File::open(archive)?);
    for e in ar.entries()? {
        let e = e?;
        let path = e
            .path()?
            .to_string_lossy()
            .trim_start_matches("./")
            .to_string();
        let Some(idx) = want.get(&path) else {
            continue;
        };
        let diff_id = &parsed.diff_ids[idx[0]];
        let dest = dir.join(diff_id.trim_start_matches("sha256:"));
        let size = decompress_checked(e, &dest, diff_id)?;
        for i in idx {
            layers[*i] = Some(LayerFile {
                diff_id: parsed.diff_ids[*i].clone(),
                path: dest.clone(),
                size,
            });
        }
    }
    let layers: Vec<LayerFile> = layers
        .into_iter()
        .skip(from)
        .collect::<Option<_>>()
        .context("docker save's archive is missing a layer")?;
    let _ = std::fs::remove_file(archive);
    Ok(Exported { config, layers })
}

/// Writes `r` (a layer tar, maybe gzipped) to `dest` uncompressed, checking it is `diff_id`.
fn decompress_checked(mut r: impl Read, dest: &Path, diff_id: &str) -> Result<u64> {
    let mut head = [0u8; 4];
    let mut got = 0;
    while got < head.len() {
        let n = r.read(&mut head[got..])?;
        if n == 0 {
            break;
        }
        got += n;
    }
    let chained = std::io::Cursor::new(head[..got].to_vec()).chain(r);
    let mut reader: Box<dyn Read> = if head[..got].starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::read::GzDecoder::new(chained))
    } else if head[..got].starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        bail!("a layer is zstd-compressed, which GimmeCores cannot send yet")
    } else {
        Box::new(chained)
    };
    let mut out = std::fs::File::create(dest)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut size = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n])?;
        size += n as u64;
    }
    out.flush()?;
    ensure!(
        id_of_hash(&hasher.finalize().into()) == diff_id,
        "a layer does not match the image's config"
    );
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(data: &[u8]) -> String {
        sha256_id(data)
    }

    fn config(diff_ids: &[String]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "architecture": "arm64", "os": "linux",
            "config": {"Env": ["PATH=/bin"]},
            "rootfs": {"type": "layers", "diff_ids": diff_ids},
        }))
        .unwrap()
    }

    #[test]
    fn ids_are_checked() {
        assert!(is_sha256_id(&format!("sha256:{}", "a".repeat(64))));
        for bad in [
            "sha256:".to_string(),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}", "a".repeat(63)),
            format!("sha512:{}", "a".repeat(64)),
            format!("sha256:{}/", "a".repeat(64)),
        ] {
            assert!(!is_sha256_id(&bad), "{bad}");
        }
    }

    #[test]
    fn configs_are_read_strictly() {
        let l = vec![sha(b"one"), sha(b"two")];
        let c = parse_config(&config(&l)).unwrap();
        assert_eq!(c.diff_ids, l);
        assert_eq!((c.os.as_str(), c.architecture.as_str()), ("linux", "arm64"));
        for bad in [
            serde_json::json!({"os": "linux", "architecture": "arm64",
                "rootfs": {"type": "layers", "diff_ids": []}}),
            serde_json::json!({"os": "linux", "architecture": "arm64",
                "rootfs": {"type": "other", "diff_ids": [sha(b"x")]}}),
            serde_json::json!({"os": "linux", "architecture": "arm64",
                "rootfs": {"type": "layers", "diff_ids": ["../../etc"]}}),
            serde_json::json!({"os": "linux", "rootfs": {"type": "layers", "diff_ids": [sha(b"x")]}}),
        ] {
            assert!(
                parse_config(&serde_json::to_vec(&bad).unwrap()).is_err(),
                "{bad}"
            );
        }
        let many: Vec<String> = (0..=MAX_LAYERS).map(|i| sha(&[i as u8, 1])).collect();
        assert!(parse_config(&config(&many)).is_err());
    }

    fn loaded(borrower: &PeerKey, id: &str, diff_ids: &[String], size: u64) -> Loaded {
        Loaded {
            borrower: borrower.to_hex(),
            keys: vec![id.into()],
            config: format!("{id}-config"),
            docker_id: id.into(),
            tag: tag_for(&PeerKey([9; 32]), borrower, id),
            diff_ids: diff_ids.to_vec(),
            sizes: vec![size; diff_ids.len()],
            config_bytes: 1,
            loaded_at: 1,
            used_at: 1,
        }
    }

    #[test]
    fn only_the_layers_above_a_shared_base_are_needed() {
        let b = PeerKey([7; 32]);
        let base = [sha(b"base"), sha(b"deps")];
        let v1 = [base[0].clone(), base[1].clone(), sha(b"app v1")];
        let v2 = [base[0].clone(), base[1].clone(), sha(b"app v2")];
        let other = [sha(b"other base"), base[1].clone()];
        let reg = [loaded(&b, "sha256:1", &v1, 10)];
        assert_eq!(shared_prefix(&v2, &reg), 2, "only the changed top layer");
        assert_eq!(shared_prefix(&v1, &reg), 3);
        assert_eq!(
            shared_prefix(&other, &reg),
            0,
            "the same layer on another base is new"
        );
        assert_eq!(shared_prefix(&v2, &[]), 0);
        // A layer of unknown size cannot be left out: the manifest needs its size.
        let mut unknown = loaded(&b, "sha256:2", &v1, 10);
        unknown.sizes[1] = 0;
        assert_eq!(shared_prefix(&v2, &[unknown]), 1);
    }

    #[test]
    fn a_borrowers_images_are_its_own_and_counted_once() {
        let (a, b) = (PeerKey([1; 32]), PeerKey([2; 32]));
        let id = |n: u8| format!("sha256:{}", hex::encode([n; 32]));
        let mut r = Registry::default();
        r.images.push(loaded(&a, &id(1), &[sha(b"l")], 5));
        r.images.push(loaded(&a, &id(2), &[sha(b"m")], 7));
        r.images.push(loaded(&b, &id(2), &[sha(b"m")], 7));
        r.images.push(loaded(&b, &id(3), &[sha(b"n")], 9));
        // Two layers and two configs (1 byte each).
        assert_eq!(r.held(&a), 5 + 7 + 2);
        // A layer two images share is counted once.
        r.images
            .push(loaded(&a, &id(4), &[sha(b"l"), sha(b"top")], 5));
        assert_eq!(r.held(&a), 5 + 7 + 5 + 3);
        assert_eq!(r.layer_size(&a, &sha(b"top")), Some(5));
        r.images.pop();
        assert_eq!(r.others(&a), [id(3)], "the image both sent is A's too");
        assert_eq!(r.others(&b), [id(1)]);
        assert!(r.find(&a, &id(3)).is_none());
        assert!(r.find(&a, &id(1)).is_some());
        let tag = tag_for(&PeerKey([9; 32]), &a, &id(1));
        assert_eq!(
            tag,
            format!(
                "gimmecores.local/{}/from-{}:{}",
                "09".repeat(32),
                "01".repeat(32),
                "01".repeat(32)
            ),
            "whole keys and digest"
        );
        assert_eq!(borrower_of_tag(&PeerKey([9; 32]), &tag), Some(a));
        assert_eq!(
            borrower_of_tag(&PeerKey([8; 32]), &tag),
            None,
            "another lender's"
        );
        assert_eq!(
            borrower_of_tag(&PeerKey([9; 32]), "gimmecores.local/x:y"),
            None
        );
    }

    fn layer_files(dir: &Path, data: &[Vec<u8>]) -> (Vec<String>, Vec<u64>, Vec<LayerFile>) {
        let diff_ids: Vec<String> = data.iter().map(|d| sha(d)).collect();
        let files = data
            .iter()
            .zip(&diff_ids)
            .map(|(d, id)| {
                let p = dir.join(&id[7..]);
                std::fs::write(&p, d).unwrap();
                LayerFile {
                    diff_id: id.clone(),
                    path: p,
                    size: d.len() as u64,
                }
            })
            .collect();
        let sizes = data.iter().map(|d| d.len() as u64).collect();
        (diff_ids, sizes, files)
    }

    fn entries(tar: &[u8]) -> BTreeMap<String, Vec<u8>> {
        let mut ar = tar::Archive::new(tar);
        let mut out = BTreeMap::new();
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            let n = e.path().unwrap().to_string_lossy().into_owned();
            let mut v = Vec::new();
            e.read_to_end(&mut v).unwrap();
            assert!(out.insert(n.clone(), v).is_none(), "{n} twice");
        }
        out
    }

    #[test]
    fn the_archive_names_only_the_lenders_tag_and_holds_what_is_needed() {
        let dir = tempfile::tempdir().unwrap();
        let (diff_ids, sizes, files) =
            layer_files(dir.path(), &[b"layer zero".to_vec(), b"layer one".to_vec()]);
        let cfg = config(&diff_ids);
        let tag = "gimmecores.local/from-x:y";
        // Layer 0 is left out: Docker has it.
        let (tar, manifest_id) =
            write_archive(Vec::new(), &cfg, &diff_ids, &sizes, &files[1..], tag).unwrap();
        let e = entries(&tar);
        let blob = |d: &str| format!("blobs/sha256/{}", &d[7..]);
        let names: Vec<String> = e.keys().cloned().collect();
        let mut want = vec![
            blob(&sha(&cfg)),
            blob(&diff_ids[1]),
            blob(&manifest_id),
            "index.json".to_string(),
            "manifest.json".to_string(),
            "oci-layout".to_string(),
        ];
        want.sort();
        assert_eq!(names, want);
        let classic: serde_json::Value = serde_json::from_slice(&e["manifest.json"]).unwrap();
        assert_eq!(classic[0]["RepoTags"], serde_json::json!([tag]));
        assert_eq!(classic[0]["Layers"].as_array().unwrap().len(), 2);
        let index: serde_json::Value = serde_json::from_slice(&e["index.json"]).unwrap();
        assert_eq!(
            index["manifests"][0]["annotations"]["io.containerd.image.name"],
            tag
        );
        let manifest: serde_json::Value = serde_json::from_slice(&e[&blob(&manifest_id)]).unwrap();
        assert_eq!(sha(&e[&blob(&manifest_id)]), manifest_id);
        assert_eq!(manifest["config"]["digest"], sha(&cfg));
        assert_eq!(
            manifest["layers"][0]["size"], 10,
            "every layer's size, sent or not"
        );
        // A blob that is not one of the image's layers is refused.
        let (_, _, stray) = layer_files(dir.path(), &[b"stray".to_vec()]);
        assert!(write_archive(Vec::new(), &cfg, &diff_ids, &sizes, &stray, tag).is_err());
    }

    #[test]
    fn a_layer_listed_twice_is_written_once_even_when_it_is_also_beneath() {
        let dir = tempfile::tempdir().unwrap();
        let empty = b"empty layer".to_vec();
        let (d, sz, f) = layer_files(
            dir.path(),
            &[b"base".to_vec(), empty.clone(), b"app".to_vec()],
        );
        // base, empty, app, empty: Docker has base and empty; app and empty (again) are sent.
        let diff_ids = vec![d[0].clone(), d[1].clone(), d[2].clone(), d[1].clone()];
        let sizes = vec![sz[0], sz[1], sz[2], sz[1]];
        let sent = [f[2].clone(), f[1].clone()];
        let (tar, _) = write_archive(
            Vec::new(),
            &config(&diff_ids),
            &diff_ids,
            &sizes,
            &sent,
            "t:1",
        )
        .unwrap();
        let e = entries(&tar);
        assert_eq!(e.get(&format!("blobs/sha256/{}", &d[1][7..])), Some(&empty));
        assert!(e.contains_key(&format!("blobs/sha256/{}", &d[2][7..])));
        assert!(!e.contains_key(&format!("blobs/sha256/{}", &d[0][7..])));
    }

    #[test]
    fn layers_are_checked_and_unzipped() {
        let dir = tempfile::tempdir().unwrap();
        let data = b"a layer's bytes".repeat(1000);
        let id = sha(&data);
        let dest = dir.path().join("l");
        assert_eq!(
            decompress_checked(data.as_slice(), &dest, &id).unwrap(),
            data.len() as u64
        );
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&data).unwrap();
        let gz = gz.finish().unwrap();
        assert_eq!(
            decompress_checked(gz.as_slice(), &dest, &id).unwrap(),
            data.len() as u64
        );
        assert_eq!(std::fs::read(&dest).unwrap(), data);
        assert!(decompress_checked(&b"other"[..], &dest, &id).is_err());
        assert!(decompress_checked(&[0x28u8, 0xb5, 0x2f, 0xfd, 0][..], &dest, &id).is_err());
    }
}
