//! Sending container images between paired devices (docs/design/container-images.md).
//!
//! Lender: answers what it needs of an image ([`Node::handle_image_query`]), loads what it was
//! sent under a name of its own ([`Node::ensure_sent_image`]), keeps a borrower's images within
//! its grant's allowance, and removes them when the borrower's last grant ends
//! ([`Node::sweep_images`]). Borrower: exports and uploads only what the lender asked for
//! ([`Node::image_to_send`]), one image at a time per lender.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result, anyhow, bail, ensure};
use gimmecores_core::{ExecutionMode, GrantId, PeerKey};
use gimmecores_proto::peer::v1 as pb;
use gimmecores_proto::peer::v1::peer_message::Body;
use iroh::endpoint::{Connection, SendStream};

use crate::blobs::Digest;
use crate::images::{self, DockerImages, LayerFile, Loaded};
use crate::node::Node;
use crate::tree;
use crate::{now, wire};

/// A task's image as the lender received it.
#[derive(Clone, Debug)]
pub(crate) enum TaskImage {
    /// An image already on the lender, by name (the owner's own, or one they pulled).
    Named(String),
    /// An image the borrower sends (now or earlier): what its Docker calls it (`key`), and the
    /// blobs just uploaded.
    Sent {
        reference: String,
        key: String,
        config: Option<Digest>,
        layers: Vec<Digest>,
    },
}

impl TaskImage {
    pub(crate) fn from_proto(img: pb::ImageEnv) -> Result<Self> {
        crate::activity::validate_image(&img.reference)?;
        if img.digest.is_empty() {
            ensure!(
                img.config.is_none() && img.layers.is_empty(),
                "an image sent without its id"
            );
            return Ok(Self::Named(img.reference));
        }
        ensure!(images::is_sha256_id(&img.digest), "not an image id");
        ensure!(img.layers.len() <= images::MAX_LAYERS, "too many layers");
        let config = img.config.as_ref().map(Digest::from_proto).transpose()?;
        let layers = img
            .layers
            .iter()
            .map(Digest::from_proto)
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            config.is_some() || layers.is_empty(),
            "layers sent without the image's config"
        );
        Ok(Self::Sent {
            reference: img.reference,
            key: img.digest,
            config,
            layers,
        })
    }

    /// The name the borrower gave (shown and audited).
    pub(crate) fn reference(&self) -> &str {
        match self {
            Self::Named(r) | Self::Sent { reference: r, .. } => r,
        }
    }

    pub(crate) fn id(&self) -> Option<&str> {
        match self {
            Self::Named(_) => None,
            Self::Sent { key, .. } => Some(key),
        }
    }
}

fn gib(b: u64) -> String {
    let b = b as f64;
    if b >= f64::from(1u32 << 30) {
        format!("{:.1} GiB", b / f64::from(1u32 << 30))
    } else {
        format!("{:.0} MiB", (b / f64::from(1u32 << 20)).max(1.0))
    }
}

fn key_of_hex(h: &str) -> Option<PeerKey> {
    let mut k = [0u8; 32];
    hex::decode_to_slice(h, &mut k).ok()?;
    Some(PeerKey(k))
}

/// An image must be for the lender's own Docker: the same OS and processor.
fn check_platform(os: &str, arch: &str, here_os: &str, here_arch: &str) -> Result<()> {
    ensure!(
        os == here_os && arch == here_arch,
        "the image is for {os}/{arch}, and this lender runs {here_os}/{here_arch} images \
         (build it with `--platform {here_os}/{here_arch}`)"
    );
    Ok(())
}

/// Counts a sent image as in use while a task runs in it (it is never removed meanwhile).
pub(crate) struct ImageInUse {
    node: Node,
    config: String,
}

impl Drop for ImageInUse {
    fn drop(&mut self) {
        let mut s = self.node.state();
        if let Some(n) = s.images_in_use.get_mut(&self.config) {
            *n -= 1;
            if *n == 0 {
                s.images_in_use.remove(&self.config);
            }
        }
    }
}

/// Removes the borrower's export folder however sending ends.
pub(crate) struct Staging(std::path::PathBuf);

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Node {
    fn image_runtime(&self) -> Result<Arc<DockerImages>> {
        self.inner
            .executors
            .images
            .clone()
            .context("this lender cannot receive images (it has no Docker)")
    }

    /// The image allowance of `grant` for `remote` now: a live grant of `remote`'s, covering
    /// containers, that lets it send images.
    fn images_allowance(&self, remote: &PeerKey, grant: GrantId) -> Result<u64> {
        let s = self.state();
        s.grants
            .authorize_blobs(*remote, grant, now())
            .map_err(|_| anyhow!("no live grant for sending images"))?;
        let t = s.grants.terms(grant).context("no such grant")?;
        ensure!(
            t.modes.contains(ExecutionMode::Container),
            "this grant does not cover containers"
        );
        ensure!(
            t.images_bytes > 0,
            "this grant does not let you send images (ask for one with `--images`)"
        );
        Ok(t.images_bytes)
    }

    fn save_images(&self, reg: &images::Registry) {
        if let Err(e) = reg.save(&self.inner.paths.images_file()) {
            tracing::warn!("could not save the list of borrowers' images: {e:#}");
        }
    }

    /// `remote`'s loaded images that Docker still has under their tags. Those it definitely
    /// lost (the owner removed them) are forgotten; if Docker does not answer, nothing is.
    async fn live_images(&self, remote: &PeerKey, rt: &DockerImages) -> Result<Vec<Loaded>> {
        let mine: Vec<Loaded> = self.state().images.of(remote).cloned().collect();
        let (mut live, mut gone) = (Vec::new(), Vec::new());
        for l in mine {
            match rt.lookup(&l.tag).await? {
                Some(id) if id == l.docker_id => live.push(l),
                _ => gone.push(l.tag),
            }
        }
        if !gone.is_empty() {
            let mut s = self.state();
            s.images.images.retain(|l| !gone.contains(&l.tag));
            self.save_images(&s.images);
        }
        Ok(live)
    }

    // -------------------------------------------------------------- lender

    pub(crate) async fn handle_image_query(
        &self,
        remote: PeerKey,
        q: pb::ImageQuery,
        mut send: SendStream,
    ) -> Result<()> {
        let reply = match self.image_needs(&remote, &q).await {
            Ok(n) => n,
            Err(e) => pb::ImageNeeds {
                refused: wire::clean_text(&format!("{e:#}"), 400),
                ..Default::default()
            },
        };
        wire::send(&mut send, Body::ImageNeeds(reply)).await?;
        send.finish()?;
        Ok(())
    }

    async fn image_needs(&self, remote: &PeerKey, q: &pb::ImageQuery) -> Result<pb::ImageNeeds> {
        let grant = GrantId(q.grant_id.as_slice().try_into().context("bad grant id")?);
        let allowance = self.images_allowance(remote, grant)?;
        ensure!(images::is_sha256_id(&q.image_id), "not an image id");
        ensure!(
            !q.diff_ids.is_empty() && q.diff_ids.len() <= images::MAX_LAYERS,
            "an image has 1 to {} layers",
            images::MAX_LAYERS
        );
        ensure!(
            q.diff_ids.iter().all(|d| images::is_sha256_id(d)),
            "not a layer id"
        );
        ensure!(
            self.lend_modes().0.contains(ExecutionMode::Container),
            "this device does not lend container tasks (any more)"
        );
        let rt = self.image_runtime()?;
        let (os, arch) = rt.platform().await?;
        check_platform(&q.os, &q.architecture, &os, &arch)?;
        // An estimate (0: none); the exact size is checked before loading.
        ensure!(
            q.size_bytes <= allowance,
            "the image ({}) is larger than this grant lets you send ({})",
            gib(q.size_bytes),
            gib(allowance)
        );
        let _one = self.inner.image_lock.lock().await;
        let live = self.live_images(remote, &rt).await?;
        if live.iter().any(|l| l.keys.contains(&q.image_id)) {
            return Ok(pb::ImageNeeds {
                loaded: true,
                ..Default::default()
            });
        }
        let from = images::shared_prefix(&q.diff_ids, &live);
        Ok(pb::ImageNeeds {
            send_from: u32::try_from(from)?,
            ..Default::default()
        })
    }

    /// A task naming an image already on the lender: the names GimmeCores uses itself, and
    /// images other borrowers sent, are treated as not there.
    pub(crate) async fn check_named_image(&self, remote: &PeerKey, reference: &str) -> Result<()> {
        let not_here = || {
            anyhow!(
                "image {reference} is not on the lender; GimmeCores never downloads images. \
                 The lender's owner can run `docker pull {reference}` to allow it, or ask \
                 for a grant that lets you send your own (`--images`)"
            )
        };
        if reference.starts_with(images::LOCAL_REGISTRY) {
            return Err(not_here());
        }
        let others = self.state().images.others(remote);
        if others.is_empty() {
            return Ok(());
        }
        let Some(rt) = self.inner.executors.images.clone() else {
            return Ok(());
        };
        // Fail closed: if Docker cannot say what the name is, nothing runs.
        match rt.lookup(reference).await? {
            Some(id) if others.contains(&id) => Err(not_here()),
            _ => Ok(()),
        }
    }

    /// The image to run for a task that names a sent image: already loaded for this borrower,
    /// or loaded now from the blobs just uploaded. Returns what Docker calls it, counted as in
    /// use until the guard drops.
    pub(crate) async fn ensure_sent_image(
        &self,
        remote: &PeerKey,
        grant: GrantId,
        image: &TaskImage,
    ) -> Result<(String, ImageInUse)> {
        let TaskImage::Sent {
            reference,
            key,
            config,
            layers,
        } = image
        else {
            bail!("not a sent image");
        };
        let rt = self.image_runtime()?;
        let blobs = self.inner.blobs.clone();
        let sent: Vec<Digest> = layers.iter().copied().chain(*config).collect();
        let one = self.inner.image_lock.lock().await;
        let live = self.live_images(remote, &rt).await?;
        let in_use = |node: &Node, config: &str| {
            *node
                .state()
                .images_in_use
                .entry(config.to_string())
                .or_insert(0) += 1;
            ImageInUse {
                node: node.clone(),
                config: config.to_string(),
            }
        };
        if let Some(l) = live.iter().find(|l| l.keys.contains(key)) {
            // Loaded already (perhaps by a task that sent it a moment ago): what this one sent
            // is not needed.
            for d in &sent {
                blobs.remove(remote, d);
            }
            let mut s = self.state();
            if let Some(r) = s.images.images.iter_mut().find(|r| r.tag == l.tag) {
                r.used_at = now();
            }
            self.save_images(&s.images);
            drop(s);
            return Ok((l.docker_id.clone(), in_use(self, &l.config)));
        }
        let allowance = self.images_allowance(remote, grant)?;
        let config = config.as_ref().context(
            "the image is no longer on the lender for you; run the task again to send it",
        )?;
        let cfg = blobs
            .get(remote, config)
            .context("the image's config was not sent")?;
        ensure!(Digest::of(&cfg) == *config, "the image's config is corrupt");
        let config_id = images::sha256_id(&cfg);
        let parsed = images::parse_config(&cfg)?;
        let (os, arch) = rt.platform().await?;
        check_platform(&parsed.os, &parsed.architecture, &os, &arch)?;
        let n = parsed.diff_ids.len();
        // What was sent must be the image's own layers; their sizes come from the blobs.
        let mut sent_sizes = BTreeMap::new();
        for d in layers {
            let id = images::id_of_hash(&d.hash);
            ensure!(
                parsed.diff_ids.contains(&id),
                "a layer sent is not the image's"
            );
            sent_sizes.insert(id, d.size);
        }
        // Docker has the layers beneath `have`, from an image loaded for this borrower; every
        // layer above must have been sent.
        let have = images::shared_prefix(&parsed.diff_ids, &live);
        let mut sizes = Vec::with_capacity(n);
        let mut files = Vec::new();
        {
            let s = self.state();
            for (i, d) in parsed.diff_ids.iter().enumerate() {
                if i < have {
                    sizes.push(s.images.layer_size(remote, d).unwrap_or(0));
                    continue;
                }
                let size = *sent_sizes.get(d).context(
                    "the lender no longer has the image's lower layers; run the task again to send them",
                )?;
                let digest = Digest {
                    hash: images::id_hash(d)?,
                    size,
                };
                ensure!(
                    blobs.has(remote, &digest),
                    "a layer of the image was not sent; run the task again"
                );
                sizes.push(size);
                files.push(LayerFile {
                    diff_id: d.clone(),
                    path: blobs.file_of(remote, &digest),
                    size,
                });
            }
        }
        let total = sizes.iter().fold(config.size, |a, b| a.saturating_add(*b));
        ensure!(
            total <= allowance,
            "the image ({}) is larger than this grant lets you send ({})",
            gib(total),
            gib(allowance)
        );
        let tag = images::tag_for(&self.key(), remote, &config_id);
        let at = now();
        let mut new = Loaded {
            borrower: remote.to_hex(),
            keys: vec![key.clone()],
            config: config_id.clone(),
            docker_id: String::new(),
            tag: tag.clone(),
            diff_ids: parsed.diff_ids.clone(),
            sizes: sizes.clone(),
            config_bytes: config.size,
            loaded_at: at,
            used_at: at,
        };
        // Room within the allowance, before Docker holds more than it.
        let after = self
            .make_room(remote, &new, have, allowance, &rt, &live)
            .await?;
        new.docker_id = rt.load(cfg, parsed.diff_ids, sizes, files, &tag).await?;
        {
            let mut s = self.state();
            let hex = remote.to_hex();
            // The same image under another of the borrower's names: one record.
            if let Some(r) = s
                .images
                .images
                .iter_mut()
                .find(|r| r.borrower == hex && r.config == config_id)
            {
                if !r.keys.contains(key) {
                    r.keys.push(key.clone());
                }
                r.docker_id = new.docker_id.clone();
                r.used_at = at;
            } else {
                s.images.images.push(new.clone());
            }
            self.save_images(&s.images);
        }
        // Docker holds the only copy now.
        for d in &sent {
            blobs.remove(remote, d);
        }
        let received: u64 = layers.iter().map(|d| d.size).sum();
        self.audit_best_effort(
            "storage",
            Some(remote),
            format!(
                "loaded the container image {reference} ({}) sent by {}: {} of {n} layers received, {}",
                &config_id[7..19],
                self.peer_name(remote),
                n - have,
                gib(received)
            ),
            serde_json::json!({
                "image": reference, "config": config_id, "docker_id": new.docker_id,
                "tag": tag, "layers": n, "layers_received": n - have,
                "bytes_received": received,
            }),
        );
        let guard = in_use(self, &config_id);
        // Older images sharing its layers could only go once it was loaded (Docker would have
        // removed the shared layers with them).
        for v in after {
            self.remove_image(remote, &v, &rt, "to stay within its grant")
                .await;
        }
        drop(one);
        Ok((new.docker_id, guard))
    }

    /// Makes room for `new` within `allowance`, removing `remote`'s least recently used images
    /// not in use. Those sharing no layer with `new` go now; those sharing its lower layers
    /// (`have`) can only go once it is loaded, so they are returned. Refuses when even that
    /// would not be enough.
    async fn make_room(
        &self,
        remote: &PeerKey,
        new: &Loaded,
        have: usize,
        allowance: u64,
        rt: &DockerImages,
        live: &[Loaded],
    ) -> Result<Vec<Loaded>> {
        let below: std::collections::BTreeSet<&String> = new.diff_ids[..have].iter().collect();
        let (keep, mut evictable): (Vec<Loaded>, Vec<Loaded>) = {
            let s = self.state();
            live.iter()
                .filter(|l| l.config != new.config)
                .cloned()
                .partition(|l| s.images_in_use.contains_key(&l.config))
        };
        evictable.sort_by_key(|l| l.used_at);
        let fits = |kept: &[Loaded]| images::held_by(kept.iter().chain([new])) <= allowance;
        let all = |keep: &[Loaded], ev: &[Loaded]| -> Vec<Loaded> {
            keep.iter().chain(ev).cloned().collect()
        };
        let mut now_ = Vec::new();
        let mut later = Vec::new();
        while !fits(&all(&keep, &evictable)) {
            if evictable.is_empty() {
                bail!(
                    "with this image, the images you sent here would take {}, more than this \
                     grant allows ({}); those in use by running tasks stay until they end",
                    gib(images::held_by(keep.iter().chain([new]))),
                    gib(allowance)
                );
            }
            // Least recently used first.
            let v = evictable.remove(0);
            if v.diff_ids.iter().any(|d| below.contains(d)) {
                later.push(v);
            } else {
                now_.push(v);
            }
        }
        for v in now_ {
            self.remove_image(remote, &v, rt, "to make room for a newer one")
                .await;
        }
        Ok(later)
    }

    async fn remove_image(&self, remote: &PeerKey, v: &Loaded, rt: &DockerImages, why: &str) {
        if let Err(e) = rt.untag(&v.tag).await {
            tracing::warn!("{e:#}");
            return;
        }
        {
            let mut s = self.state();
            s.images.images.retain(|l| l.tag != v.tag);
            self.save_images(&s.images);
        }
        self.audit_best_effort(
            "storage",
            Some(remote),
            format!(
                "removed a container image ({}) of {} {why}",
                &v.config[7..19],
                self.peer_name(remote)
            ),
            serde_json::json!({ "config": v.config, "tag": v.tag }),
        );
    }

    /// Removes the images of every borrower that no longer holds a live grant (with its other
    /// stored files, [`Node::sweep_blobs`]): only the tags GimmeCores added, so an image the
    /// owner also has under a name of their own stays. Retried on the next sweep (every 2 s)
    /// while Docker is away or a task still runs in one.
    pub(crate) async fn sweep_images(&self) {
        if self.inner.images_sweeping.swap(true, Ordering::AcqRel) {
            return;
        }
        struct Done<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for Done<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _done = Done(&self.inner.images_sweeping);
        let at = now();
        let gone: Vec<Loaded> = {
            let s = self.state();
            s.images
                .images
                .iter()
                .filter(|l| {
                    key_of_hex(&l.borrower).is_none_or(|k| !s.grants.has_live_grant(k, at))
                        && !s.images_in_use.contains_key(&l.config)
                })
                .cloned()
                .collect()
        };
        let Some(rt) = self.inner.executors.images.clone() else {
            // No Docker to remove them from: forget them.
            if !gone.is_empty() {
                let mut s = self.state();
                s.images.images.retain(|l| !gone.contains(l));
                self.save_images(&s.images);
            }
            return;
        };
        // Docker's own list too, on start and then every minute: a tag whose record was lost
        // (an unreadable `images.json`, a stop between a load and its record) is still this
        // lender's, by its name, and goes the same way.
        let check_docker = {
            let mut last = self
                .inner
                .images_checked
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let due = last.is_none_or(|t| t.elapsed() >= std::time::Duration::from_secs(60));
            if due {
                *last = Some(std::time::Instant::now());
            }
            due
        };
        if gone.is_empty() && !check_docker {
            return;
        }
        let _one = self.inner.image_lock.lock().await;
        for l in gone {
            let who = key_of_hex(&l.borrower).unwrap_or(PeerKey([0; 32]));
            self.remove_image(&who, &l, &rt, "which no longer holds a live grant")
                .await;
        }
        if !check_docker {
            return;
        }
        let me = self.key();
        let tags = match rt.tags_with(&images::sent_prefix(&me)).await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("{e:#}");
                return;
            }
        };
        for tag in tags {
            let who = images::borrower_of_tag(&me, &tag);
            let keep = {
                let s = self.state();
                who.is_some_and(|k| s.grants.has_live_grant(k, now()))
                    && s.images.images.iter().any(|l| l.tag == tag)
            };
            if keep {
                continue;
            }
            match rt.untag(&tag).await {
                Ok(()) => self.audit_best_effort(
                    "storage",
                    who.as_ref(),
                    "removed a container image GimmeCores had loaded and no longer kept a record of"
                        .to_string(),
                    serde_json::json!({ "tag": tag }),
                ),
                Err(e) => tracing::warn!("{e:#}"),
            }
        }
    }

    // -------------------------------------------------------------- borrower

    /// One image at a time per lender: a second task sending the same image waits, then finds
    /// the layers already there.
    pub(crate) fn image_send_lock(&self, lender: &PeerKey) -> Arc<tokio::sync::Mutex<()>> {
        self.inner
            .image_sends
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(*lender)
            .or_default()
            .clone()
    }

    /// For a task naming `reference` under `grant`: when the grant lets this device send images
    /// and the image is on this device's Docker, asks the lender what it needs and exports only
    /// that into `staging`. Returns the task's image and the blobs to upload; `None` when the
    /// task just names the image (the lender must have it).
    pub(crate) async fn image_to_send(
        &self,
        conn: &Connection,
        grant: GrantId,
        reference: &str,
        staging: &Path,
    ) -> Result<Option<(pb::ImageEnv, Vec<(Digest, tree::Source)>, Staging)>> {
        let allowed = self.state().borrowed.get(&grant).is_some_and(|b| {
            b.terms.images_bytes > 0 && b.terms.modes.contains(ExecutionMode::Container)
        });
        if !allowed {
            return Ok(None);
        }
        let docker = crate::exec::locate_docker();
        let Some(local) = images::inspect_local(&docker, reference).await else {
            return Ok(None);
        };
        let needs = {
            let (mut send, mut recv) = conn.open_bi().await?;
            wire::send(
                &mut send,
                Body::ImageQuery(pb::ImageQuery {
                    grant_id: grant.0.to_vec(),
                    image_id: local.id.clone(),
                    diff_ids: local.diff_ids.clone(),
                    os: local.os.clone(),
                    architecture: local.architecture.clone(),
                    size_bytes: local.size,
                }),
            )
            .await?;
            send.finish()?;
            match wire::recv(&mut recv).await? {
                Body::ImageNeeds(n) => n,
                Body::Error(e) => bail!("the lender cannot take images: {}", e.message),
                _ => bail!("unexpected reply to ImageQuery"),
            }
        };
        if !needs.refused.is_empty() {
            bail!(
                "the lender cannot run {reference}: {}",
                wire::clean_text(&needs.refused, 400)
            );
        }
        let mut env = pb::ImageEnv {
            reference: reference.to_string(),
            digest: local.id.clone(),
            config: None,
            layers: vec![],
        };
        let guard = Staging(staging.to_path_buf());
        if needs.loaded {
            return Ok(Some((env, vec![], guard)));
        }
        let from = needs.send_from as usize;
        ensure!(
            from <= local.diff_ids.len(),
            "the lender asked for a layer the image lacks"
        );
        std::fs::create_dir_all(staging)?;
        let exported = images::export(&docker, &local, from, staging).await?;
        let config = Digest::of(&exported.config);
        let mut blobs = vec![(config, tree::Source::Bytes(exported.config))];
        for l in exported.layers {
            let d = Digest {
                hash: images::id_hash(&l.diff_id)?,
                size: l.size,
            };
            env.layers.push(d.to_proto());
            blobs.push((d, tree::Source::File(l.path)));
        }
        env.config = Some(config.to_proto());
        Ok(Some((env, blobs, guard)))
    }
}
