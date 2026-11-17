//! Running tasks across devices: upload only missing blobs, submit, stream logs, return outputs.
//!
//! Lender-side checks, in order: an active grant for that exact device (I1, I14), limits within
//! the grant, container mode with no network in v1 (I5), a fresh per-task workspace (I4), and
//! cancellation on revoke/expiry/unpair (I3).

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use gimmecores_core::{
    Denied, ExecutionMode, Gpu, GrantId, GrantState, NetworkPolicy, PeerKey, TaskId, TaskRequest,
};
use gimmecores_proto::peer::v1 as pb;
use gimmecores_proto::peer::v1::peer_message::Body;
use gimmecores_proto::peer::v1::{task_event::Event, task_result::Status};
use iroh::endpoint::{RecvStream, SendStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::blobs::Digest;
use crate::exec::{LogChunk, RunEnd, RunSpec};
use crate::node::Node;
use crate::tree;
use crate::{now, wire};

const CHUNK: usize = 1 << 20;
/// How often a running task's workspace is measured against the disk limit.
const WATCH_INTERVAL: Duration = Duration::from_secs(1);
/// Slow walks back off, but never beyond this (the entry cap keeps walks short).
const MAX_WATCH_INTERVAL: Duration = Duration::from_secs(5);

/// What the audit log keeps of a command: the program and the start of its arguments, with
/// likely secrets hidden. Calls can carry data (the Python SDK sends arguments on the command
/// line), which the log must not keep forever; the full command is identified by
/// [`argv_digest`].
pub fn argv_summary(argv: &[String]) -> String {
    const MAX: usize = 160;
    let mut masked = crate::activity::masked_text(argv);
    masked.extend(argv.iter().skip(masked.len()).take(32).cloned());
    let joined = masked
        .iter()
        .map(|a| crate::wire::clean_text(a, MAX))
        .collect::<Vec<_>>()
        .join(" ");
    if joined.chars().count() > MAX {
        let head: String = joined.chars().take(MAX).collect();
        format!("{head}… ({} arguments)", argv.len())
    } else {
        joined
    }
}

pub fn argv_digest(argv: &[String]) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    for a in argv {
        h.update((a.len() as u64).to_be_bytes());
        h.update(a.as_bytes());
    }
    hex::encode(h.finalize())
}

fn workspaces_of(s: &crate::node::State, grant: GrantId) -> u64 {
    s.workspace_bytes
        .values()
        .filter(|(g, _)| *g == grant)
        .map(|(_, b)| *b)
        .sum()
}
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3600);

/// What the borrower wants to run.
#[derive(Clone, Debug)]
pub struct TaskSpec {
    /// Project folder to send; outputs are written back into it.
    pub dir: PathBuf,
    pub argv: Vec<String>,
    pub image: Option<String>,
    /// Where to run on the lender. `None`: container if an image is given, else sandbox.
    pub mode: Option<ExecutionMode>,
    pub outputs: Vec<String>,
    pub excludes: Vec<String>,
    /// Files the user confirmed sending even though the secret scan flags them.
    pub allow_secrets: Vec<PathBuf>,
    /// Files an SDK adds under `.gmc-sdk/` (e.g. its worker's payload), sent with the project.
    pub extra_files: Vec<(String, Vec<u8>)>,
    /// Local files or folders an SDK sends under `.gmc-sdk/` (see [`tree::Attachment`]).
    pub attachments: Vec<tree::Attachment>,
    /// Where declared outputs are written (default: `dir`).
    pub output_dir: Option<PathBuf>,
    /// Environment variables for the task: secrets the user chose to send by name. Sent
    /// encrypted, never logged; the lender's audit records the names only.
    pub env: Vec<(String, String)>,
    pub cpu_millis: u32,
    pub memory_bytes: u64,
    pub timeout: Duration,
    /// A slower level than the grant's for this task (`None`: the grant's). The lender takes
    /// the slower of the two, so asking for more has no effect.
    pub speed: Option<gimmecores_core::Speed>,
    /// When the grant allows it, send the image from this device's Docker if the lender lacks
    /// it (docs/design/container-images.md). False: only name it (tasks from agents, `gmc mcp`).
    pub send_image: bool,
    /// Build caches the lender keeps between this project's tasks (caches.rs); not uploaded.
    pub caches: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskStatus {
    Succeeded,
    Failed,
    TimedOut,
    Cancelled,
    Revoked,
    LimitExceeded,
    Rejected,
}

impl TaskStatus {
    fn from_proto(v: i32) -> Self {
        match Status::try_from(v) {
            Ok(Status::Succeeded) => Self::Succeeded,
            Ok(Status::TimedOut) => Self::TimedOut,
            Ok(Status::Cancelled) => Self::Cancelled,
            Ok(Status::Revoked) => Self::Revoked,
            Ok(Status::LimitExceeded) => Self::LimitExceeded,
            Ok(Status::Rejected) => Self::Rejected,
            _ => Self::Failed,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TaskReport {
    pub status: TaskStatus,
    pub exit_code: i32,
    pub error: Option<String>,
    pub uploaded_bytes: u64,
    pub output_bytes: u64,
    /// Local paths not sent (symlinks or special files).
    pub skipped: Vec<PathBuf>,
}

/// Aborts a background task when dropped (whichever way the owner returns).
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// What a borrower is told when the grant book refuses its task. Only a borrower whose grant is
/// paused learns why lending is paused; a device without a live grant learns nothing about
/// this computer's state.
fn refusal_text(d: &gimmecores_core::Denied, paused_because: Option<&str>) -> String {
    use gimmecores_core::Denied;
    match d {
        Denied::GrantInactive(GrantState::Paused) => match paused_because {
            Some(why) => format!("the lender is paused ({why}); try again later"),
            None => "the lender is paused; try again later".into(),
        },
        Denied::NoGrant | Denied::NotPaired | Denied::PairingClosed => {
            "refused: no active grant".into()
        }
        Denied::GrantInactive(_) => "refused: the grant has ended".into(),
        Denied::ExceedsGrant => {
            "refused: more than the grant allows, or too many tasks at once".into()
        }
        Denied::Invalid => {
            "refused: this task id was already used, or it asks for no CPU or memory".into()
        }
    }
}

fn id16(bytes: &[u8], what: &str) -> Result<[u8; 16]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("{what} must be 16 bytes"))
}

fn result_event(task: &[u8], r: pb::TaskResult) -> Body {
    Body::TaskEvent(pb::TaskEvent {
        task_id: task.to_vec(),
        event: Some(Event::Finished(r)),
    })
}

fn rejected(task: &[u8], why: &str) -> Body {
    result_event(
        task,
        pb::TaskResult {
            status: Status::Rejected as i32,
            error: Some(pb::RemoteError {
                r#type: "Rejected".into(),
                message: why.into(),
                traceback: String::new(),
            }),
            ..Default::default()
        },
    )
}

/// Lets a task container (an unprivileged user) write its own workspace. The parent work
/// directory stays owner-only, so other local users still cannot reach it.
#[cfg(unix)]
fn open_workspace(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for e in ignore::WalkBuilder::new(dir)
        .standard_filters(false)
        .build()
    {
        let e = e?;
        if e.file_type().is_some_and(|t| t.is_dir()) {
            std::fs::set_permissions(e.path(), std::fs::Permissions::from_mode(0o777))?;
        } else if e.file_type().is_some_and(|t| t.is_file()) {
            let m = std::fs::metadata(e.path())?.permissions().mode();
            let mode = if m & 0o111 != 0 { 0o777 } else { 0o666 };
            std::fs::set_permissions(e.path(), std::fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn open_workspace(_dir: &Path) -> Result<()> {
    Ok(())
}

/// A kept package folder in use by one task; released when the task ends.
struct KeptPackages {
    node: Node,
    dir: PathBuf,
}

impl Drop for KeptPackages {
    fn drop(&mut self) {
        let mut s = self.node.state();
        if let Some(n) = s.kept_in_use.get_mut(&self.dir) {
            *n -= 1;
            if *n == 0 {
                s.kept_in_use.remove(&self.dir);
            }
        }
    }
}

/// Kept package folders per borrower; the oldest unused ones go first.
const MAX_KEPT_PACKAGES: usize = 3;

impl Node {
    /// The borrower's packages in this task (`.gmc-sdk/env`), unpacked once into its own
    /// namespace and kept for its later tasks: every blob is hash-checked while unpacking, files
    /// are read-only, and the sandbox lets tasks read but never change the folder. Counted
    /// against the grant's disk limit and deleted with the namespace. None when the task has no
    /// packages, or keeping them would go over the disk limit (the task then gets its own copy).
    fn keep_packages(
        &self,
        remote: PeerKey,
        grant: GrantId,
        root: &Digest,
    ) -> Result<Option<KeptPackages>> {
        let blobs = &self.inner.blobs;
        let Some(env) = tree::subtree(blobs, &remote, root, tree::PACKAGES_DIR)? else {
            return Ok(None);
        };
        let base = blobs.kept_dir(&remote);
        let dir = base.join(env.hex());
        *self.state().kept_in_use.entry(dir.clone()).or_insert(0) += 1;
        let kept = KeptPackages {
            node: self.clone(),
            dir: dir.clone(),
        };
        if dir.is_dir() {
            // Most recently used, for eviction.
            if let Ok(f) = std::fs::File::open(&dir) {
                let _ = f.set_modified(std::time::SystemTime::now());
            }
            return Ok(Some(kept));
        }
        let quota = self
            .blob_quota(&remote, grant)
            .map_err(|d| anyhow!("{d:?}"))?;
        std::fs::create_dir_all(&base)?;
        let tmp = base.join(format!(
            "tmp-{}",
            hex::encode(&crate::wire::random32()?[..8])
        ));
        let built = (|| -> Result<bool> {
            tree::materialize(blobs, &remote, &env, &tmp)?;
            if blobs.usage(&remote) > quota {
                return Ok(false);
            }
            make_read_only(&tmp)?;
            Ok(true)
        })();
        match built {
            Ok(true) => {}
            Ok(false) => {
                let _ = std::fs::remove_dir_all(&tmp);
                blobs.dirs_changed(&remote);
                return Ok(None);
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp);
                return Err(e);
            }
        }
        if let Err(e) = std::fs::rename(&tmp, &dir) {
            let _ = std::fs::remove_dir_all(&tmp);
            // Another task of this borrower kept the same packages first.
            ensure!(dir.is_dir(), "keeping packages: {e}");
        } else {
            let size = tree::disk_usage(&dir).unwrap_or(0);
            self.audit_best_effort(
                "task",
                Some(&remote),
                format!(
                    "kept {} of packages for {} between tasks",
                    human_bytes(size),
                    self.peer_name(&remote)
                ),
                serde_json::json!({ "packages": env.hex(), "bytes": size }),
            );
            self.evict_kept(&base);
        }
        blobs.dirs_changed(&remote);
        Ok(Some(kept))
    }

    /// Keeps at most [`MAX_KEPT_PACKAGES`] folders per borrower (oldest unused go first) and
    /// removes unfinished ones left by a crash.
    fn evict_kept(&self, base: &Path) {
        let Ok(rd) = std::fs::read_dir(base) else {
            return;
        };
        let mut done = Vec::new();
        for e in rd.flatten() {
            let (path, name) = (e.path(), e.file_name().to_string_lossy().into_owned());
            let modified = e
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            if name.starts_with("tmp-") {
                if modified
                    .elapsed()
                    .is_ok_and(|a| a > Duration::from_secs(3600))
                {
                    let _ = std::fs::remove_dir_all(&path);
                }
            } else {
                done.push((modified, path));
            }
        }
        done.sort();
        let excess = done.len().saturating_sub(MAX_KEPT_PACKAGES);
        let in_use = self.state().kept_in_use.clone();
        for (_, path) in done.into_iter().take(excess) {
            if !in_use.contains_key(&path) {
                let _ = std::fs::remove_dir_all(&path);
            }
        }
    }

    /// Disk the borrower may still fill with stored files under `grant`: the grant's disk limit
    /// minus what its running tasks' workspaces hold.
    fn blob_quota(&self, peer: &PeerKey, grant: GrantId) -> Result<u64, Denied> {
        let s = self.state();
        s.grants.authorize_blobs(*peer, grant, now())?;
        let held = s.images.held(peer);
        let limit = s.grants.terms(grant).map_or(0, |t| disk_allowance(t, held));
        Ok(limit.saturating_sub(workspaces_of(&s, grant)))
    }

    /// Measures a running task's workspace until `done`, and cancels the task if the grant's
    /// files plus all its workspaces outgrow the disk limit, or the workspace can no longer be
    /// inspected (fail closed). Returns why it stopped the task, if it did.
    async fn watch_workspace(
        &self,
        remote: PeerKey,
        grant: GrantId,
        task: TaskId,
        workspace: PathBuf,
        token: CancellationToken,
        done: CancellationToken,
    ) -> Option<String> {
        loop {
            let ws = workspace.clone();
            let started = std::time::Instant::now();
            let measured = tokio::task::spawn_blocking(move || tree::disk_usage(&ws))
                .await
                .map_err(|e| anyhow!("{e}"))
                .and_then(|r| r);
            // A slow walk (huge trees) must not eat the lender's CPU: back off.
            let pause = (started.elapsed() * 5).clamp(WATCH_INTERVAL, MAX_WATCH_INTERVAL);
            let why = match measured {
                Err(e) if !done.is_cancelled() => Some(format!(
                    "the task's workspace could not be measured ({e:#}), so its disk limit could not be enforced"
                )),
                Err(_) => None,
                Ok(bytes) => {
                    let (limit, others) = {
                        let mut s = self.state();
                        s.workspace_bytes.insert(task, (grant, bytes));
                        if let Some(h) = s.running.get(&task) {
                            h.usage.set_disk(bytes);
                        }
                        let held = s.images.held(&remote);
                        (
                            s.grants.terms(grant).map_or(0, |t| disk_allowance(t, held)),
                            workspaces_of(&s, grant),
                        )
                    };
                    let used = others.saturating_add(self.inner.blobs.usage(&remote));
                    (used > limit).then(|| {
                        format!(
                            "disk limit reached: this grant's files and workspaces use {used} bytes of the {limit} allowed"
                        )
                    })
                }
            };
            if let Some(why) = why {
                self.mark_task(task, |h| h.stop(crate::activity::EndCause::DiskLimit));
                token.cancel();
                return Some(why);
            }
            tokio::select! {
                () = done.cancelled() => return None,
                () = tokio::time::sleep(pause) => {}
            }
        }
    }

    // ------------------------------------------------------------------ lender side

    /// `FindMissingBlobs`, then the borrower streams `BlobChunk`s; we ack with an empty
    /// `MissingBlobs` once everything is stored.
    pub(crate) async fn handle_blob_upload(
        &self,
        remote: PeerKey,
        req: pb::FindMissingBlobs,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<()> {
        let grant = GrantId(id16(&req.grant_id, "grant id")?);
        if self.blob_quota(&remote, grant).is_err() {
            return wire::send_error(&mut send, pb::error::Code::NoGrant, "no active grant").await;
        }
        let mut missing = Vec::new();
        for d in &req.digests {
            let d = Digest::from_proto(d)?;
            if !self.inner.blobs.has(&remote, &d) {
                missing.push(d.to_proto());
            }
        }
        wire::send(
            &mut send,
            Body::Missing(pb::MissingBlobs { digests: missing }),
        )
        .await?;

        let mut writer: Option<(Digest, crate::blobs::BlobWriter)> = None;
        loop {
            let body = match wire::recv(&mut recv).await {
                Ok(b) => b,
                Err(_) => break, // borrower finished its side
            };
            let Body::BlobChunk(c) = body else {
                return wire::send_error(&mut send, pb::error::Code::Invalid, "expected BlobChunk")
                    .await;
            };
            let d = Digest::from_proto(c.digest.as_ref().context("chunk without digest")?)?;
            if writer.as_ref().is_none_or(|(wd, _)| *wd != d) {
                // I14 re-checked for every new blob: a revoke stops an upload in progress.
                let quota = match self.blob_quota(&remote, grant) {
                    Ok(q) => q,
                    Err(_) => {
                        return wire::send_error(
                            &mut send,
                            pb::error::Code::GrantInactive,
                            "grant ended",
                        )
                        .await;
                    }
                };
                match self.inner.blobs.writer(&remote, d, quota) {
                    Ok(w) => writer = Some((d, w)),
                    Err(e) => {
                        return wire::send_error(
                            &mut send,
                            pb::error::Code::ExceedsGrant,
                            &e.to_string(),
                        )
                        .await;
                    }
                }
            }
            let (_, w) = writer.as_mut().context("no blob in progress")?;
            if let Err(e) = w.write(c.offset, &c.data) {
                return wire::send_error(&mut send, pb::error::Code::Invalid, &e.to_string()).await;
            }
            if c.last {
                let (_, w) = writer.take().context("no blob in progress")?;
                if let Err(e) = w.finish() {
                    return wire::send_error(&mut send, pb::error::Code::Invalid, &e.to_string())
                        .await;
                }
            }
        }
        wire::send(
            &mut send,
            Body::Missing(pb::MissingBlobs { digests: vec![] }),
        )
        .await?;
        send.finish()?;
        Ok(())
    }

    /// Serves `BlobGet` requests for the borrower's own namespace only (I14).
    pub(crate) async fn handle_blob_get(
        &self,
        remote: PeerKey,
        first: pb::BlobGet,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<()> {
        let mut next = Some(first);
        while let Some(get) = next.take() {
            let grant = GrantId(id16(&get.grant_id, "grant id")?);
            if self.blob_quota(&remote, grant).is_err() {
                return wire::send_error(&mut send, pb::error::Code::NoGrant, "no active grant")
                    .await;
            }
            let d = Digest::from_proto(get.digest.as_ref().context("missing digest")?)?;
            let data = match self.inner.blobs.get(&remote, &d) {
                Ok(data) => data,
                Err(e) => {
                    return wire::send_error(&mut send, pb::error::Code::Invalid, &e.to_string())
                        .await;
                }
            };
            send_blob(&mut send, &d, &data, &get.grant_id).await?;
            next = match wire::recv(&mut recv).await {
                Ok(Body::BlobGet(g)) => Some(g),
                _ => None,
            };
        }
        send.finish()?;
        Ok(())
    }

    pub(crate) fn handle_cancel(&self, remote: PeerKey, c: pb::CancelTask) -> Result<()> {
        let task = TaskId(id16(&c.task_id, "task id")?);
        let mut s = self.state();
        if let Some(h) = s.running.get_mut(&task)
            && h.info.peer == remote
        {
            h.stop(crate::activity::EndCause::BorrowerCancelled);
            s.activity_rev += 1;
        }
        Ok(())
    }

    pub(crate) async fn handle_submit(
        &self,
        remote: PeerKey,
        t: pb::SubmitTask,
        mut send: SendStream,
    ) -> Result<()> {
        let tid = t.task_id.clone();
        let outcome = self.run_submitted(remote, t, &mut send).await;
        let body = match outcome {
            Ok(result) => result_event(&tid, result),
            Err(e) => rejected(&tid, &format!("{e:#}")),
        };
        wire::send(&mut send, body).await?;
        send.finish()?;
        send.stopped().await.ok();
        Ok(())
    }

    async fn run_submitted(
        &self,
        remote: PeerKey,
        t: pb::SubmitTask,
        send: &mut SendStream,
    ) -> Result<pb::TaskResult> {
        let task = TaskId(id16(&t.task_id, "task id")?);
        let grant = GrantId(id16(&t.grant_id, "grant id")?);
        let report_usage = t.report_usage;
        let (caches, cache_scope) = (t.caches.clone(), t.cache_scope.clone());
        // A slower level than the grant's, if the task asked for one (never faster).
        let asked_speed = crate::grants_flow::speed_from(t.speed);
        let Some(pb::submit_task::Work::Command(cmd)) = t.work else {
            bail!("only command tasks are supported in this version");
        };
        ensure!(!cmd.argv.is_empty(), "empty command");
        // Fail closed: an unknown mode, a mode this user does not lend, or one without a
        // working runner is refused. Never falls back to another mode.
        let mode = crate::grants_flow::mode_from(t.mode)
            .context("the task names no known way of running it")?;
        let mode_name = crate::exec::mode_name(mode);
        ensure!(
            mode != ExecutionMode::Native,
            "running as the lender's user without a sandbox is not available yet"
        );
        ensure!(
            self.lend_modes().0.contains(mode),
            "this device does not lend {mode_name} tasks (any more)"
        );
        let exec = self
            .inner
            .executors
            .get(mode)
            .cloned()
            .with_context(|| format!("this device cannot run {mode_name} tasks"))?;
        if t.network == pb::NetworkPolicy::Internet as i32 {
            bail!("network access is not available before M4");
        }
        let task_image = match t.env.and_then(|e| e.kind) {
            Some(pb::environment::Kind::Image(img)) => {
                Some(crate::images_flow::TaskImage::from_proto(img)?)
            }
            Some(_) => bail!("only image environments are supported in this version"),
            None => None,
        };
        // The name shown and audited; what runs is decided just before it starts.
        let image = task_image.as_ref().map(|i| i.reference().to_string());
        match (mode, &image) {
            (ExecutionMode::Sandbox, Some(_)) => bail!(
                "sandbox tasks use the lender's installed tools; an image needs container mode"
            ),
            (ExecutionMode::Container, None) => bail!("container tasks need an image (--image)"),
            _ => {}
        }
        let limits = t.limits.context("missing limits")?;
        // Variables a task may set: no replacing the lender's own, bounded (fail closed).
        let env_vars: Vec<(String, String)> = cmd
            .environment
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        crate::exec::check_env(&env_vars)?;
        let env_names: Vec<&String> = cmd.environment.keys().collect();
        let input_root = Digest::from_proto(t.input_root.as_ref().context("missing input root")?)?;
        let outputs = t
            .output_paths
            .iter()
            .map(|p| tree::validate_output_path(p).map(|_| p.clone()))
            .collect::<Result<Vec<_>>>()?;

        // A Trusted grant is usable only while Trusted mode is still on here (turning it off
        // revokes such grants; this also covers the moment it lapses).
        let trusted_grant = self.state().grants.terms(grant).map(|g| g.trust)
            == Some(gimmecores_core::TrustLevel::Trusted);
        ensure!(
            !trusted_grant || self.is_trusted(&remote),
            "Trusted mode is no longer on for this device"
        );

        // I1: nothing runs unless the grant book says yes.
        let req = TaskRequest {
            cpu_millis: limits.cpu_millis,
            memory_bytes: limits.memory_bytes,
            disk_bytes: 0,
            gpu: Gpu::None,
            mode,
            network: NetworkPolicy::None,
        };
        // I1: admitted only if the grant book says yes, in one critical section with the
        // registry. A refusal writes nothing to the audit log: a paired device without a live
        // grant cannot append entries, and a replayed task id is not recorded twice.
        let token = CancellationToken::new();
        let mut info = crate::activity::TaskInfo {
            id: task,
            peer: remote,
            peer_name: self.peer_name(&remote),
            grant,
            grant_limits: pb::Limits::default(),
            grant_not_after: 0,
            command: crate::activity::show_command(&cmd.argv),
            env_names: {
                let mut names: Vec<String> = cmd
                    .environment
                    .keys()
                    .map(|k| crate::activity::show_env_name(k))
                    .collect();
                names.sort();
                names.truncate(8);
                names
            },
            env_total: cmd.environment.len(),
            image: image.clone(),
            mode,
            cpu_millis: limits.cpu_millis,
            memory_bytes: limits.memory_bytes,
            timeout_secs: t
                .timeout
                .and_then(|d| u64::try_from(d.seconds).ok())
                .unwrap_or(DEFAULT_TIMEOUT.as_secs()),
            created_at: now(),
            group: crate::activity::group_of(&remote, &cmd.argv, mode, image.as_deref()),
            // Decided below, with the grant's terms and the owner's setting in hand.
            speed: gimmecores_core::Speed::Background,
            // The sandbox applies levels; containers run in their runtime's own scheduling.
            speed_applied: mode == ExecutionMode::Sandbox,
        };
        let (not_after, usage, speed) = {
            let mut s = self.state();
            if let Err(d) = s.grants.start_task(remote, grant, task, req, now()) {
                bail!(
                    "{}",
                    refusal_text(&d, s.paused.as_ref().map(|p| p.1.as_str()))
                );
            }
            let terms = s.grants.terms(grant);
            info.grant_limits = terms
                .map(|g| crate::grants_flow::limits_to(&g.limits))
                .unwrap_or_default();
            let not_after = terms.map_or(0, |g| g.not_after);
            info.grant_not_after = not_after;
            info.speed =
                crate::speed::effective(terms.and_then(|g| g.speed), s.task_speed, asked_speed);
            let speed = info.speed;
            let hosted = crate::activity::Hosted::new(info, token.clone());
            let usage = hosted.usage.clone();
            s.running.insert(task, hosted);
            s.activity_rev += 1;
            (not_after, usage, speed)
        };
        // I11, strict: recorded before anything runs; if the record cannot be written, the
        // admission is undone and nothing runs.
        let recorded = self.audit(
            "task",
            Some(&remote),
            format!(
                "starting for {}: {}",
                self.peer_name(&remote),
                argv_summary(&cmd.argv)
            ),
            serde_json::json!({
                "task": hex::encode(task.0),
                "grant": hex::encode(grant.0),
                "argv": argv_summary(&cmd.argv),
                "argv_sha256": argv_digest(&cmd.argv),
                // Names only, never values: these are the borrower's secrets.
                "env_names": env_names,
                "image": image,
                "image_id": task_image.as_ref().and_then(|i| i.id()),
                "mode": mode_name,
                "cpu_millis": limits.cpu_millis,
                "memory_bytes": limits.memory_bytes,
                "speed": speed.name(),
                "input_root": input_root.hex(),
            }),
        );
        if let Err(e) = recorded {
            let mut s = self.state();
            s.grants.finish_task(task);
            s.running.remove(&task);
            s.activity_rev += 1;
            drop(s);
            tracing::warn!("a task was not started: the audit log could not be written: {e:#}");
            bail!("could not record the task; nothing was started");
        }
        let workspace = self.inner.paths.work_dir().join(hex::encode(task.0));
        // Its build caches, moved into the task folder once it is made (caches.rs).
        if !caches.is_empty() {
            self.state()
                .caches_wanted
                .insert(task, (cache_scope.clone(), caches.clone()));
        }
        let result = self
            .execute(
                remote,
                grant,
                task,
                &cmd,
                exec,
                task_image,
                mode,
                &input_root,
                &outputs,
                limits,
                t.timeout,
                not_after,
                &workspace,
                token.clone(),
                usage.clone(),
                report_usage,
                speed,
                send,
            )
            .await;
        // Retire the task in one critical section and decide, in one place, how it ended.
        let (result, ended) = {
            let mut s = self.state();
            s.grants.finish_task(task);
            s.workspace_bytes.remove(&task);
            s.activity_rev += 1;
            let hosted = s.running.remove(&task);
            let grant_ended = matches!(
                s.grants.state(grant),
                Some(GrantState::Revoked | GrantState::Expired)
            );
            drop(s);
            let speed = self.service_speed();
            match hosted {
                Some(h) => {
                    let (result, ended) = crate::activity::outcome(&h, result, grant_ended, speed);
                    (result, Some(ended))
                }
                None => (result, None),
            }
        };
        if let Some(e) = ended
            && self.is_paired(&remote)
        {
            self.state().history.add(e);
        }
        // Outputs are collected: its caches go back (or are dropped), then the folder goes.
        self.state().caches_wanted.remove(&task);
        let keep = !matches!(&result, Ok(r) if r.status == Status::LimitExceeded as i32);
        let closed = {
            let (node, ws) = (self.clone(), workspace.clone());
            tokio::task::spawn_blocking(move || {
                node.check_in_caches(remote, grant, task, &ws, keep)
            })
            .await
            .unwrap_or_else(|_| workspace.clone())
        };
        remove_workspace(&closed);
        // A process left behind may have made the old path again: never kept.
        if closed != workspace {
            remove_workspace(&workspace);
        }
        let summary = match &result {
            Ok(r) if r.status == Status::Rejected as i32 => format!(
                "failed to run: {}",
                r.error.as_ref().map(|e| e.message.as_str()).unwrap_or("")
            ),
            Ok(r) => format!(
                "finished: {:?}, exit {}",
                Status::try_from(r.status).unwrap_or(Status::Failed),
                r.exit_code
            ),
            Err(e) => format!("failed to run: {e:#}"),
        };
        self.audit_best_effort(
            "task",
            Some(&remote),
            summary,
            serde_json::json!({ "task": hex::encode(task.0) }),
        );
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute(
        &self,
        remote: PeerKey,
        grant: GrantId,
        task: TaskId,
        cmd: &pb::Command,
        exec: std::sync::Arc<dyn crate::exec::Executor>,
        image: Option<crate::images_flow::TaskImage>,
        mode: ExecutionMode,
        input_root: &Digest,
        outputs: &[String],
        limits: pb::Limits,
        timeout: Option<prost_types::Duration>,
        not_after: u64,
        workspace: &Path,
        token: CancellationToken,
        usage: std::sync::Arc<crate::usage::UsageCell>,
        report_usage: bool,
        speed: gimmecores_core::Speed,
        send: &mut SendStream,
    ) -> Result<pb::TaskResult> {
        // macOS checks every native library the first time it loads from a new file, which
        // costs seconds per task for packages like NumPy. In the macOS sandbox, a borrower's
        // packages are therefore unpacked once and kept (verified, read-only to tasks); each
        // task folder links to them.
        let kept = if cfg!(target_os = "macos") && mode == ExecutionMode::Sandbox {
            let node = self.clone();
            let root = *input_root;
            tokio::task::spawn_blocking(move || node.keep_packages(remote, grant, &root)).await??
        } else {
            None
        };
        // I4: a fresh workspace holding only the borrower's own input tree.
        {
            let (blobs, ws, root) = (
                self.inner.blobs.clone(),
                workspace.to_path_buf(),
                *input_root,
            );
            let link = kept.as_ref().map(|k| k.dir.clone());
            tokio::task::spawn_blocking(move || -> Result<()> {
                match &link {
                    Some(dir) => {
                        let skip = Path::new(tree::PACKAGES_DIR);
                        tree::materialize_except(&blobs, &remote, &root, &ws, Some(skip))?;
                        let at = ws.join(tree::PACKAGES_DIR);
                        std::fs::create_dir_all(at.parent().context("no parent")?)?;
                        #[cfg(unix)]
                        std::os::unix::fs::symlink(dir, &at)?;
                        // No silent fallback: a task must not start without its packages.
                        #[cfg(not(unix))]
                        bail!(
                            "kept package folders are not supported on this platform yet ({})",
                            dir.display()
                        );
                    }
                    None => {
                        tree::materialize(&blobs, &remote, &root, &ws)?;
                    }
                }
                open_workspace(&ws)
            })
            .await??;
        }
        // The borrower's build caches for this project, moved in (caches.rs).
        let wanted = self.state().caches_wanted.remove(&task);
        if let Some((scope, paths)) = wanted {
            let (node, ws, root) = (self.clone(), workspace.to_path_buf(), *input_root);
            let runtime = crate::exec::mode_name(mode);
            // Kept packages are linked in, not part of the folder.
            let skip = kept.is_some().then(|| Path::new(tree::PACKAGES_DIR));
            tokio::task::spawn_blocking(move || {
                node.check_out_caches(remote, task, &scope, runtime, &paths, &ws, &root, skip)
            })
            .await??;
        }
        let requested = timeout
            .and_then(|d| u64::try_from(d.seconds).ok())
            .map_or(DEFAULT_TIMEOUT, Duration::from_secs);
        let until_expiry = Duration::from_secs(not_after.saturating_sub(now()));
        let workdir = match cmd.working_directory.as_str() {
            "" => workspace.to_path_buf(),
            wd => workspace.join(tree::validate_output_path(wd)?),
        };
        // The image: one on the lender (not GimmeCores' own, not another borrower's), or the
        // borrower's own, loaded now if it was just sent; in use until the task ends.
        let (image, _image_in_use) = match image {
            None => (None, None),
            Some(crate::images_flow::TaskImage::Named(r)) => {
                self.check_named_image(&remote, &r).await?;
                (Some(r), None)
            }
            Some(sent) => {
                // A revoke (or the borrower cancelling) stops a long load too.
                let (id, guard) = tokio::select! {
                    r = self.ensure_sent_image(&remote, grant, &sent) => r?,
                    () = token.cancelled() => bail!("stopped while its image was being loaded"),
                };
                (Some(id), Some(guard))
            }
        };
        let effective = requested.min(until_expiry);
        self.mark_task(task, |h| {
            h.effective_timeout_secs = Some(effective.as_secs());
            h.grant_bound = until_expiry < requested;
        });
        let spec = RunSpec {
            name: format!("gmc-{}", hex::encode(task.0)),
            argv: cmd.argv.clone(),
            workdir,
            image,
            cpu_millis: limits.cpu_millis,
            memory_bytes: limits.memory_bytes,
            timeout: effective,
            env: cmd
                .environment
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            read_only: kept.iter().map(|k| k.dir.clone()).collect(),
            usage: Some(usage.clone()),
            speed,
        };
        wire::send(
            send,
            Body::TaskEvent(pb::TaskEvent {
                task_id: task.0.to_vec(),
                event: Some(Event::Started(pb::Started {
                    at: None,
                    warm: false,
                    speed: crate::grants_flow::speed_to(Some(speed)) as i32,
                    speed_applied: mode == ExecutionMode::Sandbox,
                })),
            }),
        )
        .await?;
        self.mark_task(task, |h| h.started_sent = true);

        let started = std::time::Instant::now();
        let watch_done = CancellationToken::new();
        let watcher = {
            let (node, ws, t, d) = (
                self.clone(),
                workspace.to_path_buf(),
                token.clone(),
                watch_done.clone(),
            );
            tokio::spawn(async move { node.watch_workspace(remote, grant, task, ws, t, d).await })
        };
        let (tx, mut rx) = mpsc::channel::<LogChunk>(64);
        let run_token = token.clone();
        let run = tokio::spawn(async move { exec.run(spec, tx, run_token).await });
        // The task's figures, when the borrower asked for them; a send blocked for longer
        // than the interval does not make the next reports come in a burst.
        let mut reports = tokio::time::interval(crate::remote::REPORT_EVERY);
        reports.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        reports.tick().await;
        loop {
            let event = tokio::select! {
                chunk = rx.recv() => {
                    let Some(chunk) = chunk else { break };
                    Event::Log(pb::LogChunk {
                        stream: if chunk.stderr {
                            pb::log_chunk::Stream::Stderr as i32
                        } else {
                            pb::log_chunk::Stream::Stdout as i32
                        },
                        data: chunk.data,
                    })
                }
                _ = reports.tick(), if report_usage => {
                    let Some(u) = self.usage_report(task) else { continue };
                    Event::Usage(u)
                }
            };
            let event = pb::TaskEvent {
                task_id: task.0.to_vec(),
                event: Some(event),
            };
            if wire::send(send, Body::TaskEvent(event)).await.is_err() && !token.is_cancelled() {
                // The borrower went away.
                self.mark_task(task, |h| h.stop(crate::activity::EndCause::BorrowerGone));
                token.cancel();
            }
        }
        let end = run.await;
        // Stop the watcher before anything can return early, so it never records this task's
        // workspace after the caller has forgotten it.
        watch_done.cancel();
        let over_limit = watcher.await.ok().flatten();
        let end = end??;
        if let RunEnd::Exited(code) = end {
            self.mark_task(task, |h| h.exit = Some(code));
        }
        let stop_note = self
            .state()
            .running
            .get(&task)
            .and_then(|h| h.stop)
            .and_then(crate::activity::EndCause::note)
            .map(str::to_owned);
        let stopped_why = match &end {
            RunEnd::LimitExceeded(why) => Some(why.clone()),
            _ => over_limit.clone(),
        };
        if let Some(note) = stop_note {
            let note = pb::TaskEvent {
                task_id: task.0.to_vec(),
                event: Some(Event::Log(pb::LogChunk {
                    stream: pb::log_chunk::Stream::Stderr as i32,
                    data: format!("gimmecores: {note}\n").into_bytes(),
                })),
            };
            let _ = wire::send(send, Body::TaskEvent(note)).await;
        }
        if let Some(why) = &stopped_why {
            let note = pb::TaskEvent {
                task_id: task.0.to_vec(),
                event: Some(Event::Log(pb::LogChunk {
                    stream: pb::log_chunk::Stream::Stderr as i32,
                    data: format!("gimmecores: task stopped by the lender: {why}\n").into_bytes(),
                })),
            };
            let _ = wire::send(send, Body::TaskEvent(note)).await;
        }

        let grant_ended = matches!(
            self.state().grants.state(grant),
            Some(GrantState::Revoked | GrantState::Expired)
        );
        let (status, exit_code) = match end {
            RunEnd::Exited(0) => (Status::Succeeded, 0),
            RunEnd::Exited(code) => (Status::Failed, code),
            RunEnd::TimedOut => (Status::TimedOut, -1),
            RunEnd::Cancelled if over_limit.is_some() => (Status::LimitExceeded, -1),
            RunEnd::LimitExceeded(_) => (Status::LimitExceeded, -1),
            RunEnd::Cancelled if grant_ended => (Status::Revoked, -1),
            RunEnd::Cancelled => (Status::Cancelled, -1),
        };

        let mut result = pb::TaskResult {
            status: status as i32,
            exit_code,
            usage: Some(pb::ResourceUsage {
                wall: Some(prost_types::Duration {
                    seconds: i64::try_from(started.elapsed().as_secs()).unwrap_or(i64::MAX),
                    nanos: 0,
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        if status == Status::Succeeded || status == Status::Failed {
            self.mark_task(task, |h| h.collecting = true);
            let (ws, outs) = (workspace.to_path_buf(), outputs.to_vec());
            let out_tree =
                tokio::task::spawn_blocking(move || tree::collect_outputs(&ws, &outs)).await??;
            let quota = self
                .blob_quota(&remote, grant)
                .map_err(|d| anyhow!("{d:?}"))?;
            for (d, src) in &out_tree.blobs {
                match src {
                    tree::Source::File(p) => self.inner.blobs.put_file(&remote, d, p, quota)?,
                    tree::Source::Bytes(b) => self.inner.blobs.put(&remote, d, b, quota)?,
                }
            }
            result.output_root = out_tree.root.map(Digest::to_proto);
        }
        Ok(result)
    }

    // ------------------------------------------------------------------ borrower side

    /// Runs `spec` on `lender` under `grant`, streaming logs to `logs` and writing declared
    /// outputs back into `spec.dir`.
    pub async fn run_task(
        &self,
        lender: &PeerKey,
        grant: GrantId,
        spec: TaskSpec,
        logs: mpsc::Sender<LogChunk>,
    ) -> Result<TaskReport> {
        self.run_task_until(lender, grant, spec, logs, CancellationToken::new())
            .await
    }

    /// [`Self::run_task`], stopped early by `cancel`: before the task is submitted nothing more
    /// is sent and nothing runs; once it runs, the lender is asked to stop it (it then reports
    /// it cancelled). Once the task has finished, its outputs are still fetched.
    pub async fn run_task_until(
        &self,
        lender: &PeerKey,
        grant: GrantId,
        spec: TaskSpec,
        logs: mpsc::Sender<LogChunk>,
        cancel: CancellationToken,
    ) -> Result<TaskReport> {
        self.run_task_watched(lender, grant, spec, logs, cancel, None)
            .await
    }

    /// [`Self::run_task_until`], also telling `started` when the lender starts the task (with
    /// the speed it runs at, from lenders that say).
    pub async fn run_task_watched(
        &self,
        lender: &PeerKey,
        grant: GrantId,
        spec: TaskSpec,
        logs: mpsc::Sender<LogChunk>,
        cancel: CancellationToken,
        mut started: Option<tokio::sync::oneshot::Sender<pb::Started>>,
    ) -> Result<TaskReport> {
        for o in &spec.outputs {
            tree::validate_output_path(o)?;
        }
        crate::exec::check_env(&spec.env)?;
        // Caches stay on the lender: checked here, and never uploaded.
        let caches = crate::caches::validate_all(&spec.caches)?;
        let mut ex = spec.excludes.clone();
        ex.extend(caches.iter().map(|c| format!("/{c}")));
        let dir = spec.dir.clone();
        let allow = spec.allow_secrets.clone();
        let extra = spec.extra_files.clone();
        let attachments = spec.attachments.clone();
        let (mut tree, findings) = tokio::task::spawn_blocking(move || -> Result<_> {
            let tree = tree::build_full(&dir, &ex, &extra, &attachments)?;
            // I7: look inside every file about to leave this machine.
            let mut findings = crate::secrets::scan_files(
                tree.files
                    .iter()
                    .filter(|(_, rel)| !allow.iter().any(|a| a == rel))
                    .map(|(abs, rel)| (abs.as_path(), rel.as_path())),
            );
            // An SDK's payload too: a pickled closure can carry a notebook's API key.
            for (rel, data) in &extra {
                let rel = std::path::Path::new(rel);
                if !allow.iter().any(|a| a == rel) {
                    findings.extend(crate::secrets::scan_text(
                        rel,
                        &String::from_utf8_lossy(data),
                    ));
                }
            }
            Ok((tree, findings))
        })
        .await??;
        if !findings.is_empty() {
            bail!("{}", crate::secrets::describe(&findings));
        }
        let root = tree.root.context("empty tree")?;
        if cancel.is_cancelled() {
            bail!("cancelled before the task started");
        }
        let conn = self.dial_waking(lender).await?;
        // In use: a grant a standing grant gave is renewed only while used (standing.rs).
        self.state().borrowed_used.insert(grant, crate::now());

        // 0. This device's own image, when the grant lets it send one: only the layers the
        // lender does not have, uploaded with the files (docs/design/container-images.md).
        let mut image_env = None;
        let mut sent_image_id: Option<String> = None;
        let mut _staging = None;
        // One image sent to a lender at a time, until its layers are uploaded: a second task
        // with the same image then finds them there (or the image loaded).
        let send_lock = self.image_send_lock(lender);
        let sending = match spec.image {
            Some(_) => Some(send_lock.lock().await),
            None => None,
        };
        if let Some(reference) = spec.image.as_deref()
            && spec.send_image
            && spec.mode != Some(ExecutionMode::Sandbox)
        {
            let staging = self
                .inner
                .paths
                .work_dir()
                .join(format!("send-{}", hex::encode(&wire::random32()?[..8])));
            let sending = tokio::select! {
                r = self.image_to_send(&conn, grant, reference, &staging) => r?,
                () = cancel.cancelled() => bail!("cancelled before the task started"),
            };
            if let Some((env, blobs, guard)) = sending {
                sent_image_id = Some(env.digest.clone());
                tree.blobs.extend(blobs);
                image_env = Some(env);
                _staging = Some(guard);
            }
        }
        if cancel.is_cancelled() {
            bail!("cancelled before the task started");
        }

        // 1. Upload only what the lender is missing: ask once, then send in parallel streams.
        let missing: Vec<Digest> = {
            let (mut send, mut recv) = conn.open_bi().await?;
            wire::send(
                &mut send,
                Body::FindMissing(pb::FindMissingBlobs {
                    digests: tree.blobs.keys().map(|d| d.to_proto()).collect(),
                    grant_id: grant.0.to_vec(),
                }),
            )
            .await?;
            let Body::Missing(missing) = wire::recv(&mut recv).await? else {
                bail!("unexpected reply to FindMissingBlobs");
            };
            send.finish()?;
            let _ = wire::recv(&mut recv).await;
            missing
                .digests
                .iter()
                .map(Digest::from_proto)
                .collect::<Result<_>>()?
        };
        let mut uploads = Vec::with_capacity(missing.len());
        for d in &missing {
            let src = tree
                .blobs
                .get(d)
                .context("lender asked for an unknown blob")?;
            uploads.push((*d, src.clone()));
        }
        let uploaded: u64 = uploads.iter().map(|(d, _)| d.size).sum();
        let mut streams = tokio::task::JoinSet::new();
        for group in upload_groups(uploads) {
            let conn = conn.clone();
            streams.spawn(async move { upload_stream(conn, grant, group).await });
        }
        loop {
            tokio::select! {
                r = streams.join_next() => match r {
                    Some(r) => r??,
                    None => break,
                },
                () = cancel.cancelled() => {
                    streams.abort_all();
                    bail!("cancelled before the task started");
                }
            }
        }

        drop(sending);

        // 2. Submit and stream events.
        let task_id = wire::random32()?[..16].to_vec();
        let tid = TaskId(id16(&task_id, "task id")?);
        let mode = spec.mode.unwrap_or(if spec.image.is_some() {
            ExecutionMode::Container
        } else {
            ExecutionMode::Sandbox
        });
        let (mut send, mut recv) = conn.open_bi().await?;
        // Listed on this device from now until this function returns, however it returns.
        let _record = self.record_remote(tid, lender, grant, &spec, mode);
        wire::send(
            &mut send,
            Body::SubmitTask(pb::SubmitTask {
                task_id: task_id.clone(),
                grant_id: grant.0.to_vec(),
                mode: crate::grants_flow::mode_to(mode) as i32,
                env: image_env
                    .or_else(|| {
                        spec.image.as_ref().map(|r| pb::ImageEnv {
                            reference: r.clone(),
                            ..Default::default()
                        })
                    })
                    .map(|img| pb::Environment {
                        kind: Some(pb::environment::Kind::Image(img)),
                    }),
                work: Some(pb::submit_task::Work::Command(pb::Command {
                    argv: spec.argv.clone(),
                    working_directory: String::new(),
                    environment: spec.env.iter().cloned().collect(),
                })),
                input_root: Some(root.to_proto()),
                output_paths: spec.outputs.clone(),
                limits: Some(pb::Limits {
                    cpu_millis: spec.cpu_millis,
                    memory_bytes: spec.memory_bytes,
                    ..Default::default()
                }),
                network: pb::NetworkPolicy::None as i32,
                timeout: Some(prost_types::Duration {
                    seconds: i64::try_from(spec.timeout.as_secs()).unwrap_or(i64::MAX),
                    nanos: 0,
                }),
                report_usage: true,
                speed: crate::grants_flow::speed_to(spec.speed) as i32,
                cache_scope: if caches.is_empty() {
                    Vec::new()
                } else {
                    crate::caches::scope_of(&spec.dir)
                },
                caches: caches.clone(),
            }),
        )
        .await?;
        // A cancel is sent on a stream of its own: reading this one is never interrupted, so
        // the lender's reply (the task finished, cancelled) is still read whole.
        let canceller = {
            let (conn, cancel, task_id) = (conn.clone(), cancel.clone(), task_id.clone());
            tokio::spawn(async move {
                cancel.cancelled().await;
                if let Ok((mut send, _recv)) = conn.open_bi().await {
                    let body = Body::CancelTask(pb::CancelTask { task_id });
                    if wire::send(&mut send, body).await.is_ok() {
                        let _ = send.finish();
                        let _ = send.stopped().await;
                    }
                }
            })
        };
        let canceller = AbortOnDrop(canceller);
        let result = loop {
            let Body::TaskEvent(ev) = wire::recv(&mut recv).await? else {
                bail!("unexpected message while running");
            };
            match ev.event {
                Some(Event::Log(l)) => {
                    let _ = logs
                        .send(LogChunk {
                            stderr: l.stream == pb::log_chunk::Stream::Stderr as i32,
                            data: l.data,
                        })
                        .await;
                }
                Some(Event::Started(s)) => {
                    self.remote_phase(tid, crate::remote::Phase::Running);
                    if let Some(tx) = started.take() {
                        let _ = tx.send(s);
                    }
                }
                // Kept for the task this stream belongs to, whatever id the event names.
                Some(Event::Usage(u)) => {
                    if let Some(t) = self.state().remote.get_mut(&tid) {
                        t.record(&u);
                    }
                }
                Some(Event::Finished(r)) => break r,
                _ => {}
            }
        };
        self.remote_phase(tid, crate::remote::Phase::Collecting);
        // Finished: from here on its outputs are fetched even if the caller has gone.
        drop(canceller);
        drop(logs);

        // 3. Fetch outputs into the project folder (I8): walk the returned tree by structure,
        //    accept only declared output paths, cap the total size before downloading files,
        //    and write nothing at all if any check fails.
        let mut output_bytes = 0;
        let declared: Vec<PathBuf> = spec
            .outputs
            .iter()
            .map(|o| tree::validate_output_path(o))
            .collect::<Result<_>>()?;
        if let (Some(out_root), false) = (result.output_root.as_ref(), declared.is_empty()) {
            let out_root = Digest::from_proto(out_root)?;
            let (mut send, mut recv) = conn.open_bi().await?;
            let mut fetched = std::collections::BTreeMap::new();
            let mut budget = tree::MAX_TREE_BYTES;
            let mut queue = vec![(PathBuf::new(), out_root)];
            let mut files = Vec::new();
            while let Some((path, d)) = queue.pop() {
                ensure!(fetched.len() < 100_000, "too many output directories");
                let data = fetch_blob(&mut send, &mut recv, grant, &d).await?;
                let level = tree::inspect_output_dir(&path, &data, &declared, &mut budget)?;
                queue.extend(level.dirs);
                files.extend(level.files);
                fetched.insert(d, data);
            }
            for (_, d) in &files {
                if !fetched.contains_key(d) {
                    let data = fetch_blob(&mut send, &mut recv, grant, d).await?;
                    fetched.insert(*d, data);
                }
            }
            send.finish()?;
            let dest = spec.output_dir.clone().unwrap_or_else(|| spec.dir.clone());
            ensure!(
                dest.is_absolute(),
                "the output folder must be an absolute path"
            );
            output_bytes = tokio::task::spawn_blocking(move || {
                let mut fetch = |d: &Digest| fetched.get(d).cloned().context("missing output blob");
                tree::extract(&mut fetch, &out_root, &dest)
            })
            .await??;
        }

        self.audit_best_effort(
            "task",
            Some(lender),
            format!(
                "ran on {}: {} -> {:?}, exit {}",
                self.peer_name(lender),
                argv_summary(&spec.argv),
                TaskStatus::from_proto(result.status),
                result.exit_code
            ),
            serde_json::json!({
                "image_id": sent_image_id,
                "uploaded_bytes": uploaded,
                "output_bytes": output_bytes,
                // Names only: which secrets this device sent with the task.
                "env_names": spec.env.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            }),
        );
        Ok(TaskReport {
            status: TaskStatus::from_proto(result.status),
            exit_code: result.exit_code,
            error: result.error.map(|e| e.message),
            uploaded_bytes: uploaded,
            output_bytes,
            skipped: tree.skipped,
        })
    }
}

impl Node {
    /// A running task's figures as the peer protocol carries them, for its borrower.
    fn usage_report(&self, task: TaskId) -> Option<pb::TaskUsage> {
        use crate::activity::Phase as P;
        use pb::task_usage::State as S;
        let speed = self.service_speed();
        let s = self.state();
        let h = s.running.get(&task)?;
        let mut u = crate::activity::usage_proto(
            &h.usage.read(),
            h.usage.running_for_ms().unwrap_or(0),
            h.frozen_total_ms(),
            speed,
            &h.info,
        );
        let phase = h.phase();
        u.state = match phase {
            P::Running => S::Running,
            P::Frozen => S::Frozen,
            P::Stopping => S::Stopping,
            P::Collecting => S::Collecting,
            P::Preparing | P::Starting => S::Unspecified,
        } as i32;
        if phase == P::Frozen {
            u.frozen_why =
                crate::activity_api::pause_cause(s.paused.as_ref().map(|p| p.1.as_str())) as i32;
        }
        Some(u)
    }
}

/// This device's record of one of its tasks on another device, removed when dropped (however
/// `run_task_until` returns).
struct RemoteRecord {
    node: Node,
    id: TaskId,
}

impl Drop for RemoteRecord {
    fn drop(&mut self) {
        let mut s = self.node.state();
        if s.remote.remove(&self.id).is_some() {
            s.activity_rev += 1;
        }
    }
}

impl Node {
    fn record_remote(
        &self,
        id: TaskId,
        lender: &PeerKey,
        grant: GrantId,
        spec: &TaskSpec,
        mode: ExecutionMode,
    ) -> RemoteRecord {
        let lender_name = self.peer_name(lender);
        let mut env_names: Vec<String> = spec
            .env
            .iter()
            .map(|(k, _)| crate::activity::show_env_name(k))
            .collect();
        env_names.sort();
        env_names.truncate(8);
        let mut s = self.state();
        // A grant this device does not hold (forgotten meanwhile): no limits known, so the
        // lender's memory and disk figures are bounded by the fixed ceilings only.
        let (limits, not_after) = s.borrowed.get(&grant).map_or(
            (
                gimmecores_core::Limits {
                    cpu_millis: 0,
                    memory_bytes: 0,
                    disk_bytes: 0,
                    gpu: Gpu::None,
                    max_concurrent_tasks: 0,
                },
                0,
            ),
            |b| (b.terms.limits, b.terms.not_after),
        );
        s.remote.insert(
            id,
            crate::remote::Remote {
                lender: *lender,
                lender_name,
                grant,
                limits,
                not_after,
                command: crate::activity::show_command(&spec.argv),
                env_names,
                env_total: spec.env.len(),
                image: spec.image.clone(),
                mode,
                cpu_millis: spec.cpu_millis,
                memory_bytes: spec.memory_bytes,
                timeout_secs: spec.timeout.as_secs(),
                created_at: crate::now(),
                sent: std::time::Instant::now(),
                phase: crate::remote::Phase::Waiting,
                report: None,
            },
        );
        s.activity_rev += 1;
        RemoteRecord {
            node: self.clone(),
            id,
        }
    }

    fn remote_phase(&self, id: TaskId, phase: crate::remote::Phase) {
        let mut s = self.state();
        let changed = s.remote.get_mut(&id).is_some_and(|t| {
            let changed = t.phase != phase;
            t.phase = phase;
            changed
        });
        if changed {
            s.activity_rev += 1;
        }
    }
}

/// Parallel upload streams for large uploads (one stream tops out well below a fast link).
const UPLOAD_STREAMS: usize = 4;
/// Below this, one stream: setting up more costs more than it saves.
const PARALLEL_UPLOAD_BYTES: u64 = 16 << 20;

/// Splits blobs into up to [`UPLOAD_STREAMS`] groups of similar total size (largest first).
fn upload_groups(mut blobs: Vec<(Digest, tree::Source)>) -> Vec<Vec<(Digest, tree::Source)>> {
    let total: u64 = blobs.iter().map(|(d, _)| d.size).sum();
    let n = if total >= PARALLEL_UPLOAD_BYTES {
        UPLOAD_STREAMS.min(blobs.len()).max(1)
    } else {
        1
    };
    blobs.sort_by_key(|b| std::cmp::Reverse(b.0.size));
    let mut groups: Vec<(u64, Vec<(Digest, tree::Source)>)> =
        (0..n).map(|_| (0, Vec::new())).collect();
    for b in blobs {
        let smallest = groups
            .iter_mut()
            .min_by_key(|(size, _)| *size)
            .expect("at least one group");
        smallest.0 += b.0.size;
        smallest.1.push(b);
    }
    groups
        .into_iter()
        .map(|(_, g)| g)
        .filter(|g| !g.is_empty())
        .collect()
}

/// One upload stream: names its blobs, sends those the lender still lacks, and waits for the
/// lender to confirm it stored and verified them.
async fn upload_stream(
    conn: iroh::endpoint::Connection,
    grant: GrantId,
    blobs: Vec<(Digest, tree::Source)>,
) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;
    wire::send(
        &mut send,
        Body::FindMissing(pb::FindMissingBlobs {
            digests: blobs.iter().map(|(d, _)| d.to_proto()).collect(),
            grant_id: grant.0.to_vec(),
        }),
    )
    .await?;
    let Body::Missing(missing) = wire::recv(&mut recv).await? else {
        bail!("unexpected reply to FindMissingBlobs");
    };
    let wanted: std::collections::BTreeSet<Digest> = missing
        .digests
        .iter()
        .map(Digest::from_proto)
        .collect::<Result<_>>()?;
    for (d, src) in &blobs {
        if !wanted.contains(d) {
            continue; // another stream (or task) already sent it
        }
        match src {
            tree::Source::Bytes(data) => {
                ensure!(
                    Digest::of(data) == *d,
                    "a file changed while it was being sent"
                );
                send_blob(&mut send, d, data, &grant.0).await?;
            }
            tree::Source::File(path) => send_file_blob(&mut send, d, path, &grant.0).await?,
        }
    }
    send.finish()?;
    match wire::recv(&mut recv).await? {
        Body::Missing(m) if m.digests.is_empty() => Ok(()),
        _ => bail!("lender did not confirm the upload"),
    }
}

/// Streams a file blob in chunks, hashing as it goes: memory stays at one chunk, and a file
/// that changed since it was hashed is refused (the lender also checks every blob).
async fn send_file_blob(
    send: &mut SendStream,
    d: &Digest,
    path: &Path,
    grant: &[u8],
) -> Result<()> {
    use sha2::Digest as _;
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("reading {}", path.display()))?;
    let mut hasher = sha2::Sha256::new();
    let mut offset = 0u64;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let mut filled = 0;
        while filled < buf.len() {
            let n = file.read(&mut buf[filled..]).await?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        let end = offset + filled as u64;
        ensure!(end <= d.size, "a file changed while it was being sent");
        hasher.update(&buf[..filled]);
        let last = end == d.size;
        if last {
            let hash: [u8; 32] = hasher.clone().finalize().into();
            ensure!(hash == d.hash, "a file changed while it was being sent");
        }
        if filled > 0 || offset == 0 {
            wire::send(
                send,
                Body::BlobChunk(pb::BlobChunk {
                    digest: Some(d.to_proto()),
                    offset,
                    data: buf[..filled].to_vec(),
                    last,
                    grant_id: grant.to_vec(),
                }),
            )
            .await?;
        }
        offset = end;
        if last {
            return Ok(());
        }
        ensure!(filled > 0, "a file changed while it was being sent");
    }
}

async fn send_blob(send: &mut SendStream, d: &Digest, data: &[u8], grant: &[u8]) -> Result<()> {
    if data.is_empty() {
        return wire::send(
            send,
            Body::BlobChunk(pb::BlobChunk {
                digest: Some(d.to_proto()),
                offset: 0,
                data: vec![],
                last: true,
                grant_id: grant.to_vec(),
            }),
        )
        .await;
    }
    let mut offset = 0usize;
    for chunk in data.chunks(CHUNK) {
        let last = offset + chunk.len() == data.len();
        wire::send(
            send,
            Body::BlobChunk(pb::BlobChunk {
                digest: Some(d.to_proto()),
                offset: offset as u64,
                data: chunk.to_vec(),
                last,
                grant_id: grant.to_vec(),
            }),
        )
        .await?;
        offset += chunk.len();
    }
    Ok(())
}

async fn fetch_blob(
    send: &mut SendStream,
    recv: &mut RecvStream,
    grant: GrantId,
    d: &Digest,
) -> Result<Vec<u8>> {
    wire::send(
        send,
        Body::BlobGet(pb::BlobGet {
            digest: Some(d.to_proto()),
            offset: 0,
            grant_id: grant.0.to_vec(),
        }),
    )
    .await?;
    recv_blob(recv, d).await
}

async fn recv_blob(recv: &mut RecvStream, d: &Digest) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    loop {
        let Body::BlobChunk(c) = wire::recv(recv).await? else {
            bail!("expected BlobChunk");
        };
        ensure!(c.offset == data.len() as u64, "out-of-order chunk");
        ensure!(
            (data.len() + c.data.len()) as u64 <= d.size && d.size <= tree::MAX_TREE_BYTES,
            "blob larger than declared"
        );
        data.extend_from_slice(&c.data);
        if c.last {
            break;
        }
    }
    ensure!(
        Digest::of(&data) == *d,
        "blob content does not match its digest"
    );
    Ok(data)
}

/// Files read-only (folders stay removable by the daemon; the sandbox is what stops tasks).
fn make_read_only(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for e in ignore::WalkBuilder::new(dir)
            .standard_filters(false)
            .follow_links(false)
            .build()
        {
            let e = e?;
            if e.file_type().is_some_and(|t| t.is_file()) {
                let mode = e.metadata()?.permissions().mode() & 0o555;
                std::fs::set_permissions(e.path(), std::fs::Permissions::from_mode(mode))?;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn human_bytes(n: u64) -> String {
    if n >= 1 << 30 {
        format!("{:.1} GiB", n as f64 / f64::from(1u32 << 30))
    } else {
        format!("{} MiB", n >> 20)
    }
}

/// What a grant may keep on the lender's disk: its files and workspaces, plus the image layers
/// it sends while they wait to be loaded, within what its image allowance has left once the
/// images Docker holds for the borrower (`held`) are counted.
fn disk_allowance(t: &gimmecores_core::GrantTerms, held: u64) -> u64 {
    t.limits
        .disk_bytes
        .saturating_add(t.images_bytes.saturating_sub(held))
}

/// Removes a task's folder, also where the task left folders it may not write (it can: the
/// sandbox runs as the daemon's user, and container files are handed back to it): those are
/// made writable first, without following links.
pub(crate) fn remove_workspace(path: &std::path::Path) {
    if std::fs::remove_dir_all(path).is_ok() || std::fs::symlink_metadata(path).is_err() {
        return;
    }
    open_dirs(path);
    if let Err(e) = std::fs::remove_dir_all(path) {
        tracing::warn!("could not remove a task's folder {}: {e}", path.display());
    }
}

/// Makes every folder under `path` the owner's to read, enter and write (0700), never
/// following links: what a task locked can then be measured and removed.
pub(crate) fn open_dirs(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut todo = vec![path.to_path_buf()];
        while let Some(p) = todo.pop() {
            // `symlink_metadata`: a link to a folder is not a folder, so nothing outside is
            // touched.
            if !std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_dir()) {
                continue;
            }
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700));
            if let Ok(rd) = std::fs::read_dir(&p) {
                todo.extend(rd.flatten().map(|e| e.path()));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(size: u64, n: u8) -> (Digest, tree::Source) {
        (
            Digest {
                hash: [n; 32],
                size,
            },
            tree::Source::Bytes(vec![]),
        )
    }

    #[test]
    fn large_uploads_are_spread_evenly_over_parallel_streams() {
        let small: Vec<_> = (0..10).map(|i| blob(1 << 10, i)).collect();
        assert_eq!(
            upload_groups(small).len(),
            1,
            "small uploads use one stream"
        );
        let big: Vec<_> = (0..9).map(|i| blob(8 << 20, i)).collect();
        let groups = upload_groups(big);
        assert_eq!(groups.len(), UPLOAD_STREAMS);
        let sizes: Vec<u64> = groups
            .iter()
            .map(|g| g.iter().map(|(d, _)| d.size).sum())
            .collect();
        assert!(sizes.iter().max().unwrap() - sizes.iter().min().unwrap() <= 8 << 20);
        assert_eq!(
            groups.iter().map(Vec::len).sum::<usize>(),
            9,
            "every blob once"
        );
        assert_eq!(
            upload_groups(vec![blob(1 << 30, 1)]).len(),
            1,
            "one blob, one stream"
        );
        assert!(upload_groups(vec![]).is_empty());
    }
}

#[cfg(all(test, unix))]
mod remove_tests {
    use super::remove_workspace;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn folders_the_task_locked_are_removed_and_links_are_not_followed() {
        let outside = tempfile::tempdir().unwrap();
        let keep = outside.path().join("keep");
        std::fs::create_dir(&keep).unwrap();
        std::fs::write(keep.join("f"), "x").unwrap();
        std::fs::set_permissions(&keep, std::fs::Permissions::from_mode(0o500)).unwrap();
        let ws = tempfile::tempdir().unwrap().keep();
        std::fs::create_dir_all(ws.join("a/b")).unwrap();
        std::fs::write(ws.join("a/b/f"), "x").unwrap();
        std::os::unix::fs::symlink(&keep, ws.join("a/link")).unwrap();
        for d in ["a/b", "a"] {
            std::fs::set_permissions(ws.join(d), std::fs::Permissions::from_mode(0o500)).unwrap();
        }
        remove_workspace(&ws);
        assert!(std::fs::symlink_metadata(&ws).is_err(), "left behind");
        let mode = std::fs::metadata(&keep).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o500, "a folder outside, behind a link, was changed");
        assert!(keep.join("f").exists());
        std::fs::set_permissions(&keep, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
