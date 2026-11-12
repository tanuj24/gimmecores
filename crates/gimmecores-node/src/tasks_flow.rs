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
    pub cpu_millis: u32,
    pub memory_bytes: u64,
    pub timeout: Duration,
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

impl Node {
    /// Disk the borrower may still fill with stored files under `grant`: the grant's disk limit
    /// minus what its running tasks' workspaces hold.
    fn blob_quota(&self, peer: &PeerKey, grant: GrantId) -> Result<u64, Denied> {
        let s = self.state();
        s.grants.authorize_blobs(*peer, grant, now())?;
        let limit = s.grants.terms(grant).map_or(0, |t| t.limits.disk_bytes);
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
                        (
                            s.grants.terms(grant).map_or(0, |t| t.limits.disk_bytes),
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
        let s = self.state();
        if let Some((owner, token)) = s.running.get(&task)
            && *owner == remote
        {
            token.cancel();
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
        let image = match t.env.and_then(|e| e.kind) {
            Some(pb::environment::Kind::Image(img)) => Some(img.reference),
            Some(_) => bail!("only image environments are supported in this version"),
            None => None,
        };
        match (mode, &image) {
            (ExecutionMode::Sandbox, Some(_)) => bail!(
                "sandbox tasks use the lender's installed tools; an image needs container mode"
            ),
            (ExecutionMode::Container, None) => bail!("container tasks need an image (--image)"),
            _ => {}
        }
        let limits = t.limits.context("missing limits")?;
        let input_root = Digest::from_proto(t.input_root.as_ref().context("missing input root")?)?;
        let outputs = t
            .output_paths
            .iter()
            .map(|p| tree::validate_output_path(p).map(|_| p.clone()))
            .collect::<Result<Vec<_>>>()?;

        // I1: nothing runs unless the grant book says yes.
        let req = TaskRequest {
            cpu_millis: limits.cpu_millis,
            memory_bytes: limits.memory_bytes,
            disk_bytes: 0,
            gpu: Gpu::None,
            mode,
            network: NetworkPolicy::None,
        };
        // I11, strict: the task is recorded before anything runs.
        self.audit(
            "task",
            Some(&remote),
            format!(
                "starting for {}: {}",
                self.peer_name(&remote),
                cmd.argv.join(" ")
            ),
            serde_json::json!({
                "task": hex::encode(task.0),
                "grant": hex::encode(grant.0),
                "argv": cmd.argv,
                "image": image,
                "mode": mode_name,
                "cpu_millis": limits.cpu_millis,
                "memory_bytes": limits.memory_bytes,
                "input_root": input_root.hex(),
            }),
        )?;
        let token = CancellationToken::new();
        let not_after = {
            let mut s = self.state();
            if let Err(d) = s.grants.start_task(remote, grant, task, req, now()) {
                if let Some((_, why, _, _)) = &s.paused {
                    bail!("the lender is paused ({why}); try again later");
                }
                bail!("refused: {d:?}");
            }
            s.running.insert(task, (remote, token.clone()));
            s.grants.terms(grant).map_or(0, |g| g.not_after)
        };
        let workspace = self.inner.paths.work_dir().join(hex::encode(task.0));
        let result = self
            .execute(
                remote,
                grant,
                task,
                &cmd,
                exec,
                image,
                &input_root,
                &outputs,
                limits,
                t.timeout,
                not_after,
                &workspace,
                token.clone(),
                send,
            )
            .await;
        // Stopped while it was still being set up (for example a revoke deleted its input files
        // mid-unpack): report why it stopped, not the setup error that followed.
        let result = match result {
            Err(_) if token.is_cancelled() => {
                let ended = matches!(
                    self.state().grants.state(grant),
                    Some(GrantState::Revoked | GrantState::Expired)
                );
                Ok(pb::TaskResult {
                    status: if ended {
                        Status::Revoked
                    } else {
                        Status::Cancelled
                    } as i32,
                    exit_code: -1,
                    ..Default::default()
                })
            }
            other => other,
        };
        {
            let mut s = self.state();
            s.grants.finish_task(task);
            s.running.remove(&task);
            s.workspace_bytes.remove(&task);
        }
        let _ = std::fs::remove_dir_all(&workspace);
        let summary = match &result {
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
        image: Option<String>,
        input_root: &Digest,
        outputs: &[String],
        limits: pb::Limits,
        timeout: Option<prost_types::Duration>,
        not_after: u64,
        workspace: &Path,
        token: CancellationToken,
        send: &mut SendStream,
    ) -> Result<pb::TaskResult> {
        // I4: a fresh workspace holding only the borrower's own input tree.
        {
            let (blobs, ws, root) = (
                self.inner.blobs.clone(),
                workspace.to_path_buf(),
                *input_root,
            );
            tokio::task::spawn_blocking(move || -> Result<()> {
                tree::materialize(&blobs, &remote, &root, &ws)?;
                open_workspace(&ws)
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
        let spec = RunSpec {
            name: format!("gmc-{}", hex::encode(task.0)),
            argv: cmd.argv.clone(),
            workdir,
            image,
            cpu_millis: limits.cpu_millis,
            memory_bytes: limits.memory_bytes,
            timeout: requested.min(until_expiry),
            env: cmd
                .environment
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        };
        wire::send(
            send,
            Body::TaskEvent(pb::TaskEvent {
                task_id: task.0.to_vec(),
                event: Some(Event::Started(pb::Started {
                    at: None,
                    warm: false,
                })),
            }),
        )
        .await?;

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
        while let Some(chunk) = rx.recv().await {
            let event = pb::TaskEvent {
                task_id: task.0.to_vec(),
                event: Some(Event::Log(pb::LogChunk {
                    stream: if chunk.stderr {
                        pb::log_chunk::Stream::Stderr as i32
                    } else {
                        pb::log_chunk::Stream::Stdout as i32
                    },
                    data: chunk.data,
                })),
            };
            if wire::send(send, Body::TaskEvent(event)).await.is_err() {
                token.cancel(); // borrower went away
            }
        }
        let end = run.await;
        // Stop the watcher before anything can return early, so it never records this task's
        // workspace after the caller has forgotten it.
        watch_done.cancel();
        let over_limit = watcher.await.ok().flatten();
        let end = end??;
        let stopped_why = match &end {
            RunEnd::LimitExceeded(why) => Some(why.clone()),
            _ => over_limit.clone(),
        };
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
        for o in &spec.outputs {
            tree::validate_output_path(o)?;
        }
        let (dir, ex) = (spec.dir.clone(), spec.excludes.clone());
        let allow = spec.allow_secrets.clone();
        let (tree, findings) = tokio::task::spawn_blocking(move || -> Result<_> {
            let tree = tree::build(&dir, &ex)?;
            // I7: look inside every file about to leave this machine.
            let findings = crate::secrets::scan_files(
                tree.files
                    .iter()
                    .filter(|(_, rel)| !allow.iter().any(|a| a == rel))
                    .map(|(abs, rel)| (abs.as_path(), rel.as_path())),
            );
            Ok((tree, findings))
        })
        .await??;
        if !findings.is_empty() {
            bail!("{}", crate::secrets::describe(&findings));
        }
        let root = tree.root.context("empty tree")?;
        let conn = self.dial(lender).await?;

        // 1. Upload only what the lender is missing.
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
        let mut uploaded = 0u64;
        for d in &missing.digests {
            let d = Digest::from_proto(d)?;
            let src = tree
                .blobs
                .get(&d)
                .context("lender asked for an unknown blob")?;
            let data = src.read()?;
            ensure!(
                Digest::of(&data) == d,
                "a file changed while it was being sent"
            );
            send_blob(&mut send, &d, &data, &grant.0).await?;
            uploaded += d.size;
        }
        send.finish()?;
        match wire::recv(&mut recv).await? {
            Body::Missing(m) if m.digests.is_empty() => {}
            _ => bail!("lender did not confirm the upload"),
        }

        // 2. Submit and stream events.
        let task_id = wire::random32()?[..16].to_vec();
        let (mut send, mut recv) = conn.open_bi().await?;
        wire::send(
            &mut send,
            Body::SubmitTask(pb::SubmitTask {
                task_id: task_id.clone(),
                grant_id: grant.0.to_vec(),
                mode: crate::grants_flow::mode_to(spec.mode.unwrap_or(if spec.image.is_some() {
                    ExecutionMode::Container
                } else {
                    ExecutionMode::Sandbox
                })) as i32,
                env: spec.image.as_ref().map(|r| pb::Environment {
                    kind: Some(pb::environment::Kind::Image(pb::ImageEnv {
                        reference: r.clone(),
                        digest: String::new(),
                    })),
                }),
                work: Some(pb::submit_task::Work::Command(pb::Command {
                    argv: spec.argv.clone(),
                    working_directory: String::new(),
                    environment: Default::default(),
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
            }),
        )
        .await?;
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
                Some(Event::Finished(r)) => break r,
                _ => {}
            }
        };
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
            let dest = spec.dir.clone();
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
                spec.argv.join(" "),
                TaskStatus::from_proto(result.status),
                result.exit_code
            ),
            serde_json::json!({ "uploaded_bytes": uploaded, "output_bytes": output_bytes }),
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
