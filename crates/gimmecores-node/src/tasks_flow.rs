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
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3600);

/// What the borrower wants to run.
#[derive(Clone, Debug)]
pub struct TaskSpec {
    /// Project folder to send; outputs are written back into it.
    pub dir: PathBuf,
    pub argv: Vec<String>,
    pub image: Option<String>,
    pub outputs: Vec<String>,
    pub excludes: Vec<String>,
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
    fn blob_quota(&self, peer: &PeerKey, grant: GrantId) -> Result<u64, Denied> {
        let s = self.state();
        s.grants.authorize_blobs(*peer, grant, now())?;
        Ok(s.grants.terms(grant).map_or(0, |t| t.limits.disk_bytes))
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
        if t.mode == pb::ExecutionMode::Native as i32 {
            bail!("native mode is not available before M4");
        }
        if t.network == pb::NetworkPolicy::Internet as i32 {
            bail!("network access is not available before M4");
        }
        let image = match t.env.and_then(|e| e.kind) {
            Some(pb::environment::Kind::Image(img)) => Some(img.reference),
            Some(_) => bail!("only image environments are supported in this version"),
            None => None,
        };
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
            mode: ExecutionMode::Container,
            network: NetworkPolicy::None,
        };
        let token = CancellationToken::new();
        let not_after = {
            let mut s = self.state();
            s.grants
                .start_task(remote, grant, task, req, now())
                .map_err(|d| anyhow!("refused: {d:?}"))?;
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
                image,
                &input_root,
                &outputs,
                limits,
                t.timeout,
                not_after,
                &workspace,
                token,
                send,
            )
            .await;
        {
            let mut s = self.state();
            s.grants.finish_task(task);
            s.running.remove(&task);
        }
        let _ = std::fs::remove_dir_all(&workspace);
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute(
        &self,
        remote: PeerKey,
        grant: GrantId,
        task: TaskId,
        cmd: &pb::Command,
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
        let (tx, mut rx) = mpsc::channel::<LogChunk>(64);
        let exec = self.inner.executor.clone();
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
        let end = run.await??;

        let grant_ended = matches!(
            self.state().grants.state(grant),
            Some(GrantState::Revoked | GrantState::Expired)
        );
        let (status, exit_code) = match end {
            RunEnd::Exited(0) => (Status::Succeeded, 0),
            RunEnd::Exited(code) => (Status::Failed, code),
            RunEnd::TimedOut => (Status::TimedOut, -1),
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
                self.inner.blobs.put(&remote, d, &src.read()?, quota)?;
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
        let tree = tokio::task::spawn_blocking(move || tree::build(&dir, &ex)).await??;
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
                mode: pb::ExecutionMode::Container as i32,
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

        // 3. Fetch outputs into the project folder (I8: only declared paths, validated names).
        let mut output_bytes = 0;
        if let Some(out_root) = result.output_root.as_ref() {
            let out_root = Digest::from_proto(out_root)?;
            let (mut send, mut recv) = conn.open_bi().await?;
            let mut fetched = std::collections::BTreeMap::new();
            let mut queue = vec![out_root];
            while let Some(d) = queue.pop() {
                wire::send(
                    &mut send,
                    Body::BlobGet(pb::BlobGet {
                        digest: Some(d.to_proto()),
                        offset: 0,
                        grant_id: grant.0.to_vec(),
                    }),
                )
                .await?;
                let data = recv_blob(&mut recv, &d).await?;
                if let Ok(dir) = <pb::Directory as prost::Message>::decode(data.as_slice()) {
                    for f in dir.files.iter().filter_map(|f| f.digest.as_ref()) {
                        queue.push(Digest::from_proto(f)?);
                    }
                    for sub in dir.directories.iter().filter_map(|s| s.digest.as_ref()) {
                        queue.push(Digest::from_proto(sub)?);
                    }
                }
                fetched.insert(d, data);
            }
            send.finish()?;
            let dest = spec.dir.clone();
            output_bytes = tokio::task::spawn_blocking(move || {
                let mut fetch = |d: &Digest| fetched.get(d).cloned().context("missing output blob");
                tree::extract(&mut fetch, &out_root, &dest)
            })
            .await??;
        }

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
