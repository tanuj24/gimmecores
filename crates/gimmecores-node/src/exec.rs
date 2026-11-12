//! Running tasks on the lender.
//!
//! [`DockerExecutor`] is the real sandbox (threat model 5.1). The flags are built by
//! [`docker_args`] so they can be unit-tested. [`ProcessExecutor`] runs plain local processes
//! with no isolation and exists only behind the test-only `insecure-test-executor` feature.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use gimmecores_core::{ExecutionMode, Modes};
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Hard limit on processes inside one task (fork-bomb protection).
pub const PIDS_LIMIT: u32 = 512;
/// Size of the writable `/tmp` inside the container.
pub const TMPFS_BYTES: u64 = 1 << 30;

#[derive(Clone, Debug)]
pub struct RunSpec {
    /// Unique, filesystem-safe name (also the container name).
    pub name: String,
    pub argv: Vec<String>,
    /// Host directory mounted as the task's working directory.
    pub workdir: PathBuf,
    /// OCI image (required by the Docker executor).
    pub image: Option<String>,
    pub cpu_millis: u32,
    pub memory_bytes: u64,
    pub timeout: Duration,
    /// Only explicitly declared variables; never the lender's environment.
    pub env: Vec<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunEnd {
    Exited(i32),
    TimedOut,
    Cancelled,
    /// The runner stopped the task for going over a limit (the reason says which).
    LimitExceeded(String),
}

#[derive(Clone, Debug)]
pub struct LogChunk {
    pub stderr: bool,
    pub data: Vec<u8>,
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Executor: Send + Sync {
    fn name(&self) -> &'static str;
    fn run<'a>(
        &'a self,
        spec: RunSpec,
        logs: mpsc::Sender<LogChunk>,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<RunEnd>>;

    /// Freezes a running task (laptop protections). Default: no-op.
    fn freeze<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }

    /// Resumes a frozen task. Default: no-op.
    fn thaw<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }

    /// Whether this runner works on this machine right now (a real, trivial run where
    /// possible). Only probed runners are advertised and used.
    fn probe(&self) -> BoxFuture<'_, bool> {
        Box::pin(async { true })
    }
}

/// The short name users see for a mode.
pub fn mode_name(m: ExecutionMode) -> &'static str {
    match m {
        ExecutionMode::Container => "container",
        ExecutionMode::Sandbox => "sandbox",
        ExecutionMode::Native => "native",
    }
}

/// The runners a node has, one per execution mode. A missing runner means the mode is not
/// available here; tasks never fall back from one mode to another.
#[derive(Clone, Default)]
pub struct Executors {
    pub container: Option<Arc<dyn Executor>>,
    pub sandbox: Option<Arc<dyn Executor>>,
}

impl Executors {
    /// Test-only: the unsandboxed process runner standing in for every mode.
    #[cfg(feature = "insecure-test-executor")]
    pub fn test_processes() -> Self {
        let p: Arc<dyn Executor> = Arc::new(ProcessExecutor::default());
        Self {
            container: Some(p.clone()),
            sandbox: Some(p),
        }
    }

    pub fn get(&self, m: ExecutionMode) -> Option<&Arc<dyn Executor>> {
        match m {
            ExecutionMode::Container => self.container.as_ref(),
            ExecutionMode::Sandbox => self.sandbox.as_ref(),
            ExecutionMode::Native => None,
        }
    }

    pub fn all(&self) -> impl Iterator<Item = &Arc<dyn Executor>> {
        self.container.iter().chain(self.sandbox.iter())
    }

    /// Modes whose runner passes its probe now.
    pub async fn probe(&self) -> Modes {
        let mut m = Modes::NONE;
        for mode in [ExecutionMode::Container, ExecutionMode::Sandbox] {
            if let Some(e) = self.get(mode)
                && e.probe().await
            {
                m = m.with(mode);
            }
        }
        m
    }
}

pub(crate) async fn quiet(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
}

pub(crate) fn validate(spec: &RunSpec) -> Result<()> {
    ensure!(!spec.argv.is_empty(), "empty command");
    ensure!(
        spec.name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "invalid task name"
    );
    for (k, _) in &spec.env {
        ensure!(
            !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "invalid environment variable name {k:?}"
        );
    }
    Ok(())
}

/// `docker run` arguments for a task: no network, no capabilities, no privilege escalation,
/// read-only root filesystem, unprivileged user, hard CPU/RAM/process caps, no swap.
pub fn docker_args(spec: &RunSpec) -> Result<Vec<String>> {
    validate(spec)?;
    let image = spec
        .image
        .as_deref()
        .context("container tasks need an image")?;
    ensure!(!image.starts_with('-'), "invalid image name");
    let mut a: Vec<String> = vec![
        "run".into(),
        "--rm".into(),
        // Never download anything on the lender's behalf: the consent screen promises it.
        "--pull".into(),
        "never".into(),
        "--name".into(),
        spec.name.clone(),
        "--network".into(),
        "none".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--read-only".into(),
        // Memory-backed scratch space, also the task's home: build and test tools write caches
        // there and run what they build (so no `noexec`; the task folder is executable anyway).
        "--tmpfs".into(),
        format!("/tmp:rw,exec,nosuid,size={TMPFS_BYTES}"),
        "--env".into(),
        "HOME=/tmp".into(),
        "--env".into(),
        "TMPDIR=/tmp".into(),
        "--user".into(),
        "65534:65534".into(),
        "--pids-limit".into(),
        PIDS_LIMIT.to_string(),
        "--cpus".into(),
        format!("{:.3}", f64::from(spec.cpu_millis) / 1000.0),
        "--memory".into(),
        format!("{}b", spec.memory_bytes),
        "--memory-swap".into(),
        format!("{}b", spec.memory_bytes),
        "--volume".into(),
        format!("{}:/work:rw", spec.workdir.display()),
        "--workdir".into(),
        "/work".into(),
    ];
    for (k, v) in &spec.env {
        a.push("--env".into());
        a.push(format!("{k}={v}"));
    }
    a.push("--".into());
    a.push(image.to_string());
    a.extend(spec.argv.iter().cloned());
    Ok(a)
}

pub(crate) async fn pump(
    mut r: impl tokio::io::AsyncRead + Unpin,
    stderr: bool,
    tx: mpsc::Sender<LogChunk>,
) {
    let mut buf = vec![0u8; 16 * 1024];
    while let Ok(n) = r.read(&mut buf).await {
        if n == 0
            || tx
                .send(LogChunk {
                    stderr,
                    data: buf[..n].to_vec(),
                })
                .await
                .is_err()
        {
            break;
        }
    }
}

/// Waits for the child, streaming its output; stops it on cancel or timeout.
pub(crate) async fn supervise<F>(
    mut child: Child,
    logs: mpsc::Sender<LogChunk>,
    cancel: CancellationToken,
    timeout: Duration,
    stop: F,
) -> Result<RunEnd>
where
    F: Future<Output = ()>,
{
    let out = child
        .stdout
        .take()
        .map(|s| tokio::spawn(pump(s, false, logs.clone())));
    let err = child
        .stderr
        .take()
        .map(|s| tokio::spawn(pump(s, true, logs.clone())));
    let end = tokio::select! {
        status = child.wait() => RunEnd::Exited(status?.code().unwrap_or(-1)),
        () = cancel.cancelled() => RunEnd::Cancelled,
        () = tokio::time::sleep(timeout) => RunEnd::TimedOut,
    };
    // Cancelled or timed out: stop the container (or process group) and the process.
    let stopped = !matches!(end, RunEnd::Exited(_));
    if stopped {
        stop.await;
        let _ = child.kill().await;
    }
    for mut h in [out, err].into_iter().flatten() {
        if stopped {
            // A leftover process holding the pipe must never stall a revoke (I3), nor keep
            // the log stream open: stop reading after 5 s.
            if tokio::time::timeout(Duration::from_secs(5), &mut h)
                .await
                .is_err()
            {
                h.abort();
            }
        } else {
            let _ = h.await;
        }
    }
    Ok(end)
}

pub struct DockerExecutor {
    pub docker: String,
}

impl Default for DockerExecutor {
    fn default() -> Self {
        Self {
            docker: "docker".into(),
        }
    }
}

impl DockerExecutor {
    /// True if the Docker daemon answers within 5 seconds.
    pub async fn available(&self) -> bool {
        let probe = Command::new(&self.docker)
            .args(["info", "--format", "{{.ServerVersion}}"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status();
        matches!(
            tokio::time::timeout(Duration::from_secs(5), probe).await,
            Ok(Ok(s)) if s.success()
        )
    }
}

impl Executor for DockerExecutor {
    fn name(&self) -> &'static str {
        "docker"
    }

    fn probe(&self) -> BoxFuture<'_, bool> {
        Box::pin(self.available())
    }

    fn run<'a>(
        &'a self,
        spec: RunSpec,
        logs: mpsc::Sender<LogChunk>,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<RunEnd>> {
        Box::pin(async move {
            let args = docker_args(&spec)?;
            let image = spec.image.clone().unwrap_or_default();
            let present = Command::new(&self.docker)
                .args(["image", "inspect", "--format", "{{.Id}}", "--", &image])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
                .is_ok_and(|s| s.success());
            if !present {
                anyhow::bail!(
                    "image {image} is not on the lender; GimmeCores never downloads images. \
                     The lender's owner can run `docker pull {image}` to allow it"
                );
            }
            let child = Command::new(&self.docker)
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .context("starting docker")?;
            let docker = self.docker.clone();
            let name = spec.name.clone();
            let stop = async move {
                // A frozen (paused) container is resumed first so the kill cannot hang.
                quiet(&docker, &["unpause", &name]).await;
                let _ = Command::new(docker)
                    .args(["kill", &name])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .await;
            };
            let end = supervise(child, logs, cancel, spec.timeout, stop).await;
            // On Linux, files the task created belong to the container's user, so the daemon
            // could neither measure nor delete them. Hand them over (same image, no network,
            // same unprivileged user, a few hundred milliseconds). Docker Desktop on macOS maps
            // ownership itself.
            if cfg!(target_os = "linux") {
                let mount = format!("{}:/work:rw", spec.workdir.display());
                quiet(
                    &self.docker,
                    &[
                        "run",
                        "--rm",
                        "--pull",
                        "never",
                        "--network",
                        "none",
                        "--cap-drop",
                        "ALL",
                        "--user",
                        "65534:65534",
                        "--volume",
                        &mount,
                        "--entrypoint",
                        "chmod",
                        "--",
                        &image,
                        "-R",
                        "a+rwX",
                        "/work",
                    ],
                )
                .await;
            }
            end
        })
    }

    fn freeze<'a>(&'a self, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move { quiet(&self.docker, &["pause", name]).await })
    }

    fn thaw<'a>(&'a self, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move { quiet(&self.docker, &["unpause", name]).await })
    }
}

/// Runs tasks as plain local processes. **No sandbox.** Test-only.
#[cfg(feature = "insecure-test-executor")]
#[derive(Default)]
pub struct ProcessExecutor {
    groups: std::sync::Mutex<std::collections::HashMap<String, u32>>,
}

#[cfg(feature = "insecure-test-executor")]
impl ProcessExecutor {
    fn group(&self, name: &str) -> Option<u32> {
        self.groups
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(name)
            .copied()
    }
}

#[cfg(feature = "insecure-test-executor")]
impl Executor for ProcessExecutor {
    fn name(&self) -> &'static str {
        "insecure-process"
    }

    fn run<'a>(
        &'a self,
        spec: RunSpec,
        logs: mpsc::Sender<LogChunk>,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<RunEnd>> {
        Box::pin(async move {
            validate(&spec)?;
            let mut cmd = Command::new(&spec.argv[0]);
            cmd.args(&spec.argv[1..])
                .current_dir(&spec.workdir)
                .env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .envs(spec.env.iter().cloned())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            // Own process group, so stopping the task also stops everything it started.
            #[cfg(unix)]
            cmd.process_group(0);
            let child = cmd.spawn().context("starting process")?;
            let pgid = child.id();
            if let Some(id) = pgid {
                self.groups
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(spec.name.clone(), id);
            }
            let stop = async move {
                #[cfg(unix)]
                if let Some(pgid) = pgid {
                    let _ = Command::new("kill")
                        .args(["-KILL", "--", &format!("-{pgid}")])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                        .await;
                }
                #[cfg(not(unix))]
                let _ = pgid;
            };
            let end = supervise(child, logs, cancel, spec.timeout, stop).await;
            self.groups
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&spec.name);
            end
        })
    }

    fn freeze<'a>(&'a self, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if let Some(g) = self.group(name) {
                quiet("kill", &["-STOP", "--", &format!("-{g}")]).await;
            }
        })
    }

    fn thaw<'a>(&'a self, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if let Some(g) = self.group(name) {
                quiet("kill", &["-CONT", "--", &format!("-{g}")]).await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> RunSpec {
        RunSpec {
            name: "gmc-0123abcd".into(),
            argv: vec!["pytest".into(), "-q".into()],
            workdir: PathBuf::from("/work/dir"),
            image: Some("python:3.12-slim".into()),
            cpu_millis: 2500,
            memory_bytes: 4 << 30,
            timeout: Duration::from_secs(60),
            env: vec![("CI".into(), "1".into())],
        }
    }

    fn has_pair(args: &[String], flag: &str, value: &str) -> bool {
        args.windows(2).any(|w| w[0] == flag && w[1] == value)
    }

    #[test]
    fn docker_flags_enforce_the_sandbox() {
        let a = docker_args(&spec()).unwrap();
        assert!(has_pair(&a, "--network", "none"), "I5: no network");
        assert!(has_pair(&a, "--pull", "never"), "never downloads images");
        assert!(has_pair(&a, "--cap-drop", "ALL"));
        assert!(has_pair(&a, "--security-opt", "no-new-privileges"));
        assert!(a.contains(&"--read-only".to_string()));
        assert!(has_pair(&a, "--user", "65534:65534"), "never root");
        assert!(has_pair(&a, "--pids-limit", "512"));
        assert!(has_pair(&a, "--cpus", "2.500"));
        assert!(has_pair(&a, "--memory", &format!("{}b", 4u64 << 30)));
        assert!(
            has_pair(&a, "--memory-swap", &format!("{}b", 4u64 << 30)),
            "no swap"
        );
        assert!(
            has_pair(&a, "--volume", "/work/dir:/work:rw"),
            "I4: only the workspace"
        );
        assert!(
            !a.iter().any(|x| x.contains("docker.sock")),
            "never the Docker socket"
        );
        assert!(!a.iter().any(|x| x == "--privileged"));
        let sep = a.iter().position(|x| x == "--").unwrap();
        assert_eq!(&a[sep + 1..], ["python:3.12-slim", "pytest", "-q"]);
    }

    #[test]
    fn hostile_inputs_are_rejected() {
        let mut s = spec();
        s.image = Some("--privileged".into());
        assert!(docker_args(&s).is_err(), "image cannot smuggle a flag");
        let mut s = spec();
        s.name = "x; rm -rf /".into();
        assert!(docker_args(&s).is_err());
        let mut s = spec();
        s.env = vec![("A=B --privileged".into(), "x".into())];
        assert!(docker_args(&s).is_err());
        let mut s = spec();
        s.argv.clear();
        assert!(docker_args(&s).is_err());
        let mut s = spec();
        s.image = None;
        assert!(docker_args(&s).is_err());
    }

    #[cfg(all(unix, feature = "insecure-test-executor"))]
    #[tokio::test]
    async fn process_executor_streams_logs_and_can_be_cancelled() {
        let exe = ProcessExecutor::default();
        let dir = tempfile::tempdir().unwrap();
        let (tx, mut rx) = mpsc::channel(16);
        let mut s = spec();
        s.workdir = dir.path().to_path_buf();
        s.argv = vec![
            "sh".into(),
            "-c".into(),
            "echo hi; echo oops >&2; exit 3".into(),
        ];
        let end = exe
            .run(s.clone(), tx, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(end, RunEnd::Exited(3));
        let mut out = Vec::new();
        while let Ok(c) = rx.try_recv() {
            out.push((c.stderr, String::from_utf8(c.data).unwrap()));
        }
        assert!(out.contains(&(false, "hi\n".into())));
        assert!(out.contains(&(true, "oops\n".into())));

        let cancel = CancellationToken::new();
        let (tx, _rx) = mpsc::channel(16);
        s.argv = vec!["sleep".into(), "30".into()];
        let c2 = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            c2.cancel();
        });
        let started = std::time::Instant::now();
        let end = exe.run(s.clone(), tx, cancel).await.unwrap();
        assert_eq!(end, RunEnd::Cancelled);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "I3: stopped promptly"
        );

        // A shell whose child keeps the output pipe open must still stop promptly.
        let cancel = CancellationToken::new();
        let (tx, _rx) = mpsc::channel(16);
        s.argv = vec![
            "sh".into(),
            "-c".into(),
            "echo started; sleep 30; echo never".into(),
        ];
        let c3 = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            c3.cancel();
        });
        let started = std::time::Instant::now();
        let end = exe.run(s, tx, cancel).await.unwrap();
        assert_eq!(end, RunEnd::Cancelled);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "grandchild processes are killed too"
        );
    }

    #[cfg(all(unix, feature = "insecure-test-executor"))]
    #[tokio::test]
    async fn frozen_tasks_make_no_progress_until_thawed() {
        let exe = std::sync::Arc::new(ProcessExecutor::default());
        let dir = tempfile::tempdir().unwrap();
        let mut s = spec();
        s.workdir = dir.path().to_path_buf();
        s.argv = vec![
            "sh".into(),
            "-c".into(),
            "while true; do echo tick; sleep 0.05; done".into(),
        ];
        let (tx, mut rx) = mpsc::channel(1024);
        let cancel = CancellationToken::new();
        let run = {
            let (exe, s, c) = (exe.clone(), s.clone(), cancel.clone());
            tokio::spawn(async move { exe.run(s, tx, c).await })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        exe.freeze(&s.name).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        while rx.try_recv().is_ok() {}
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(
            rx.try_recv().is_err(),
            "a frozen task must not produce output"
        );
        exe.thaw(&s.name).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(rx.try_recv().is_ok(), "a thawed task continues");
        cancel.cancel();
        assert_eq!(run.await.unwrap().unwrap(), RunEnd::Cancelled);
    }
}
