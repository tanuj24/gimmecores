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
    /// Folders outside the task folder the task may read but never change: the borrower's
    /// packages the lender keeps between tasks (sandbox only).
    pub read_only: Vec<PathBuf>,
    /// Where the runner writes what the task uses (CPU, memory, processes). `None`: nothing
    /// is measured.
    pub usage: Option<std::sync::Arc<crate::usage::UsageCell>>,
    /// How it is scheduled against the owner's apps (the sandbox applies it; containers do
    /// not yet: docs/design/task-speed.md).
    pub speed: gimmecores_core::Speed,
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

    /// Freezes task `name` (laptop protections); true when this runner knows the task and froze it.
    fn freeze<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, bool> {
        Box::pin(async { false })
    }

    /// Lets a frozen task run again; true when this runner knows the task.
    fn thaw<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, bool> {
        Box::pin(async { false })
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
    /// Docker, to receive images borrowers send (docs/design/container-images.md). `None`:
    /// this device cannot receive images.
    pub images: Option<Arc<crate::images::DockerImages>>,
}

impl Executors {
    /// Test-only: the unsandboxed process runner standing in for every mode.
    #[cfg(feature = "insecure-test-executor")]
    pub fn test_processes() -> Self {
        let p: Arc<dyn Executor> = Arc::new(ProcessExecutor::default());
        Self {
            container: Some(p.clone()),
            sandbox: Some(p),
            images: None,
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
    let _ = quiet_ok(cmd, args).await;
}

/// Like [`quiet`]; true when the command succeeded.
pub(crate) async fn quiet_ok(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success())
}

pub(crate) fn validate(spec: &RunSpec) -> Result<()> {
    ensure!(!spec.argv.is_empty(), "empty command");
    ensure!(
        spec.name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "invalid task name"
    );
    check_env(&spec.env)
}

/// Variables a lender always sets itself; a task may not replace them.
const RESERVED_ENV: &[&str] = &["PATH", "HOME", "TMPDIR", "LANG", "DEVELOPER_DIR"];
/// At most this many task variables, of at most this many bytes in all.
pub const MAX_ENV_VARS: usize = 64;
pub const MAX_ENV_BYTES: usize = 64 * 1024;

/// A task's environment variables (secrets the borrower chose to send): plain names, none of
/// the lender's own or the dynamic loader's, bounded in number and size.
pub fn check_env(env: &[(String, String)]) -> Result<()> {
    ensure!(env.len() <= MAX_ENV_VARS, "too many environment variables");
    let mut total = 0usize;
    let mut seen = std::collections::BTreeSet::new();
    for (k, v) in env {
        ensure!(
            !k.is_empty()
                && k.len() <= 128
                && !k.starts_with(|c: char| c.is_ascii_digit())
                && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "invalid environment variable name {k:?}"
        );
        ensure!(
            !RESERVED_ENV.contains(&k.as_str()) && !k.starts_with("LD_") && !k.starts_with("DYLD_"),
            "{k} is set by the lender; a task cannot replace it"
        );
        ensure!(!v.contains('\0'), "{k} contains a NUL byte");
        ensure!(seen.insert(k.as_str()), "{k} given twice");
        total = total.saturating_add(k.len() + v.len());
    }
    ensure!(
        total <= MAX_ENV_BYTES,
        "environment variables are too large"
    );
    Ok(())
}

/// The task's image name, checked so it cannot pass for a `docker` flag.
fn image_of(spec: &RunSpec) -> Result<&str> {
    let image = spec
        .image
        .as_deref()
        .context("container tasks need an image")?;
    ensure!(!image.starts_with('-'), "invalid image name");
    Ok(image)
}

/// At most this many volumes in an image (each becomes a memory-backed folder).
pub const MAX_IMAGE_VOLUMES: usize = 32;

/// The folders an image declares as volumes, to be covered by memory-backed folders: Docker
/// would otherwise give each one a writable folder on its own disk, outside the read-only
/// system, the memory cap and the grant's disk limit (tested: 600 MB written with a 256 MB
/// cap). `/tmp` and `/work` are covered already. A declared path GimmeCores cannot cover
/// safely refuses the image.
pub fn cover_volumes(declared: impl IntoIterator<Item = String>) -> Result<Vec<String>> {
    let mut out = std::collections::BTreeSet::new();
    for v in declared {
        let p = v.trim_end_matches('/');
        ensure!(
            p.starts_with('/')
                && p.len() <= 255
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
                && !p.split('/').any(|c| c == ".." || c == "."),
            "the image declares a volume at {v:?}, which GimmeCores cannot cover safely; \
             the image is refused"
        );
        if p == "/tmp" || p == "/work" {
            continue;
        }
        out.insert(p.to_string());
    }
    ensure!(
        out.len() <= MAX_IMAGE_VOLUMES,
        "the image declares more than {MAX_IMAGE_VOLUMES} volumes; it is refused"
    );
    Ok(out.into_iter().collect())
}

/// `docker run` arguments for a task: no network, no capabilities, no privilege escalation,
/// read-only root filesystem, unprivileged user, hard CPU/RAM/process caps, no swap. Each of
/// `volumes` (from [`cover_volumes`]) is a memory-backed folder.
pub fn docker_args(spec: &RunSpec, volumes: &[String]) -> Result<Vec<String>> {
    validate(spec)?;
    // Kept packages are a sandbox feature; a container only ever sees its task folder.
    ensure!(
        spec.read_only.is_empty(),
        "containers take no extra folders"
    );
    let image = image_of(spec)?;
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
        // An image's health check would run commands of its own choosing alongside the task.
        "--no-healthcheck".into(),
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
        // Docker reads a relative path as a volume name: always the folder's absolute path.
        format!(
            "{}:/work:rw",
            std::path::absolute(&spec.workdir)
                .unwrap_or_else(|_| spec.workdir.clone())
                .display()
        ),
        "--workdir".into(),
        "/work".into(),
    ];
    // Memory-backed, so they count against `--memory` like `/tmp`.
    for v in volumes {
        a.push("--tmpfs".into());
        a.push(format!(
            "{v}:rw,exec,nosuid,size={}",
            TMPFS_BYTES.min(spec.memory_bytes)
        ));
    }
    // Names only: Docker takes each value from its own environment (set by the caller), so
    // values never appear on a command line that other accounts could list.
    for (k, _) in &spec.env {
        a.push("--env".into());
        a.push(k.clone());
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
            docker: locate_docker(),
        }
    }
}

/// The hand-back image found or made, by `docker` program: one per process, so runners
/// working at the same time do not each make their own.
#[cfg(unix)]
static HAND_BACK_IMAGES: std::sync::LazyLock<
    tokio::sync::Mutex<std::collections::BTreeMap<String, String>>,
> = std::sync::LazyLock::new(Default::default);

/// `docker` from PATH, else where Docker Desktop and Homebrew put it: a daemon started at
/// login (launchd) gets only the system PATH, and container mode would look unavailable.
pub fn locate_docker() -> String {
    let on_path = std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join("docker").is_file()));
    if on_path {
        return "docker".into();
    }
    let mut known = vec![
        std::path::PathBuf::from("/usr/local/bin/docker"),
        "/opt/homebrew/bin/docker".into(),
        "/Applications/Docker.app/Contents/Resources/bin/docker".into(),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        known.push(std::path::Path::new(&home).join(".docker/bin/docker"));
    }
    known
        .into_iter()
        .find(|p| p.is_file())
        .map_or_else(|| "docker".into(), |p| p.to_string_lossy().into_owned())
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

/// Repository of the image GimmeCores makes for the hand-back step; the tag is the start of
/// its layer's digest, so each machine layout has its own and nothing is ever removed.
pub const HAND_BACK_REPO: &str = "gimmecores.local/hand-back";

/// The lender's own system folders the hand-back step runs from, read-only, so that nothing
/// from the task's image runs in it: the lender's `chmod` and the libraries it needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandBackLayout {
    /// Top-level links recreated as links (`bin -> usr/bin` on merged-/usr systems).
    pub links: Vec<(String, String)>,
    /// Top-level folders mounted read-only.
    pub dirs: Vec<String>,
    /// The lender's `chmod`, inside those folders.
    pub chmod: String,
    /// Whether `/etc/ld.so.cache` is mounted too (the dynamic loader's index).
    pub ld_cache: bool,
}

const SYSTEM_DIRS: &[&str] = &["usr", "bin", "sbin", "lib", "lib32", "lib64", "libx32"];

/// This machine's layout, or `None` when its `chmod` is not in the usual folders.
pub fn hand_back_layout() -> Option<HandBackLayout> {
    let mut links = Vec::new();
    let mut dirs = Vec::new();
    for d in SYSTEM_DIRS {
        let p = std::path::Path::new("/").join(d);
        let Ok(m) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        if m.file_type().is_symlink() {
            let target = std::fs::read_link(&p).ok()?.to_str()?.to_string();
            links.push(((*d).to_string(), target));
        } else if m.is_dir() {
            dirs.push((*d).to_string());
        }
    }
    let chmod = ["/usr/bin/chmod", "/bin/chmod"]
        .into_iter()
        .find(|c| std::path::Path::new(c).is_file())?
        .to_string();
    Some(HandBackLayout {
        links,
        dirs,
        chmod,
        ld_cache: std::path::Path::new("/etc/ld.so.cache").is_file(),
    })
}

/// The hand-back image's only layer: empty folders to mount onto, and the top-level links.
/// No program, no settings: everything that runs comes from the lender's own folders.
pub fn hand_back_tar(layout: &HandBackLayout) -> Result<Vec<u8>> {
    // Owned by root, dated 1970: the same machine always makes the same layer.
    fn header(kind: tar::EntryType, mode: u32) -> tar::Header {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(kind);
        h.set_mode(mode);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(0);
        h.set_size(0);
        h
    }
    let mut b = tar::Builder::new(Vec::new());
    let dirs = layout
        .dirs
        .iter()
        .map(String::as_str)
        .chain(["work", "etc"]);
    for d in dirs {
        let mut h = header(tar::EntryType::Directory, 0o755);
        b.append_data(&mut h, format!("{d}/"), std::io::empty())?;
    }
    for (name, target) in &layout.links {
        let mut h = header(tar::EntryType::Symlink, 0o777);
        b.append_link(&mut h, name, target)?;
    }
    if layout.ld_cache {
        let mut h = header(tar::EntryType::Regular, 0o644);
        b.append_data(&mut h, "etc/ld.so.cache", std::io::empty())?;
    }
    Ok(b.into_inner()?)
}

/// `docker run` arguments for the hand-back step: the lender's `chmod`, from its own folders
/// (read-only) in the image GimmeCores made, as the task's own unprivileged user with no
/// capabilities, no network, and only the task folder writable. It opens up everything the
/// task made (`a+rwX`) and clears setuid, setgid and sticky bits, so the daemon can read and
/// remove it all, even folders the task locked. The user owns everything it made, so this
/// needs no privilege; and the task's image is not used at all, so its own `chmod` (or
/// loader, or `ld.so.preload`) cannot keep files locked or run in this step.
pub fn hand_back_args(
    image_id: &str,
    layout: &HandBackLayout,
    workdir: &std::path::Path,
    name: &str,
) -> Vec<String> {
    let mut a: Vec<String> = [
        "run",
        "--rm",
        "--pull",
        "never",
        "--name",
        name,
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--no-healthcheck",
        "--user",
        "65534:65534",
        "--cpus",
        "0.5",
        "--memory",
        "64m",
        "--pids-limit",
        "16",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    for d in &layout.dirs {
        a.push("--volume".into());
        a.push(format!("/{d}:/{d}:ro"));
    }
    if layout.ld_cache {
        a.push("--volume".into());
        a.push("/etc/ld.so.cache:/etc/ld.so.cache:ro".into());
    }
    a.push("--volume".into());
    a.push(format!(
        "{}:/work:rw",
        std::path::absolute(workdir)
            .unwrap_or_else(|_| workdir.to_path_buf())
            .display()
    ));
    a.push("--entrypoint".into());
    a.push(layout.chmod.clone());
    a.extend(
        ["--", image_id, "-R", "a+rwX,a-st", "/work"]
            .into_iter()
            .map(String::from),
    );
    a
}

/// The id of `inspected` (`docker image inspect` output) when it is the hand-back image:
/// exactly the one layer `layer` and none of the settings that would make Docker run or set
/// anything (a tag can be re-pointed by anyone who can use Docker here, so it is checked).
pub fn is_hand_back_image(inspected: &serde_json::Value, layer: &str) -> Option<String> {
    let v = inspected
        .as_array()
        .and_then(|a| a.first())
        .unwrap_or(inspected);
    let layers = v.pointer("/RootFS/Layers")?.as_array()?;
    if layers.len() != 1 || layers[0].as_str() != Some(layer) {
        return None;
    }
    let empty = |x: Option<&serde_json::Value>| match x {
        None | Some(serde_json::Value::Null) => true,
        Some(serde_json::Value::String(s)) => s.is_empty(),
        Some(serde_json::Value::Array(a)) => a.is_empty(),
        Some(serde_json::Value::Object(o)) => o.is_empty(),
        Some(_) => false,
    };
    let config = v.get("Config");
    let settings = [
        "Env",
        "Cmd",
        "Entrypoint",
        "User",
        "WorkingDir",
        "Volumes",
        "Healthcheck",
        "OnBuild",
        "Shell",
    ];
    if settings
        .iter()
        .any(|k| !empty(config.and_then(|c| c.get(*k))))
    {
        return None;
    }
    let id = v.get("Id")?.as_str()?;
    (id.starts_with("sha256:") && id.len() == 71).then(|| id.to_string())
}

impl DockerExecutor {
    /// The folders `image` declares as volumes; `None` when the image is not on this machine.
    async fn image_volumes(&self, image: &str) -> Result<Option<Vec<String>>> {
        let out = Command::new(&self.docker)
            .args([
                "image",
                "inspect",
                "--format",
                "{{json .Config.Volumes}}",
                "--",
                image,
            ])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .output()
            .await
            .context("asking Docker about the image")?;
        if !out.status.success() {
            return Ok(None);
        }
        let declared: Option<std::collections::BTreeMap<String, serde_json::Value>> =
            serde_json::from_slice(out.stdout.trim_ascii())
                .context("could not read the image's settings")?;
        Ok(Some(declared.unwrap_or_default().into_keys().collect()))
    }

    /// The hand-back image: the one already here if it is exactly [`hand_back_tar`] with no
    /// settings ([`is_hand_back_image`]), else made with `docker import` and used by the id
    /// it returns. Never removed, so another service on this machine can use it at the same time.
    #[cfg(unix)]
    async fn hand_back_image(&self, layout: &HandBackLayout) -> Result<String> {
        use sha2::Digest;
        use tokio::io::AsyncWriteExt;
        let mut made = HAND_BACK_IMAGES.lock().await;
        if let Some(id) = made.get(&self.docker)
            && quiet_ok(&self.docker, &["image", "inspect", "--", id]).await
        {
            return Ok(id.clone());
        }
        let tar = hand_back_tar(layout)?;
        let layer = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&tar)));
        let tag = format!("{HAND_BACK_REPO}:{}", &layer[7..19]);
        let here = Command::new(&self.docker)
            .args(["image", "inspect", "--format", "{{json .}}", "--", &tag])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .output()
            .await
            .context("asking Docker about the hand-back image")?;
        if here.status.success()
            && let Ok(v) = serde_json::from_slice::<serde_json::Value>(here.stdout.trim_ascii())
            && let Some(id) = is_hand_back_image(&v, &layer)
        {
            made.insert(self.docker.clone(), id.clone());
            return Ok(id);
        }
        let mut child = Command::new(&self.docker)
            .args([
                "import",
                "--change",
                "LABEL dev.gimmecores.purpose=hand-back",
                "-",
                &tag,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("starting docker import")?;
        let mut stdin = child.stdin.take().context("docker import's input")?;
        stdin.write_all(&tar).await?;
        drop(stdin);
        let out = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
            .await
            .context("docker import took too long")??;
        ensure!(
            out.status.success(),
            "docker import: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
        ensure!(
            id.starts_with("sha256:") && id.len() == 71,
            "docker import gave {id:?}, not an image id"
        );
        made.insert(self.docker.clone(), id.clone());
        Ok(id)
    }

    /// Compiled on every Unix so it is checked everywhere; called on Linux only.
    #[cfg(unix)]
    async fn hand_back(&self, spec: &RunSpec) {
        let Some(layout) = hand_back_layout() else {
            tracing::warn!(
                "could not hand the task's files back: this system's chmod is not in /usr/bin or /bin"
            );
            return;
        };
        let image = match self.hand_back_image(&layout).await {
            Ok(i) => i,
            Err(e) => {
                tracing::warn!("could not hand the task's files back: {e:#}");
                return;
            }
        };
        let name = format!("{}-handback", spec.name);
        let args = hand_back_args(&image, &layout, &spec.workdir, &name);
        let run = Command::new(&self.docker)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output();
        match tokio::time::timeout(Duration::from_secs(30), run).await {
            // `chmod` also reports the daemon's own files (the task's inputs), which the task's
            // user may not change and which need no change; a folder that really stays locked
            // is reported when the task folder cannot be removed.
            Ok(Ok(o)) if !o.status.success() => {
                tracing::debug!("hand-back: {}", String::from_utf8_lossy(&o.stderr).trim())
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => tracing::warn!("could not hand the task's files back: {e}"),
            Err(_) => {
                quiet(&self.docker, &["kill", &name]).await;
                tracing::warn!("handing the task's files back took too long and was stopped");
            }
        }
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
            validate(&spec)?;
            let image = image_of(&spec)?.to_string();
            let Some(declared) = self.image_volumes(&image).await? else {
                anyhow::bail!(
                    "image {image} is not on the lender; GimmeCores never downloads images. \
                     The lender's owner can run `docker pull {image}` to allow it"
                );
            };
            let args = docker_args(&spec, &cover_volumes(declared)?)?;
            let child = Command::new(&self.docker)
                .args(&args)
                .envs(spec.env.iter().cloned())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .context("starting docker")?;
            // The task is running (its figures are not measured yet: the runtime's stats are a
            // later step, so they read "not measured").
            if let Some(u) = &spec.usage {
                u.mark_spawned();
            }
            let docker = self.docker.clone();
            let name = spec.name.clone();
            let stop = async move {
                // A frozen (paused) container is resumed first so the kill cannot hang.
                quiet(&docker, &["unpause", &name]).await;
                quiet(&docker, &["kill", &name]).await;
                // Stopped between `create` and `start`, a container never ran, so `--rm` does
                // not remove it, and it would keep its image (a sent one could then never go).
                quiet(&docker, &["rm", "--force", "--", &name]).await;
            };
            let end = supervise(child, logs, cancel, spec.timeout, stop).await;
            // On Linux, files the task created belong to the container's user, which can lock
            // them away from the daemon (it could neither measure nor remove them). One short
            // run of the lender's own `chmod` as that same user opens them up
            // (`hand_back_args`). Docker Desktop on macOS maps ownership itself.
            #[cfg(unix)]
            if cfg!(target_os = "linux") {
                self.hand_back(&spec).await;
            }
            end
        })
    }

    fn freeze<'a>(&'a self, name: &'a str) -> BoxFuture<'a, bool> {
        Box::pin(async move { quiet_ok(&self.docker, &["pause", name]).await })
    }

    fn thaw<'a>(&'a self, name: &'a str) -> BoxFuture<'a, bool> {
        Box::pin(async move { quiet_ok(&self.docker, &["unpause", name]).await })
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
            // Measured like the sandbox: the task's process tree, every half second.
            let usage = spec.usage.clone();
            if let Some(u) = &usage {
                u.mark_spawned();
            }
            let sample = async {
                let (Some(u), Some(root)) = (usage.as_deref(), pgid) else {
                    return std::future::pending::<()>().await;
                };
                let mut sampler = crate::usage::TreeSampler::default();
                loop {
                    crate::usage::sample_into(&mut sampler, Some(u), root).await;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            };
            let end = tokio::select! {
                end = supervise(child, logs, cancel, spec.timeout, stop) => end,
                () = sample => unreachable!("sampling never ends"),
            };
            self.groups
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&spec.name);
            end
        })
    }

    fn freeze<'a>(&'a self, name: &'a str) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            match self.group(name) {
                Some(g) => quiet_ok("kill", &["-STOP", "--", &format!("-{g}")]).await,
                None => false,
            }
        })
    }

    fn thaw<'a>(&'a self, name: &'a str) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            match self.group(name) {
                Some(g) => quiet_ok("kill", &["-CONT", "--", &format!("-{g}")]).await,
                None => false,
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
            read_only: vec![],
            usage: None,
            speed: gimmecores_core::Speed::Full,
        }
    }

    fn has_pair(args: &[String], flag: &str, value: &str) -> bool {
        args.windows(2).any(|w| w[0] == flag && w[1] == value)
    }

    #[test]
    fn docker_flags_enforce_the_sandbox() {
        let a = docker_args(&spec(), &[]).unwrap();
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
        // Variables by name only: values never on a command line others can list.
        assert!(has_pair(&a, "--env", "CI"));
        assert!(!a.iter().any(|x| x == "CI=1"));
        assert!(a.contains(&"--no-healthcheck".to_string()));
    }

    #[test]
    fn an_images_volumes_are_memory_backed() {
        let vols =
            cover_volumes(["/data/", "/var/lib/mysql", "/tmp", "/work", "/data"].map(String::from))
                .unwrap();
        assert_eq!(
            vols,
            ["/data", "/var/lib/mysql"],
            "deduplicated; /tmp and /work covered"
        );
        let a = docker_args(&spec(), &vols).unwrap();
        let size = TMPFS_BYTES.min(4 << 30);
        assert!(has_pair(
            &a,
            "--tmpfs",
            &format!("/data:rw,exec,nosuid,size={size}")
        ));
        assert!(has_pair(
            &a,
            "--tmpfs",
            &format!("/var/lib/mysql:rw,exec,nosuid,size={size}")
        ));
        let mut small = spec();
        small.memory_bytes = 256 << 20;
        let a = docker_args(&small, &vols).unwrap();
        assert!(
            has_pair(
                &a,
                "--tmpfs",
                &format!("/data:rw,exec,nosuid,size={}", 256u64 << 20)
            ),
            "never larger than the task's memory"
        );
        for bad in [
            "data",
            "/a,size=99g",
            "/a:/b",
            "/a b",
            "/a/../etc",
            "/./x",
            "/a\nb",
        ] {
            assert!(
                cover_volumes([bad.to_string()]).is_err(),
                "{bad:?} accepted"
            );
        }
        let many = (0..=MAX_IMAGE_VOLUMES).map(|i| format!("/v{i}"));
        assert!(cover_volumes(many).is_err());
    }

    fn layout() -> HandBackLayout {
        HandBackLayout {
            links: vec![("bin".into(), "usr/bin".into())],
            dirs: vec!["usr".into(), "lib".into()],
            chmod: "/usr/bin/chmod".into(),
            ld_cache: true,
        }
    }

    #[test]
    fn the_hand_back_runs_the_lenders_chmod_unprivileged_never_the_tasks_image() {
        let id = format!("sha256:{}", "a".repeat(64));
        let a = hand_back_args(
            &id,
            &layout(),
            std::path::Path::new("/w/t1"),
            "gmc-x-handback",
        );
        assert!(
            has_pair(&a, "--user", "65534:65534"),
            "the task's own user, never root"
        );
        assert!(has_pair(&a, "--cap-drop", "ALL"));
        assert!(!a.iter().any(|x| x == "--cap-add"), "no capability at all");
        assert!(has_pair(&a, "--network", "none"));
        assert!(has_pair(&a, "--security-opt", "no-new-privileges"));
        assert!(a.contains(&"--read-only".to_string()));
        assert!(a.contains(&"--no-healthcheck".to_string()));
        assert!(has_pair(&a, "--entrypoint", "/usr/bin/chmod"));
        // The lender's folders only ever read-only; the task folder is the one writable mount.
        let mounts: Vec<&String> = a
            .windows(2)
            .filter(|w| w[0] == "--volume")
            .map(|w| &w[1])
            .collect();
        assert_eq!(
            mounts,
            [
                "/usr:/usr:ro",
                "/lib:/lib:ro",
                "/etc/ld.so.cache:/etc/ld.so.cache:ro",
                "/w/t1:/work:rw"
            ]
        );
        let sep = a.iter().position(|x| x == "--").unwrap();
        assert_eq!(&a[sep + 1..], [id.as_str(), "-R", "a+rwX,a-st", "/work"]);
        assert!(!a.iter().any(|x| x.contains("python")), "no task image");
    }

    #[test]
    fn the_hand_back_image_holds_no_program() {
        let tar = hand_back_tar(&layout()).unwrap();
        let mut ar = tar::Archive::new(tar.as_slice());
        let mut seen = Vec::new();
        for e in ar.entries().unwrap() {
            let e = e.unwrap();
            let h = e.header();
            assert_eq!(h.size().unwrap(), 0, "nothing with content");
            assert_eq!(h.uid().unwrap(), 0);
            let path = e.path().unwrap().to_string_lossy().into_owned();
            let kind = match h.entry_type() {
                tar::EntryType::Directory => "dir",
                tar::EntryType::Symlink => "link",
                tar::EntryType::Regular => "file",
                other => panic!("{path}: {other:?}"),
            };
            let link = e
                .link_name()
                .unwrap()
                .map(|l| l.to_string_lossy().into_owned());
            seen.push((path, kind, link));
        }
        let want: Vec<(String, &str, Option<String>)> = vec![
            ("usr/".into(), "dir", None),
            ("lib/".into(), "dir", None),
            ("work/".into(), "dir", None),
            ("etc/".into(), "dir", None),
            ("bin".into(), "link", Some("usr/bin".into())),
            ("etc/ld.so.cache".into(), "file", None),
        ];
        assert_eq!(seen, want);
    }

    #[test]
    fn only_an_exact_hand_back_image_is_trusted() {
        let layer = format!("sha256:{}", "b".repeat(64));
        let id = format!("sha256:{}", "c".repeat(64));
        let good = serde_json::json!([{
            "Id": id,
            "RootFS": {"Type": "layers", "Layers": [layer]},
            "Config": {"Env": null, "Cmd": null, "User": "", "Volumes": null,
                       "Labels": {"dev.gimmecores.purpose": "hand-back"}}
        }]);
        assert_eq!(is_hand_back_image(&good, &layer), Some(id.clone()));
        let other = format!("sha256:{}", "d".repeat(64));
        let bad: [(&str, &str, serde_json::Value); 9] = [
            ("RootFS", "Layers", serde_json::json!([layer, layer])),
            ("RootFS", "Layers", serde_json::json!([other])),
            (
                "Config",
                "Env",
                serde_json::json!(["LD_PRELOAD=/work/x.so"]),
            ),
            ("Config", "Entrypoint", serde_json::json!(["/bin/sh"])),
            ("Config", "Cmd", serde_json::json!(["x"])),
            ("Config", "User", serde_json::json!("1000")),
            ("Config", "Volumes", serde_json::json!({"/data": {}})),
            (
                "Config",
                "Healthcheck",
                serde_json::json!({"Test": ["CMD", "x"]}),
            ),
            ("Config", "OnBuild", serde_json::json!(["RUN x"])),
        ];
        for (section, key, value) in bad {
            let mut v = good.clone();
            v[0][section][key] = value.clone();
            assert_eq!(is_hand_back_image(&v, &layer), None, "{key} = {value}");
        }
        let mut v = good.clone();
        v[0]["Id"] = serde_json::json!("abc");
        assert_eq!(is_hand_back_image(&v, &layer), None);
        let mut v = good.clone();
        v[0]["Config"]["WorkingDir"] = serde_json::json!("/work");
        assert_eq!(is_hand_back_image(&v, &layer), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn this_machines_layout_has_its_chmod() {
        let l = hand_back_layout().expect("chmod in /usr/bin or /bin");
        let top = l.chmod.trim_start_matches('/').split('/').next().unwrap();
        assert!(
            l.dirs.iter().any(|d| d == top) || l.links.iter().any(|(n, _)| n == top),
            "{l:?}"
        );
    }

    #[test]
    fn task_variables_cannot_replace_the_lenders_own() {
        let ok = |k: &str| check_env(&[(k.to_string(), "v".to_string())]).is_ok();
        assert!(ok("HF_TOKEN") && ok("_X1"));
        for bad in [
            "PATH",
            "HOME",
            "TMPDIR",
            "LANG",
            "DEVELOPER_DIR",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "",
            "1X",
            "A-B",
            "A=B",
            "A B",
        ] {
            assert!(!ok(bad), "{bad:?} accepted");
        }
        let many: Vec<_> = (0..=MAX_ENV_VARS)
            .map(|i| (format!("V{i}"), String::new()))
            .collect();
        assert!(check_env(&many).is_err());
        assert!(check_env(&[("A".into(), "x".repeat(MAX_ENV_BYTES))]).is_err());
        assert!(check_env(&[("A".into(), "1".into()), ("A".into(), "2".into())]).is_err());
        assert!(check_env(&[("A".into(), "a\0b".into())]).is_err());
    }

    #[test]
    fn hostile_inputs_are_rejected() {
        let mut s = spec();
        s.image = Some("--privileged".into());
        assert!(docker_args(&s, &[]).is_err(), "image cannot smuggle a flag");
        let mut s = spec();
        s.name = "x; rm -rf /".into();
        assert!(docker_args(&s, &[]).is_err());
        let mut s = spec();
        s.env = vec![("A=B --privileged".into(), "x".into())];
        assert!(docker_args(&s, &[]).is_err());
        let mut s = spec();
        s.argv.clear();
        assert!(docker_args(&s, &[]).is_err());
        let mut s = spec();
        s.image = None;
        assert!(docker_args(&s, &[]).is_err());
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
