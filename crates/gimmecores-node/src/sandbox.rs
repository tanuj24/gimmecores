//! The sandbox runner: tasks run inside the operating system's own isolation, with no
//! container runtime ("sandbox" execution mode; threat model 5.1).
//!
//! - macOS: Seatbelt (`sandbox-exec`) with a deny-by-default profile ([`seatbelt_profile`]).
//! - Linux: bubblewrap (`bwrap`) with new namespaces and only system locations mounted
//!   ([`bwrap_args`]).
//!
//! Both: the task can read system and tool locations and read/write only its own folder; no
//! network (not even localhost or Unix sockets, so never gmcd's own sockets); no other
//! processes, no clipboard, no AppleEvents, no keychain. A scrubbed environment with `HOME` and
//! `TMPDIR` inside the task folder. Lower CPU priority, a cap on new processes, memory watched
//! and the task stopped when over its limit, and every process it started killed when it ends.
//!
//! What it does not give, stated on the request screen: the lender's installed tools are used
//! (no bundled environment); CPU and memory are monitored, not hard limits; on macOS the task
//! runs as the lender's own user (inside the sandbox).
//!
//! Known macOS gap: a process that deliberately detaches (double fork + new session) leaves
//! the task's process group and tree, and can outlive the task, still inside the sandbox (no
//! network, no files outside its deleted folder, no IPC). Linux has no such gap: bubblewrap's
//! PID namespace ends every process with the task. A dedicated `gmc-guest` account closes it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::exec::{
    BoxFuture, Executor, LogChunk, PIDS_LIMIT, RunEnd, RunSpec, pump, quiet, validate,
};

/// Inside the task folder: the task's `HOME` and `TMPDIR`.
pub const HOME_DIR: &str = ".gmc-home";
pub const TMP_DIR: &str = ".gmc-tmp";

/// Where a sandboxed task finds programs: system and tool locations only, never anything in
/// the lender's home (a `rustup` toolchain in `~/.cargo/bin` is not visible; `~/.cargo` can
/// hold a registry token). The tool list (tools.rs) probes exactly these.
pub const PATH: &str = "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin";
/// How often memory is measured and new processes are noticed.
const WATCH: Duration = Duration::from_millis(500);

/// System and tool locations a task may read (never anything under the user's home).
#[cfg(target_os = "macos")]
const MAC_READ: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/System",
    "/Library/Developer",
    // python.org's installer (system-wide, read-only for tasks).
    "/Library/Frameworks/Python.framework",
    "/Applications/Xcode.app",
    "/opt/homebrew",
    "/private/etc",
    "/private/var/db/timezone",
    "/private/var/select",
    "/dev",
];

/// Canonical, UTF-8 forms of a task's read-only folders (the sandbox matches real paths).
fn read_only_paths(paths: &[PathBuf]) -> Result<Vec<String>> {
    paths
        .iter()
        .map(|p| {
            let c = std::fs::canonicalize(p)
                .with_context(|| format!("read-only folder {} is missing", p.display()))?;
            ensure!(c.is_dir(), "{} is not a folder", c.display());
            c.to_str()
                .map(String::from)
                .context("read-only folder path is not UTF-8")
        })
        .collect()
}

/// The command that runs the sandbox at `speed` on macOS (nothing for full speed).
pub fn mac_speed(speed: gimmecores_core::Speed) -> Vec<&'static str> {
    use gimmecores_core::Speed;
    match speed {
        Speed::Full => vec![],
        // QoS clamp "utility": measured on an M2 Max, the owner's own work slowed 14% instead
        // of 83%; borrowed work got about 60% of full speed (docs/design/task-speed.md).
        Speed::AppsFirst => vec!["/usr/sbin/taskpolicy", "-c", "utility"],
        // Darwin background: efficiency cores and throttled I/O; the owner's work slowed 2%.
        Speed::Background => vec!["/usr/sbin/taskpolicy", "-b"],
    }
}

/// The command that runs the sandbox at `speed` on Linux. `chrt` is in util-linux, present
/// on every distribution GimmeCores supports; without it, background is nice 19 alone.
pub fn linux_speed(speed: gimmecores_core::Speed) -> Vec<&'static str> {
    use gimmecores_core::Speed;
    match speed {
        Speed::Full => vec!["nice", "-n", "0"],
        Speed::AppsFirst => vec!["nice", "-n", "10"],
        Speed::Background if Path::new("/usr/bin/chrt").exists() => {
            vec!["nice", "-n", "19", "/usr/bin/chrt", "--idle", "0"]
        }
        Speed::Background => vec!["nice", "-n", "19"],
    }
}

/// Scheme string literal for a Seatbelt profile.
fn sb_str(p: &str) -> Result<String> {
    ensure!(
        !p.chars().any(char::is_control),
        "path contains control characters"
    );
    Ok(format!(
        "\"{}\"",
        p.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

/// The Seatbelt profile for a task whose folder is `work` (already canonical). Deny by
/// default; allow only what ordinary command-line tools need.
pub fn seatbelt_profile(work: &Path, read_only: &[&str]) -> Result<String> {
    let work = work.to_str().context("task folder path is not UTF-8")?;
    let mut reads: Vec<&str> = read_only.to_vec();
    reads.push(work);
    // Tools resolve paths upward, so every parent folder may be looked up (names and
    // attributes only, never listed or read).
    let mut parents = std::collections::BTreeSet::new();
    for r in &reads {
        let mut p = Path::new(r);
        while let Some(parent) = p.parent() {
            if parent != Path::new("/") {
                parents.insert(parent.to_string_lossy().into_owned());
            }
            p = parent;
        }
    }
    let lit = |xs: &mut dyn Iterator<Item = &str>, kind: &str| -> Result<String> {
        xs.map(|x| sb_str(x).map(|q| format!("({kind} {q})")))
            .collect::<Result<Vec<_>>>()
            .map(|v| v.join(" "))
    };
    let parents = lit(&mut parents.iter().map(String::as_str), "literal")?;
    let reads = lit(&mut reads.iter().copied(), "subpath")?;
    let work_q = sb_str(work)?;
    Ok(format!(
        r#"(version 1)
(deny default)
(allow process-fork)
(allow process-exec*)
(allow signal (target same-sandbox))
(allow process-info* (target same-sandbox))
(allow sysctl-read)
(allow ipc-posix-sem)
(allow file-read-metadata (literal "/etc") (literal "/var") (literal "/tmp") {parents})
(allow file-read* (literal "/") {reads})
(allow file-write* (subpath {work_q}) (literal "/dev/null") (literal "/dev/dtracehelper"))
(allow file-ioctl (literal "/dev/null") (literal "/dev/dtracehelper"))
"#
    ))
}

/// bubblewrap arguments for a task whose folder is `work`: new user, PID, network, IPC, UTS
/// and mount namespaces; system locations read-only; only the task folder writable; a private
/// `/tmp`; the home folder and `/run` (where gmcd's sockets live) not mounted at all.
pub fn bwrap_args(work: &Path, read_only: &[String], argv: &[String]) -> Result<Vec<String>> {
    let work = work.to_str().context("task folder path is not UTF-8")?;
    let mut a: Vec<String> = [
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    for d in [
        "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/etc", "/opt",
    ] {
        match std::fs::symlink_metadata(d) {
            Ok(m) if m.file_type().is_symlink() => {
                if let Ok(target) = std::fs::read_link(d) {
                    a.extend([
                        "--symlink".into(),
                        target.to_string_lossy().into_owned(),
                        d.into(),
                    ]);
                }
            }
            Ok(_) => a.extend(["--ro-bind".into(), d.into(), d.into()]),
            Err(_) => {}
        }
    }
    a.extend(["--bind".into(), work.into(), work.into()]);
    for r in read_only {
        a.extend(["--ro-bind".into(), r.clone(), r.clone()]);
    }
    a.extend(["--chdir".into(), work.into(), "--".into()]);
    a.extend(argv.iter().cloned());
    Ok(a)
}

use crate::usage::{descendants, process_table};

async fn signal(pids: &[u32], sig: &str) {
    if pids.is_empty() {
        return;
    }
    let mut args = vec!["-s".to_string(), sig.to_string(), "--".to_string()];
    args.extend(pids.iter().map(u32::to_string));
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    quiet("kill", &args).await;
}

/// What the per-user process cap counts for this user now: processes on macOS, threads on
/// Linux (where RLIMIT_NPROC counts every thread).
async fn user_process_count() -> u32 {
    let uid = Command::new("id").arg("-u").output().await.ok();
    let uid = uid.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    let Some(uid) = uid else { return 0 };
    let args: &[&str] = if cfg!(target_os = "linux") {
        &["-A", "-L", "-o", "uid="]
    } else {
        &["-A", "-o", "uid="]
    };
    let out = Command::new("ps").args(args).output().await.ok();
    out.map_or(0, |o| {
        let n = String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter(|l| l.trim() == uid)
            .count();
        u32::try_from(n).unwrap_or(u32::MAX)
    })
}

/// Tasks currently running: name -> (root pid, every process seen under it, by name).
type Running = HashMap<String, (u32, HashMap<u32, String>)>;

pub struct SandboxExecutor {
    running: Mutex<Running>,
    /// New processes one task may start.
    pub pids_limit: u32,
    /// The sandbox program (`sandbox-exec` on macOS, `bwrap` on Linux).
    pub wrapper: PathBuf,
}

impl Default for SandboxExecutor {
    fn default() -> Self {
        Self {
            running: Mutex::new(HashMap::new()),
            pids_limit: PIDS_LIMIT,
            wrapper: if cfg!(target_os = "macos") {
                "/usr/bin/sandbox-exec".into()
            } else {
                "bwrap".into()
            },
        }
    }
}

impl SandboxExecutor {
    fn lock(&self) -> std::sync::MutexGuard<'_, Running> {
        self.running.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Every live process of the task: the tree under its root plus anything seen before that
    /// is still alive with the same name (it may have detached itself).
    async fn task_pids(&self, name: &str) -> Vec<u32> {
        let Some((root, seen)) = self.lock().get(name).cloned() else {
            return Vec::new();
        };
        let table = process_table().await;
        let mut pids: Vec<u32> = descendants(&table, root).iter().map(|p| p.pid).collect();
        for p in &table {
            if seen.get(&p.pid) == Some(&p.comm) && !pids.contains(&p.pid) {
                pids.push(p.pid);
            }
        }
        pids
    }

    fn command(&self, spec: &RunSpec, work: &Path, nproc: u32) -> Result<Command> {
        let mut env: Vec<(String, String)> = vec![
            ("PATH".into(), PATH.into()),
            (
                "HOME".into(),
                work.join(HOME_DIR).to_string_lossy().into_owned(),
            ),
            (
                "TMPDIR".into(),
                work.join(TMP_DIR).to_string_lossy().into_owned(),
            ),
            ("LANG".into(), "C.UTF-8".into()),
        ];
        // The lender's choice of developer tools (macOS), never anything secret.
        if let Some(d) = std::env::var_os("DEVELOPER_DIR") {
            env.push(("DEVELOPER_DIR".into(), d.to_string_lossy().into_owned()));
        }
        for (k, v) in &spec.env {
            // The dynamic loader's variables stay the lender's to set.
            if !(k.starts_with("DYLD_") || k.starts_with("LD_")) {
                env.push((k.clone(), v.clone()));
            }
        }
        let mut cmd = if cfg!(target_os = "macos") {
            let extra = read_only_paths(&spec.read_only)?;
            let mut reads: Vec<&str> = MAC_READ_OR_EMPTY.to_vec();
            reads.extend(extra.iter().map(String::as_str));
            let profile = seatbelt_profile(work, &reads)?;
            let mut c = Command::new("/bin/bash");
            c.args(["-c", "ulimit -u \"$1\" || exit 125; shift; exec \"$@\""])
                .arg("gmc-sandbox")
                .arg(nproc.to_string())
                // How macOS schedules it: a QoS clamp (`nice` does nothing here). Inherited by
                // everything the task starts; the sandbox refuses `setpriority`, so a task
                // cannot lift it (tests: sandbox_hostile).
                .args(mac_speed(spec.speed))
                .arg(&self.wrapper)
                .arg("-p")
                .arg(profile)
                .args(&spec.argv);
            c
        } else if cfg!(target_os = "linux") {
            let mut c = Command::new("prlimit");
            c.arg(format!("--nproc={nproc}:{nproc}"))
                .arg("--")
                // Niceness (and idle scheduling for background): an unprivileged task can lower
                // these, never raise them (tests: sandbox_hostile).
                .args(linux_speed(spec.speed))
                .arg(&self.wrapper)
                .args(bwrap_args(
                    work,
                    &read_only_paths(&spec.read_only)?,
                    &spec.argv,
                )?);
            c
        } else {
            bail!("the sandbox is not supported on this platform yet");
        };
        cmd.current_dir(work)
            .env_clear()
            .envs(env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        cmd.process_group(0);
        Ok(cmd)
    }
}

#[cfg(target_os = "macos")]
const MAC_READ_OR_EMPTY: &[&str] = MAC_READ;
#[cfg(not(target_os = "macos"))]
const MAC_READ_OR_EMPTY: &[&str] = &[];

impl Executor for SandboxExecutor {
    fn name(&self) -> &'static str {
        "sandbox"
    }

    fn run<'a>(
        &'a self,
        spec: RunSpec,
        logs: mpsc::Sender<LogChunk>,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<RunEnd>> {
        Box::pin(async move {
            validate(&spec)?;
            // A leading dash would be read as an option by the sandbox program.
            ensure!(!spec.argv[0].starts_with('-'), "invalid command");
            let work = std::fs::canonicalize(&spec.workdir).context("task folder")?;
            for d in [HOME_DIR, TMP_DIR] {
                std::fs::create_dir_all(work.join(d))?;
            }
            let nproc = user_process_count().await.saturating_add(self.pids_limit);
            let child = self
                .command(&spec, &work, nproc)?
                .spawn()
                .context("starting the sandbox")?;
            let root = child.id().context("sandbox exited at once")?;
            self.lock()
                .insert(spec.name.clone(), (root, HashMap::new()));

            // Watch memory, measure what the task uses, and remember every process it starts.
            spec.usage.as_ref().inspect(|u| u.mark_spawned());
            let stop_for_limit = cancel.child_token();
            let watcher = async {
                let mut sampler = crate::usage::TreeSampler::default();
                loop {
                    let (tree, _, rss) =
                        crate::usage::sample_into(&mut sampler, spec.usage.as_deref(), root).await;
                    if let Some((_, seen)) = self.lock().get_mut(&spec.name) {
                        for p in &tree {
                            seen.insert(p.pid, p.comm.clone());
                        }
                    }
                    if spec.memory_bytes > 0 && rss > spec.memory_bytes {
                        stop_for_limit.cancel();
                        return format!(
                            "memory limit reached: {} MiB used of {} MiB",
                            rss >> 20,
                            spec.memory_bytes >> 20
                        );
                    }
                    tokio::time::sleep(WATCH).await;
                }
            };
            let stop = async {
                // The whole process group (catches `(cmd &)` and `nohup`), then every process
                // seen under the task.
                quiet("kill", &["-KILL", "--", &format!("-{root}")]).await;
                let pids = self.task_pids(&spec.name).await;
                signal(&pids, "KILL").await;
            };
            let run = supervise_all(child, logs, stop_for_limit.clone(), spec.timeout, stop);
            tokio::pin!(run, watcher);
            let mut over: Option<String> = None;
            let end = loop {
                tokio::select! {
                    end = &mut run => break end,
                    why = &mut watcher, if over.is_none() => over = Some(why),
                }
            };
            let end = match (end, over) {
                (Ok(RunEnd::Cancelled), Some(why)) if !cancel.is_cancelled() => {
                    Ok(RunEnd::LimitExceeded(why))
                }
                (end, _) => end,
            };
            // Nothing the task started outlives it.
            quiet("kill", &["-KILL", "--", &format!("-{root}")]).await;
            let leftovers = self.task_pids(&spec.name).await;
            signal(&leftovers, "KILL").await;
            self.lock().remove(&spec.name);
            end
        })
    }

    fn freeze<'a>(&'a self, name: &'a str) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let pids = self.task_pids(name).await;
            signal(&pids, "STOP").await;
            !pids.is_empty()
        })
    }

    fn thaw<'a>(&'a self, name: &'a str) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let pids = self.task_pids(name).await;
            signal(&pids, "CONT").await;
            !pids.is_empty()
        })
    }

    fn probe(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            let Ok(dir) = tempfile_dir() else {
                return false;
            };
            let spec = RunSpec {
                name: "gmc-probe".into(),
                argv: vec!["true".into()],
                workdir: dir.clone(),
                image: None,
                cpu_millis: 1000,
                memory_bytes: 0,
                timeout: Duration::from_secs(10),
                env: vec![],
                read_only: vec![],
                usage: None,
                speed: gimmecores_core::Speed::Full,
            };
            let (tx, mut rx) = mpsc::channel(8);
            tokio::spawn(async move { while rx.recv().await.is_some() {} });
            let ok = matches!(
                self.run(spec, tx, CancellationToken::new()).await,
                Ok(RunEnd::Exited(0))
            );
            let _ = std::fs::remove_dir_all(&dir);
            ok
        })
    }
}

/// Like [`crate::exec::supervise`], but when the main process ends for any reason, everything
/// the task started is stopped before its output is drained (a leftover background process
/// would otherwise hold the output open, and keep running).
async fn supervise_all<F>(
    mut child: tokio::process::Child,
    logs: mpsc::Sender<LogChunk>,
    cancel: CancellationToken,
    timeout: Duration,
    stop_all: F,
) -> Result<RunEnd>
where
    F: std::future::Future<Output = ()>,
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
    stop_all.await;
    let _ = child.kill().await;
    for mut h in [out, err].into_iter().flatten() {
        if tokio::time::timeout(Duration::from_secs(5), &mut h)
            .await
            .is_err()
        {
            // Something still holds the output open: stop reading so the log stream ends.
            h.abort();
        }
    }
    Ok(end)
}

/// A fresh private folder for the probe run.
fn tempfile_dir() -> Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "gmc-probe-{}",
        hex::encode(crate::wire::random32()?)
    ));
    std::fs::create_dir_all(&dir)?;
    crate::fsutil::restrict_dir(&dir)?;
    Ok(dir)
}
