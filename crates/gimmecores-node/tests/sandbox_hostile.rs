//! The sandbox runner against hostile tasks: real `sandbox-exec` on macOS, real bubblewrap on
//! Linux. Where no sandbox works, these tests fail when `GMC_REQUIRE_SANDBOX=1` (CI, macOS
//! always) and are skipped otherwise.
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use gimmecores_node::exec::{Executor, LogChunk, RunEnd, RunSpec};
use gimmecores_node::sandbox::SandboxExecutor;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

struct Env {
    /// Stands in for the daemon's state folder: holds the workspace and a secret.
    _home: tempfile::TempDir,
    work: PathBuf,
    secret: PathBuf,
}

fn setup() -> Env {
    let home = tempfile::Builder::new().prefix("gmc").tempdir().unwrap();
    let work = home.path().join("work").join("task1");
    std::fs::create_dir_all(&work).unwrap();
    let secret = home.path().join("identity.key");
    std::fs::write(&secret, "TOP-SECRET").unwrap();
    Env {
        work,
        secret,
        _home: home,
    }
}

async fn available(x: &SandboxExecutor) -> bool {
    let ok = x.probe().await;
    let required =
        cfg!(target_os = "macos") || std::env::var("GMC_REQUIRE_SANDBOX").as_deref() == Ok("1");
    assert!(ok || !required, "the sandbox does not work on this machine");
    if !ok {
        eprintln!("skipping: no working sandbox here");
    }
    ok
}

async fn run_with(
    x: &SandboxExecutor,
    work: &Path,
    script: &str,
    memory: u64,
    cancel: CancellationToken,
) -> (RunEnd, String) {
    let (tx, mut rx) = mpsc::channel::<LogChunk>(256);
    let out = tokio::spawn(async move {
        let mut s = String::new();
        while let Some(c) = rx.recv().await {
            s.push_str(&String::from_utf8_lossy(&c.data));
        }
        s
    });
    let spec = RunSpec {
        name: format!("t{}", std::process::id()),
        argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
        workdir: work.to_path_buf(),
        image: None,
        cpu_millis: 1000,
        memory_bytes: memory,
        timeout: Duration::from_secs(60),
        env: vec![],
        read_only: vec![],
    };
    let end = x.run(spec, tx, cancel).await.unwrap();
    (end, out.await.unwrap())
}

async fn run(x: &SandboxExecutor, work: &Path, script: &str) -> (RunEnd, String) {
    run_with(x, work, script, 1 << 30, CancellationToken::new()).await
}

fn failed(end: &RunEnd) -> bool {
    !matches!(end, RunEnd::Exited(0))
}

#[tokio::test]
async fn ordinary_work_runs_with_a_clean_environment() {
    let x = SandboxExecutor::default();
    if !available(&x).await {
        return;
    }
    let e = setup();
    let (end, out) = run(
        &x,
        &e.work,
        "echo hi > out.txt && cat out.txt && mkdir -p sub && echo ok > sub/f && env | sort",
    )
    .await;
    assert_eq!(end, RunEnd::Exited(0), "{out}");
    assert!(out.starts_with("hi\n"), "{out}");
    assert_eq!(
        std::fs::read_to_string(e.work.join("sub/f")).unwrap(),
        "ok\n"
    );
    let keys: Vec<&str> = out
        .lines()
        .skip(1)
        .filter_map(|l| l.split('=').next())
        .collect();
    for k in &keys {
        assert!(
            [
                "PATH",
                "HOME",
                "TMPDIR",
                "LANG",
                "DEVELOPER_DIR",
                "PWD",
                "SHLVL",
                "_",
                "OLDPWD"
            ]
            .contains(k),
            "unexpected variable {k} reached the task: {out}"
        );
    }
    let home_line = out.lines().find(|l| l.starts_with("HOME=")).unwrap();
    assert!(home_line.contains(".gmc-home"), "{home_line}");
}

#[tokio::test]
async fn files_outside_the_task_folder_cannot_be_read_or_written() {
    let x = SandboxExecutor::default();
    if !available(&x).await {
        return;
    }
    let e = setup();
    let s = e.secret.display().to_string();
    let parent = e
        .work
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .display()
        .to_string();
    let (end, out) = run(&x, &e.work, &format!("cat '{s}'")).await;
    assert!(failed(&end) && !out.contains("TOP-SECRET"), "{out}");
    // macOS refuses the listing; on Linux the parents are empty placeholders inside the
    // sandbox. Either way nothing of the daemon's folder is visible.
    let (_, out) = run(&x, &e.work, &format!("ls -a '{parent}'")).await;
    assert!(
        !out.contains("identity.key"),
        "the daemon's folder is visible: {out}"
    );
    let (_, out) = run(
        &x,
        &e.work,
        &format!("ls -a '{}'", e.secret.parent().unwrap().display()),
    )
    .await;
    assert!(!out.contains("identity.key"), "{out}");
    // Writes outside the task folder never reach the real disk.
    let _ = run(&x, &e.work, &format!("echo x > '{parent}/planted'")).await;
    assert!(!Path::new(&parent).join("planted").exists());
    let home = std::env::var("HOME").unwrap();
    let (end, out) = run(&x, &e.work, &format!("ls -a '{home}'")).await;
    assert!(failed(&end), "your home folder is not visible: {out}");
}

#[tokio::test]
async fn no_network_not_even_localhost_or_unix_sockets() {
    let x = SandboxExecutor::default();
    if !available(&x).await {
        return;
    }
    let e = setup();
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    tcp.set_nonblocking(true).unwrap();
    let port = tcp.local_addr().unwrap().port();
    // Like gmcd's control socket.
    let sock = PathBuf::from(format!("/tmp/gmc-sbx-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock);
    let unix = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    unix.set_nonblocking(true).unwrap();
    let (end, out) = run(
        &x,
        &e.work,
        &format!(
            "curl -s -m 3 http://127.0.0.1:{port}/; echo tcp=$?; \
             curl -s -m 3 --unix-socket {} http://x/; echo unix=$?; \
             curl -s -m 3 https://example.com/ -o /dev/null; echo net=$?",
            sock.display()
        ),
    )
    .await;
    let _ = std::fs::remove_file(&sock);
    assert_eq!(end, RunEnd::Exited(0), "{out}");
    for kind in ["tcp", "unix", "net"] {
        assert!(
            !out.contains(&format!("{kind}=0")),
            "{kind} connected: {out}"
        );
    }
    assert!(tcp.accept().is_err(), "the TCP listener saw a connection");
    assert!(unix.accept().is_err(), "the Unix socket saw a connection");
}

#[tokio::test]
async fn memory_over_the_limit_stops_the_task() {
    let x = SandboxExecutor::default();
    if !available(&x).await {
        return;
    }
    let e = setup();
    let (end, out) = run_with(
        &x,
        &e.work,
        "python3 -c \"import time; b = b'x' * (400 << 20); time.sleep(30)\"",
        100 << 20,
        CancellationToken::new(),
    )
    .await;
    assert!(
        matches!(&end, RunEnd::LimitExceeded(why) if why.contains("memory")),
        "{end:?} {out}"
    );
}

#[tokio::test]
async fn a_task_cannot_start_unlimited_processes() {
    let mut x = SandboxExecutor::default();
    x.pids_limit = 20;
    if !available(&x).await {
        return;
    }
    let e = setup();
    let (_, out) = run(
        &x,
        &e.work,
        "python3 -c \"
import os, time
n = 0
for i in range(80):
    try:
        if os.fork() == 0:
            time.sleep(3); os._exit(0)
        n += 1
    except OSError:
        pass
print('forked', n)
\"",
    )
    .await;
    let n: u32 = out
        .lines()
        .find_map(|l| l.strip_prefix("forked "))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or_else(|| panic!("{out}"));
    assert!(n < 80, "all 80 forks succeeded: {out}");
}

fn running(marker: &str) -> bool {
    let mut s = String::new();
    std::process::Command::new("ps")
        .args(["-A", "-o", "args="])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap()
        .stdout
        .unwrap()
        .read_to_string(&mut s)
        .unwrap();
    s.lines().any(|l| l.contains(marker))
}

#[tokio::test]
async fn stopping_a_task_stops_everything_it_started() {
    let x = SandboxExecutor::default();
    if !available(&x).await {
        return;
    }
    let e = setup();
    let cancel = CancellationToken::new();
    let c = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        c.cancel();
    });
    let (end, _) = run_with(
        &x,
        &e.work,
        "sleep 317 & sleep 317 & (sleep 317 &) ; wait",
        1 << 30,
        cancel,
    )
    .await;
    assert_eq!(end, RunEnd::Cancelled);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!running("sleep 317"), "a process outlived the task");
}

#[tokio::test]
async fn background_processes_do_not_outlive_a_finished_task() {
    let x = SandboxExecutor::default();
    if !available(&x).await {
        return;
    }
    let e = setup();
    let (end, _) = run(&x, &e.work, "sleep 318 & sleep 1; echo done").await;
    assert_eq!(end, RunEnd::Exited(0));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!running("sleep 318"));
}

/// Linux only: bubblewrap's PID namespace ends every process with the task. On macOS a process
/// that deliberately detaches can outlive the task (inside the sandbox); see sandbox.rs.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_detached_process_is_still_stopped() {
    let x = SandboxExecutor::default();
    if !available(&x).await {
        return;
    }
    let e = setup();
    // Double fork + new session: the classic way to escape a process group.
    let (end, out) = run(
        &x,
        &e.work,
        "python3 -c \"
import os
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        os.execvp('sleep', ['sleep', '319'])
    os._exit(0)
\"; sleep 2; echo parent-done",
    )
    .await;
    assert_eq!(end, RunEnd::Exited(0), "{out}");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let survived = running("sleep 319");
    if survived {
        let _ = std::process::Command::new("pkill")
            .args(["-f", "sleep 319"])
            .status();
    }
    assert!(!survived, "a detached process survived the task");
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn macos_apps_clipboard_keychain_and_other_processes_are_out_of_reach() {
    let x = SandboxExecutor::default();
    if !available(&x).await {
        return;
    }
    let e = setup();
    for cmd in [
        "osascript -e 'tell application \"Finder\" to get name of startup disk'",
        "pbpaste",
        "launchctl list",
        "security find-generic-password -s gimmecores",
        "open -a Calculator",
        "ps -A",
        "kill -0 1",
        "screencapture -x shot.png",
    ] {
        let (end, out) = run(&x, &e.work, cmd).await;
        assert!(failed(&end), "{cmd} worked inside the sandbox: {out}");
    }
}

#[tokio::test]
async fn an_option_cannot_be_smuggled_in_as_the_command() {
    let x = SandboxExecutor::default();
    let e = setup();
    let (tx, _rx) = mpsc::channel(8);
    let spec = RunSpec {
        name: "smuggle".into(),
        argv: vec![
            "-p".into(),
            "(version 1)(allow default)".into(),
            "/bin/sh".into(),
        ],
        workdir: e.work.clone(),
        image: None,
        cpu_millis: 1000,
        memory_bytes: 1 << 30,
        timeout: Duration::from_secs(5),
        env: vec![],
        read_only: vec![],
    };
    assert!(x.run(spec, tx, CancellationToken::new()).await.is_err());
}

mod common;

#[tokio::test]
async fn end_to_end_a_borrowed_task_runs_in_the_lenders_sandbox() {
    use gimmecores_core::{ExecutionMode, Modes};
    use gimmecores_node::exec::Executors;
    use gimmecores_node::grants_flow::{Decision, GrantOutcome, standard_terms};
    use gimmecores_node::node::{Node, NodeConfig};
    use gimmecores_node::paths::Paths;
    use gimmecores_node::presence::{FixedPresence, Outcome};
    use gimmecores_node::tasks_flow::{TaskSpec, TaskStatus};
    use std::sync::Arc;

    if !available(&SandboxExecutor::default()).await {
        return;
    }
    let lender_home = tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap();
    let lender = Node::start(NodeConfig {
        paths: Paths::at(lender_home.path()),
        device_name: "Desktop".into(),
        bind: "127.0.0.1:0".parse().unwrap(),
        executors: Executors {
            container: None,
            sandbox: Some(Arc::new(SandboxExecutor::default())),
        },
        presence: Arc::new(FixedPresence(Outcome::Verified)),
    })
    .await
    .unwrap();
    assert_eq!(
        lender.lend_modes().1,
        Modes::only(ExecutionMode::Sandbox),
        "the probe found the sandbox and no container runtime"
    );
    lender.set_lending(true).unwrap();
    lender
        .set_lend_modes(Modes::only(ExecutionMode::Sandbox))
        .unwrap();
    let (borrower, _h) = common::fresh_node("Laptop").await;
    common::pair(&borrower, &lender).await;
    let ask = {
        let (b, k) = (borrower.clone(), lender.key());
        tokio::spawn(async move {
            b.request_grant(&k, &standard_terms(1, 1, 1, gimmecores_node::now()), "e2e")
                .await
        })
    };
    let req = common::eventually(|| lender.incoming_requests().into_iter().next()).await;
    lender
        .respond_to_request(req.id, Decision::Accept(None))
        .unwrap();
    let GrantOutcome::Granted { id, .. } = ask.await.unwrap().unwrap() else {
        panic!("not granted");
    };

    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("in.txt"), "21\n").unwrap();
    let key = lender_home.path().join("identity.key");
    let script = format!(
        "cat '{}' > /dev/null 2>&1; echo key=$?; mkdir -p out; \
         echo $(( $(cat in.txt) * 2 )) > out/answer.txt; echo done",
        key.display()
    );
    let (tx, mut rx) = mpsc::channel::<LogChunk>(64);
    let logs = tokio::spawn(async move {
        let mut s = String::new();
        while let Some(c) = rx.recv().await {
            s.push_str(&String::from_utf8_lossy(&c.data));
        }
        s
    });
    let report = borrower
        .run_task(
            &lender.key(),
            id,
            TaskSpec {
                dir: project.path().to_path_buf(),
                argv: vec!["/bin/sh".into(), "-c".into(), script],
                image: None,
                mode: None,
                outputs: vec!["out".into()],
                excludes: vec![],
                allow_secrets: vec![],
                extra_files: vec![],
                attachments: vec![],
                cpu_millis: 1000,
                memory_bytes: 1 << 30,
                timeout: Duration::from_secs(60),
            },
            tx,
        )
        .await
        .unwrap();
    let logs = logs.await.unwrap();
    assert_eq!(report.status, TaskStatus::Succeeded, "{report:?} {logs}");
    assert!(logs.contains("done"), "{logs}");
    assert!(
        !logs.contains("key=0"),
        "read the lender's identity key: {logs}"
    );
    assert_eq!(
        std::fs::read_to_string(project.path().join("out/answer.txt")).unwrap(),
        "42\n"
    );
}
