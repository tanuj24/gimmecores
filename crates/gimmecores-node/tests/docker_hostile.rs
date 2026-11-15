//! The container runner against real Docker. Skipped where Docker is not running, unless
//! `GMC_REQUIRE_DOCKER=1` (CI on Linux), in which case a missing Docker fails the run.
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::time::Duration;

use gimmecores_node::exec::{DockerExecutor, Executor, LogChunk, RunEnd, RunSpec};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// A small image already on this machine (the runner never downloads one).
fn image() -> Option<String> {
    let required = std::env::var("GMC_REQUIRE_DOCKER").as_deref() == Ok("1");
    let docker_up = StdCommand::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !docker_up {
        assert!(!required, "Docker is required here but not running");
        eprintln!("skipping: Docker is not running");
        return None;
    }
    let found = [
        "alpine:3.20",
        "alpine:latest",
        "busybox:latest",
        "golang:1.27-alpine",
    ]
    .into_iter()
    .find(|i| {
        StdCommand::new("docker")
            .args(["image", "inspect", i])
            .output()
            .is_ok_and(|o| o.status.success())
    });
    assert!(found.is_some() || !required, "no test image present");
    found.map(String::from)
}

struct Env {
    _home: tempfile::TempDir,
    work: PathBuf,
}

fn setup() -> Env {
    let home = tempfile::Builder::new().prefix("gmc").tempdir().unwrap();
    let work = home.path().join("work").join("task1");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(home.path().join("identity.key"), "TOP-SECRET").unwrap();
    // As the node prepares a workspace for the unprivileged container user.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o777)).unwrap();
    Env { work, _home: home }
}

/// A container name no other test in this run (or an earlier run's leftover) uses. The clock
/// alone is not enough: macOS reads it in microseconds, so tests running in parallel could get
/// the same name.
fn name() -> String {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    format!(
        "gmc-test-{}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    )
}

async fn run_with(
    image: &str,
    work: &Path,
    script: &str,
    memory: u64,
    cancel: CancellationToken,
    name: String,
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
        name,
        argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
        workdir: work.to_path_buf(),
        image: Some(image.into()),
        cpu_millis: 1000,
        memory_bytes: memory,
        timeout: Duration::from_secs(120),
        env: vec![],
        read_only: vec![],
        usage: None,
        speed: gimmecores_core::Speed::Full,
    };
    let end = DockerExecutor::default()
        .run(spec, tx, cancel)
        .await
        .unwrap();
    (end, out.await.unwrap())
}

async fn run(image: &str, work: &Path, script: &str) -> (RunEnd, String) {
    run_with(
        image,
        work,
        script,
        512 << 20,
        CancellationToken::new(),
        name(),
    )
    .await
}

#[tokio::test]
async fn ordinary_work_runs_as_an_unprivileged_user() {
    let Some(img) = image() else { return };
    let e = setup();
    let (end, out) = run(
        &img,
        &e.work,
        "id -u; echo hi > out.txt; mkdir -p sub && echo ok > sub/f; echo home=$HOME; \
         mkdir -p $HOME/.cache && echo cached; \
         printf '#!/bin/sh\\necho ran-from-tmp\\n' > /tmp/t.sh && chmod +x /tmp/t.sh && /tmp/t.sh",
    )
    .await;
    assert_eq!(end, RunEnd::Exited(0), "{out}");
    assert!(out.starts_with("65534\n"), "{out}");
    assert!(out.contains("cached"), "tools can use a home folder: {out}");
    assert!(
        out.contains("ran-from-tmp"),
        "build tools can run what they build: {out}"
    );
    assert_eq!(
        std::fs::read_to_string(e.work.join("out.txt")).unwrap(),
        "hi\n"
    );
    assert_eq!(
        std::fs::read_to_string(e.work.join("sub/f")).unwrap(),
        "ok\n"
    );
    // The daemon can clean up what the task left (on Linux the container's user owns it).
    std::fs::remove_dir_all(&e.work).unwrap();
}

#[tokio::test]
async fn no_network_no_capabilities_and_a_read_only_system() {
    let Some(img) = image() else { return };
    let e = setup();
    let (end, out) = run(
        &img,
        &e.work,
        "wget -q -T 3 -O /dev/null http://1.1.1.1/ && echo NET-OK; \
         wget -q -T 3 -O /dev/null http://host.docker.internal/ && echo HOST-OK; \
         touch /etc/pwned && echo ROOTFS-WRITABLE; \
         grep CapEff /proc/self/status; ls /; true",
    )
    .await;
    assert_eq!(end, RunEnd::Exited(0), "{out}");
    for bad in ["NET-OK", "HOST-OK", "ROOTFS-WRITABLE"] {
        assert!(!out.contains(bad), "{bad}: {out}");
    }
    assert!(out.contains("CapEff:\t0000000000000000"), "{out}");
}

#[tokio::test]
async fn only_the_task_folder_is_visible() {
    let Some(img) = image() else { return };
    let e = setup();
    let (_, out) = run(
        &img,
        &e.work,
        "cat ../identity.key 2>&1; ls -a / /Users /home 2>&1; find / -name identity.key 2>/dev/null; true",
    )
    .await;
    assert!(!out.contains("TOP-SECRET"), "{out}");
    assert!(!out.contains("identity.key\n"), "{out}");
}

#[tokio::test]
async fn memory_over_the_limit_kills_the_task() {
    let Some(img) = image() else { return };
    let e = setup();
    // /tmp is memory-backed and counts against the container's memory.
    let (end, out) = run_with(
        &img,
        &e.work,
        "head -c 300000000 /dev/zero > /tmp/big && echo survived",
        64 << 20,
        CancellationToken::new(),
        name(),
    )
    .await;
    assert!(
        !out.contains("survived") || end != RunEnd::Exited(0),
        "{end:?} {out}"
    );
}

#[tokio::test]
async fn process_count_is_capped() {
    let Some(img) = image() else { return };
    let e = setup();
    // Shell built-ins only: once the cap is reached nothing new can start.
    let (_, out) = run(
        &img,
        &e.work,
        "n=0; i=0; while [ $i -lt 700 ]; do sleep 20 & n=$((n+1)); i=$((i+1)); done; echo running=$n",
    )
    .await;
    let refused = out.contains("can't fork") || out.contains("Resource temporarily unavailable");
    let started = out
        .lines()
        .find_map(|l| l.strip_prefix("running="))
        .and_then(|n| n.trim().parse::<u32>().ok());
    assert!(
        refused || started.is_some_and(|n| n <= 512),
        "700 processes were allowed: {out}"
    );
}

fn container_exists(name: &str) -> bool {
    let o = StdCommand::new("docker")
        .args(["ps", "-aq", "--filter", &format!("name=^{name}$")])
        .output()
        .unwrap();
    !String::from_utf8_lossy(&o.stdout).trim().is_empty()
}

#[tokio::test]
async fn stopping_a_task_removes_its_container() {
    let Some(img) = image() else { return };
    let e = setup();
    let n = name();
    let cancel = CancellationToken::new();
    let c = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        c.cancel();
    });
    let (end, _) = run_with(&img, &e.work, "sleep 300", 64 << 20, cancel, n.clone()).await;
    assert_eq!(end, RunEnd::Cancelled);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!container_exists(&n), "container {n} still exists");
}

#[tokio::test]
async fn freezing_and_thawing_a_container() {
    let Some(img) = image() else { return };
    let e = setup();
    let n = name();
    let x = std::sync::Arc::new(DockerExecutor::default());
    let (tx, mut rx) = mpsc::channel::<LogChunk>(64);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let spec = RunSpec {
        name: n.clone(),
        argv: vec!["sleep".into(), "4".into()],
        workdir: e.work.clone(),
        image: Some(img),
        cpu_millis: 1000,
        memory_bytes: 64 << 20,
        timeout: Duration::from_secs(60),
        env: vec![],
        read_only: vec![],
        usage: None,
        speed: gimmecores_core::Speed::Full,
    };
    let task = {
        let x = x.clone();
        tokio::spawn(async move { x.run(spec, tx, CancellationToken::new()).await })
    };
    for _ in 0..100 {
        let r = StdCommand::new("docker")
            .args(["inspect", "-f", "{{.State.Running}}", &n])
            .output()
            .unwrap();
        if String::from_utf8_lossy(&r.stdout).trim() == "true" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    x.freeze(&n).await;
    let paused = StdCommand::new("docker")
        .args(["inspect", "-f", "{{.State.Paused}}", &n])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&paused.stdout).trim(), "true");
    x.thaw(&n).await;
    assert_eq!(task.await.unwrap().unwrap(), RunEnd::Exited(0));
}

#[tokio::test]
async fn an_image_that_is_not_here_is_refused_not_downloaded() {
    let Some(_) = image() else { return };
    let e = setup();
    let (tx, _rx) = mpsc::channel(8);
    let missing = "gimmecores-test/not-here:0";
    let spec = RunSpec {
        name: name(),
        argv: vec!["true".into()],
        workdir: e.work.clone(),
        image: Some(missing.into()),
        cpu_millis: 1000,
        memory_bytes: 64 << 20,
        timeout: Duration::from_secs(30),
        env: vec![],
        read_only: vec![],
        usage: None,
        speed: gimmecores_core::Speed::Full,
    };
    let err = DockerExecutor::default()
        .run(spec, tx, CancellationToken::new())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("never downloads"), "{err}");
}

mod common;

#[tokio::test]
async fn end_to_end_a_borrowed_task_runs_in_a_container_on_the_lender() {
    use gimmecores_core::{ExecutionMode, Modes};
    use gimmecores_node::exec::Executors;
    use gimmecores_node::grants_flow::{Decision, GrantOutcome, standard_terms};
    use gimmecores_node::node::{Node, NodeConfig};
    use gimmecores_node::paths::Paths;
    use gimmecores_node::presence::{FixedPresence, Outcome};
    use gimmecores_node::tasks_flow::{TaskSpec, TaskStatus};
    use std::sync::Arc;

    let Some(img) = image() else { return };
    let lender_home = tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap();
    let lender = Node::start(NodeConfig {
        paths: Paths::at(lender_home.path()),
        device_name: "Desktop".into(),
        bind: "127.0.0.1:0".parse().unwrap(),
        executors: Executors {
            container: Some(Arc::new(DockerExecutor::default())),
            sandbox: None,
        },
        presence: Arc::new(FixedPresence(Outcome::Verified)),
    })
    .await
    .unwrap();
    assert_eq!(lender.lend_modes().1, Modes::only(ExecutionMode::Container));
    lender.set_lending(true).unwrap();
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
    let GrantOutcome::Granted { id, terms } = ask.await.unwrap().unwrap() else {
        panic!("not granted");
    };
    assert_eq!(terms.modes, Modes::CONTAINER);

    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir(project.path().join("src")).unwrap();
    std::fs::write(project.path().join("src/in.txt"), "21\n").unwrap();
    let script = "cat ../identity.key /work/../identity.key > /dev/null 2>&1; echo key=$?; \
                  mkdir -p out; echo $(( $(cat src/in.txt) * 2 )) > out/answer.txt; id -u";
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
                argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
                image: Some(img),
                mode: None,
                outputs: vec!["out".into()],
                excludes: vec![],
                allow_secrets: vec![],
                extra_files: vec![],
                attachments: vec![],
                output_dir: None,
                env: vec![],
                cpu_millis: 1000,
                memory_bytes: 256 << 20,
                timeout: Duration::from_secs(120),
                speed: None,
            },
            tx,
        )
        .await
        .unwrap();
    let logs = logs.await.unwrap();
    assert_eq!(report.status, TaskStatus::Succeeded, "{report:?} {logs}");
    assert!(!logs.contains("key=0"), "{logs}");
    assert!(logs.contains("65534"), "{logs}");
    assert_eq!(
        std::fs::read_to_string(project.path().join("out/answer.txt")).unwrap(),
        "42\n"
    );
}

/// A container task is shown running once `docker run` started it, and its time counts from
/// then (its figures are not measured yet: they stay "not measured", never zero).
#[tokio::test]
async fn a_container_task_is_shown_running_with_unmeasured_figures() {
    let Some(img) = image() else { return };
    let env = setup();
    let usage = gimmecores_node::usage::UsageCell::new();
    let (tx, mut rx) = mpsc::channel::<LogChunk>(16);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let spec = RunSpec {
        name: name(),
        argv: vec!["/bin/sh".into(), "-c".into(), "sleep 2".into()],
        workdir: env.work.clone(),
        image: Some(img),
        cpu_millis: 1000,
        memory_bytes: 256 << 20,
        timeout: Duration::from_secs(60),
        env: vec![],
        read_only: vec![],
        usage: Some(usage.clone()),
        speed: gimmecores_core::Speed::Full,
    };
    let end = DockerExecutor::default()
        .run(spec, tx, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(end, RunEnd::Exited(0));
    assert!(usage.spawned());
    assert!(
        usage.running_for_ms().unwrap() >= 1500,
        "{:?}",
        usage.running_for_ms()
    );
    let u = usage.read();
    assert_eq!(
        (u.cpu_time_ms, u.memory_bytes, u.processes),
        (None, None, None)
    );
}
