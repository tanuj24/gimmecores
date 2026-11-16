//! Build caches kept on the lender between tasks (#26): only for the borrower that made them,
//! only while it holds a live grant, counted in its disk quota, and never a way to move or
//! reach the lender's own files.
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

mod common;

use std::path::Path;
use std::time::Duration;

use common::{eventually, node, pair};
use gimmecores_core::GrantId;
use gimmecores_node::exec::LogChunk;
use gimmecores_node::grants_flow::{Decision, GrantOutcome, standard_terms};
use gimmecores_node::node::Node;
use gimmecores_node::now;
use gimmecores_node::tasks_flow::{TaskReport, TaskSpec, TaskStatus};
use tokio::sync::mpsc;

async fn granted(borrower: &Node, lender: &Node) -> GrantId {
    let req = {
        let (b, k) = (borrower.clone(), lender.key());
        tokio::spawn(async move {
            b.request_grant(&k, &standard_terms(2, 2, 1, now()), "")
                .await
        })
    };
    let incoming = eventually(|| lender.incoming_requests().into_iter().next()).await;
    lender
        .respond_to_request(incoming.id, Decision::Accept(None))
        .unwrap();
    match req.await.unwrap().unwrap() {
        GrantOutcome::Granted { id, .. } => id,
        other => panic!("{other:?}"),
    }
}

fn spec(dir: &Path, script: &str, caches: &[&str]) -> TaskSpec {
    TaskSpec {
        send_image: true,
        dir: dir.to_path_buf(),
        argv: vec!["sh".into(), "-c".into(), script.into()],
        image: None,
        mode: None,
        outputs: vec![],
        excludes: vec![],
        allow_secrets: vec![],
        extra_files: vec![],
        attachments: vec![],
        output_dir: None,
        env: vec![],
        cpu_millis: 1000,
        memory_bytes: 512 << 20,
        timeout: Duration::from_secs(60),
        speed: None,
        caches: caches.iter().map(|c| (*c).to_string()).collect(),
    }
}

async fn run(b: &Node, l: &Node, g: GrantId, s: TaskSpec) -> (TaskReport, String) {
    let (tx, mut rx) = mpsc::channel::<LogChunk>(64);
    let collect = tokio::spawn(async move {
        let mut out = String::new();
        while let Some(c) = rx.recv().await {
            out.push_str(&String::from_utf8_lossy(&c.data));
        }
        out
    });
    let report = b.run_task(&l.key(), g, s, tx).await.unwrap();
    (report, collect.await.unwrap())
}

fn project() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("src.txt"), "source").unwrap();
    d
}

#[tokio::test]
async fn a_cache_is_there_for_the_next_task_of_the_same_project() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    let g = granted(&laptop, &desktop).await;
    let p = project();
    let (r, _) = run(
        &laptop,
        &desktop,
        g,
        spec(
            p.path(),
            "mkdir -p target && echo built > target/out",
            &["target"],
        ),
    )
    .await;
    assert_eq!(r.status, TaskStatus::Succeeded);
    let (r, out) = run(
        &laptop,
        &desktop,
        g,
        spec(p.path(), "cat target/out", &["target"]),
    )
    .await;
    assert_eq!(r.status, TaskStatus::Succeeded, "{out}");
    assert_eq!(out.trim(), "built");
    // Not for another project of the same borrower.
    let other = project();
    let (r, out) = run(
        &laptop,
        &desktop,
        g,
        spec(
            other.path(),
            "cat target/out 2>&1 || echo cold",
            &["target"],
        ),
    )
    .await;
    assert_eq!(r.status, TaskStatus::Succeeded);
    assert!(out.contains("cold"), "{out}");
    // A cache is not uploaded: a local `target/` stays on the borrower.
    std::fs::create_dir_all(p.path().join("target")).unwrap();
    std::fs::write(p.path().join("target/local"), "here only").unwrap();
    let (_, out) = run(
        &laptop,
        &desktop,
        g,
        spec(p.path(), "ls target", &["target"]),
    )
    .await;
    assert!(!out.contains("local"), "{out}");
}

#[tokio::test]
async fn another_borrower_never_sees_it() {
    let (a, _h1) = node("Alice").await;
    let (b, _h2) = node("Bob").await;
    let (desktop, _h3) = node("Desktop").await;
    pair(&a, &desktop).await;
    pair(&b, &desktop).await;
    let ga = granted(&a, &desktop).await;
    let gb = granted(&b, &desktop).await;
    // Same folder name and cache path on both borrowers.
    let p = project();
    run(
        &a,
        &desktop,
        ga,
        spec(p.path(), "mkdir -p c && echo secret > c/s", &["c"]),
    )
    .await;
    let (r, out) = run(
        &b,
        &desktop,
        gb,
        spec(p.path(), "cat c/s 2>&1 || echo nothing", &["c"]),
    )
    .await;
    assert_eq!(r.status, TaskStatus::Succeeded);
    assert!(out.contains("nothing") && !out.contains("secret"), "{out}");
}

#[tokio::test]
async fn a_task_cannot_turn_its_cache_into_a_way_out() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    let g = granted(&laptop, &desktop).await;
    // The lender's own files, outside any task.
    let outside = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(outside.path().join("c")).unwrap();
    std::fs::write(outside.path().join("c/owner.txt"), "the owner's").unwrap();
    let p = project();
    // The cache `sub/c`: the task replaces `sub` with a link to the outside folder, then the
    // cache itself with a link too.
    let script = format!(
        "rm -rf sub && ln -s {} sub; ln -s {} other",
        outside.path().display(),
        outside.path().display()
    );
    let (r, _) = run(&laptop, &desktop, g, spec(p.path(), &script, &["sub/c"])).await;
    assert_eq!(r.status, TaskStatus::Succeeded);
    // Nothing of the owner's was moved into the cache.
    assert_eq!(
        std::fs::read_to_string(outside.path().join("c/owner.txt")).unwrap(),
        "the owner's"
    );
    let script = format!("ln -s {} c", outside.path().join("c").display());
    run(&laptop, &desktop, g, spec(p.path(), &script, &["c"])).await;
    assert!(outside.path().join("c/owner.txt").exists());
    // And the next task does not get a link out as its cache.
    let (_, out) = run(
        &laptop,
        &desktop,
        g,
        spec(p.path(), "test -L c && echo LINK || echo plain", &["c"]),
    )
    .await;
    assert!(out.contains("plain"), "{out}");
    let (_, out) = run(
        &laptop,
        &desktop,
        g,
        spec(p.path(), "ls sub/c 2>&1 || echo none", &["sub/c"]),
    )
    .await;
    assert!(!out.contains("owner.txt"), "{out}");
}

#[tokio::test]
async fn it_counts_in_the_quota_and_goes_with_the_last_grant() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    let g = granted(&laptop, &desktop).await;
    let p = project();
    let before = desktop.blob_usage(&laptop.key());
    run(
        &laptop,
        &desktop,
        g,
        spec(
            p.path(),
            "mkdir -p c && head -c 3000000 /dev/zero > c/big",
            &["c"],
        ),
    )
    .await;
    let after = desktop.blob_usage(&laptop.key());
    assert!(after >= before + 3_000_000, "{before} -> {after}");
    // The last grant ends: the cache goes with the borrower's other files.
    desktop.revoke_grant(g).await.unwrap();
    eventually(|| (desktop.blob_usage(&laptop.key()) == 0).then_some(())).await;
    let g = granted(&laptop, &desktop).await;
    let (_, out) = run(
        &laptop,
        &desktop,
        g,
        spec(p.path(), "ls c 2>&1 || echo cold", &["c"]),
    )
    .await;
    assert!(out.contains("cold"), "{out}");
}

#[tokio::test]
async fn two_tasks_at_once_do_not_share_one_cache() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    let g = granted(&laptop, &desktop).await;
    let p = project();
    run(
        &laptop,
        &desktop,
        g,
        spec(p.path(), "mkdir -p c && echo v1 > c/v", &["c"]),
    )
    .await;
    // The first holds the cache for a while; the second starts cold meanwhile.
    let slow = {
        let (l, d, s) = (
            laptop.clone(),
            desktop.clone(),
            spec(p.path(), "cat c/v; sleep 2; echo v2 > c/v", &["c"]),
        );
        tokio::spawn(async move { run(&l, &d, g, s).await })
    };
    tokio::time::sleep(Duration::from_millis(800)).await;
    let (_, out) = run(
        &laptop,
        &desktop,
        g,
        spec(
            p.path(),
            "cat c/v 2>&1 || echo cold; mkdir -p c && echo mine > c/v",
            &["c"],
        ),
    )
    .await;
    assert!(out.contains("cold"), "{out}");
    let (_, out1) = slow.await.unwrap();
    assert!(out1.contains("v1"), "{out1}");
    // The task that held it put it back; the other's copy was its own.
    let (_, out) = run(&laptop, &desktop, g, spec(p.path(), "cat c/v", &["c"])).await;
    assert_eq!(out.trim(), "v2");
}

#[tokio::test]
async fn cache_paths_are_checked() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    let g = granted(&laptop, &desktop).await;
    let p = project();
    for bad in ["/etc", "../up", ".gmc-sdk/x", ""] {
        let (tx, _rx) = mpsc::channel::<LogChunk>(64);
        let r = laptop
            .run_task(&desktop.key(), g, spec(p.path(), "true", &[bad]), tx)
            .await;
        assert!(r.is_err(), "{bad:?} was accepted");
    }
}

/// A lender running tasks with real runners (not the test processes).
async fn real_lender(executors: gimmecores_node::exec::Executors) -> (Node, tempfile::TempDir) {
    use gimmecores_node::node::NodeConfig;
    use gimmecores_node::paths::Paths;
    use gimmecores_node::presence::{FixedPresence, Outcome};
    let home = tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap();
    let n = Node::start(NodeConfig {
        paths: Paths::at(home.path()),
        device_name: "Desktop".into(),
        bind: "127.0.0.1:0".parse().unwrap(),
        executors,
        presence: std::sync::Arc::new(FixedPresence(Outcome::Verified)),
    })
    .await
    .unwrap();
    n.set_lending(true).unwrap();
    n.set_protections(gimmecores_node::power::Protections {
        pause_on_battery: false,
        idle_only: false,
        pause_when_hot: false,
    })
    .unwrap();
    (n, home)
}

/// Writes into the cache, locks a folder in it, reads it back next time, and the namespace
/// still goes when the grant ends: under `image` (a container) or the OS sandbox.
async fn cache_round_trip(desktop: &Node, image: Option<String>) {
    let (laptop, _h) = common::fresh_node("Laptop").await;
    pair(&laptop, desktop).await;
    let g = granted(&laptop, desktop).await;
    let p = project();
    let mut first = spec(
        p.path(),
        "mkdir -p c/locked && echo warm > c/x && echo in > c/locked/f && chmod 000 c/locked",
        &["c"],
    );
    first.image = image.clone();
    let (r, out) = run(&laptop, desktop, g, first).await;
    assert_eq!(r.status, TaskStatus::Succeeded, "{out}");
    assert!(desktop.blob_usage(&laptop.key()) > 0);
    let mut second = spec(p.path(), "cat c/x", &["c"]);
    second.image = image;
    let (r, out) = run(&laptop, desktop, g, second).await;
    assert_eq!(r.status, TaskStatus::Succeeded, "{out}");
    assert_eq!(out.trim(), "warm");
    desktop.revoke_grant(g).await.unwrap();
    eventually(|| (desktop.blob_usage(&laptop.key()) == 0).then_some(())).await;
}

#[tokio::test]
async fn caches_work_in_the_real_sandbox() {
    use gimmecores_core::{ExecutionMode, Modes};
    use gimmecores_node::exec::{Executor, Executors};
    use gimmecores_node::sandbox::SandboxExecutor;
    let x = SandboxExecutor::default();
    let required =
        cfg!(target_os = "macos") || std::env::var("GMC_REQUIRE_SANDBOX").as_deref() == Ok("1");
    if !x.probe().await {
        assert!(!required, "the sandbox does not work on this machine");
        eprintln!("skipping: no working sandbox here");
        return;
    }
    let (desktop, _h) = real_lender(Executors {
        container: None,
        sandbox: Some(std::sync::Arc::new(x)),
        images: None,
    })
    .await;
    desktop
        .set_lend_modes(Modes::only(ExecutionMode::Sandbox))
        .unwrap();
    cache_round_trip(&desktop, None).await;
}

#[tokio::test]
async fn caches_work_in_real_docker() {
    use gimmecores_core::{ExecutionMode, Modes};
    use gimmecores_node::exec::{DockerExecutor, Executors};
    let required = std::env::var("GMC_REQUIRE_DOCKER").as_deref() == Ok("1");
    let docker = |args: &[&str]| {
        std::process::Command::new("docker")
            .args(args)
            .output()
            .is_ok_and(|o| o.status.success())
    };
    if !docker(&["info"]) {
        assert!(!required, "Docker is required here but not running");
        eprintln!("skipping: Docker is not running");
        return;
    }
    let Some(img) = ["alpine:3.20", "alpine:latest", "busybox:latest"]
        .into_iter()
        .find(|i| docker(&["image", "inspect", i]))
    else {
        assert!(!required, "no test image present");
        return;
    };
    let (desktop, _h) = real_lender(Executors {
        container: Some(std::sync::Arc::new(DockerExecutor::default())),
        sandbox: None,
        images: Some(std::sync::Arc::new(
            gimmecores_node::images::DockerImages::default(),
        )),
    })
    .await;
    desktop
        .set_lend_modes(Modes::only(ExecutionMode::Container))
        .unwrap();
    cache_round_trip(&desktop, Some(img.to_string())).await;
}
