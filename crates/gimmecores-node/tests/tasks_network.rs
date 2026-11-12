#![allow(clippy::unwrap_used)]
#![cfg(unix)]

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::{eventually, node, pair};
use gimmecores_core::{GrantId, PeerKey};
use gimmecores_node::exec::LogChunk;
use gimmecores_node::grants_flow::{Decision, GrantOutcome, standard_terms};
use gimmecores_node::node::Node;
use gimmecores_node::now;
use gimmecores_node::tasks_flow::{TaskReport, TaskSpec, TaskStatus};
use tokio::sync::mpsc;

/// Pairs two nodes and returns an active grant from `lender` to `borrower`.
async fn granted(borrower: &Node, lender: &Node) -> GrantId {
    pair(borrower, lender).await;
    let req = {
        let (b, k) = (borrower.clone(), lender.key());
        tokio::spawn(async move {
            b.request_grant(&k, &standard_terms(2, 2, 1, now()), "tests")
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

fn spec(dir: &Path, script: &str, outputs: &[&str]) -> TaskSpec {
    TaskSpec {
        dir: dir.to_path_buf(),
        argv: vec!["sh".into(), "-c".into(), script.into()],
        image: None,
        outputs: outputs.iter().map(|s| s.to_string()).collect(),
        excludes: vec![],
        cpu_millis: 1000,
        memory_bytes: 1 << 30,
        timeout: Duration::from_secs(30),
    }
}

async fn run(b: &Node, lender: &PeerKey, g: GrantId, s: TaskSpec) -> (TaskReport, String) {
    let (tx, mut rx) = mpsc::channel::<LogChunk>(64);
    let collect = tokio::spawn(async move {
        let mut out = String::new();
        while let Some(c) = rx.recv().await {
            out.push_str(&String::from_utf8_lossy(&c.data));
        }
        out
    });
    let report = b.run_task(lender, g, s, tx).await.unwrap();
    (report, collect.await.unwrap())
}

#[tokio::test]
async fn task_runs_remotely_streams_logs_and_returns_outputs() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;

    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("input.txt"), "42\n").unwrap();
    let script = "mkdir -p out && cat input.txt > out/result.txt && echo computed";
    let (report, logs) = run(
        &laptop,
        &desktop.key(),
        g,
        spec(project.path(), script, &["out"]),
    )
    .await;
    assert_eq!(report.status, TaskStatus::Succeeded, "{report:?}");
    assert!(logs.contains("computed"), "{logs}");
    assert_eq!(
        std::fs::read_to_string(project.path().join("out/result.txt")).unwrap(),
        "42\n"
    );
    assert!(report.uploaded_bytes > 0);

    // The first run wrote out/result.txt into the project, so the next run sends only that new
    // file and the changed directory listings - far less than the first upload.
    let (second, _) = run(
        &laptop,
        &desktop.key(),
        g,
        spec(project.path(), "true", &[]),
    )
    .await;
    assert_eq!(second.status, TaskStatus::Succeeded);
    assert!(second.uploaded_bytes < report.uploaded_bytes + 200);
    // Nothing changed since: content addressing means nothing is re-sent at all.
    let (third, _) = run(
        &laptop,
        &desktop.key(),
        g,
        spec(project.path(), "true", &[]),
    )
    .await;
    assert_eq!(third.uploaded_bytes, 0, "unchanged files are not re-sent");
}

#[tokio::test]
async fn failures_report_the_exit_code() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();
    let (report, logs) = run(
        &laptop,
        &desktop.key(),
        g,
        spec(project.path(), "echo boom >&2; exit 7", &[]),
    )
    .await;
    assert_eq!(report.status, TaskStatus::Failed);
    assert_eq!(report.exit_code, 7);
    assert!(logs.contains("boom"));
}

#[tokio::test]
async fn i7_secrets_never_reach_the_lender() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join(".env"), "TOKEN=hunter2").unwrap();
    std::fs::create_dir_all(project.path().join(".ssh")).unwrap();
    std::fs::write(project.path().join(".ssh/id_ed25519"), "key").unwrap();
    std::fs::write(project.path().join("app.py"), "print(1)").unwrap();
    let script = "ls -a; test -e .env && echo LEAK; test -e .ssh && echo LEAK; true";
    let (report, logs) = run(
        &laptop,
        &desktop.key(),
        g,
        spec(project.path(), script, &[]),
    )
    .await;
    assert_eq!(report.status, TaskStatus::Succeeded);
    assert!(logs.contains("app.py"), "{logs}");
    assert!(
        !logs.contains("LEAK"),
        "secret files reached the lender: {logs}"
    );
}

#[tokio::test]
async fn i1_tasks_without_a_valid_grant_or_beyond_it_are_rejected() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();

    // Unknown grant: even the upload is refused (I14).
    let (tx, _rx) = mpsc::channel(8);
    let bogus = laptop
        .run_task(
            &desktop.key(),
            GrantId([0xEE; 16]),
            spec(project.path(), "true", &[]),
            tx,
        )
        .await;
    assert!(bogus.is_err(), "upload without a grant must fail");

    // More CPU than granted (2 cores).
    let mut big = spec(project.path(), "echo ran", &[]);
    big.cpu_millis = 3000;
    let (report, logs) = run(&laptop, &desktop.key(), g, big).await;
    assert_eq!(report.status, TaskStatus::Rejected, "{report:?}");
    assert!(!logs.contains("ran"));
}

#[tokio::test]
async fn i3_revoke_kills_a_running_task_quickly() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();
    let handle = {
        let (l, k, s) = (
            laptop.clone(),
            desktop.key(),
            spec(project.path(), "echo started; sleep 30", &[]),
        );
        tokio::spawn(async move { run(&l, &k, g, s).await })
    };
    eventually(|| {
        (desktop.grant_state(g).is_some() && desktop_has_running(&desktop)).then_some(())
    })
    .await;
    let t0 = Instant::now();
    desktop.revoke_grant(g).await.unwrap();
    let (report, _) = handle.await.unwrap();
    assert_eq!(report.status, TaskStatus::Revoked, "{report:?}");
    assert!(
        t0.elapsed() < Duration::from_secs(10),
        "I3: within 10 seconds"
    );
}

#[tokio::test]
async fn i3_stop_all_lending_kills_running_tasks() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();
    let handle = {
        let (l, k, s) = (
            laptop.clone(),
            desktop.key(),
            spec(project.path(), "sleep 30", &[]),
        );
        tokio::spawn(async move { run(&l, &k, g, s).await })
    };
    eventually(|| desktop_has_running(&desktop).then_some(())).await;
    assert_eq!(desktop.stop_all_lending().len(), 1);
    let (report, _) = handle.await.unwrap();
    assert_eq!(report.status, TaskStatus::Revoked);
}

fn desktop_has_running(n: &Node) -> bool {
    n.running_task_count() > 0
}
