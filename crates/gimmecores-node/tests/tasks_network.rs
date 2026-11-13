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
        mode: None,
        outputs: outputs.iter().map(|s| s.to_string()).collect(),
        excludes: vec![],
        allow_secrets: vec![],
        extra_files: vec![],
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

#[tokio::test]
async fn i11_both_sides_keep_a_verifiable_audit_trail() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();
    let (report, _) = run(
        &laptop,
        &desktop.key(),
        g,
        spec(project.path(), "echo hi", &[]),
    )
    .await;
    assert_eq!(report.status, TaskStatus::Succeeded);

    use gimmecores_node::audit;
    let lender = audit::read(&desktop.paths().audit_log()).unwrap();
    assert!(lender.iter().any(|e| e.kind == "lending"), "{lender:#?}");
    assert!(lender.iter().any(|e| e.kind == "pair"));
    assert!(
        lender
            .iter()
            .any(|e| e.kind == "grant" && e.summary.starts_with("accepted"))
    );
    assert!(
        lender
            .iter()
            .any(|e| e.kind == "task" && e.summary.contains("starting for Laptop: sh -c echo hi"))
    );
    assert!(
        lender
            .iter()
            .any(|e| e.kind == "task" && e.summary.contains("finished"))
    );
    assert!(audit::verify(&desktop.paths().audit_log()).is_ok());

    let borrower = audit::read(&laptop.paths().audit_log()).unwrap();
    assert!(
        borrower
            .iter()
            .any(|e| e.kind == "grant" && e.summary.starts_with("received grant"))
    );
    assert!(
        borrower
            .iter()
            .any(|e| e.kind == "task" && e.summary.contains("ran on Desktop"))
    );
    assert!(audit::verify(&laptop.paths().audit_log()).is_ok());
}

#[tokio::test]
async fn i7_secrets_inside_ordinary_files_block_the_upload() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("main.py"), "print('ok')").unwrap();
    // A fake AWS key pasted into a normal source file (assembled at runtime).
    std::fs::write(
        project.path().join("settings.py"),
        format!("KEY = '{}{}'\n", "AKIA", "ABCDEFGHIJKLMNOP"),
    )
    .unwrap();

    let (tx, _rx) = mpsc::channel(8);
    let err = laptop
        .run_task(&desktop.key(), g, spec(project.path(), "true", &[]), tx)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("possible secrets") && err.contains("settings.py:1"),
        "{err}"
    );
    assert_eq!(desktop.running_task_count(), 0);

    // Explicitly allowed: the user decided this file may go.
    let mut allowed = spec(project.path(), "test -e settings.py && echo sent", &[]);
    allowed.allow_secrets = vec!["settings.py".into()];
    let (report, logs) = run(&laptop, &desktop.key(), g, allowed).await;
    assert_eq!(report.status, TaskStatus::Succeeded);
    assert!(logs.contains("sent"));
}

#[tokio::test]
async fn laptop_protections_pause_new_work_and_resume() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();

    desktop.apply_protection(Some("on battery")).await;
    assert_eq!(
        desktop.grant_state(g),
        Some(gimmecores_core::GrantState::Paused)
    );
    assert_eq!(desktop.pause_reason().as_deref(), Some("on battery"));
    let (report, _) = run(
        &laptop,
        &desktop.key(),
        g,
        spec(project.path(), "echo ran", &[]),
    )
    .await;
    assert_eq!(report.status, TaskStatus::Rejected);
    assert!(
        report
            .error
            .unwrap_or_default()
            .contains("paused (on battery)")
    );

    desktop.apply_protection(None).await;
    assert_eq!(
        desktop.grant_state(g),
        Some(gimmecores_core::GrantState::Active)
    );
    let (report, logs) = run(
        &laptop,
        &desktop.key(),
        g,
        spec(project.path(), "echo ran", &[]),
    )
    .await;
    assert_eq!(report.status, TaskStatus::Succeeded);
    assert!(logs.contains("ran"));
}

#[tokio::test]
async fn pausing_freezes_a_running_task_and_resuming_continues_it() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();
    let handle = {
        let script = "for i in 1 2 3 4 5 6 7 8 9 10; do echo step$i; sleep 0.1; done";
        let (l, k, s) = (
            laptop.clone(),
            desktop.key(),
            spec(project.path(), script, &[]),
        );
        tokio::spawn(async move { run(&l, &k, g, s).await })
    };
    eventually(|| desktop_has_running(&desktop).then_some(())).await;
    desktop.apply_protection(Some("on battery")).await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(desktop_has_running(&desktop), "frozen, not finished");
    desktop.apply_protection(None).await;
    let (report, logs) = handle.await.unwrap();
    assert_eq!(report.status, TaskStatus::Succeeded, "{report:?}");
    assert!(logs.contains("step10"), "{logs}");
}

#[tokio::test]
async fn i14_a_borrowers_files_are_deleted_once_no_grant_is_left() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;

    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("input.txt"), "private code\n").unwrap();
    let (report, _) = run(
        &laptop,
        &desktop.key(),
        g,
        spec(project.path(), "true", &[]),
    )
    .await;
    assert_eq!(report.status, TaskStatus::Succeeded, "{report:?}");
    let ns = desktop.paths().blobs_dir().join(laptop.key().to_hex());
    assert!(
        ns.exists(),
        "the lender holds the borrower's files while the grant is live"
    );

    desktop.revoke_grant(g).await.unwrap();
    assert!(
        !ns.exists(),
        "revoking the only grant deletes the borrower's files"
    );
    let log = std::fs::read_to_string(desktop.paths().audit_log()).unwrap();
    assert!(log.contains("\"kind\":\"storage\""), "{log}");
}

#[tokio::test]
async fn a_task_that_fills_the_disk_past_the_grant_is_stopped() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    let mut terms = standard_terms(2, 2, 1, now());
    terms.limits.disk_bytes = 1 << 20;
    let req = {
        let (b, k, t) = (laptop.clone(), desktop.key(), terms.clone());
        tokio::spawn(async move { b.request_grant(&k, &t, "tests").await })
    };
    let incoming = eventually(|| desktop.incoming_requests().into_iter().next()).await;
    desktop
        .respond_to_request(incoming.id, Decision::Accept(None))
        .unwrap();
    let g = match req.await.unwrap().unwrap() {
        GrantOutcome::Granted { id, .. } => id,
        other => panic!("{other:?}"),
    };

    let project = tempfile::tempdir().unwrap();
    let t = Instant::now();
    let (report, logs) = run(
        &laptop,
        &desktop.key(),
        g,
        spec(
            project.path(),
            "dd if=/dev/zero of=big bs=1048576 count=50 2>/dev/null; sleep 30",
            &[],
        ),
    )
    .await;
    assert_eq!(report.status, TaskStatus::LimitExceeded, "{report:?}");
    assert!(logs.contains("disk limit reached"), "{logs}");
    assert!(t.elapsed() < Duration::from_secs(10), "stopped promptly");
}

#[tokio::test]
async fn files_appearing_and_vanishing_during_a_build_do_not_stop_it() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();
    // Like a compiler: temporary files and directories created and deleted for ~3 seconds,
    // while the lender measures the workspace every second.
    let script = "end=$(( $(date +%s) + 3 )); while [ $(date +%s) -lt $end ]; do \
                  for i in 1 2 3 4 5 6 7 8; do mkdir -p t/$i && echo x > t/$i/f; done; \
                  rm -rf t; done; echo done";
    let (report, logs) = run(
        &laptop,
        &desktop.key(),
        g,
        spec(project.path(), script, &[]),
    )
    .await;
    assert_eq!(report.status, TaskStatus::Succeeded, "{report:?} {logs}");
}

#[tokio::test]
async fn i14_unpairing_or_turning_lending_off_deletes_a_borrowers_files() {
    for how in ["unpair", "lending off"] {
        let (laptop, _h1) = node("Laptop").await;
        let (desktop, _h2) = node("Desktop").await;
        let g = granted(&laptop, &desktop).await;
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("input.txt"), "private code\n").unwrap();
        let (report, _) = run(
            &laptop,
            &desktop.key(),
            g,
            spec(project.path(), "true", &[]),
        )
        .await;
        assert_eq!(report.status, TaskStatus::Succeeded, "{report:?}");
        let ns = desktop.paths().blobs_dir().join(laptop.key().to_hex());
        assert!(ns.exists());
        match how {
            "unpair" => drop(desktop.forget_peer(&laptop.key()).unwrap()),
            _ => drop(desktop.set_lending(false).unwrap()),
        }
        assert!(!ns.exists(), "{how} deletes the borrower's files");
    }
}
