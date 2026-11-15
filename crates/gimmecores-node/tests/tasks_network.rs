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
        attachments: vec![],
        output_dir: None,
        env: vec![],
        cpu_millis: 1000,
        memory_bytes: 1 << 30,
        timeout: Duration::from_secs(30),
        speed: None,
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

#[tokio::test]
async fn secrets_sent_by_name_reach_the_task_but_never_a_log() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "a").unwrap();
    let value = format!("tok-{}", "s3cr3t-value-123");
    let mut s = spec(dir.path(), "printf '%s' \"$GMC_TEST_TOKEN\" | wc -c", &[]);
    s.env = vec![("GMC_TEST_TOKEN".into(), value.clone())];
    let (report, out) = run(&laptop, &desktop.key(), g, s).await;
    assert_eq!(report.status, TaskStatus::Succeeded, "{out}");
    assert_eq!(
        out.trim(),
        value.len().to_string(),
        "the task saw the value"
    );
    for log in [desktop.paths().audit_log(), laptop.paths().audit_log()] {
        let text = std::fs::read_to_string(log).unwrap();
        assert!(text.contains("GMC_TEST_TOKEN"), "the name is recorded");
        assert!(!text.contains(&value), "the value is never recorded");
    }

    // The lender's own variables cannot be replaced, from either side.
    for name in ["PATH", "HOME", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES"] {
        let mut s = spec(dir.path(), "true", &[]);
        s.env = vec![(name.into(), "/tmp/evil".into())];
        let (tx, _rx) = mpsc::channel::<LogChunk>(64);
        assert!(
            laptop.run_task(&desktop.key(), g, s, tx).await.is_err(),
            "{name} accepted"
        );
    }
}

/// Upload throughput over loopback (run with --release --ignored --nocapture).
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn upload_speed() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    desktop
        .set_protections(gimmecores_node::power::Protections {
            pause_on_battery: false,
            idle_only: false,
            pause_when_hot: false,
        })
        .unwrap();
    let g = {
        pair(&laptop, &desktop).await;
        let req = {
            let (b, k) = (laptop.clone(), desktop.key());
            let mut t = standard_terms(2, 2, 1, now());
            t.limits.disk_bytes = 8 << 30;
            tokio::spawn(async move { b.request_grant(&k, &t, "tests").await })
        };
        let incoming = eventually(|| desktop.incoming_requests().into_iter().next()).await;
        desktop
            .respond_to_request(incoming.id, Decision::Accept(None))
            .unwrap();
        match req.await.unwrap().unwrap() {
            GrantOutcome::Granted { id, .. } => id,
            other => panic!("{other:?}"),
        }
    };
    let dir = tempfile::tempdir().unwrap();
    let mut seed = 1u64;
    for i in 0..16 {
        let mut data = vec![0u8; 64 << 20];
        for chunk in data.chunks_mut(8) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            chunk.copy_from_slice(&seed.to_le_bytes()[..chunk.len()]);
        }
        std::fs::write(dir.path().join(format!("f{i}.bin")), data).unwrap();
    }
    let t = std::time::Instant::now();
    let (report, out) = run(&laptop, &desktop.key(), g, spec(dir.path(), "true", &[])).await;
    let secs = t.elapsed().as_secs_f64();
    assert_eq!(
        report.status,
        TaskStatus::Succeeded,
        "{out} {:?}",
        report.error
    );
    eprintln!(
        "uploaded {} MiB in {secs:.2} s: {:.2} Gbit/s",
        report.uploaded_bytes >> 20,
        report.uploaded_bytes as f64 * 8.0 / secs / 1e9
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_uploads_stay_within_the_disk_limit() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    let req = {
        let (b, k) = (laptop.clone(), desktop.key());
        let mut t = standard_terms(2, 2, 1, now());
        t.limits.disk_bytes = 10 << 20;
        tokio::spawn(async move { b.request_grant(&k, &t, "tests").await })
    };
    let incoming = eventually(|| desktop.incoming_requests().into_iter().next()).await;
    desktop
        .respond_to_request(incoming.id, Decision::Accept(None))
        .unwrap();
    let GrantOutcome::Granted { id: g, .. } = req.await.unwrap().unwrap() else {
        panic!("not granted")
    };
    // 32 MiB in eight files: large enough for parallel streams, each file fitting alone.
    let dir = tempfile::tempdir().unwrap();
    for i in 0..8u8 {
        std::fs::write(dir.path().join(format!("f{i}")), vec![i; 4 << 20]).unwrap();
    }
    let (tx, _rx) = mpsc::channel::<LogChunk>(64);
    let r = laptop
        .run_task(&desktop.key(), g, spec(dir.path(), "true", &[]), tx)
        .await;
    assert!(r.is_err(), "over the limit: {r:?}");
    // What the lender kept for this borrower never went over the limit.
    let blobs = desktop.paths().blobs_dir().join(laptop.key().to_hex());
    let stored: u64 = std::fs::read_dir(&blobs)
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.metadata().ok())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0);
    assert!(stored <= 10 << 20, "stored {stored} bytes");
}

/// A borrower that skips its own checks: the lender refuses variables that would replace its
/// own (the dynamic loader's above all) before anything runs.
#[tokio::test]
async fn the_lender_refuses_loader_variables_from_a_hostile_borrower() {
    use gimmecores_node::wire;
    use gimmecores_proto::peer::v1 as pb;
    use gimmecores_proto::peer::v1::peer_message::Body;

    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    for (name, value) in [
        ("LD_PRELOAD", "/tmp/evil.so"),
        ("DYLD_INSERT_LIBRARIES", "/x"),
        ("PATH", "/tmp"),
    ] {
        let conn = laptop.dial_raw(&desktop.key()).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        wire::send(
            &mut send,
            Body::SubmitTask(pb::SubmitTask {
                task_id: vec![7; 16],
                grant_id: g.0.to_vec(),
                mode: pb::ExecutionMode::Sandbox as i32,
                work: Some(pb::submit_task::Work::Command(pb::Command {
                    argv: vec!["true".into()],
                    working_directory: String::new(),
                    environment: [(name.to_string(), value.to_string())].into(),
                })),
                limits: Some(pb::Limits {
                    cpu_millis: 1000,
                    memory_bytes: 1 << 30,
                    ..Default::default()
                }),
                input_root: Some(pb::Digest {
                    hash: vec![0; 32],
                    size_bytes: 0,
                    function: pb::DigestFunction::Sha256 as i32,
                }),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        let Body::TaskEvent(ev) = wire::recv(&mut recv).await.unwrap() else {
            panic!("expected a task event")
        };
        let Some(pb::task_event::Event::Finished(r)) = ev.event else {
            panic!("expected the task to be refused: {ev:?}")
        };
        assert_eq!(r.status, pb::task_result::Status::Rejected as i32, "{name}");
        let why = r.error.map(|e| e.message).unwrap_or_default();
        assert!(why.contains("set by the lender"), "{name}: {why}");
    }
    let log = std::fs::read_to_string(desktop.paths().audit_log()).unwrap();
    assert!(
        !log.contains("evil.so"),
        "refused before anything was recorded as starting"
    );
}

#[tokio::test]
async fn the_borrower_can_cancel_a_running_task_and_the_lender_stops_it() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();
    let cancel = tokio_util::sync::CancellationToken::new();
    let handle = {
        let (l, k, c) = (laptop.clone(), desktop.key(), cancel.clone());
        let s = spec(project.path(), "echo started; sleep 30", &[]);
        tokio::spawn(async move {
            let (tx, mut rx) = mpsc::channel::<LogChunk>(64);
            tokio::spawn(async move { while rx.recv().await.is_some() {} });
            l.run_task_until(&k, g, s, tx, c).await
        })
    };
    eventually(|| desktop_has_running(&desktop).then_some(())).await;
    let t0 = Instant::now();
    cancel.cancel();
    let report = handle.await.unwrap().unwrap();
    assert_eq!(report.status, TaskStatus::Cancelled, "{report:?}");
    assert!(t0.elapsed() < Duration::from_secs(10), "stopped promptly");
    eventually(|| (!desktop_has_running(&desktop)).then_some(())).await;
    // The grant itself is untouched: the next task runs normally.
    let (next, _) = run(
        &laptop,
        &desktop.key(),
        g,
        spec(project.path(), "true", &[]),
    )
    .await;
    assert_eq!(next.status, TaskStatus::Succeeded);
}

#[tokio::test]
async fn a_task_cancelled_before_it_starts_never_runs() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();
    let marker = project.path().join("ran");
    let cancel = tokio_util::sync::CancellationToken::new();
    cancel.cancel();
    let (tx, _rx) = mpsc::channel::<LogChunk>(64);
    let s = spec(project.path(), "touch ran", &["ran"]);
    let err = laptop
        .run_task_until(&desktop.key(), g, s, tx, cancel)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("cancelled"), "{err:#}");
    assert!(!marker.exists());
    assert!(!desktop_has_running(&desktop));
}

#[tokio::test]
async fn a_node_that_stops_ends_the_tasks_it_was_running() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();
    let handle = {
        let (l, k) = (laptop.clone(), desktop.key());
        // A process tree, not one process: the child must go too.
        let s = spec(project.path(), "sleep 30 & echo started; wait", &[]);
        tokio::spawn(async move {
            let (tx, mut rx) = mpsc::channel::<LogChunk>(64);
            tokio::spawn(async move { while rx.recv().await.is_some() {} });
            l.run_task(&k, g, s, tx).await
        })
    };
    eventually(|| desktop_has_running(&desktop).then_some(())).await;
    let t0 = Instant::now();
    desktop.shutdown().await;
    assert!(!desktop_has_running(&desktop), "nothing is left running");
    assert!(t0.elapsed() < Duration::from_secs(8), "stopped promptly");
    // The borrower is told, instead of waiting for a task that will never finish.
    let outcome = tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("the borrower hears about it")
        .unwrap();
    match outcome {
        Ok(report) => assert_eq!(report.status, TaskStatus::Cancelled, "{report:?}"),
        Err(e) => assert!(!format!("{e:#}").is_empty()),
    }
    // What was done is on record.
    let log = std::fs::read_to_string(desktop.paths().audit_log()).unwrap();
    assert!(log.contains("stopping: 1 running task(s) stopped"), "{log}");
}

/// A raw task submission from `from` to `to`, as a hostile device could send it.
async fn submit_raw(
    from: &Node,
    to: &PeerKey,
    task_id: u8,
    grant: [u8; 16],
    image: Option<String>,
) -> gimmecores_proto::peer::v1::TaskResult {
    use gimmecores_node::wire;
    use gimmecores_proto::peer::v1 as pb;
    use gimmecores_proto::peer::v1::peer_message::Body;
    let conn = from.dial_raw(to).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let mode = if image.is_some() {
        pb::ExecutionMode::Container
    } else {
        pb::ExecutionMode::Sandbox
    };
    wire::send(
        &mut send,
        Body::SubmitTask(pb::SubmitTask {
            task_id: vec![task_id; 16],
            grant_id: grant.to_vec(),
            mode: mode as i32,
            env: image.map(|reference| pb::Environment {
                kind: Some(pb::environment::Kind::Image(pb::ImageEnv {
                    reference,
                    digest: String::new(),
                })),
            }),
            work: Some(pb::submit_task::Work::Command(pb::Command {
                argv: vec!["echo".into(), "starting-for-nobody".into()],
                working_directory: String::new(),
                environment: Default::default(),
            })),
            limits: Some(pb::Limits {
                cpu_millis: 1000,
                memory_bytes: 1 << 30,
                ..Default::default()
            }),
            input_root: Some(pb::Digest {
                hash: vec![0; 32],
                size_bytes: 0,
                function: pb::DigestFunction::Sha256 as i32,
            }),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let Body::TaskEvent(ev) = wire::recv(&mut recv).await.unwrap() else {
        panic!("expected a task event")
    };
    let Some(pb::task_event::Event::Finished(r)) = ev.event else {
        panic!("expected the task to be refused: {ev:?}")
    };
    r
}

/// A paired device with no grant cannot write to the lender's audit log by sending tasks.
#[tokio::test]
async fn a_refused_task_writes_no_audit_entry() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    common::pair(&laptop, &desktop).await;
    let log = desktop.paths().audit_log();
    let before = std::fs::metadata(&log).map(|m| m.len()).unwrap_or(0);
    for i in 0..20u8 {
        let r = submit_raw(&laptop, &desktop.key(), i, [9; 16], None).await;
        assert_eq!(
            r.status,
            gimmecores_proto::peer::v1::task_result::Status::Rejected as i32
        );
        let why = r.error.map(|e| e.message).unwrap_or_default();
        assert!(why.contains("no active grant"), "{why}");
    }
    // An oversized image name is refused before anything else (it is never cleaned).
    let r = submit_raw(
        &laptop,
        &desktop.key(),
        99,
        [9; 16],
        Some("a".repeat(1 << 20)),
    )
    .await;
    let why = r.error.map(|e| e.message).unwrap_or_default();
    assert!(why.contains("not a valid container image"), "{why}");
    let after = std::fs::metadata(&log).map(|m| m.len()).unwrap_or(0);
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(!text.contains("starting-for-nobody"), "{text}");
    assert!(
        after - before < 1024,
        "the log grew by {} bytes",
        after - before
    );
}

/// Only a device whose own grant is paused learns that, and why, lending is paused here.
#[tokio::test]
async fn a_device_without_a_grant_is_not_told_why_lending_is_paused() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let (tablet, _h3) = node("Tablet").await;
    let g = granted(&laptop, &desktop).await;
    common::pair(&tablet, &desktop).await;
    desktop.apply_protection(Some("on battery")).await;
    let r = submit_raw(&tablet, &desktop.key(), 1, g.0, None).await;
    let why = r.error.map(|e| e.message).unwrap_or_default();
    assert!(!why.contains("battery") && !why.contains("paused"), "{why}");
    // The grant's own holder is told.
    let r = submit_raw(&laptop, &desktop.key(), 2, g.0, None).await;
    let why = r.error.map(|e| e.message).unwrap_or_default();
    assert!(why.contains("paused (on battery)"), "{why}");
}

/// Commands reach the audit logs shortened, with likely secrets hidden, on both devices.
#[tokio::test]
async fn audit_entries_stay_short_and_hide_tokens() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();
    let big = "x".repeat(10_000);
    let token = "t0ps3cretvalue123";
    let mut s = spec(project.path(), "echo seen; true", &[]);
    s.argv = vec![
        "sh".into(),
        "-c".into(),
        "echo got \"$1\"; true".into(),
        "--".into(),
        format!("--token={token}"),
        big,
    ];
    let (report, logs) = run(&laptop, &desktop.key(), g, s).await;
    assert_eq!(report.status, TaskStatus::Succeeded, "{report:?}");
    // The task itself still receives the argument.
    assert!(logs.contains(token), "{logs}");
    for (who, n) in [("lender", &desktop), ("borrower", &laptop)] {
        let log = std::fs::read_to_string(n.paths().audit_log()).unwrap();
        assert!(!log.contains(token), "{who} log holds the token");
        let longest = log.lines().map(str::len).max().unwrap_or(0);
        assert!(longest < 2048, "{who} log line of {longest} bytes");
    }
    let borrower = std::fs::read_to_string(laptop.paths().audit_log()).unwrap();
    assert!(borrower.contains("ran on Desktop"), "{borrower}");
}
