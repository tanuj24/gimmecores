//! What the lender sees: each task running here with its command, what it asked for and what
//! it uses; finished tasks grouped with how they ended; the owner stopping one task.
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
use gimmecores_proto::local::v1 as l;
use gimmecores_proto::peer::v1 as pb;
use tokio::sync::mpsc;

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

fn spec(dir: &Path, argv: &[&str]) -> TaskSpec {
    TaskSpec {
        dir: dir.to_path_buf(),
        argv: argv.iter().map(|s| s.to_string()).collect(),
        image: None,
        mode: None,
        outputs: vec![],
        excludes: vec![],
        allow_secrets: vec![],
        extra_files: vec![],
        attachments: vec![],
        output_dir: None,
        env: vec![("CI".into(), "1".into())],
        cpu_millis: 1500,
        memory_bytes: 512 << 20,
        timeout: Duration::from_secs(60),
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

/// Keeps one core busy for about three seconds on any shell (dash is several times faster than
/// bash): built-ins only, with the clock read rarely (short-lived processes are what sampling
/// can miss).
const BUSY: &str = "end=$(( $(date +%s) + 3 )); while [ $(date +%s) -lt $end ]; do i=0; while [ $i -lt 20000 ]; do i=$((i+1)); done; done";

#[tokio::test]
async fn the_lender_lists_a_running_task_with_what_it_asked_for_and_uses() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("data.bin"), vec![7u8; 300_000]).unwrap();
    let token = "t0ps3cretvalue123";
    let handle = {
        let (l, k) = (laptop.clone(), desktop.key());
        let s = spec(
            project.path(),
            &["sh", "-c", BUSY, "--", &format!("--token={token}")],
        );
        tokio::spawn(async move { run(&l, &k, g, s).await })
    };
    // Running, measured: CPU time, a CPU rate, memory, processes, the folder's size.
    let row = eventually(|| {
        let a = desktop.activity();
        let r = a.running.first()?.clone();
        let u = r.usage?;
        (r.phase == l::ExecPhase::Running as i32
            && u.cpu_time_ms? >= 300
            && u.cpu_millis_now.is_some()
            && u.disk_bytes.is_some())
        .then_some(r)
    })
    .await;
    assert_eq!(row.direction, l::Direction::Here as i32);
    assert_eq!(row.peer_name, "Laptop");
    assert_eq!(row.argv[..2], ["sh", "-c"]);
    // Long arguments are cut at 64 characters, never merged with the next.
    let shown: String = BUSY.chars().take(64).collect();
    assert_eq!(row.argv[2], format!("{shown}…"), "{:?}", row.argv);
    assert!(row.argv_cut);
    assert_eq!(row.argv_total, 5);
    assert!(
        !row.argv.iter().any(|a| a.contains(token)),
        "{:?}",
        row.argv
    );
    assert_eq!(row.argv_hidden, 1);
    assert_eq!(row.env_names, ["CI"]);
    let asked = row.asked.unwrap();
    assert_eq!((asked.cpu_millis, asked.memory_bytes), (1500, 512 << 20));
    assert!(
        !asked.cpu_limit_enforced,
        "the sandbox monitors CPU, it does not cap it"
    );
    assert!(asked.effective_timeout.is_some());
    let u = row.usage.unwrap();
    assert!(
        u.memory_bytes.unwrap() > 0 && u.processes.unwrap() >= 1,
        "{u:?}"
    );
    assert!(u.disk_bytes.unwrap() >= 300_000, "{u:?}");
    assert!(!u.reported_by_peer);
    assert!(row.can_stop);

    let (report, _) = handle.await.unwrap();
    assert_eq!(report.status, TaskStatus::Succeeded, "{report:?}");
    // Finished: filed with how it ended and what it used in all.
    let a = eventually(|| {
        let a = desktop.activity();
        (a.running.is_empty() && !a.recent.is_empty()).then_some(a)
    })
    .await;
    let g = &a.recent[0];
    assert_eq!((g.count, g.succeeded), (1, 1));
    assert!(g.cpu_time_ms_total.unwrap() >= 1000, "{g:?}");
    let end = g.last.as_ref().unwrap().ending.clone().unwrap();
    assert_eq!(end.exit_code, Some(0));
    assert_eq!(end.cause, pb::EndCause::Exited as i32);
    assert!(a.since.unwrap().seconds > 0);
}

#[tokio::test]
async fn the_owner_stops_one_task_and_the_borrower_is_told_why() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();
    let handle = {
        let (l, k) = (laptop.clone(), desktop.key());
        let s = spec(project.path(), &["sh", "-c", "echo started; sleep 30"]);
        tokio::spawn(async move { run(&l, &k, g, s).await })
    };
    let id = eventually(|| {
        let r = desktop.activity().running.first()?.clone();
        (r.phase == l::ExecPhase::Running as i32).then_some(r.id)
    })
    .await;
    let t0 = Instant::now();
    desktop
        .stop_task(gimmecores_core::TaskId(id.as_slice().try_into().unwrap()))
        .unwrap();
    let (report, logs) = handle.await.unwrap();
    assert!(t0.elapsed() < Duration::from_secs(10));
    assert_eq!(report.status, TaskStatus::Cancelled, "{report:?}");
    assert!(logs.contains("stopped by the lender's owner"), "{logs}");
    let a = eventually(|| {
        let a = desktop.activity();
        a.running.is_empty().then_some(a)
    })
    .await;
    let end = a.recent[0].last.as_ref().unwrap().ending.clone().unwrap();
    assert_eq!(end.cause, pb::EndCause::OwnerStopped as i32);
    assert_eq!(end.exit_code, None);
    assert_eq!(a.recent[0].stopped, 1);
    // Only that task: the grant still works.
    let (next, _) = run(&laptop, &desktop.key(), g, spec(project.path(), &["true"])).await;
    assert_eq!(next.status, TaskStatus::Succeeded);
    assert!(desktop.stop_task(gimmecores_core::TaskId([1; 16])).is_err());
}

#[tokio::test]
async fn a_revoked_task_is_filed_with_its_cause() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();
    let handle = {
        let (l, k) = (laptop.clone(), desktop.key());
        let s = spec(project.path(), &["sleep", "30"]);
        tokio::spawn(async move { run(&l, &k, g, s).await })
    };
    eventually(|| (!desktop.activity().running.is_empty()).then_some(())).await;
    desktop.revoke_grant(g).await.unwrap();
    let (report, _) = handle.await.unwrap();
    assert_eq!(report.status, TaskStatus::Revoked);
    let a = eventually(|| {
        let a = desktop.activity();
        a.running.is_empty().then_some(a)
    })
    .await;
    let end = a.recent[0].last.as_ref().unwrap().ending.clone().unwrap();
    assert_eq!(end.cause, pb::EndCause::GrantRevoked as i32);
}

#[tokio::test]
async fn a_paused_task_shows_frozen_and_counts_its_frozen_time() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();
    let handle = {
        let (l, k) = (laptop.clone(), desktop.key());
        let s = spec(project.path(), &["sh", "-c", "sleep 2; echo done"]);
        tokio::spawn(async move { run(&l, &k, g, s).await })
    };
    eventually(|| {
        let r = desktop.activity().running.first()?.clone();
        (r.phase == l::ExecPhase::Running as i32).then_some(())
    })
    .await;
    desktop.apply_protection(Some("on battery")).await;
    let row = desktop.activity().running[0].clone();
    assert_eq!(row.phase, l::ExecPhase::Frozen as i32);
    assert_eq!(
        row.usage.unwrap().frozen_why,
        pb::PauseCause::OnBattery as i32
    );
    tokio::time::sleep(Duration::from_millis(600)).await;
    desktop.apply_protection(None).await;
    let (report, logs) = handle.await.unwrap();
    assert_eq!(report.status, TaskStatus::Succeeded, "{logs}");
    let a = desktop.activity();
    let u = a.recent[0].last.as_ref().unwrap().usage.unwrap();
    assert!(u.frozen_ms >= 500, "{u:?}");
}

#[tokio::test]
async fn unpairing_forgets_that_devices_history() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();
    let (r, _) = run(&laptop, &desktop.key(), g, spec(project.path(), &["true"])).await;
    assert_eq!(r.status, TaskStatus::Succeeded);
    eventually(|| (!desktop.activity().recent.is_empty()).then_some(())).await;
    desktop.forget_peer(&laptop.key()).unwrap();
    assert!(desktop.activity().recent.is_empty());
}
