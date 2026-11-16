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
        send_image: true,
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

#[tokio::test]
async fn the_borrower_sees_its_task_there_with_the_lenders_figures() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();
    let token = "t0ps3cretvalue123";
    let handle = {
        let (l, k) = (laptop.clone(), desktop.key());
        let s = spec(
            project.path(),
            &["sh", "-c", BUSY, "--", &format!("--token={token}")],
        );
        tokio::spawn(async move { run(&l, &k, g, s).await })
    };
    // On the borrower: its own task, there, with figures the lender reported while it runs.
    let (row, load) = eventually(|| {
        let a = laptop.activity_with_there();
        let r = a.running.first()?.clone();
        let u = r.usage?;
        let load = a.borrowed.first()?.clone();
        (r.phase == l::ExecPhase::Running as i32
            && u.cpu_millis_now.is_some()
            && u.memory_bytes.is_some()
            && load.cpu_millis.is_some())
        .then_some((r, load))
    })
    .await;
    assert_eq!(row.direction, l::Direction::There as i32);
    assert_eq!(row.peer_name, "Desktop");
    assert_eq!(row.grant_id, g.0.to_vec());
    assert_eq!(row.argv[..2], ["sh", "-c"]);
    assert!(
        !row.argv.iter().any(|a| a.contains(token)),
        "{:?}",
        row.argv
    );
    assert!(
        !row.can_stop,
        "stopping it from here is CancelJob's, not built yet"
    );
    let u = row.usage.unwrap();
    assert!(u.reported_by_peer, "the lender's claim");
    assert!(
        u.memory_bytes.unwrap() <= 2 << 30,
        "at most the grant's memory"
    );
    assert!(u.run_ms > 0);
    assert_eq!(load.peer_name, "Desktop");
    assert_eq!((load.tasks, load.running), (1, 1));
    assert_eq!(load.grant_limits.unwrap().cpu_millis, 2000);
    assert!(load.memory_bytes.is_some());
    // A client that does not ask (older ones read every row as running here) sees none of it,
    // and the lender lists the same task as running there for Laptop.
    assert!(laptop.activity().running.is_empty());
    assert!(laptop.activity().borrowed.is_empty());
    let here = desktop.activity();
    assert_eq!(here.running.len(), 1);
    assert_eq!(
        here.running[0].id, row.id,
        "the same task id on both devices"
    );
    assert!(desktop.activity_with_there().borrowed.is_empty());

    let (report, _) = handle.await.unwrap();
    assert_eq!(report.status, TaskStatus::Succeeded, "{report:?}");
    // Finished: no longer listed; the grant is still listed, with nothing running.
    let a = laptop.activity_with_there();
    assert!(a.running.is_empty(), "{:?}", a.running);
    let load = &a.borrowed[0];
    assert_eq!((load.tasks, load.running), (0, 0));
    assert_eq!((load.cpu_millis, load.memory_bytes), (Some(0), Some(0)));
}

#[tokio::test]
async fn a_cancelled_task_there_is_no_longer_listed() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();
    let cancel = tokio_util::sync::CancellationToken::new();
    let handle = {
        let (l, k, c) = (laptop.clone(), desktop.key(), cancel.clone());
        let s = spec(project.path(), &["sh", "-c", "sleep 30"]);
        tokio::spawn(async move {
            let (tx, _rx) = mpsc::channel::<LogChunk>(64);
            l.run_task_until(&k, g, s, tx, c).await
        })
    };
    eventually(|| {
        let r = laptop.activity_with_there().running.first()?.clone();
        (r.phase == l::ExecPhase::Running as i32).then_some(())
    })
    .await;
    cancel.cancel();
    let _ = handle.await.unwrap();
    assert!(laptop.activity_with_there().running.is_empty());
}

/// What `from` gets when it asks `to` about `grant` directly, as any paired device could.
async fn ask_load_raw(from: &Node, to: &PeerKey, grant: GrantId) -> pb::LoadReport {
    use gimmecores_node::wire;
    use gimmecores_proto::peer::v1::peer_message::Body;
    let conn = from.dial_raw(to).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    wire::send(
        &mut send,
        Body::LoadRequest(pb::LoadRequest {
            grant_id: grant.0.to_vec(),
        }),
    )
    .await
    .unwrap();
    send.finish().unwrap();
    match wire::recv(&mut recv).await.unwrap() {
        Body::LoadReport(r) => r,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_lenders_load_reaches_its_borrowers_only_when_its_owner_shares_it() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;

    // Off by default: asked while the borrower's listing is read, answered "not shared".
    assert!(!desktop.share_load());
    laptop.refresh_lender_loads().await;
    let seen = laptop.activity_with_there().borrowed[0]
        .lender
        .clone()
        .unwrap();
    assert!(!seen.shared, "{seen:?}");
    assert_eq!((seen.cpu_cores, seen.cpu_busy_millis), (0, None));

    // Turning it on needs presence, and is on record.
    let (strict, _h3) = common::fresh_node_with(
        "Strict",
        gimmecores_node::presence::Outcome::Denied("no".into()),
    )
    .await;
    assert!(strict.set_share_load(true).await.is_err());
    assert!(!strict.share_load());
    desktop.set_share_load(true).await.unwrap();
    let log = std::fs::read_to_string(desktop.paths().audit_log()).unwrap();
    assert!(
        log.contains("may now see how busy this computer is"),
        "{log}"
    );

    // Now the borrower sees the lender's whole computer.
    let mut seen = None;
    for _ in 0..40 {
        laptop.refresh_lender_loads().await;
        seen = laptop.activity_with_there().borrowed[0].lender.clone();
        if seen.as_ref().is_some_and(|l| l.shared) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let seen = seen.unwrap();
    assert!(seen.shared, "{seen:?}");
    assert!(seen.cpu_cores >= 1 && seen.memory_total_bytes > 0);
    assert!(seen.cpu_busy_millis.is_some() && seen.memory_used_bytes.is_some());

    // Only to the holder of a live grant: another paired device naming the same grant gets
    // nothing, and neither does the holder once the grant is revoked.
    let (phone, _h4) = node("Phone").await;
    pair(&phone, &desktop).await;
    assert!(!ask_load_raw(&phone, &desktop.key(), g).await.shared);
    assert!(ask_load_raw(&laptop, &desktop.key(), g).await.shared);
    desktop.revoke_grant(g).await.unwrap();
    assert!(!ask_load_raw(&laptop, &desktop.key(), g).await.shared);
    // Turned off: nothing for anyone, and turning it off needs no presence.
    desktop.set_share_load(false).await.unwrap();
    assert!(!desktop.share_load());
}

#[tokio::test]
async fn a_lender_that_does_not_answer_does_not_hold_up_listings() {
    use gimmecores_node::load_share::FIRST_ANSWER_WAIT;
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    granted(&laptop, &desktop).await;
    // The lender goes away (lid closed); the borrower still holds its grant.
    desktop.shutdown().await;
    let t = Instant::now();
    laptop.refresh_lender_loads().await;
    assert!(
        t.elapsed() < FIRST_ANSWER_WAIT + Duration::from_millis(500),
        "waited {:?} for a lender never heard from",
        t.elapsed()
    );
    // Once that question has ended (at most its 5 s limit), listings never wait on it again,
    // and it is not asked again at every listing.
    tokio::time::sleep(Duration::from_secs(6)).await;
    for _ in 0..5 {
        let t = Instant::now();
        laptop.refresh_lender_loads().await;
        assert!(
            t.elapsed() < Duration::from_millis(200),
            "{:?}",
            t.elapsed()
        );
    }
    assert!(laptop.activity_with_there().borrowed[0].lender.is_none());
}

/// The level a running task's row shows on `node`, once it runs.
async fn running_speed(node: &Node, there: bool) -> (Option<gimmecores_core::Speed>, bool) {
    let row = eventually(|| {
        let a = if there {
            node.activity_with_there()
        } else {
            node.activity()
        };
        let r = a.running.into_iter().next()?;
        let u = r.usage?;
        (r.phase == l::ExecPhase::Running as i32 && u.task_speed != 0).then_some(u)
    })
    .await;
    (
        gimmecores_node::grants_flow::speed_from(row.task_speed),
        row.task_speed_applied,
    )
}

#[tokio::test]
async fn tasks_run_at_the_owners_level_and_a_grant_can_name_another() {
    use gimmecores_core::Speed;
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    let g = granted(&laptop, &desktop).await;
    let project = tempfile::tempdir().unwrap();
    let start = |g, speed| {
        let (l, k) = (laptop.clone(), desktop.key());
        let mut s = spec(project.path(), &["sh", "-c", "sleep 3"]);
        s.speed = speed;
        tokio::spawn(async move { run(&l, &k, g, s).await })
    };

    // Out of the box: the owner's apps first, applied (the sandbox), and the borrower is told.
    assert_eq!(desktop.task_speed(), Speed::AppsFirst);
    let t = start(g, None);
    assert_eq!(
        running_speed(&desktop, false).await,
        (Some(Speed::AppsFirst), true)
    );
    assert_eq!(running_speed(&laptop, true).await.0, Some(Speed::AppsFirst));
    t.await.unwrap();

    // A grant that names no speed follows the setting at each task's start.
    desktop.set_task_speed(Speed::Background).await.unwrap();
    let t = start(g, None);
    assert_eq!(
        running_speed(&desktop, false).await.0,
        Some(Speed::Background)
    );
    t.await.unwrap();
    desktop.set_task_speed(Speed::AppsFirst).await.unwrap();

    // A grant may name full speed, fixed by the owner's approval (the prompt names it).
    let req = {
        let (b, k) = (laptop.clone(), desktop.key());
        tokio::spawn(async move {
            let mut terms = standard_terms(2, 2, 1, now());
            terms.speed = Some(Speed::Full);
            b.request_grant(&k, &terms, "fast builds").await
        })
    };
    let incoming = eventually(|| desktop.incoming_requests().into_iter().next()).await;
    assert_eq!(incoming.requested.speed, Some(Speed::Full));
    desktop
        .respond_to_request(incoming.id, Decision::Accept(None))
        .unwrap();
    let fast = match req.await.unwrap().unwrap() {
        GrantOutcome::Granted { id, .. } => id,
        other => panic!("{other:?}"),
    };
    let t = start(fast, None);
    assert_eq!(running_speed(&desktop, false).await.0, Some(Speed::Full));
    t.await.unwrap();
    // A task may ask for less than its grant, never more.
    let t = start(fast, Some(Speed::Background));
    assert_eq!(
        running_speed(&desktop, false).await.0,
        Some(Speed::Background)
    );
    t.await.unwrap();
    let t = start(g, Some(Speed::Full));
    assert_eq!(
        running_speed(&desktop, false).await.0,
        Some(Speed::AppsFirst),
        "asking for more than the grant has no effect"
    );
    t.await.unwrap();
}

#[tokio::test]
async fn a_faster_level_needs_the_owner_and_a_slower_one_never_does() {
    use gimmecores_core::Speed;
    let (strict, _h) = common::fresh_node_with(
        "Strict",
        gimmecores_node::presence::Outcome::Denied("no".into()),
    )
    .await;
    assert!(strict.set_task_speed(Speed::Full).await.is_err());
    assert_eq!(strict.task_speed(), Speed::AppsFirst);
    strict.set_task_speed(Speed::Background).await.unwrap();
    assert_eq!(strict.task_speed(), Speed::Background);
    assert!(strict.set_task_speed(Speed::AppsFirst).await.is_err());
    let log = std::fs::read_to_string(strict.paths().audit_log()).unwrap();
    assert!(log.contains("now run at background"), "{log}");
}
