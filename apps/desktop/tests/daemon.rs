//! The desktop app's daemon calls, against real daemons on loopback (presence simulated).
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::time::Duration;

use gimmecores_desktop::daemon;
use gimmecores_node::grants_flow::{GrantOutcome, standard_terms};
use gimmecores_node::node::{Node, NodeConfig};
use gimmecores_node::paths::Paths;
use gimmecores_node::presence::{FixedPresence, Outcome};

async fn start(name: &str) -> (Node, tempfile::TempDir) {
    // Short paths: Unix socket paths are length-limited.
    let home = tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap();
    let node = Node::start(NodeConfig {
        paths: Paths::at(home.path()),
        device_name: name.into(),
        bind: "127.0.0.1:0".parse().unwrap(),
        executors: gimmecores_node::exec::Executors::test_processes(),
        presence: std::sync::Arc::new(FixedPresence(Outcome::Verified)),
    })
    .await
    .unwrap();
    tokio::spawn(gimmecores_node::api::serve(node.clone()));
    for _ in 0..100 {
        if node.paths().control_socket().exists() && node.paths().client_socket().exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (node, home)
}

async fn until<T>(mut f: impl AsyncFnMut() -> Option<T>) -> T {
    for _ in 0..200 {
        if let Some(v) = f().await {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("condition not met in time");
}

/// Pairs two devices the way a user does in the app: ticket, compare code, confirm on both.
async fn pair_in_app(a: &Path, b: &Path) {
    let ticket = daemon::open_pairing(b).await.unwrap();
    assert!(ticket.ticket.starts_with("gmc1:"));
    daemon::start_pairing(a, &ticket.ticket).await.unwrap();
    for home in [a, b] {
        let s = until(async || {
            daemon::snapshot(home)
                .await
                .pairings
                .into_iter()
                .find(|p| p.state == "compare")
        })
        .await;
        assert_eq!(s.code.len(), 7, "code shown as \"123 456\": {s:?}");
        daemon::confirm_pairing(home, &s.session, true)
            .await
            .unwrap();
    }
    for home in [a, b] {
        until(async || {
            daemon::snapshot(home)
                .await
                .peers
                .iter()
                .any(|p| p.paired)
                .then_some(())
        })
        .await;
    }
}

#[tokio::test]
async fn a_stopped_daemon_is_a_state_not_an_error() {
    let empty = tempfile::tempdir().unwrap();
    let s = daemon::snapshot(empty.path()).await;
    assert!(!s.running);
    assert!(s.error.unwrap().contains("gmcd"));
    assert!(
        !empty.path().join("run").exists(),
        "the app never creates daemon state"
    );
}

#[tokio::test]
async fn lending_requests_grants_and_pairing_through_the_app() {
    let (laptop, h1) = start("Laptop").await;
    let (desktop, h2) = start("Desktop").await;
    let (lap, desk) = (h1.path(), h2.path());

    let s = daemon::snapshot(desk).await;
    assert!(s.running, "{:?}", s.error);
    let st = s.status.unwrap();
    assert_eq!(st.device_name, "Desktop");
    assert!(!st.lending, "off after install");
    assert!(st.presence_required);

    daemon::set_lending(desk, true, false, false, false)
        .await
        .unwrap();
    assert!(daemon::snapshot(desk).await.status.unwrap().lending);
    assert_eq!(
        st.lend_modes,
        ["container"],
        "containers only after install"
    );
    daemon::set_lend_modes(desk, &["container".into(), "sandbox".into()])
        .await
        .unwrap();
    let st = daemon::snapshot(desk).await.status.unwrap();
    assert_eq!(st.lend_modes, ["container", "sandbox"]);
    assert_eq!(
        st.available_modes,
        ["container", "sandbox"],
        "probed runners"
    );

    pair_in_app(lap, desk).await;
    let peers = daemon::snapshot(desk).await.peers;
    assert_eq!(peers[0].name, "Laptop");

    // The laptop asks; the desktop's window shows the request with who, what and why.
    let ask = {
        let (l, k) = (laptop.clone(), desktop.key());
        tokio::spawn(async move {
            l.request_grant(
                &k,
                &standard_terms(2, 4, 1, gimmecores_node::now()),
                "run the tests",
            )
            .await
        })
    };
    let req = until(async || daemon::snapshot(desk).await.requests.into_iter().next()).await;
    assert_eq!(req.peer_name, "Laptop");
    assert_eq!(req.cores, 2.0);
    assert_eq!(req.memory_gib, 4.0);
    assert_eq!(req.detail, "run the tests");
    assert_eq!(req.modes, ["container", "sandbox"], "what the lender lends");
    assert!(req.expires_at > 0);

    daemon::respond(desk, &req.id, true, false).await.unwrap();
    assert!(matches!(
        ask.await.unwrap().unwrap(),
        GrantOutcome::Granted { .. }
    ));
    let s = daemon::snapshot(desk).await;
    assert!(s.requests.is_empty());
    assert_eq!(s.lent.len(), 1);
    assert_eq!(s.lent[0].state, "active");
    let borrowed = daemon::snapshot(lap).await.borrowed;
    assert_eq!(borrowed.len(), 1);
    assert_eq!(borrowed[0].peer_name, "Desktop");

    daemon::revoke(desk, &s.lent[0].id).await.unwrap();
    assert!(daemon::snapshot(desk).await.lent.is_empty());

    daemon::stop_all(desk).await.unwrap();
    daemon::unpair(desk, &peers[0].fingerprint).await.unwrap();
    assert!(!daemon::snapshot(desk).await.peers.iter().any(|p| p.paired));
}

#[tokio::test]
async fn a_refused_presence_check_surfaces_as_a_readable_error() {
    let home = tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap();
    let node = Node::start(NodeConfig {
        paths: Paths::at(home.path()),
        device_name: "Mac".into(),
        bind: "127.0.0.1:0".parse().unwrap(),
        executors: gimmecores_node::exec::Executors::test_processes(),
        presence: std::sync::Arc::new(FixedPresence(Outcome::Denied("cancelled".into()))),
    })
    .await
    .unwrap();
    tokio::spawn(gimmecores_node::api::serve(node.clone()));
    until(async || node.paths().control_socket().exists().then_some(())).await;
    let e = daemon::set_lending(home.path(), true, false, false, false)
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("not approved"), "{e}");
    assert!(!e.contains("status:"), "no gRPC noise: {e}");
}

/// The window's activity view: a task from another device with what it asked for and what it
/// uses, stopped from the window, then listed as finished. With GMC_UI_FIXTURE set, also writes
/// the real snapshot and listings the window receives (for rendering the UI outside the app).
#[tokio::test]
async fn the_window_sees_and_stops_a_task_from_another_device() {
    let (laptop, h1) = start("Laptop").await;
    let (desktop, h2) = start("Desktop").await;
    let (lap, desk) = (h1.path(), h2.path());
    daemon::set_lending(desk, true, false, true, true)
        .await
        .unwrap();
    daemon::set_lend_modes(desk, &["sandbox".into()])
        .await
        .unwrap();
    pair_in_app(lap, desk).await;
    let ask = {
        let (l, k) = (laptop.clone(), desktop.key());
        tokio::spawn(async move {
            l.request_grant(
                &k,
                &standard_terms(4, 8, 2, gimmecores_node::now()),
                "builds",
            )
            .await
        })
    };
    let req = until(async || daemon::snapshot(desk).await.requests.into_iter().next()).await;
    daemon::respond(desk, &req.id, true, false).await.unwrap();
    let GrantOutcome::Granted { id: grant, .. } = ask.await.unwrap().unwrap() else {
        panic!("not granted")
    };

    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("big.bin"), vec![1u8; 2 << 20]).unwrap();
    let busy = "end=$(( $(date +%s) + 5 )); while [ $(date +%s) -lt $end ]; do i=0; while [ $i -lt 20000 ]; do i=$((i+1)); done; done";
    let mut done_spec = gimmecores_node::tasks_flow::TaskSpec {
        send_image: true,
        dir: project.path().to_path_buf(),
        argv: vec!["sh".into(), "-c".into(), "echo quick".into()],
        image: None,
        mode: None,
        outputs: vec![],
        excludes: vec![],
        allow_secrets: vec![],
        extra_files: vec![],
        attachments: vec![],
        output_dir: None,
        env: vec![("HF_TOKEN".into(), "x".into()), ("CI".into(), "1".into())],
        cpu_millis: 2000,
        memory_bytes: 1 << 30,
        timeout: Duration::from_secs(120),
        speed: None,
    };
    let run = |spec: gimmecores_node::tasks_flow::TaskSpec| {
        let (l, k) = (laptop.clone(), desktop.key());
        tokio::spawn(async move {
            let (tx, mut rx) = tokio::sync::mpsc::channel(64);
            tokio::spawn(async move { while rx.recv().await.is_some() {} });
            l.run_task(&k, grant, spec, tx).await
        })
    };
    // One that finishes, so the finished list has something.
    run(done_spec.clone()).await.unwrap().unwrap();
    done_spec.argv = vec![
        "sh".into(),
        "-c".into(),
        busy.into(),
        "--".into(),
        "--api-key".into(),
        "s3cr3tvalue".into(),
    ];
    let busy_task = run(done_spec);

    let row = until(async || {
        let a = daemon::activity(desk).await.ok()?;
        let r = a.running.into_iter().next()?;
        (r.cpu_time_ms.unwrap_or(0) >= 300 && r.cpu_now_cores.is_some() && r.disk.is_some())
            .then_some(r)
    })
    .await;
    assert_eq!(row.peer_name, "Laptop");
    assert_eq!(row.phase, "running");
    assert_eq!(row.mode, "sandbox");
    assert_eq!(row.argv[..2], ["sh", "-c"]);
    assert_eq!(
        row.argv[2],
        format!("{}…", busy.chars().take(64).collect::<String>())
    );
    assert!(row.argv_cut);
    assert_eq!(row.argv[5], "[hidden: looks like a secret]");
    assert_eq!(row.env_names, ["CI", "HF_TOKEN"]);
    assert_eq!(row.asked_cores, 2.0);
    assert_eq!(row.asked_memory, 1 << 30);
    assert_eq!(row.grant_cores, 4.0);
    assert_eq!(row.measured_by, "process_tree");
    assert!(row.memory_now.unwrap() > 0 && row.disk.unwrap() >= 2 << 20);
    assert!(row.can_stop);
    // Its level: the lender's default, applied by the sandbox; the setting can be changed.
    assert_eq!(row.task_speed, "apps-first");
    assert!(row.task_speed_applied);
    assert_eq!(
        daemon::snapshot(desk).await.status.unwrap().task_speed,
        "apps-first"
    );
    // This computer as a whole, with the sandboxed task's share measured (both daemons run on
    // this one machine, so its use is part of the total).
    let m = until(async || {
        let m = daemon::activity(desk).await.ok()?.machine?;
        m.cpu_lent_cores.is_some_and(|c| c > 0.0).then_some(m)
    })
    .await;
    assert!(m.cores >= 1 && m.memory_total > 0);
    assert!(m.cpu_busy_cores.is_some_and(|c| c <= f64::from(m.cores)));
    assert!(m.memory_used.is_some_and(|u| u <= m.memory_total));
    assert!(m.memory_lent.is_some_and(|l| l > 0 && l <= m.memory_total));
    // The borrower's side: its task there, with the lender's figures, apart from what runs on
    // the borrower itself; the lender lists none of the borrower's view.
    let lap_view = until(async || {
        let a = daemon::activity(lap).await.ok()?;
        let b = a.borrowed.first()?;
        (b.running == 1 && b.cpu_cores.is_some() && b.memory.is_some()).then_some(a)
    })
    .await;
    assert!(
        lap_view.running.is_empty(),
        "nothing runs on the borrower itself"
    );
    assert_eq!(lap_view.there.len(), 1);
    assert_eq!(
        lap_view.there[0].id, row.id,
        "the same task on both devices"
    );
    assert!(lap_view.there[0].reported_by_peer);
    assert_eq!(lap_view.borrowed[0].peer_name, "Desktop");
    assert_eq!(lap_view.borrowed[0].grant_cores, 4.0);
    let desk_view = daemon::activity(desk).await.unwrap();
    assert!(desk_view.there.is_empty() && desk_view.borrowed.is_empty());
    assert_eq!(desk_view.running.len(), 1);
    // The lender's whole computer: not shared until its owner says so, then seen.
    assert!(
        !lap_view.borrowed[0]
            .lender
            .as_ref()
            .is_some_and(|l| l.shared)
    );
    daemon::set_share_load(desk, true).await.unwrap();
    assert!(daemon::snapshot(desk).await.status.unwrap().share_load);
    let lap_view = until(async || {
        let a = daemon::activity(lap).await.ok()?;
        let l = a.borrowed.first()?.lender.as_ref()?;
        (l.shared && l.cpu_busy_cores.is_some()).then_some(a)
    })
    .await;
    let whole = lap_view.borrowed[0].lender.as_ref().unwrap();
    assert!(whole.cores >= 1 && whole.memory_total > 0);
    if let Some(path) = std::env::var_os("GMC_UI_FIXTURE") {
        let state = serde_json::json!({"start_at_login": true, "bundled": true, "cli_installed": true,
                                       "homebrew_service": false, "reduced": false});
        let fixture = serde_json::json!({
            "snapshot": daemon::snapshot(desk).await,
            "service_state": state,
            "activity": daemon::activity(desk).await.unwrap(),
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
        let borrower = serde_json::json!({
            "snapshot": daemon::snapshot(lap).await,
            "service_state": state,
            "activity": lap_view,
        });
        let mut p = std::path::PathBuf::from(&path);
        p.set_extension("borrower.json");
        std::fs::write(p, serde_json::to_vec_pretty(&borrower).unwrap()).unwrap();
    }

    daemon::set_task_speed(desk, "background").await.unwrap();
    assert_eq!(
        daemon::snapshot(desk).await.status.unwrap().task_speed,
        "background"
    );
    assert!(daemon::set_task_speed(desk, "turbo").await.is_err());
    daemon::stop_task(desk, &row.id).await.unwrap();
    let report = busy_task.await.unwrap().unwrap();
    assert_eq!(
        report.status,
        gimmecores_node::tasks_flow::TaskStatus::Cancelled
    );
    let a = until(async || {
        let a = daemon::activity(desk).await.ok()?;
        (a.running.is_empty() && a.recent.len() == 2).then_some(a)
    })
    .await;
    let stopped = a.recent.iter().find(|g| g.stopped == 1).unwrap();
    let ending = stopped.last.ending.as_ref().unwrap();
    assert_eq!(ending.words, "Stopped by you");
    assert!(stopped.cpu_time_total_ms.unwrap() >= 300);
    let quick = a.recent.iter().find(|g| g.succeeded == 1).unwrap();
    assert_eq!(quick.last.ending.as_ref().unwrap().words, "Finished");
    assert!(
        daemon::stop_task(desk, &row.id).await.is_err(),
        "already gone"
    );
    assert!(daemon::stop_task(desk, "nothex").await.is_err());
}
