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

    daemon::set_lending(desk, true, false, false, false).await.unwrap();
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

    daemon::respond(desk, &req.id, true).await.unwrap();
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
