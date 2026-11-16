#![allow(clippy::unwrap_used, dead_code)]

use std::time::Duration;

use gimmecores_node::node::{Node, NodeConfig, PairStatus, PairingView};
use gimmecores_node::paths::Paths;
use gimmecores_node::presence::{FixedPresence, Outcome};

/// A node with lending turned on (as if its user enabled it). The machine running the tests
/// never pauses it: on a laptop on battery, or a hot one, lending would stop at the first
/// power reading, a minute in. Tests of pausing call `apply_protection` themselves.
pub async fn node(name: &str) -> (Node, tempfile::TempDir) {
    let (n, h) = fresh_node(name).await;
    n.set_lending(true).unwrap();
    n.set_protections(gimmecores_node::power::Protections {
        pause_on_battery: false,
        idle_only: false,
        pause_when_hot: false,
    })
    .unwrap();
    n.set_lend_modes(
        gimmecores_core::Modes::CONTAINER.with(gimmecores_core::ExecutionMode::Sandbox),
    )
    .unwrap();
    (n, h)
}

/// A node exactly as after install: lending off. Its owner approves every presence check.
pub async fn fresh_node(name: &str) -> (Node, tempfile::TempDir) {
    fresh_node_with(name, Outcome::Verified).await
}

/// A fresh node whose presence checks (I13) always answer `presence`.
pub async fn fresh_node_with(name: &str, presence: Outcome) -> (Node, tempfile::TempDir) {
    let home = tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap();
    let node = Node::start(NodeConfig {
        paths: Paths::at(home.path()),
        device_name: name.to_string(),
        bind: "127.0.0.1:0".parse().unwrap(),
        executors: gimmecores_node::exec::Executors::test_processes(),
        presence: std::sync::Arc::new(FixedPresence(presence)),
    })
    .await
    .unwrap();
    (node, home)
}

pub async fn wait_for(node: &Node, pred: impl Fn(&PairingView) -> bool) -> PairingView {
    for _ in 0..200 {
        if let Some(v) = node.pairings().into_iter().find(|v| pred(v)) {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out; sessions: {:?}", node.pairings());
}

/// Pairs `a` (initiator) with `b`, both users confirming.
pub async fn pair(a: &Node, b: &Node) {
    b.open_pairing();
    let id_a = a.start_pairing(b.addr()).await.unwrap();
    let view_b = wait_for(b, |v| v.code.is_some() && v.peer == a.key()).await;
    a.confirm_pairing(id_a, true).unwrap();
    b.confirm_pairing(view_b.id, true).unwrap();
    wait_for(a, |v| v.id == id_a && v.status == PairStatus::Paired).await;
    wait_for(b, |v| v.id == view_b.id && v.status == PairStatus::Paired).await;
}

/// Polls until `f` returns `Some`.
pub async fn eventually<T>(mut f: impl FnMut() -> Option<T>) -> T {
    for _ in 0..200 {
        if let Some(v) = f() {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("condition not met in time");
}
