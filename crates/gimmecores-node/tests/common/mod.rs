#![allow(clippy::unwrap_used, dead_code)]

use std::time::Duration;

use gimmecores_node::node::{Node, NodeConfig, PairStatus, PairingView};
use gimmecores_node::paths::Paths;

pub async fn node(name: &str) -> (Node, tempfile::TempDir) {
    let home = tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap();
    let node = Node::start(NodeConfig {
        paths: Paths::at(home.path()),
        device_name: name.to_string(),
        bind: "127.0.0.1:0".parse().unwrap(),
        executor: std::sync::Arc::new(gimmecores_node::exec::ProcessExecutor),
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
