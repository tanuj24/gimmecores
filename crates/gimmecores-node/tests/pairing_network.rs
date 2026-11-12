#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

use std::time::Duration;

use gimmecores_node::node::{Node, NodeConfig, PairStatus, PairingView};
use gimmecores_node::paths::Paths;

async fn node(name: &str) -> (Node, tempfile::TempDir) {
    let home = tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap();
    let node = Node::start(NodeConfig {
        paths: Paths::at(home.path()),
        device_name: name.to_string(),
        bind: "127.0.0.1:0".parse().unwrap(),
    })
    .await
    .unwrap();
    (node, home)
}

async fn wait_for(node: &Node, pred: impl Fn(&PairingView) -> bool) -> PairingView {
    for _ in 0..200 {
        if let Some(v) = node.pairings().into_iter().find(|v| pred(v)) {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out; sessions: {:?}", node.pairings());
}

#[tokio::test]
async fn pairing_end_to_end_both_confirm() {
    let (a, _ha) = node("Maya's MacBook").await;
    let (b, _hb) = node("Desktop").await;
    b.open_pairing();

    let id_a = a.start_pairing(b.addr()).await.unwrap();
    let view_b = wait_for(&b, |v| v.code.is_some()).await;
    let view_a = wait_for(&a, |v| v.id == id_a && v.code.is_some()).await;
    assert_eq!(
        view_a.code, view_b.code,
        "both screens must show the same code"
    );
    assert_eq!(view_a.peer_name, "Desktop");
    assert_eq!(view_b.peer_name, "Maya's MacBook");
    assert!(
        !a.is_paired(&b.key()),
        "nothing is trusted before both confirm"
    );

    a.confirm_pairing(id_a, true).unwrap();
    b.confirm_pairing(view_b.id, true).unwrap();
    wait_for(&a, |v| v.status == PairStatus::Paired).await;
    wait_for(&b, |v| v.status == PairStatus::Paired).await;
    assert!(a.is_paired(&b.key()));
    assert!(b.is_paired(&a.key()));
}

#[tokio::test]
async fn one_rejection_means_nobody_is_paired() {
    let (a, _ha) = node("A").await;
    let (b, _hb) = node("B").await;
    b.open_pairing();
    let id_a = a.start_pairing(b.addr()).await.unwrap();
    let view_b = wait_for(&b, |v| v.code.is_some()).await;
    a.confirm_pairing(id_a, true).unwrap();
    b.confirm_pairing(view_b.id, false).unwrap();
    wait_for(&a, |v| matches!(v.status, PairStatus::Failed(_))).await;
    wait_for(&b, |v| matches!(v.status, PairStatus::Failed(_))).await;
    assert!(!a.is_paired(&b.key()));
    assert!(!b.is_paired(&a.key()));
}

#[tokio::test]
async fn i2_pairing_is_refused_while_pairing_mode_is_closed() {
    let (a, _ha) = node("A").await;
    let (b, _hb) = node("B").await;
    // B never opened pairing mode.
    assert!(a.start_pairing(b.addr()).await.is_err());
    assert!(b.pairings().is_empty(), "no session may be created");
    assert!(!b.is_paired(&a.key()));
}
