//! One daemon per state directory: a second one refuses to start instead of racing the
//! first on its files and sockets.
#![allow(clippy::unwrap_used)]

use gimmecores_node::exec::Executors;
use gimmecores_node::node::{Node, NodeConfig};
use gimmecores_node::paths::Paths;
use gimmecores_node::presence::{FixedPresence, Outcome};

async fn start(home: &std::path::Path) -> anyhow::Result<Node> {
    Node::start(NodeConfig {
        paths: Paths::at(home),
        device_name: "Laptop".into(),
        bind: "127.0.0.1:0".parse().unwrap(),
        executors: Executors::test_processes(),
        presence: std::sync::Arc::new(FixedPresence(Outcome::Verified)),
    })
    .await
}

#[tokio::test]
async fn a_second_daemon_on_the_same_state_refuses_to_start() {
    let home = tempfile::tempdir().unwrap();
    let first = start(home.path()).await.unwrap();
    let second = start(home.path()).await;
    let err = second.err().expect("second daemon started");
    assert!(err.is::<gimmecores_node::node::AlreadyRunning>(), "{err:#}");

    // A separate state directory is fine alongside it.
    let other = tempfile::tempdir().unwrap();
    let separate = start(other.path()).await.unwrap();
    separate.shutdown().await;

    // Once the first stops, the state directory is free again.
    first.shutdown().await;
    drop(first);
    let again = start(home.path()).await.unwrap();
    again.shutdown().await;
}
