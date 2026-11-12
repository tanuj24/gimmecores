//! Local discovery over loopback (tests never announce anything on a real network). Skipped
//! where multicast on loopback does not work, unless `GMC_REQUIRE_MDNS=1`.
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

mod common;

use std::path::Path;
use std::time::Duration;

use common::wait_for;
use gimmecores_node::exec::Executors;
use gimmecores_node::node::{Node, NodeConfig, PairStatus};
use gimmecores_node::paths::Paths;
use gimmecores_node::presence::{FixedPresence, Outcome};

fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start(home: &Path, name: &str, port: u16) -> Node {
    Node::start(NodeConfig {
        paths: Paths::at(home),
        device_name: name.into(),
        bind: format!("127.0.0.1:{port}").parse().unwrap(),
        executors: Executors::test_processes(),
        presence: std::sync::Arc::new(FixedPresence(Outcome::Verified)),
    })
    .await
    .unwrap()
}

async fn within<T>(secs: u64, mut f: impl AsyncFnMut() -> Option<T>) -> Option<T> {
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < end {
        if let Some(v) = f().await {
            return Some(v);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    None
}

#[tokio::test]
async fn pair_without_a_ticket_then_find_a_moved_device_by_its_rotating_id() {
    let (ha, hb) = (
        tempfile::Builder::new()
            .prefix("gmc")
            .tempdir_in("/tmp")
            .unwrap(),
        tempfile::Builder::new()
            .prefix("gmc")
            .tempdir_in("/tmp")
            .unwrap(),
    );
    let a = start(ha.path(), "Laptop", free_port()).await;
    let b = start(hb.path(), "Studio", free_port()).await;

    // B opens pairing mode: A sees it nearby, with its name, without any ticket.
    b.open_pairing();
    let found = within(20, async || {
        a.nearby().into_iter().find(|n| n.key == b.key())
    })
    .await;
    let Some(found) = found else {
        assert!(
            std::env::var("GMC_REQUIRE_MDNS").as_deref() != Ok("1"),
            "multicast discovery did not work"
        );
        eprintln!("skipping: multicast on loopback does not work here");
        return;
    };
    assert_eq!(found.name, "Studio");

    let id_a = a
        .start_pairing_nearby(&b.key().fingerprint())
        .await
        .unwrap();
    let view_b = wait_for(&b, |v| v.code.is_some() && v.peer == a.key()).await;
    a.confirm_pairing(id_a, true).unwrap();
    b.confirm_pairing(view_b.id, true).unwrap();
    wait_for(&a, |v| v.id == id_a && v.status == PairStatus::Paired).await;
    wait_for(&b, |v| v.id == view_b.id && v.status == PairStatus::Paired).await;
    // (Other tests' devices may be nearby on loopback too.)
    assert!(
        !a.nearby().iter().any(|n| n.key == b.key()),
        "paired devices are not listed as nearby"
    );

    // B comes back on another port (like a new IP). A finds it again only through B's
    // rotating identifier, then reaches it.
    b.shutdown().await;
    drop(b);
    let b = start(hb.path(), "Studio", free_port()).await;
    let reached = within(40, async || a.link_test(&b.key()).await.ok()).await;
    assert!(reached.is_some(), "A did not find B at its new address");
}

#[tokio::test]
async fn with_discovery_off_nothing_is_heard() {
    let (ha, hb) = (
        tempfile::Builder::new()
            .prefix("gmc")
            .tempdir_in("/tmp")
            .unwrap(),
        tempfile::Builder::new()
            .prefix("gmc")
            .tempdir_in("/tmp")
            .unwrap(),
    );
    let a = start(ha.path(), "Laptop", free_port()).await;
    a.set_discovery_mode(gimmecores_node::discovery::DiscoveryMode::Off)
        .unwrap();
    let b = start(hb.path(), "Studio", free_port()).await;
    b.open_pairing();
    let heard = within(8, async || a.nearby().into_iter().next()).await;
    assert!(heard.is_none(), "a device with discovery off listened");
}
