//! Grant requests that wait for the lender's owner without holding up the borrower (#23).
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

mod common;

use std::time::{Duration, Instant};

use common::{eventually, node, pair};
use gimmecores_core::GrantState;
use gimmecores_node::grants_flow::{Decision, GrantOutcome, standard_terms};
use gimmecores_node::node::{Node, NodeConfig};
use gimmecores_node::now;
use gimmecores_node::paths::Paths;
use gimmecores_node::presence::{FixedPresence, Outcome};

async fn queue(b: &Node, l: &Node) -> Vec<u8> {
    let t = Instant::now();
    let GrantOutcome::Queued { request_id, .. } = b
        .request_grant_queued(&l.key(), &standard_terms(1, 1, 1, now()), "later")
        .await
        .unwrap()
    else {
        panic!("not queued")
    };
    assert!(t.elapsed() < Duration::from_secs(5), "it did not wait");
    request_id
}

#[tokio::test]
async fn the_answer_comes_back_when_the_owner_gets_to_it() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    queue(&laptop, &desktop).await;
    assert_eq!(laptop.waiting_requests().len(), 1);
    // Later, the owner accepts it; the laptop holds the grant without asking again.
    let req = eventually(|| desktop.incoming_requests().into_iter().next()).await;
    desktop
        .respond_to_request(req.id, Decision::Accept(None))
        .unwrap();
    eventually(|| (laptop.borrowed_grants().len() == 1).then_some(())).await;
    eventually(|| laptop.waiting_requests().is_empty().then_some(())).await;
    assert_eq!(desktop.grant_state(req.id), Some(GrantState::Active));
}

#[tokio::test]
async fn a_declined_or_unanswered_request_is_forgotten() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    queue(&laptop, &desktop).await;
    let req = eventually(|| desktop.incoming_requests().into_iter().next()).await;
    desktop
        .respond_to_request(req.id, Decision::Decline("not today".into()))
        .unwrap();
    eventually(|| laptop.waiting_requests().is_empty().then_some(())).await;
    assert!(laptop.borrowed_grants().is_empty());
    let log = std::fs::read_to_string(laptop.paths().audit_log()).unwrap();
    assert!(log.contains("declined the request: not today"), "{log}");

    // Nobody answers (tests shorten the wait): it lapses, and the laptop is told.
    desktop.set_decision_timeout(Duration::from_millis(400));
    queue(&laptop, &desktop).await;
    eventually(|| laptop.waiting_requests().is_empty().then_some(())).await;
    let log = std::fs::read_to_string(laptop.paths().audit_log()).unwrap();
    assert!(log.contains("did not answer the request"), "{log}");
}

#[tokio::test]
async fn a_borrower_that_was_away_asks_for_its_answer() {
    let home = tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap();
    let port = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let start = || async {
        Node::start(NodeConfig {
            paths: Paths::at(home.path()),
            device_name: "Laptop".into(),
            bind: format!("127.0.0.1:{port}").parse().unwrap(),
            executors: gimmecores_node::exec::Executors::test_processes(),
            presence: std::sync::Arc::new(FixedPresence(Outcome::Verified)),
        })
        .await
        .unwrap()
    };
    let laptop = start().await;
    let (desktop, _h) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    let request_id = queue(&laptop, &desktop).await;
    // The laptop goes away; its owner accepts meanwhile (the answer cannot be delivered).
    laptop.shutdown().await;
    drop(laptop);
    let req = eventually(|| desktop.incoming_requests().into_iter().next()).await;
    desktop
        .respond_to_request(req.id, Decision::Accept(None))
        .unwrap();
    eventually(|| (desktop.grant_state(req.id) == Some(GrantState::Active)).then_some(())).await;

    // Back, it still knows what it asked for, asks, and gets the grant.
    let laptop = start().await;
    let waiting = laptop.waiting_requests();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].request.request_id, request_id);
    assert_eq!(laptop.poll_waiting().await, 1);
    assert_eq!(laptop.borrowed_grants().len(), 1);
    assert!(laptop.waiting_requests().is_empty());
}

#[tokio::test]
async fn a_standing_grant_answers_at_once() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    desktop
        .set_standing_rule(&laptop.key(), &standard_terms(2, 2, 2, now()), 8)
        .await
        .unwrap();
    let out = laptop
        .request_grant_queued(&desktop.key(), &standard_terms(1, 1, 1, now()), "")
        .await
        .unwrap();
    assert!(matches!(out, GrantOutcome::Granted { .. }), "{out:?}");
    assert!(laptop.waiting_requests().is_empty());
}

#[tokio::test]
async fn one_device_cannot_fill_the_lenders_list() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    for _ in 0..gimmecores_node::grants_flow::MAX_QUEUED_PER_DEVICE {
        queue(&laptop, &desktop).await;
    }
    let out = laptop
        .request_grant_queued(&desktop.key(), &standard_terms(1, 1, 1, now()), "")
        .await
        .unwrap();
    assert!(
        matches!(&out, GrantOutcome::Declined(why) if why.contains("too many")),
        "{out:?}"
    );
}
