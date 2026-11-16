//! Standing grants (#22): requests within limits the owner set once are accepted without
//! asking; anything else still asks; ending one revokes what it accepted; it lapses; a rule
//! edited on disk is not trusted.
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

mod common;

use std::time::Duration;

use common::{eventually, node, pair};
use gimmecores_core::{GrantState, Modes};
use gimmecores_node::grants_flow::{Decision, GrantOutcome, standard_terms, verify_signed};
use gimmecores_node::node::{Node, NodeConfig};
use gimmecores_node::now;
use gimmecores_node::paths::Paths;
use gimmecores_node::presence::{FixedPresence, Outcome};

/// The owner allows "Laptop" up to 4 cores and 8 GiB, sandbox or container, grants up to 8 h.
async fn with_rule() -> (Node, Node, tempfile::TempDir, tempfile::TempDir) {
    let (laptop, h1) = node("Laptop").await;
    let (desktop, h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    desktop
        .set_standing_rule(&laptop.key(), &standard_terms(4, 8, 8, now()), 8)
        .await
        .unwrap();
    (laptop, desktop, h1, h2)
}

async fn ask(b: &Node, l: &Node, cores: u32, gib: u64, hours: u64) -> GrantOutcome {
    b.request_grant(&l.key(), &standard_terms(cores, gib, hours, now()), "t")
        .await
        .unwrap()
}

#[tokio::test]
async fn requests_within_the_limits_are_accepted_without_asking() {
    let (laptop, desktop, _h1, _h2) = with_rule().await;
    let GrantOutcome::Granted { id, terms } = ask(&laptop, &desktop, 2, 4, 2).await else {
        panic!("not accepted by the standing grant")
    };
    assert_eq!(terms.limits.cpu_millis, 2000, "as asked, not widened");
    assert!(desktop.incoming_requests().is_empty(), "nobody was asked");
    assert_eq!(desktop.grant_state(id), Some(GrantState::Active));
    // Both sides can tell it was the standing grant, from the signed grant itself.
    assert!(desktop.issued_by_rule(id));
    let (_, held) = laptop.borrowed_grants().into_iter().next().unwrap();
    assert!(
        verify_signed(&held.signed, &desktop.key(), &laptop.key())
            .unwrap()
            .by_standing_rule
    );
    let log = std::fs::read_to_string(desktop.paths().audit_log()).unwrap();
    assert!(log.contains("accepted by standing grant"), "{log}");
}

#[tokio::test]
async fn anything_beyond_the_limits_still_asks_the_owner() {
    let (laptop, desktop, _h1, _h2) = with_rule().await;
    desktop.set_decision_timeout(Duration::from_millis(400));
    for (cores, gib, hours) in [(5, 4, 2), (2, 9, 2), (2, 4, 9)] {
        let req = {
            let (b, l) = (laptop.clone(), desktop.clone());
            tokio::spawn(async move { ask(&b, &l, cores, gib, hours).await })
        };
        // It waits for the owner, who is not there.
        eventually(|| desktop.incoming_requests().into_iter().next()).await;
        assert!(matches!(req.await.unwrap(), GrantOutcome::NoAnswer));
    }
    // A device without a standing grant is asked about as before.
    let (other, _h3) = node("Other").await;
    pair(&other, &desktop).await;
    let req = {
        let (b, l) = (other.clone(), desktop.clone());
        tokio::spawn(async move { ask(&b, &l, 1, 1, 1).await })
    };
    eventually(|| desktop.incoming_requests().into_iter().next()).await;
    assert!(matches!(req.await.unwrap(), GrantOutcome::NoAnswer));
}

#[tokio::test]
async fn it_grants_only_the_ways_it_allows() {
    let (laptop, desktop, _h1, _h2) = with_rule().await;
    let mut terms = standard_terms(1, 1, 1, now());
    terms.modes = Modes::NONE.with(gimmecores_core::ExecutionMode::Sandbox);
    desktop
        .set_standing_rule(&laptop.key(), &terms, 8)
        .await
        .unwrap();
    // The laptop asks for "container or sandbox"; it gets the sandbox only.
    let GrantOutcome::Granted { terms, .. } = ask(&laptop, &desktop, 1, 1, 1).await else {
        panic!("not accepted")
    };
    assert_eq!(
        terms.modes,
        Modes::NONE.with(gimmecores_core::ExecutionMode::Sandbox)
    );
}

#[tokio::test]
async fn ending_it_revokes_what_it_accepted_and_nothing_else() {
    let (laptop, desktop, _h1, _h2) = with_rule().await;
    let GrantOutcome::Granted { id: auto, .. } = ask(&laptop, &desktop, 1, 1, 1).await else {
        panic!("not accepted")
    };
    // One the owner accepted by hand, beyond the rule.
    let manual = {
        let (b, l) = (laptop.clone(), desktop.clone());
        tokio::spawn(async move { ask(&b, &l, 6, 1, 1).await })
    };
    let req = eventually(|| desktop.incoming_requests().into_iter().next()).await;
    desktop
        .respond_to_request(req.id, Decision::Accept(None))
        .unwrap();
    let GrantOutcome::Granted { id: by_hand, .. } = manual.await.unwrap() else {
        panic!("not accepted by hand")
    };
    assert!(!desktop.issued_by_rule(by_hand));

    assert_eq!(
        desktop.remove_standing_rule(&laptop.key()).await.unwrap(),
        1
    );
    assert!(desktop.standing_rule(&laptop.key()).is_none());
    assert_eq!(desktop.grant_state(auto), Some(GrantState::Revoked));
    assert_eq!(desktop.grant_state(by_hand), Some(GrantState::Active));
    // And the next request asks again.
    desktop.set_decision_timeout(Duration::from_millis(300));
    assert!(matches!(
        ask(&laptop, &desktop, 1, 1, 1).await,
        GrantOutcome::NoAnswer
    ));
}

#[tokio::test]
async fn it_lapses_and_unpairing_deletes_it() {
    let (laptop, desktop, _h1, _h2) = with_rule().await;
    desktop
        .set_standing_until(&laptop.key(), now() - 1)
        .unwrap();
    assert!(desktop.standing_rule(&laptop.key()).is_none(), "lapsed");
    desktop.set_decision_timeout(Duration::from_millis(300));
    assert!(matches!(
        ask(&laptop, &desktop, 1, 1, 1).await,
        GrantOutcome::NoAnswer
    ));
    // The service removes it and says so.
    eventually(|| {
        std::fs::read_to_string(desktop.paths().audit_log())
            .unwrap()
            .contains("lapsed")
            .then_some(())
    })
    .await;

    let (laptop2, desktop2, _h3, _h4) = with_rule().await;
    desktop2.forget_peer(&laptop2.key()).unwrap();
    assert!(desktop2.standing_rule(&laptop2.key()).is_none());
}

#[tokio::test]
async fn only_the_owner_present_creates_one_and_ending_one_needs_nobody() {
    let (strict, _h1) = common::fresh_node_with("Strict", Outcome::Denied("no".into())).await;
    let (other, _h2) = node("Other").await;
    let e = strict
        .set_standing_rule(&other.key(), &standard_terms(1, 1, 1, now()), 8)
        .await
        .unwrap_err();
    assert!(
        e.downcast_ref::<gimmecores_node::node::PresenceRefused>()
            .is_some(),
        "{e:#}"
    );
    assert!(strict.standing_rule(&other.key()).is_none());
    // Trusted grants never get one, whoever asks.
    let (laptop, desktop, _h3, _h4) = with_rule().await;
    let mut t = standard_terms(1, 1, 1, now());
    t.trust = gimmecores_core::TrustLevel::Trusted;
    assert!(
        desktop
            .set_standing_rule(&laptop.key(), &t, 8)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_rule_edited_on_disk_is_not_trusted() {
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
            device_name: "Desktop".into(),
            bind: format!("127.0.0.1:{port}").parse().unwrap(),
            executors: gimmecores_node::exec::Executors::test_processes(),
            presence: std::sync::Arc::new(FixedPresence(Outcome::Verified)),
        })
        .await
        .unwrap()
    };
    let desktop = start().await;
    let (laptop, _h) = node("Laptop").await;
    pair(&laptop, &desktop).await;
    desktop
        .set_standing_rule(&laptop.key(), &standard_terms(2, 2, 2, now()), 8)
        .await
        .unwrap();
    assert!(desktop.standing_rule(&laptop.key()).is_some());
    desktop.shutdown().await;
    drop(desktop);

    // Someone widens it in the file: 2 cores become 64.
    let file = Paths::at(home.path()).peers_file();
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains("\"cpu_millis\": 2000"), "{text}");
    gimmecores_node::fsutil::write_private(
        &file,
        text.replace("\"cpu_millis\": 2000", "\"cpu_millis\": 64000")
            .as_bytes(),
    )
    .unwrap();

    let desktop = start().await;
    assert!(desktop.standing_rule(&laptop.key()).is_none());
    eventually(|| {
        std::fs::read_to_string(desktop.paths().audit_log())
            .unwrap()
            .contains("signature does not verify")
            .then_some(())
    })
    .await;
}

#[tokio::test]
async fn grants_cannot_be_stacked_past_the_limits() {
    // 4 cores, 8 GiB memory, 10 GiB disk in all; each request below asks for 10 GiB of disk.
    let (laptop, desktop, _h1, _h2) = with_rule().await;
    desktop.set_decision_timeout(Duration::from_millis(400));
    // Two requests at the same moment: one is accepted, the other waits for the owner.
    let (a, b) = tokio::join!(
        ask(&laptop, &desktop, 1, 1, 1),
        ask(&laptop, &desktop, 1, 1, 1)
    );
    let granted = [&a, &b]
        .iter()
        .filter(|o| matches!(o, GrantOutcome::Granted { .. }))
        .count();
    assert_eq!(granted, 1, "{a:?} / {b:?}");
    // While that one lives, another goes to the owner too.
    assert!(matches!(
        ask(&laptop, &desktop, 1, 1, 1).await,
        GrantOutcome::NoAnswer
    ));
}

#[tokio::test]
async fn after_a_restart_ending_it_still_revokes_what_it_accepted() {
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
        let n = Node::start(NodeConfig {
            paths: Paths::at(home.path()),
            device_name: "Desktop".into(),
            bind: format!("127.0.0.1:{port}").parse().unwrap(),
            executors: gimmecores_node::exec::Executors::test_processes(),
            presence: std::sync::Arc::new(FixedPresence(Outcome::Verified)),
        })
        .await
        .unwrap();
        n.set_lending(true).unwrap();
        n.set_protections(gimmecores_node::power::Protections {
            pause_on_battery: false,
            idle_only: false,
            pause_when_hot: false,
        })
        .unwrap();
        n.set_lend_modes(Modes::CONTAINER.with(gimmecores_core::ExecutionMode::Sandbox))
            .unwrap();
        n
    };
    let desktop = start().await;
    let (laptop, _h) = node("Laptop").await;
    pair(&laptop, &desktop).await;
    desktop
        .set_standing_rule(&laptop.key(), &standard_terms(4, 8, 8, now()), 8)
        .await
        .unwrap();
    let GrantOutcome::Granted { id, .. } = ask(&laptop, &desktop, 1, 1, 1).await else {
        panic!("not accepted")
    };
    desktop.shutdown().await;
    drop(desktop);

    let desktop = start().await;
    assert_eq!(desktop.grant_state(id), Some(GrantState::Active), "kept");
    assert!(desktop.issued_by_rule(id), "and still known as the rule's");
    assert_eq!(
        desktop.remove_standing_rule(&laptop.key()).await.unwrap(),
        1
    );
    assert_eq!(desktop.grant_state(id), Some(GrantState::Revoked));
}
