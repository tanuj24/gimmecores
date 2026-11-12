//! I13 through the daemon's Control socket: actions that let other devices do more need the
//! owner's OS-verified presence; actions that reduce access never do.
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

mod common;

use std::time::Duration;

use common::{eventually, fresh_node, fresh_node_with, pair, wait_for};
use gimmecores_node::api;
use gimmecores_node::grants_flow::standard_terms;
use gimmecores_node::node::Node;
use gimmecores_node::now;
use gimmecores_node::presence::Outcome;
use gimmecores_proto::local::v1 as l;
use gimmecores_proto::local::v1::control_client::ControlClient;
use tonic::Code;
use tonic::transport::Channel;

async fn control(node: &Node) -> ControlClient<Channel> {
    tokio::spawn(api::serve(node.clone()));
    let path = node.paths().control_socket();
    for _ in 0..100 {
        if path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    ControlClient::new(api::channel(&path).await.unwrap())
}

fn lend_on() -> l::SetLendingRequest {
    l::SetLendingRequest {
        enabled: true,
        idle_only: false,
        allow_on_battery: false,
    }
}

fn audit(node: &Node) -> String {
    std::fs::read_to_string(node.paths().audit_log()).unwrap()
}

#[tokio::test]
async fn i13_turning_lending_on_needs_the_owner() {
    let (n, _h) = fresh_node_with("Desktop", Outcome::Denied("cancelled".into())).await;
    let mut ctl = control(&n).await;
    let err = ctl.set_lending(lend_on()).await.unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");
    assert!(!n.lending_enabled(), "nothing changed");
    assert!(audit(&n).contains("not approved: turn on lending"));
    // Turning lending off reduces access: never asks.
    ctl.set_lending(l::SetLendingRequest::default())
        .await
        .unwrap();
}

#[tokio::test]
async fn i13_accepting_a_request_needs_the_owner_and_declining_does_not() {
    let (laptop, _h1) = fresh_node("Laptop").await;
    let (desktop, _h2) = fresh_node_with("Desktop", Outcome::Denied("cancelled".into())).await;
    desktop.set_lending(true).unwrap(); // in-process: as if approved earlier
    pair(&laptop, &desktop).await;
    let mut ctl = control(&desktop).await;
    let ask = {
        let (b, k) = (laptop.clone(), desktop.key());
        tokio::spawn(async move {
            b.request_grant(&k, &standard_terms(2, 2, 1, now()), "tests")
                .await
        })
    };
    let req = eventually(|| desktop.incoming_requests().into_iter().next()).await;
    let accept = l::RespondToGrantRequest {
        grant_id: req.id.0.to_vec(),
        decision: l::respond_to_grant_request::Decision::Accept as i32,
        edited: None,
    };
    let err = ctl.respond_to_grant(accept).await.unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(desktop.incoming_requests().len(), 1, "still waiting");
    let log = audit(&desktop);
    assert!(
        log.contains("let \\\"Laptop\\\" use 2 cores"),
        "the prompt names who and what: {log}"
    );
    ctl.respond_to_grant(l::RespondToGrantRequest {
        grant_id: req.id.0.to_vec(),
        decision: l::respond_to_grant_request::Decision::Decline as i32,
        edited: None,
    })
    .await
    .unwrap();
    assert!(ask.await.unwrap().is_ok());
}

#[tokio::test]
async fn i13_confirming_a_pairing_needs_the_owner_and_rejecting_does_not() {
    let (laptop, _h1) = fresh_node("Laptop").await;
    let (desktop, _h2) = fresh_node_with("Desktop", Outcome::Denied("cancelled".into())).await;
    let mut ctl = control(&desktop).await;
    desktop.open_pairing();
    laptop.start_pairing(desktop.addr()).await.unwrap();
    let view = wait_for(&desktop, |v| v.code.is_some()).await;
    let session_id = view.id.to_be_bytes().to_vec();
    let err = ctl
        .confirm_pairing(l::ConfirmPairingRequest {
            session_id: session_id.clone(),
            codes_match: true,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert!(!desktop.is_paired(&laptop.key()));
    ctl.confirm_pairing(l::ConfirmPairingRequest {
        session_id,
        codes_match: false,
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn i13_when_the_os_cannot_ask_nothing_on_the_socket_can_switch_the_check_off() {
    let (n, _h) = fresh_node_with("Pi", Outcome::Unavailable("no screen".into())).await;
    let mut ctl = control(&n).await;
    let err = ctl.set_lending(lend_on()).await.unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert!(
        err.message().contains("gmcd --no-presence"),
        "{}",
        err.message()
    );
    let err = ctl
        .set_presence(l::SetPresenceRequest { required: false })
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        Code::PermissionDenied,
        "a script cannot opt out"
    );
    assert!(n.presence().0);

    // The process that starts the daemon can (gmcd --no-presence): audited, not persisted.
    n.waive_presence_for_this_run();
    assert!(audit(&n).contains("presence checks OFF for this run"));
    ctl.set_lending(lend_on()).await.unwrap();
    assert!(n.lending_enabled());
    let settings = std::fs::read_to_string(n.paths().settings_file()).unwrap();
    assert!(
        settings.contains("\"require_presence\": true"),
        "{settings}"
    );
}

#[tokio::test]
async fn i13_loosening_laptop_protections_needs_the_owner() {
    let (n, _h) = fresh_node_with("Laptop", Outcome::Denied("cancelled".into())).await;
    n.set_lending(true).unwrap(); // in-process: as if approved earlier
    let mut ctl = control(&n).await;
    let on_battery = l::SetLendingRequest {
        enabled: true,
        idle_only: false,
        allow_on_battery: true,
    };
    let err = ctl.set_lending(on_battery).await.unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert!(n.protections().pause_on_battery, "unchanged");
    // Tightening never asks.
    ctl.set_lending(l::SetLendingRequest {
        enabled: true,
        idle_only: true,
        allow_on_battery: false,
    })
    .await
    .unwrap();
    assert!(n.protections().idle_only);
}

#[tokio::test]
async fn i13_where_presence_works_turning_it_off_needs_presence() {
    let (n, _h) = fresh_node_with("Mac", Outcome::Denied("cancelled".into())).await;
    let mut ctl = control(&n).await;
    let err = ctl
        .set_presence(l::SetPresenceRequest { required: false })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert!(n.presence().0, "still required");
}
