//! WatchEvents: a subscriber hears about new requests, grant changes, pairing, activity and
//! status changes as they happen.
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

mod common;

use std::time::Duration;

use common::{node, pair};
use gimmecores_node::api;
use gimmecores_node::grants_flow::standard_terms;
use gimmecores_node::node::Node;
use gimmecores_node::now;
use gimmecores_proto::local::v1 as l;
use gimmecores_proto::local::v1::control_client::ControlClient;
use gimmecores_proto::peer::v1 as pb;
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

/// The next event matching `f`, within 10 s.
async fn next_matching(
    s: &mut tonic::Streaming<l::Event>,
    f: impl Fn(&l::event::Kind) -> bool,
) -> l::event::Kind {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let ev = s.message().await.unwrap().unwrap();
            let kind = ev.kind.unwrap();
            if f(&kind) {
                return kind;
            }
        }
    })
    .await
    .expect("no such event")
}

#[tokio::test]
async fn a_subscriber_hears_requests_grants_and_status_as_they_change() {
    let (lender, _h1) = node("Desktop").await;
    let (borrower, _h2) = node("Laptop").await;
    let mut events = control(&lender)
        .await
        .watch_events(l::WatchEventsRequest {})
        .await
        .unwrap()
        .into_inner();

    pair(&borrower, &lender).await;
    let ask = {
        let (b, k) = (borrower.clone(), lender.key());
        tokio::spawn(async move {
            b.request_grant(&k, &standard_terms(1, 1, 1, now()), "t")
                .await
        })
    };
    // A new request arrives as a grant in the REQUESTED state.
    let l::event::Kind::Grant(g) = next_matching(
        &mut events,
        |k| matches!(k, l::event::Kind::Grant(g) if g.state == pb::GrantState::Requested as i32),
    )
    .await
    else {
        unreachable!()
    };
    lender
        .respond_to_request(
            gimmecores_core::GrantId(g.grant_id.as_slice().try_into().unwrap()),
            gimmecores_node::grants_flow::Decision::Accept(None),
        )
        .unwrap();
    next_matching(&mut events, |k| {
        matches!(k, l::event::Kind::Grant(x) if x.grant_id == g.grant_id
            && x.state == pb::GrantState::Active as i32)
    })
    .await;
    ask.await.unwrap().unwrap();

    // Turning lending off is a status change (and revokes the grant).
    lender.set_lending(false).unwrap();
    next_matching(
        &mut events,
        |k| matches!(k, l::event::Kind::Status(s) if !s.lending_enabled),
    )
    .await;
    next_matching(&mut events, |k| {
        matches!(k, l::event::Kind::Grant(x) if x.grant_id == g.grant_id
            && x.state == pb::GrantState::Revoked as i32)
    })
    .await;
}

/// A lender with a granted device and nothing happening sends nothing: listings report the
/// time a grant was signed, not the time of the listing.
#[tokio::test]
async fn a_quiet_lender_sends_no_events() {
    let (lender, _h1) = node("Desktop").await;
    let (borrower, _h2) = node("Laptop").await;
    pair(&borrower, &lender).await;
    let ask = {
        let (b, k) = (borrower.clone(), lender.key());
        tokio::spawn(async move {
            b.request_grant(&k, &standard_terms(1, 1, 1, now()), "t")
                .await
        })
    };
    let req = common::eventually(|| lender.incoming_requests().into_iter().next()).await;
    lender
        .respond_to_request(req.id, gimmecores_node::grants_flow::Decision::Accept(None))
        .unwrap();
    ask.await.unwrap().unwrap();

    let mut client = control(&lender).await;
    let mut events = client
        .watch_events(l::WatchEventsRequest {})
        .await
        .unwrap()
        .into_inner();
    let quiet = tokio::time::timeout(Duration::from_millis(2500), events.message()).await;
    assert!(quiet.is_err(), "an event with nothing happening: {quiet:?}");

    // The listed grant carries the time it was signed, the same on every call.
    let mut c = gimmecores_proto::local::v1::client_client::ClientClient::new(
        api::channel(&lender.paths().client_socket()).await.unwrap(),
    );
    let list = || l::ListGrantsRequest {
        include_inactive: false,
    };
    let first = c.list_grants(list()).await.unwrap().into_inner().grants;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let second = c.list_grants(list()).await.unwrap().into_inner().grants;
    assert_eq!(first, second);
    let issued = first[0].grant.as_ref().unwrap().issued_at.unwrap().seconds;
    assert!(issued > 0 && u64::try_from(issued).unwrap() <= now());
}
