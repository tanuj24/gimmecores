#![allow(clippy::unwrap_used)]

mod common;

use common::{eventually, node, pair};
use gimmecores_core::GrantState;
use gimmecores_node::grants_flow::{Decision, GrantOutcome, standard_terms};
use gimmecores_node::now;

#[tokio::test]
async fn borrower_gets_a_signed_grant_only_after_the_lender_accepts() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;

    let terms = standard_terms(4, 8, 2, now());
    let req = {
        let laptop = laptop.clone();
        let desktop_key = desktop.key();
        let terms = terms.clone();
        tokio::spawn(async move {
            laptop
                .request_grant(&desktop_key, &terms, "run tests")
                .await
        })
    };
    let incoming = eventually(|| desktop.incoming_requests().into_iter().next()).await;
    assert_eq!(incoming.borrower, laptop.key());
    assert_eq!(incoming.borrower_name, "Laptop");
    assert_eq!(incoming.reason, "run tests");
    assert_eq!(
        desktop.grant_state(incoming.id),
        Some(GrantState::Requested)
    );
    assert!(
        laptop.borrowed_grants().is_empty(),
        "nothing usable before acceptance"
    );

    desktop
        .respond_to_request(incoming.id, Decision::Accept(None))
        .unwrap();
    let outcome = req.await.unwrap().unwrap();
    let GrantOutcome::Granted { id, terms: got } = outcome else {
        panic!("expected a grant, got {outcome:?}");
    };
    assert_eq!(id, incoming.id);
    assert_eq!(got.limits, terms.limits);
    assert_eq!(desktop.grant_state(id), Some(GrantState::Active));
    assert_eq!(laptop.borrowed_grants().len(), 1);
}

#[tokio::test]
async fn lender_can_reduce_but_never_exceed_the_request() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    let asked = standard_terms(4, 8, 2, now());
    let req = {
        let (laptop, k, t) = (laptop.clone(), desktop.key(), asked.clone());
        tokio::spawn(async move { laptop.request_grant(&k, &t, "").await })
    };
    let incoming = eventually(|| desktop.incoming_requests().into_iter().next()).await;

    let more = standard_terms(8, 8, 2, now());
    assert!(
        desktop
            .respond_to_request(incoming.id, Decision::Accept(Some(more)))
            .is_err()
    );

    let less = standard_terms(2, 4, 1, now());
    desktop
        .respond_to_request(incoming.id, Decision::Accept(Some(less.clone())))
        .unwrap();
    let GrantOutcome::Granted { terms, .. } = req.await.unwrap().unwrap() else {
        panic!("expected a grant");
    };
    assert_eq!(terms.limits.cpu_millis, 2000);
    assert_eq!(terms.limits.memory_bytes, 4 << 30);
}

#[tokio::test]
async fn declined_requests_leave_nothing_usable() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    let req = {
        let (laptop, k) = (laptop.clone(), desktop.key());
        tokio::spawn(async move {
            laptop
                .request_grant(&k, &standard_terms(2, 2, 1, now()), "")
                .await
        })
    };
    let incoming = eventually(|| desktop.incoming_requests().into_iter().next()).await;
    desktop
        .respond_to_request(incoming.id, Decision::Decline("busy".into()))
        .unwrap();
    assert!(matches!(req.await.unwrap().unwrap(), GrantOutcome::Declined(r) if r == "busy"));
    assert_eq!(desktop.grant_state(incoming.id), Some(GrantState::Declined));
    assert!(laptop.borrowed_grants().is_empty());
}

#[tokio::test]
async fn unpaired_devices_cannot_even_ask() {
    let (stranger, _h1) = node("Stranger").await;
    let (desktop, _h2) = node("Desktop").await;
    // Not paired: the stranger has no address on file and the desktop would refuse anyway.
    assert!(
        stranger
            .request_grant(&desktop.key(), &standard_terms(1, 1, 1, now()), "")
            .await
            .is_err()
    );
    assert!(desktop.incoming_requests().is_empty());
}

#[tokio::test]
async fn lender_revoke_reaches_the_borrower() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    let req = {
        let (laptop, k) = (laptop.clone(), desktop.key());
        tokio::spawn(async move {
            laptop
                .request_grant(&k, &standard_terms(2, 2, 1, now()), "")
                .await
        })
    };
    let incoming = eventually(|| desktop.incoming_requests().into_iter().next()).await;
    desktop
        .respond_to_request(incoming.id, Decision::Accept(None))
        .unwrap();
    req.await.unwrap().unwrap();
    assert_eq!(laptop.borrowed_grants().len(), 1);

    desktop.revoke_grant(incoming.id).await.unwrap();
    assert_eq!(desktop.grant_state(incoming.id), Some(GrantState::Revoked));
    eventually(|| laptop.borrowed_grants().is_empty().then_some(())).await;
}
