#![allow(clippy::unwrap_used)]

mod common;

use common::{eventually, fresh_node, node, pair};
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

#[tokio::test]
async fn lending_is_off_after_install_and_requests_are_declined() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = fresh_node("Desktop").await;
    assert!(!desktop.lending_enabled(), "principle 1: off by default");
    pair(&laptop, &desktop).await;
    let outcome = laptop
        .request_grant(&desktop.key(), &standard_terms(1, 1, 1, now()), "")
        .await
        .unwrap();
    assert!(
        matches!(outcome, GrantOutcome::Declined(ref r) if r.contains("lending is turned off")),
        "{outcome:?}"
    );
    assert!(
        desktop.incoming_requests().is_empty(),
        "the user is not even asked"
    );
}

#[tokio::test]
async fn turning_lending_off_revokes_everything() {
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
    desktop.set_lending(false).unwrap();
    assert_eq!(desktop.grant_state(incoming.id), Some(GrantState::Revoked));
    assert!(!desktop.lending_enabled());
}

#[test]
fn pairing_tickets_round_trip_and_reject_garbage() {
    use gimmecores_node::wire::parse_ticket;
    let key = "a".repeat(64);
    assert!(parse_ticket(&format!("gmc1:{key}@192.168.1.5:47474,127.0.0.1:47474")).is_ok());
    // One unusable address does not spoil the ticket.
    let t = parse_ticket(&format!("gmc1:{key}@[fe80::1%zz]:1,192.168.1.5:47474")).unwrap();
    assert_eq!(t.ip_addrs().count(), 1);
    for bad in [
        "",
        "gmc1:",
        "gmc2:aa@1.2.3.4:1",
        &format!("gmc1:{key}"),
        &format!("gmc1:{key}@nonsense"),
        "gmc1:zz@1.2.3.4:1",
    ] {
        assert!(parse_ticket(bad).is_err(), "{bad:?}");
    }
}

#[tokio::test]
async fn link_test_measures_rtt_and_throughput_between_paired_devices() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    let s = laptop.link_test(&desktop.key()).await.unwrap();
    assert_eq!(s.interface, "loopback");
    assert!(s.rtt_min <= s.rtt_median && s.rtt_median <= s.rtt_p95);
    assert!(s.rtt_median < std::time::Duration::from_millis(50), "{s:?}");
    assert!(
        s.upload_bps > 10_000_000 && s.download_bps > 10_000_000,
        "{s:?}"
    );
    assert!(!s.good_for.is_empty());
    assert!(
        laptop.last_link(&desktop.key()).is_some(),
        "result is remembered for gmc peers"
    );
}

#[tokio::test]
async fn unpaired_devices_cannot_run_a_link_test() {
    let (stranger, _h1) = node("Stranger").await;
    let (desktop, _h2) = node("Desktop").await;
    assert!(stranger.link_test(&desktop.key()).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn link_speed() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    let s = laptop.link_test(&desktop.key()).await.unwrap();
    eprintln!(
        "LINK up {:.2} Gbit/s down {:.2} Gbit/s",
        s.upload_bps as f64 / 1e9,
        s.download_bps as f64 / 1e9
    );
}
