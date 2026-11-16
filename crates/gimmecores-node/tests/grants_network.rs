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
async fn a_request_nobody_answers_lapses_and_is_not_called_declined() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    desktop.set_decision_timeout(std::time::Duration::from_millis(300));
    let outcome = laptop
        .request_grant(&desktop.key(), &standard_terms(1, 1, 1, now()), "")
        .await
        .unwrap();
    assert!(matches!(outcome, GrantOutcome::NoAnswer), "got {outcome:?}");
    // The lender's book says it lapsed, and nothing is pending or usable on either side.
    let lent = desktop.lent_grants();
    assert_eq!(lent.len(), 1);
    assert_eq!(lent[0].2, GrantState::Expired);
    assert!(desktop.incoming_requests().is_empty());
    assert!(laptop.borrowed_grants().is_empty());
    // Asking also told each side which version the other runs (`gmc peers`).
    let ours = gimmecores_node::software_version();
    assert_eq!(laptop.peer_version(&desktop.key()).unwrap().0, ours);
    assert_eq!(desktop.peer_version(&laptop.key()).unwrap().0, ours);
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

/// A request's reason is written to the lender's audit log cleaned and capped, however long
/// or strange the text the other device sent.
#[tokio::test]
async fn a_grant_request_reason_is_capped_in_the_log() {
    let (laptop, _h1) = common::node("Laptop").await;
    let (desktop, _h2) = common::node("Desktop").await;
    common::pair(&laptop, &desktop).await;
    let reason = format!("please\u{202e}{}", "r".repeat(1 << 20));
    let ask = {
        let (b, k) = (laptop.clone(), desktop.key());
        tokio::spawn(async move {
            b.request_grant(
                &k,
                &gimmecores_node::grants_flow::standard_terms(1, 1, 1, gimmecores_node::now()),
                &reason,
            )
            .await
        })
    };
    let req = common::eventually(|| desktop.incoming_requests().into_iter().next()).await;
    desktop
        .respond_to_request(
            req.id,
            gimmecores_node::grants_flow::Decision::Decline("no".into()),
        )
        .unwrap();
    let _ = ask.await;
    let log = std::fs::read_to_string(desktop.paths().audit_log()).unwrap();
    let longest = log.lines().map(str::len).max().unwrap_or(0);
    assert!(longest < 2048, "a log line of {longest} bytes");
    assert!(!log.contains('\u{202e}'));
}

#[tokio::test]
async fn a_device_learns_how_to_wake_another_only_while_its_owner_allows_it() {
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    let macs = gimmecores_node::wake::local_macs();
    assert!(laptop.wake_macs(&desktop.key()).is_empty());
    assert!(
        laptop.wake(&desktop.key()).is_err(),
        "not allowed: nothing to send"
    );
    // A request carries no addresses while the desktop's owner has not allowed waking.
    desktop.set_decision_timeout(std::time::Duration::from_millis(200));
    let _ = laptop
        .request_grant(&desktop.key(), &standard_terms(1, 1, 1, now()), "")
        .await;
    assert!(laptop.wake_macs(&desktop.key()).is_empty());

    desktop.set_wake_allowed(&laptop.key(), true).await.unwrap();
    assert!(desktop.wake_allowed(&laptop.key()));
    assert!(!laptop.wake_allowed(&desktop.key()), "one direction only");
    if macs.is_empty() {
        eprintln!("no network card on a local network here: addresses not checked");
    } else {
        // Told at once, both devices being up.
        eventually(|| (laptop.wake_macs(&desktop.key()) == macs).then_some(())).await;
    }
    // Stopping needs no presence, and the laptop is told to forget the addresses.
    desktop
        .set_wake_allowed(&laptop.key(), false)
        .await
        .unwrap();
    eventually(|| laptop.wake_macs(&desktop.key()).is_empty().then_some(())).await;
}

#[tokio::test]
async fn allowing_a_device_to_wake_this_one_needs_the_owner() {
    let (strict, _h1) = common::fresh_node_with(
        "Strict",
        gimmecores_node::presence::Outcome::Denied("no".into()),
    )
    .await;
    let (other, _h2) = node("Other").await;
    let e = strict
        .set_wake_allowed(&other.key(), true)
        .await
        .unwrap_err();
    assert!(
        e.downcast_ref::<gimmecores_node::node::PresenceRefused>()
            .is_some(),
        "{e:#}"
    );
    assert!(!strict.wake_allowed(&other.key()));
}

#[tokio::test]
async fn sandbox_grants_list_the_lenders_tools_while_it_shares_them() {
    use gimmecores_core::{ExecutionMode, Modes};
    use gimmecores_node::grants_flow::verify_signed;
    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    desktop
        .set_lend_modes(Modes::CONTAINER.with(ExecutionMode::Sandbox))
        .unwrap();
    desktop.set_tools_for_tests(vec![("python3".into(), "3.13.2".into())]);
    let tools_in = |modes: Modes| {
        let (laptop, desktop) = (laptop.clone(), desktop.clone());
        async move {
            let mut terms = standard_terms(1, 1, 1, now());
            terms.modes = modes;
            let ask = {
                let (b, k) = (laptop.clone(), desktop.key());
                tokio::spawn(async move { b.request_grant(&k, &terms, "").await })
            };
            let req = eventually(|| desktop.incoming_requests().into_iter().next()).await;
            desktop
                .respond_to_request(req.id, Decision::Accept(None))
                .unwrap();
            let GrantOutcome::Granted { id, .. } = ask.await.unwrap().unwrap() else {
                panic!("not granted")
            };
            let held = laptop
                .borrowed_grants()
                .into_iter()
                .find(|(g, _)| *g == id)
                .unwrap()
                .1;
            verify_signed(&held.signed, &desktop.key(), &laptop.key())
                .unwrap()
                .tools
                .into_iter()
                .map(|t| (t.name, t.version))
                .collect::<Vec<_>>()
        }
    };
    let sandbox = Modes::NONE.with(ExecutionMode::Sandbox);
    assert_eq!(
        tools_in(sandbox).await,
        [("python3".to_string(), "3.13.2".to_string())]
    );
    // A container sees its image's tools, not these: none listed.
    assert!(tools_in(Modes::CONTAINER).await.is_empty());
    // The owner stops sharing them (no presence needed).
    desktop.set_share_tools(false).await.unwrap();
    assert!(tools_in(sandbox).await.is_empty());
}
