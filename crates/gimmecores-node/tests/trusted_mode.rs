//! Trusted mode (threat model, section 6): a property of a pair of devices, turned on by each
//! side's own user (with presence), carried in signed grants, and withdrawn by either side.
//! The borrower's own setting is what lets results be decoded as code; nothing a lender sends
//! can switch that on.
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

mod common;

use std::path::Path;
use std::time::Duration;

use common::{eventually, fresh_node_with, node, pair};
use gimmecores_core::{GrantId, GrantState, TrustLevel};
use gimmecores_node::api;
use gimmecores_node::grants_flow::{Decision, GrantOutcome, standard_terms};
use gimmecores_node::node::{Node, NodeConfig};
use gimmecores_node::now;
use gimmecores_node::paths::Paths;
use gimmecores_node::presence::{FixedPresence, Outcome};
use gimmecores_proto::local::v1 as l;
use gimmecores_proto::local::v1::client_client::ClientClient;
use gimmecores_proto::local::v1::control_client::ControlClient;
use gimmecores_proto::peer::v1 as pb;
use tonic::Code;
use tonic::transport::Channel;

fn trusted_terms() -> gimmecores_core::GrantTerms {
    let mut t = standard_terms(1, 1, 2, now());
    t.trust = TrustLevel::Trusted;
    t
}

/// Borrower asks; the lender's user accepts as asked.
async fn ask(
    borrower: &Node,
    lender: &Node,
    terms: gimmecores_core::GrantTerms,
) -> anyhow::Result<GrantOutcome> {
    let task = {
        let (b, k) = (borrower.clone(), lender.key());
        tokio::spawn(async move { b.request_grant(&k, &terms, "t").await })
    };
    // A request refused before it reaches the lender's user never shows up there.
    for _ in 0..40 {
        if task.is_finished() {
            break;
        }
        if let Some(r) = lender.incoming_requests().into_iter().next() {
            lender
                .respond_to_request(r.id, Decision::Accept(None))
                .unwrap();
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    task.await.unwrap()
}

async fn trusted_pair() -> (Node, Node, tempfile::TempDir, tempfile::TempDir) {
    let (lender, hl) = node("Desktop").await;
    let (borrower, hb) = node("Laptop").await;
    pair(&borrower, &lender).await;
    (lender, borrower, hl, hb)
}

#[tokio::test]
async fn a_trusted_grant_needs_trusted_mode_on_both_devices() {
    let (lender, borrower, _hl, _hb) = trusted_pair().await;

    // Neither side: the borrower does not even ask.
    let err = ask(&borrower, &lender, trusted_terms()).await.unwrap_err();
    assert!(format!("{err:#}").contains("Trusted mode"), "{err:#}");

    // Only the borrower: the lender declines without asking its user.
    borrower.set_trusted_mode(&lender.key(), true).unwrap();
    let GrantOutcome::Declined(why) = ask(&borrower, &lender, trusted_terms()).await.unwrap()
    else {
        panic!("granted without the lender's Trusted mode")
    };
    assert!(why.contains("Trusted mode"), "{why}");

    // Both: granted, and the signed grant says Trusted.
    lender.set_trusted_mode(&borrower.key(), true).unwrap();
    let GrantOutcome::Granted { id, terms } =
        ask(&borrower, &lender, trusted_terms()).await.unwrap()
    else {
        panic!("declined")
    };
    assert_eq!(terms.trust, TrustLevel::Trusted);
    let lent = lender
        .lent_grants()
        .into_iter()
        .find(|g| g.0 == id)
        .unwrap();
    assert_eq!(lent.3.trust, TrustLevel::Trusted);

    // Only paired devices can be trusted.
    let (stranger, _hs) = node("Stranger").await;
    assert!(lender.set_trusted_mode(&stranger.key(), true).is_err());
}

#[tokio::test]
async fn a_standard_request_is_never_upgraded_to_trusted() {
    let (lender, borrower, _hl, _hb) = trusted_pair().await;
    lender.set_trusted_mode(&borrower.key(), true).unwrap();
    borrower.set_trusted_mode(&lender.key(), true).unwrap();
    let asked = standard_terms(1, 1, 2, now());
    let task = {
        let (b, k, t) = (borrower.clone(), lender.key(), asked.clone());
        tokio::spawn(async move { b.request_grant(&k, &t, "t").await })
    };
    let r = eventually(|| lender.incoming_requests().into_iter().next()).await;
    let mut more = asked.clone();
    more.trust = TrustLevel::Trusted;
    assert!(
        lender
            .respond_to_request(r.id, Decision::Accept(Some(more)))
            .is_err(),
        "the lender may only reduce what was asked"
    );
    lender
        .respond_to_request(r.id, Decision::Accept(None))
        .unwrap();
    let GrantOutcome::Granted { terms, .. } = task.await.unwrap().unwrap() else {
        panic!("declined")
    };
    assert_eq!(terms.trust, TrustLevel::Standard);
}

fn lent_state(n: &Node, g: GrantId) -> Option<GrantState> {
    n.lent_grants().into_iter().find(|x| x.0 == g).map(|x| x.2)
}

#[tokio::test]
async fn turning_it_off_on_either_side_withdraws_trusted_grants_only() {
    let (lender, borrower, _hl, _hb) = trusted_pair().await;
    lender.set_trusted_mode(&borrower.key(), true).unwrap();
    borrower.set_trusted_mode(&lender.key(), true).unwrap();
    let GrantOutcome::Granted { id: t1, .. } =
        ask(&borrower, &lender, trusted_terms()).await.unwrap()
    else {
        panic!()
    };
    let GrantOutcome::Granted { id: s1, .. } =
        ask(&borrower, &lender, standard_terms(1, 1, 2, now()))
            .await
            .unwrap()
    else {
        panic!()
    };

    // The lender turns it off: its Trusted grant is revoked; the standard one stays.
    lender.set_trusted_mode(&borrower.key(), false).unwrap();
    assert!(!lender.is_trusted(&borrower.key()));
    assert_eq!(lent_state(&lender, t1), Some(GrantState::Revoked));
    assert_eq!(lent_state(&lender, s1), Some(GrantState::Active));
    eventually(|| (!borrower.borrowed_grants().iter().any(|(id, _)| *id == t1)).then_some(()))
        .await;

    // Again, and this time the borrower turns its side off: it drops the grant itself
    // and tells the lender, which revokes it too.
    lender.set_trusted_mode(&borrower.key(), true).unwrap();
    let GrantOutcome::Granted { id: t2, .. } =
        ask(&borrower, &lender, trusted_terms()).await.unwrap()
    else {
        panic!()
    };
    borrower.set_trusted_mode(&lender.key(), false).unwrap();
    assert!(!borrower.borrowed_grants().iter().any(|(id, _)| *id == t2));
    assert!(
        borrower.borrowed_grants().iter().any(|(id, _)| *id == s1),
        "standard grants are not affected"
    );
    eventually(|| (lent_state(&lender, t2) == Some(GrantState::Revoked)).then_some(())).await;
    let audit = std::fs::read_to_string(borrower.paths().audit_log()).unwrap();
    assert!(audit.contains("Trusted mode turned on"), "{audit}");
    assert!(audit.contains("turned off"), "{audit}");
}

// ---------------------------------------------------------------- through the sockets

async fn serve(node: &Node) {
    tokio::spawn(api::serve(node.clone()));
    let path = node.paths().control_socket();
    for _ in 0..100 {
        if path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn control(node: &Node) -> ControlClient<Channel> {
    ControlClient::new(api::channel(&node.paths().control_socket()).await.unwrap())
}

async fn client(node: &Node) -> ClientClient<Channel> {
    ClientClient::new(api::channel(&node.paths().client_socket()).await.unwrap())
}

#[tokio::test]
async fn i13_turning_it_on_needs_the_warning_and_the_owner_and_turning_it_off_does_not() {
    let (lender, _hl) = node("Desktop").await;
    let (borrower, _hb) = fresh_node_with("Laptop", Outcome::Denied("cancelled".into())).await;
    pair(&borrower, &lender).await;
    serve(&borrower).await;
    let mut ctl = control(&borrower).await;
    let fp = lender.key().fingerprint();

    let err = ctl
        .set_trusted_mode(l::SetTrustedModeRequest {
            peer_fingerprint: fp.clone(),
            enabled: true,
            warning_acknowledged: false,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(err.message().contains("run any code on your machine"));

    let err = ctl
        .set_trusted_mode(l::SetTrustedModeRequest {
            peer_fingerprint: fp.clone(),
            enabled: true,
            warning_acknowledged: true,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");
    assert!(!borrower.is_trusted(&lender.key()));

    ctl.set_trusted_mode(l::SetTrustedModeRequest {
        peer_fingerprint: fp,
        enabled: false,
        warning_acknowledged: false,
    })
    .await
    .unwrap();
}

fn job(dir: &Path, trusted: bool, script: &str) -> l::JobSpec {
    l::JobSpec {
        project_root: dir.to_string_lossy().into_owned(),
        trusted,
        inline_tasks: vec![l::InlineTask {
            name: "t".into(),
            work: Some(l::inline_task::Work::Command(pb::Command {
                argv: vec!["sh".into(), "-c".into(), script.into()],
                ..Default::default()
            })),
            mode: pb::ExecutionMode::Sandbox as i32,
            files: vec![l::InlineFile {
                path: ".gmc-sdk/payload".into(),
                data: b"payload".to_vec(),
            }],
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// Runs a job to the end: (`trusted_results`, stdout, final status).
async fn submit(c: &mut ClientClient<Channel>, j: l::JobSpec) -> Result<(bool, String, i32), Code> {
    let mut stream = c.submit_job(j).await.map_err(|e| e.code())?.into_inner();
    let (mut out, mut status, mut trusted) = (String::new(), 0, false);
    while let Some(ev) = stream.message().await.map_err(|e| e.code())? {
        match ev.event {
            Some(l::job_event::Event::Task(t)) => match t.event {
                Some(pb::task_event::Event::Log(c)) => {
                    out.push_str(&String::from_utf8_lossy(&c.data));
                }
                Some(pb::task_event::Event::Finished(r)) => status = r.status,
                _ => {}
            },
            Some(l::job_event::Event::Done(d)) => trusted = d.trusted_results,
            _ => {}
        }
    }
    Ok((trusted, out, status))
}

#[tokio::test]
async fn only_the_borrowers_daemon_vouches_for_trusted_results() {
    let (lender, borrower, _hl, _hb) = trusted_pair().await;
    serve(&borrower).await;
    let mut c = client(&borrower).await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("x"), "x").unwrap();

    // A standard grant: a Trusted job has nothing to run under.
    let GrantOutcome::Granted { .. } = ask(&borrower, &lender, standard_terms(1, 1, 2, now()))
        .await
        .unwrap()
    else {
        panic!()
    };
    let code = submit(&mut c, job(dir.path(), true, "true"))
        .await
        .unwrap_err();
    assert_eq!(code, Code::FailedPrecondition);
    // A standard job runs, and is never vouched for. The SDK's files arrive.
    let (trusted, out, status) = submit(&mut c, job(dir.path(), false, "cat .gmc-sdk/payload"))
        .await
        .unwrap();
    assert!(!trusted);
    assert_eq!(status, pb::task_result::Status::Succeeded as i32);
    assert_eq!(out, "payload");
    assert!(
        !dir.path().join(".gmc-sdk").exists(),
        "SDK files are not written into the project"
    );

    // The SDK's payload is scanned for secrets like any project file.
    let mut leaky = job(dir.path(), false, "true");
    leaky.inline_tasks[0].files[0].data =
        b"api_key = ghp_abcdefghijklmnopqrstuvwxyz0123456789AB".to_vec();
    let code = submit(&mut c, leaky).await.unwrap_err();
    assert_eq!(code, Code::Aborted);

    // Both sides on, a Trusted grant: vouched for.
    lender.set_trusted_mode(&borrower.key(), true).unwrap();
    borrower.set_trusted_mode(&lender.key(), true).unwrap();
    let GrantOutcome::Granted { .. } = ask(&borrower, &lender, trusted_terms()).await.unwrap()
    else {
        panic!()
    };
    let (trusted, _, status) = submit(&mut c, job(dir.path(), true, "true")).await.unwrap();
    assert_eq!(status, pb::task_result::Status::Succeeded as i32);
    assert!(trusted);

    // Turned off on this side while the task runs: not vouched for.
    let running = {
        let mut c = c.clone();
        let j = job(dir.path(), true, "sleep 2");
        tokio::spawn(async move { submit(&mut c, j).await })
    };
    tokio::time::sleep(Duration::from_millis(700)).await;
    borrower.set_trusted_mode(&lender.key(), false).unwrap();
    let (trusted, _, _) = running.await.unwrap().unwrap();
    assert!(!trusted, "vouched for after Trusted mode was turned off");
}

// ---------------------------------------------------------------- restarts and lapsing

async fn start(home: &Path, name: &str, port: u16) -> Node {
    Node::start(NodeConfig {
        paths: Paths::at(home),
        device_name: name.into(),
        bind: format!("127.0.0.1:{port}").parse().unwrap(),
        executors: gimmecores_node::exec::Executors::test_processes(),
        presence: std::sync::Arc::new(FixedPresence(Outcome::Verified)),
    })
    .await
    .unwrap()
}

fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn a_lapsed_trusted_mode_drops_saved_trusted_grants_on_restart() {
    let hl = tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap();
    let port = free_port();
    let lender = start(hl.path(), "Desktop", port).await;
    lender.set_lending(true).unwrap();
    // Saved, so the restart below finds grants active on a laptop on battery too.
    lender
        .set_protections(gimmecores_node::power::Protections {
            pause_on_battery: false,
            idle_only: false,
        })
        .unwrap();
    let (borrower, _hb) = node("Laptop").await;
    pair(&borrower, &lender).await;
    lender.set_trusted_mode(&borrower.key(), true).unwrap();
    borrower.set_trusted_mode(&lender.key(), true).unwrap();
    let GrantOutcome::Granted { id, .. } = ask(&borrower, &lender, trusted_terms()).await.unwrap()
    else {
        panic!()
    };
    let GrantOutcome::Granted { id: std_id, .. } =
        ask(&borrower, &lender, standard_terms(1, 1, 2, now()))
            .await
            .unwrap()
    else {
        panic!()
    };
    lender.shutdown().await;
    drop(lender);

    // 30 days pass while the lender is off.
    let peers = hl.path().join("peers.json");
    let mut list: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&peers).unwrap()).unwrap();
    list[0]["trusted_until"] = serde_json::json!(now() - 1);
    std::fs::write(&peers, serde_json::to_vec(&list).unwrap()).unwrap();

    let lender = start(hl.path(), "Desktop", port).await;
    assert!(!lender.is_trusted(&borrower.key()));
    assert!(lent_state(&lender, id).is_none(), "trusted grant came back");
    assert_eq!(lent_state(&lender, std_id), Some(GrantState::Active));
}
