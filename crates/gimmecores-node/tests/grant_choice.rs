//! A borrower can hold several grants from one lender (a request that waited, a standing
//! grant's, a renewal): each task goes under one it fits, not just the newest.
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

mod common;

use std::time::Duration;

use common::{node, pair};
use gimmecores_node::api;
use gimmecores_node::grants_flow::{Decision, GrantOutcome, standard_terms};
use gimmecores_node::node::Node;
use gimmecores_node::now;
use gimmecores_proto::local::v1 as l;
use gimmecores_proto::local::v1::client_client::ClientClient;
use gimmecores_proto::peer::v1 as pb;

/// The borrower asks; the lender's user accepts as asked.
async fn ask(borrower: &Node, lender: &Node, terms: gimmecores_core::GrantTerms) {
    let task = {
        let (b, k) = (borrower.clone(), lender.key());
        tokio::spawn(async move { b.request_grant(&k, &terms, "t").await })
    };
    for _ in 0..200 {
        if let Some(r) = lender.incoming_requests().into_iter().next() {
            lender
                .respond_to_request(r.id, Decision::Accept(None))
                .unwrap();
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(matches!(
        task.await.unwrap().unwrap(),
        GrantOutcome::Granted { .. }
    ));
}

/// Runs `sh -c script` asking for `cores`: (final status, stdout).
async fn run(
    c: &mut ClientClient<tonic::transport::Channel>,
    cores: u32,
    script: &str,
) -> (i32, String) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("x"), "x").unwrap();
    let job = l::JobSpec {
        project_root: dir.path().to_string_lossy().into_owned(),
        inline_tasks: vec![l::InlineTask {
            name: "t".into(),
            work: Some(l::inline_task::Work::Command(pb::Command {
                argv: vec!["sh".into(), "-c".into(), script.into()],
                ..Default::default()
            })),
            mode: pb::ExecutionMode::Sandbox as i32,
            resources: Some(pb::Limits {
                cpu_millis: cores * 1000,
                memory_bytes: 256 << 20,
                ..Default::default()
            }),
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut stream = c.submit_job(job).await.unwrap().into_inner();
    let (mut status, mut out) = (0, String::new());
    while let Some(ev) = stream.message().await.unwrap() {
        if let Some(l::job_event::Event::Task(t)) = ev.event {
            match t.event {
                Some(pb::task_event::Event::Log(c)) => {
                    out.push_str(&String::from_utf8_lossy(&c.data))
                }
                Some(pb::task_event::Event::Finished(r)) => status = r.status,
                _ => {}
            }
        }
    }
    (status, out)
}

#[tokio::test]
async fn a_task_goes_under_a_grant_it_fits() {
    let (lender, _hl) = node("Desktop").await;
    let (borrower, _hb) = node("Laptop").await;
    pair(&borrower, &lender).await;
    // Two cores for an hour, then one core for two hours: the newer one lasts longer.
    ask(&borrower, &lender, standard_terms(2, 1, 1, now())).await;
    ask(&borrower, &lender, standard_terms(1, 1, 2, now())).await;

    tokio::spawn(api::serve(borrower.clone()));
    let socket = borrower.paths().client_socket();
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut c = ClientClient::new(api::channel(&socket).await.unwrap());

    let (status, out) = run(&mut c, 2, "echo two-cores").await;
    assert_eq!(status, pb::task_result::Status::Succeeded as i32, "{out}");
    assert!(out.contains("two-cores"));
    let (status, out) = run(&mut c, 1, "echo one-core").await;
    assert_eq!(status, pb::task_result::Status::Succeeded as i32, "{out}");
    assert!(out.contains("one-core"));
    // Three cores fit neither: refused, as before, under the longest one.
    let (status, _) = run(&mut c, 3, "echo three").await;
    assert_ne!(status, pb::task_result::Status::Succeeded as i32);
}
