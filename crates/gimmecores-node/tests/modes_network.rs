//! The lender decides which ways of running tasks it lends; grants and tasks follow that.
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

mod common;

use std::time::Duration;

use common::{eventually, fresh_node, pair};
use gimmecores_core::{ExecutionMode, GrantId, Modes};
use gimmecores_node::exec::LogChunk;
use gimmecores_node::grants_flow::{Decision, GrantOutcome, standard_terms};
use gimmecores_node::node::Node;
use gimmecores_node::now;
use gimmecores_node::tasks_flow::{TaskReport, TaskSpec, TaskStatus};
use tokio::sync::mpsc;

const BOTH: Modes = Modes {
    container: true,
    sandbox: true,
    native: false,
};

/// A lender lending `modes`, paired with a borrower; returns the borrower's request outcome.
async fn ask(lends: Modes) -> (Node, Node, GrantOutcome, Vec<tempfile::TempDir>) {
    let (laptop, h1) = fresh_node("Laptop").await;
    let (desktop, h2) = fresh_node("Desktop").await;
    desktop.set_lending(true).unwrap();
    desktop.set_lend_modes(lends).unwrap();
    pair(&laptop, &desktop).await;
    let req = {
        let (b, k) = (laptop.clone(), desktop.key());
        tokio::spawn(async move {
            b.request_grant(&k, &standard_terms(2, 2, 1, now()), "tests")
                .await
        })
    };
    let outcome = if lends.is_empty() {
        req.await.unwrap().unwrap()
    } else {
        let incoming = eventually(|| desktop.incoming_requests().into_iter().next()).await;
        assert_eq!(
            incoming.requested.modes,
            lends.intersect(BOTH),
            "the request screen shows only what is lent"
        );
        desktop
            .respond_to_request(incoming.id, Decision::Accept(None))
            .unwrap();
        req.await.unwrap().unwrap()
    };
    (laptop, desktop, outcome, vec![h1, h2])
}

fn granted(o: &GrantOutcome) -> (GrantId, Modes) {
    match o {
        GrantOutcome::Granted { id, terms } => (*id, terms.modes),
        other => panic!("{other:?}"),
    }
}

async fn run(
    b: &Node,
    l: &Node,
    g: GrantId,
    image: Option<&str>,
    mode: Option<ExecutionMode>,
) -> TaskReport {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("x"), "x").unwrap();
    let (tx, mut rx) = mpsc::channel::<LogChunk>(64);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    b.run_task(
        &l.key(),
        g,
        TaskSpec {
            dir: dir.path().to_path_buf(),
            argv: vec!["true".into()],
            image: image.map(String::from),
            mode,
            outputs: vec![],
            excludes: vec![],
            allow_secrets: vec![],
            cpu_millis: 1000,
            memory_bytes: 1 << 30,
            timeout: Duration::from_secs(30),
        },
        tx,
    )
    .await
    .unwrap()
}

fn refused(r: &TaskReport, why: &str) {
    assert_eq!(r.status, TaskStatus::Rejected, "{r:?}");
    let e = r.error.clone().unwrap_or_default();
    assert!(e.contains(why), "{e}");
}

#[tokio::test]
async fn a_container_only_lender_grants_containers_and_refuses_sandbox_tasks() {
    let (laptop, desktop, outcome, _h) = ask(Modes::CONTAINER).await;
    let (g, modes) = granted(&outcome);
    assert_eq!(modes, Modes::CONTAINER, "asked for both, got what is lent");
    let r = run(&laptop, &desktop, g, None, None).await;
    refused(&r, "sandbox");
}

#[tokio::test]
async fn a_sandbox_lender_runs_tasks_without_an_image() {
    let (laptop, desktop, outcome, _h) = ask(Modes::only(ExecutionMode::Sandbox)).await;
    let (g, modes) = granted(&outcome);
    assert_eq!(modes, Modes::only(ExecutionMode::Sandbox));
    let r = run(&laptop, &desktop, g, None, None).await;
    assert_eq!(r.status, TaskStatus::Succeeded, "{r:?}");
    // An image asks for a container, which this grant does not allow.
    let r = run(&laptop, &desktop, g, Some("python:3.12-slim"), None).await;
    refused(&r, "container");
}

#[tokio::test]
async fn a_lender_that_lends_nothing_declines_without_asking() {
    let (_l, desktop, outcome, _h) = ask(Modes::NONE).await;
    match outcome {
        GrantOutcome::Declined(why) => assert!(why.contains("lends no way"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(
        desktop.incoming_requests().is_empty(),
        "the user was never bothered"
    );
}

#[tokio::test]
async fn withdrawing_a_mode_applies_to_grants_already_given() {
    let (laptop, desktop, outcome, _h) = ask(BOTH).await;
    let (g, modes) = granted(&outcome);
    assert_eq!(modes, BOTH);
    assert_eq!(
        run(&laptop, &desktop, g, None, None).await.status,
        TaskStatus::Succeeded
    );
    desktop.set_lend_modes(Modes::CONTAINER).unwrap();
    let r = run(&laptop, &desktop, g, None, None).await;
    refused(&r, "does not lend sandbox");
}

#[tokio::test]
async fn mode_and_image_must_agree() {
    let (laptop, desktop, outcome, _h) = ask(BOTH).await;
    let (g, _) = granted(&outcome);
    let r = run(&laptop, &desktop, g, None, Some(ExecutionMode::Container)).await;
    refused(&r, "need an image");
    let r = run(
        &laptop,
        &desktop,
        g,
        Some("img"),
        Some(ExecutionMode::Sandbox),
    )
    .await;
    refused(&r, "installed tools");
    let r = run(&laptop, &desktop, g, None, Some(ExecutionMode::Native)).await;
    assert_eq!(r.status, TaskStatus::Rejected, "{r:?}");
}
