//! Grants survive a daemon restart; revoked or tampered ones do not come back.
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

mod common;

use std::path::Path;
use std::time::Duration;

use common::{eventually, pair};
use gimmecores_core::{GrantId, GrantState};
use gimmecores_node::exec::{Executors, LogChunk};
use gimmecores_node::grants_flow::{Decision, GrantOutcome, standard_terms};
use gimmecores_node::node::{Node, NodeConfig};
use gimmecores_node::now;
use gimmecores_node::paths::Paths;
use gimmecores_node::presence::{FixedPresence, Outcome};
use gimmecores_node::tasks_flow::{TaskSpec, TaskStatus};
use tokio::sync::mpsc;

fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start(home: &Path, name: &str, port: u16) -> Node {
    Node::start(NodeConfig {
        paths: Paths::at(home),
        device_name: name.into(),
        bind: format!("127.0.0.1:{port}").parse().unwrap(),
        executors: Executors::test_processes(),
        presence: std::sync::Arc::new(FixedPresence(Outcome::Verified)),
    })
    .await
    .unwrap()
}

struct Pair {
    lender: Node,
    borrower: Node,
    lender_home: tempfile::TempDir,
    borrower_home: tempfile::TempDir,
    lender_port: u16,
    borrower_port: u16,
    grant: GrantId,
}

async fn granted() -> Pair {
    let lender_home = tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap();
    let borrower_home = tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap();
    let (lender_port, borrower_port) = (free_port(), free_port());
    let lender = start(lender_home.path(), "Desktop", lender_port).await;
    let borrower = start(borrower_home.path(), "Laptop", borrower_port).await;
    lender.set_lending(true).unwrap();
    lender
        .set_lend_modes(
            gimmecores_core::Modes::CONTAINER.with(gimmecores_core::ExecutionMode::Sandbox),
        )
        .unwrap();
    pair(&borrower, &lender).await;
    let ask = {
        let (b, k) = (borrower.clone(), lender.key());
        tokio::spawn(async move {
            b.request_grant(&k, &standard_terms(1, 1, 2, now()), "t")
                .await
        })
    };
    let req = eventually(|| lender.incoming_requests().into_iter().next()).await;
    lender
        .respond_to_request(req.id, Decision::Accept(None))
        .unwrap();
    let GrantOutcome::Granted { id, .. } = ask.await.unwrap().unwrap() else {
        panic!("not granted")
    };
    Pair {
        lender,
        borrower,
        lender_home,
        borrower_home,
        lender_port,
        borrower_port,
        grant: id,
    }
}

async fn run(b: &Node, l: &Node, g: GrantId) -> TaskStatus {
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
            image: None,
            mode: None,
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
    .map_or(TaskStatus::Rejected, |r| r.status)
}

async fn restart(n: Node, home: &Path, name: &str, port: u16) -> Node {
    n.shutdown().await;
    drop(n);
    tokio::time::sleep(Duration::from_millis(200)).await;
    start(home, name, port).await
}

fn lent_state(n: &Node, g: GrantId) -> Option<GrantState> {
    n.lent_grants().into_iter().find(|x| x.0 == g).map(|x| x.2)
}

#[tokio::test]
async fn grants_survive_a_restart_of_either_side() {
    let p = granted().await;
    assert_eq!(
        run(&p.borrower, &p.lender, p.grant).await,
        TaskStatus::Succeeded
    );

    let lender = restart(p.lender, p.lender_home.path(), "Desktop", p.lender_port).await;
    assert_eq!(lent_state(&lender, p.grant), Some(GrantState::Active));
    let borrower = restart(
        p.borrower,
        p.borrower_home.path(),
        "Laptop",
        p.borrower_port,
    )
    .await;
    assert!(
        borrower
            .borrowed_grants()
            .iter()
            .any(|(id, _)| *id == p.grant)
    );
    assert_eq!(
        run(&borrower, &lender, p.grant).await,
        TaskStatus::Succeeded
    );
    let log = std::fs::read_to_string(lender.paths().audit_log()).unwrap();
    assert!(log.contains("1 grant(s) restored"), "{log}");
}

#[tokio::test]
async fn a_revoked_grant_stays_revoked_after_a_restart() {
    let p = granted().await;
    p.lender.revoke_grant(p.grant).await.unwrap();
    let lender = restart(p.lender, p.lender_home.path(), "Desktop", p.lender_port).await;
    assert_eq!(lent_state(&lender, p.grant), None);
    assert_ne!(
        run(&p.borrower, &lender, p.grant).await,
        TaskStatus::Succeeded
    );
}

#[tokio::test]
async fn an_edited_grants_file_cannot_enlarge_a_grant() {
    let p = granted().await;
    let file = p.lender.paths().grants_file();
    let text = std::fs::read_to_string(&file).unwrap();
    // Flip one hex digit inside the signed grant.
    let at = text.find("\"signed\": \"").unwrap() + 40;
    let mut bytes = text.into_bytes();
    bytes[at] = if bytes[at] == b'0' { b'1' } else { b'0' };
    std::fs::write(&file, bytes).unwrap();
    let lender = restart(p.lender, p.lender_home.path(), "Desktop", p.lender_port).await;
    assert_eq!(
        lent_state(&lender, p.grant),
        None,
        "a changed grant is dropped"
    );
    let log = std::fs::read_to_string(lender.paths().audit_log()).unwrap();
    assert!(log.contains("1 dropped"), "{log}");
}

#[tokio::test]
async fn turning_lending_off_drops_saved_grants() {
    let p = granted().await;
    p.lender.set_lending(false).unwrap();
    let lender = restart(p.lender, p.lender_home.path(), "Desktop", p.lender_port).await;
    assert!(
        lender
            .lent_grants()
            .iter()
            .all(|g| g.2 != GrantState::Active)
    );
}
