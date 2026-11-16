//! A borrower's packages kept between tasks on a macOS lender (real Seatbelt sandbox): unpacked
//! once, readable by that borrower's tasks, never changeable by them, invisible to others, and
//! gone with the borrower's grant.
#![allow(clippy::unwrap_used)]
#![cfg(target_os = "macos")]

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::{eventually, pair};
use gimmecores_core::{ExecutionMode, GrantId, Modes};
use gimmecores_node::exec::{Executors, LogChunk};
use gimmecores_node::grants_flow::{Decision, GrantOutcome, standard_terms};
use gimmecores_node::node::{Node, NodeConfig};
use gimmecores_node::now;
use gimmecores_node::paths::Paths;
use gimmecores_node::presence::{FixedPresence, Outcome};
use gimmecores_node::sandbox::SandboxExecutor;
use gimmecores_node::tasks_flow::{TaskSpec, TaskStatus};
use gimmecores_node::tree::Attachment;
use tokio::sync::mpsc;

async fn start(name: &str, sandboxed: bool) -> (Node, tempfile::TempDir) {
    let home = tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap();
    let executors = if sandboxed {
        Executors {
            container: None,
            sandbox: Some(Arc::new(SandboxExecutor::default())),
            images: None,
        }
    } else {
        Executors::default()
    };
    let node = Node::start(NodeConfig {
        paths: Paths::at(home.path()),
        device_name: name.into(),
        bind: "127.0.0.1:0".parse().unwrap(),
        executors,
        presence: Arc::new(FixedPresence(Outcome::Verified)),
    })
    .await
    .unwrap();
    (node, home)
}

async fn grant(borrower: &Node, lender: &Node) -> GrantId {
    pair(borrower, lender).await;
    let ask = {
        let (b, k) = (borrower.clone(), lender.key());
        tokio::spawn(async move {
            b.request_grant(&k, &standard_terms(1, 1, 1, now()), "t")
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
    id
}

/// Runs `script` with `sh -c` on the lender; returns (status, stdout + stderr).
async fn run(
    b: &Node,
    l: &Node,
    g: GrantId,
    script: &str,
    packages: Option<&Path>,
) -> (TaskStatus, String) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("main.txt"), "x").unwrap();
    let (tx, mut rx) = mpsc::channel::<LogChunk>(64);
    let out = tokio::spawn(async move {
        let mut s = Vec::new();
        while let Some(c) = rx.recv().await {
            s.extend(c.data);
        }
        String::from_utf8_lossy(&s).into_owned()
    });
    let report = b
        .run_task(
            &l.key(),
            g,
            TaskSpec {
                send_image: true,
                caches: vec![],
                dir: dir.path().to_path_buf(),
                argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
                image: None,
                mode: Some(ExecutionMode::Sandbox),
                outputs: vec![],
                excludes: vec![],
                allow_secrets: vec![],
                extra_files: vec![],
                attachments: packages
                    .map(|p| Attachment {
                        local: p.to_path_buf(),
                        path: ".gmc-sdk/env".into(),
                        packages: true,
                    })
                    .into_iter()
                    .collect(),
                output_dir: None,
                env: vec![],
                cpu_millis: 1000,
                memory_bytes: 1 << 30,
                timeout: Duration::from_secs(60),
                speed: None,
            },
            tx,
        )
        .await;
    let text = out.await.unwrap();
    match report {
        Ok(r) => (r.status, text),
        Err(e) => (TaskStatus::Rejected, format!("{text}\n{e:#}")),
    }
}

fn packages() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("pkg")).unwrap();
    std::fs::write(d.path().join("pkg/f.py"), "original\n").unwrap();
    d
}

const ATTACK: &str = r#"
real=$(cd .gmc-sdk/env && pwd -P)
echo "REAL=$real"
echo x >> .gmc-sdk/env/pkg/f.py && echo "BROKE: write"
echo x >> "$real/pkg/f.py" && echo "BROKE: write by real path"
: > "$real/pkg/f.py" && echo "BROKE: truncate"
chmod 644 "$real/pkg/f.py" && echo "BROKE: chmod"
rm -f "$real/pkg/f.py" && [ ! -e "$real/pkg/f.py" ] && echo "BROKE: unlink"
mv "$real/pkg" "$real/pkg2" && echo "BROKE: rename folder"
mv "$real" "$real.x" && echo "BROKE: rename kept folder"
mv "$(dirname "$real")" "$(dirname "$real").x" && echo "BROKE: rename parent"
ln "$real/pkg/f.py" hardlink && echo x >> hardlink && echo "BROKE: hard link"
mkdir "$real/new" && echo "BROKE: create"
ls "$(dirname "$real")" && echo "BROKE: listed other kept folders"
# Replacing the link affects only this task's own folder.
rm .gmc-sdk/env && mkdir -p .gmc-sdk/env/pkg && echo evil > .gmc-sdk/env/pkg/f.py && echo "own folder ok"
exit 0
"#;

#[tokio::test]
async fn kept_packages_cannot_be_changed_or_read_by_others_and_go_with_the_grant() {
    let (lender, _h1) = start("Desktop", true).await;
    let (borrower, _h2) = start("Laptop", false).await;
    let (other, _h3) = start("Other", false).await;
    lender.set_lending(true).unwrap();
    lender
        .set_protections(gimmecores_node::power::Protections {
            pause_on_battery: false,
            idle_only: false,
            pause_when_hot: false,
        })
        .unwrap();
    lender
        .set_lend_modes(Modes::NONE.with(ExecutionMode::Sandbox))
        .unwrap();
    if !lender.lend_modes().1.contains(ExecutionMode::Sandbox) {
        eprintln!("no working sandbox here; skipping");
        return;
    }
    let g = grant(&borrower, &lender).await;
    let pkgs = packages();

    // 1. A task attacks its kept packages.
    let (status, out) = run(&borrower, &lender, g, ATTACK, Some(pkgs.path())).await;
    assert_eq!(status, TaskStatus::Succeeded, "{out}");
    assert!(!out.contains("BROKE"), "{out}");
    assert!(out.contains("own folder ok"), "{out}");
    let real = PathBuf::from(
        out.lines()
            .find_map(|l| l.strip_prefix("REAL="))
            .expect("the task saw its packages"),
    );
    assert!(
        real.starts_with(std::fs::canonicalize(lender.paths().blobs_dir()).unwrap()),
        "kept inside the borrower's namespace: {}",
        real.display()
    );
    assert_eq!(
        std::fs::read_to_string(real.join("pkg/f.py")).unwrap(),
        "original\n"
    );

    // 2. The next task gets the same, unchanged copy (no second unpack).
    let (status, out) = run(
        &borrower,
        &lender,
        g,
        "cat .gmc-sdk/env/pkg/f.py; cd .gmc-sdk/env && pwd -P",
        Some(pkgs.path()),
    )
    .await;
    assert_eq!(status, TaskStatus::Succeeded, "{out}");
    assert!(out.starts_with("original\n"), "{out}");
    assert!(out.contains(real.to_str().unwrap()), "{out}");

    // 3. Another borrower's task cannot read it.
    let g2 = grant(&other, &lender).await;
    let script = format!(
        "cat {0}/pkg/f.py && echo BROKE; ls {0} && echo BROKE; exit 0",
        real.display()
    );
    let (status, out) = run(&other, &lender, g2, &script, None).await;
    assert_eq!(status, TaskStatus::Succeeded, "{out}");
    assert!(!out.contains("original") && !out.contains("BROKE"), "{out}");

    // 4. Gone with the grant.
    lender.revoke_grant(g).await.unwrap();
    eventually(|| (!real.exists()).then_some(())).await;
    let log = std::fs::read_to_string(lender.paths().audit_log()).unwrap();
    assert!(log.contains("of packages for"), "{log}");
}
