//! Dependencies fetched by the borrower and used offline on the lender (#27).
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

mod common;

use std::time::Duration;

use common::{eventually, node, pair};
use gimmecores_node::deps::{Kind, prepare};
use gimmecores_node::exec::LogChunk;
use gimmecores_node::grants_flow::{Decision, GrantOutcome, standard_terms};
use gimmecores_node::now;
use gimmecores_node::tasks_flow::{TaskSpec, TaskStatus};
use tokio::sync::mpsc;

/// A crate with one crates.io dependency, built on the lender without network.
#[tokio::test]
async fn a_cargo_project_builds_on_the_lender_from_vendored_sources() {
    let p = tempfile::tempdir().unwrap();
    std::fs::create_dir(p.path().join("src")).unwrap();
    std::fs::write(
        p.path().join("Cargo.toml"),
        "[package]\nname = \"depcheck\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
         [dependencies]\nhex = \"=0.4.3\"\n\n[workspace]\n",
    )
    .unwrap();
    std::fs::write(
        p.path().join("src/main.rs"),
        "fn main() { println!(\"{}\", hex::encode([1u8, 2, 255])); }\n",
    )
    .unwrap();
    // From what this computer's Cargo already has (this workspace depends on hex 0.4.3).
    let lock = std::process::Command::new("cargo")
        .args(["generate-lockfile", "--offline", "-q"])
        .current_dir(p.path())
        .status();
    if !lock.is_ok_and(|s| s.success()) {
        eprintln!("skipping: hex 0.4.3 is not in this computer's Cargo cache");
        return;
    }
    let cache = tempfile::tempdir().unwrap();
    let deps = prepare(Kind::Cargo, p.path(), cache.path(), true).unwrap();
    assert!(cache.path().join("cargo").read_dir().unwrap().count() == 1);

    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    let req = {
        let (b, k) = (laptop.clone(), desktop.key());
        tokio::spawn(async move {
            b.request_grant(&k, &standard_terms(2, 2, 1, now()), "")
                .await
        })
    };
    let r = eventually(|| desktop.incoming_requests().into_iter().next()).await;
    desktop
        .respond_to_request(r.id, Decision::Accept(None))
        .unwrap();
    let GrantOutcome::Granted { id, .. } = req.await.unwrap().unwrap() else {
        panic!("not granted")
    };
    let (tx, mut rx) = mpsc::channel::<LogChunk>(64);
    let logs = tokio::spawn(async move {
        let mut s = String::new();
        while let Some(c) = rx.recv().await {
            s.push_str(&String::from_utf8_lossy(&c.data));
        }
        s
    });
    let report = laptop
        .run_task(
            &desktop.key(),
            id,
            TaskSpec {
                send_image: true,
                caches: vec![],
                dir: p.path().to_path_buf(),
                argv: vec!["cargo".into(), "run".into(), "-q".into()],
                image: None,
                mode: None,
                outputs: vec![],
                excludes: vec![],
                allow_secrets: vec![],
                extra_files: vec![],
                attachments: deps.attachments,
                output_dir: None,
                env: deps.env,
                cpu_millis: 2000,
                memory_bytes: 1 << 30,
                timeout: Duration::from_secs(240),
                speed: None,
            },
            tx,
        )
        .await
        .unwrap();
    let logs = logs.await.unwrap();
    assert_eq!(report.status, TaskStatus::Succeeded, "{logs}");
    assert_eq!(logs.trim(), "0102ff", "{logs}");
}

/// The same in a Rust container on a lender with Docker (skipped without Docker or the image).
#[tokio::test]
async fn a_cargo_project_builds_in_a_container_from_vendored_sources() {
    use gimmecores_core::{ExecutionMode, Modes};
    use gimmecores_node::exec::{DockerExecutor, Executors};
    use gimmecores_node::node::{Node, NodeConfig};
    use gimmecores_node::paths::Paths;
    use gimmecores_node::presence::{FixedPresence, Outcome};
    let docker = |args: &[&str]| {
        std::process::Command::new("docker")
            .args(args)
            .output()
            .is_ok_and(|o| o.status.success())
    };
    let image = "rust:1-bookworm";
    if !docker(&["info"]) || !docker(&["image", "inspect", image]) {
        eprintln!("skipping: Docker or {image} is not here");
        return;
    }
    let p = tempfile::tempdir().unwrap();
    std::fs::create_dir(p.path().join("src")).unwrap();
    std::fs::write(
        p.path().join("Cargo.toml"),
        "[package]\nname = \"depcheck\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
         [dependencies]\nhex = \"=0.4.3\"\n\n[workspace]\n",
    )
    .unwrap();
    std::fs::write(
        p.path().join("src/main.rs"),
        "fn main() { println!(\"{}\", hex::encode([1u8, 2, 255])); }\n",
    )
    .unwrap();
    let lock = std::process::Command::new("cargo")
        .args(["generate-lockfile", "--offline", "-q"])
        .current_dir(p.path())
        .status();
    if !lock.is_ok_and(|s| s.success()) {
        eprintln!("skipping: hex 0.4.3 is not in this computer's Cargo cache");
        return;
    }
    let cache = tempfile::tempdir().unwrap();
    let deps = prepare(Kind::Cargo, p.path(), cache.path(), true).unwrap();
    let home = tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap();
    let desktop = Node::start(NodeConfig {
        paths: Paths::at(home.path()),
        device_name: "Desktop".into(),
        bind: "127.0.0.1:0".parse().unwrap(),
        executors: Executors {
            container: Some(std::sync::Arc::new(DockerExecutor::default())),
            sandbox: None,
            images: Some(std::sync::Arc::new(
                gimmecores_node::images::DockerImages::default(),
            )),
        },
        presence: std::sync::Arc::new(FixedPresence(Outcome::Verified)),
    })
    .await
    .unwrap();
    desktop.set_lending(true).unwrap();
    desktop
        .set_protections(gimmecores_node::power::Protections {
            pause_on_battery: false,
            idle_only: false,
            pause_when_hot: false,
        })
        .unwrap();
    assert_eq!(
        desktop.lend_modes().1,
        Modes::only(ExecutionMode::Container)
    );
    let (laptop, _h) = common::fresh_node("Laptop").await;
    pair(&laptop, &desktop).await;
    let req = {
        let (b, k) = (laptop.clone(), desktop.key());
        tokio::spawn(async move {
            b.request_grant(&k, &standard_terms(2, 2, 1, now()), "")
                .await
        })
    };
    let r = eventually(|| desktop.incoming_requests().into_iter().next()).await;
    desktop
        .respond_to_request(r.id, Decision::Accept(None))
        .unwrap();
    let GrantOutcome::Granted { id, .. } = req.await.unwrap().unwrap() else {
        panic!("not granted")
    };
    let (tx, mut rx) = mpsc::channel::<LogChunk>(64);
    let logs = tokio::spawn(async move {
        let mut s = String::new();
        while let Some(c) = rx.recv().await {
            s.push_str(&String::from_utf8_lossy(&c.data));
        }
        s
    });
    let report = laptop
        .run_task(
            &desktop.key(),
            id,
            TaskSpec {
                send_image: false,
                caches: vec![],
                dir: p.path().to_path_buf(),
                argv: vec!["cargo".into(), "run".into(), "-q".into()],
                image: Some(image.into()),
                mode: None,
                outputs: vec![],
                excludes: vec![],
                allow_secrets: vec![],
                extra_files: vec![],
                attachments: deps.attachments,
                output_dir: None,
                env: deps.env,
                cpu_millis: 2000,
                memory_bytes: 2 << 30,
                timeout: Duration::from_secs(600),
                speed: None,
            },
            tx,
        )
        .await
        .unwrap();
    let logs = logs.await.unwrap();
    assert_eq!(report.status, TaskStatus::Succeeded, "{logs}");
    assert_eq!(logs.trim(), "0102ff", "{logs}");
}

/// npm: the cache made here is what `npm ci` uses there, offline (skipped without npm).
#[tokio::test]
async fn npm_ci_runs_there_from_the_cache_made_here() {
    if !std::process::Command::new("npm")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        eprintln!("skipping: npm is not here");
        return;
    }
    let p = tempfile::tempdir().unwrap();
    std::fs::write(
        p.path().join("package.json"),
        r#"{"name":"depcheck","version":"1.0.0","private":true}"#,
    )
    .unwrap();
    std::fs::write(
        p.path().join("package-lock.json"),
        r#"{"name":"depcheck","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"depcheck","version":"1.0.0"}}}"#,
    )
    .unwrap();
    let cache = tempfile::tempdir().unwrap();
    let deps = prepare(Kind::Npm, p.path(), cache.path(), true).unwrap();
    assert!(
        deps.env
            .iter()
            .any(|(k, v)| k == "npm_config_offline" && v == "true")
    );
    // The project's own folder was not touched.
    assert!(!p.path().join("node_modules").exists());

    let (laptop, _h1) = node("Laptop").await;
    let (desktop, _h2) = node("Desktop").await;
    pair(&laptop, &desktop).await;
    let req = {
        let (b, k) = (laptop.clone(), desktop.key());
        tokio::spawn(async move {
            b.request_grant(&k, &standard_terms(1, 1, 1, now()), "")
                .await
        })
    };
    let r = eventually(|| desktop.incoming_requests().into_iter().next()).await;
    desktop
        .respond_to_request(r.id, Decision::Accept(None))
        .unwrap();
    let GrantOutcome::Granted { id, .. } = req.await.unwrap().unwrap() else {
        panic!("not granted")
    };
    let (tx, mut rx) = mpsc::channel::<LogChunk>(64);
    let logs = tokio::spawn(async move {
        let mut s = String::new();
        while let Some(c) = rx.recv().await {
            s.push_str(&String::from_utf8_lossy(&c.data));
        }
        s
    });
    let report = laptop
        .run_task(
            &desktop.key(),
            id,
            TaskSpec {
                send_image: true,
                caches: vec![],
                dir: p.path().to_path_buf(),
                argv: vec![
                    "sh".into(),
                    "-c".into(),
                    "npm ci && npm config get offline".into(),
                ],
                image: None,
                mode: None,
                outputs: vec![],
                excludes: vec![],
                allow_secrets: vec![],
                extra_files: vec![],
                attachments: deps.attachments,
                output_dir: None,
                env: deps.env,
                cpu_millis: 1000,
                memory_bytes: 1 << 30,
                timeout: Duration::from_secs(120),
                speed: None,
            },
            tx,
        )
        .await
        .unwrap();
    let logs = logs.await.unwrap();
    assert_eq!(report.status, TaskStatus::Succeeded, "{logs}");
    assert!(logs.trim_end().ends_with("true"), "{logs}");
}
