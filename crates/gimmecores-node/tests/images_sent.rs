//! A borrower sends its own container image to the lender (docs/design/container-images.md),
//! against real Docker. Skipped where Docker is not running, unless `GMC_REQUIRE_DOCKER=1`.
//! Both devices use this machine's one Docker, as two GimmeCores services would on one
//! computer; the lender still loads the image under its own name. With one Docker the lender
//! already has the borrower's layers, so whether an archive may leave layers out is tested
//! between two Dockers by `scripts/linux/e2e-images.sh`.
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

use std::path::Path;
use std::process::Command as StdCommand;
use std::sync::Arc;
use std::time::Duration;

use gimmecores_core::{GrantId, Modes};
use gimmecores_node::exec::{DockerExecutor, Executors, LogChunk};
use gimmecores_node::grants_flow::{Decision, GrantOutcome, standard_terms};
use gimmecores_node::node::{Node, NodeConfig};
use gimmecores_node::paths::Paths;
use gimmecores_node::presence::{FixedPresence, Outcome};
use gimmecores_node::tasks_flow::{TaskReport, TaskSpec};
use tokio::sync::mpsc;

mod common;

fn base_image() -> Option<String> {
    let required = std::env::var("GMC_REQUIRE_DOCKER").as_deref() == Ok("1");
    let up = StdCommand::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !up {
        assert!(!required, "Docker is required here but not running");
        eprintln!("skipping: Docker is not running");
        return None;
    }
    let found = [
        "alpine:3.20",
        "alpine:latest",
        "busybox:latest",
        "golang:1.27-alpine",
    ]
    .into_iter()
    .find(|i| {
        StdCommand::new("docker")
            .args(["image", "inspect", i])
            .output()
            .is_ok_and(|o| o.status.success())
    });
    assert!(found.is_some() || !required, "no test image present");
    found.map(String::from)
}

fn unique() -> String {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    format!(
        "{}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    )
}

fn docker(args: &[&str]) -> String {
    let o = StdCommand::new("docker").args(args).output().unwrap();
    assert!(
        o.status.success(),
        "docker {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

fn exists(reference: &str) -> bool {
    StdCommand::new("docker")
        .args(["image", "inspect", reference])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// A test image, removed when dropped.
struct Img(String);

impl Drop for Img {
    fn drop(&mut self) {
        let _ = StdCommand::new("docker")
            .args(["image", "rm", "-f", &self.0])
            .output();
    }
}

/// `base` plus one layer holding `/app/v` = `version`.
fn layered(base: &str, version: &str) -> Img {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("app")).unwrap();
    std::fs::write(dir.path().join("app/v"), format!("{version}\n")).unwrap();
    let c = format!("gmc-test-img-{}", unique());
    let tag = format!("gmc-test-sent:{}", unique());
    docker(&["create", "--name", &c, base, "true"]);
    docker(&[
        "cp",
        &format!("{}/.", dir.path().display()),
        &format!("{c}:/"),
    ]);
    docker(&["commit", &c, &tag]);
    docker(&["rm", "-f", &c]);
    Img(tag)
}

fn id_of(r: &str) -> String {
    docker(&["image", "inspect", "--format", "{{.Id}}", r])
}

async fn lender() -> (Node, tempfile::TempDir) {
    let home = tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap();
    let node = Node::start(NodeConfig {
        paths: Paths::at(home.path()),
        device_name: "Desktop".into(),
        bind: "127.0.0.1:0".parse().unwrap(),
        executors: Executors {
            container: Some(Arc::new(DockerExecutor::default())),
            sandbox: None,
            images: Some(Arc::new(gimmecores_node::images::DockerImages::default())),
        },
        presence: Arc::new(FixedPresence(Outcome::Verified)),
    })
    .await
    .unwrap();
    node.set_lending(true).unwrap();
    (node, home)
}

async fn grant(borrower: &Node, lender: &Node, images_bytes: u64) -> GrantId {
    // Four tasks of one core at once.
    let mut terms = standard_terms(4, 1, 1, gimmecores_node::now());
    terms.modes = Modes::CONTAINER;
    terms.images_bytes = images_bytes;
    let ask = {
        let (b, k) = (borrower.clone(), lender.key());
        tokio::spawn(async move { b.request_grant(&k, &terms, "images").await })
    };
    let req = common::eventually(|| lender.incoming_requests().into_iter().next()).await;
    lender
        .respond_to_request(req.id, Decision::Accept(None))
        .unwrap();
    let GrantOutcome::Granted { id, terms } = ask.await.unwrap().unwrap() else {
        panic!("not granted");
    };
    assert_eq!(terms.images_bytes, images_bytes);
    id
}

async fn run(
    borrower: &Node,
    lender: &Node,
    grant: GrantId,
    image: &str,
    project: &Path,
) -> anyhow::Result<(TaskReport, String)> {
    let (tx, mut rx) = mpsc::channel::<LogChunk>(64);
    let logs = tokio::spawn(async move {
        let mut s = String::new();
        while let Some(c) = rx.recv().await {
            s.push_str(&String::from_utf8_lossy(&c.data));
        }
        s
    });
    let report = borrower
        .run_task(
            &lender.key(),
            grant,
            TaskSpec {
                send_image: true,
                caches: vec![],
                dir: project.to_path_buf(),
                argv: vec!["/bin/sh".into(), "-c".into(), "cat /app/v".into()],
                image: Some(image.into()),
                mode: None,
                outputs: vec![],
                excludes: vec![],
                allow_secrets: vec![],
                extra_files: vec![],
                attachments: vec![],
                output_dir: None,
                env: vec![],
                cpu_millis: 1000,
                memory_bytes: 256 << 20,
                timeout: Duration::from_secs(120),
                speed: None,
            },
            tx,
        )
        .await;
    let logs = logs.await.unwrap();
    report.map(|r| (r, logs))
}

/// The tags `lender` gave images it loaded for `borrower`.
fn lender_tags(lender: &Node, borrower: &Node) -> Vec<String> {
    let prefix = format!(
        "{}{}:",
        gimmecores_node::images::sent_prefix(&lender.key()),
        borrower.key().to_hex()
    );
    let mut v: Vec<String> = docker(&["images", "--format", "{{.Repository}}:{{.Tag}}"])
        .lines()
        .filter(|l| l.starts_with(&prefix))
        .map(String::from)
        .collect();
    v.sort();
    v
}

/// The size of `image`'s layers, uncompressed.
fn layers_size(image: &str) -> u64 {
    use std::io::Read;
    let dir = tempfile::tempdir().unwrap();
    let saved = dir.path().join("s.tar");
    docker(&["save", "-o", &saved.display().to_string(), image]);
    let names: Vec<String> = {
        let mut ar = tar::Archive::new(std::fs::File::open(&saved).unwrap());
        let mut m = String::new();
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            if e.path().unwrap().to_string_lossy() == "manifest.json" {
                e.read_to_string(&mut m).unwrap();
            }
        }
        let v: serde_json::Value = serde_json::from_str(&m).unwrap();
        v[0]["Layers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap().to_string())
            .collect()
    };
    let mut ar = tar::Archive::new(std::fs::File::open(&saved).unwrap());
    let mut total = 0u64;
    for e in ar.entries().unwrap() {
        let mut e = e.unwrap();
        if !names.contains(&e.path().unwrap().to_string_lossy().into_owned()) {
            continue;
        }
        let mut raw = Vec::new();
        e.read_to_end(&mut raw).unwrap();
        total += if raw.starts_with(&[0x1f, 0x8b]) {
            std::io::copy(
                &mut flate2::read::GzDecoder::new(raw.as_slice()),
                &mut std::io::sink(),
            )
            .unwrap()
        } else {
            raw.len() as u64
        };
    }
    total
}

/// `n` bytes no other image has.
fn noise(n: usize, seed: &str) -> String {
    use sha2::Digest;
    let mut out = String::with_capacity(n * 2);
    let mut h = sha2::Sha256::digest(seed.as_bytes());
    while out.len() < n {
        out.push_str(&hex::encode(h));
        h = sha2::Sha256::digest(h);
    }
    out.truncate(n);
    out
}

/// `base` plus `extra` layers: `""` is an empty layer (always the same one, as older builders
/// made), anything else a layer with `/app/v` = it. Made with `docker load`: `docker commit`
/// adds no layer when nothing changed.
fn crafted(base: &str, extra: &[&str]) -> Img {
    use sha2::Digest;
    use std::io::Read;
    let dir = tempfile::tempdir().unwrap();
    let saved = dir.path().join("base.tar");
    docker(&["save", "-o", &saved.display().to_string(), base]);
    let read = |want: &str| -> Vec<u8> {
        let mut ar = tar::Archive::new(std::fs::File::open(&saved).unwrap());
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            if e.path().unwrap().to_string_lossy() == want {
                let mut v = Vec::new();
                e.read_to_end(&mut v).unwrap();
                return v;
            }
        }
        panic!("{want} not in docker save's archive")
    };
    let manifest: serde_json::Value = serde_json::from_slice(&read("manifest.json")).unwrap();
    let mut config: serde_json::Value =
        serde_json::from_slice(&read(manifest[0]["Config"].as_str().unwrap())).unwrap();
    let mut layers: Vec<Vec<u8>> = manifest[0]["Layers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let raw = read(p.as_str().unwrap());
            if raw.starts_with(&[0x1f, 0x8b]) {
                let mut v = Vec::new();
                flate2::read::GzDecoder::new(raw.as_slice())
                    .read_to_end(&mut v)
                    .unwrap();
                v
            } else {
                raw
            }
        })
        .collect();
    for version in extra {
        layers.push(if version.is_empty() {
            vec![0u8; 1024]
        } else {
            let mut b = tar::Builder::new(Vec::new());
            let data = format!("{version}\n");
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(0);
            h.set_cksum();
            b.append_data(&mut h, "app/v", data.as_bytes()).unwrap();
            b.into_inner().unwrap()
        });
    }
    let sha = |d: &[u8]| format!("sha256:{}", hex::encode(sha2::Sha256::digest(d)));
    let diff_ids: Vec<String> = layers.iter().map(|l| sha(l)).collect();
    config["rootfs"]["diff_ids"] = serde_json::json!(diff_ids);
    config.as_object_mut().unwrap().remove("history");
    let config = serde_json::to_vec(&config).unwrap();
    let tag = format!("gmc-test-sent:{}", unique());
    let mut out = tar::Builder::new(Vec::new());
    let mut add = |name: &str, data: &[u8]| {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(0);
        h.set_cksum();
        out.append_data(&mut h, name, data).unwrap();
    };
    let names: Vec<String> = diff_ids
        .iter()
        .map(|d| format!("{}.tar", &d[7..]))
        .collect();
    add(
        "manifest.json",
        &serde_json::to_vec(&serde_json::json!([{
            "Config": "config.json", "RepoTags": [tag], "Layers": names,
        }]))
        .unwrap(),
    );
    add("config.json", &config);
    let mut seen = std::collections::BTreeSet::new();
    for (n, l) in names.iter().zip(&layers) {
        if seen.insert(n.clone()) {
            add(n, l);
        }
    }
    let archive = dir.path().join("repeated.tar");
    std::fs::write(&archive, out.into_inner().unwrap()).unwrap();
    docker(&["load", "-i", &archive.display().to_string()]);
    let got: Vec<String> = serde_json::from_str(&docker(&[
        "image",
        "inspect",
        "--format",
        "{{json .RootFS.Layers}}",
        &tag,
    ]))
    .unwrap();
    assert_eq!(got, diff_ids);
    Img(tag)
}

#[tokio::test]
async fn a_borrower_sends_its_image_and_a_rebuild_sends_only_the_new_layer() {
    let Some(base) = base_image() else { return };
    let v1 = layered(&base, "one");
    let v2 = layered(&v1.0, "two");
    let (lender, _lh) = lender().await;
    let (borrower, _bh) = common::fresh_node("Laptop").await;
    common::pair(&borrower, &lender).await;
    let g = grant(&borrower, &lender, 2 << 30).await;
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("in.txt"), "x").unwrap();

    // First: the whole image travels (the lender has nothing of this borrower's yet).
    let (r, logs) = run(&borrower, &lender, g, &v1.0, project.path())
        .await
        .unwrap();
    assert!(logs.contains("one"), "{r:?} {logs}");
    let tags = lender_tags(&lender, &borrower);
    assert_eq!(
        tags.len(),
        1,
        "loaded under the lender's own name: {tags:?}"
    );
    let first = r.uploaded_bytes;
    assert!(first > 1 << 20, "the base layers were sent: {first}");

    // A rebuild: only its new top layer (and the config) travels.
    let (r, logs) = run(&borrower, &lender, g, &v2.0, project.path())
        .await
        .unwrap();
    assert!(logs.contains("two"), "{r:?} {logs}");
    assert!(
        r.uploaded_bytes < 256 << 10,
        "more than the new layer was sent: {} (first run {first})",
        r.uploaded_bytes
    );
    assert_eq!(lender_tags(&lender, &borrower).len(), 2);

    // Again: nothing of the image travels.
    let (r, logs) = run(&borrower, &lender, g, &v2.0, project.path())
        .await
        .unwrap();
    assert!(logs.contains("two"), "{logs}");
    assert!(r.uploaded_bytes < 16 << 10, "{}", r.uploaded_bytes);

    // The grant ends: the lender's names go, the borrower's own images stay.
    lender.revoke_grant(g).await.unwrap();
    common::eventually(|| lender_tags(&lender, &borrower).is_empty().then_some(())).await;
    assert!(
        exists(&v1.0) && exists(&v2.0),
        "the borrower's own images were touched"
    );
}

#[tokio::test]
async fn an_image_listing_a_layer_twice_is_sent_whole() {
    let Some(base) = base_image() else { return };
    // The lender gets the base and an empty layer with the first; the second lists that
    // empty layer again above its app layer, so it is sent although it is also beneath.
    let v1 = crafted(&base, &["", "plain"]);
    let twice = crafted(&base, &["", "twice", ""]);
    let (lender, _lh) = lender().await;
    let (borrower, _bh) = common::fresh_node("Laptop").await;
    common::pair(&borrower, &lender).await;
    let g = grant(&borrower, &lender, 2 << 30).await;
    let project = tempfile::tempdir().unwrap();
    run(&borrower, &lender, g, &v1.0, project.path())
        .await
        .unwrap();
    // Sent on top of the base and empty layer (from v1), then fresh to a borrower with nothing.
    let (r, logs) = run(&borrower, &lender, g, &twice.0, project.path())
        .await
        .unwrap();
    assert!(logs.contains("twice"), "{r:?} {logs}");
    let (other, _oh) = common::fresh_node("Other").await;
    common::pair(&other, &lender).await;
    let go = grant(&other, &lender, 2 << 30).await;
    let (r, logs) = run(&other, &lender, go, &twice.0, project.path())
        .await
        .unwrap();
    assert!(logs.contains("twice"), "{r:?} {logs}");
    lender.revoke_grant(g).await.unwrap();
    lender.revoke_grant(go).await.unwrap();
    common::eventually(|| {
        (lender_tags(&lender, &borrower).is_empty() && lender_tags(&lender, &other).is_empty())
            .then_some(())
    })
    .await;
}

#[tokio::test]
async fn tasks_sending_the_same_image_at_once_all_run() {
    let Some(base) = base_image() else { return };
    let v1 = layered(&base, "together");
    let (lender, _lh) = lender().await;
    let (borrower, _bh) = common::fresh_node("Laptop").await;
    common::pair(&borrower, &lender).await;
    let g = grant(&borrower, &lender, 2 << 30).await;
    let project = tempfile::tempdir().unwrap();
    let mut runs = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let (b, l, img, dir) = (
            borrower.clone(),
            lender.clone(),
            v1.0.clone(),
            project.path().to_path_buf(),
        );
        runs.spawn(async move { run(&b, &l, g, &img, &dir).await });
    }
    let mut uploaded = Vec::new();
    while let Some(r) = runs.join_next().await {
        let (r, logs) = r.unwrap().unwrap();
        assert!(logs.contains("together"), "{r:?} {logs}");
        uploaded.push(r.uploaded_bytes);
    }
    // The image went once; the others found it there.
    uploaded.sort_unstable();
    assert!(uploaded[..3].iter().all(|b| *b < 16 << 10), "{uploaded:?}");
    assert_eq!(lender_tags(&lender, &borrower).len(), 1);
    lender.revoke_grant(g).await.unwrap();
    common::eventually(|| lender_tags(&lender, &borrower).is_empty().then_some(())).await;
}

#[tokio::test]
async fn a_borrowers_images_stay_within_its_allowance() {
    let Some(base) = base_image() else { return };
    // The base's layers as they travel (uncompressed): Docker's own `.Size` differs between its
    // image stores.
    let size = layers_size(&base);
    // Room for the base and one 6 MB layer, not two.
    let x = layered(&base, &noise(6 << 20, "x"));
    let y = layered(&base, &noise(6 << 20, "y"));
    let (lender, _lh) = lender().await;
    let (borrower, _bh) = common::fresh_node("Laptop").await;
    common::pair(&borrower, &lender).await;
    let g = grant(&borrower, &lender, size + (9 << 20)).await;
    let project = tempfile::tempdir().unwrap();
    run(&borrower, &lender, g, &x.0, project.path())
        .await
        .unwrap();
    let after_x = lender_tags(&lender, &borrower);
    assert_eq!(after_x.len(), 1);
    // y replaces x (least recently used, shares only the base).
    let (r, _) = run(&borrower, &lender, g, &y.0, project.path())
        .await
        .unwrap();
    assert!(r.error.is_none(), "{r:?}");
    let after_y = lender_tags(&lender, &borrower);
    assert_eq!(after_y.len(), 1, "{after_y:?}");
    assert_ne!(after_y, after_x, "x was not removed for y");
    // An image larger than the whole allowance is refused: before it is sent where the
    // borrower's Docker can estimate its size (the classic store), else before it is loaded.
    let (small, _sh) = common::fresh_node("Small").await;
    common::pair(&small, &lender).await;
    let gs = grant(&small, &lender, 1 << 20).await;
    let msg = match run(&small, &lender, gs, &x.0, project.path()).await {
        Err(e) => format!("{e:#}"),
        Ok((r, _)) => r.error.unwrap_or_default(),
    };
    assert!(
        msg.contains("larger than this grant lets you send"),
        "{msg}"
    );
    assert!(lender_tags(&lender, &small).is_empty());
    lender.revoke_grant(g).await.unwrap();
    lender.revoke_grant(gs).await.unwrap();
    common::eventually(|| lender_tags(&lender, &borrower).is_empty().then_some(())).await;
}

#[tokio::test]
async fn images_of_a_grant_gone_while_the_lender_was_stopped_are_removed() {
    let Some(base) = base_image() else { return };
    let v1 = layered(&base, "restart");
    let (lender, lh) = lender().await;
    let (borrower, _bh) = common::fresh_node("Laptop").await;
    common::pair(&borrower, &lender).await;
    let g = grant(&borrower, &lender, 2 << 30).await;
    let project = tempfile::tempdir().unwrap();
    run(&borrower, &lender, g, &v1.0, project.path())
        .await
        .unwrap();
    assert_eq!(lender_tags(&lender, &borrower).len(), 1);
    let me = lender.key();
    // A tag of this lender's with no record at all (its `images.json` lost, say), for a device
    // that holds no grant here.
    let orphan = format!(
        "{}{}:{}",
        gimmecores_node::images::sent_prefix(&me),
        "ab".repeat(32),
        "cd".repeat(32)
    );
    docker(&["tag", &v1.0, &orphan]);
    lender.shutdown().await;
    drop(lender);
    // The grant is gone when it starts again (as if it expired meanwhile).
    std::fs::remove_file(Paths::at(lh.path()).grants_file()).unwrap();
    let again = Node::start(NodeConfig {
        paths: Paths::at(lh.path()),
        device_name: "Desktop".into(),
        bind: "127.0.0.1:0".parse().unwrap(),
        executors: Executors {
            container: Some(Arc::new(DockerExecutor::default())),
            sandbox: None,
            images: Some(Arc::new(gimmecores_node::images::DockerImages::default())),
        },
        presence: Arc::new(FixedPresence(Outcome::Verified)),
    })
    .await
    .unwrap();
    common::eventually(|| {
        (lender_tags(&again, &borrower).is_empty() && !exists(&orphan)).then_some(())
    })
    .await;
    assert_eq!(again.key(), me);
    assert!(exists(&v1.0), "only the lender's own tags go");
    again.shutdown().await;
}

#[tokio::test]
async fn another_borrower_cannot_run_a_sent_image() {
    let Some(base) = base_image() else { return };
    let v1 = layered(&base, "mine");
    let (lender, _lh) = lender().await;
    let (alice, _ah) = common::fresh_node("Alice").await;
    let (bob, _bh) = common::fresh_node("Bob").await;
    common::pair(&alice, &lender).await;
    common::pair(&bob, &lender).await;
    let ga = grant(&alice, &lender, 1 << 30).await;
    let gb = grant(&bob, &lender, 0).await;
    let project = tempfile::tempdir().unwrap();
    run(&alice, &lender, ga, &v1.0, project.path())
        .await
        .unwrap();
    let tags = lender_tags(&lender, &alice);
    assert_eq!(tags.len(), 1);
    let tag = tags[0].clone();
    let id = id_of(&tag);
    // Bob names Alice's image as the lender knows it: by tag, by id, by short id.
    for name in [tag.clone(), id.clone(), id[7..19].to_string()] {
        let (r, logs) = run(&bob, &lender, gb, &name, project.path()).await.unwrap();
        let err = r.error.clone().unwrap_or_default();
        assert!(err.contains("is not on the lender"), "{name}: {r:?} {logs}");
        assert!(!logs.contains("mine"), "{name}: {logs}");
    }
    lender.revoke_grant(ga).await.unwrap();
    common::eventually(|| lender_tags(&lender, &alice).is_empty().then_some(())).await;
}

#[tokio::test]
async fn an_image_for_another_processor_is_refused_before_it_is_sent() {
    if base_image().is_none() {
        return;
    }
    // An image built for the processor this machine is not.
    let here = docker(&["info", "--format", "{{.Architecture}}"]);
    let other = if here.contains("aarch64") || here.contains("arm64") {
        "amd64"
    } else {
        "arm64"
    };
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("f"), "x").unwrap();
    let tar = dir.path().join("root.tar");
    assert!(
        StdCommand::new("tar")
            .args(["-C", &dir.path().display().to_string(), "-cf"])
            .arg(&tar)
            .arg("f")
            .status()
            .unwrap()
            .success()
    );
    let foreign = Img(format!("gmc-test-foreign:{}", unique()));
    docker(&[
        "import",
        "--platform",
        &format!("linux/{other}"),
        &tar.display().to_string(),
        &foreign.0,
    ]);
    // Older Dockers (20.10) ignore `--platform` here: nothing foreign to test with.
    if docker(&[
        "image",
        "inspect",
        "--format",
        "{{.Architecture}}",
        &foreign.0,
    ]) != other
    {
        eprintln!("skipping: this Docker cannot make a linux/{other} image");
        return;
    }
    let (lender, _lh) = lender().await;
    let (borrower, _bh) = common::fresh_node("Laptop").await;
    common::pair(&borrower, &lender).await;
    let g = grant(&borrower, &lender, 1 << 30).await;
    let project = tempfile::tempdir().unwrap();
    let err = run(&borrower, &lender, g, &foreign.0, project.path())
        .await
        .expect_err("refused");
    let msg = format!("{err:#}");
    assert!(
        msg.contains(&format!("the image is for linux/{other}")) && msg.contains("--platform"),
        "{msg}"
    );
    assert!(lender_tags(&lender, &borrower).is_empty());
}

#[tokio::test]
async fn without_an_allowance_an_image_is_only_named() {
    let Some(base) = base_image() else { return };
    let v1 = layered(&base, "named");
    let (lender, _lh) = lender().await;
    let (borrower, _bh) = common::fresh_node("Laptop").await;
    common::pair(&borrower, &lender).await;
    let g = grant(&borrower, &lender, 0).await;
    let project = tempfile::tempdir().unwrap();
    // This machine's Docker has it, so the lender runs it by name, as before; nothing is sent.
    let (r, logs) = run(&borrower, &lender, g, &v1.0, project.path())
        .await
        .unwrap();
    assert!(logs.contains("named"), "{r:?} {logs}");
    assert!(lender_tags(&lender, &borrower).is_empty());
}
