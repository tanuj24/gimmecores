//! A lender that macOS holds at background priority (a launchd job of type `Background`, or
//! anything started under `taskpolicy -b`) runs tasks several times slower. `gmc status` must
//! say so, and must stay quiet for a daemon started normally.
#![allow(clippy::unwrap_used)]
#![cfg(target_os = "macos")]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Starts a real `gmcd` with its own state folder, on loopback only.
fn daemon(home: &Path, prefix: &[&str]) -> Child {
    let gmcd = env!("CARGO_BIN_EXE_gmcd");
    let listen = format!("127.0.0.1:{}", free_port());
    let mut argv: Vec<&str> = prefix.to_vec();
    argv.extend([
        gmcd,
        "--name",
        "Held back",
        "--listen",
        &listen,
        "--no-presence",
        "--identity-store",
        "file",
    ]);
    let child = Command::new(argv[0])
        .args(&argv[1..])
        .env("GMC_HOME", home)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let ready = home.join("run").join("client.sock");
    let t0 = Instant::now();
    while !ready.exists() {
        assert!(t0.elapsed() < Duration::from_secs(20), "gmcd did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    child
}

fn status(home: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_gmc"))
        .arg("status")
        .env("GMC_HOME", home)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn own_priority() -> i32 {
    let out = Command::new("/bin/ps")
        .args(["-o", "pri=", "-p", &std::process::id().to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
}

#[test]
fn status_says_when_the_system_holds_the_service_back() {
    // Short path: Unix socket paths are length-limited.
    let home = tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap();
    let mut held = daemon(home.path(), &["/usr/sbin/taskpolicy", "-b"]);
    let text = status(home.path());
    let _ = held.kill();
    let _ = held.wait();
    assert!(text.contains("speed:    REDUCED"), "{text}");
    assert!(text.contains("background priority"), "{text}");
}

/// A launchd job of type `Standard` (also what a missing type means) runs at this level.
#[test]
fn status_says_when_the_service_runs_below_normal_priority() {
    let home = tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap();
    let mut held = daemon(home.path(), &["/usr/sbin/taskpolicy", "-c", "utility"]);
    let text = status(home.path());
    let _ = held.kill();
    let _ = held.wait();
    assert!(text.contains("speed:    REDUCED"), "{text}");
    assert!(text.contains("below normal priority"), "{text}");
    assert!(text.contains("about half as fast"), "{text}");
}

#[test]
fn status_is_quiet_for_a_daemon_started_normally() {
    if own_priority() <= 20 {
        eprintln!("skipped: these tests themselves run below normal priority");
        return;
    }
    let home = tempfile::Builder::new()
        .prefix("gmc")
        .tempdir_in("/tmp")
        .unwrap();
    let mut normal = daemon(home.path(), &[]);
    let text = status(home.path());
    let _ = normal.kill();
    let _ = normal.wait();
    assert!(!text.contains("speed:"), "{text}");
}
