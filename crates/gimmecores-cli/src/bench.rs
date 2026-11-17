//! `gmc bench <device>`: is sending work there worth it? (#29)
//!
//! Needs a live grant from that device (sandbox runtime). Measures, in about half a minute:
//! the link (as `gmc link-test`), the cost of starting an empty task there (median of 5),
//! the speed of one core and of several there against this computer, with the same small
//! workload on both (Python if both have `python3`, else the shell), and the upload speed of
//! a fresh 16 MiB file. Then says roughly which jobs finish sooner there. The last result is
//! kept (owner-only, next to the service's state) and shown by `gmc peers`.

use std::io::IsTerminal;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use gimmecores_node::paths::Paths;
use gimmecores_proto::local::v1 as l;
use gimmecores_proto::peer::v1 as pb;
use serde::{Deserialize, Serialize};

/// What one bench measured.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Bench {
    pub at: u64,
    pub link: String,
    pub rtt_ms: f64,
    pub up_mbps: f64,
    /// Starting an empty task there, end to end (median).
    pub start_s: f64,
    /// Work per second there divided by here: one core, and `cores` at once against all of
    /// this computer's.
    pub one_core: f64,
    pub cores: u32,
    pub many_cores: f64,
    /// A fresh file, sent with a task: megabytes per second.
    pub upload_mbps: f64,
    pub workload: String,
}

impl Bench {
    /// How long a job must take here to finish sooner there, sending `mb` megabytes of changed
    /// files, if it can use the cores the grant gives; `None`: it never does.
    pub fn break_even(&self, mb: f64) -> Option<f64> {
        let speedup = self.many_cores.max(self.one_core);
        if speedup <= 1.0 {
            return None;
        }
        let fixed = self.start_s + mb / self.upload_mbps.max(0.1);
        Some(fixed / (1.0 - 1.0 / speedup))
    }

    /// One line for `gmc peers`.
    pub fn summary(&self) -> String {
        let verdict = match self.break_even(10.0) {
            Some(t) => format!(
                "jobs over ~{} with < 10 MB to send finish sooner there",
                secs(t)
            ),
            None => "not faster than here; offload to keep this computer free".to_string(),
        };
        format!(
            "bench: {:.1}x one core, {:.1}x on {} cores, start {:.2} s; {verdict}",
            self.one_core, self.many_cores, self.cores, self.start_s
        )
    }
}

fn secs(t: f64) -> String {
    if t < 90.0 {
        format!("{t:.0} s")
    } else {
        format!("{:.0} min", t / 60.0)
    }
}

fn file(paths: &Paths, fingerprint: &str) -> std::path::PathBuf {
    let safe: String = fingerprint
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    paths.root().join("bench").join(format!("{safe}.json"))
}

/// The last bench of a device, if any.
pub fn last(paths: &Paths, fingerprint: &str) -> Option<Bench> {
    serde_json::from_slice(&std::fs::read(file(paths, fingerprint)).ok()?).ok()
}

fn keep(paths: &Paths, fingerprint: &str, b: &Bench) -> Result<()> {
    let f = file(paths, fingerprint);
    if let Some(d) = f.parent() {
        std::fs::create_dir_all(d)?;
        gimmecores_node::fsutil::restrict_dir(d)?;
    }
    gimmecores_node::fsutil::write_private(&f, &serde_json::to_vec_pretty(b)?)
}

/// The workload: a fixed amount of integer work, printing its own time (seconds) when it can.
fn workload(python: bool, n: u64) -> Vec<String> {
    if python {
        vec![
            "python3".into(),
            "-c".into(),
            format!(
                "import time\nt=time.perf_counter()\ns=0\nfor i in range({n}): s+=i*i%7\n\
                 print(time.perf_counter()-t)"
            ),
        ]
    } else {
        vec![
            "sh".into(),
            "-c".into(),
            format!("i=0; while [ $i -lt {n} ]; do i=$((i+1)); done"),
        ]
    }
}

/// `k` copies of the workload at once.
fn parallel(python: bool, n: u64, k: u32) -> Vec<String> {
    let one = workload(python, n);
    let quoted = one
        .iter()
        .map(|a| format!("'{}'", a.replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" ");
    vec![
        "sh".into(),
        "-c".into(),
        format!("for j in $(seq {k}); do {quoted} & done; wait"),
    ]
}

/// Runs `argv` here; returns (stdout, seconds).
async fn here(argv: &[String], dir: &Path) -> Result<(String, f64)> {
    let t = Instant::now();
    let out = tokio::process::Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(dir)
        .output()
        .await
        .with_context(|| format!("running {:?} here", argv[0]))?;
    if !out.status.success() {
        bail!("{:?} failed here", argv[0]);
    }
    Ok((
        String::from_utf8_lossy(&out.stdout).into_owned(),
        t.elapsed().as_secs_f64(),
    ))
}

/// Runs `argv` there, sending `dir`; returns (stdout, seconds end to end).
async fn there(
    paths: &Paths,
    fingerprint: &str,
    argv: Vec<String>,
    dir: &Path,
    cpus: u32,
) -> Result<(String, f64)> {
    let task = l::InlineTask {
        name: "bench".into(),
        mode: pb::ExecutionMode::Sandbox as i32,
        work: Some(l::inline_task::Work::Command(pb::Command {
            argv,
            working_directory: String::new(),
            environment: Default::default(),
        })),
        resources: Some(pb::Limits {
            cpu_millis: cpus * 1000,
            memory_bytes: 512 << 20,
            ..Default::default()
        }),
        network: pb::NetworkPolicy::None as i32,
        timeout: Some(prost_types::Duration {
            seconds: 300,
            nanos: 0,
        }),
        peers: vec![fingerprint.to_string()],
        shards: 1,
        ..Default::default()
    };
    let job = l::JobSpec {
        project_root: dir.display().to_string(),
        inline_tasks: vec![task],
        ..Default::default()
    };
    let t = Instant::now();
    let mut stream = crate::client(paths)
        .await?
        .submit_job(job)
        .await
        .map_err(crate::status_err)?
        .into_inner();
    let (mut out, mut ok) = (String::new(), false);
    while let Some(ev) = stream.message().await.map_err(crate::status_err)? {
        match ev.event {
            Some(l::job_event::Event::Task(t)) => match t.event {
                Some(pb::task_event::Event::Log(log))
                    if log.stream == pb::log_chunk::Stream::Stdout as i32 =>
                {
                    out.push_str(&String::from_utf8_lossy(&log.data));
                }
                Some(pb::task_event::Event::Finished(r)) => {
                    ok = r.status == pb::task_result::Status::Succeeded as i32;
                }
                _ => {}
            },
            Some(l::job_event::Event::Done(_)) => break,
            _ => {}
        }
    }
    ensure_ok(ok)?;
    Ok((out, t.elapsed().as_secs_f64()))
}

fn ensure_ok(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        bail!("the task did not succeed there")
    }
}

/// The work's own time when it printed one, else the elapsed time less the start cost.
fn work_time(out: &str, elapsed: f64, start: f64) -> f64 {
    out.lines()
        .filter_map(|l| l.trim().parse::<f64>().ok())
        .fold(None, |m: Option<f64>, v| Some(m.map_or(v, |m| m.max(v))))
        .unwrap_or((elapsed - start).max(0.01))
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

pub async fn run(paths: &Paths, peer: &str) -> Result<()> {
    let tty = std::io::stderr().is_terminal();
    let say = |s: &str| {
        if tty {
            eprintln!("{s}");
        }
    };
    let mut c = crate::client(paths).await?;
    let peers = c
        .list_peers(l::ListPeersRequest {
            include_discovered: false,
        })
        .await
        .map_err(crate::status_err)?
        .into_inner()
        .peers;
    let p = crate::pick_peer(&peers, peer)?;
    let grants = c
        .list_grants(l::ListGrantsRequest {
            include_inactive: false,
        })
        .await
        .map_err(crate::status_err)?
        .into_inner()
        .grants;
    let cores = grants
        .iter()
        .filter(|g| {
            !g.as_lender
                && g.state == pb::GrantState::Active as i32
                && g.peer_fingerprint == p.fingerprint
                && g.grant.as_ref().is_some_and(|x| {
                    x.modes.contains(&(pb::ExecutionMode::Sandbox as i32))
                })
        })
        .filter_map(|g| g.grant.as_ref()?.limits)
        .map(|l| l.cpu_millis / 1000)
        .max()
        .context(format!(
            "no live grant from {peer:?} for its sandbox; ask with `gmc grants request {peer} --runtime sandbox`"
        ))?
        .max(1);
    let here_cores = std::thread::available_parallelism().map_or(1, |n| n.get() as u32);
    let mut b = Bench {
        at: gimmecores_node::now(),
        cores,
        ..Default::default()
    };

    say(&format!(
        "Benchmarking {} (about half a minute)...",
        p.device_name
    ));
    say("  link...");
    let s = c
        .link_test(l::LinkTestRequest {
            peer_fingerprint: p.fingerprint.clone(),
        })
        .await
        .map_err(crate::status_err)?
        .into_inner();
    b.link = s.interface_kind.clone();
    b.rtt_ms = s
        .rtt_median
        .map_or(0.0, |d| d.seconds as f64 * 1e3 + f64::from(d.nanos) / 1e6);
    b.up_mbps = s.upload_bits_per_second as f64 / 1e6;

    let empty = tempfile::tempdir()?;
    say("  starting an empty task (5 times)...");
    let mut starts = Vec::new();
    for _ in 0..5 {
        starts.push(
            there(paths, &p.fingerprint, vec!["true".into()], empty.path(), 1)
                .await?
                .1,
        );
    }
    b.start_s = median(starts);

    // The same workload on both sides: Python when both have it.
    let python = here(&workload(true, 10), empty.path()).await.is_ok()
        && there(paths, &p.fingerprint, workload(true, 10), empty.path(), 1)
            .await
            .is_ok();
    b.workload = if python { "python3" } else { "sh" }.into();
    // About a second of work here.
    let mut n: u64 = if python { 2_000_000 } else { 200_000 };
    let (out, el) = here(&workload(python, n), empty.path()).await?;
    let t1 = work_time(&out, el, 0.0);
    n = ((n as f64) * (1.0 / t1.max(0.05))).clamp(1e4, 1e9) as u64;
    say("  one core, here and there...");
    let (out, el) = here(&workload(python, n), empty.path()).await?;
    let here_one = work_time(&out, el, 0.0);
    let (out, el) = there(paths, &p.fingerprint, workload(python, n), empty.path(), 1).await?;
    let there_one = work_time(&out, el, b.start_s);
    b.one_core = here_one / there_one.max(0.001);
    say(&format!("  {cores} cores there, {here_cores} here..."));
    let (out, el) = here(&parallel(python, n, here_cores), empty.path()).await?;
    let here_many = work_time(&out, el, 0.0);
    let (out, el) = there(
        paths,
        &p.fingerprint,
        parallel(python, n, cores),
        empty.path(),
        cores,
    )
    .await?;
    let there_many = work_time(&out, el, b.start_s);
    // Work per second: copies done over the time taken, there against here.
    b.many_cores =
        (f64::from(cores) / there_many.max(0.001)) / (f64::from(here_cores) / here_many.max(0.001));

    say("  sending 16 MiB...");
    let up = tempfile::tempdir()?;
    // Bytes nothing on the way could compress (a fixed pseudo-random sequence).
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15 ^ b.at;
    let data: Vec<u8> = (0..16usize << 20)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u8
        })
        .collect();
    std::fs::write(up.path().join("bench.bin"), &data)?;
    let (_, el) = there(paths, &p.fingerprint, vec!["true".into()], up.path(), 1).await?;
    b.upload_mbps = 16.0 * 1.048_576 / (el - b.start_s).max(0.05);

    keep(paths, &p.fingerprint, &b)?;
    println!("{} ({})", p.device_name, b.link);
    println!(
        "  link:          {:.1} ms round trip, {:.0} Mbps up",
        b.rtt_ms, b.up_mbps
    );
    println!(
        "  start a task:  {:.2} s (empty task, end to end)",
        b.start_s
    );
    println!(
        "  one core:      {:.2}x this computer ({})",
        b.one_core, b.workload
    );
    println!(
        "  {} cores:       {:.2}x this computer's {} cores",
        cores, b.many_cores, here_cores
    );
    println!("  upload:        {:.0} MB/s with a task", b.upload_mbps);
    match (b.break_even(1.0), b.break_even(100.0)) {
        (Some(small), Some(big)) => println!(
            "  verdict:       jobs longer than ~{} with little to send (~{} with 100 MB of \
             changed files) finish sooner there.",
            secs(small),
            secs(big)
        ),
        _ => println!(
            "  verdict:       it is not faster than this computer. Sending work there still \
             keeps this computer free, and adds cores for work that splits (`--shards`)."
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_verdict_weighs_start_and_upload_against_speed() {
        let b = Bench {
            start_s: 0.5,
            one_core: 1.0,
            many_cores: 2.0,
            upload_mbps: 10.0,
            ..Default::default()
        };
        // 0.5 s start + 1 s upload, saved at half the time: jobs over 3 s.
        assert!((b.break_even(10.0).unwrap() - 3.0).abs() < 1e-9);
        let slow = Bench {
            one_core: 0.7,
            many_cores: 0.9,
            ..b.clone()
        };
        assert_eq!(slow.break_even(1.0), None);
        assert!(slow.summary().contains("not faster"));
    }

    #[test]
    fn the_workloads_run_here() {
        let d = tempfile::tempdir().unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (out, el) = rt.block_on(here(&workload(false, 1000), d.path())).unwrap();
        assert!(out.is_empty() && el > 0.0);
        let (_, el) = rt
            .block_on(here(&parallel(false, 1000, 3), d.path()))
            .unwrap();
        assert!(el > 0.0);
        assert!((work_time("0.5\n0.75\n", 9.0, 1.0) - 0.75).abs() < 1e-9);
        assert!((work_time("", 3.0, 1.0) - 2.0).abs() < 1e-9);
    }
}
