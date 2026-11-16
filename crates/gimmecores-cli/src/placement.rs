//! Where `gmc run` runs (#24) and splitting one command across devices (#25).
//!
//! `--where remote` (the default) sends the command to a device that granted this one
//! resources, as before. `--where local` runs it here, as a normal program in this folder.
//! `--where auto` runs it here when no device granted anything, or when this computer has
//! enough idle cores for it; otherwise on the device with the most room in its grants.
//!
//! `--shards N` runs the command N times, shard k of N knowing which it is: `{shard}` in the
//! command becomes `k/N`, and `GMC_SHARD=k`, `GMC_SHARDS=N` are set (pytest-split's `--group`,
//! `jest --shard`, `vitest --shard`, a list of Go packages). Shards are spread over every
//! device with a live grant, as many at once on each as its grants have room for (and over
//! this computer with `--where auto` or `local`); each line of output is prefixed `[k/N]`, a
//! shard's `--out` files come back under `out/shard-k/`, and the exit code is the worst
//! shard's.

use std::io::Write;
use std::sync::Mutex;

use anyhow::{Result, bail};
use gimmecores_proto::local::v1 as l;
use gimmecores_proto::peer::v1 as pb;

/// Exit code for a shard or run that could not complete (the lender refused it, the
/// connection failed, it timed out): like `docker run`, 125.
pub const EXIT_GMC: u8 = 125;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Where {
    Local,
    Remote,
    Auto,
}

impl Where {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "local" => Self::Local,
            "remote" => Self::Remote,
            "auto" => Self::Auto,
            other => bail!("--where must be local, remote or auto, not {other:?}"),
        })
    }
}

/// Shard `k` of `n` (1-based).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shard {
    pub k: u32,
    pub n: u32,
}

impl Shard {
    /// The command with `{shard}` replaced by `k/n`.
    pub fn argv(self, argv: &[String]) -> Vec<String> {
        argv.iter()
            .map(|a| a.replace("{shard}", &format!("{}/{}", self.k, self.n)))
            .collect()
    }

    /// `GMC_SHARD` and `GMC_SHARDS`, set for every shard (also when there is one).
    pub fn env(self) -> Vec<(String, String)> {
        vec![
            ("GMC_SHARD".into(), self.k.to_string()),
            ("GMC_SHARDS".into(), self.n.to_string()),
        ]
    }

    pub fn prefix(self) -> String {
        if self.n > 1 {
            format!("[{}/{}] ", self.k, self.n)
        } else {
            String::new()
        }
    }
}

/// Where one worker runs its shards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Slot {
    Here,
    There { fingerprint: String, name: String },
}

impl Slot {
    pub fn label(&self) -> &str {
        match self {
            Self::Here => "this computer",
            Self::There { name, .. } => name,
        }
    }
}

/// A device's live grants to this one, as room for tasks of `cpu_millis` each.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Room {
    pub fingerprint: String,
    pub name: String,
    pub tasks: usize,
}

/// How many tasks of `cpu_millis` fit in the live grants each device gave this one, for the
/// runtime asked (`mode`, unspecified: any), most room first. `only`: one device.
pub fn rooms(
    grants: &[l::GrantInfo],
    names: &[(String, String)],
    cpu_millis: u32,
    mode: pb::ExecutionMode,
    only: Option<&str>,
) -> Vec<Room> {
    let mut out: Vec<Room> = Vec::new();
    for g in grants {
        let Some(grant) = g.grant.as_ref() else {
            continue;
        };
        if g.as_lender || g.state != pb::GrantState::Active as i32 {
            continue;
        }
        if mode != pb::ExecutionMode::Unspecified && !grant.modes.contains(&(mode as i32)) {
            continue;
        }
        let name = names
            .iter()
            .find(|(fp, _)| *fp == g.peer_fingerprint)
            .map_or_else(|| g.peer_fingerprint.clone(), |(_, n)| n.clone());
        if only.is_some_and(|o| o != name && o != g.peer_fingerprint) {
            continue;
        }
        let lim = grant.limits.unwrap_or_default();
        let by_cpu = (lim.cpu_millis / cpu_millis.max(1)).max(1) as usize;
        let tasks = by_cpu.min(lim.max_concurrent_tasks.max(1) as usize);
        match out.iter_mut().find(|r| r.fingerprint == g.peer_fingerprint) {
            Some(r) => r.tasks += tasks,
            None => out.push(Room {
                fingerprint: g.peer_fingerprint.clone(),
                name,
                tasks,
            }),
        }
    }
    out.sort_by(|a, b| b.tasks.cmp(&a.tasks).then(a.name.cmp(&b.name)));
    out
}

/// Cores this computer is not using now (sampled for about 0.2 s).
pub fn idle_cores() -> f64 {
    let mut sys = sysinfo::System::new();
    sys.refresh_cpu_usage();
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    sys.refresh_cpu_usage();
    let cores = sys.cpus().len().max(1) as f64;
    cores * (1.0 - f64::from(sys.global_cpu_usage()) / 100.0)
}

/// The workers for a run: which places, and why (said on a terminal).
pub fn plan(
    wh: Where,
    rooms: &[Room],
    shards: u32,
    cpus: u32,
    idle: f64,
    cores: usize,
) -> Result<(Vec<Slot>, String)> {
    let there = |r: &Room| Slot::There {
        fingerprint: r.fingerprint.clone(),
        name: r.name.clone(),
    };
    let remote: Vec<Slot> = rooms
        .iter()
        .flat_map(|r| std::iter::repeat_n(there(r), r.tasks))
        .collect();
    let fits_here = ((idle / f64::from(cpus.max(1))).floor() as usize).min(shards as usize);
    match wh {
        Wh::Remote => {
            if remote.is_empty() {
                bail!(
                    "no device has granted you resources; ask with `gmc grants request <device>` (or run here with `--where local`)"
                );
            }
            Ok((remote, String::new()))
        }
        Wh::Local => {
            let n = (cores / cpus.max(1) as usize).max(1).min(shards as usize);
            Ok((vec![Slot::Here; n], "here, as asked".into()))
        }
        Wh::Auto => {
            if remote.is_empty() {
                let n = fits_here.max(1);
                return Ok((
                    vec![Slot::Here; n],
                    "here: no device has granted you resources".into(),
                ));
            }
            if shards == 1 {
                return Ok(if fits_here >= 1 {
                    (
                        vec![Slot::Here],
                        format!("here: this computer has {idle:.0} idle cores"),
                    )
                } else {
                    (
                        vec![remote[0].clone()],
                        format!("on {}: this computer is busy", remote[0].label()),
                    )
                });
            }
            let mut slots = vec![Slot::Here; fits_here];
            slots.extend(remote);
            Ok((slots, String::new()))
        }
    }
}

use Where as Wh;

/// Shards' output cut into whole lines, each prefixed with its shard, so two shards' bytes
/// never share a line.
#[derive(Default)]
pub struct Lines {
    partial: std::collections::BTreeMap<(u32, bool), Vec<u8>>,
}

impl Lines {
    /// The complete lines `data` finishes, prefixed.
    pub fn push(&mut self, s: Shard, stderr: bool, data: &[u8]) -> Vec<u8> {
        let buf = self.partial.entry((s.k, stderr)).or_default();
        buf.extend_from_slice(data);
        let mut out = Vec::new();
        while let Some(i) = buf.iter().position(|b| *b == b'\n') {
            out.extend_from_slice(s.prefix().as_bytes());
            out.extend(buf.drain(..=i));
        }
        out
    }

    /// What is left of a shard's last line, on stdout and on stderr.
    pub fn flush(&mut self, s: Shard) -> [Vec<u8>; 2] {
        [false, true].map(|stderr| {
            let mut out = Vec::new();
            if let Some(buf) = self
                .partial
                .remove(&(s.k, stderr))
                .filter(|b| !b.is_empty())
            {
                out.extend_from_slice(s.prefix().as_bytes());
                out.extend(buf);
                out.push(b'\n');
            }
            out
        })
    }
}

/// `gmc run`'s output: as it comes for one task, in prefixed lines for shards.
#[derive(Default)]
pub struct Out {
    lines: Mutex<Lines>,
}

fn emit(stderr: bool, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let _ = if stderr {
        std::io::stderr().write_all(data)
    } else {
        std::io::stdout().write_all(data)
    };
}

impl Out {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn write(&self, s: Shard, stderr: bool, data: &[u8]) {
        if s.n <= 1 {
            emit(stderr, data);
            return;
        }
        let done = self
            .lines
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(s, stderr, data);
        emit(stderr, &done);
    }

    /// What is left of a shard's last line.
    pub fn flush(&self, s: Shard) {
        let [o, e] = self
            .lines
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .flush(s);
        emit(false, &o);
        emit(true, &e);
    }
}

/// The overall exit code: the worst shard's (an error beats a failure, a failure success).
pub fn worst(codes: &[u8]) -> u8 {
    if codes.contains(&EXIT_GMC) {
        EXIT_GMC
    } else {
        codes.iter().copied().max().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_shard_knows_which_it_is() {
        let s = Shard { k: 2, n: 4 };
        assert_eq!(
            s.argv(&["pytest".into(), "--group".into(), "{shard}".into()]),
            ["pytest", "--group", "2/4"]
        );
        assert_eq!(
            s.env(),
            [
                ("GMC_SHARD".into(), "2".into()),
                ("GMC_SHARDS".into(), "4".into())
            ]
        );
        assert_eq!(s.prefix(), "[2/4] ");
        assert_eq!(Shard { k: 1, n: 1 }.prefix(), "");
    }

    #[test]
    fn lines_from_two_shards_never_mix() {
        let mut l = Lines::default();
        let (a, b) = (Shard { k: 1, n: 2 }, Shard { k: 2, n: 2 });
        assert!(l.push(a, false, b"hel").is_empty());
        assert_eq!(l.push(b, false, b"one\ntw"), b"[2/2] one\n");
        assert_eq!(l.push(a, false, b"lo\n"), b"[1/2] hello\n");
        assert_eq!(l.flush(b), [b"[2/2] tw\n".to_vec(), Vec::new()]);
        assert_eq!(l.flush(a), [Vec::<u8>::new(), Vec::new()]);
    }

    #[test]
    fn the_worst_shard_decides_the_exit_code() {
        assert_eq!(worst(&[0, 0]), 0);
        assert_eq!(worst(&[0, 1, 4]), 4);
        assert_eq!(worst(&[0, 4, EXIT_GMC]), EXIT_GMC);
    }

    fn grant(fp: &str, cpu: u32, at_once: u32, modes: &[pb::ExecutionMode]) -> l::GrantInfo {
        l::GrantInfo {
            peer_fingerprint: fp.into(),
            state: pb::GrantState::Active as i32,
            grant: Some(pb::Grant {
                limits: Some(pb::Limits {
                    cpu_millis: cpu,
                    max_concurrent_tasks: at_once,
                    ..Default::default()
                }),
                modes: modes.iter().map(|m| *m as i32).collect(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn room_is_what_live_grants_hold_for_the_runtime_asked() {
        use pb::ExecutionMode::{Container, Sandbox, Unspecified};
        let names = [
            ("A".to_string(), "Desktop".to_string()),
            ("B".into(), "Mini".into()),
        ];
        let mut lent = grant("B", 8000, 8, &[Sandbox]);
        lent.as_lender = true;
        let grants = [
            grant("A", 4000, 4, &[Sandbox]),
            grant("A", 2000, 2, &[Container]),
            grant("B", 8000, 2, &[Sandbox, Container]),
            lent,
        ];
        let r = rooms(&grants, &names, 1000, Unspecified, None);
        assert_eq!(
            r[0],
            Room {
                fingerprint: "A".into(),
                name: "Desktop".into(),
                tasks: 6
            }
        );
        assert_eq!(r[1].tasks, 2, "tasks at once cap it");
        let r = rooms(&grants, &names, 2000, Sandbox, None);
        assert_eq!(r.iter().map(|r| r.tasks).collect::<Vec<_>>(), [2, 2]);
        assert_eq!(
            rooms(&grants, &names, 1000, Unspecified, Some("Mini")).len(),
            1
        );
    }

    #[test]
    fn auto_runs_here_when_nothing_is_granted_or_this_computer_is_idle() {
        let room = [Room {
            fingerprint: "A".into(),
            name: "Desktop".into(),
            tasks: 2,
        }];
        let (s, why) = plan(Where::Auto, &[], 1, 1, 0.0, 8).unwrap();
        assert_eq!(s, [Slot::Here]);
        assert!(why.contains("no device"));
        let (s, _) = plan(Where::Auto, &room, 1, 2, 6.5, 8).unwrap();
        assert_eq!(s, [Slot::Here]);
        let (s, why) = plan(Where::Auto, &room, 1, 2, 1.0, 8).unwrap();
        assert_eq!(s[0].label(), "Desktop");
        assert!(why.contains("busy"));
        // Shards: here as far as idle cores go, plus every device's room.
        let (s, _) = plan(Where::Auto, &room, 8, 1, 3.2, 8).unwrap();
        assert_eq!(s.iter().filter(|x| **x == Slot::Here).count(), 3);
        assert_eq!(s.len(), 5);
        assert!(plan(Where::Remote, &[], 1, 1, 8.0, 8).is_err());
        assert_eq!(
            plan(Where::Local, &room, 4, 2, 0.0, 8).unwrap().0,
            [Slot::Here, Slot::Here, Slot::Here, Slot::Here]
        );
    }
}
