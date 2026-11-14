//! What a task running here uses, measured from outside it (docs/design/activity.md, 3.3 and
//! 5.8).
//!
//! Unknown is never zero: every figure starts as "not measured" and stays so until a runner
//! measures it. The cell is owned by the task's record; runners only write into it, so the
//! figures do not depend on how the task ends.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Stored for a figure that was not measured.
const NOT: u64 = u64::MAX;
/// "Now" figures older than this read as not measured; totals and peaks keep their value.
pub const STALE_MS: u64 = 5_000;

/// The figures of one task, written by its runner and the disk walk, read by anyone.
#[derive(Debug)]
pub struct UsageCell {
    cpu_time_ms: AtomicU64,
    cpu_millis_now: AtomicU64,
    mem_now: AtomicU64,
    mem_peak: AtomicU64,
    disk_now: AtomicU64,
    processes: AtomicU64,
    /// When the process figures were last sampled (ms since `epoch`).
    sampled_at: AtomicU64,
    /// When the task's first process existed (ms since `epoch`).
    spawned_at: AtomicU64,
    epoch: Instant,
}

/// A copy of the figures; `None` means not measured.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub cpu_millis_now: Option<u32>,
    pub cpu_time_ms: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub memory_peak_bytes: Option<u64>,
    pub disk_bytes: Option<u64>,
    pub processes: Option<u32>,
}

fn opt(v: u64) -> Option<u64> {
    (v != NOT).then_some(v)
}

/// Raises `a` to `v` (a value never measured counts as below everything).
fn raise(a: &AtomicU64, v: u64) {
    let mut old = a.load(Ordering::Relaxed);
    while old == NOT || old < v {
        match a.compare_exchange_weak(old, v, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(seen) => old = seen,
        }
    }
}

impl Default for UsageCell {
    fn default() -> Self {
        Self {
            cpu_time_ms: AtomicU64::new(NOT),
            cpu_millis_now: AtomicU64::new(NOT),
            mem_now: AtomicU64::new(NOT),
            mem_peak: AtomicU64::new(NOT),
            disk_now: AtomicU64::new(NOT),
            processes: AtomicU64::new(NOT),
            sampled_at: AtomicU64::new(NOT),
            spawned_at: AtomicU64::new(NOT),
            epoch: Instant::now(),
        }
    }
}

impl UsageCell {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(NOT - 1)
    }

    /// The task's first process exists (the runner started it).
    pub fn mark_spawned(&self) {
        let _ =
            self.spawned_at
                .compare_exchange(NOT, self.ms(), Ordering::Relaxed, Ordering::Relaxed);
    }

    /// How long the task's processes have existed, if they have.
    pub fn running_for_ms(&self) -> Option<u64> {
        opt(self.spawned_at.load(Ordering::Relaxed)).map(|t| self.ms().saturating_sub(t))
    }

    pub fn spawned(&self) -> bool {
        self.spawned_at.load(Ordering::Relaxed) != NOT
    }

    /// The size of the task's folder.
    pub fn set_disk(&self, bytes: u64) {
        self.disk_now.store(bytes.min(NOT - 1), Ordering::Relaxed);
    }

    /// One sample of the task's processes.
    pub fn record(&self, s: &Sample) {
        if let Some(t) = s.cpu_time_ms {
            // CPU time never decreases.
            raise(&self.cpu_time_ms, t.min(NOT - 1));
        }
        self.cpu_millis_now
            .store(s.cpu_millis_now.map_or(NOT, u64::from), Ordering::Relaxed);
        self.mem_now.store(s.memory_bytes, Ordering::Relaxed);
        raise(&self.mem_peak, s.memory_bytes.min(NOT - 1));
        self.processes
            .store(u64::from(s.processes), Ordering::Relaxed);
        self.sampled_at.store(self.ms(), Ordering::Relaxed);
    }

    /// The figures now. "Now" figures are dropped once the last sample is stale.
    pub fn read(&self) -> Usage {
        let fresh = opt(self.sampled_at.load(Ordering::Relaxed))
            .is_some_and(|t| self.ms().saturating_sub(t) <= STALE_MS);
        let now = |v: &AtomicU64| {
            if fresh {
                opt(v.load(Ordering::Relaxed))
            } else {
                None
            }
        };
        Usage {
            cpu_millis_now: now(&self.cpu_millis_now).and_then(|v| u32::try_from(v).ok()),
            cpu_time_ms: opt(self.cpu_time_ms.load(Ordering::Relaxed)),
            memory_bytes: now(&self.mem_now),
            memory_peak_bytes: opt(self.mem_peak.load(Ordering::Relaxed)),
            disk_bytes: opt(self.disk_now.load(Ordering::Relaxed)),
            processes: now(&self.processes).and_then(|v| u32::try_from(v).ok()),
        }
    }

    /// The figures as they stood at the end: totals and peaks only ("now" figures of a task
    /// that has ended mean nothing).
    pub fn final_read(&self) -> Usage {
        let u = self.read();
        Usage {
            cpu_millis_now: None,
            memory_bytes: None,
            processes: None,
            ..u
        }
    }
}

// ------------------------------------------------------------------ the process table

/// One row of the process table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
    pub rss_kb: u64,
    /// CPU time used so far, if this platform's table reports it.
    pub cpu_ms: Option<u64>,
    pub comm: String,
}

/// `ps` time as printed on macOS (`MM:SS.cc`, `HH:MM:SS.cc`) and Linux (`[DD-]HH:MM:SS`),
/// in milliseconds.
pub fn parse_ps_time(s: &str) -> Option<u64> {
    let s = s.trim();
    let (days, rest) = match s.split_once('-') {
        Some((d, r)) => (d.parse::<u64>().ok()?, r),
        None => (0, s),
    };
    let parts: Vec<&str> = rest.split(':').collect();
    if parts.is_empty() || parts.len() > 3 || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    let (sec, frac) = match parts[parts.len() - 1].split_once('.') {
        Some((a, b)) => (a, b),
        None => (parts[parts.len() - 1], ""),
    };
    if !sec.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut ms = sec.parse::<u64>().ok()? * 1000;
    if !frac.is_empty() {
        let f: String = frac.chars().chain("000".chars()).take(3).collect();
        ms += f.parse::<u64>().ok()?;
    }
    let mut mult = 60_000u64;
    for p in parts[..parts.len() - 1].iter().rev() {
        if !p.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        ms += p.parse::<u64>().ok()? * mult;
        mult *= 60;
    }
    Some(ms + days * 86_400_000)
}

/// Reads one line of `ps -A -o pid=,ppid=,rss=[,time=],comm=`. A row whose time does not
/// parse keeps its pid, parent and memory (they also enforce limits), with CPU unknown.
fn parse_row(line: &str, with_time: bool) -> Option<Proc> {
    let mut it = line.split_whitespace();
    let pid = it.next()?.parse().ok()?;
    let ppid = it.next()?.parse().ok()?;
    let rss_kb = it.next()?.parse().ok()?;
    let cpu_ms = if with_time {
        parse_ps_time(it.next()?)
    } else {
        None
    };
    Some(Proc {
        pid,
        ppid,
        rss_kb,
        cpu_ms,
        comm: it.collect::<Vec<_>>().join(" "),
    })
}

/// Set once the time column turned out unusable here: from then on the exact table without
/// it (enforcement never depends on the new column).
static NO_TIME_COLUMN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Every process, with CPU time where `ps` reports it (macOS; on Linux it is read from
/// `/proc`, see [`linux_cpu_ms`]).
pub async fn process_table() -> Vec<Proc> {
    let with_time =
        cfg!(target_os = "macos") && !NO_TIME_COLUMN.load(std::sync::atomic::Ordering::Relaxed);
    let cols = if with_time {
        "pid=,ppid=,rss=,time=,comm="
    } else {
        "pid=,ppid=,rss=,comm="
    };
    let out = tokio::process::Command::new("ps")
        .args(["-A", "-o", cols])
        .stderr(std::process::Stdio::null())
        .output()
        .await;
    let rows: Vec<Proc> = match &out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter_map(|l| parse_row(l, with_time))
            .collect(),
        _ => Vec::new(),
    };
    if with_time && rows.is_empty() {
        NO_TIME_COLUMN.store(true, std::sync::atomic::Ordering::Relaxed);
        return Box::pin(process_table()).await;
    }
    rows
}

/// `root` and everything below it.
pub fn descendants(table: &[Proc], root: u32) -> Vec<&Proc> {
    let mut out: Vec<&Proc> = table.iter().filter(|p| p.pid == root).collect();
    let mut i = 0;
    while i < out.len() {
        let parent = out[i].pid;
        out.extend(table.iter().filter(|p| p.ppid == parent && p.pid != parent));
        i += 1;
    }
    out
}

/// Linux: CPU time of one process and its waited-for children, from `/proc/<pid>/stat`
/// (utime + stime + cutime + cstime, in clock ticks).
pub fn linux_cpu_ms(pid: u32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let ticks = parse_proc_stat_ticks(&text)?;
    let hz = clock_ticks()?;
    Some(ticks.saturating_mul(1000) / hz)
}

/// The sum of fields 14 to 17 of a `/proc/<pid>/stat` line. The command name (field 2) may
/// hold spaces and parentheses, so fields are counted after its last `)`.
pub fn parse_proc_stat_ticks(stat: &str) -> Option<u64> {
    let after = &stat[stat.rfind(')')? + 1..];
    let f: Vec<&str> = after.split_whitespace().collect();
    // After the name: state is field 3 (index 0); utime is field 14 (index 11).
    let mut sum = 0u64;
    for i in 11..=14 {
        sum = sum.checked_add(f.get(i)?.parse::<u64>().ok()?)?;
    }
    Some(sum)
}

fn clock_ticks() -> Option<u64> {
    static HZ: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *HZ.get_or_init(|| {
        let out = std::process::Command::new("getconf")
            .arg("CLK_TCK")
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|hz| *hz > 0)
    })
}

/// One sample of a task's process tree.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sample {
    pub cpu_time_ms: Option<u64>,
    pub cpu_millis_now: Option<u32>,
    pub memory_bytes: u64,
    pub processes: u32,
}

/// Turns successive views of a task's processes into figures. CPU time is a lower bound: a
/// process that starts and ends between two samples is never seen (on macOS `ps` does not
/// add ended children's time to their parent).
#[derive(Debug, Default)]
pub struct TreeSampler {
    /// Each live pid's last CPU time.
    last: HashMap<u32, u64>,
    /// CPU time of processes no longer in the tree (macOS).
    gone_ms: u64,
    /// The highest total so far, and when the "now" figure was last computed from it.
    held: Option<u64>,
    rate_base: Option<(u64, Instant)>,
    last_now: Option<u32>,
}

impl TreeSampler {
    /// `tree` with each process's CPU time already filled in where known. `children_included`
    /// is true where a process's time includes its ended children (Linux), so ended
    /// processes are not added again.
    pub fn sample(&mut self, tree: &[Proc], children_included: bool, at: Instant) -> Sample {
        let memory_bytes = tree.iter().map(|p| p.rss_kb.saturating_mul(1024)).sum();
        let processes = u32::try_from(tree.len()).unwrap_or(u32::MAX);
        let known = !tree.is_empty() && tree.iter().all(|p| p.cpu_ms.is_some());
        if !known {
            return Sample {
                memory_bytes,
                processes,
                cpu_time_ms: self.held,
                cpu_millis_now: None,
            };
        }
        let now: HashMap<u32, u64> = tree
            .iter()
            .filter_map(|p| p.cpu_ms.map(|t| (p.pid, t)))
            .collect();
        if !children_included {
            for (pid, old) in &self.last {
                match now.get(pid) {
                    None => self.gone_ms = self.gone_ms.saturating_add(*old),
                    // A smaller value: the pid was reused by a new process.
                    Some(new) if new < old => self.gone_ms = self.gone_ms.saturating_add(*old),
                    _ => {}
                }
            }
        }
        self.last = now;
        let live: u64 = self.last.values().sum();
        let total = live.saturating_add(if children_included { 0 } else { self.gone_ms });
        let dipped = self.held.is_some_and(|h| total < h);
        let held = self.held.map_or(total, |h| h.max(total));
        self.held = Some(held);
        let cpu_millis_now = match self.rate_base {
            None => {
                self.rate_base = Some((held, at));
                None
            }
            Some((base, t0)) => {
                let dt = at.saturating_duration_since(t0).as_millis();
                if dt >= 900 {
                    self.rate_base = Some((held, at));
                    let v = if dipped {
                        None
                    } else {
                        u32::try_from(u128::from(held - base) * 1000 / dt).ok()
                    };
                    self.last_now = v;
                    v
                } else {
                    self.last_now
                }
            }
        };
        Sample {
            cpu_time_ms: Some(held),
            cpu_millis_now,
            memory_bytes,
            processes,
        }
    }
}

/// Samples the tree under `root` once and writes it into `cell`: the table is read once and
/// returned, for the caller's own checks (memory limit, leftover processes).
pub async fn sample_into(
    sampler: &mut TreeSampler,
    cell: Option<&UsageCell>,
    root: u32,
) -> (Vec<Proc>, Vec<u32>, u64) {
    let table = process_table().await;
    let mut tree: Vec<Proc> = descendants(&table, root).into_iter().cloned().collect();
    let linux = cfg!(target_os = "linux");
    if linux {
        for p in &mut tree {
            p.cpu_ms = linux_cpu_ms(p.pid);
        }
    }
    let s = sampler.sample(&tree, linux, Instant::now());
    if let Some(cell) = cell {
        cell.record(&s);
    }
    let pids = tree.iter().map(|p| p.pid).collect();
    (tree, pids, s.memory_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn ps_times_parse_on_both_systems() {
        assert_eq!(parse_ps_time("0:00.01"), Some(10));
        assert_eq!(parse_ps_time("54:41.65"), Some(54 * 60_000 + 41_650));
        assert_eq!(parse_ps_time("1:02:03.5"), Some(3_723_500));
        assert_eq!(parse_ps_time("00:00:00"), Some(0));
        assert_eq!(parse_ps_time("01:00:01"), Some(3_601_000));
        assert_eq!(
            parse_ps_time("2-01:00:00"),
            Some(2 * 86_400_000 + 3_600_000)
        );
        for bad in ["", "abc", "1:x", ":", "1::2", "-1:00", "1.2.3"] {
            assert_eq!(parse_ps_time(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn rows_keep_memory_when_their_time_does_not_parse() {
        let r = parse_row("  42  1  2048 ?? my app", true).unwrap();
        assert_eq!((r.pid, r.ppid, r.rss_kb, r.cpu_ms), (42, 1, 2048, None));
        let r = parse_row("42 1 2048 0:01.50 sleep", true).unwrap();
        assert_eq!(r.cpu_ms, Some(1500));
        assert_eq!(r.comm, "sleep");
        let r = parse_row("42 1 2048 sleep 10", false).unwrap();
        assert_eq!((r.cpu_ms, r.comm.as_str()), (None, "sleep 10"));
    }

    #[test]
    fn proc_stat_counts_fields_after_the_name() {
        // A name with spaces and a parenthesis, as a task may choose.
        let line =
            "123 (my (evil) prog) S 1 123 123 0 -1 4194304 100 0 0 0 250 50 7 3 20 0 1 0 1000 0 0";
        assert_eq!(parse_proc_stat_ticks(line), Some(250 + 50 + 7 + 3));
        assert_eq!(parse_proc_stat_ticks("garbage"), None);
        assert_eq!(parse_proc_stat_ticks("1 (x) S 1 2"), None);
    }

    fn p(pid: u32, ppid: u32, cpu: Option<u64>, rss_kb: u64) -> Proc {
        Proc {
            pid,
            ppid,
            rss_kb,
            cpu_ms: cpu,
            comm: "x".into(),
        }
    }

    #[test]
    fn cpu_time_counts_ended_processes_and_never_decreases() {
        let t0 = Instant::now();
        let mut s = TreeSampler::default();
        let a = s.sample(&[p(1, 0, Some(100), 10), p(2, 1, Some(400), 20)], false, t0);
        assert_eq!(a.cpu_time_ms, Some(500));
        assert_eq!(a.cpu_millis_now, None, "no rate from one sample");
        assert_eq!(a.memory_bytes, 30 * 1024);
        // Process 2 ended; 1 ran on. Its time stays counted (macOS).
        let b = s.sample(
            &[p(1, 0, Some(1100), 10)],
            false,
            t0 + Duration::from_secs(1),
        );
        assert_eq!(b.cpu_time_ms, Some(1500));
        assert_eq!(b.cpu_millis_now, Some(1000), "one core over that second");
        // A reused pid with a smaller value.
        let c = s.sample(&[p(1, 0, Some(10), 10)], false, t0 + Duration::from_secs(2));
        assert_eq!(c.cpu_time_ms, Some(1510));
        // Linux: a parent's figure includes ended children; a dip is never a negative rate.
        let mut l = TreeSampler::default();
        l.sample(&[p(1, 0, Some(500), 1), p(2, 1, Some(300), 1)], true, t0);
        let d = l.sample(&[p(1, 0, Some(700), 1)], true, t0 + Duration::from_secs(1));
        assert_eq!(d.cpu_time_ms, Some(800), "held at the highest total");
        assert_eq!(d.cpu_millis_now, None, "not measured while the sum dips");
    }

    #[test]
    fn unknown_cpu_is_not_zero() {
        let mut s = TreeSampler::default();
        let a = s.sample(&[p(1, 0, None, 4)], false, Instant::now());
        assert_eq!((a.cpu_time_ms, a.cpu_millis_now), (None, None));
        assert_eq!(a.memory_bytes, 4096);
        let cell = UsageCell::default();
        assert_eq!(cell.read(), Usage::default(), "a new cell measured nothing");
        cell.record(&a);
        let u = cell.read();
        assert_eq!(u.cpu_time_ms, None);
        assert_eq!(u.memory_bytes, Some(4096));
        assert_eq!(u.memory_peak_bytes, Some(4096));
        assert_eq!(u.disk_bytes, None);
        cell.set_disk(10);
        assert_eq!(cell.read().disk_bytes, Some(10));
        assert_eq!(cell.final_read().memory_bytes, None);
        assert_eq!(cell.final_read().memory_peak_bytes, Some(4096));
    }

    #[tokio::test]
    async fn a_busy_process_tree_is_measured() {
        // A shell with a busy child: memory, processes and CPU time all show up.
        let mut child = tokio::process::Command::new("sh")
            .args([
                "-c",
                "i=0; while [ $i -lt 2000000 ]; do i=$((i+1)); done & wait",
            ])
            .spawn()
            .unwrap();
        let root = child.id().unwrap();
        let cell = UsageCell::default();
        let mut s = TreeSampler::default();
        let t0 = Instant::now();
        let mut seen = Usage::default();
        while t0.elapsed() < Duration::from_secs(4) {
            sample_into(&mut s, Some(&cell), root).await;
            seen = cell.read();
            if seen.cpu_time_ms.unwrap_or(0) >= 300 && seen.cpu_millis_now.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        let _ = child.kill().await;
        assert!(seen.cpu_time_ms.unwrap_or(0) >= 300, "{seen:?}");
        assert!(seen.cpu_millis_now.unwrap_or(0) >= 300, "{seen:?}");
        assert!(seen.memory_bytes.unwrap_or(0) > 0, "{seen:?}");
        assert!(seen.processes.unwrap_or(0) >= 2, "{seen:?}");
    }
}
