//! The borrower's side of activity: this device's own tasks running on other devices, with the
//! figures each lender reports while they run (docs/design/activity.md, stage 2).
//!
//! Every figure here is the lender's claim (threat model T2). It is bounded before it is kept:
//! memory and disk at most the grant's (the lender enforces those), CPU at most a fixed
//! ceiling (the sandbox does not cap CPU, so an honest lender can report more than the grant:
//! that is shown as over, as the lender's own screen shows it), times at most what this device
//! itself has seen elapse. A report is kept for the task whose stream it arrived on, never one
//! named inside it, and it stops counting once reports stop arriving.

use std::time::{Duration, Instant};

use gimmecores_core::{ExecutionMode, GrantId, Limits, PeerKey};
use gimmecores_proto::peer::v1 as pb;

use crate::activity::ShownCommand;

/// How often a lender sends a task's figures when asked.
pub const REPORT_EVERY: Duration = Duration::from_secs(2);
/// A report older than this no longer counts: the figures read "not reported".
pub const REPORT_STALE: Duration = Duration::from_secs(7);
/// No real machine has more cores than this (4096); a CPU figure above it is not believed.
pub const CPU_CEILING_MILLIS: u32 = 4096 * 1000;
/// Nor more processes in one task than this.
pub const PROCESS_CEILING: u32 = 1_000_000;
/// Memory and disk figures where the grant names no limit: nothing has more than this (64 TiB).
pub const BYTES_CEILING: u64 = 1 << 46;

/// Where one of this device's tasks is, as far as this device knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Sent; the lender has not said it started.
    Waiting,
    /// The lender said it started.
    Running,
    /// Finished there; its outputs are being fetched.
    Collecting,
}

/// A lender's figures for one task, after bounding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub cpu_millis_now: Option<u32>,
    pub cpu_time_ms: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub memory_peak_bytes: Option<u64>,
    pub disk_bytes: Option<u64>,
    pub processes: Option<u32>,
    pub run_ms: u64,
    pub frozen_ms: u64,
    pub frozen: bool,
    pub frozen_why: pb::PauseCause,
    pub speed: pb::ServiceSpeed,
}

/// Bounds a lender's report for a task under a grant with `limits`, which this device has seen
/// running for `elapsed`. Values that cannot be true are dropped (not measured), values above
/// what the lender enforces are cut to it, unknown enum values read as unspecified.
pub fn accept_report(u: &pb::TaskUsage, limits: &Limits, elapsed: Duration) -> Report {
    let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    let enforced = |v: Option<u64>, limit: u64| {
        if limit == 0 {
            v.filter(|v| *v <= BYTES_CEILING)
        } else {
            v.map(|v| v.min(limit))
        }
    };
    let run_ms = u.run_ms.min(elapsed_ms);
    // CPU time over the run cannot exceed every core of the largest machine for that long.
    let cpu_time_ceiling = elapsed_ms.saturating_mul(u64::from(CPU_CEILING_MILLIS) / 1000);
    Report {
        cpu_millis_now: u.cpu_millis_now.filter(|c| *c <= CPU_CEILING_MILLIS),
        cpu_time_ms: u.cpu_time_ms.filter(|t| *t <= cpu_time_ceiling),
        memory_bytes: enforced(u.memory_bytes, limits.memory_bytes),
        memory_peak_bytes: enforced(u.memory_peak_bytes, limits.memory_bytes),
        disk_bytes: enforced(u.disk_bytes, limits.disk_bytes),
        processes: u.processes.filter(|p| *p <= PROCESS_CEILING),
        run_ms,
        frozen_ms: u.frozen_ms.min(run_ms),
        frozen: u.state == pb::task_usage::State::Frozen as i32,
        frozen_why: pb::PauseCause::try_from(u.frozen_why).unwrap_or(pb::PauseCause::Unspecified),
        speed: pb::ServiceSpeed::try_from(u.speed).unwrap_or(pb::ServiceSpeed::Unspecified),
    }
}

/// One of this device's tasks on another device.
#[derive(Clone, Debug)]
pub struct Remote {
    pub lender: PeerKey,
    pub lender_name: String,
    pub grant: GrantId,
    pub limits: Limits,
    pub not_after: u64,
    pub command: ShownCommand,
    pub env_names: Vec<String>,
    pub env_total: usize,
    pub image: Option<String>,
    pub mode: ExecutionMode,
    pub cpu_millis: u32,
    pub memory_bytes: u64,
    pub timeout_secs: u64,
    /// Sent (Unix seconds).
    pub created_at: u64,
    /// Sent (this device's clock), for bounding the lender's times.
    pub sent: Instant,
    pub phase: Phase,
    /// The last report and when it arrived.
    pub report: Option<(Instant, Report)>,
}

impl Remote {
    /// The last report, if it is recent enough to count.
    pub fn fresh_report(&self) -> Option<&Report> {
        self.report
            .as_ref()
            .filter(|(at, _)| at.elapsed() <= REPORT_STALE)
            .map(|(_, r)| r)
    }

    /// Records a report that arrived on this task's own stream.
    pub fn record(&mut self, u: &pb::TaskUsage) {
        let r = accept_report(u, &self.limits, self.sent.elapsed());
        self.report = Some((Instant::now(), r));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            cpu_millis: 2000,
            memory_bytes: 1 << 30,
            disk_bytes: 10 << 30,
            gpu: gimmecores_core::Gpu::None,
            max_concurrent_tasks: 4,
        }
    }

    fn honest() -> pb::TaskUsage {
        pb::TaskUsage {
            state: pb::task_usage::State::Running as i32,
            frozen_why: pb::PauseCause::Unspecified as i32,
            cpu_millis_now: Some(2400),
            cpu_time_ms: Some(9_000),
            memory_bytes: Some(300 << 20),
            memory_peak_bytes: Some(400 << 20),
            disk_bytes: Some(5 << 20),
            processes: Some(3),
            run_ms: 5_000,
            frozen_ms: 0,
            speed: pb::ServiceSpeed::Normal as i32,
        }
    }

    #[test]
    fn an_honest_report_is_kept_as_sent() {
        let r = accept_report(&honest(), &limits(), Duration::from_secs(6));
        // Above the grant's 2 cores: the sandbox does not cap CPU, and the lender's own screen
        // shows it as over. Kept, so both sides tell the same story.
        assert_eq!(r.cpu_millis_now, Some(2400));
        assert_eq!(r.cpu_time_ms, Some(9_000));
        assert_eq!(r.memory_bytes, Some(300 << 20));
        assert_eq!(r.memory_peak_bytes, Some(400 << 20));
        assert_eq!((r.run_ms, r.frozen_ms, r.processes), (5_000, 0, Some(3)));
        assert_eq!(r.speed, pb::ServiceSpeed::Normal);
        assert!(!r.frozen);
    }

    #[test]
    fn a_lying_lenders_figures_are_bounded() {
        let lie = pb::TaskUsage {
            state: 99,
            frozen_why: 1234,
            cpu_millis_now: Some(u32::MAX),
            cpu_time_ms: Some(u64::MAX),
            memory_bytes: Some(u64::MAX),
            memory_peak_bytes: Some(u64::MAX),
            disk_bytes: Some(u64::MAX),
            processes: Some(u32::MAX),
            run_ms: u64::MAX,
            frozen_ms: u64::MAX,
            speed: -7,
        };
        let r = accept_report(&lie, &limits(), Duration::from_secs(6));
        assert_eq!(r.cpu_millis_now, None, "more cores than any machine has");
        assert_eq!(r.cpu_time_ms, None, "more CPU time than could have passed");
        assert_eq!(r.memory_bytes, Some(1 << 30), "at most the grant's memory");
        assert_eq!(r.memory_peak_bytes, Some(1 << 30));
        assert_eq!(r.disk_bytes, Some(10 << 30), "at most the grant's disk");
        assert_eq!(r.processes, None);
        assert_eq!(
            r.run_ms, 6_000,
            "never longer than this device has seen it run"
        );
        assert_eq!(r.frozen_ms, 6_000, "frozen for at most the whole run");
        assert!(!r.frozen);
        assert_eq!(r.frozen_why, pb::PauseCause::Unspecified);
        assert_eq!(r.speed, pb::ServiceSpeed::Unspecified);
        // Without a known limit, only the fixed ceilings apply.
        let none = Limits {
            memory_bytes: 0,
            disk_bytes: 0,
            ..limits()
        };
        let r = accept_report(&lie, &none, Duration::from_secs(6));
        assert_eq!((r.memory_bytes, r.disk_bytes), (None, None));
        // A CPU figure at the ceiling is still believed; one above it is not.
        let mut edge = honest();
        edge.cpu_millis_now = Some(CPU_CEILING_MILLIS);
        assert_eq!(
            accept_report(&edge, &limits(), Duration::from_secs(6)).cpu_millis_now,
            Some(CPU_CEILING_MILLIS)
        );
    }

    #[test]
    fn a_report_stops_counting_when_reports_stop() {
        let mut t = Remote {
            lender: PeerKey([1; 32]),
            lender_name: "Studio".into(),
            grant: GrantId([2; 16]),
            limits: limits(),
            not_after: 0,
            command: ShownCommand::default(),
            env_names: vec![],
            env_total: 0,
            image: None,
            mode: ExecutionMode::Sandbox,
            cpu_millis: 1000,
            memory_bytes: 1 << 30,
            timeout_secs: 60,
            created_at: 0,
            sent: Instant::now(),
            phase: Phase::Running,
            report: None,
        };
        assert!(t.fresh_report().is_none());
        t.record(&honest());
        assert!(t.fresh_report().is_some());
        let r = t.report.as_mut().unwrap();
        r.0 = Instant::now() - REPORT_STALE - Duration::from_millis(1);
        assert!(
            t.fresh_report().is_none(),
            "an old report reads as not reported"
        );
    }
}
