//! The activity listing served on the Control socket (docs/design/activity.md, section 8).
//! Rows carry command text other devices chose: Control only, never Client.

use gimmecores_core::ExecutionMode;
use gimmecores_proto::local::v1 as api;
use gimmecores_proto::peer::v1 as pb;

use crate::activity::{Ended, Group, Hosted, Phase};
use crate::node::Node;
use crate::usage::Usage;

/// Rows of running tasks listed per direction.
const MAX_RUNNING: usize = 64;

fn ts(secs: u64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: i64::try_from(secs).unwrap_or(i64::MAX),
        nanos: 0,
    }
}

fn duration(secs: u64) -> prost_types::Duration {
    prost_types::Duration {
        seconds: i64::try_from(secs).unwrap_or(i64::MAX),
        nanos: 0,
    }
}

/// Why lending is paused, as an enum (the reason text comes from `power::pause_reason`).
fn pause_cause(reason: Option<&str>) -> pb::PauseCause {
    match reason {
        None => pb::PauseCause::Unspecified,
        Some(r) if r.contains("battery") => pb::PauseCause::OnBattery,
        Some(r) if r.contains("hot") => pb::PauseCause::Hot,
        Some(r) if r.contains("using") => pb::PauseCause::OwnerActive,
        Some(_) => pb::PauseCause::Other,
    }
}

fn source(mode: ExecutionMode) -> pb::UsageSource {
    match mode {
        ExecutionMode::Sandbox => pb::UsageSource::ProcessTree,
        // Container figures are not measured yet: the runtime's stats are a later step.
        _ => pb::UsageSource::None,
    }
}

fn usage(
    u: &Usage,
    run_ms: u64,
    frozen_ms: u64,
    mode: ExecutionMode,
    speed: pb::ServiceSpeed,
    frozen_why: pb::PauseCause,
) -> api::Usage {
    api::Usage {
        cpu_millis_now: u.cpu_millis_now,
        cpu_time_ms: u.cpu_time_ms,
        memory_bytes: u.memory_bytes,
        memory_peak_bytes: u.memory_peak_bytes,
        disk_bytes: u.disk_bytes,
        processes: u.processes,
        run_ms,
        frozen_ms,
        reported_by_peer: false,
        frozen_why: frozen_why as i32,
        source: source(mode) as i32,
        speed: speed as i32,
    }
}

fn base(info: &crate::activity::TaskInfo) -> api::Execution {
    api::Execution {
        id: info.id.0.to_vec(),
        direction: api::Direction::Here as i32,
        peer_fingerprint: info.peer.fingerprint(),
        peer_name: info.peer_name.clone(),
        grant_id: info.grant.0.to_vec(),
        group: info.group.to_vec(),
        label: String::new(),
        argv: info.command.args.clone(),
        argv_total: u32::try_from(info.command.total).unwrap_or(u32::MAX),
        argv_hidden: u32::try_from(info.command.hidden).unwrap_or(u32::MAX),
        argv_cut: info.command.cut,
        env_names: info.env_names.clone(),
        env_total: u32::try_from(info.env_total).unwrap_or(u32::MAX),
        image: info.image.clone().unwrap_or_default(),
        mode: crate::grants_flow::mode_to(info.mode) as i32,
        asked: Some(api::Asked {
            cpu_millis: info.cpu_millis,
            memory_bytes: info.memory_bytes,
            timeout: Some(duration(info.timeout_secs)),
            effective_timeout: None,
            defaults: false,
            cpu_limit_enforced: info.mode == ExecutionMode::Container,
        }),
        grant_limits: Some(info.grant_limits),
        grant_not_after: Some(ts(info.grant_not_after)),
        created_at: Some(ts(info.created_at)),
        ..Default::default()
    }
}

fn running_row(h: &Hosted, speed: pb::ServiceSpeed, pause: pb::PauseCause) -> api::Execution {
    let mut e = base(&h.info);
    if let Some(a) = e.asked.as_mut() {
        a.effective_timeout = h.effective_timeout_secs.map(duration);
    }
    let run_ms = h.usage.running_for_ms();
    let now = crate::now();
    e.started_at = run_ms.map(|ms| ts(now.saturating_sub(ms / 1000)));
    e.phase = h.phase().to_proto();
    let frozen_why = if h.frozen_since.is_some() {
        pause
    } else {
        pb::PauseCause::Unspecified
    };
    e.usage = Some(usage(
        &h.usage.read(),
        run_ms.unwrap_or(0),
        h.frozen_total_ms(),
        h.info.mode,
        speed,
        frozen_why,
    ));
    e.can_stop = h.stop.is_none();
    e
}

fn ended_row(x: &Ended) -> api::Execution {
    let mut e = base(&x.info);
    e.phase = api::ExecPhase::Ended as i32;
    e.started_at = None;
    e.usage = Some(usage(
        &x.usage,
        x.run_ms,
        x.frozen_ms,
        x.info.mode,
        x.speed,
        pb::PauseCause::Unspecified,
    ));
    e.ending = Some(api::Ending {
        status: x.status as i32,
        cause: x.cause.to_proto() as i32,
        exit_code: x.exit,
        message: x.message.clone(),
        ended_at: Some(ts(x.ended_at)),
    });
    e
}

fn group_row(g: &Group) -> api::ExecutionGroup {
    api::ExecutionGroup {
        group: g.key.to_vec(),
        direction: api::Direction::Here as i32,
        peer_fingerprint: g.peer.fingerprint(),
        peer_name: g.peer_name.clone(),
        count: g.count,
        succeeded: g.succeeded,
        failed: g.failed,
        stopped: g.stopped,
        not_run: g.not_run,
        first_at: Some(ts(g.first_at)),
        last_at: Some(ts(g.last_at)),
        cpu_time_ms_total: (g.cpu_measured_runs > 0).then_some(g.cpu_time_ms_total),
        cpu_measured_runs: g.cpu_measured_runs,
        run_ms_total: g.run_ms_total,
        frozen_ms_total: g.frozen_ms_total,
        memory_peak_bytes_max: g.memory_peak_max,
        slowest_speed: g.slowest_speed as i32,
        last: Some(ended_row(&g.last)),
        last_problem: g.last_problem.as_ref().map(ended_row),
    }
}

/// The whole listing. The state lock is taken once and only for copying.
/// This computer's load, with the part tasks from other devices use now. That part is left
/// out ("not measured") while any running task's figures are not measured (containers), so a
/// borrower's use is never shown as the owner's own.
pub fn machine_row(node: &Node, load: crate::machine::Load) -> api::MachineLoad {
    let (lent_cpu, lent_memory) = {
        let s = node.state();
        let mut cpu = Some(0u32);
        let mut memory = Some(0u64);
        for h in s.running.values() {
            // No process (being prepared, or its results are being stored): it uses nothing.
            if !matches!(h.phase(), Phase::Running | Phase::Frozen | Phase::Stopping) {
                continue;
            }
            let u = h.usage.read();
            cpu = cpu.zip(u.cpu_millis_now).map(|(a, b)| a.saturating_add(b));
            memory = memory.zip(u.memory_bytes).map(|(a, b)| a.saturating_add(b));
        }
        (cpu, memory)
    };
    api::MachineLoad {
        cpu_cores: load.cpu_cores,
        cpu_busy_millis: load.cpu_busy_millis,
        lent_cpu_millis: lent_cpu.map(|v| v.min(load.cpu_cores.saturating_mul(1000))),
        memory_total_bytes: load.memory_total_bytes,
        memory_used_bytes: load.memory_used_bytes,
        lent_memory_bytes: lent_memory.map(|v| v.min(load.memory_total_bytes)),
        gpus: load
            .gpus
            .into_iter()
            .map(|(g, busy)| api::GpuLoad {
                name: g.name,
                kind: g.kind as i32,
                memory_bytes: g.memory_bytes,
                busy_percent: busy,
            })
            .collect(),
    }
}

pub fn listing(node: &Node) -> api::Activity {
    let speed = node.service_speed();
    let s = node.state();
    let pause = pause_cause(s.paused.as_ref().map(|p| p.1.as_str()));
    let mut running: Vec<&Hosted> = s.running.values().collect();
    running.sort_by_key(|h| h.info.created_at);
    let omitted = running.len().saturating_sub(MAX_RUNNING);
    api::Activity {
        revision: s.activity_rev,
        since: Some(ts(node.inner_started_at())),
        running: running
            .iter()
            .take(MAX_RUNNING)
            .map(|h| running_row(h, speed, pause))
            .collect(),
        running_here_omitted: u32::try_from(omitted).unwrap_or(u32::MAX),
        recent: s.history.groups.iter().map(group_row).collect(),
        // Measured by the Control handler, which can wait for a CPU reading.
        machine: None,
    }
}
