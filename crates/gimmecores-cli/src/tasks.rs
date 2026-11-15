//! `gmc tasks`: what runs on this computer for other devices, with what each task asked for
//! and what it uses, and what ran recently. Plain text that fits 80 columns.

use std::io::{IsTerminal, Write};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Result, bail};
use gimmecores_node::paths::Paths;
use gimmecores_proto::local::v1 as l;
use gimmecores_proto::peer::v1 as pb;

use crate::{TaskCmd, control, status_err};

pub(crate) async fn run(
    paths: &Paths,
    action: Option<TaskCmd>,
    all: bool,
    watch: bool,
) -> Result<ExitCode> {
    let mut c = control(paths).await?;
    if let Some(TaskCmd::Stop { id }) = action {
        let a = c
            .list_activity(l::ListActivityRequest {
                known_revision: 0,
                // Only tasks running here can be stopped here: never wait on other devices.
                include_there: false,
            })
            .await
            .map_err(status_err)?
            .into_inner();
        let task = find(&a.running, &id)?;
        c.stop_task(l::StopTaskRequest {
            task_id: task.id.clone(),
        })
        .await
        .map_err(status_err)?;
        println!(
            "Stopped task {} ({}) for {}. Its grant is unchanged.",
            short(&task.id),
            command_line(task, 50),
            task.peer_name
        );
        return Ok(ExitCode::SUCCESS);
    }
    loop {
        let a = c
            .list_activity(l::ListActivityRequest {
                known_revision: 0,
                include_there: true,
            })
            .await
            .map_err(status_err)?
            .into_inner();
        let text = render(&a, all || watch);
        if watch && std::io::stdout().is_terminal() {
            print!("\x1b[2J\x1b[H");
        }
        print!("{text}");
        std::io::stdout().flush()?;
        if !watch {
            return Ok(ExitCode::SUCCESS);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// The running task whose id starts with `prefix` (at least 6 hex characters, unique).
fn find<'a>(running: &'a [l::Execution], prefix: &str) -> Result<&'a l::Execution> {
    let prefix = prefix.trim().to_ascii_lowercase();
    if prefix.len() < 6 || !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("give at least the first 6 characters of the task's id (see `gmc tasks`)");
    }
    // Only tasks running here: this device's own tasks elsewhere are the lenders' to stop.
    let hits: Vec<&l::Execution> = running
        .iter()
        .filter(|e| e.direction != l::Direction::There as i32)
        .filter(|e| hex::encode(&e.id).starts_with(&prefix))
        .collect();
    match hits.as_slice() {
        [one] => Ok(one),
        [] => bail!("no task running here has an id starting with {prefix}"),
        many => bail!(
            "{} tasks match {prefix}: {}",
            many.len(),
            many.iter()
                .map(|e| short(&e.id))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn short(id: &[u8]) -> String {
    hex::encode(id).chars().take(8).collect()
}

/// `2m14s`, `42s`, `1h05m`.
pub(crate) fn dur(ms: u64) -> String {
    let s = ms / 1000;
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m{:02}s", s / 60, s % 60),
        _ => format!("{}h{:02}m", s / 3600, (s % 3600) / 60),
    }
}

/// `310 MiB`, `1.9 GiB`.
pub(crate) fn bytes(b: u64) -> String {
    const MIB: f64 = (1u64 << 20) as f64;
    let m = b as f64 / MIB;
    if m >= 1024.0 {
        format!("{:.1} GiB", m / 1024.0)
    } else if m >= 10.0 {
        format!("{m:.0} MiB")
    } else {
        format!("{m:.1} MiB")
    }
}

/// `0.9 cores`, `1 core`, `2.5 cores`.
pub(crate) fn cores(millis: u32) -> String {
    let c = f64::from(millis) / 1000.0;
    if (c - 1.0).abs() < 0.05 {
        "1 core".into()
    } else if c.fract().abs() < 0.05 {
        format!("{c:.0} cores")
    } else {
        format!("{c:.1} cores")
    }
}

/// The command as one line: arguments with spaces quoted, cut to `max` characters.
fn command_line(e: &l::Execution, max: usize) -> String {
    let joined = e
        .argv
        .iter()
        .map(|a| {
            if a.is_empty() || a.contains(char::is_whitespace) {
                format!("'{a}'")
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    if joined.chars().count() > max {
        format!("{}…", joined.chars().take(max - 1).collect::<String>())
    } else {
        joined
    }
}

fn mode(e: &l::Execution) -> &'static str {
    match pb::ExecutionMode::try_from(e.mode) {
        Ok(pb::ExecutionMode::Container) => "container",
        Ok(pb::ExecutionMode::Sandbox) => "sandbox",
        _ => "?",
    }
}

fn phase(p: i32) -> &'static str {
    match l::ExecPhase::try_from(p) {
        Ok(l::ExecPhase::Preparing) => "preparing",
        Ok(l::ExecPhase::Starting) => "starting",
        Ok(l::ExecPhase::Running) => "running",
        Ok(l::ExecPhase::Frozen) => "frozen",
        Ok(l::ExecPhase::Stopping) => "stopping",
        Ok(l::ExecPhase::Collecting) => "storing results",
        _ => "ended",
    }
}

/// Why a task ended, in words.
pub(crate) fn ending(e: &l::Ending) -> String {
    use pb::EndCause as C;
    let cause = pb::EndCause::try_from(e.cause).unwrap_or(C::Unspecified);
    match cause {
        C::Exited => match e.exit_code {
            Some(0) => "finished".into(),
            Some(n) => format!("failed, exit {n}"),
            None => "finished".into(),
        },
        C::Timeout => "stopped: its time limit".into(),
        C::GrantExpired => "stopped: the grant ran out".into(),
        C::GrantRevoked => "stopped: grant revoked".into(),
        C::LendingOff => "stopped: lending turned off".into(),
        C::Unpaired => "stopped: device unpaired".into(),
        C::TrustEnded => "stopped: Trusted mode ended".into(),
        C::OwnerStopped => "stopped by you".into(),
        C::PausedTooLong => "stopped: paused over 10 minutes".into(),
        C::MemoryLimit => "stopped: over its memory".into(),
        C::DiskLimit => "stopped: over the grant's disk".into(),
        C::BorrowerCancelled => "cancelled by its device".into(),
        C::BorrowerGone => "stopped: its device went away".into(),
        C::RunnerError => "could not start".into(),
        C::OutputError => "results not stored".into(),
        C::ServiceStopping => "stopped: GimmeCores stopped".into(),
        C::Refused | C::Unspecified => "ended".into(),
    }
}

fn figure<T>(v: Option<T>, f: impl Fn(T) -> String) -> String {
    v.map_or_else(|| "not measured".into(), f)
}

fn speed_note(s: i32) -> Option<&'static str> {
    match pb::ServiceSpeed::try_from(s) {
        Ok(pb::ServiceSpeed::Reduced) => Some("reduced speed here (below normal priority)"),
        Ok(pb::ServiceSpeed::Background) => {
            Some("reduced speed here (background priority: efficiency cores only)")
        }
        _ => None,
    }
}

/// This computer as a whole: what is in use, and how much of it tasks from other devices use.
fn machine(m: &l::MachineLoad) -> String {
    let mut out = String::from("This computer\n");
    let share = |lent: Option<String>, zero: bool| match lent {
        _ if zero => String::new(),
        Some(l) => format!(", {l} for other devices"),
        None => ", other devices' share not measured".into(),
    };
    let cpu = match m.cpu_busy_millis {
        Some(b) => format!(
            "{} of {} in use{}",
            cores(b),
            m.cpu_cores,
            share(m.lent_cpu_millis.map(cores), m.lent_cpu_millis == Some(0))
        ),
        None => format!("not measured ({} cores)", m.cpu_cores),
    };
    out.push_str(&format!("  cpu     {cpu}\n"));
    let memory = match m.memory_used_bytes {
        Some(u) => format!(
            "{} of {} in use{}",
            bytes(u),
            bytes(m.memory_total_bytes),
            share(
                m.lent_memory_bytes.map(bytes),
                m.lent_memory_bytes == Some(0)
            )
        ),
        None => format!("not measured ({})", bytes(m.memory_total_bytes)),
    };
    out.push_str(&format!("  memory  {memory}\n"));
    for g in &m.gpus {
        let own = if g.memory_bytes > 0 {
            format!(" ({})", bytes(g.memory_bytes))
        } else {
            String::new()
        };
        let busy = figure(g.busy_percent, |p| format!("{p}% busy"));
        out.push_str(&format!("  gpu     {}{own}: {busy}, not lent\n", g.name));
    }
    out.push('\n');
    out
}

/// A lender's whole computer, as it shares it: `cpu 9.8 cores of 12 in use, memory ...`.
fn whole(l: &l::LenderLoad) -> String {
    let cpu = l.cpu_busy_millis.map_or_else(
        || "cpu not reported".to_string(),
        |b| format!("cpu {} of {} in use", cores(b), l.cpu_cores),
    );
    let memory = l.memory_used_bytes.map_or_else(
        || "memory not reported".to_string(),
        |u| format!("memory {} of {}", bytes(u), bytes(l.memory_total_bytes)),
    );
    let gpu = l
        .gpus
        .first()
        .and_then(|g| g.busy_percent)
        .map(|p| format!(", gpu {p}% busy"))
        .unwrap_or_default();
    format!("{cpu}, {memory}{gpu}")
}

/// This device's own tasks on other devices, per lender, with the figures each lender reports.
fn there(a: &l::Activity) -> String {
    if a.borrowed.is_empty() {
        return String::new();
    }
    let mut out = String::from("\nYour tasks on other devices (figures as each device reports)\n");
    for b in &a.borrowed {
        let limits = b.grant_limits.unwrap_or_default();
        let figures = if b.running == 0 {
            String::new()
        } else {
            format!(
                "  cpu {}  memory {}",
                b.cpu_millis.map_or_else(
                    || "not reported".into(),
                    |c| format!("{} of {}", cores(c), cores(limits.cpu_millis))
                ),
                b.memory_bytes.map_or_else(
                    || "not reported".into(),
                    |m| format!("{} of {}", bytes(m), bytes(limits.memory_bytes))
                ),
            )
        };
        let count = match b.tasks {
            0 => "nothing running".to_string(),
            1 => "1 task".to_string(),
            n => format!("{n} tasks"),
        };
        out.push_str(&format!("  {}  {count}{figures}\n", b.peer_name));
        if let Some(lender) = b.lender.as_ref().filter(|l| l.shared) {
            out.push_str(&format!("      whole computer: {}\n", whole(lender)));
        }
        for e in a
            .running
            .iter()
            .filter(|e| e.direction == l::Direction::There as i32 && e.grant_id == b.grant_id)
        {
            let u = e.usage.unwrap_or_default();
            let when = if u.run_ms > 0 {
                format!(" {}", dur(u.run_ms))
            } else {
                String::new()
            };
            out.push_str(&format!(
                "      {}  {}{when}  {}\n",
                short(&e.id),
                match l::ExecPhase::try_from(e.phase) {
                    Ok(l::ExecPhase::Waiting) => "waiting",
                    Ok(l::ExecPhase::Collecting) => "fetching results",
                    Ok(p) => phase(p as i32),
                    Err(_) => "?",
                },
                command_line(e, 46)
            ));
        }
    }
    out
}

pub(crate) fn render(a: &l::Activity, all: bool) -> String {
    let mut out = String::new();
    let now = gimmecores_node::now();
    if let Some(m) = &a.machine {
        out.push_str(&machine(m));
    }
    let here: Vec<&l::Execution> = a
        .running
        .iter()
        .filter(|e| e.direction != l::Direction::There as i32)
        .collect();
    if here.is_empty() {
        out.push_str("Nothing is running on this computer for other devices.\n");
    } else {
        out.push_str("Running here for other devices\n");
    }
    for e in &here {
        let u = e.usage.unwrap_or_default();
        let asked = e.asked.unwrap_or_default();
        out.push_str(&format!(
            "  {}  {} {}  for {}  {}\n",
            short(&e.id),
            phase(e.phase),
            dur(u.run_ms),
            e.peer_name,
            mode(e)
        ));
        let mut cmd = format!("      {}", command_line(e, 68));
        let mut notes = Vec::new();
        if e.argv_total as usize > e.argv.len() {
            notes.push(format!("{} arguments", e.argv_total));
        }
        if e.argv_hidden > 0 {
            notes.push(format!("{} hidden", e.argv_hidden));
        }
        if !notes.is_empty() {
            cmd.push_str(&format!("  ({})", notes.join(", ")));
        }
        out.push_str(&cmd);
        out.push('\n');
        let timeout = asked
            .effective_timeout
            .or(asked.timeout)
            .map_or(String::new(), |d| {
                format!(
                    ", stop after {}",
                    dur(u64::try_from(d.seconds).unwrap_or(0) * 1000)
                )
            });
        out.push_str(&format!(
            "      asked   {}, {}{}\n",
            cores(asked.cpu_millis),
            bytes(asked.memory_bytes),
            timeout
        ));
        let cpu_now = u.cpu_millis_now.map(|m| format!("{} now", cores(m)));
        let cpu_time = u.cpu_time_ms.map(|t| format!("{} of CPU time", dur(t)));
        let cpu = match (cpu_now, cpu_time) {
            (None, None) => "not measured".to_string(),
            (a, b) => [a, b].into_iter().flatten().collect::<Vec<_>>().join(", "),
        };
        let over = u.cpu_millis_now.is_some_and(|m| {
            asked.cpu_millis > 0 && m > asked.cpu_millis + 100 && !asked.cpu_limit_enforced
        });
        out.push_str(&format!("      cpu     {cpu}\n"));
        if over {
            out.push_str("      note    above what it asked for: the sandbox does not cap CPU\n");
        }
        out.push_str(&format!(
            "      memory  {}\n",
            match (u.memory_bytes, u.memory_peak_bytes) {
                (None, None) => "not measured".into(),
                (now_, peak) => [
                    now_.map(|b| format!("{} now", bytes(b))),
                    peak.map(|b| format!("peak {}", bytes(b))),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(", "),
            }
        ));
        out.push_str(&format!(
            "      disk    {}\n",
            figure(u.disk_bytes, |b| format!("{} in its folder", bytes(b)))
        ));
        if u.frozen_ms > 0 || e.phase == l::ExecPhase::Frozen as i32 {
            out.push_str(&format!("      frozen  {} so far\n", dur(u.frozen_ms)));
        }
        if let Some(level) = gimmecores_node::grants_flow::speed_from(u.task_speed) {
            out.push_str(&format!(
                "      speed   {}{}\n",
                gimmecores_node::speed::describe(level),
                if u.task_speed_applied {
                    ""
                } else {
                    " (not applied to containers yet)"
                }
            ));
        }
        if let Some(n) = speed_note(u.speed) {
            out.push_str(&format!("      note    {n}\n"));
        }
    }
    if a.running_here_omitted > 0 {
        out.push_str(&format!("  … and {} more\n", a.running_here_omitted));
    }
    if !here.is_empty() {
        out.push_str("Stop one: gmc tasks stop <id>\n");
    }
    out.push_str(&there(a));
    if all {
        let since = a.since.map_or(0, |t| u64::try_from(t.seconds).unwrap_or(0));
        out.push('\n');
        if a.recent.is_empty() {
            out.push_str(&format!(
                "Nothing has finished here since GimmeCores started {} ago.\n",
                dur(now.saturating_sub(since) * 1000)
            ));
        } else {
            out.push_str(&format!(
                "Finished here since GimmeCores started {} ago (kept in memory only)\n",
                dur(now.saturating_sub(since) * 1000)
            ));
        }
        for g in &a.recent {
            let Some(last) = &g.last else { continue };
            let last_at = g
                .last_at
                .map_or(0, |t| u64::try_from(t.seconds).unwrap_or(0));
            let what = if g.count > 1 {
                format!("{} ×{}", command_line(last, 40), g.count)
            } else {
                command_line(last, 46)
            };
            let how = if g.count == 1 {
                last.ending.as_ref().map_or_else(|| "ended".into(), ending)
            } else {
                let mut parts = vec![format!("{} finished", g.succeeded)];
                if g.failed > 0 {
                    parts.push(format!("{} failed", g.failed));
                }
                if g.stopped > 0 {
                    parts.push(format!("{} stopped", g.stopped));
                }
                if g.not_run > 0 {
                    parts.push(format!("{} not run", g.not_run));
                }
                parts.join(", ")
            };
            out.push_str(&format!(
                "  for {}  {}  {} ago\n      {what}\n",
                g.peer_name,
                how,
                dur(now.saturating_sub(last_at) * 1000)
            ));
            let cpu = g
                .cpu_time_ms_total
                .map_or_else(|| "cpu not measured".into(), |t| format!("cpu {}", dur(t)));
            let peak = g
                .memory_peak_bytes_max
                .map_or_else(String::new, |b| format!(", peak memory {}", bytes(b)));
            out.push_str(&format!(
                "      ran {}{}, {cpu}{peak}\n",
                dur(g.run_ms_total),
                if g.frozen_ms_total > 0 {
                    format!(" ({} frozen)", dur(g.frozen_ms_total))
                } else {
                    String::new()
                }
            ));
            if g.count > 1
                && let Some(p) = g.last_problem.as_ref().and_then(|p| p.ending.as_ref())
            {
                out.push_str(&format!("      last problem: {}\n", ending(p)));
            }
        }
    } else if !a.recent.is_empty() {
        out.push_str(&format!(
            "{} finished group(s) since GimmeCores started: gmc tasks --all\n",
            a.recent.len()
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn figures_read_as_people_say_them() {
        assert_eq!(dur(42_000), "42s");
        assert_eq!(dur(134_000), "2m14s");
        assert_eq!(dur(3_900_000), "1h05m");
        assert_eq!(bytes(310 << 20), "310 MiB");
        assert_eq!(bytes(2040 << 20), "2.0 GiB");
        assert_eq!(cores(1000), "1 core");
        assert_eq!(cores(900), "0.9 cores");
        assert_eq!(cores(4000), "4 cores");
    }

    #[test]
    fn this_computer_reads_clearly_and_an_unmeasured_share_says_so() {
        let mut m = l::MachineLoad {
            cpu_cores: 12,
            cpu_busy_millis: Some(4100),
            lent_cpu_millis: Some(2000),
            memory_total_bytes: 32 << 30,
            memory_used_bytes: Some(18 << 30),
            lent_memory_bytes: Some(1 << 30),
            gpus: vec![l::GpuLoad {
                name: "Apple M2 Max".into(),
                kind: pb::GpuKind::Metal as i32,
                memory_bytes: 0,
                busy_percent: Some(12),
            }],
        };
        let a = l::Activity {
            machine: Some(m.clone()),
            ..Default::default()
        };
        let text = render(&a, false);
        assert!(
            text.contains("cpu     4.1 cores of 12 in use, 2 cores for other devices"),
            "{text}"
        );
        assert!(
            text.contains("memory  18.0 GiB of 32.0 GiB in use, 1.0 GiB for other devices"),
            "{text}"
        );
        assert!(
            text.contains("gpu     Apple M2 Max: 12% busy, not lent"),
            "{text}"
        );
        assert!(text.lines().all(|l| l.chars().count() <= 80), "{text}");

        // A container task: its share is not measured, never folded into "in use" as zero.
        m.lent_cpu_millis = None;
        m.lent_memory_bytes = None;
        m.cpu_busy_millis = None;
        m.gpus[0].busy_percent = None;
        let text = render(
            &l::Activity {
                machine: Some(m),
                ..Default::default()
            },
            false,
        );
        assert!(text.contains("cpu     not measured (12 cores)"), "{text}");
        assert!(text.contains("other devices' share not measured"), "{text}");
        assert!(
            text.contains("Apple M2 Max: not measured, not lent"),
            "{text}"
        );
        // Nothing lent: no share at all.
        let idle = l::MachineLoad {
            cpu_cores: 8,
            cpu_busy_millis: Some(500),
            lent_cpu_millis: Some(0),
            memory_total_bytes: 8 << 30,
            memory_used_bytes: Some(4 << 30),
            lent_memory_bytes: Some(0),
            gpus: vec![],
        };
        let text = machine(&idle);
        assert!(text.contains("cpu     0.5 cores of 8 in use\n"), "{text}");
    }

    #[test]
    fn tasks_elsewhere_are_listed_apart_and_cannot_be_stopped_here() {
        let mut elsewhere = row();
        elsewhere.direction = l::Direction::There as i32;
        elsewhere.peer_name = "Studio".into();
        elsewhere.grant_id = vec![9; 16];
        elsewhere.id = vec![0xcd; 16];
        let a = l::Activity {
            running: vec![row(), elsewhere],
            borrowed: vec![l::BorrowedLoad {
                grant_id: vec![9; 16],
                peer_name: "Studio".into(),
                grant_limits: Some(pb::Limits {
                    cpu_millis: 4000,
                    memory_bytes: 8 << 30,
                    ..Default::default()
                }),
                tasks: 1,
                running: 1,
                cpu_millis: Some(3100),
                memory_bytes: None,
                lender: Some(l::LenderLoad {
                    shared: true,
                    cpu_cores: 12,
                    cpu_busy_millis: Some(9800),
                    memory_total_bytes: 32 << 30,
                    memory_used_bytes: Some(20 << 30),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        let text = render(&a, false);
        assert!(text.contains("abababab  running"), "{text}");
        assert!(
            text.contains("Studio  1 task  cpu 3.1 cores of 4 cores  memory not reported"),
            "{text}"
        );
        assert!(
            text.contains("      cdcdcdcd  running 4m03s  make -j8 'a b'"),
            "{text}"
        );
        assert!(
            text.contains(
                "      whole computer: cpu 9.8 cores of 12 in use, memory 20.0 GiB of 32.0 GiB"
            ),
            "{text}"
        );
        assert!(text.lines().all(|l| l.chars().count() <= 80), "{text}");
        // Only the task running here can be stopped here.
        assert!(find(&a.running, "cdcdcd").is_err());
        assert!(find(&a.running, "ababab").is_ok());
    }

    fn row() -> l::Execution {
        l::Execution {
            id: vec![0xab; 16],
            peer_name: "Laptop".into(),
            argv: vec!["make".into(), "-j8".into(), "a b".into()],
            argv_total: 3,
            mode: pb::ExecutionMode::Sandbox as i32,
            phase: l::ExecPhase::Running as i32,
            asked: Some(l::Asked {
                cpu_millis: 2000,
                memory_bytes: 4 << 30,
                ..Default::default()
            }),
            usage: Some(l::Usage {
                cpu_millis_now: Some(3400),
                cpu_time_ms: Some(400_000),
                memory_bytes: None,
                memory_peak_bytes: None,
                run_ms: 243_000,
                ..Default::default()
            }),
            can_stop: true,
            ..Default::default()
        }
    }

    #[test]
    fn a_running_task_reads_clearly_and_unknown_is_not_zero() {
        let a = l::Activity {
            running: vec![row()],
            ..Default::default()
        };
        let text = render(&a, false);
        assert!(
            text.contains("abababab  running 4m03s  for Laptop  sandbox"),
            "{text}"
        );
        assert!(text.contains("make -j8 'a b'"), "{text}");
        assert!(text.contains("asked   2 cores, 4.0 GiB"), "{text}");
        assert!(text.contains("3.4 cores now, 6m40s of CPU time"), "{text}");
        assert!(text.contains("above what it asked for"), "{text}");
        assert!(text.contains("memory  not measured"), "{text}");
        assert!(text.contains("disk    not measured"), "{text}");
        assert!(text.lines().all(|l| l.chars().count() <= 80), "{text}");
        let empty = render(&l::Activity::default(), true);
        assert!(empty.contains("Nothing is running"), "{empty}");
    }

    #[test]
    fn ids_must_be_unique_prefixes() {
        let mut a = row();
        let mut b = row();
        a.id = vec![0x11; 16];
        b.id = vec![0x12; 16];
        let rows = vec![a, b];
        assert!(find(&rows, "1111").is_err(), "too short");
        assert!(find(&rows, "111111").is_ok());
        assert!(find(&rows, "999999").is_err());
        assert!(find(&rows, "zzzzzz").is_err());
    }
}
