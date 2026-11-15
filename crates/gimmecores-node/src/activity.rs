//! What runs, shown safely: the text rules for commands, labels and image names that come from
//! another device (docs/design/activity.md, section 3.6).
//!
//! Command text is untrusted and may carry a secret typed on a command line. Every argument is
//! shown on its own (boundaries kept), control and invisible characters are escaped (never
//! deleted, so two words never merge), each is cut to a fixed length, and likely secrets are
//! hidden first. Hiding is a heuristic: screens say so.

/// Arguments shown per command.
pub const SHOWN_ARGS: usize = 12;
/// Characters shown per argument or label.
pub const SHOWN_CHARS: usize = 64;
/// What replaces a likely secret.
pub const HIDDEN: &str = "[hidden: looks like a secret]";

/// Characters that change how text reads without being seen: escaped, never shown raw.
fn invisible(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x061C | 0x180E
        | 0x200B..=0x200F
        | 0x2028..=0x202E
        | 0x2060..=0x206F
        | 0xFEFF
        | 0xFFF9..=0xFFFB
        | 0xE0000..=0xE007F)
}

/// One argument (or label) as it may be shown: escaped and cut to `max` characters.
pub fn escape(raw: &str, max: usize) -> String {
    let mut out = String::new();
    let mut shown = 0usize;
    for c in raw.chars() {
        let piece = match c {
            '\\' => "\\\\".to_string(),
            '\n' => "\\n".to_string(),
            '\t' => "\\t".to_string(),
            '\r' => "\\r".to_string(),
            '\u{1b}' => "\\e".to_string(),
            c if c.is_control() => format!("\\x{{{:02X}}}", c as u32),
            c if invisible(c) => format!("\\u{{{:04X}}}", c as u32),
            c => c.to_string(),
        };
        let n = piece.chars().count();
        if shown + n > max {
            out.push('…');
            return out;
        }
        out.push_str(&piece);
        shown += n;
    }
    out
}

/// An argument as shown: escaped, at most [`SHOWN_CHARS`] characters.
pub fn show_arg(raw: &str) -> String {
    escape(raw, SHOWN_CHARS)
}

/// A label chosen by the other device (an SDK function name): escaped and cut; anything over
/// 256 bytes is treated as no label.
pub fn show_label(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 256 {
        return None;
    }
    Some(escape(raw, SHOWN_CHARS))
}

/// Words that mark an option or variable as holding a secret, compared with whole parts of
/// its name (split on `-`, `_` and `.`), so `--max_tokens` and `--author` are not hidden.
const SECRET_PARTS: [&str; 7] = [
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "credentials",
    "bearer",
];

fn secret_name(name: &str) -> bool {
    let parts: Vec<String> = name
        .trim_start_matches('-')
        .split(['-', '_', '.'])
        .filter(|p| !p.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    if parts
        .iter()
        .any(|p| SECRET_PARTS.contains(&p.as_str()) || p == "apikey")
    {
        return true;
    }
    parts.windows(2).any(|w| {
        matches!(
            (w[0].as_str(), w[1].as_str()),
            ("api", "key") | ("access", "key") | ("private", "key")
        )
    })
}

/// One argument after looking for secrets. Whether it is hidden is a property of the
/// argument, never inferred from its text (an argument may itself contain the marker).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Arg<'a> {
    Plain(&'a str),
    /// The whole argument looks like a secret.
    Hidden,
    /// `name=value` whose name says the value is a secret: the name, raw.
    HiddenValue(&'a str),
}

/// Characters of an option name shown before a hidden value.
const SHOWN_NAME_CHARS: usize = 32;

/// The first [`SHOWN_ARGS`] arguments with likely secrets marked: a known token shape anywhere
/// in an argument, the value of `--name=value` or `NAME=value`, and the argument after a bare
/// `--name`, when the name says it holds a secret. Later arguments are never shown.
pub fn mask_args(argv: &[String]) -> Vec<Arg<'_>> {
    let mut out = Vec::with_capacity(argv.len().min(SHOWN_ARGS));
    let mut hide_next = false;
    for a in argv.iter().take(SHOWN_ARGS) {
        let head: String = a.chars().take(4096).collect();
        if hide_next {
            hide_next = false;
            out.push(Arg::Hidden);
            continue;
        }
        if !crate::secrets::scan_text(std::path::Path::new("argv"), &head).is_empty() {
            out.push(Arg::Hidden);
            continue;
        }
        if let Some((name, _)) = a.split_once('=')
            && !name.is_empty()
            && name.len() <= 4096
            && !name.contains(char::is_whitespace)
            && secret_name(name)
        {
            out.push(Arg::HiddenValue(name));
            continue;
        }
        if head.starts_with('-') && !head.contains('=') && secret_name(&head) {
            hide_next = true;
        }
        out.push(Arg::Plain(a));
    }
    out
}

/// The masked arguments as plain text (for the audit log, which cleans and cuts it).
pub fn masked_text(argv: &[String]) -> Vec<String> {
    mask_args(argv)
        .into_iter()
        .map(|a| match a {
            Arg::Plain(s) => s.to_string(),
            Arg::Hidden => HIDDEN.to_string(),
            Arg::HiddenValue(name) => {
                format!(
                    "{}={HIDDEN}",
                    name.chars().take(SHOWN_NAME_CHARS).collect::<String>()
                )
            }
        })
        .collect()
}

/// A command as shown: likely secrets hidden, each argument escaped and cut; also how many
/// arguments there were and whether any was cut or left out.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShownCommand {
    pub args: Vec<String>,
    /// Which of `args` are hidden (same length as `args`).
    pub hidden_at: Vec<bool>,
    pub total: usize,
    pub hidden: usize,
    pub cut: bool,
}

pub fn show_command(argv: &[String]) -> ShownCommand {
    let masked = mask_args(argv);
    let mut cut = argv.len() > SHOWN_ARGS;
    let mut args = Vec::with_capacity(masked.len());
    let mut hidden_at = Vec::with_capacity(masked.len());
    for a in &masked {
        let (text, hidden) = match a {
            Arg::Plain(raw) => {
                let s = show_arg(raw);
                cut |= s.ends_with('…') && !raw.ends_with('…');
                (s, false)
            }
            Arg::Hidden => (HIDDEN.to_string(), true),
            Arg::HiddenValue(name) => {
                let n = escape(name, SHOWN_NAME_CHARS);
                cut |= n.ends_with('…');
                (format!("{n}={HIDDEN}"), true)
            }
        };
        args.push(text);
        hidden_at.push(hidden);
    }
    ShownCommand {
        hidden: hidden_at.iter().filter(|h| **h).count(),
        args,
        hidden_at,
        total: argv.len(),
        cut,
    }
}

/// A variable name as shown (names are already limited to ASCII letters, digits and `_`).
pub fn show_env_name(name: &str) -> String {
    escape(name, SHOWN_CHARS)
}

/// A container image reference is refused, not cleaned: a cleaned name would be a different
/// image. At most 255 bytes of `[A-Za-z0-9._/:@-]`, starting with a letter or digit.
pub fn validate_image(reference: &str) -> anyhow::Result<()> {
    let ok = !reference.is_empty()
        && reference.len() <= 255
        && reference
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && reference
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._/:@-".contains(c));
    anyhow::ensure!(ok, "not a valid container image name");
    Ok(())
}

// ------------------------------------------------------------------ records

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use gimmecores_core::{ExecutionMode, GrantId, PeerKey, TaskId};
use gimmecores_proto::peer::v1 as pb;
use tokio_util::sync::CancellationToken;

use crate::usage::{Usage, UsageCell};

/// Why a task ended, as this device saw it (the same values as `pb::EndCause`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndCause {
    Exited,
    Timeout,
    GrantExpired,
    GrantRevoked,
    LendingOff,
    Unpaired,
    TrustEnded,
    OwnerStopped,
    PausedTooLong,
    MemoryLimit,
    DiskLimit,
    BorrowerCancelled,
    BorrowerGone,
    RunnerError,
    OutputError,
    ServiceStopping,
}

impl EndCause {
    pub fn to_proto(self) -> pb::EndCause {
        use pb::EndCause as P;
        match self {
            Self::Exited => P::Exited,
            Self::Timeout => P::Timeout,
            Self::GrantExpired => P::GrantExpired,
            Self::GrantRevoked => P::GrantRevoked,
            Self::LendingOff => P::LendingOff,
            Self::Unpaired => P::Unpaired,
            Self::TrustEnded => P::TrustEnded,
            Self::OwnerStopped => P::OwnerStopped,
            Self::PausedTooLong => P::PausedTooLong,
            Self::MemoryLimit => P::MemoryLimit,
            Self::DiskLimit => P::DiskLimit,
            Self::BorrowerCancelled => P::BorrowerCancelled,
            Self::BorrowerGone => P::BorrowerGone,
            Self::RunnerError => P::RunnerError,
            Self::OutputError => P::OutputError,
            Self::ServiceStopping => P::ServiceStopping,
        }
    }

    /// The status a stop of this kind ends in (the wire's status values are unchanged, so
    /// older borrowers read what they always read).
    pub fn stopped_status(self) -> pb::task_result::Status {
        use pb::task_result::Status as S;
        match self {
            Self::DiskLimit | Self::MemoryLimit => S::LimitExceeded,
            Self::GrantRevoked
            | Self::GrantExpired
            | Self::LendingOff
            | Self::Unpaired
            | Self::TrustEnded => S::Revoked,
            Self::Timeout => S::TimedOut,
            Self::RunnerError | Self::OutputError => S::Rejected,
            Self::Exited
            | Self::OwnerStopped
            | Self::PausedTooLong
            | Self::BorrowerCancelled
            | Self::BorrowerGone
            | Self::ServiceStopping => S::Cancelled,
        }
    }

    /// The line a borrower's user reads when the lender stopped the task for this reason
    /// (older borrowers show it as the task's own error output).
    pub fn note(self) -> Option<&'static str> {
        match self {
            Self::OwnerStopped => Some("task stopped by the lender's owner"),
            Self::PausedTooLong => {
                Some("task stopped: lending was paused for more than 10 minutes")
            }
            Self::ServiceStopping => Some("task stopped: the lender's service is stopping"),
            _ => None,
        }
    }
}

/// Where a task running here stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Its files are being unpacked.
    Preparing,
    /// The runner was asked to start it; no process yet.
    Starting,
    Running,
    /// Frozen by a pause, confirmed by its runner.
    Frozen,
    /// A stop was asked for and has not finished.
    Stopping,
    /// Its results are being stored.
    Collecting,
}

impl Phase {
    pub fn to_proto(self) -> i32 {
        use gimmecores_proto::local::v1::ExecPhase as P;
        (match self {
            Self::Preparing => P::Preparing,
            Self::Starting => P::Starting,
            Self::Running => P::Running,
            Self::Frozen => P::Frozen,
            Self::Stopping => P::Stopping,
            Self::Collecting => P::Collecting,
        }) as i32
    }
}

/// What a task asked for and where it runs: fixed at admission.
#[derive(Clone, Debug)]
pub struct TaskInfo {
    pub id: TaskId,
    pub peer: PeerKey,
    /// The device's name when the task arrived (kept: a task stopped by an unpair keeps it).
    pub peer_name: String,
    pub grant: GrantId,
    pub grant_limits: pb::Limits,
    pub grant_not_after: u64,
    pub command: ShownCommand,
    pub env_names: Vec<String>,
    pub env_total: usize,
    pub image: Option<String>,
    pub mode: ExecutionMode,
    pub cpu_millis: u32,
    pub memory_bytes: u64,
    pub timeout_secs: u64,
    /// Arrived (Unix seconds).
    pub created_at: u64,
    /// Same device, command and way of running: finished tasks are filed together.
    pub group: [u8; 8],
    /// The level it runs at against the owner's apps (docs/design/task-speed.md).
    pub speed: gimmecores_core::Speed,
    /// Whether its runner applies that level (the sandbox does; containers do not yet).
    pub speed_applied: bool,
}

/// The group a task is filed in: computed here, never chosen by the other device.
pub fn group_of(
    peer: &PeerKey,
    argv: &[String],
    mode: ExecutionMode,
    image: Option<&str>,
) -> [u8; 8] {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(b"gmc-group-v1");
    h.update(peer.0);
    h.update(crate::tasks_flow::argv_digest(argv).as_bytes());
    h.update([match mode {
        ExecutionMode::Container => 1,
        ExecutionMode::Sandbox => 2,
        ExecutionMode::Native => 3,
    }]);
    h.update(image.unwrap_or("").as_bytes());
    let d = h.finalize();
    let mut g = [0u8; 8];
    g.copy_from_slice(&d[..8]);
    g
}

/// A task running here for another device: the registry entry and what is shown about it,
/// one record under one lock.
#[derive(Debug)]
pub struct Hosted {
    pub info: Arc<TaskInfo>,
    pub token: CancellationToken,
    pub usage: Arc<UsageCell>,
    pub started_sent: bool,
    /// The time limit it runs under: the smaller of what it asked and the grant's time left.
    pub effective_timeout_secs: Option<u64>,
    /// The limit was the grant's end, not the task's own.
    pub grant_bound: bool,
    pub frozen_since: Option<Instant>,
    pub frozen_ms: u64,
    /// The first reason it was stopped; later ones do not overwrite it.
    pub stop: Option<EndCause>,
    /// The command ended with this code.
    pub exit: Option<i32>,
    pub collecting: bool,
}

impl Hosted {
    pub fn new(info: TaskInfo, token: CancellationToken) -> Self {
        Self {
            info: Arc::new(info),
            token,
            usage: UsageCell::new(),
            started_sent: false,
            effective_timeout_secs: None,
            grant_bound: false,
            frozen_since: None,
            frozen_ms: 0,
            stop: None,
            exit: None,
            collecting: false,
        }
    }

    pub fn phase(&self) -> Phase {
        if self.stop.is_some() {
            Phase::Stopping
        } else if self.collecting {
            Phase::Collecting
        } else if self.frozen_since.is_some() {
            Phase::Frozen
        } else if self.usage.spawned() {
            Phase::Running
        } else if self.started_sent {
            Phase::Starting
        } else {
            Phase::Preparing
        }
    }

    pub fn frozen_total_ms(&self) -> u64 {
        self.frozen_ms
            .saturating_add(self.frozen_since.map_or(0, |t| {
                u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX)
            }))
    }

    /// Marks the stop reason (the first one wins) and stops the task.
    pub fn stop(&mut self, cause: EndCause) {
        self.stop.get_or_insert(cause);
        self.token.cancel();
    }
}

/// A task that ended here.
#[derive(Clone, Debug)]
pub struct Ended {
    pub info: Arc<TaskInfo>,
    pub status: pb::task_result::Status,
    pub cause: EndCause,
    pub exit: Option<i32>,
    /// At most 200 escaped characters.
    pub message: String,
    pub usage: Usage,
    pub run_ms: u64,
    pub frozen_ms: u64,
    /// Unix seconds.
    pub ended_at: u64,
    pub speed: pb::ServiceSpeed,
}

impl Ended {
    fn exited_zero(&self) -> bool {
        self.status == pb::task_result::Status::Succeeded
    }
}

/// The finished tasks of one group.
#[derive(Clone, Debug)]
pub struct Group {
    pub key: [u8; 8],
    pub peer: PeerKey,
    pub peer_name: String,
    pub count: u32,
    pub succeeded: u32,
    pub failed: u32,
    pub stopped: u32,
    pub not_run: u32,
    pub first_at: u64,
    pub last_at: u64,
    pub cpu_time_ms_total: u64,
    pub cpu_measured_runs: u32,
    pub run_ms_total: u64,
    pub frozen_ms_total: u64,
    pub memory_peak_max: Option<u64>,
    pub slowest_speed: pb::ServiceSpeed,
    pub last: Ended,
    pub last_problem: Option<Ended>,
}

/// Groups kept per device, and in all.
pub const GROUPS_PER_PEER: usize = 8;
pub const GROUPS_IN_ALL: usize = 32;

fn slower(a: pb::ServiceSpeed, b: pb::ServiceSpeed) -> pb::ServiceSpeed {
    if (b as i32) > (a as i32) { b } else { a }
}

/// What ran here recently, in memory only: gone when the service stops; a device's history
/// goes when it is unpaired.
#[derive(Debug, Default)]
pub struct History {
    /// Newest activity first.
    pub groups: VecDeque<Group>,
}

impl History {
    pub fn add(&mut self, e: Ended) {
        use pb::task_result::Status as S;
        let bucket = |g: &mut Group, e: &Ended| match e.status {
            S::Succeeded => g.succeeded += 1,
            S::Failed => g.failed += 1,
            S::Rejected => g.not_run += 1,
            _ => g.stopped += 1,
        };
        let at = self.groups.iter().position(|g| g.key == e.info.group);
        let mut g = match at.and_then(|i| self.groups.remove(i)) {
            Some(g) => g,
            None => Group {
                key: e.info.group,
                peer: e.info.peer,
                peer_name: e.info.peer_name.clone(),
                count: 0,
                succeeded: 0,
                failed: 0,
                stopped: 0,
                not_run: 0,
                first_at: e.ended_at,
                last_at: e.ended_at,
                cpu_time_ms_total: 0,
                cpu_measured_runs: 0,
                run_ms_total: 0,
                frozen_ms_total: 0,
                memory_peak_max: None,
                slowest_speed: e.speed,
                last: e.clone(),
                last_problem: None,
            },
        };
        g.count = g.count.saturating_add(1);
        bucket(&mut g, &e);
        g.last_at = e.ended_at;
        g.peer_name.clone_from(&e.info.peer_name);
        if let Some(t) = e.usage.cpu_time_ms {
            g.cpu_time_ms_total = g.cpu_time_ms_total.saturating_add(t);
            g.cpu_measured_runs = g.cpu_measured_runs.saturating_add(1);
        }
        g.run_ms_total = g.run_ms_total.saturating_add(e.run_ms);
        g.frozen_ms_total = g.frozen_ms_total.saturating_add(e.frozen_ms);
        if let Some(p) = e.usage.memory_peak_bytes {
            g.memory_peak_max = Some(g.memory_peak_max.map_or(p, |m| m.max(p)));
        }
        g.slowest_speed = slower(g.slowest_speed, e.speed);
        if !e.exited_zero() {
            g.last_problem = Some(e.clone());
        }
        g.last = e;
        self.groups.push_front(g);
        self.trim();
    }

    /// Keeps at most [`GROUPS_PER_PEER`] per device and [`GROUPS_IN_ALL`] in all: the
    /// device's own oldest group goes first, so one device cannot push out another's history.
    fn trim(&mut self) {
        let peers: Vec<PeerKey> = self.groups.iter().map(|g| g.peer).collect();
        for peer in peers {
            while self.groups.iter().filter(|g| g.peer == peer).count() > GROUPS_PER_PEER {
                if let Some(i) = self.groups.iter().rposition(|g| g.peer == peer) {
                    self.groups.remove(i);
                }
            }
        }
        while self.groups.len() > GROUPS_IN_ALL {
            // The device holding the most groups gives up its oldest.
            let mut counts: std::collections::BTreeMap<PeerKey, usize> = Default::default();
            for g in &self.groups {
                *counts.entry(g.peer).or_default() += 1;
            }
            let Some((peer, _)) = counts.into_iter().max_by_key(|(_, n)| *n) else {
                break;
            };
            if let Some(i) = self.groups.iter().rposition(|g| g.peer == peer) {
                self.groups.remove(i);
            }
        }
    }

    pub fn forget(&mut self, peer: &PeerKey) {
        self.groups.retain(|g| g.peer != *peer);
    }
}

/// The usage figures as the peer protocol carries them.
pub fn usage_proto(
    u: &Usage,
    h_run_ms: u64,
    frozen_ms: u64,
    speed: pb::ServiceSpeed,
    info: &TaskInfo,
) -> pb::TaskUsage {
    pb::TaskUsage {
        task_speed: crate::grants_flow::speed_to(Some(info.speed)) as i32,
        task_speed_applied: info.speed_applied,
        state: pb::task_usage::State::Unspecified as i32,
        frozen_why: pb::PauseCause::Unspecified as i32,
        cpu_millis_now: u.cpu_millis_now,
        cpu_time_ms: u.cpu_time_ms,
        memory_bytes: u.memory_bytes,
        memory_peak_bytes: u.memory_peak_bytes,
        disk_bytes: u.disk_bytes,
        processes: u.processes,
        run_ms: h_run_ms,
        frozen_ms,
        speed: speed as i32,
    }
}

/// How a task ended, decided in one place from what its runner returned and what was
/// recorded while it ran (the first stop reason, the exit code). Returns the result for the
/// borrower and the record for the history. The wire's status values are unchanged; the cause
/// and the final figures are added.
pub fn outcome(
    h: &Hosted,
    result: anyhow::Result<pb::TaskResult>,
    grant_ended: bool,
    speed: pb::ServiceSpeed,
) -> (anyhow::Result<pb::TaskResult>, Ended) {
    use pb::task_result::Status as S;
    let usage = h.usage.final_read();
    let run_ms = h.usage.running_for_ms().unwrap_or(0);
    let frozen_ms = h.frozen_total_ms();
    let mut message = String::new();
    let mut r = match result {
        Ok(r) => r,
        Err(e) => {
            message = format!("{e:#}");
            pb::TaskResult {
                status: S::Rejected as i32,
                exit_code: h.exit.unwrap_or(-1),
                error: Some(pb::RemoteError {
                    r#type: "Rejected".into(),
                    message: message.clone(),
                    traceback: String::new(),
                }),
                ..Default::default()
            }
        }
    };
    let status = S::try_from(r.status).unwrap_or(S::Failed);
    let (status, cause) = match status {
        S::Succeeded | S::Failed => (status, EndCause::Exited),
        // Status unchanged for older borrowers; the cause says the limit was the grant's end.
        S::TimedOut if h.grant_bound => (S::TimedOut, EndCause::GrantExpired),
        S::TimedOut => (S::TimedOut, EndCause::Timeout),
        S::LimitExceeded => (S::LimitExceeded, h.stop.unwrap_or(EndCause::MemoryLimit)),
        // A stop recorded while it ran (or while it was being set up) says why.
        _ if h.stop.is_some() => {
            let c = h.stop.unwrap_or(EndCause::BorrowerGone);
            (c.stopped_status(), c)
        }
        S::Rejected if h.exit.is_some() => (S::Rejected, EndCause::OutputError),
        S::Rejected => (S::Rejected, EndCause::RunnerError),
        _ if grant_ended => (S::Revoked, EndCause::GrantRevoked),
        _ => (S::Cancelled, EndCause::BorrowerGone),
    };
    r.status = status as i32;
    if status != S::Rejected && !matches!(status, S::Succeeded | S::Failed) {
        r.exit_code = -1;
    }
    r.cause = cause.to_proto() as i32;
    r.final_usage = Some(usage_proto(&usage, run_ms, frozen_ms, speed, &h.info));
    let exit = match cause {
        EndCause::Exited => Some(r.exit_code),
        EndCause::OutputError => h.exit,
        _ => None,
    };
    let ended = Ended {
        info: h.info.clone(),
        status,
        cause,
        exit,
        message: escape(&message, 200),
        usage,
        run_ms,
        frozen_ms,
        ended_at: crate::now(),
        speed,
    };
    (Ok(r), ended)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ended(peer: u8, group: u8, status: pb::task_result::Status, cpu: Option<u64>) -> Ended {
        Ended {
            info: Arc::new(TaskInfo {
                id: TaskId([group; 16]),
                peer: PeerKey([peer; 32]),
                peer_name: format!("device {peer}"),
                grant: GrantId([0; 16]),
                grant_limits: pb::Limits::default(),
                grant_not_after: 0,
                command: ShownCommand::default(),
                env_names: vec![],
                env_total: 0,
                image: None,
                mode: ExecutionMode::Sandbox,
                cpu_millis: 1000,
                memory_bytes: 1 << 30,
                timeout_secs: 60,
                created_at: 1,
                group: [group; 8],
                speed: gimmecores_core::Speed::AppsFirst,
                speed_applied: true,
            }),
            status,
            cause: EndCause::Exited,
            exit: Some(0),
            message: String::new(),
            usage: Usage {
                cpu_time_ms: cpu,
                memory_peak_bytes: Some(u64::from(group) * 10),
                ..Default::default()
            },
            run_ms: 100,
            frozen_ms: 0,
            ended_at: 5,
            speed: pb::ServiceSpeed::Normal,
        }
    }

    #[test]
    fn finished_tasks_are_grouped_and_failures_kept() {
        use pb::task_result::Status as S;
        let mut h = History::default();
        for _ in 0..239 {
            h.add(ended(1, 7, S::Succeeded, Some(10)));
        }
        h.add(ended(1, 7, S::Failed, None));
        h.add(ended(1, 7, S::Succeeded, Some(10)));
        assert_eq!(h.groups.len(), 1);
        let g = &h.groups[0];
        assert_eq!((g.count, g.succeeded, g.failed), (241, 240, 1));
        assert_eq!((g.cpu_time_ms_total, g.cpu_measured_runs), (2400, 240));
        assert_eq!(g.last.status, S::Succeeded);
        assert_eq!(g.last_problem.as_ref().map(|e| e.status), Some(S::Failed));
    }

    #[test]
    fn one_device_cannot_push_out_another_ones_history() {
        use pb::task_result::Status as S;
        let mut h = History::default();
        h.add(ended(2, 200, S::Succeeded, None));
        for g in 0..50u8 {
            h.add(ended(1, g, S::Succeeded, None));
        }
        assert_eq!(
            h.groups
                .iter()
                .filter(|g| g.peer == PeerKey([1; 32]))
                .count(),
            GROUPS_PER_PEER
        );
        assert!(h.groups.iter().any(|g| g.peer == PeerKey([2; 32])));
        // The newest groups are kept, newest first.
        assert_eq!(h.groups[0].key, [49; 8]);
        h.forget(&PeerKey([1; 32]));
        assert_eq!(h.groups.len(), 1);
    }

    fn hosted() -> Hosted {
        let e = ended(1, 1, pb::task_result::Status::Succeeded, None);
        Hosted::new((*e.info).clone(), CancellationToken::new())
    }

    #[test]
    fn a_time_limit_set_by_the_grants_end_keeps_its_status_and_names_the_cause() {
        use pb::task_result::Status as S;
        let timed_out = || {
            Ok(pb::TaskResult {
                status: S::TimedOut as i32,
                exit_code: -1,
                ..Default::default()
            })
        };
        let mut h = hosted();
        h.grant_bound = true;
        let (r, e) = outcome(&h, timed_out(), false, pb::ServiceSpeed::Normal);
        let r = r.unwrap();
        assert_eq!(r.status, S::TimedOut as i32);
        assert_eq!(r.cause, pb::EndCause::GrantExpired as i32);
        assert_eq!(e.cause, EndCause::GrantExpired);
        let (r, _) = outcome(&hosted(), timed_out(), false, pb::ServiceSpeed::Normal);
        assert_eq!(r.unwrap().cause, pb::EndCause::Timeout as i32);
        // A stop recorded while it ran decides a cancelled end; the exit code is not kept.
        let mut h = hosted();
        h.stop(EndCause::OwnerStopped);
        let cancelled = Ok(pb::TaskResult {
            status: S::Cancelled as i32,
            exit_code: 137,
            ..Default::default()
        });
        let (r, e) = outcome(&h, cancelled, false, pb::ServiceSpeed::Normal);
        let r = r.unwrap();
        assert_eq!((r.status, r.exit_code), (S::Cancelled as i32, -1));
        assert_eq!((e.cause, e.exit), (EndCause::OwnerStopped, None));
        // A failure after the command ran keeps its exit code and says results were lost.
        let mut h = hosted();
        h.exit = Some(0);
        let (r, e) = outcome(
            &h,
            Err(anyhow::anyhow!("disk full")),
            false,
            pb::ServiceSpeed::Normal,
        );
        let r = r.unwrap();
        assert_eq!(r.status, S::Rejected as i32);
        assert_eq!(e.cause, EndCause::OutputError);
        assert_eq!(e.exit, Some(0));
        assert_eq!(e.message, "disk full");
    }

    #[test]
    fn stops_end_in_the_statuses_older_borrowers_know() {
        use pb::task_result::Status as S;
        assert_eq!(EndCause::GrantRevoked.stopped_status(), S::Revoked);
        assert_eq!(EndCause::LendingOff.stopped_status(), S::Revoked);
        assert_eq!(EndCause::DiskLimit.stopped_status(), S::LimitExceeded);
        assert_eq!(EndCause::OwnerStopped.stopped_status(), S::Cancelled);
        assert_eq!(EndCause::ServiceStopping.stopped_status(), S::Cancelled);
        assert!(EndCause::OwnerStopped.note().is_some());
    }

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn arguments_keep_boundaries_and_escape_controls() {
        let c = show_command(&v(&[
            "sh",
            "-c",
            "echo a b",
            "x\ny",
            "e\u{1b}[31m",
            "a\u{202e}b",
        ]));
        assert_eq!(
            c.args,
            ["sh", "-c", "echo a b", "x\\ny", "e\\e[31m", "a\\u{202E}b"]
        );
        assert_eq!(c.total, 6);
        assert!(!c.cut && c.hidden == 0);
        // Nothing is deleted: escapes are visible and words never merge.
        assert_eq!(show_arg("a\u{200b}b"), "a\\u{200B}b");
        assert_eq!(show_arg("a\\b"), "a\\\\b");
        assert_eq!(show_arg("\u{7}"), "\\x{07}");
    }

    #[test]
    fn long_arguments_and_commands_are_cut() {
        let long = "x".repeat(200);
        let shown = show_arg(&long);
        assert_eq!(shown.chars().count(), SHOWN_CHARS + 1);
        assert!(shown.ends_with('…'));
        let many: Vec<String> = (0..40).map(|i| format!("a{i}")).collect();
        let c = show_command(&many);
        assert_eq!(c.args.len(), SHOWN_ARGS);
        assert_eq!(c.total, 40);
        assert!(c.cut);
        // An escape is never split by the cut.
        let near = format!("{}\n", "y".repeat(SHOWN_CHARS - 1));
        assert!(show_arg(&near).ends_with('…'));
        assert!(!show_arg(&near).contains("\\n"));
    }

    #[test]
    fn likely_secrets_are_hidden_but_ordinary_flags_are_not() {
        let key = format!("{}{}", "AKIA", "ABCDEFGHIJKLMNOP");
        let ghp = format!("{}{}", "ghp_", "a".repeat(36));
        let c = show_command(&v(&[
            "deploy",
            "--token=s3cr3t-value",
            "--api-key",
            "plainvalue",
            "API_KEY=abc",
            &key,
            &format!("https://x:{ghp}@example.com"),
            "--max_tokens=512",
            "--tokenizer",
            "bert",
            "--author=Ada",
            "/very/long/path/to/some/file/that/is/not/a/secret/at/all.txt",
        ]));
        assert_eq!(c.args[0], "deploy");
        assert_eq!(c.args[1], format!("--token={HIDDEN}"));
        assert_eq!(c.args[2], "--api-key");
        assert_eq!(c.args[3], HIDDEN);
        assert_eq!(c.args[4], format!("API_KEY={HIDDEN}"));
        assert_eq!(c.args[5], HIDDEN);
        assert_eq!(c.args[6], HIDDEN);
        assert_eq!(c.args[7], "--max_tokens=512");
        assert_eq!(c.args[8], "--tokenizer");
        assert_eq!(c.args[9], "bert");
        assert_eq!(c.args[10], "--author=Ada");
        assert!(c.args[11].starts_with("/very/long/path"));
        assert_eq!(c.hidden, 5);
    }

    #[test]
    fn an_argument_cannot_pass_itself_off_as_hidden_or_smuggle_controls() {
        let marker_raw = format!("{HIDDEN}\u{1b}[2J\u{202e}{}", "z".repeat(1 << 20));
        let long_name = format!("\u{1b}[2J-token-{}=v", "n".repeat(4000));
        let c = show_command(&v(&["x", &marker_raw, &long_name]));
        for a in &c.args {
            assert!(
                !a.chars().any(|ch| ch.is_control() || ch == '\u{202e}'),
                "{a:?}"
            );
            assert!(
                a.chars().count() <= SHOWN_CHARS + 1 + HIDDEN.len() + 1,
                "{} chars",
                a.len()
            );
        }
        // The marker text in an argument is shown as text, escaped and cut: it is not hidden.
        assert!(!c.hidden_at[1]);
        assert!(c.args[1].contains("\\e[2J"), "{:?}", c.args[1]);
        // A long, hostile option name before a hidden value is escaped and cut.
        assert!(c.hidden_at[2]);
        assert!(c.args[2].starts_with("\\e[2J-token-"), "{:?}", c.args[2]);
        assert!(
            c.args[2].ends_with(&format!("…={HIDDEN}")),
            "{:?}",
            c.args[2]
        );
        assert_eq!(c.hidden, 1);
        // And in the audit log's text the value is gone, the name cut.
        let t = masked_text(&v(&[&long_name]));
        assert!(!t[0].ends_with("=v") && t[0].len() < 100, "{t:?}");
    }

    #[test]
    fn labels_are_escaped_or_absent() {
        assert_eq!(show_label("square"), Some("square".into()));
        assert_eq!(show_label("  "), None);
        assert_eq!(show_label(&"x".repeat(300)), None);
        assert_eq!(show_label("a\u{202e}b").as_deref(), Some("a\\u{202E}b"));
    }

    #[test]
    fn image_names_are_validated() {
        for ok in ["python:3.12-slim", "ghcr.io/x/y@sha256:abc", "alpine"] {
            validate_image(ok).unwrap();
        }
        let long = "a".repeat(256);
        for bad in ["", ":x", "a b", "a\u{202e}b", "a;rm", long.as_str(), "-x"] {
            assert!(validate_image(bad).is_err(), "{bad:?}");
        }
    }
}
