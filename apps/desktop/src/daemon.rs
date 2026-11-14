//! Reads and changes the local daemon's state over its owner-only sockets.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use gimmecores_client::api;
use gimmecores_proto::peer::v1 as pb;
use serde::Serialize;

/// Everything the window shows, read in one go.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Snapshot {
    /// False when gmcd is not running (then `error` says why).
    pub running: bool,
    pub error: Option<String>,
    pub status: Option<StatusView>,
    /// Waiting for this user's decision (this device lends).
    pub requests: Vec<GrantView>,
    /// Grants this device gave (active or paused).
    pub lent: Vec<GrantView>,
    /// Grants other devices gave this one.
    pub borrowed: Vec<GrantView>,
    pub peers: Vec<PeerView>,
    pub pairings: Vec<PairingView>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct StatusView {
    pub device_name: String,
    pub fingerprint: String,
    pub lending: bool,
    /// Non-empty while laptop protections pause lending.
    pub pause_reason: String,
    pub idle_only: bool,
    pub pause_on_battery: bool,
    pub pause_when_hot: bool,
    pub presence_required: bool,
    pub presence_method: String,
    pub running_for_others: u32,
    pub cpu_cores: u32,
    pub memory_gib: f64,
    /// Ways of running tasks this user lends: "container", "sandbox".
    pub lend_modes: Vec<String>,
    /// Ways that work on this machine right now.
    pub available_modes: Vec<String>,
    /// Paired devices find each other on the local network.
    pub discovery: bool,
    /// Non-empty while the system holds the service back (tasks run slower than they could).
    pub performance_note: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct GrantView {
    /// Hex grant id.
    pub id: String,
    pub peer_fingerprint: String,
    pub peer_name: String,
    /// requested, active, paused, revoked, expired, declined
    pub state: String,
    pub cores: f64,
    pub memory_gib: f64,
    pub disk_gib: f64,
    /// Unix seconds.
    pub expires_at: i64,
    /// The borrower's reason (requests) or the running task count (lent grants).
    pub detail: String,
    /// Where tasks under this grant may run: "container", "sandbox", "native".
    pub modes: Vec<String>,
    /// A Trusted grant (Python objects both ways; needs Trusted mode on both devices).
    pub trusted: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct PeerView {
    pub fingerprint: String,
    pub name: String,
    pub paired: bool,
    /// "wifi, 0.4 ms, 940 Mbit/s" from the last link test, if any.
    pub link: Option<String>,
    /// Unix seconds when this device's Trusted mode for the peer lapses (None: off).
    pub trusted_until: Option<i64>,
    /// The peer holds Trusted mode on for this device too (as its grants show; display only).
    pub trusted_remote: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct PairingView {
    /// Hex session id.
    pub session: String,
    pub peer_name: String,
    pub peer_fingerprint: String,
    /// "123 456" once both sides can compare it.
    pub code: String,
    /// waiting, compare, paired, failed
    pub state: String,
    pub error: String,
    /// This name was seen before with a different key: possible impersonation.
    pub name_warning: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Ticket {
    pub ticket: String,
    pub closes_at: i64,
}

/// The daemon's message without gRPC noise.
fn msg(e: tonic::Status) -> anyhow::Error {
    anyhow!("{}", e.message())
}

const GIB: f64 = (1u64 << 30) as f64;

fn mode_names(modes: &[i32]) -> Vec<String> {
    modes
        .iter()
        .filter_map(|m| match pb::ExecutionMode::try_from(*m) {
            Ok(pb::ExecutionMode::Container) => Some("container".to_string()),
            Ok(pb::ExecutionMode::Sandbox) => Some("sandbox".to_string()),
            Ok(pb::ExecutionMode::Native) => Some("native".to_string()),
            _ => None,
        })
        .collect()
}

fn grant_view(g: &api::GrantInfo, names: &BTreeMap<String, String>) -> GrantView {
    let state = pb::GrantState::try_from(g.state).unwrap_or(pb::GrantState::Unspecified);
    let state = match state {
        pb::GrantState::Requested => "requested",
        pb::GrantState::Offered => "offered",
        pb::GrantState::Active => "active",
        pb::GrantState::Paused => "paused",
        pb::GrantState::Revoked => "revoked",
        pb::GrantState::Expired => "expired",
        pb::GrantState::Declined => "declined",
        _ => "unknown",
    };
    let limits = g.grant.as_ref().and_then(|x| x.limits).unwrap_or_default();
    let peer_name = names
        .get(&g.peer_fingerprint)
        .cloned()
        .unwrap_or_else(|| "Unknown device".into());
    // Requests read "<name> asks: <reason>"; show only the reason.
    let detail = g
        .state_reason
        .strip_prefix(&format!("{peer_name} asks: "))
        .unwrap_or(&g.state_reason)
        .to_string();
    GrantView {
        id: hex::encode(&g.grant_id),
        peer_fingerprint: g.peer_fingerprint.clone(),
        peer_name,
        state: state.into(),
        cores: f64::from(limits.cpu_millis) / 1000.0,
        memory_gib: limits.memory_bytes as f64 / GIB,
        disk_gib: limits.disk_bytes as f64 / GIB,
        expires_at: g
            .grant
            .as_ref()
            .and_then(|x| x.not_after)
            .map_or(0, |t| t.seconds),
        detail,
        modes: g
            .grant
            .as_ref()
            .map(|x| mode_names(&x.modes))
            .unwrap_or_default(),
        trusted: g
            .grant
            .as_ref()
            .is_some_and(|x| x.trust == pb::TrustLevel::Trusted as i32),
    }
}

fn link_summary(l: &api::LinkStats) -> String {
    let ms = l
        .rtt_median
        .map_or(0.0, |d| d.seconds as f64 * 1e3 + f64::from(d.nanos) / 1e6);
    let mbps = l.upload_bits_per_second.min(l.download_bits_per_second) / 1_000_000;
    format!("{}, {ms:.1} ms, {mbps} Mbit/s", l.interface_kind)
}

fn pairing_view(s: &api::PairingSession) -> PairingView {
    let state = match api::pairing_session::State::try_from(s.state) {
        Ok(api::pairing_session::State::Waiting) => "waiting",
        Ok(api::pairing_session::State::CompareCode) => "compare",
        Ok(api::pairing_session::State::Paired) => "paired",
        Ok(api::pairing_session::State::Failed) => "failed",
        _ => "unknown",
    };
    PairingView {
        session: hex::encode(&s.session_id),
        peer_name: s.peer_device_name.clone(),
        peer_fingerprint: s.peer_fingerprint.clone(),
        code: s.code.clone(),
        state: state.into(),
        error: s.error.clone(),
        name_warning: s.name_previously_seen_with_other_key,
    }
}

/// Reads everything; a daemon that is not running is a normal state, not an error.
pub async fn snapshot(home: &Path) -> Snapshot {
    match read(home).await {
        Ok(s) => s,
        Err(e) => Snapshot {
            running: false,
            error: Some(format!("{e:#}")),
            ..Default::default()
        },
    }
}

async fn read(home: &Path) -> Result<Snapshot> {
    if !gimmecores_client::client_socket(home).exists() {
        return Err(anyhow!("GimmeCores is not running. Start it with `gmcd`."));
    }
    let mut client = gimmecores_client::client(home).await?;
    let mut control = gimmecores_client::control(home).await?;
    let st = client
        .get_status(api::GetStatusRequest {})
        .await
        .map_err(msg)?
        .into_inner();
    let caps = st.capabilities.clone().unwrap_or_default();
    let peers = client
        .list_peers(api::ListPeersRequest {
            include_discovered: true,
        })
        .await
        .map_err(msg)?
        .into_inner()
        .peers;
    let names: BTreeMap<String, String> = peers
        .iter()
        .map(|p| (p.fingerprint.clone(), p.device_name.clone()))
        .collect();
    let grants = client
        .list_grants(api::ListGrantsRequest {
            include_inactive: false,
        })
        .await
        .map_err(msg)?
        .into_inner()
        .grants;
    let pairings = control
        .list_pairings(api::ListPairingsRequest {})
        .await
        .map_err(msg)?
        .into_inner()
        .sessions;

    let mut snap = Snapshot {
        running: true,
        status: Some(StatusView {
            device_name: st.device_name,
            fingerprint: st.fingerprint,
            lending: st.lending_enabled,
            pause_reason: st.pause_reason,
            idle_only: st.idle_only,
            pause_on_battery: st.pause_on_battery,
            pause_when_hot: st.pause_when_hot,
            presence_required: st.presence_required,
            presence_method: st.presence_method,
            running_for_others: st.active_lent_tasks,
            cpu_cores: caps.cpu_cores,
            memory_gib: caps.memory_bytes as f64 / GIB,
            lend_modes: mode_names(&st.lend_modes),
            available_modes: mode_names(&st.available_modes),
            discovery: st.discovery != api::DiscoveryMode::Off as i32,
            performance_note: st.performance_note,
        }),
        peers: peers
            .iter()
            .map(|p| PeerView {
                fingerprint: p.fingerprint.clone(),
                name: p.device_name.clone(),
                paired: p.paired,
                link: p.links.first().map(link_summary),
                trusted_until: p.trusted_until.map(|t| t.seconds),
                trusted_remote: p.trusted_mode_remote,
            })
            .collect(),
        pairings: pairings.iter().map(pairing_view).collect(),
        ..Default::default()
    };
    for g in &grants {
        let v = grant_view(g, &names);
        if !g.as_lender {
            snap.borrowed.push(v);
        } else if v.state == "requested" {
            snap.requests.push(v);
        } else {
            snap.lent.push(v);
        }
    }
    Ok(snap)
}

fn grant_id(hex_id: &str) -> Result<Vec<u8>> {
    let id = hex::decode(hex_id).context("bad grant id")?;
    anyhow::ensure!(id.len() == 16, "bad grant id");
    Ok(id)
}

/// Turns lending on or off. Turning it on, or loosening protections, makes the daemon ask for
/// Touch ID / password first.
/// The daemon's change notifications (WatchEvents): one message per change, for refreshing
/// without polling.
pub async fn events(home: &Path) -> Result<tonic::Streaming<api::Event>> {
    Ok(gimmecores_client::control(home)
        .await?
        .watch_events(api::WatchEventsRequest {})
        .await
        .map_err(msg)?
        .into_inner())
}

pub async fn set_lending(
    home: &Path,
    enabled: bool,
    idle_only: bool,
    allow_on_battery: bool,
    allow_when_hot: bool,
) -> Result<()> {
    gimmecores_client::control(home)
        .await?
        .set_lending(api::SetLendingRequest {
            enabled,
            idle_only,
            allow_on_battery,
            allow_when_hot,
        })
        .await
        .map_err(msg)?;
    Ok(())
}

/// Chooses how tasks from other devices may run here ("container", "sandbox"). Adding one
/// makes the daemon ask for Touch ID / password first; an empty list lends nothing.
pub async fn set_lend_modes(home: &Path, modes: &[String]) -> Result<()> {
    let mut v = Vec::new();
    for m in modes {
        v.push(match m.as_str() {
            "container" => pb::ExecutionMode::Container as i32,
            "sandbox" => pb::ExecutionMode::Sandbox as i32,
            other => return Err(anyhow!("unknown runtime {other:?}")),
        });
    }
    gimmecores_client::control(home)
        .await?
        .set_lend_modes(api::SetLendModesRequest { modes: v })
        .await
        .map_err(msg)?;
    Ok(())
}

/// Revokes every grant and stops running tasks. Never asks for confirmation.
pub async fn stop_all(home: &Path) -> Result<()> {
    gimmecores_client::client(home)
        .await?
        .stop_all_lending(api::StopAllLendingRequest {
            reason: "stopped from the desktop app".into(),
        })
        .await
        .map_err(msg)?;
    Ok(())
}

/// Accept (daemon asks for Touch ID / password) or decline a request.
pub async fn respond(home: &Path, grant_hex: &str, accept: bool) -> Result<()> {
    let decision = if accept {
        api::respond_to_grant_request::Decision::Accept
    } else {
        api::respond_to_grant_request::Decision::Decline
    };
    gimmecores_client::control(home)
        .await?
        .respond_to_grant(api::RespondToGrantRequest {
            grant_id: grant_id(grant_hex)?,
            decision: decision as i32,
            edited: None,
        })
        .await
        .map_err(msg)?;
    Ok(())
}

pub async fn revoke(home: &Path, grant_hex: &str) -> Result<()> {
    gimmecores_client::control(home)
        .await?
        .revoke_grant(api::RevokeGrantRequest {
            grant_id: grant_id(grant_hex)?,
            reason: "revoked from the desktop app".into(),
        })
        .await
        .map_err(msg)?;
    Ok(())
}

/// Opens this device's 2-minute pairing window and returns its ticket.
pub async fn open_pairing(home: &Path) -> Result<Ticket> {
    let r = gimmecores_client::control(home)
        .await?
        .open_pairing(api::OpenPairingRequest {})
        .await
        .map_err(msg)?
        .into_inner();
    Ok(Ticket {
        ticket: r.ticket,
        closes_at: r.closes_at.map_or(0, |t| t.seconds),
    })
}

/// Starts pairing with the device whose ticket the user pasted.
pub async fn start_pairing(home: &Path, ticket: &str) -> Result<PairingView> {
    let s = gimmecores_client::control(home)
        .await?
        .start_pairing(api::StartPairingRequest {
            target: Some(api::start_pairing_request::Target::Ticket(
                ticket.trim().to_string(),
            )),
        })
        .await
        .map_err(msg)?
        .into_inner();
    Ok(pairing_view(&s))
}

/// Starts pairing with a nearby device (one with pairing mode open).
pub async fn start_pairing_nearby(home: &Path, fingerprint: &str) -> Result<PairingView> {
    let s = gimmecores_client::control(home)
        .await?
        .start_pairing(api::StartPairingRequest {
            target: Some(api::start_pairing_request::Target::PeerFingerprint(
                fingerprint.to_string(),
            )),
        })
        .await
        .map_err(msg)?
        .into_inner();
    Ok(pairing_view(&s))
}

/// Paired devices find each other on the local network (on), or no adverts and no listening.
pub async fn set_discovery(home: &Path, on: bool) -> Result<()> {
    let mode = if on {
        api::DiscoveryMode::PairedOnly
    } else {
        api::DiscoveryMode::Off
    };
    gimmecores_client::control(home)
        .await?
        .set_discovery(api::SetDiscoveryRequest { mode: mode as i32 })
        .await
        .map_err(msg)?;
    Ok(())
}

/// The user compared the codes. A match makes the daemon ask for Touch ID / password.
pub async fn confirm_pairing(home: &Path, session_hex: &str, codes_match: bool) -> Result<()> {
    gimmecores_client::control(home)
        .await?
        .confirm_pairing(api::ConfirmPairingRequest {
            session_id: hex::decode(session_hex).context("bad session id")?,
            codes_match,
        })
        .await
        .map_err(msg)?;
    Ok(())
}

/// Turns this device's side of Trusted mode with a paired device on or off. The window shows
/// the warning (and asks again) before it calls this with `enabled`; the daemon then asks the
/// OS to confirm the owner is present.
pub async fn set_trusted_mode(home: &Path, fingerprint: &str, enabled: bool) -> Result<()> {
    gimmecores_client::control(home)
        .await?
        .set_trusted_mode(api::SetTrustedModeRequest {
            peer_fingerprint: fingerprint.to_string(),
            enabled,
            warning_acknowledged: enabled,
        })
        .await
        .map_err(msg)?;
    Ok(())
}

pub async fn unpair(home: &Path, fingerprint: &str) -> Result<()> {
    gimmecores_client::control(home)
        .await?
        .unpair(api::UnpairRequest {
            peer_fingerprint: fingerprint.to_string(),
        })
        .await
        .map_err(msg)?;
    Ok(())
}

// ------------------------------------------------------------------ activity

/// What runs on this computer for other devices, and what ran recently.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ActivityView {
    /// Changes when a task appears, ends or changes phase (not for figures).
    pub revision: u64,
    /// Unix seconds: when GimmeCores started (history begins here).
    pub since: i64,
    pub running: Vec<ExecView>,
    pub omitted: u32,
    pub recent: Vec<GroupView>,
}

/// One task. Every figure that was not measured is `null`, never 0.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ExecView {
    /// Hex id; `short` is its first 8 characters.
    pub id: String,
    pub short: String,
    pub peer_name: String,
    pub label: String,
    /// Escaped, cut, likely secrets hidden (by the daemon).
    pub argv: Vec<String>,
    pub argv_total: u32,
    pub argv_hidden: u32,
    pub argv_cut: bool,
    pub env_names: Vec<String>,
    pub env_total: u32,
    pub image: String,
    /// "sandbox" or "container".
    pub mode: String,
    /// preparing, starting, running, frozen, stopping, collecting, ended
    pub phase: String,
    pub asked_cores: f64,
    pub asked_memory: u64,
    pub timeout_secs: Option<i64>,
    pub effective_timeout_secs: Option<i64>,
    pub cpu_limit_enforced: bool,
    pub grant_cores: f64,
    pub grant_memory: u64,
    pub grant_disk: u64,
    pub grant_until: i64,
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub run_ms: u64,
    pub frozen_ms: u64,
    /// on_battery, hot, owner_active, other, or "" when not frozen.
    pub frozen_why: String,
    pub cpu_now_cores: Option<f64>,
    pub cpu_time_ms: Option<u64>,
    pub memory_now: Option<u64>,
    pub memory_peak: Option<u64>,
    pub disk: Option<u64>,
    pub processes: Option<u32>,
    /// process_tree, container_stats, none
    pub measured_by: String,
    /// normal, reduced, background, or "" (not reported).
    pub speed: String,
    pub can_stop: bool,
    pub ending: Option<EndingView>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct EndingView {
    /// succeeded, failed, timed_out, cancelled, revoked, limit_exceeded, rejected
    pub status: String,
    /// The reason in plain words.
    pub words: String,
    pub exit_code: Option<i32>,
    pub message: String,
    pub ended_at: i64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct GroupView {
    pub key: String,
    pub peer_name: String,
    pub count: u32,
    pub succeeded: u32,
    pub failed: u32,
    pub stopped: u32,
    pub not_run: u32,
    pub first_at: i64,
    pub last_at: i64,
    pub cpu_time_total_ms: Option<u64>,
    pub cpu_measured_runs: u32,
    pub run_ms_total: u64,
    pub frozen_ms_total: u64,
    pub memory_peak_max: Option<u64>,
    pub slowest_speed: String,
    pub last: ExecView,
    pub last_problem: Option<ExecView>,
}

fn secs(t: Option<&prost_types::Timestamp>) -> i64 {
    t.map_or(0, |t| t.seconds)
}

fn speed_name(s: i32) -> String {
    match pb::ServiceSpeed::try_from(s) {
        Ok(pb::ServiceSpeed::Normal) => "normal",
        Ok(pb::ServiceSpeed::Reduced) => "reduced",
        Ok(pb::ServiceSpeed::Background) => "background",
        _ => "",
    }
    .into()
}

/// Why a task ended, in the words the window shows.
pub fn end_words(cause: i32, exit: Option<i32>) -> String {
    use pb::EndCause as C;
    match pb::EndCause::try_from(cause).unwrap_or(C::Unspecified) {
        C::Exited => match exit {
            Some(0) | None => "Finished".into(),
            Some(n) => format!("Failed with exit code {n}"),
        },
        C::Timeout => "Stopped at its time limit".into(),
        C::GrantExpired => "Stopped: the grant ran out".into(),
        C::GrantRevoked => "Stopped: you revoked the grant".into(),
        C::LendingOff => "Stopped: lending was turned off".into(),
        C::Unpaired => "Stopped: the device was unpaired".into(),
        C::TrustEnded => "Stopped: Trusted mode ended".into(),
        C::OwnerStopped => "Stopped by you".into(),
        C::PausedTooLong => "Stopped: paused for over 10 minutes".into(),
        C::MemoryLimit => "Stopped: it used more memory than it asked for".into(),
        C::DiskLimit => "Stopped: the grant's disk space ran out".into(),
        C::BorrowerCancelled => "Cancelled by the device that started it".into(),
        C::BorrowerGone => "Stopped: the device that started it went away".into(),
        C::RunnerError => "Could not start".into(),
        C::OutputError => "Ran, but its results could not be stored".into(),
        C::ServiceStopping => "Stopped: GimmeCores was stopped".into(),
        C::Refused | C::Unspecified => "Ended".into(),
    }
}

fn exec_view(e: &api::Execution) -> ExecView {
    let asked = e.asked.unwrap_or_default();
    let u = e.usage.unwrap_or_default();
    let limits = e.grant_limits.unwrap_or_default();
    let id = hex::encode(&e.id);
    ExecView {
        short: id.chars().take(8).collect(),
        id,
        peer_name: e.peer_name.clone(),
        label: e.label.clone(),
        argv: e.argv.clone(),
        argv_total: e.argv_total,
        argv_hidden: e.argv_hidden,
        argv_cut: e.argv_cut,
        env_names: e.env_names.clone(),
        env_total: e.env_total,
        image: e.image.clone(),
        mode: mode_names(&[e.mode]).into_iter().next().unwrap_or_default(),
        phase: match api::ExecPhase::try_from(e.phase) {
            Ok(api::ExecPhase::Preparing) => "preparing",
            Ok(api::ExecPhase::Uploading) => "uploading",
            Ok(api::ExecPhase::Waiting) => "waiting",
            Ok(api::ExecPhase::Starting) => "starting",
            Ok(api::ExecPhase::Running) => "running",
            Ok(api::ExecPhase::Frozen) => "frozen",
            Ok(api::ExecPhase::Stopping) => "stopping",
            Ok(api::ExecPhase::Collecting) => "collecting",
            _ => "ended",
        }
        .into(),
        asked_cores: f64::from(asked.cpu_millis) / 1000.0,
        asked_memory: asked.memory_bytes,
        timeout_secs: asked.timeout.map(|d| d.seconds),
        effective_timeout_secs: asked.effective_timeout.map(|d| d.seconds),
        cpu_limit_enforced: asked.cpu_limit_enforced,
        grant_cores: f64::from(limits.cpu_millis) / 1000.0,
        grant_memory: limits.memory_bytes,
        grant_disk: limits.disk_bytes,
        grant_until: secs(e.grant_not_after.as_ref()),
        created_at: secs(e.created_at.as_ref()),
        started_at: e.started_at.as_ref().map(|t| t.seconds),
        run_ms: u.run_ms,
        frozen_ms: u.frozen_ms,
        frozen_why: match pb::PauseCause::try_from(u.frozen_why) {
            Ok(pb::PauseCause::OnBattery) => "on_battery",
            Ok(pb::PauseCause::Hot) => "hot",
            Ok(pb::PauseCause::OwnerActive) => "owner_active",
            Ok(pb::PauseCause::Other) => "other",
            _ => "",
        }
        .into(),
        cpu_now_cores: u.cpu_millis_now.map(|m| f64::from(m) / 1000.0),
        cpu_time_ms: u.cpu_time_ms,
        memory_now: u.memory_bytes,
        memory_peak: u.memory_peak_bytes,
        disk: u.disk_bytes,
        processes: u.processes,
        measured_by: match pb::UsageSource::try_from(u.source) {
            Ok(pb::UsageSource::ProcessTree) => "process_tree",
            Ok(pb::UsageSource::ContainerStats) => "container_stats",
            _ => "none",
        }
        .into(),
        speed: speed_name(u.speed),
        can_stop: e.can_stop,
        ending: e.ending.as_ref().map(|x| EndingView {
            status: match pb::task_result::Status::try_from(x.status) {
                Ok(pb::task_result::Status::Succeeded) => "succeeded",
                Ok(pb::task_result::Status::Failed) => "failed",
                Ok(pb::task_result::Status::TimedOut) => "timed_out",
                Ok(pb::task_result::Status::Cancelled) => "cancelled",
                Ok(pb::task_result::Status::Revoked) => "revoked",
                Ok(pb::task_result::Status::LimitExceeded) => "limit_exceeded",
                Ok(pb::task_result::Status::Rejected) => "rejected",
                _ => "ended",
            }
            .into(),
            words: end_words(x.cause, x.exit_code),
            exit_code: x.exit_code,
            message: x.message.clone(),
            ended_at: secs(x.ended_at.as_ref()),
        }),
    }
}

fn group_view(g: &api::ExecutionGroup) -> GroupView {
    GroupView {
        key: hex::encode(&g.group),
        peer_name: g.peer_name.clone(),
        count: g.count,
        succeeded: g.succeeded,
        failed: g.failed,
        stopped: g.stopped,
        not_run: g.not_run,
        first_at: secs(g.first_at.as_ref()),
        last_at: secs(g.last_at.as_ref()),
        cpu_time_total_ms: g.cpu_time_ms_total,
        cpu_measured_runs: g.cpu_measured_runs,
        run_ms_total: g.run_ms_total,
        frozen_ms_total: g.frozen_ms_total,
        memory_peak_max: g.memory_peak_bytes_max,
        slowest_speed: speed_name(g.slowest_speed),
        last: g.last.as_ref().map(exec_view).unwrap_or_default(),
        last_problem: g.last_problem.as_ref().map(exec_view),
    }
}

pub fn activity_view(a: &api::Activity) -> ActivityView {
    ActivityView {
        revision: a.revision,
        since: secs(a.since.as_ref()),
        running: a.running.iter().map(exec_view).collect(),
        omitted: a.running_here_omitted,
        recent: a.recent.iter().map(group_view).collect(),
    }
}

/// What runs here and what ran recently (Control socket).
pub async fn activity(home: &Path) -> Result<ActivityView> {
    let a = gimmecores_client::control(home)
        .await?
        .list_activity(api::ListActivityRequest { known_revision: 0 })
        .await
        .map_err(msg)?
        .into_inner();
    Ok(activity_view(&a))
}

/// Stops one task running here for another device. Never asks for confirmation (it only
/// reduces access).
pub async fn stop_task(home: &Path, task_hex: &str) -> Result<()> {
    let id = hex::decode(task_hex).context("bad task id")?;
    anyhow::ensure!(id.len() == 16, "bad task id");
    gimmecores_client::control(home)
        .await?
        .stop_task(api::StopTaskRequest { task_id: id })
        .await
        .map_err(msg)?;
    Ok(())
}
