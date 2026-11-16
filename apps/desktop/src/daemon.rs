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
    /// Devices holding a grant from this one may see how busy this whole computer is.
    pub share_load: bool,
    /// How tasks from other devices run here: "full", "apps-first" or "background".
    pub task_speed: String,
    /// Idle sleep is held off while tasks from other devices run, and is held off now.
    pub keep_awake: bool,
    pub keeping_awake: bool,
    /// Grants for this computer's sandbox list its tools and versions.
    pub share_tools: bool,
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
    /// The speed the grant names: "full", "apps-first", "background", or "" (none: tasks follow
    /// the lender's setting).
    pub speed: String,
    /// Bytes of container images the borrower may send (0: none).
    pub images_gib: f64,
    /// Accepted by a standing grant, without anyone asked at the time.
    pub by_rule: bool,
}

fn task_speed_name(v: i32) -> String {
    match pb::TaskSpeed::try_from(v) {
        Ok(pb::TaskSpeed::Full) => "full",
        Ok(pb::TaskSpeed::AppsFirst) => "apps-first",
        Ok(pb::TaskSpeed::Background) => "background",
        Ok(pb::TaskSpeed::Unspecified) => "",
        // A level this app does not know: shown as the slowest, never as full.
        Err(_) => "background",
    }
    .into()
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
    /// This computer's owner lets that device wake it (Wake-on-LAN).
    pub wake_allowed: bool,
    /// That device lets this one wake it.
    pub can_wake: bool,
    /// This computer's standing grant for that device: what it accepts without asking.
    pub standing: Option<StandingView>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct StandingView {
    pub cores: f64,
    pub memory_gib: f64,
    pub disk_gib: f64,
    pub modes: Vec<String>,
    /// The fastest speed it approves ("" : none faster than the owner's setting).
    pub speed: String,
    pub images_gib: f64,
    pub max_hours: u32,
    /// Unix seconds when it lapses.
    pub until: i64,
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
        speed: g
            .grant
            .as_ref()
            .map_or(String::new(), |x| task_speed_name(x.speed)),
        images_gib: g.grant.as_ref().map_or(0, |x| x.images_bytes) as f64 / GIB,
        by_rule: g.grant.as_ref().is_some_and(|x| x.by_standing_rule),
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
            share_load: st.share_load,
            keep_awake: st.keep_awake,
            keeping_awake: st.keeping_awake,
            share_tools: st.share_tools,
            task_speed: match task_speed_name(st.task_speed).as_str() {
                "" => "apps-first".into(),
                s => s.into(),
            },
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
                wake_allowed: p.wake_allowed,
                can_wake: p.can_wake,
                standing: p.standing.as_ref().map(|r| {
                    let l = r.limits.unwrap_or_default();
                    StandingView {
                        cores: f64::from(l.cpu_millis) / 1000.0,
                        memory_gib: l.memory_bytes as f64 / GIB,
                        disk_gib: l.disk_bytes as f64 / GIB,
                        modes: mode_names(&r.modes),
                        speed: task_speed_name(r.speed),
                        images_gib: r.images_bytes as f64 / GIB,
                        max_hours: r.max_hours,
                        until: r.until.map_or(0, |t| t.seconds),
                    }
                }),
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
/// Accepts or declines a request. `always` also creates a standing grant with its terms, said
/// in the same presence prompt (Standard requests only).
pub async fn respond(home: &Path, grant_hex: &str, accept: bool, always: bool) -> Result<()> {
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
            always: accept && always,
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
/// How tasks from other devices run here ("full", "apps-first", "background"). A faster
/// level asks for Touch ID, Windows Hello or the password (gmcd does).
pub async fn set_task_speed(home: &Path, speed: &str) -> Result<()> {
    let v = match speed {
        "full" => pb::TaskSpeed::Full,
        "apps-first" => pb::TaskSpeed::AppsFirst,
        "background" => pb::TaskSpeed::Background,
        other => return Err(anyhow!("unknown speed {other:?}")),
    };
    gimmecores_client::control(home)
        .await?
        .set_task_speed(api::SetTaskSpeedRequest { speed: v as i32 })
        .await
        .map_err(msg)?;
    Ok(())
}

/// Lists this computer's tools in the grants it gives for its sandbox. Turning it on asks for
/// Touch ID, Windows Hello or the password (gmcd does).
pub async fn set_share_tools(home: &Path, enabled: bool) -> Result<()> {
    gimmecores_client::control(home)
        .await?
        .set_share_tools(api::SetShareToolsRequest { enabled })
        .await
        .map_err(msg)?;
    Ok(())
}

/// Keeps this computer awake while tasks from other devices run. Turning it on asks for
/// Touch ID, Windows Hello or the password (gmcd does).
pub async fn set_keep_awake(home: &Path, enabled: bool) -> Result<()> {
    gimmecores_client::control(home)
        .await?
        .set_keep_awake(api::SetKeepAwakeRequest { enabled })
        .await
        .map_err(msg)?;
    Ok(())
}

/// Lets devices holding a grant see how busy this whole computer is. Turning it on asks for
/// Touch ID, Windows Hello or the password (gmcd does).
pub async fn set_share_load(home: &Path, enabled: bool) -> Result<()> {
    gimmecores_client::control(home)
        .await?
        .set_share_load(api::SetShareLoadRequest { enabled })
        .await
        .map_err(msg)?;
    Ok(())
}

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

/// Lets a paired device wake this computer (Wake-on-LAN), or stops letting it. Allowing asks
/// for Touch ID, Windows Hello or the password (gmcd does).
pub async fn set_wake_allowed(home: &Path, fingerprint: &str, allowed: bool) -> Result<()> {
    gimmecores_client::control(home)
        .await?
        .set_wake_allowed(api::SetWakeAllowedRequest {
            peer_fingerprint: fingerprint.to_string(),
            allowed,
        })
        .await
        .map_err(msg)?;
    Ok(())
}

/// Ends this computer's standing grant for a device and revokes the grants it accepted (no
/// presence: it reduces access).
pub async fn end_standing(home: &Path, fingerprint: &str) -> Result<()> {
    gimmecores_client::control(home)
        .await?
        .set_standing_rule(api::SetStandingRuleRequest {
            peer_fingerprint: fingerprint.to_string(),
            rule: None,
        })
        .await
        .map_err(msg)?;
    Ok(())
}

/// Sends a paired device a wake-up (it must have let this one wake it).
pub async fn wake(home: &Path, fingerprint: &str) -> Result<()> {
    gimmecores_client::client(home)
        .await?
        .wake_peer(api::WakePeerRequest {
            peer_fingerprint: fingerprint.to_string(),
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
    /// This computer as a whole; `None` from a gmcd that does not report it.
    pub machine: Option<MachineView>,
    /// This device's own tasks running on other devices (never in `running`, which is only
    /// what runs here). Figures are the lenders' reports.
    pub there: Vec<ExecView>,
    /// Per grant this device holds: what its tasks there use, as the lender reports.
    pub borrowed: Vec<BorrowedLoadView>,
}

/// What this device's tasks use on one lender, as it reports. `null` figures: not reported.
#[derive(Clone, Debug, Default, Serialize)]
pub struct BorrowedLoadView {
    /// Hex grant id (as in `GrantView::id`).
    pub grant_id: String,
    pub peer_name: String,
    pub grant_cores: f64,
    pub grant_memory: u64,
    pub tasks: u32,
    pub running: u32,
    pub cpu_cores: Option<f64>,
    pub memory: Option<u64>,
    /// The lender's whole computer, if its owner shares it (`None`: not known yet).
    pub lender: Option<LenderLoadView>,
}

/// A lender's whole computer as it shares it (every program on it, its owner's included).
#[derive(Clone, Debug, Default, Serialize)]
pub struct LenderLoadView {
    /// `false`: its owner does not share it; nothing else is set.
    pub shared: bool,
    pub cores: u32,
    pub cpu_busy_cores: Option<f64>,
    pub memory_total: u64,
    pub memory_used: Option<u64>,
    pub gpus: Vec<GpuView>,
}

fn borrowed_load_view(b: &api::BorrowedLoad) -> BorrowedLoadView {
    let limits = b.grant_limits.unwrap_or_default();
    BorrowedLoadView {
        grant_id: hex::encode(&b.grant_id),
        peer_name: b.peer_name.clone(),
        grant_cores: f64::from(limits.cpu_millis) / 1000.0,
        grant_memory: limits.memory_bytes,
        tasks: b.tasks,
        running: b.running,
        cpu_cores: b.cpu_millis.map(|m| f64::from(m) / 1000.0),
        memory: b.memory_bytes,
        lender: b.lender.as_ref().map(|l| LenderLoadView {
            shared: l.shared,
            cores: l.cpu_cores,
            cpu_busy_cores: l.cpu_busy_millis.map(|m| f64::from(m) / 1000.0),
            memory_total: l.memory_total_bytes,
            memory_used: l.memory_used_bytes,
            gpus: l
                .gpus
                .iter()
                .map(|g| GpuView {
                    name: g.name.clone(),
                    memory: 0,
                    busy_percent: g.busy_percent.filter(|p| *p <= 100),
                })
                .collect(),
        }),
    }
}

/// This computer as a whole. Every figure that was not measured is `null`, never 0; the
/// "lent" figures are what tasks from other devices use now (`null` while one of them is not
/// measured, so it is never counted as the owner's own use).
#[derive(Clone, Debug, Default, Serialize)]
pub struct MachineView {
    pub cores: u32,
    pub cpu_busy_cores: Option<f64>,
    pub cpu_lent_cores: Option<f64>,
    pub memory_total: u64,
    pub memory_used: Option<u64>,
    pub memory_lent: Option<u64>,
    pub gpus: Vec<GpuView>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct GpuView {
    pub name: String,
    /// Its own memory; 0 when it shares the system's or it is not known.
    pub memory: u64,
    pub busy_percent: Option<u32>,
}

fn machine_view(m: &api::MachineLoad) -> MachineView {
    let cores = |v: Option<u32>| v.map(|m| f64::from(m) / 1000.0);
    MachineView {
        cores: m.cpu_cores,
        cpu_busy_cores: cores(m.cpu_busy_millis),
        cpu_lent_cores: cores(m.lent_cpu_millis),
        memory_total: m.memory_total_bytes,
        memory_used: m.memory_used_bytes,
        memory_lent: m.lent_memory_bytes,
        gpus: m
            .gpus
            .iter()
            .map(|g| GpuView {
                name: g.name.clone(),
                memory: g.memory_bytes,
                busy_percent: g.busy_percent.filter(|p| *p <= 100),
            })
            .collect(),
    }
}

/// One task. Every figure that was not measured is `null`, never 0.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ExecView {
    /// Hex id; `short` is its first 8 characters.
    pub id: String,
    pub short: String,
    /// Hex grant id.
    pub grant_id: String,
    /// The figures are another device's report (this device's task running there).
    pub reported_by_peer: bool,
    /// The level it runs at ("full", "apps-first", "background", "" not reported), and
    /// whether its runner applies levels.
    pub task_speed: String,
    pub task_speed_applied: bool,
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
        grant_id: hex::encode(&e.grant_id),
        reported_by_peer: u.reported_by_peer,
        task_speed: task_speed_name(u.task_speed),
        task_speed_applied: u.task_speed_applied,
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
        running: a
            .running
            .iter()
            .filter(|e| e.direction != api::Direction::There as i32)
            .map(exec_view)
            .collect(),
        there: a
            .running
            .iter()
            .filter(|e| e.direction == api::Direction::There as i32)
            .map(exec_view)
            .collect(),
        borrowed: a.borrowed.iter().map(borrowed_load_view).collect(),
        omitted: a.running_here_omitted,
        recent: a.recent.iter().map(group_view).collect(),
        machine: a.machine.as_ref().map(machine_view),
    }
}

/// What runs here and what ran recently (Control socket).
pub async fn activity(home: &Path) -> Result<ActivityView> {
    let a = gimmecores_client::control(home)
        .await?
        .list_activity(api::ListActivityRequest {
            known_revision: 0,
            include_there: true,
        })
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
