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
