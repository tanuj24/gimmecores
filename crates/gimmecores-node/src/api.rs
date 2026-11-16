//! The local API (`spec/proto/gimmecores/local/v1/local.proto`): gRPC over owner-only Unix
//! sockets. **Client** (submit work, ask for grants) and **Control** (consent actions) are
//! served on separate sockets so code that submits work can never reach consent actions (I13).
//!
//! Control calls marked `[presence]` in the spec ask the OS to verify that the owner is present
//! (Touch ID / login password on macOS, polkit on Linux) before they act, here in the daemon,
//! so a process that reaches the Control socket still cannot approve anything by itself (I13).

use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

use anyhow::Result;
use gimmecores_core::{GrantId, GrantState, PeerKey};
use gimmecores_proto::local::v1 as api;
use gimmecores_proto::local::v1::client_server::{Client, ClientServer};
use gimmecores_proto::local::v1::control_server::{Control, ControlServer};
use gimmecores_proto::peer::v1 as pb;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::grants_flow::{Decision, GrantOutcome, terms_from_request};
use crate::node::{Node, PairStatus, PairingView};
use crate::tasks_flow::{DEFAULT_TIMEOUT, TaskSpec, TaskStatus};
use crate::{now, wire};

type Res<T> = Result<Response<T>, Status>;

fn internal(e: impl std::fmt::Display) -> Status {
    Status::internal(e.to_string())
}

/// A peer-chosen name as shown inside an OS prompt: no quotes to break out of the quoted name,
/// and short.
fn prompt_name(name: &str) -> String {
    wire::clean_name(name)
        .chars()
        .map(|c| if c == '"' { '\'' } else { c })
        .take(40)
        .collect()
}

fn refused(e: crate::node::PresenceRefused) -> Status {
    Status::permission_denied(e.to_string())
}

/// "2 cores, 4 GiB memory, 10 GiB disk, for 1 hour".
fn describe_terms(t: &gimmecores_core::GrantTerms) -> String {
    let l = &t.limits;
    let cores = f64::from(l.cpu_millis) / 1000.0;
    let gib = |b: u64| b as f64 / f64::from(1u32 << 30);
    let mins = t.not_after.saturating_sub(now()).div_ceil(60);
    let time = if mins >= 120 {
        format!("{} hours", mins.div_ceil(60))
    } else {
        format!("{mins} minutes")
    };
    let modes: Vec<&str> = t
        .modes
        .iter()
        .map(|m| match m {
            // The borrower names the image: any one on this computer, the owner's own included.
            gimmecores_core::ExecutionMode::Container => {
                "in a container (it can run and read any Docker image on this computer)"
            }
            gimmecores_core::ExecutionMode::Sandbox => "in this computer's sandbox",
            gimmecores_core::ExecutionMode::Native => "as you, without a sandbox",
        })
        .collect();
    let trusted = if t.trust == gimmecores_core::TrustLevel::Trusted {
        ", TRUSTED (Python objects may be exchanged both ways)"
    } else {
        ""
    };
    // A named speed is fixed by this approval, so the prompt always says it.
    let speed = t.speed.map_or(String::new(), |s| {
        format!(", speed: {}", crate::speed::describe(s))
    });
    // Sending images puts the borrower's own software on this disk, so the prompt says so.
    let images = if t.images_bytes > 0 {
        format!(
            ", may send its own container images up to {:.1} GiB",
            gib(t.images_bytes)
        )
    } else {
        String::new()
    };
    format!(
        "{cores} cores, {:.1} GiB memory, {:.1} GiB disk, for {time}, {}{images}{speed}{trusted}",
        gib(l.memory_bytes),
        gib(l.disk_bytes),
        modes.join(" or ")
    )
}

/// Shown before Trusted mode is turned on (threat model, section 6).
pub const TRUSTED_MODE_WARNING: &str = "Trusted mode lets this device run any code on your \
     machine through returned results. Only enable it between your own devices or someone you \
     trust completely.";

/// The SDK's own files sent with a task (its worker's payload).
const MAX_INLINE_FILES: usize = 64 << 20;

fn grant_id(b: &[u8]) -> Result<GrantId, Status> {
    b.try_into()
        .map(GrantId)
        .map_err(|_| Status::invalid_argument("grant id must be 16 bytes"))
}

fn find_peer(node: &Node, who: &str) -> Result<PeerKey, Status> {
    node.find_peer(who)
        .ok_or_else(|| Status::not_found(format!("no paired device named {who:?}")))
}

/// A standing grant as the API shows it.
fn rule_to_proto(r: &crate::standing::StandingRule) -> api::StandingRule {
    api::StandingRule {
        limits: Some(pb::Limits {
            cpu_millis: r.cpu_millis,
            memory_bytes: r.memory_bytes,
            disk_bytes: r.disk_bytes,
            ..Default::default()
        }),
        modes: crate::grants_flow::modes_to(r.modes()),
        speed: crate::grants_flow::speed_to(
            r.speed
                .as_deref()
                .and_then(gimmecores_core::Speed::from_name),
        ) as i32,
        images_bytes: r.images_bytes,
        max_hours: r.max_hours,
        created_at: Some(ts(r.created_at)),
        until: Some(ts(r.until)),
    }
}

/// The terms a standing grant in a request allows (its end is set per grant).
fn rule_terms(r: &api::StandingRule) -> gimmecores_core::GrantTerms {
    let l = r.limits.unwrap_or_default();
    gimmecores_core::GrantTerms {
        limits: gimmecores_core::Limits {
            cpu_millis: l.cpu_millis,
            memory_bytes: l.memory_bytes,
            disk_bytes: if l.disk_bytes == 0 {
                10 << 30
            } else {
                l.disk_bytes
            },
            gpu: gimmecores_core::Gpu::None,
            max_concurrent_tasks: l.cpu_millis.div_ceil(1000).max(1),
        },
        not_after: 0,
        modes: crate::grants_flow::modes_from(&r.modes),
        network: gimmecores_core::NetworkPolicy::None,
        trust: gimmecores_core::TrustLevel::Standard,
        speed: crate::grants_flow::speed_from(r.speed),
        images_bytes: r.images_bytes,
    }
}

/// A presence refusal as permission denied; anything else as a failed precondition.
fn refused_or_failed(e: &anyhow::Error) -> Status {
    match e.downcast_ref::<crate::node::PresenceRefused>() {
        Some(p) => refused(p.clone()),
        None => Status::failed_precondition(format!("{e:#}")),
    }
}

fn ts(secs: u64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: i64::try_from(secs).unwrap_or(i64::MAX),
        nanos: 0,
    }
}

fn state_proto(s: GrantState) -> i32 {
    (match s {
        GrantState::Requested => pb::GrantState::Requested,
        GrantState::Offered => pb::GrantState::Offered,
        GrantState::Active => pb::GrantState::Active,
        GrantState::Paused => pb::GrantState::Paused,
        GrantState::Expired => pb::GrantState::Expired,
        GrantState::Revoked => pb::GrantState::Revoked,
        GrantState::Declined => pb::GrantState::Declined,
    }) as i32
}

fn pairing_proto(v: &PairingView) -> api::PairingSession {
    let (state, error) = match &v.status {
        PairStatus::Waiting => (api::pairing_session::State::Waiting, String::new()),
        PairStatus::CompareCode => (api::pairing_session::State::CompareCode, String::new()),
        PairStatus::Paired => (api::pairing_session::State::Paired, String::new()),
        PairStatus::Failed(e) => (api::pairing_session::State::Failed, e.clone()),
    };
    api::PairingSession {
        session_id: v.id.to_be_bytes().to_vec(),
        peer_device_name: v.peer_name.clone(),
        peer_fingerprint: v.peer.fingerprint(),
        code: v.code.map(|c| c.to_string()).unwrap_or_default(),
        state: state as i32,
        error,
        name_previously_seen_with_other_key: v.name_previously_seen_with_other_key,
    }
}

fn session_id(b: &[u8]) -> Result<u64, Status> {
    let arr: [u8; 8] = b
        .try_into()
        .map_err(|_| Status::invalid_argument("bad session id"))?;
    Ok(u64::from_be_bytes(arr))
}

#[derive(Clone)]
pub struct ClientApi(pub Node);

#[derive(Clone)]
pub struct ControlApi(pub Node);

impl ClientApi {
    fn status(&self) -> api::Status {
        let n = &self.0;
        api::Status {
            device_name: n.name().to_string(),
            fingerprint: n.key().fingerprint(),
            version: crate::software_version().to_string(),
            program_removed: n
                .program_removed()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            lending_enabled: n.lending_enabled(),
            discovery: match n.discovery_mode() {
                crate::discovery::DiscoveryMode::Off => api::DiscoveryMode::Off,
                crate::discovery::DiscoveryMode::PairedOnly => api::DiscoveryMode::PairedOnly,
            } as i32,
            capabilities: Some(crate::caps::capabilities(
                n.lending_enabled(),
                n.lend_modes().0,
                n.lend_modes().1,
            )),
            active_lent_tasks: u32::try_from(n.running_task_count()).unwrap_or(u32::MAX),
            active_borrowed_tasks: 0,
            pause_reason: n.pause_reason().unwrap_or_default(),
            idle_only: n.protections().idle_only,
            pause_on_battery: n.protections().pause_on_battery,
            pause_when_hot: n.protections().pause_when_hot,
            presence_required: n.presence().0,
            presence_method: n.presence().1.to_string(),
            identity_store: crate::identity::current_store(n.paths())
                .describe()
                .to_string(),
            lend_modes: crate::grants_flow::modes_to(n.lend_modes().0),
            available_modes: crate::grants_flow::modes_to(n.lend_modes().1),
            performance_note: n.slow_reason().unwrap_or_default().to_string(),
            share_load: n.share_load(),
            keep_awake: n.keep_awake(),
            keeping_awake: n.keeping_awake(),
            share_tools: n.share_tools(),
            tools: crate::tools::to_proto(&n.tools()),
            task_speed: crate::grants_flow::speed_to(Some(n.task_speed())) as i32,
        }
    }
}

#[tonic::async_trait]
impl Client for ClientApi {
    async fn get_status(&self, _: Request<api::GetStatusRequest>) -> Res<api::Status> {
        Ok(Response::new(self.status()))
    }

    async fn list_peers(&self, req: Request<api::ListPeersRequest>) -> Res<api::ListPeersResponse> {
        let include_discovered = req.into_inner().include_discovered;
        let mut peers: Vec<api::Peer> = self
            .0
            .paired_peers_detailed()
            .into_iter()
            .map(|(key, name, paired_at)| api::Peer {
                fingerprint: key.fingerprint(),
                device_name: name,
                paired: true,
                paired_at: Some(ts(paired_at)),
                trusted_mode_local: self.0.trusted_until(&key).is_some(),
                trusted_until: self.0.trusted_until(&key).map(ts),
                // Only what the peer's own grants say (a claim, for display).
                trusted_mode_remote: self.0.borrowed_grants().iter().any(|(_, b)| {
                    b.lender == key
                        && b.terms.trust == gimmecores_core::TrustLevel::Trusted
                        && b.terms.not_after > now()
                }),
                links: self
                    .0
                    .last_link(&key)
                    .map(|l| l.to_proto())
                    .into_iter()
                    .collect(),
                software_version: self.0.peer_version(&key).map(|v| v.0).unwrap_or_default(),
                wake_allowed: self.0.wake_allowed(&key),
                can_wake: !self.0.wake_macs(&key).is_empty(),
                version_seen: self.0.peer_version(&key).map(|v| ts(v.1)),
                standing: self.0.standing_rule(&key).as_ref().map(rule_to_proto),
                ..Default::default()
            })
            .collect();
        if include_discovered {
            // Devices nearby with pairing mode open (only their own adverts say so).
            peers.extend(self.0.nearby().into_iter().map(|n| api::Peer {
                fingerprint: n.key.fingerprint(),
                device_name: n.name,
                paired: false,
                online: true,
                ..Default::default()
            }));
        }
        Ok(Response::new(api::ListPeersResponse { peers }))
    }

    async fn link_test(&self, req: Request<api::LinkTestRequest>) -> Res<api::LinkStats> {
        let peer = find_peer(&self.0, &req.into_inner().peer_fingerprint)?;
        let stats = self.0.link_test(&peer).await.map_err(internal)?;
        Ok(Response::new(stats.to_proto()))
    }

    async fn request_grant(&self, req: Request<api::RequestGrantRequest>) -> Res<api::GrantInfo> {
        let r = req.into_inner();
        let lender = find_peer(&self.0, &r.peer_fingerprint)?;
        let wanted = r
            .request
            .ok_or_else(|| Status::invalid_argument("missing request"))?;
        let terms = terms_from_request(&wanted, now())
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let outcome = if r.no_wait {
            self.0
                .request_grant_queued(&lender, &terms, &wanted.reason)
                .await
                .map_err(|e| Status::failed_precondition(format!("{e:#}")))?
        } else {
            self.0
                .request_grant(&lender, &terms, &wanted.reason)
                .await
                .map_err(internal)?
        };
        Ok(Response::new(match outcome {
            // Kept for the lender's owner; ListGrants shows it until it is answered.
            GrantOutcome::Queued {
                request_id,
                expires_at,
            } => api::GrantInfo {
                request_id,
                peer_fingerprint: lender.fingerprint(),
                state: pb::GrantState::Requested as i32,
                state_reason: format!("waiting for its owner until {expires_at}"),
                ..Default::default()
            },
            GrantOutcome::Granted { id, .. } => api::GrantInfo {
                grant_id: id.0.to_vec(),
                peer_fingerprint: lender.fingerprint(),
                as_lender: false,
                state: pb::GrantState::Active as i32,
                // The grant as the lender signed it (verified when it was stored).
                grant: self
                    .0
                    .borrowed_grants()
                    .into_iter()
                    .find(|(g, _)| *g == id)
                    .and_then(|(_, b)| {
                        crate::grants_flow::verify_signed(&b.signed, &b.lender, &self.0.key()).ok()
                    }),
                ..Default::default()
            },
            GrantOutcome::Declined(reason) => api::GrantInfo {
                peer_fingerprint: lender.fingerprint(),
                state: pb::GrantState::Declined as i32,
                state_reason: reason,
                ..Default::default()
            },
            // The request lapsed: nobody there decided. Clients tell this from a refusal.
            GrantOutcome::NoAnswer => api::GrantInfo {
                peer_fingerprint: lender.fingerprint(),
                state: pb::GrantState::Expired as i32,
                state_reason: "nobody answered on that device in time".into(),
                ..Default::default()
            },
        }))
    }

    async fn list_grants(
        &self,
        req: Request<api::ListGrantsRequest>,
    ) -> Res<api::ListGrantsResponse> {
        let include_inactive = req.into_inner().include_inactive;
        let n = &self.0;
        let mut grants = Vec::new();
        for r in n.incoming_requests() {
            grants.push(api::GrantInfo {
                grant_id: r.id.0.to_vec(),
                peer_fingerprint: r.borrower.fingerprint(),
                as_lender: true,
                state: pb::GrantState::Requested as i32,
                grant: Some(n.grant_proto(r.id, r.borrower, &r.requested, &[], None)),
                state_reason: format!("{} asks: {}", r.borrower_name, r.reason),
                ..Default::default()
            });
        }
        for (id, borrower, state, terms, running) in n.lent_grants() {
            if state == GrantState::Requested || (!include_inactive && state.is_terminal()) {
                continue;
            }
            grants.push(api::GrantInfo {
                grant_id: id.0.to_vec(),
                peer_fingerprint: borrower.fingerprint(),
                as_lender: true,
                state: state_proto(state),
                grant: Some(n.grant_proto(id, borrower, &terms, &[], n.issued_at(id))),
                state_reason: format!("{running} task(s) running"),
                ..Default::default()
            });
        }
        // Requests a lender keeps for its owner (#23): what was asked, until when.
        for w in n.waiting_requests() {
            let terms = terms_from_request(&w.request, w.asked_at).ok();
            grants.push(api::GrantInfo {
                request_id: w.request.request_id.clone(),
                peer_fingerprint: w.lender.fingerprint(),
                as_lender: false,
                state: pb::GrantState::Requested as i32,
                grant: Some(pb::Grant {
                    limits: w.request.limits,
                    modes: w.request.modes.clone(),
                    not_after: Some(ts(w.expires_at)),
                    trust: w.request.trust,
                    speed: w.request.speed,
                    images_bytes: w.request.images_bytes,
                    ..Default::default()
                }),
                state_reason: format!(
                    "waiting for its owner; asked for {} h",
                    terms.map_or(0, |t| t.not_after.saturating_sub(w.asked_at).div_ceil(3600))
                ),
                ..Default::default()
            });
        }
        for (id, b) in n.borrowed_grants() {
            if !include_inactive && b.terms.not_after <= now() {
                continue;
            }
            grants.push(api::GrantInfo {
                grant_id: id.0.to_vec(),
                peer_fingerprint: b.lender.fingerprint(),
                as_lender: false,
                state: pb::GrantState::Active as i32,
                grant: crate::grants_flow::verify_signed(&b.signed, &b.lender, &n.key()).ok(),
                ..Default::default()
            });
        }
        Ok(Response::new(api::ListGrantsResponse { grants }))
    }

    async fn plan_job(&self, _: Request<api::JobSpec>) -> Res<api::JobPlan> {
        Err(Status::unimplemented("planning is not implemented yet"))
    }

    type SubmitJobStream = Pin<Box<dyn Stream<Item = Result<api::JobEvent, Status>> + Send>>;

    async fn submit_job(&self, req: Request<api::JobSpec>) -> Res<Self::SubmitJobStream> {
        let job = req.into_inner();
        let task = job
            .inline_tasks
            .first()
            .cloned()
            .ok_or_else(|| Status::invalid_argument("no task given"))?;
        let Some(pb::submit_task::Work::Command(cmd)) = task.work.clone().map(|w| match w {
            api::inline_task::Work::Command(c) => pb::submit_task::Work::Command(c),
            api::inline_task::Work::Call(c) => pb::submit_task::Work::Call(c),
        }) else {
            return Err(Status::invalid_argument("only command tasks are supported"));
        };
        let node = self.0.clone();
        // Pick a usable grant: from the named peer if given, otherwise any active one.
        let wanted_peer = match task.peers.first() {
            Some(p) => Some(find_peer(&node, p)?),
            None => None,
        };
        // A Trusted job runs only under a Trusted grant, and only while this device's own
        // Trusted mode for that lender is on: this side's flag is what protects this side.
        let trusted = job.trusted;
        let (grant, lender) = node
            .borrowed_grants()
            .into_iter()
            .filter(|(_, b)| b.terms.not_after > now())
            .filter(|(_, b)| {
                !trusted
                    || (b.terms.trust == gimmecores_core::TrustLevel::Trusted
                        && node.is_trusted(&b.lender))
            })
            .filter(|(_, b)| wanted_peer.is_none_or(|p| p == b.lender))
            // The one that lasts longest: a renewed grant over the one it replaces.
            .max_by_key(|(_, b)| b.terms.not_after)
            .map(|(id, b)| (id, b.lender))
            .ok_or_else(|| {
                Status::failed_precondition(if trusted {
                    "no Trusted grant: turn on Trusted mode for each other on both devices \
                     (`gmc trust <device> on`), then `gmc grants request <device> --trusted`"
                } else {
                    "no active grant; ask for one with `gmc grants request`"
                })
            })?;
        let mut extra_files = Vec::with_capacity(task.files.len());
        let mut extra_bytes = 0usize;
        for f in task.files {
            extra_bytes = extra_bytes.saturating_add(f.data.len());
            if extra_bytes > MAX_INLINE_FILES {
                return Err(Status::invalid_argument("the SDK's files are over 64 MiB"));
            }
            extra_files.push((f.path, f.data));
        }
        let attachments = task
            .attachments
            .into_iter()
            .map(|a| crate::tree::Attachment {
                local: std::path::PathBuf::from(a.local_path),
                path: a.path,
                packages: a.packages,
            })
            .collect();
        let limits = task.resources.unwrap_or_default();
        let image = match task.env.and_then(|e| e.kind) {
            Some(pb::environment::Kind::Image(i)) => Some(i.reference),
            _ => None,
        };
        let mode = match task.mode {
            0 => None,
            v => Some(
                crate::grants_flow::mode_from(v)
                    .ok_or_else(|| Status::invalid_argument("unknown way of running tasks"))?,
            ),
        };
        let spec = TaskSpec {
            // Agents (`gmc mcp`) only ever name an image; the CLI and the SDK may send one.
            send_image: !task.name_image_only,
            caches: task.caches.clone(),
            speed: crate::grants_flow::speed_from(task.speed),
            dir: std::path::PathBuf::from(&job.project_root),
            argv: cmd.argv,
            image,
            mode,
            outputs: task.outputs,
            excludes: task.excludes,
            extra_files,
            attachments,
            env: cmd
                .environment
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            output_dir: match task.output_dir.as_str() {
                "" => None,
                d if std::path::Path::new(d).is_absolute() => Some(std::path::PathBuf::from(d)),
                _ => {
                    return Err(Status::invalid_argument(
                        "output_dir must be an absolute path",
                    ));
                }
            },
            allow_secrets: job
                .confirmed_sensitive_paths
                .iter()
                .map(std::path::PathBuf::from)
                .collect(),
            cpu_millis: if limits.cpu_millis == 0 {
                1000
            } else {
                limits.cpu_millis
            },
            memory_bytes: if limits.memory_bytes == 0 {
                1 << 30
            } else {
                limits.memory_bytes
            },
            timeout: task
                .timeout
                .and_then(|d| u64::try_from(d.seconds).ok())
                .map_or(DEFAULT_TIMEOUT, Duration::from_secs),
        };
        let (tx, rx) = mpsc::channel::<Result<api::JobEvent, Status>>(64);
        tokio::spawn(async move {
            let (log_tx, mut log_rx) = mpsc::channel(64);
            let fwd_tx = tx.clone();
            let lender_fp = lender.fingerprint();
            let fp = lender_fp.clone();
            let forward = tokio::spawn(async move {
                while let Some(chunk) = log_rx.recv().await {
                    let chunk: crate::exec::LogChunk = chunk;
                    let ev = api::JobEvent {
                        task_name: "task".into(),
                        peer_fingerprint: fp.clone(),
                        event: Some(api::job_event::Event::Task(pb::TaskEvent {
                            task_id: vec![],
                            event: Some(pb::task_event::Event::Log(pb::LogChunk {
                                stream: if chunk.stderr {
                                    pb::log_chunk::Stream::Stderr as i32
                                } else {
                                    pb::log_chunk::Stream::Stdout as i32
                                },
                                data: chunk.data,
                            })),
                        })),
                        ..Default::default()
                    };
                    if fwd_tx.send(Ok(ev)).await.is_err() {
                        break;
                    }
                }
            });
            // A client that hangs up (Ctrl-C in `gmc run`, an SDK process that exits, an agent
            // session that ends) cancels its task: the lender stops it and frees what it held.
            let cancel = tokio_util::sync::CancellationToken::new();
            let hangup = {
                let (tx, cancel) = (tx.clone(), cancel.clone());
                tokio::spawn(async move {
                    tx.closed().await;
                    cancel.cancel();
                })
            };
            // The lender's "started" (with the task's speed) goes to the client as it comes.
            let (started_tx, started_rx) = tokio::sync::oneshot::channel::<pb::Started>();
            let started = {
                let (tx, fp) = (tx.clone(), lender_fp.clone());
                tokio::spawn(async move {
                    if let Ok(s) = started_rx.await {
                        let _ = tx
                            .send(Ok(api::JobEvent {
                                task_name: "task".into(),
                                peer_fingerprint: fp,
                                event: Some(api::job_event::Event::Task(pb::TaskEvent {
                                    task_id: vec![],
                                    event: Some(pb::task_event::Event::Started(s)),
                                })),
                                ..Default::default()
                            }))
                            .await;
                    }
                })
            };
            let report = node
                .run_task_watched(&lender, grant, spec, log_tx, cancel, Some(started_tx))
                .await;
            let _ = started.await;
            hangup.abort();
            let _ = forward.await;
            let final_event = match report {
                Ok(r) => {
                    let status = match r.status {
                        TaskStatus::Succeeded => pb::task_result::Status::Succeeded,
                        TaskStatus::Failed => pb::task_result::Status::Failed,
                        TaskStatus::TimedOut => pb::task_result::Status::TimedOut,
                        TaskStatus::Cancelled => pb::task_result::Status::Cancelled,
                        TaskStatus::Revoked => pb::task_result::Status::Revoked,
                        TaskStatus::LimitExceeded => pb::task_result::Status::LimitExceeded,
                        TaskStatus::Rejected => pb::task_result::Status::Rejected,
                    };
                    let ok = r.status == TaskStatus::Succeeded;
                    let _ = tx
                        .send(Ok(api::JobEvent {
                            peer_fingerprint: lender_fp.clone(),
                            event: Some(api::job_event::Event::Task(pb::TaskEvent {
                                task_id: vec![],
                                event: Some(pb::task_event::Event::Finished(pb::TaskResult {
                                    status: status as i32,
                                    exit_code: r.exit_code,
                                    error: r.error.map(|m| pb::RemoteError {
                                        message: m,
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                })),
                            })),
                            ..Default::default()
                        }))
                        .await;
                    // Checked again now: turning Trusted mode off (or its lapsing) during the
                    // task drops the grant, and then nothing it returned may be unpickled.
                    let trusted_results = trusted
                        && node.is_trusted(&lender)
                        && node.borrowed_grants().iter().any(|(id, b)| {
                            *id == grant
                                && b.lender == lender
                                && b.terms.trust == gimmecores_core::TrustLevel::Trusted
                        });
                    Ok(api::JobEvent {
                        peer_fingerprint: lender_fp,
                        event: Some(api::job_event::Event::Done(api::JobDone {
                            succeeded: u32::from(ok),
                            failed: u32::from(!ok),
                            output_directory: job.project_root.clone(),
                            trusted_results,
                        })),
                        ..Default::default()
                    })
                }
                Err(e) => Err(Status::aborted(format!("{e:#}"))),
            };
            let _ = tx.send(final_event).await;
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn wake_peer(&self, req: Request<api::WakePeerRequest>) -> Res<api::WakePeerResponse> {
        let key = find_peer(&self.0, &req.into_inner().peer_fingerprint)?;
        let sent = self
            .0
            .wake(&key)
            .map_err(|e| Status::failed_precondition(format!("{e:#}")))?;
        Ok(Response::new(api::WakePeerResponse {
            packets_sent: u32::try_from(sent).unwrap_or(u32::MAX),
        }))
    }

    async fn cancel_job(&self, _: Request<api::CancelJobRequest>) -> Res<api::CancelJobResponse> {
        Err(Status::unimplemented(
            "cancel is not implemented yet; use Ctrl-C",
        ))
    }

    async fn stop_all_lending(&self, _: Request<api::StopAllLendingRequest>) -> Res<api::Status> {
        self.0.set_lending(false).map_err(internal)?;
        Ok(Response::new(self.status()))
    }
}

#[tonic::async_trait]
impl Control for ControlApi {
    async fn list_activity(&self, req: Request<api::ListActivityRequest>) -> Res<api::Activity> {
        let include_there = req.into_inner().include_there;
        if include_there {
            // Lenders that share their load are asked while someone is looking.
            self.0.refresh_lender_loads().await;
        }
        let machine = self.0.machine_load().await;
        let mut activity = crate::activity_api::listing_with(&self.0, include_there);
        activity.machine = Some(machine);
        Ok(Response::new(activity))
    }

    async fn stop_task(&self, req: Request<api::StopTaskRequest>) -> Res<api::StopTaskResponse> {
        let id: [u8; 16] = req
            .into_inner()
            .task_id
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("a task id is 16 bytes"))?;
        self.0
            .stop_task(gimmecores_core::TaskId(id))
            .map_err(|e| Status::not_found(format!("{e:#}")))?;
        Ok(Response::new(api::StopTaskResponse {}))
    }

    async fn set_lending(&self, req: Request<api::SetLendingRequest>) -> Res<api::Status> {
        let r = req.into_inner();
        let current = self.0.protections();
        let loosens = (r.allow_on_battery && current.pause_on_battery)
            || (!r.idle_only && current.idle_only)
            || (r.allow_when_hot && current.pause_when_hot);
        // Refused before any Windows Hello prompt: there is nothing to approve.
        if r.enabled
            && let Some(why) = crate::node::LENDING_UNAVAILABLE
        {
            return Err(Status::failed_precondition(why));
        }
        if r.enabled && !self.0.lending_enabled() {
            self.0
                .require_presence("turn on lending, so paired devices can ask to use this computer")
                .await
                .map_err(refused)?;
        } else if r.enabled && loosens {
            self.0
                .require_presence(
                    "lend on battery power, while you are using this computer, or while it is hot",
                )
                .await
                .map_err(refused)?;
        }
        if r.enabled {
            self.0
                .set_protections(crate::power::Protections {
                    pause_on_battery: !r.allow_on_battery,
                    idle_only: r.idle_only,
                    pause_when_hot: !r.allow_when_hot,
                })
                .map_err(internal)?;
        }
        self.0.set_lending(r.enabled).map_err(internal)?;
        Ok(Response::new(ClientApi(self.0.clone()).status()))
    }

    async fn set_lend_modes(&self, req: Request<api::SetLendModesRequest>) -> Res<api::Status> {
        // An empty list means "lend no way of running tasks" (not the protocol default).
        let mut wanted = gimmecores_core::Modes::NONE;
        for v in req.into_inner().modes {
            let m = crate::grants_flow::mode_from(v)
                .ok_or_else(|| Status::invalid_argument("unknown way of running tasks"))?;
            wanted = wanted.with(m);
        }
        if wanted.native {
            return Err(Status::invalid_argument(
                "running as you without a sandbox is not available yet",
            ));
        }
        let current = self.0.lend_modes().0;
        if !wanted.is_subset_of(current) {
            let added: Vec<&str> = wanted
                .iter()
                .filter(|m| !current.contains(*m))
                .map(|m| match m {
                    gimmecores_core::ExecutionMode::Sandbox => {
                        "lend tasks in this computer's sandbox (they use its installed tools)"
                    }
                    _ => "lend tasks in containers",
                })
                .collect();
            self.0
                .require_presence(&added.join(" and "))
                .await
                .map_err(refused)?;
        }
        self.0.set_lend_modes(wanted).map_err(internal)?;
        Ok(Response::new(ClientApi(self.0.clone()).status()))
    }

    async fn set_task_speed(&self, req: Request<api::SetTaskSpeedRequest>) -> Res<api::Status> {
        let speed = crate::grants_flow::speed_from(req.into_inner().speed)
            .ok_or_else(|| Status::invalid_argument("name a speed"))?;
        self.0.set_task_speed(speed).await.map_err(refused)?;
        Ok(Response::new(ClientApi(self.0.clone()).status()))
    }

    async fn set_wake_allowed(&self, req: Request<api::SetWakeAllowedRequest>) -> Res<api::Peer> {
        let r = req.into_inner();
        let key = find_peer(&self.0, &r.peer_fingerprint)?;
        self.0
            .set_wake_allowed(&key, r.allowed)
            .await
            .map_err(|e| refused_or_failed(&e))?;
        Ok(Response::new(api::Peer {
            fingerprint: key.fingerprint(),
            device_name: self.0.peer_name(&key),
            paired: true,
            wake_allowed: r.allowed,
            can_wake: !self.0.wake_macs(&key).is_empty(),
            ..Default::default()
        }))
    }

    async fn set_standing_rule(&self, req: Request<api::SetStandingRuleRequest>) -> Res<api::Peer> {
        let r = req.into_inner();
        let key = find_peer(&self.0, &r.peer_fingerprint)?;
        match r.rule {
            // Ending it reduces access: no presence. Its grants are revoked.
            None => {
                self.0
                    .remove_standing_rule(&key)
                    .await
                    .map_err(|e| refused_or_failed(&e))?;
            }
            Some(rule) => {
                let hours = if rule.max_hours == 0 {
                    crate::standing::MAX_HOURS
                } else {
                    rule.max_hours
                };
                self.0
                    .set_standing_rule(&key, &rule_terms(&rule), hours)
                    .await
                    .map_err(|e| refused_or_failed(&e))?;
            }
        }
        Ok(Response::new(api::Peer {
            fingerprint: key.fingerprint(),
            device_name: self.0.peer_name(&key),
            paired: true,
            standing: self.0.standing_rule(&key).as_ref().map(rule_to_proto),
            ..Default::default()
        }))
    }

    async fn set_share_tools(&self, req: Request<api::SetShareToolsRequest>) -> Res<api::Status> {
        self.0
            .set_share_tools(req.into_inner().enabled)
            .await
            .map_err(refused)?;
        Ok(Response::new(ClientApi(self.0.clone()).status()))
    }

    async fn set_keep_awake(&self, req: Request<api::SetKeepAwakeRequest>) -> Res<api::Status> {
        self.0
            .set_keep_awake(req.into_inner().enabled)
            .await
            .map_err(refused)?;
        Ok(Response::new(ClientApi(self.0.clone()).status()))
    }

    async fn set_share_load(&self, req: Request<api::SetShareLoadRequest>) -> Res<api::Status> {
        self.0
            .set_share_load(req.into_inner().enabled)
            .await
            .map_err(refused)?;
        Ok(Response::new(ClientApi(self.0.clone()).status()))
    }

    async fn set_presence(&self, req: Request<api::SetPresenceRequest>) -> Res<api::Status> {
        self.0
            .set_require_presence(req.into_inner().required)
            .await
            .map_err(refused)?;
        Ok(Response::new(ClientApi(self.0.clone()).status()))
    }

    async fn set_discovery(&self, req: Request<api::SetDiscoveryRequest>) -> Res<api::Status> {
        use crate::discovery::DiscoveryMode;
        let mode = match api::DiscoveryMode::try_from(req.into_inner().mode) {
            Ok(api::DiscoveryMode::Off) => DiscoveryMode::Off,
            Ok(api::DiscoveryMode::PairedOnly) => DiscoveryMode::PairedOnly,
            Ok(api::DiscoveryMode::Everyone10Min) => {
                return Err(Status::invalid_argument(
                    "open pairing mode instead: it lets nearby devices find this one while it is open",
                ));
            }
            _ => return Err(Status::invalid_argument("unknown discovery mode")),
        };
        self.0.set_discovery_mode(mode).map_err(internal)?;
        Ok(Response::new(ClientApi(self.0.clone()).status()))
    }

    type WatchEventsStream = Pin<Box<dyn Stream<Item = Result<api::Event, Status>> + Send>>;

    async fn watch_events(
        &self,
        _: Request<api::WatchEventsRequest>,
    ) -> Res<Self::WatchEventsStream> {
        let (tx, rx) = mpsc::channel(256);
        let node = self.0.clone();
        tokio::spawn(async move {
            // Compares snapshots instead of hooking every place state changes: a change can
            // never be missed, at the cost of up to EVENT_INTERVAL of delay.
            let mut last = EventSnapshot::take(&node).await;
            loop {
                tokio::time::sleep(EVENT_INTERVAL).await;
                if tx.is_closed() {
                    return;
                }
                let next = EventSnapshot::take(&node).await;
                for ev in last.changes_to(&next) {
                    if tx.send(Ok(ev)).await.is_err() {
                        return;
                    }
                }
                last = next;
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn open_pairing(
        &self,
        _: Request<api::OpenPairingRequest>,
    ) -> Res<api::OpenPairingResponse> {
        let ticket = self.0.ticket().ok_or_else(|| {
            Status::unavailable("no network address yet; try again in a few seconds")
        })?;
        let closes = self.0.open_pairing();
        Ok(Response::new(api::OpenPairingResponse {
            closes_at: Some(ts(closes)),
            ticket,
        }))
    }

    async fn start_pairing(
        &self,
        req: Request<api::StartPairingRequest>,
    ) -> Res<api::PairingSession> {
        let id = match req.into_inner().target {
            Some(api::start_pairing_request::Target::Ticket(t)) => {
                let addr =
                    wire::parse_ticket(&t).map_err(|e| Status::invalid_argument(e.to_string()))?;
                self.0.start_pairing(addr).await.map_err(internal)?
            }
            Some(api::start_pairing_request::Target::PeerFingerprint(fp)) => self
                .0
                .start_pairing_nearby(&fp)
                .await
                .map_err(|e| Status::failed_precondition(format!("{e:#}")))?,
            None => {
                return Err(Status::invalid_argument(
                    "pairing needs a ticket or a nearby device",
                ));
            }
        };
        let view = self
            .0
            .pairing(id)
            .ok_or_else(|| Status::internal("session vanished"))?;
        Ok(Response::new(pairing_proto(&view)))
    }

    async fn confirm_pairing(
        &self,
        req: Request<api::ConfirmPairingRequest>,
    ) -> Res<api::PairingSession> {
        let r = req.into_inner();
        let id = session_id(&r.session_id)?;
        if r.codes_match {
            let view = self
                .0
                .pairing(id)
                .ok_or_else(|| Status::not_found("no such session"))?;
            let code = view
                .code
                .map(|c| format!(" (code {c})"))
                .unwrap_or_default();
            self.0
                .require_presence(&format!(
                    "pair with \"{}\"{code}",
                    prompt_name(&view.peer_name)
                ))
                .await
                .map_err(refused)?;
        }
        self.0
            .confirm_pairing(id, r.codes_match)
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        let view = self
            .0
            .pairing(id)
            .ok_or_else(|| Status::not_found("no such session"))?;
        Ok(Response::new(pairing_proto(&view)))
    }

    async fn list_pairings(
        &self,
        _: Request<api::ListPairingsRequest>,
    ) -> Res<api::ListPairingsResponse> {
        Ok(Response::new(api::ListPairingsResponse {
            sessions: self.0.pairings().iter().map(pairing_proto).collect(),
        }))
    }

    async fn unpair(&self, req: Request<api::UnpairRequest>) -> Res<api::Peer> {
        let who = req.into_inner().peer_fingerprint;
        let key = find_peer(&self.0, &who)?;
        self.0.forget_peer(&key).map_err(internal)?;
        Ok(Response::new(api::Peer {
            fingerprint: key.fingerprint(),
            paired: false,
            ..Default::default()
        }))
    }

    async fn set_trusted_mode(&self, req: Request<api::SetTrustedModeRequest>) -> Res<api::Peer> {
        let r = req.into_inner();
        let key = find_peer(&self.0, &r.peer_fingerprint)?;
        if r.enabled {
            if !r.warning_acknowledged {
                return Err(Status::failed_precondition(format!(
                    "show the user this first, then acknowledge it: {TRUSTED_MODE_WARNING}"
                )));
            }
            let name = self.0.peer_name(&key);
            self.0
                .require_presence(&format!(
                    "turn on Trusted mode with {name:?} for 30 days: {name:?} could then run \
                     any code on this computer through the results it returns"
                ))
                .await
                .map_err(refused)?;
        }
        self.0
            .set_trusted_mode(&key, r.enabled)
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        Ok(Response::new(api::Peer {
            fingerprint: key.fingerprint(),
            device_name: self.0.peer_name(&key),
            paired: true,
            trusted_mode_local: self.0.trusted_until(&key).is_some(),
            trusted_until: self.0.trusted_until(&key).map(ts),
            ..Default::default()
        }))
    }

    async fn respond_to_grant(
        &self,
        req: Request<api::RespondToGrantRequest>,
    ) -> Res<api::GrantInfo> {
        let r = req.into_inner();
        let id = grant_id(&r.grant_id)?;
        let decision = match api::respond_to_grant_request::Decision::try_from(r.decision) {
            Ok(api::respond_to_grant_request::Decision::Accept) => {
                let edited = match r.edited {
                    Some(g) => Some(
                        crate::grants_flow::terms_from_grant(&g)
                            .map_err(|e| Status::invalid_argument(e.to_string()))?,
                    ),
                    None => None,
                };
                let request = self
                    .0
                    .incoming_requests()
                    .into_iter()
                    .find(|v| v.id == id)
                    .ok_or_else(|| Status::not_found("no such request"))?;
                // Approve exactly what the prompt showed: the terms go into the decision, so the
                // reduce-only check rejects anything else.
                let terms = edited.unwrap_or(request.requested);
                // "Always accept requests like this": a standing grant with these terms, said
                // in the same prompt (standing.rs).
                let rule = if r.always {
                    let hours = terms.not_after.saturating_sub(now()).div_ceil(3600);
                    Some(
                        crate::standing::StandingRule::new(
                            &terms,
                            u32::try_from(hours).unwrap_or(u32::MAX),
                            now(),
                        )
                        .map_err(|e| Status::failed_precondition(format!("{e:#}")))?,
                    )
                } else {
                    None
                };
                let name = prompt_name(&request.borrower_name);
                let also = rule.as_ref().map_or(String::new(), |r| {
                    format!(
                        ", and accept requests like this from \"{name}\" without asking you for \
                         {} days ({})",
                        crate::standing::STANDING_DAYS,
                        r.describe()
                    )
                });
                self.0
                    .require_presence(&format!(
                        "let \"{name}\" use {}{also}",
                        describe_terms(&terms)
                    ))
                    .await
                    .map_err(refused)?;
                if let Some(rule) = rule {
                    self.0
                        .store_standing_rule(&request.borrower, rule)
                        .map_err(|e| Status::failed_precondition(format!("{e:#}")))?;
                }
                Decision::Accept(Some(terms))
            }
            Ok(api::respond_to_grant_request::Decision::Decline) => {
                Decision::Decline("declined by the lender".into())
            }
            _ => {
                return Err(Status::invalid_argument(
                    "decision must be accept or decline",
                ));
            }
        };
        self.0
            .respond_to_request(id, decision)
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        Ok(Response::new(api::GrantInfo {
            grant_id: id.0.to_vec(),
            as_lender: true,
            ..Default::default()
        }))
    }

    async fn revoke_grant(&self, req: Request<api::RevokeGrantRequest>) -> Res<api::GrantInfo> {
        let id = grant_id(&req.into_inner().grant_id)?;
        let killed = self
            .0
            .revoke_grant(id)
            .await
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        Ok(Response::new(api::GrantInfo {
            grant_id: id.0.to_vec(),
            as_lender: true,
            state: pb::GrantState::Revoked as i32,
            state_reason: format!("{} running task(s) stopped", killed.len()),
            ..Default::default()
        }))
    }

    async fn add_rule(&self, _: Request<api::AddRuleRequest>) -> Res<api::Rule> {
        Err(Status::unimplemented(
            "standing rules are not implemented yet",
        ))
    }

    async fn list_rules(&self, _: Request<api::ListRulesRequest>) -> Res<api::ListRulesResponse> {
        Ok(Response::new(api::ListRulesResponse { rules: vec![] }))
    }

    async fn remove_rule(&self, _: Request<api::RemoveRuleRequest>) -> Res<api::Rule> {
        Err(Status::unimplemented(
            "standing rules are not implemented yet",
        ))
    }

    type QueryAuditStream = Pin<Box<dyn Stream<Item = Result<api::AuditEntry, Status>> + Send>>;

    async fn query_audit(
        &self,
        req: Request<api::QueryAuditRequest>,
    ) -> Res<Self::QueryAuditStream> {
        let r = req.into_inner();
        let since = r.since.map_or(0, |s| u64::try_from(s.seconds).unwrap_or(0));
        let entries = crate::audit::read(&self.0.paths().audit_log()).map_err(internal)?;
        let items: Vec<Result<api::AuditEntry, Status>> = entries
            .into_iter()
            .filter(|e| e.at >= since)
            .filter(|e| {
                r.peer_fingerprint.is_empty()
                    || e.peer.as_deref() == Some(r.peer_fingerprint.as_str())
            })
            .map(|e| {
                Ok(api::AuditEntry {
                    sequence: e.seq,
                    at: Some(ts(e.at)),
                    kind: e.kind,
                    peer_fingerprint: e.peer.unwrap_or_default(),
                    summary: e.summary,
                    details: serde_json::to_vec(&e.details).unwrap_or_default(),
                    previous_hash: hex::decode(&e.prev).unwrap_or_default(),
                    hash: hex::decode(&e.hash).unwrap_or_default(),
                })
            })
            .collect();
        Ok(Response::new(Box::pin(tokio_stream::iter(items))))
    }
}

/// Serves both services until the process exits, each on an owner-only endpoint
/// (gimmecores-os::ipc).
pub async fn serve(node: Node) -> Result<()> {
    let paths = node.paths().clone();
    let client = gimmecores_os::ipc::bind_private(&paths.client_socket())?;
    let control = gimmecores_os::ipc::bind_private(&paths.control_socket())?;
    let c = tonic::transport::Server::builder()
        .add_service(
            // Room for an SDK's payload files (MAX_INLINE_FILES) plus the rest of the job.
            ClientServer::new(ClientApi(node.clone()))
                .max_decoding_message_size(MAX_INLINE_FILES + (1 << 20)),
        )
        .serve_with_incoming(client);
    let k = tonic::transport::Server::builder()
        .add_service(ControlServer::new(ControlApi(node)))
        .serve_with_incoming(control);
    tokio::try_join!(c, k)?;
    Ok(())
}

/// Opens a gRPC channel to one of the daemon's endpoints.
pub async fn channel(path: &Path) -> Result<tonic::transport::Channel> {
    gimmecores_client::channel(path).await
}

/// How often an event stream looks for changes.
const EVENT_INTERVAL: Duration = Duration::from_millis(250);

/// What a subscriber is told about, keyed so changes can be found.
struct EventSnapshot {
    grants: std::collections::BTreeMap<Vec<u8>, api::GrantInfo>,
    pairings: std::collections::BTreeMap<Vec<u8>, api::PairingSession>,
    /// Tasks each peer runs here.
    activity: std::collections::BTreeMap<PeerKey, u32>,
    /// The activity listing's revision.
    activity_rev: u64,
    status: api::Status,
}

impl EventSnapshot {
    async fn take(node: &Node) -> Self {
        let grants = ClientApi(node.clone())
            .list_grants(Request::new(api::ListGrantsRequest {
                include_inactive: true,
            }))
            .await
            .map(|r| r.into_inner().grants)
            .unwrap_or_default()
            .into_iter()
            .map(|mut g| {
                // A lent grant's text counts its running tasks: a task starting is reported
                // as activity, not as a change of the grant.
                if g.as_lender && g.state != pb::GrantState::Requested as i32 {
                    g.state_reason.clear();
                }
                (g.grant_id.clone(), g)
            })
            .collect();
        let pairings = node
            .pairings()
            .iter()
            .map(pairing_proto)
            .map(|p| (p.session_id.clone(), p))
            .collect();
        let mut activity = std::collections::BTreeMap::new();
        let activity_rev = {
            let s = node.state();
            for h in s.running.values() {
                *activity.entry(h.info.peer).or_insert(0u32) += 1;
            }
            s.activity_rev
        };
        let mut status = ClientApi(node.clone()).status();
        // The machine's description (and its live readings) are not changes worth an event,
        // nor are task counts (activity events carry those).
        status.capabilities = None;
        status.active_lent_tasks = 0;
        status.active_borrowed_tasks = 0;
        Self {
            grants,
            pairings,
            activity,
            activity_rev,
            status,
        }
    }

    fn changes_to(&self, next: &Self) -> Vec<api::Event> {
        use api::event::Kind;
        let mut out = Vec::new();
        // Status first: a change of status (lending off, say) is the cause of the grant
        // changes that come with it.
        if self.status != next.status {
            out.push(Kind::Status(next.status.clone()));
        }
        for (id, g) in &next.grants {
            if self.grants.get(id) != Some(g) {
                out.push(Kind::Grant(g.clone()));
            }
        }
        for (id, p) in &next.pairings {
            if self.pairings.get(id) != Some(p) {
                out.push(Kind::Pairing(p.clone()));
            }
        }
        let peers: std::collections::BTreeSet<&PeerKey> =
            self.activity.keys().chain(next.activity.keys()).collect();
        for peer in peers {
            let (was, now) = (
                self.activity.get(peer).copied().unwrap_or(0),
                next.activity.get(peer).copied().unwrap_or(0),
            );
            if was != now {
                out.push(Kind::Activity(api::ActivityUpdate {
                    peer_fingerprint: peer.fingerprint(),
                    lending: now > 0,
                    running_tasks: now,
                    ..Default::default()
                }));
            }
        }
        if self.activity_rev != next.activity_rev {
            out.push(Kind::ActivityChanged(api::ActivityChanged {
                revision: next.activity_rev,
            }));
        }
        out.into_iter()
            .map(|k| api::Event { kind: Some(k) })
            .collect()
    }
}
