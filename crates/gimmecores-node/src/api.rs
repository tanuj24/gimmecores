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

use anyhow::{Context, Result};
use gimmecores_core::{GrantId, GrantState, PeerKey};
use gimmecores_proto::local::v1 as api;
use gimmecores_proto::local::v1::client_server::{Client, ClientServer};
use gimmecores_proto::local::v1::control_server::{Control, ControlServer};
use gimmecores_proto::peer::v1 as pb;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
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
    format!(
        "{cores} cores, {:.1} GiB memory, {:.1} GiB disk, for {time}",
        gib(l.memory_bytes),
        gib(l.disk_bytes)
    )
}

fn grant_id(b: &[u8]) -> Result<GrantId, Status> {
    b.try_into()
        .map(GrantId)
        .map_err(|_| Status::invalid_argument("grant id must be 16 bytes"))
}

fn find_peer(node: &Node, who: &str) -> Result<PeerKey, Status> {
    node.find_peer(who)
        .ok_or_else(|| Status::not_found(format!("no paired device named {who:?}")))
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
            lending_enabled: n.lending_enabled(),
            discovery: api::DiscoveryMode::PairedOnly as i32,
            capabilities: Some(crate::caps::capabilities(n.lending_enabled())),
            active_lent_tasks: u32::try_from(n.running_task_count()).unwrap_or(u32::MAX),
            active_borrowed_tasks: 0,
            pause_reason: n.pause_reason().unwrap_or_default(),
            idle_only: n.protections().idle_only,
            pause_on_battery: n.protections().pause_on_battery,
            presence_required: n.presence().0,
            presence_method: n.presence().1.to_string(),
        }
    }
}

#[tonic::async_trait]
impl Client for ClientApi {
    async fn get_status(&self, _: Request<api::GetStatusRequest>) -> Res<api::Status> {
        Ok(Response::new(self.status()))
    }

    async fn list_peers(&self, _: Request<api::ListPeersRequest>) -> Res<api::ListPeersResponse> {
        let peers = self
            .0
            .paired_peers_detailed()
            .into_iter()
            .map(|(key, name, paired_at)| api::Peer {
                fingerprint: key.fingerprint(),
                device_name: name,
                paired: true,
                paired_at: Some(ts(paired_at)),
                links: self
                    .0
                    .last_link(&key)
                    .map(|l| l.to_proto())
                    .into_iter()
                    .collect(),
                ..Default::default()
            })
            .collect();
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
        let outcome = self
            .0
            .request_grant(&lender, &terms, &wanted.reason)
            .await
            .map_err(internal)?;
        Ok(Response::new(match outcome {
            GrantOutcome::Granted { id, terms } => api::GrantInfo {
                grant_id: id.0.to_vec(),
                peer_fingerprint: lender.fingerprint(),
                as_lender: false,
                state: pb::GrantState::Active as i32,
                grant: Some(self.0.grant_proto(id, self.0.key(), &terms, &[])),
                ..Default::default()
            },
            GrantOutcome::Declined(reason) => api::GrantInfo {
                peer_fingerprint: lender.fingerprint(),
                state: pb::GrantState::Declined as i32,
                state_reason: reason,
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
                grant: Some(n.grant_proto(r.id, r.borrower, &r.requested, &[])),
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
                grant: Some(n.grant_proto(id, borrower, &terms, &[])),
                state_reason: format!("{running} task(s) running"),
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
        let (grant, lender) = node
            .borrowed_grants()
            .into_iter()
            .filter(|(_, b)| b.terms.not_after > now())
            .find(|(_, b)| wanted_peer.is_none_or(|p| p == b.lender))
            .map(|(id, b)| (id, b.lender))
            .ok_or_else(|| {
                Status::failed_precondition(
                    "no active grant; ask for one with `gmc grants request`",
                )
            })?;
        let limits = task.resources.unwrap_or_default();
        let image = match task.env.and_then(|e| e.kind) {
            Some(pb::environment::Kind::Image(i)) => Some(i.reference),
            _ => None,
        };
        let spec = TaskSpec {
            dir: std::path::PathBuf::from(&job.project_root),
            argv: cmd.argv,
            image,
            outputs: task.outputs,
            excludes: task.excludes,
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
            let report = node.run_task(&lender, grant, spec, log_tx).await;
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
                    Ok(api::JobEvent {
                        peer_fingerprint: lender_fp,
                        event: Some(api::job_event::Event::Done(api::JobDone {
                            succeeded: u32::from(ok),
                            failed: u32::from(!ok),
                            output_directory: job.project_root.clone(),
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
    async fn set_lending(&self, req: Request<api::SetLendingRequest>) -> Res<api::Status> {
        let r = req.into_inner();
        let current = self.0.protections();
        let loosens =
            (r.allow_on_battery && current.pause_on_battery) || (!r.idle_only && current.idle_only);
        if r.enabled && !self.0.lending_enabled() {
            self.0
                .require_presence("turn on lending, so paired devices can ask to use this computer")
                .await
                .map_err(refused)?;
        } else if r.enabled && loosens {
            self.0
                .require_presence("lend on battery power or while you are using this computer")
                .await
                .map_err(refused)?;
        }
        if r.enabled {
            self.0
                .set_protections(crate::power::Protections {
                    pause_on_battery: !r.allow_on_battery,
                    idle_only: r.idle_only,
                })
                .map_err(internal)?;
        }
        self.0.set_lending(r.enabled).map_err(internal)?;
        Ok(Response::new(ClientApi(self.0.clone()).status()))
    }

    async fn set_presence(&self, req: Request<api::SetPresenceRequest>) -> Res<api::Status> {
        self.0
            .set_require_presence(req.into_inner().required)
            .await
            .map_err(refused)?;
        Ok(Response::new(ClientApi(self.0.clone()).status()))
    }

    async fn set_discovery(&self, _: Request<api::SetDiscoveryRequest>) -> Res<api::Status> {
        Err(Status::unimplemented(
            "discovery is not implemented yet; pair with a ticket",
        ))
    }

    type WatchEventsStream = Pin<Box<dyn Stream<Item = Result<api::Event, Status>> + Send>>;

    async fn watch_events(
        &self,
        _: Request<api::WatchEventsRequest>,
    ) -> Res<Self::WatchEventsStream> {
        Err(Status::unimplemented("events are not implemented yet"))
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
        let addr = match req.into_inner().target {
            Some(api::start_pairing_request::Target::Ticket(t)) => {
                wire::parse_ticket(&t).map_err(|e| Status::invalid_argument(e.to_string()))?
            }
            _ => {
                return Err(Status::invalid_argument(
                    "pairing needs a ticket in this version",
                ));
            }
        };
        let id = self.0.start_pairing(addr).await.map_err(internal)?;
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

    async fn set_trusted_mode(&self, _: Request<api::SetTrustedModeRequest>) -> Res<api::Peer> {
        Err(Status::unimplemented(
            "Trusted mode arrives with the Python SDK (M2)",
        ))
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
                self.0
                    .require_presence(&format!(
                        "let \"{}\" use {}",
                        prompt_name(&request.borrower_name),
                        describe_terms(&terms)
                    ))
                    .await
                    .map_err(refused)?;
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

/// Binds a Unix socket readable and writable only by this user.
#[cfg(unix)]
fn bind_private(path: &Path) -> Result<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    if path.exists() {
        std::fs::remove_file(path)?; // stale socket from a previous run
    }
    let listener = tokio::net::UnixListener::bind(path)
        .with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Serves both services until the process exits.
#[cfg(unix)]
pub async fn serve(node: Node) -> Result<()> {
    let paths = node.paths().clone();
    let client = bind_private(&paths.client_socket())?;
    let control = bind_private(&paths.control_socket())?;
    let c = tonic::transport::Server::builder()
        .add_service(ClientServer::new(ClientApi(node.clone())))
        .serve_with_incoming(UnixListenerStream::new(client));
    let k = tonic::transport::Server::builder()
        .add_service(ControlServer::new(ControlApi(node)))
        .serve_with_incoming(UnixListenerStream::new(control));
    tokio::try_join!(c, k)?;
    Ok(())
}

/// Opens a gRPC channel over a Unix socket.
#[cfg(unix)]
pub async fn channel(path: &Path) -> Result<tonic::transport::Channel> {
    gimmecores_client::channel(path).await
}
