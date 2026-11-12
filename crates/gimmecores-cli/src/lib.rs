//! The `gimmecores` / `gmc` command line and the `gmcd` daemon.

use std::io::{IsTerminal, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use gimmecores_node::api;
use gimmecores_node::exec::DockerExecutor;
use gimmecores_node::node::{Node, NodeConfig};
use gimmecores_node::paths::Paths;
use gimmecores_proto::local::v1 as l;
use gimmecores_proto::local::v1::client_client::ClientClient;
use gimmecores_proto::local::v1::control_client::ControlClient;
use gimmecores_proto::peer::v1 as pb;

pub const DEFAULT_PORT: u16 = 47474;

#[derive(Parser)]
#[command(
    name = "gmc",
    version,
    about = "GimmeCores: borrow CPU, RAM and GPU from nearby machines, with their owner's consent"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the background service in the foreground (same as `gmcd`).
    Daemon(DaemonArgs),
    /// Show this device's status.
    Status,
    /// Turn lending on or off. Off revokes every grant and stops running tasks.
    Lend {
        #[arg(value_parser = ["on", "off"])]
        state: String,
        /// Lend only while you are away from the keyboard (pauses as soon as you return).
        #[arg(long)]
        when_idle: bool,
        /// Keep lending on battery power (default: pause on battery).
        #[arg(long)]
        on_battery: bool,
    },
    /// Stop all lending now (revokes every grant, stops running tasks).
    Stop,
    /// Pair with another device. Without a ticket: open pairing mode and print this device's ticket.
    Pair { ticket: Option<String> },
    /// List paired devices.
    Peers,
    /// Forget a paired device (revokes everything it holds here).
    Unpair { peer: String },
    /// List grants, or request one.
    Grants {
        #[command(subcommand)]
        action: Option<GrantCmd>,
        /// Include expired, revoked and declined grants.
        #[arg(long)]
        all: bool,
    },
    /// Review incoming requests for this machine's resources.
    Requests,
    /// Revoke a grant you gave (stops its running tasks).
    Revoke { grant: String },
    /// Run a command on a device that granted you resources.
    Run(RunArgs),
    /// Show the audit log of everything that happened on this device.
    Audit {
        /// Check that no entry was changed, removed or reordered.
        #[arg(long)]
        verify: bool,
    },
}

#[derive(clap::Args)]
struct DaemonArgs {
    /// Name other devices will see.
    #[arg(long)]
    name: Option<String>,
    /// Address to listen on for other devices.
    #[arg(long, default_value_t = SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT)))]
    listen: SocketAddr,
}

#[derive(Subcommand)]
enum GrantCmd {
    /// Ask a paired device for resources (its owner decides).
    Request {
        peer: String,
        #[arg(long, default_value_t = 2)]
        cpus: u32,
        #[arg(long, default_value = "4g")]
        memory: String,
        #[arg(long, default_value_t = 2)]
        hours: u64,
        #[arg(long, default_value = "")]
        reason: String,
    },
}

#[derive(clap::Args)]
struct RunArgs {
    /// Device to run on (name or fingerprint); default: any device that granted you resources.
    #[arg(long)]
    peer: Option<String>,
    /// Container image to run in (required by lenders using the Docker sandbox).
    #[arg(long)]
    image: Option<String>,
    #[arg(long, default_value_t = 1)]
    cpus: u32,
    #[arg(long, default_value = "1g")]
    memory: String,
    /// Output path to bring back into this folder (repeatable).
    #[arg(long = "out")]
    outputs: Vec<String>,
    /// Extra glob to exclude from upload (repeatable).
    #[arg(long = "exclude")]
    excludes: Vec<String>,
    /// Send this file even though the secret scan flags it (repeatable; path relative to here).
    #[arg(long = "allow-secret")]
    allow_secrets: Vec<String>,
    /// Timeout in seconds.
    #[arg(long, default_value_t = 3600)]
    timeout: u64,
    /// Command and arguments.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim().to_ascii_lowercase();
    let (num, mult) = match s.chars().last() {
        Some('g') => (&s[..s.len() - 1], 1u64 << 30),
        Some('m') => (&s[..s.len() - 1], 1u64 << 20),
        Some('k') => (&s[..s.len() - 1], 1u64 << 10),
        _ => (s.as_str(), 1),
    };
    let n: f64 = num.parse().with_context(|| format!("invalid size {s:?}"))?;
    if !(n.is_finite() && n > 0.0) {
        bail!("size must be positive");
    }
    Ok((n * mult as f64) as u64)
}

fn gib(bytes: u64) -> String {
    format!("{:.1} GB", bytes as f64 / f64::from(1u32 << 30))
}

/// Consent stand-in until OS-verified user presence (I13) lands: an interactive terminal and
/// an explicit "yes". Piped input is refused so scripts cannot approve on the user's behalf.
fn confirm(question: &str) -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        bail!("this needs your confirmation in an interactive terminal");
    }
    print!("{question} Type \"yes\" to confirm: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().eq_ignore_ascii_case("yes"))
}

async fn client(paths: &Paths) -> Result<ClientClient<tonic::transport::Channel>> {
    Ok(ClientClient::new(
        api::channel(&paths.client_socket()).await?,
    ))
}

async fn control(paths: &Paths) -> Result<ControlClient<tonic::transport::Channel>> {
    Ok(ControlClient::new(
        api::channel(&paths.control_socket()).await?,
    ))
}

fn status_err(e: tonic::Status) -> anyhow::Error {
    anyhow::anyhow!("{}", e.message())
}

pub fn main() -> ExitCode {
    let cli = Cli::parse();
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run(cli)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

pub fn daemon_main() -> ExitCode {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let args = DaemonArgs {
        name: None,
        listen: SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT)),
    };
    match rt.block_on(daemon(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn daemon(args: DaemonArgs) -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let paths = Paths::from_env()?;
    let name = args
        .name
        .or_else(sysinfo::System::host_name)
        .unwrap_or_else(|| "GimmeCores device".into());
    let docker = DockerExecutor::default();
    let docker_ok = docker.available().await;
    let node = Node::start(NodeConfig {
        paths: paths.clone(),
        device_name: name,
        bind: args.listen,
        executor: Arc::new(docker),
    })
    .await?;
    println!(
        "gmcd running as {:?} ({})",
        node.name(),
        node.key().fingerprint()
    );
    println!("  state:    {}", paths.root().display());
    println!(
        "  network:  {} (LAN only; no relays, no router port mapping)",
        args.listen
    );
    println!(
        "  lending:  {}",
        if node.lending_enabled() {
            "ON"
        } else {
            "off (turn on with `gmc lend on`)"
        }
    );
    if !docker_ok {
        println!(
            "  warning:  Docker is not running; tasks from other devices will be refused until it is."
        );
    }
    tokio::select! {
        r = api::serve(node.clone()) => r?,
        _ = tokio::signal::ctrl_c() => println!("\nstopping"),
    }
    node.shutdown().await;
    Ok(())
}

fn print_pairing(s: &l::PairingSession) {
    println!(
        "Pairing with {:?} ({})",
        s.peer_device_name, s.peer_fingerprint
    );
    if s.name_previously_seen_with_other_key {
        println!(
            "  WARNING: a different device previously used this name. Make sure this is the device you expect."
        );
    }
}

async fn finish_pairing(
    ctl: &mut ControlClient<tonic::transport::Channel>,
    mut s: l::PairingSession,
) -> Result<()> {
    for _ in 0..240 {
        if !s.code.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        s = ctl
            .list_pairings(l::ListPairingsRequest {})
            .await
            .map_err(status_err)?
            .into_inner()
            .sessions
            .into_iter()
            .find(|x| x.session_id == s.session_id)
            .context("pairing session vanished")?;
    }
    print_pairing(&s);
    println!("\n    Code: {}\n", s.code);
    println!("Check that the other device shows exactly the same code.");
    let ok = confirm("Do the codes match?")?;
    let mut s = ctl
        .confirm_pairing(l::ConfirmPairingRequest {
            session_id: s.session_id.clone(),
            codes_match: ok,
        })
        .await
        .map_err(status_err)?
        .into_inner();
    let id = s.session_id.clone();
    for _ in 0..480 {
        match l::pairing_session::State::try_from(s.state) {
            Ok(l::pairing_session::State::Paired) => {
                println!("Paired with {:?}.", s.peer_device_name);
                return Ok(());
            }
            Ok(l::pairing_session::State::Failed) => bail!("pairing failed: {}", s.error),
            _ => {}
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        s = ctl
            .list_pairings(l::ListPairingsRequest {})
            .await
            .map_err(status_err)?
            .into_inner()
            .sessions
            .into_iter()
            .find(|x| x.session_id == id)
            .context("pairing session vanished")?;
    }
    bail!("timed out waiting for the other device")
}

async fn run(cli: Cli) -> Result<ExitCode> {
    if let Cmd::Daemon(args) = cli.cmd {
        daemon(args).await?;
        return Ok(ExitCode::SUCCESS);
    }
    let paths = Paths::from_env()?;
    match cli.cmd {
        Cmd::Daemon(_) => unreachable!("handled above"),
        Cmd::Status => {
            let s = client(&paths)
                .await?
                .get_status(l::GetStatusRequest {})
                .await
                .map_err(status_err)?
                .into_inner();
            let caps = s.capabilities.unwrap_or_default();
            println!("{} ({})", s.device_name, s.fingerprint);
            println!(
                "  lending:  {}",
                if s.lending_enabled { "ON" } else { "off" }
            );
            if !s.pause_reason.is_empty() {
                println!(
                    "  paused:   {} (tasks are frozen until this clears)",
                    s.pause_reason
                );
            }
            println!(
                "  rules:    {}, {}",
                if s.pause_on_battery {
                    "pauses on battery"
                } else {
                    "lends on battery"
                },
                if s.idle_only {
                    "only while you are away"
                } else {
                    "even while you work"
                }
            );
            println!(
                "  machine:  {} {}, {} cores, {}",
                caps.os,
                caps.arch,
                caps.cpu_cores,
                gib(caps.memory_bytes)
            );
            println!("  running for others: {} task(s)", s.active_lent_tasks);
        }
        Cmd::Lend {
            state,
            when_idle,
            on_battery,
        } => {
            let enable = state == "on";
            if enable
                && !confirm(
                    "Allow paired devices to ASK to use this machine? Each request still needs your approval.",
                )?
            {
                println!("Lending stays off.");
                return Ok(ExitCode::SUCCESS);
            }
            control(&paths)
                .await?
                .set_lending(l::SetLendingRequest {
                    enabled: enable,
                    idle_only: when_idle,
                    allow_on_battery: on_battery,
                })
                .await
                .map_err(status_err)?;
            println!(
                "Lending is {}.",
                if enable {
                    "ON"
                } else {
                    "off; every grant was revoked"
                }
            );
        }
        Cmd::Stop => {
            client(&paths)
                .await?
                .stop_all_lending(l::StopAllLendingRequest {
                    reason: "gmc stop".into(),
                })
                .await
                .map_err(status_err)?;
            println!("Stopped all lending: every grant revoked, running tasks stopped.");
        }
        Cmd::Pair { ticket: None } => {
            let mut ctl = control(&paths).await?;
            let r = ctl
                .open_pairing(l::OpenPairingRequest {})
                .await
                .map_err(status_err)?
                .into_inner();
            println!(
                "Pairing mode is open for 2 minutes. On the other device run:\n\n    gmc pair {}\n",
                r.ticket
            );
            println!("Waiting for a request...");
            let mut seen = std::collections::HashSet::new();
            for p in ctl
                .list_pairings(l::ListPairingsRequest {})
                .await
                .map_err(status_err)?
                .into_inner()
                .sessions
            {
                seen.insert(p.session_id);
            }
            for _ in 0..480 {
                let sessions = ctl
                    .list_pairings(l::ListPairingsRequest {})
                    .await
                    .map_err(status_err)?
                    .into_inner()
                    .sessions;
                if let Some(s) = sessions.into_iter().find(|s| !seen.contains(&s.session_id)) {
                    return finish_pairing(&mut ctl, s)
                        .await
                        .map(|()| ExitCode::SUCCESS);
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            bail!("pairing mode closed without a request");
        }
        Cmd::Pair { ticket: Some(t) } => {
            let mut ctl = control(&paths).await?;
            let s = ctl
                .start_pairing(l::StartPairingRequest {
                    target: Some(l::start_pairing_request::Target::Ticket(t)),
                })
                .await
                .map_err(status_err)?
                .into_inner();
            finish_pairing(&mut ctl, s).await?;
        }
        Cmd::Peers => {
            let peers = client(&paths)
                .await?
                .list_peers(l::ListPeersRequest {
                    include_discovered: false,
                })
                .await
                .map_err(status_err)?
                .into_inner()
                .peers;
            if peers.is_empty() {
                println!("No paired devices. Pair with `gmc pair`.");
            }
            for p in peers {
                println!("{:<28} {}", p.device_name, p.fingerprint);
            }
        }
        Cmd::Unpair { peer } => {
            control(&paths)
                .await?
                .unpair(l::UnpairRequest {
                    peer_fingerprint: peer.clone(),
                })
                .await
                .map_err(status_err)?;
            println!("Forgot {peer:?}; everything it held here was revoked.");
        }
        Cmd::Grants { action: None, all } => {
            let grants = client(&paths)
                .await?
                .list_grants(l::ListGrantsRequest {
                    include_inactive: all,
                })
                .await
                .map_err(status_err)?
                .into_inner()
                .grants;
            if grants.is_empty() {
                println!("No grants.");
            }
            for g in grants {
                let state = pb::GrantState::try_from(g.state)
                    .map(|s| {
                        s.as_str_name()
                            .trim_start_matches("GRANT_STATE_")
                            .to_lowercase()
                    })
                    .unwrap_or_default();
                let limits = g.grant.as_ref().and_then(|x| x.limits).unwrap_or_default();
                println!(
                    "{}  {:<5} {:<9} {} cores, {}  peer {}  {}",
                    hex::encode(&g.grant_id),
                    if g.as_lender { "lent" } else { "held" },
                    state,
                    f64::from(limits.cpu_millis) / 1000.0,
                    gib(limits.memory_bytes),
                    g.peer_fingerprint,
                    g.state_reason
                );
            }
        }
        Cmd::Grants {
            action:
                Some(GrantCmd::Request {
                    peer,
                    cpus,
                    memory,
                    hours,
                    reason,
                }),
            ..
        } => {
            let mem = parse_size(&memory)?;
            println!(
                "Asking {peer:?} for {cpus} cores and {} for {hours} h. Waiting for its owner to decide...",
                gib(mem)
            );
            let req = pb::GrantRequest {
                request_id: vec![],
                limits: Some(pb::Limits {
                    cpu_millis: cpus * 1000,
                    memory_bytes: mem,
                    disk_bytes: 10 << 30,
                    gpu: pb::GpuKind::None as i32,
                    max_concurrent_tasks: cpus.max(1),
                }),
                modes: vec![pb::ExecutionMode::Container as i32],
                network: pb::NetworkPolicy::None as i32,
                duration: Some(prost_types::Duration {
                    seconds: i64::try_from(hours * 3600)?,
                    nanos: 0,
                }),
                trust: pb::TrustLevel::Standard as i32,
                reason,
            };
            let g = client(&paths)
                .await?
                .request_grant(l::RequestGrantRequest {
                    peer_fingerprint: peer,
                    request: Some(req),
                })
                .await
                .map_err(status_err)?
                .into_inner();
            if g.state == pb::GrantState::Active as i32 {
                println!(
                    "Granted ({}). Run work with `gmc run -- <command>`.",
                    hex::encode(&g.grant_id)
                );
            } else {
                println!("Declined: {}", g.state_reason);
                return Ok(ExitCode::FAILURE);
            }
        }
        Cmd::Requests => {
            let grants = client(&paths)
                .await?
                .list_grants(l::ListGrantsRequest {
                    include_inactive: false,
                })
                .await
                .map_err(status_err)?
                .into_inner()
                .grants;
            let pending: Vec<_> = grants
                .into_iter()
                .filter(|g| g.as_lender && g.state == pb::GrantState::Requested as i32)
                .collect();
            if pending.is_empty() {
                println!("No pending requests.");
            }
            let mut ctl = control(&paths).await?;
            for g in pending {
                let limits = g.grant.as_ref().and_then(|x| x.limits).unwrap_or_default();
                println!("\n{}", g.state_reason);
                println!("  Device:   {}", g.peer_fingerprint);
                println!(
                    "  Wants:    up to {} CPU cores and {} RAM, no GPU",
                    f64::from(limits.cpu_millis) / 1000.0,
                    gib(limits.memory_bytes)
                );
                println!("  Runs in:  a Docker container; it cannot see your files or other apps");
                println!("  Network:  none while running; nothing is downloaded");
                println!(
                    "  The device can stop being trusted at any time with `gmc revoke` or `gmc stop`."
                );
                let accept = confirm("Accept this request?")?;
                let decision = if accept {
                    l::respond_to_grant_request::Decision::Accept
                } else {
                    l::respond_to_grant_request::Decision::Decline
                };
                ctl.respond_to_grant(l::RespondToGrantRequest {
                    grant_id: g.grant_id.clone(),
                    decision: decision as i32,
                    edited: None,
                })
                .await
                .map_err(status_err)?;
                println!("{}", if accept { "Accepted." } else { "Declined." });
            }
        }
        Cmd::Revoke { grant } => {
            let id = hex::decode(grant.trim()).context("grant id is hex (see `gmc grants`)")?;
            let r = control(&paths)
                .await?
                .revoke_grant(l::RevokeGrantRequest {
                    grant_id: id,
                    reason: "gmc revoke".into(),
                })
                .await
                .map_err(status_err)?
                .into_inner();
            println!("Revoked; {}.", r.state_reason);
        }
        Cmd::Run(args) => return run_task(&paths, args).await,
        Cmd::Audit { verify: true } => {
            let n = gimmecores_node::audit::verify(&paths.audit_log())?;
            println!("Audit log intact: {n} entries, chain verified.");
        }
        Cmd::Audit { verify: false } => {
            let mut stream = control(&paths)
                .await?
                .query_audit(l::QueryAuditRequest {
                    since: None,
                    peer_fingerprint: String::new(),
                })
                .await
                .map_err(status_err)?
                .into_inner();
            while let Some(e) = stream.message().await.map_err(status_err)? {
                let at = e.at.map_or(0, |t| t.seconds);
                println!("{:>5}  {at}  {:<8} {}", e.sequence, e.kind, e.summary);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

async fn run_task(paths: &Paths, args: RunArgs) -> Result<ExitCode> {
    let project: PathBuf = std::env::current_dir()?;
    let task = l::InlineTask {
        name: "run".into(),
        env: args.image.map(|r| pb::Environment {
            kind: Some(pb::environment::Kind::Image(pb::ImageEnv {
                reference: r,
                digest: String::new(),
            })),
        }),
        work: Some(l::inline_task::Work::Command(pb::Command {
            argv: args.command,
            working_directory: String::new(),
            environment: Default::default(),
        })),
        outputs: args.outputs,
        excludes: args.excludes,
        resources: Some(pb::Limits {
            cpu_millis: args.cpus * 1000,
            memory_bytes: parse_size(&args.memory)?,
            ..Default::default()
        }),
        network: pb::NetworkPolicy::None as i32,
        timeout: Some(prost_types::Duration {
            seconds: i64::try_from(args.timeout)?,
            nanos: 0,
        }),
        retry: 0,
        local_fallback: false,
        peers: args.peer.into_iter().collect(),
        shards: 1,
        ..Default::default()
    };
    let job = l::JobSpec {
        project_root: project.display().to_string(),
        inline_tasks: vec![task],
        confirmed_sensitive_paths: args.allow_secrets,
        ..Default::default()
    };
    let mut stream = client(paths)
        .await?
        .submit_job(job)
        .await
        .map_err(status_err)?
        .into_inner();
    let mut exit = ExitCode::SUCCESS;
    while let Some(ev) = stream.message().await.map_err(status_err)? {
        match ev.event {
            Some(l::job_event::Event::Task(t)) => match t.event {
                Some(pb::task_event::Event::Log(log)) => {
                    if log.stream == pb::log_chunk::Stream::Stderr as i32 {
                        std::io::stderr().write_all(&log.data)?;
                    } else {
                        std::io::stdout().write_all(&log.data)?;
                    }
                }
                Some(pb::task_event::Event::Finished(r)) => {
                    let status = pb::task_result::Status::try_from(r.status)
                        .unwrap_or(pb::task_result::Status::Failed);
                    exit = match status {
                        pb::task_result::Status::Succeeded => ExitCode::SUCCESS,
                        pb::task_result::Status::Failed => {
                            ExitCode::from(u8::try_from(r.exit_code.clamp(1, 255)).unwrap_or(1))
                        }
                        other => {
                            let why = r.error.map(|e| e.message).unwrap_or_default();
                            eprintln!(
                                "gmc: task {}: {why}",
                                other
                                    .as_str_name()
                                    .trim_start_matches("STATUS_")
                                    .to_lowercase()
                            );
                            ExitCode::from(125)
                        }
                    };
                }
                _ => {}
            },
            Some(l::job_event::Event::Done(_)) => break,
            _ => {}
        }
    }
    Ok(exit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_parse() {
        assert_eq!(parse_size("4g").unwrap(), 4 << 30);
        assert_eq!(parse_size("512m").unwrap(), 512 << 20);
        assert_eq!(parse_size("1.5G").unwrap(), 3 << 29);
        assert!(parse_size("-1g").is_err());
        assert!(parse_size("lots").is_err());
    }

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
