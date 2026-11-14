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

mod mcp;
mod tasks;

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
        /// Keep lending while the computer is hot (default: pause until it cools down).
        #[arg(long)]
        when_hot: bool,
    },
    /// Stop all lending now (revokes every grant, stops running tasks).
    Stop,
    /// Show or choose how tasks from other devices may run here: `container` (Docker or
    /// compatible), `sandbox` (this computer's own sandbox and installed tools), or `none`.
    /// Adding one needs Touch ID, Windows Hello or your password.
    Runtimes {
        #[arg(value_parser = ["container", "sandbox", "none"])]
        lend: Vec<String>,
    },
    /// Require Touch ID, Windows Hello or your password before approving anything (default: on). Turning it off
    /// needs Touch ID, Windows Hello or your password; machines with no screen use `gmcd --no-presence` instead.
    Presence {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// Pair with another device: give a nearby device's name (see `gmc nearby`) or its
    /// ticket. Without one: open pairing mode, so nearby devices can find this one for 2 minutes
    /// (and print a ticket for devices on other networks).
    Pair { target: Option<String> },
    /// Devices nearby with pairing mode open.
    Nearby,
    /// Local discovery: `on` (paired devices find each other with identifiers only they
    /// recognise; the default) or `off` (no adverts, no listening).
    Discovery {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// List paired devices.
    Peers,
    /// Forget a paired device (revokes everything it holds here).
    Unpair { peer: String },
    /// Trusted mode with a paired device: lets Python code send functions and results as
    /// pickles (lambdas, notebooks), which means that device can run any code on this one.
    /// Both devices must turn it on; it lapses after 30 days. `off` ends it and its grants.
    Trust {
        peer: String,
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
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
    /// What runs on this computer for other devices: each task's command, what it asked for
    /// and what it uses. `--all` adds what ran recently.
    Tasks {
        #[command(subcommand)]
        action: Option<TaskCmd>,
        /// Also list tasks that finished since GimmeCores started.
        #[arg(long)]
        all: bool,
        /// Redraw every second until Ctrl-C.
        #[arg(long)]
        watch: bool,
    },
    /// Run a command on a device that granted you resources.
    Run(RunArgs),
    /// Measure the link to a paired device (round trip and encrypted throughput).
    LinkTest { peer: String },
    /// Serve the Model Context Protocol on stdin/stdout, so AI agents (Claude Code, Claude
    /// Desktop, ...) can run commands on devices that granted you resources. Agents cannot ask
    /// for or approve access, override the secret scan, or send folders outside --root.
    Mcp {
        /// A folder agents may send (repeatable). Default: the folder this starts in. The disk
        /// root and your home folder are refused.
        #[arg(long = "root")]
        roots: Vec<PathBuf>,
    },
    /// Show the audit log of everything that happened on this device.
    Audit {
        /// Check that no entry was changed, removed or reordered.
        #[arg(long)]
        verify: bool,
    },
}

/// gmcd: the GimmeCores background service.
#[derive(clap::Parser)]
#[command(name = "gmcd", version)]
struct DaemonArgs {
    /// Name other devices will see.
    #[arg(long)]
    name: Option<String>,
    /// Approve pairings and requests without Touch ID, Windows Hello or a password, for machines with no screen
    /// (servers, Raspberry Pis). Applies only while this daemon runs; audited.
    #[arg(long)]
    no_presence: bool,
    /// Address to listen on for other devices.
    #[arg(long, default_value_t = SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT)))]
    listen: SocketAddr,
    /// Where to keep this device's identity key: `file` (owner-only file, the default) or
    /// `keychain` (macOS login Keychain, opt-in: the key file is moved in, and macOS asks once
    /// after each rebuild or upgrade until releases are signed). Without this flag the key stays
    /// where it is. A key in the Keychain never moves back out.
    #[arg(long, value_parser = ["keychain", "file"])]
    identity_store: Option<String>,
}

#[derive(Subcommand)]
enum TaskCmd {
    /// Stop one task running here for another device (give the start of its id). Its grant
    /// and the device's other tasks are not touched.
    Stop { id: String },
}

#[derive(Subcommand)]
enum GrantCmd {
    /// Ask a paired device for resources (its owner decides).
    Request {
        peer: String,
        /// Where your tasks may run on the lender: container, sandbox or any.
        #[arg(long, default_value = "any", value_parser = ["any", "container", "sandbox"])]
        runtime: String,
        #[arg(long, default_value_t = 2)]
        cpus: u32,
        #[arg(long, default_value = "4g")]
        memory: String,
        #[arg(long, default_value_t = 2)]
        hours: u64,
        #[arg(long, default_value = "")]
        reason: String,
        /// Ask for a Trusted grant (needs Trusted mode on both devices: `gmc trust`).
        #[arg(long)]
        trusted: bool,
    },
}

#[derive(clap::Args)]
struct RunArgs {
    /// Device to run on (name or fingerprint); default: any device that granted you resources.
    #[arg(long)]
    peer: Option<String>,
    /// Container image to run in (container runtime only).
    #[arg(long)]
    image: Option<String>,
    /// Where to run on the lender: container or sandbox. Default: container if --image is
    /// given, else sandbox (the lender's own tools, no container runtime needed).
    #[arg(long, value_parser = ["container", "sandbox"])]
    runtime: Option<String>,
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

/// Devices nearby with pairing mode open.
async fn nearby(paths: &Paths) -> Result<Vec<l::Peer>> {
    Ok(client(paths)
        .await?
        .list_peers(l::ListPeersRequest {
            include_discovered: true,
        })
        .await
        .map_err(status_err)?
        .into_inner()
        .peers
        .into_iter()
        .filter(|p| !p.paired)
        .collect())
}

fn mode_names(modes: &[i32]) -> String {
    let names: Vec<&str> = modes
        .iter()
        .filter_map(|m| match pb::ExecutionMode::try_from(*m) {
            Ok(pb::ExecutionMode::Container) => Some("container"),
            Ok(pb::ExecutionMode::Sandbox) => Some("sandbox"),
            Ok(pb::ExecutionMode::Native) => Some("native"),
            _ => None,
        })
        .collect();
    if names.is_empty() {
        "nothing".into()
    } else {
        names.join(", ")
    }
}

/// What each way of running means for the lender, in plain words.
fn runs_in(modes: &[i32]) -> Vec<&'static str> {
    modes
        .iter()
        .filter_map(|m| match pb::ExecutionMode::try_from(*m) {
            Ok(pb::ExecutionMode::Container) => {
                Some("a container (Docker): it cannot see your files or other apps")
            }
            Ok(pb::ExecutionMode::Sandbox) => Some(
                "this computer's sandbox, as your user: only its own folder, no network; uses your installed tools; CPU and memory limits are monitored, not hard",
            ),
            Ok(pb::ExecutionMode::Native) => Some("directly as you, WITHOUT a sandbox"),
            _ => None,
        })
        .collect()
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
/// The daemon will ask the OS to confirm the owner is present (I13).
fn presence_hint() {
    let how = if cfg!(target_os = "macos") {
        "Touch ID or your password"
    } else if cfg!(windows) {
        "Windows Hello: your PIN, face or fingerprint"
    } else {
        "your password"
    };
    println!("Confirm on this device if asked ({how})...");
}

/// A date as `YYYY-MM-DD (in N days)`, in UTC (no time-zone database needed).
fn when(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let now = i64::try_from(gimmecores_node::now()).unwrap_or(0);
    let left = ((unix - now).max(0) + 86_399) / 86_400;
    format!("{y:04}-{m:02}-{d:02} (in {left} days)")
}

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
    // Windows: gmcd is a windowed program (no console window at login); its output goes to
    // the terminal that started it, wherever it was redirected, or to gmcd.log in its home.
    if cfg!(windows)
        && let Ok(paths) = gimmecores_node::paths::Paths::from_env()
    {
        let home = paths.root();
        if !home.exists() && std::fs::create_dir_all(home).is_ok() {
            let _ = gimmecores_os::private::restrict_dir(home);
        }
        gimmecores_os::console::output_for_background(&home.join("gmcd.log"), 10 << 20);
    }
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let args = <DaemonArgs as clap::Parser>::parse();
    match rt.block_on(daemon(args)) {
        Ok(()) => ExitCode::SUCCESS,
        // Not a failure: one is already serving. Exiting cleanly also keeps a second
        // background service (launchd, systemd, brew services) from restarting it in a loop.
        Err(e) if e.is::<gimmecores_node::node::AlreadyRunning>() => {
            eprintln!("{e}");
            ExitCode::SUCCESS
        }
        // Not restarted by launchd/systemd into prompt after prompt: it needs the owner.
        Err(e) if e.is::<gimmecores_node::identity::KeychainUnavailable>() => {
            eprintln!("gmcd is not running: {e}");
            ExitCode::SUCCESS
        }
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
    let store = match args.identity_store.as_deref() {
        Some("keychain") => gimmecores_node::identity::IdentityStore::Keychain,
        Some(_) => gimmecores_node::identity::IdentityStore::File,
        None => gimmecores_node::identity::current_store(&paths),
    };
    gimmecores_node::identity::prepare(&paths, store)?;
    let name = args
        .name
        .or_else(sysinfo::System::host_name)
        .unwrap_or_else(|| "GimmeCores device".into());
    let docker = DockerExecutor::default();
    let node = Node::start(NodeConfig {
        paths: paths.clone(),
        device_name: name,
        bind: args.listen,
        executors: gimmecores_node::exec::Executors {
            container: Some(Arc::new(docker)),
            sandbox: Some(Arc::new(
                gimmecores_node::sandbox::SandboxExecutor::default(),
            )),
        },
        presence: Arc::new(gimmecores_node::presence::OsPresence),
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
    if args.no_presence {
        node.waive_presence_for_this_run();
    }
    let (required, method) = node.presence();
    if required {
        println!("  approval: needs you present ({method})");
    } else {
        println!(
            "  WARNING:  presence checks are OFF: anything that can run commands as you can approve requests (`gmc presence on`)"
        );
    }
    let (lent, works) = node.lend_modes();
    let names = |m: gimmecores_core::Modes| {
        let v: Vec<&str> = m.iter().map(gimmecores_node::exec::mode_name).collect();
        if v.is_empty() {
            "nothing".to_string()
        } else {
            v.join(", ")
        }
    };
    println!(
        "  runs in:  {} (works here now: {}; change with `gmc runtimes`)",
        names(lent),
        names(works)
    );
    if lent.container && !works.container {
        println!("  warning:  Docker is not running; container tasks are refused until it is.");
    }
    tokio::select! {
        r = api::serve(node.clone()) => r?,
        () = stop_requested() => println!("\nstopping"),
    }
    node.shutdown().await;
    Ok(())
}

/// Resolves when this process is asked to stop: Ctrl-C, or the signal a service manager sends
/// (launchd, systemd, `brew services stop`, the app's switch, logging out, a closed terminal).
/// All of them must end in `Node::shutdown`, which stops the tasks running here.
async fn stop_requested() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let (Ok(mut term), Ok(mut hup)) = (
            signal(SignalKind::terminate()),
            signal(SignalKind::hangup()),
        ) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
                _ = hup.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
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
    if ok {
        presence_hint();
    }
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
                "  rules:    {}, {}, {}",
                if s.pause_on_battery {
                    "pauses on battery"
                } else {
                    "lends on battery"
                },
                if cfg!(windows) {
                    // Windows gives no temperature reading: the rule never triggers.
                    "heat not measured on Windows"
                } else if s.pause_when_hot {
                    "pauses when hot"
                } else {
                    "lends when hot"
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
            println!("  identity: kept in {}", s.identity_store);
            println!(
                "  approval: {}",
                if s.presence_required {
                    format!("needs you present ({})", s.presence_method)
                } else {
                    "WITHOUT presence checks".to_string()
                }
            );
            println!(
                "  runs in:  {} (works here now: {})",
                mode_names(&s.lend_modes),
                mode_names(&s.available_modes)
            );
            println!("  running for others: {} task(s)", s.active_lent_tasks);
            if !s.performance_note.is_empty() {
                println!("  speed:    REDUCED. {}", s.performance_note);
            }
        }
        Cmd::Lend {
            state,
            when_idle,
            on_battery,
            when_hot,
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
            if enable {
                presence_hint();
            }
            control(&paths)
                .await?
                .set_lending(l::SetLendingRequest {
                    enabled: enable,
                    idle_only: when_idle,
                    allow_on_battery: on_battery,
                    allow_when_hot: when_hot,
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
        Cmd::Presence { state } => {
            let required = state == "on";
            if !required
                && !confirm(
                    "Approve pairings and requests WITHOUT Touch ID, Windows Hello or a password? Anything that can run commands as you could then approve them.",
                )?
            {
                println!("Presence checks stay on.");
                return Ok(ExitCode::SUCCESS);
            }
            if !required {
                presence_hint();
            }
            control(&paths)
                .await?
                .set_presence(l::SetPresenceRequest { required })
                .await
                .map_err(status_err)?;
            println!(
                "Presence checks are {}.",
                if required { "on" } else { "OFF" }
            );
        }
        Cmd::Runtimes { lend } if lend.is_empty() => {
            let s = client(&paths)
                .await?
                .get_status(l::GetStatusRequest {})
                .await
                .map_err(status_err)?
                .into_inner();
            println!("Lends tasks in: {}", mode_names(&s.lend_modes));
            println!("Works here now: {}", mode_names(&s.available_modes));
            for line in runs_in(&s.lend_modes) {
                println!("  - {line}");
            }
        }
        Cmd::Runtimes { lend } => {
            let mut modes = Vec::new();
            for m in &lend {
                match m.as_str() {
                    "container" => modes.push(pb::ExecutionMode::Container as i32),
                    "sandbox" => modes.push(pb::ExecutionMode::Sandbox as i32),
                    _ => {}
                }
            }
            if lend.iter().any(|m| m == "none") && !modes.is_empty() {
                bail!("`none` cannot be combined with other runtimes");
            }
            presence_hint();
            let s = control(&paths)
                .await?
                .set_lend_modes(l::SetLendModesRequest { modes })
                .await
                .map_err(status_err)?
                .into_inner();
            println!("Lends tasks in: {}", mode_names(&s.lend_modes));
            let missing: Vec<i32> = s
                .lend_modes
                .iter()
                .filter(|m| !s.available_modes.contains(m))
                .copied()
                .collect();
            if !missing.is_empty() {
                println!(
                    "Note: not available on this machine right now: {} (tasks in it are refused until it is)",
                    mode_names(&missing)
                );
            }
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
        Cmd::Pair { target: None } => {
            let mut ctl = control(&paths).await?;
            let r = ctl
                .open_pairing(l::OpenPairingRequest {})
                .await
                .map_err(status_err)?
                .into_inner();
            println!(
                "Pairing mode is open for 2 minutes. On the other device run `gmc nearby`, then\n`gmc pair <this device's name>`. From another network, use the ticket instead:\n\n    gmc pair {}\n",
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
        Cmd::Pair { target: Some(t) } => {
            let target = if t.starts_with("gmc1:") {
                l::start_pairing_request::Target::Ticket(t)
            } else {
                let nearby = nearby(&paths).await?;
                let wanted = t.to_lowercase();
                let hits: Vec<&l::Peer> = nearby
                    .iter()
                    .filter(|p| {
                        p.device_name.to_lowercase() == wanted
                            || p.fingerprint.to_lowercase().starts_with(&wanted)
                    })
                    .collect();
                match hits.as_slice() {
                    [p] => l::start_pairing_request::Target::PeerFingerprint(p.fingerprint.clone()),
                    [] => bail!(
                        "no nearby device called {t:?} has pairing mode open (see `gmc nearby`, or use its ticket)"
                    ),
                    _ => bail!(
                        "several nearby devices match {t:?}; use the fingerprint from `gmc nearby`"
                    ),
                }
            };
            let mut ctl = control(&paths).await?;
            let s = ctl
                .start_pairing(l::StartPairingRequest {
                    target: Some(target),
                })
                .await
                .map_err(status_err)?
                .into_inner();
            finish_pairing(&mut ctl, s).await?;
        }
        Cmd::Nearby => {
            let found = nearby(&paths).await?;
            if found.is_empty() {
                println!(
                    "No nearby device has pairing mode open. On the other device run `gmc pair` (or use the desktop app)."
                );
            }
            for p in found {
                println!("{}  ({})", p.device_name, p.fingerprint);
            }
        }
        Cmd::Discovery { state } => {
            let mode = if state == "on" {
                l::DiscoveryMode::PairedOnly
            } else {
                l::DiscoveryMode::Off
            };
            control(&paths)
                .await?
                .set_discovery(l::SetDiscoveryRequest { mode: mode as i32 })
                .await
                .map_err(status_err)?;
            println!(
                "Discovery is {}.",
                if state == "on" {
                    "on: your paired devices find each other; nothing identifies this device to anyone else"
                } else {
                    "off: no adverts, no listening (reach devices by their last address or a ticket)"
                }
            );
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
                let link = p.links.first().map_or_else(
                    || "link not measured (gmc link-test <name>)".to_string(),
                    |l| {
                        let ms = l.rtt_median.map_or(0.0, |d| {
                            d.seconds as f64 * 1000.0 + f64::from(d.nanos) / 1e6
                        });
                        format!(
                            "{} · {:.0} Mbps · {:.2} ms · good for: {}",
                            l.interface_kind,
                            l.upload_bits_per_second.min(l.download_bits_per_second) as f64 / 1e6,
                            ms,
                            l.good_for.join(", ")
                        )
                    },
                );
                println!("{:<28} {}  {}", p.device_name, p.fingerprint, link);
                if let Some(until) = p.trusted_until {
                    println!(
                        "{:<28} TRUSTED here until {}{}",
                        "",
                        when(until.seconds),
                        if p.trusted_mode_remote {
                            " (and there)"
                        } else {
                            ""
                        }
                    );
                }
            }
        }
        Cmd::Trust { peer, state } => {
            let enabled = state == "on";
            if enabled {
                println!(
                    "WARNING: Trusted mode lets {peer:?} run any code on your machine through \
                     returned results. Only enable it between your own devices or someone you \
                     trust completely. It lasts 30 days; the other device must turn it on too."
                );
                if !confirm("Turn on Trusted mode?")? {
                    println!("Nothing changed.");
                    return Ok(ExitCode::FAILURE);
                }
                presence_hint();
            }
            let p = control(&paths)
                .await?
                .set_trusted_mode(l::SetTrustedModeRequest {
                    peer_fingerprint: peer.clone(),
                    enabled,
                    warning_acknowledged: enabled,
                })
                .await
                .map_err(status_err)?
                .into_inner();
            match p.trusted_until {
                Some(until) => println!(
                    "Trusted mode with {:?} is on here until {}. Ask for a Trusted grant with \
                     `gmc grants request {peer} --trusted` once it is on there too.",
                    p.device_name,
                    when(until.seconds)
                ),
                None => println!("Trusted mode with {peer:?} is off; its Trusted grants ended."),
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
                let trusted = g
                    .grant
                    .as_ref()
                    .is_some_and(|x| x.trust == pb::TrustLevel::Trusted as i32);
                println!(
                    "{}  {:<5} {:<9} {} cores, {}  peer {}{}  {}",
                    hex::encode(&g.grant_id),
                    if g.as_lender { "lent" } else { "held" },
                    state,
                    f64::from(limits.cpu_millis) / 1000.0,
                    gib(limits.memory_bytes),
                    g.peer_fingerprint,
                    if trusted { "  TRUSTED" } else { "" },
                    g.state_reason
                );
            }
        }
        Cmd::Grants {
            action:
                Some(GrantCmd::Request {
                    peer,
                    runtime,
                    cpus,
                    memory,
                    hours,
                    reason,
                    trusted,
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
                modes: match runtime.as_str() {
                    "container" => vec![pb::ExecutionMode::Container as i32],
                    "sandbox" => vec![pb::ExecutionMode::Sandbox as i32],
                    _ => vec![
                        pb::ExecutionMode::Container as i32,
                        pb::ExecutionMode::Sandbox as i32,
                    ],
                },
                network: pb::NetworkPolicy::None as i32,
                duration: Some(prost_types::Duration {
                    seconds: i64::try_from(hours * 3600)?,
                    nanos: 0,
                }),
                trust: if trusted {
                    pb::TrustLevel::Trusted as i32
                } else {
                    pb::TrustLevel::Standard as i32
                },
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
                let modes = g
                    .grant
                    .as_ref()
                    .map(|x| x.modes.clone())
                    .unwrap_or_default();
                println!(
                    "Granted ({}), runs in: {}. Run work with `gmc run -- <command>`.",
                    hex::encode(&g.grant_id),
                    mode_names(&modes)
                );
            } else {
                println!("Declined: {}", g.state_reason);
                return Ok(ExitCode::FAILURE);
            }
        }
        Cmd::Tasks { action, all, watch } => {
            return tasks::run(&paths, action, all, watch).await;
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
                for line in runs_in(
                    &g.grant
                        .as_ref()
                        .map(|x| x.modes.clone())
                        .unwrap_or_default(),
                ) {
                    println!("  Runs in:  {line}");
                }
                println!("  Network:  none while running; nothing is downloaded");
                if g.grant
                    .as_ref()
                    .is_some_and(|x| x.trust == pb::TrustLevel::Trusted as i32)
                {
                    println!(
                        "  TRUSTED:  Python objects (pickles) may be exchanged both ways; tasks \
                         still run in the sandbox or a container here"
                    );
                }
                println!(
                    "  The device can stop being trusted at any time with `gmc revoke` or `gmc stop`."
                );
                let accept = confirm("Accept this request?")?;
                if accept {
                    presence_hint();
                }
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
        Cmd::LinkTest { peer } => {
            println!("Measuring the link to {peer:?} (about 5 seconds)...");
            let s = client(&paths)
                .await?
                .link_test(l::LinkTestRequest {
                    peer_fingerprint: peer,
                })
                .await
                .map_err(status_err)?
                .into_inner();
            let ms = |d: Option<prost_types::Duration>| {
                d.map_or(0.0, |d| {
                    d.seconds as f64 * 1000.0 + f64::from(d.nanos) / 1e6
                })
            };
            let mbps = |b: u64| b as f64 / 1e6;
            println!("  link:      {}", s.interface_kind);
            println!(
                "  round trip: {:.2} ms min, {:.2} ms median, {:.2} ms p95",
                ms(s.rtt_min),
                ms(s.rtt_median),
                ms(s.rtt_p95)
            );
            println!(
                "  speed:     {:.0} Mbps up, {:.0} Mbps down (encrypted, as GimmeCores sees it)",
                mbps(s.upload_bits_per_second),
                mbps(s.download_bits_per_second)
            );
            println!("  good for:  {}", s.good_for.join(", "));
        }
        Cmd::Mcp { roots } => {
            mcp::serve(paths.client_socket(), roots).await?;
        }
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
    let mode = match args.runtime.as_deref() {
        Some("container") => pb::ExecutionMode::Container as i32,
        Some("sandbox") => pb::ExecutionMode::Sandbox as i32,
        _ => pb::ExecutionMode::Unspecified as i32,
    };
    let task = l::InlineTask {
        name: "run".into(),
        mode,
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
    fn dates_are_civil_utc() {
        assert!(when(0).starts_with("1970-01-01"));
        assert!(when(951_782_400).starts_with("2000-02-29"));
        assert!(when(1_794_528_000).starts_with("2026-11-13"));
    }

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
