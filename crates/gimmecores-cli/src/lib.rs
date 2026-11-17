//! The `gimmecores` / `gmc` command line and the `gmcd` daemon.

use std::io::{IsTerminal, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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

mod bench;
mod mcp;
mod placement;
mod tasks;

pub const DEFAULT_PORT: u16 = 47474;

/// This build: "0.1.1 (943d37b 2026-11-16)" (commit and its date), or the bare version when
/// built outside a git checkout (build_info.rs).
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), env!("GMC_VERSION_SUFFIX"));

#[derive(Parser)]
#[command(
    name = "gmc",
    version = VERSION,
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
    /// Show or choose how tasks from other devices run here: full (like your own apps),
    /// apps-first (your apps come first; the default) or background (idle time only). A
    /// faster level needs Touch ID, Windows Hello or your password. Grants that named a speed
    /// keep the one you approved.
    Speed {
        #[arg(value_parser = ["full", "apps-first", "background"])]
        level: Option<String>,
    },
    /// Let devices you lend to see how busy this whole computer is: CPU, memory and GPUs, your
    /// own apps included (default: off). Only devices holding a live grant from you see it.
    /// Turning it on needs Touch ID, Windows Hello or your password.
    ShareLoad {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// Keep this computer from going to sleep while tasks from other devices run (default: on).
    /// Turning it back on needs Touch ID, Windows Hello or your password. Closing a laptop's lid
    /// still puts it to sleep.
    KeepAwake {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// List this computer's tools and versions (Python, Node, Rust, Go, ...) in the grants it
    /// gives for its sandbox, so borrowers and agents know what their tasks will find
    /// (default: on). Turning it back on needs Touch ID, Windows Hello or your password.
    ShareTools {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// Compare this computer's tools with a device's (from its latest grant for its sandbox):
    /// what is missing there, and versions that differ.
    Doctor {
        #[arg(long)]
        peer: String,
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
    /// Let a paired device wake this computer from sleep (Wake-on-LAN), or stop letting it.
    /// It then receives this computer's network card addresses; `off` makes it forget them.
    /// Allowing needs Touch ID, Windows Hello or your password.
    AllowWake {
        peer: String,
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// Wake a paired device that let this one wake it (Wake-on-LAN). `gmc run` and
    /// `gmc grants request` also do this by themselves when it does not answer.
    Wake { peer: String },
    /// Standing grants: accept requests from one of your devices without asking, within
    /// limits you set once (Touch ID, Windows Hello or your password). Each grant lasts at
    /// most 8 hours; the standing grant lapses after 30 days unless you set it again.
    /// Without a subcommand: list them.
    Standing {
        #[command(subcommand)]
        action: Option<StandingCmd>,
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
    /// Is sending work to a device worth it? Measures the link, the cost of starting a task
    /// there, its speed per core and on all the cores its grant gives against this computer,
    /// and the upload speed, then says which jobs finish sooner there (about half a minute;
    /// needs a live grant for its sandbox). `gmc peers` shows the last result.
    Bench { peer: String },
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
#[command(name = "gmcd", version = VERSION)]
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

/// The speed a held grant gives your tasks on the lender: "apps-first (fixed for this grant)",
/// or the owner's setting, which tasks follow at start.
pub(crate) fn grant_speed(g: &pb::Grant) -> String {
    use gimmecores_node::grants_flow::speed_from;
    match (speed_from(g.speed), speed_from(g.lender_speed)) {
        (Some(s), _) => format!("{} (fixed for this grant)", s.name()),
        (None, Some(s)) => format!(
            "{} (the owner's setting when granted; it can change)",
            s.name()
        ),
        (None, None) => "the owner's setting".to_string(),
    }
}

/// "up to 4 cores, 8.0 GiB memory, 10.0 GiB disk, container or sandbox, grants up to 8 h".
fn standing_text(r: &l::StandingRule) -> String {
    let lim = r.limits.unwrap_or_default();
    let speed = gimmecores_node::grants_flow::speed_from(r.speed)
        .map_or(String::new(), |s| format!(", speed up to {}", s.name()));
    let images = if r.images_bytes > 0 {
        format!(", images up to {}", gib(r.images_bytes))
    } else {
        String::new()
    };
    format!(
        "up to {} cores, {} memory, {} disk, {}{speed}{images}, grants up to {} h",
        f64::from(lim.cpu_millis) / 1000.0,
        gib(lim.memory_bytes),
        gib(lim.disk_bytes),
        mode_names(&r.modes),
        r.max_hours
    )
}

/// The tools a device listed in the newest grant this one holds from it, if any.
fn held_tools(held: &[l::GrantInfo], fingerprint: &str) -> Option<Vec<(String, String)>> {
    held.iter()
        .filter(|g| !g.as_lender && g.peer_fingerprint == fingerprint)
        .filter_map(|g| g.grant.as_ref())
        .filter(|g| !g.tools.is_empty())
        .max_by_key(|g| g.issued_at.map_or(0, |t| t.seconds))
        .map(|g| gimmecores_node::tools::from_proto(&g.tools))
}

/// "python3 3.13.2, node 22.11.0".
fn tools_text(t: &[(String, String)]) -> String {
    t.iter()
        .map(|(n, v)| format!("{n} {v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `gmc doctor --peer`: this computer's tools against a device's.
/// The paired device `who` names: by fingerprint, or by name when only one has it (as gmcd
/// resolves names).
pub(crate) fn pick_peer<'a>(peers: &'a [l::Peer], who: &str) -> Result<&'a l::Peer> {
    if let Some(p) = peers.iter().find(|p| p.fingerprint == who) {
        return Ok(p);
    }
    let named: Vec<&l::Peer> = peers.iter().filter(|p| p.device_name == who).collect();
    match named[..] {
        [p] => Ok(p),
        [] => bail!("no paired device named {who:?}"),
        _ => bail!(
            "more than one paired device is named {who:?}: give the fingerprint of the one you \
             mean (`gmc peers`)"
        ),
    }
}

async fn doctor(paths: &Paths, peer: &str) -> Result<ExitCode> {
    let mut c = client(paths).await?;
    let peers = c
        .list_peers(l::ListPeersRequest {
            include_discovered: false,
        })
        .await
        .map_err(status_err)?
        .into_inner()
        .peers;
    let p = pick_peer(&peers, peer)?;
    let held = c
        .list_grants(l::ListGrantsRequest {
            include_inactive: false,
        })
        .await
        .map_err(status_err)?
        .into_inner()
        .grants;
    let Some(there) = held_tools(&held, &p.fingerprint) else {
        println!(
            "{:?} has not listed its tools: it needs a live grant to you for its sandbox, from \
             GimmeCores 0.1.1 or later with `gmc share-tools on` (the default).",
            p.device_name
        );
        return Ok(ExitCode::FAILURE);
    };
    let here = gimmecores_node::tools::probe().await;
    println!("{:<10} {:<14} {:<14}", "tool", "here", p.device_name);
    let mut differ = 0;
    for (tool, _) in gimmecores_node::tools::TOOLS {
        let h = here
            .iter()
            .find(|(n, _)| n == tool)
            .map(|(_, v)| v.as_str());
        let t = there
            .iter()
            .find(|(n, _)| n == tool)
            .map(|(_, v)| v.as_str());
        if h.is_none() && t.is_none() {
            continue;
        }
        let note = match (h, t) {
            (Some(_), None) => "MISSING there",
            (Some(a), Some(b))
                if gimmecores_node::tools::major_minor(a)
                    != gimmecores_node::tools::major_minor(b) =>
            {
                "differs"
            }
            _ => "",
        };
        if !note.is_empty() {
            differ += 1;
        }
        println!(
            "{:<10} {:<14} {:<14} {note}",
            tool,
            h.unwrap_or("-"),
            t.unwrap_or("-")
        );
    }
    if differ == 0 {
        println!("Everything this computer has, it has too (same major.minor versions).");
    }
    Ok(ExitCode::SUCCESS)
}

/// Said when a grant leaves tasks below full speed: between your own devices, ask for full.
const FULL_SPEED_TIP: &str = "Lending between your own devices? Ask with `--speed full` \
     to run at full speed (the owner approves it).";

/// `gmc grants request` when nobody answered on the lender: try again later (EX_TEMPFAIL).
const EXIT_NO_ANSWER: u8 = 75;

#[derive(Subcommand)]
enum StandingCmd {
    /// Create, renew or change the standing grant for a paired device. Requests it sends
    /// within these limits are then accepted without asking you (Standard grants only).
    Set {
        peer: String,
        /// Where its tasks may run here: container, sandbox or any.
        #[arg(long, default_value = "any", value_parser = ["any", "container", "sandbox"])]
        runtime: String,
        #[arg(long, default_value_t = 2)]
        cpus: u32,
        #[arg(long, default_value = "4g")]
        memory: String,
        #[arg(long, default_value = "10g")]
        disk: String,
        /// The longest grant it accepts, in hours (1 to 8).
        #[arg(long, default_value_t = 8)]
        hours: u32,
        /// The fastest speed it approves: full, apps-first or background. Default: none faster
        /// than your own setting (`gmc speed`).
        #[arg(long, value_parser = ["full", "apps-first", "background"])]
        speed: Option<String>,
        /// Let it send its own container images, up to this much of your disk, e.g. `8g`.
        #[arg(long, default_value = "0")]
        images: String,
    },
    /// End the standing grant for a device, and revoke the grants it accepted.
    Off { peer: String },
}

#[derive(Subcommand)]
enum GrantCmd {
    /// Ask a paired device for resources (its owner decides).
    ///
    /// Exit status: 0 granted, 1 declined, 75 nobody answered in time (nothing was granted;
    /// ask again later).
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
        /// How your tasks are scheduled against the lender's own apps: full, apps-first or
        /// background. Default: whatever the lender's owner chose. Faster than their choice is
        /// shown to them and needs their approval like the rest of the request.
        #[arg(long, value_parser = ["full", "apps-first", "background"])]
        speed: Option<String>,
        /// Let `gmc run --image` send your own container images (from this computer's Docker)
        /// when the lender lacks them, taking up to this much of its disk, e.g. `8g`. Only the
        /// layers it lacks travel; they are removed when your grants there end. Default: none.
        #[arg(long, default_value = "0")]
        images: String,
        /// Do not wait for its owner: the device keeps the request (up to 24 hours) and
        /// `gmc grants` shows it until it is answered (then the grant, if accepted).
        #[arg(long)]
        no_wait: bool,
    },
}

#[derive(clap::Args)]
struct RunArgs {
    /// Device to run on (name or fingerprint); default: any device that granted you resources.
    #[arg(long)]
    peer: Option<String>,
    /// Container image to run in (container runtime only): one the lender has, or your own
    /// from this computer's Docker, sent if the grant allows images (`grants request --images`);
    /// only the layers the lender lacks travel.
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
    /// A folder the lender keeps between this project's runs, e.g. `target` or `.cache/npm`
    /// (repeatable, up to 8): builds start warm. Not uploaded; kept only while you hold a live
    /// grant there, counted in its disk limit, never seen by other devices. Bring it back with
    /// `--out` if you want its contents here.
    #[arg(long = "cache")]
    caches: Vec<String>,
    /// Fetch the dependencies of this project's lockfile here and send them, so the task can
    /// build without network there: `cargo` (Cargo.lock), `npm` (package-lock.json), `go`
    /// (go.mod), or `auto` (whichever lockfiles are here). Kept in a cache on this computer and
    /// fetched again only when the lockfile changes; your project is not touched.
    #[arg(long = "deps", value_parser = ["cargo", "npm", "go", "auto"])]
    deps: Vec<String>,
    /// Filled from --deps: what the task gets.
    #[arg(skip)]
    deps_env: Vec<(String, String)>,
    #[arg(skip)]
    deps_files: Vec<l::Attachment>,
    /// Send this file even though the secret scan flags it (repeatable; path relative to here).
    #[arg(long = "allow-secret")]
    allow_secrets: Vec<String>,
    /// Timeout in seconds.
    #[arg(long, default_value_t = 3600)]
    timeout: u64,
    /// Run gentler than the grant allows: apps-first or background (the lender takes the
    /// slower of this and the grant's speed, so asking for more has no effect).
    #[arg(long, value_parser = ["full", "apps-first", "background"])]
    speed: Option<String>,
    /// Where to run: `remote` (a device that granted you resources), `local` (here, as a
    /// normal program in this folder) or `auto` (here when no device granted anything or this
    /// computer has enough idle cores, otherwise the device with the most room).
    #[arg(long = "where", default_value = "remote", value_parser = ["remote", "local", "auto"])]
    place: String,
    /// Run the command N times as shards spread over every device that granted you resources
    /// (and this computer with `--where auto` or `local`). Shard k of N gets `{shard}` in the
    /// command replaced by `k/N` and `GMC_SHARD=k`, `GMC_SHARDS=N` (pytest-split, `jest
    /// --shard`, `vitest --shard`); output lines are prefixed `[k/N]`, a remote shard's `--out`
    /// files come back under `out/shard-k/`, and the exit code is the worst shard's.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=256))]
    shards: u32,
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
                Some(
                    "a container (Docker): it cannot see your files or other apps, but it can run any Docker image on this computer and read what is inside it",
                )
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
        "Windows Hello; without it, your Windows password after Ctrl+Alt+Delete"
    } else {
        "your password"
    };
    println!("Confirm on this device if asked ({how})...");
}

/// A date as `YYYY-MM-DD (in N days)`, in UTC (no time-zone database needed).
/// "2026-11-16 07:22:03" (UTC), for logs.
fn stamp(unix: u64) -> String {
    let secs = i64::try_from(unix).unwrap_or(0);
    let t = secs.rem_euclid(86_400);
    format!(
        "{} {:02}:{:02}:{:02}",
        date(secs),
        t / 3600,
        t % 3600 / 60,
        t % 60
    )
}

fn when(unix: i64) -> String {
    let now = i64::try_from(gimmecores_node::now()).unwrap_or(0);
    let left = ((unix - now).max(0) + 86_399) / 86_400;
    format!("{} (in {left} days)", date(unix))
}

/// "2026-11-16" (UTC).
fn date(unix: i64) -> String {
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
    format!("{y:04}-{m:02}-{d:02}")
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
    gimmecores_node::set_software_version(VERSION);
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
            images: Some(Arc::new(gimmecores_node::images::DockerImages {
                docker: docker.docker.clone(),
            })),
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
    // Kept in the service's log, so a later problem can be matched with what ran when.
    println!(
        "  started:  {} UTC, GimmeCores {VERSION}, from {}",
        stamp(gimmecores_node::now()),
        std::env::current_exe().map_or_else(|_| "?".into(), |p| p.display().to_string())
    );
    println!("  state:    {}", paths.root().display());
    println!(
        "  network:  {} (LAN only; no relays, no router port mapping)",
        args.listen
    );
    println!(
        "  lending:  {}",
        if gimmecores_node::node::LENDING_UNAVAILABLE.is_some() {
            "not available on this platform yet (borrowing works)"
        } else if node.lending_enabled() {
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
    // Notes the time if this program is removed while it runs (#20: an app that vanished
    // from Applications); `gmc status` and the MCP tools then say so too.
    let watch = {
        let node = node.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                if let Some(p) = node.program_removed() {
                    eprintln!(
                        "{} UTC: this service's program was removed while it ran ({}). \
                         Reinstall GimmeCores, then start it again.",
                        stamp(gimmecores_node::now()),
                        p.display()
                    );
                    break;
                }
            }
        })
    };
    tokio::select! {
        r = api::serve(node.clone()) => r?,
        () = stop_requested() => println!("\nstopping"),
    }
    watch.abort();
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
                if gimmecores_node::node::LENDING_UNAVAILABLE.is_some() {
                    "not available on Windows yet (borrowing from your other computers works)"
                } else if s.lending_enabled {
                    "ON"
                } else {
                    "off"
                }
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
            let gpus: String = caps
                .gpus
                .iter()
                .map(|g| format!(", GPU {}", g.name))
                .collect();
            println!(
                "  machine:  {} {}, {} cores, {}{gpus}",
                caps.os,
                caps.arch,
                caps.cpu_cores,
                gib(caps.memory_bytes)
            );
            println!(
                "  version:  {}",
                if s.version == VERSION {
                    s.version.clone()
                } else if s.version.is_empty() {
                    format!(
                        "older than this gmc ({VERSION}): restart the service to run this version"
                    )
                } else {
                    format!(
                        "{} (this gmc is {VERSION}: restart the service to run it)",
                        s.version
                    )
                }
            );
            if !s.program_removed.is_empty() {
                println!(
                    "  WARNING:  the running service's program was removed ({}). Reinstall \
                     GimmeCores, then start it again.",
                    s.program_removed
                );
            }
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
            println!(
                "  priority: tasks from other devices {} (`gmc speed`)",
                gimmecores_node::speed::runs(
                    gimmecores_node::grants_flow::speed_from(s.task_speed)
                        .unwrap_or(gimmecores_core::Speed::DEFAULT)
                )
            );
            if s.share_load {
                println!(
                    "  sharing:  devices with a grant see how busy this computer is (`gmc share-load off`)"
                );
            }
            if s.share_tools {
                let t: Vec<(String, String)> = s
                    .tools
                    .iter()
                    .map(|t| (t.name.clone(), t.version.clone()))
                    .collect();
                println!(
                    "  tools:    {} (listed in sandbox grants; `gmc share-tools off`)",
                    if t.is_empty() {
                        "none found yet".to_string()
                    } else {
                        tools_text(&t)
                    }
                );
            }
            println!(
                "  sleep:    {}",
                match (s.keep_awake, s.keeping_awake) {
                    (true, true) => "kept awake now: tasks from other devices are running",
                    (true, false) =>
                        "kept awake while tasks from other devices run (`gmc keep-awake`)",
                    (false, _) =>
                        "may sleep while tasks from other devices run (`gmc keep-awake on`)",
                }
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
        Cmd::Speed { level: None } => {
            let s = client(&paths)
                .await?
                .get_status(l::GetStatusRequest {})
                .await
                .map_err(status_err)?
                .into_inner();
            let level = gimmecores_node::grants_flow::speed_from(s.task_speed)
                .unwrap_or(gimmecores_core::Speed::DEFAULT);
            println!(
                "Here, tasks from other devices {} ({}).",
                gimmecores_node::speed::runs(level),
                level.name()
            );
            println!("Change it: gmc speed full|apps-first|background");
        }
        Cmd::Speed { level: Some(level) } => {
            let speed = gimmecores_core::Speed::from_name(&level)
                .ok_or_else(|| anyhow::anyhow!("unknown speed {level}"))?;
            presence_hint();
            control(&paths)
                .await?
                .set_task_speed(l::SetTaskSpeedRequest {
                    speed: gimmecores_node::grants_flow::speed_to(Some(speed)) as i32,
                })
                .await
                .map_err(status_err)?;
            println!(
                "From now on, tasks from other devices {} here ({}). Grants that named a speed keep the one you approved.",
                gimmecores_node::speed::runs(speed),
                speed.name()
            );
        }
        Cmd::ShareTools { state } => {
            let enabled = state == "on";
            if enabled {
                presence_hint();
            }
            control(&paths)
                .await?
                .set_share_tools(l::SetShareToolsRequest { enabled })
                .await
                .map_err(status_err)?;
            println!(
                "{}",
                if enabled {
                    "Grants for this computer's sandbox now list its tools and versions."
                } else {
                    "Grants no longer list this computer's tools."
                }
            );
        }
        Cmd::Doctor { peer } => return doctor(&paths, &peer).await,
        Cmd::KeepAwake { state } => {
            let enabled = state == "on";
            if enabled {
                presence_hint();
            }
            control(&paths)
                .await?
                .set_keep_awake(l::SetKeepAwakeRequest { enabled })
                .await
                .map_err(status_err)?;
            println!(
                "{}",
                if enabled {
                    "This computer now stays awake while tasks from other devices run (closing a laptop's lid still sleeps it)."
                } else {
                    "This computer may now sleep while tasks from other devices run; they stall until it wakes."
                }
            );
        }
        Cmd::ShareLoad { state } => {
            let enabled = state == "on";
            if enabled {
                presence_hint();
            }
            control(&paths)
                .await?
                .set_share_load(l::SetShareLoadRequest { enabled })
                .await
                .map_err(status_err)?;
            println!(
                "{}",
                if enabled {
                    "Devices holding a grant from this computer can now see how busy it is (CPU, memory, GPUs, your own apps included)."
                } else {
                    "Devices you lend to no longer see how busy this computer is."
                }
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
            // Grants held, for the tools each device listed.
            let held = client(&paths)
                .await?
                .list_grants(l::ListGrantsRequest {
                    include_inactive: false,
                })
                .await
                .map_err(status_err)?
                .into_inner()
                .grants;
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
                if let Some(t) = held_tools(&held, &p.fingerprint) {
                    println!("{:<28} tools there: {}", "", tools_text(&t));
                }
                if let Some(b) = bench::last(&paths, &p.fingerprint) {
                    println!("{:<28} {}", "", b.summary());
                }
                match (p.wake_allowed, p.can_wake) {
                    (true, true) => println!(
                        "{:<28} may wake this computer, and can be woken from here",
                        ""
                    ),
                    (true, false) => println!("{:<28} may wake this computer", ""),
                    (false, true) => println!("{:<28} can be woken from here (`gmc wake`)", ""),
                    (false, false) => {}
                }
                if !p.software_version.is_empty() {
                    println!(
                        "{:<28} runs GimmeCores {}{}",
                        "",
                        p.software_version,
                        p.version_seen.map_or(String::new(), |t| {
                            format!(
                                " (as of {} UTC)",
                                stamp(u64::try_from(t.seconds).unwrap_or(0))
                            )
                        })
                    );
                }
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
        Cmd::Standing { action: None } => {
            let peers = client(&paths)
                .await?
                .list_peers(l::ListPeersRequest {
                    include_discovered: false,
                })
                .await
                .map_err(status_err)?
                .into_inner()
                .peers;
            let mut any = false;
            for p in peers {
                if let Some(r) = p.standing {
                    any = true;
                    println!(
                        "{:<28} {}; until {}",
                        p.device_name,
                        standing_text(&r),
                        r.until.map_or_else(String::new, |t| when(t.seconds))
                    );
                }
            }
            if !any {
                println!(
                    "No standing grants. Create one with `gmc standing set <device>`, or tick \
                     \"Always accept requests like this\" when you accept one in the app."
                );
            }
        }
        Cmd::Standing {
            action:
                Some(StandingCmd::Set {
                    peer,
                    runtime,
                    cpus,
                    memory,
                    disk,
                    hours,
                    speed,
                    images,
                }),
        } => {
            let modes = match runtime.as_str() {
                "container" => vec![pb::ExecutionMode::Container as i32],
                "sandbox" => vec![pb::ExecutionMode::Sandbox as i32],
                _ => vec![
                    pb::ExecutionMode::Container as i32,
                    pb::ExecutionMode::Sandbox as i32,
                ],
            };
            let rule = l::StandingRule {
                limits: Some(pb::Limits {
                    cpu_millis: cpus * 1000,
                    memory_bytes: parse_size(&memory)?,
                    disk_bytes: parse_size(&disk)?,
                    ..Default::default()
                }),
                modes,
                speed: gimmecores_node::grants_flow::speed_to(
                    speed.as_deref().and_then(gimmecores_core::Speed::from_name),
                ) as i32,
                images_bytes: if images == "0" {
                    0
                } else {
                    parse_size(&images)?
                },
                max_hours: hours,
                ..Default::default()
            };
            presence_hint();
            let p = control(&paths)
                .await?
                .set_standing_rule(l::SetStandingRuleRequest {
                    peer_fingerprint: peer,
                    rule: Some(rule),
                })
                .await
                .map_err(status_err)?
                .into_inner();
            if let Some(r) = p.standing {
                println!(
                    "Requests from {:?} are now accepted without asking you: {}. Until {}; \
                     you are told each time (audit log, app). End it with `gmc standing off \
                     {:?}`.",
                    p.device_name,
                    standing_text(&r),
                    r.until.map_or_else(String::new, |t| when(t.seconds)),
                    p.device_name
                );
            }
        }
        Cmd::Standing {
            action: Some(StandingCmd::Off { peer }),
        } => {
            let p = control(&paths)
                .await?
                .set_standing_rule(l::SetStandingRuleRequest {
                    peer_fingerprint: peer,
                    rule: None,
                })
                .await
                .map_err(status_err)?
                .into_inner();
            println!(
                "Requests from {:?} ask you again; the grants its standing grant accepted are \
                 revoked.",
                p.device_name
            );
        }
        Cmd::AllowWake { peer, state } => {
            let allowed = state == "on";
            if allowed {
                presence_hint();
            }
            let p = control(&paths)
                .await?
                .set_wake_allowed(l::SetWakeAllowedRequest {
                    peer_fingerprint: peer,
                    allowed,
                })
                .await
                .map_err(status_err)?
                .into_inner();
            if allowed {
                let how = if cfg!(target_os = "macos") {
                    "System Settings > Energy, \"Wake for network access\""
                } else if cfg!(windows) {
                    "Device Manager > the network adapter > Power Management, \"Allow this \
                     device to wake the computer\""
                } else {
                    "`ethtool -s <card> wol g`, and Wake-on-LAN on in the firmware"
                };
                println!(
                    "{:?} may now wake this computer: it receives this computer's network card \
                     addresses. Waking works only where this computer supports it ({how}; \
                     often wired Ethernet only).",
                    p.device_name
                );
            } else {
                println!(
                    "{:?} may no longer wake this computer; it is told to forget its addresses.",
                    p.device_name
                );
            }
        }
        Cmd::Wake { peer } => {
            let r = client(&paths)
                .await?
                .wake_peer(l::WakePeerRequest {
                    peer_fingerprint: peer.clone(),
                })
                .await
                .map_err(status_err)?
                .into_inner();
            println!(
                "Sent {peer:?} a wake-up ({} packets). A sleeping computer takes a few seconds to \
                 answer.",
                r.packets_sent
            );
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
                let images = match g.grant.as_ref().map_or(0, |x| x.images_bytes) {
                    0 => String::new(),
                    b => format!(", images up to {}", gib(b)),
                };
                // Held grants: how fast your tasks run there.
                let speed = match g.grant.as_ref() {
                    Some(x) if !g.as_lender => format!(", speed {}", grant_speed(x)),
                    _ => String::new(),
                };
                // A request a device keeps for its owner: waiting, not a grant yet.
                if !g.as_lender && g.state == pb::GrantState::Requested as i32 {
                    println!(
                        "{}  asked waiting   {} cores, {}  peer {}  {}",
                        hex::encode(&g.request_id),
                        f64::from(limits.cpu_millis) / 1000.0,
                        gib(limits.memory_bytes),
                        g.peer_fingerprint,
                        g.state_reason
                    );
                    continue;
                }
                println!(
                    "{}  {:<5} {:<9} {} cores, {}{images}{speed}  peer {}{}{}  {}",
                    hex::encode(&g.grant_id),
                    if g.as_lender { "lent" } else { "held" },
                    state,
                    f64::from(limits.cpu_millis) / 1000.0,
                    gib(limits.memory_bytes),
                    g.peer_fingerprint,
                    if trusted { "  TRUSTED" } else { "" },
                    if g.grant.as_ref().is_some_and(|x| x.by_standing_rule) {
                        "  (standing)"
                    } else {
                        ""
                    },
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
                    speed,
                    images,
                    no_wait,
                }),
            ..
        } => {
            let mem = parse_size(&memory)?;
            let images_bytes = if images == "0" {
                0
            } else {
                parse_size(&images)?
            };
            println!(
                "Asking {peer:?} for {cpus} cores and {} for {hours} h.{}",
                gib(mem),
                if no_wait {
                    ""
                } else {
                    " Waiting for its owner to decide..."
                }
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
                speed: gimmecores_node::grants_flow::speed_to(
                    speed.as_deref().and_then(gimmecores_core::Speed::from_name),
                ) as i32,
                images_bytes,
                renews: Vec::new(),
                queue: false,
            };
            let g = client(&paths)
                .await?
                .request_grant(l::RequestGrantRequest {
                    peer_fingerprint: peer.clone(),
                    request: Some(req),
                    no_wait,
                })
                .await
                .map_err(status_err)?
                .into_inner();
            if g.state == pb::GrantState::Requested as i32 {
                println!(
                    "{peer:?} keeps the request for its owner (up to 24 hours). `gmc grants` \
                     shows it until it is answered, then the grant if it is accepted."
                );
            } else if g.state == pb::GrantState::Active as i32 {
                let modes = g
                    .grant
                    .as_ref()
                    .map(|x| x.modes.clone())
                    .unwrap_or_default();
                if g.grant.as_ref().is_some_and(|x| x.by_standing_rule) {
                    println!(
                        "Accepted without asking: {peer:?} has a standing grant for this device."
                    );
                }
                println!(
                    "Granted ({}), runs in: {}, speed: {}. Run work with `gmc run -- <command>`.",
                    hex::encode(&g.grant_id),
                    mode_names(&modes),
                    g.grant.as_ref().map_or_else(String::new, grant_speed)
                );
                let fixed = g
                    .grant
                    .as_ref()
                    .and_then(|x| gimmecores_node::grants_flow::speed_from(x.speed));
                if fixed != Some(gimmecores_core::Speed::Full) {
                    println!("{FULL_SPEED_TIP}");
                }
                let images = g.grant.as_ref().map_or(0, |x| x.images_bytes);
                if images_bytes > 0 && images == 0 {
                    println!(
                        "Note: the lender did not let you send images (its GimmeCores may be older \
                         than that); `gmc run --image` can only use images it already has."
                    );
                } else if images > 0 {
                    println!(
                        "You may send your own container images, up to {}: `gmc run --image <yours>`.",
                        gib(images)
                    );
                }
            } else if g.state == pb::GrantState::Expired as i32
                // A daemon older than the "no answer" outcome reports it as this decline.
                || g.state_reason == "no answer from the lender"
            {
                println!(
                    "{peer:?} didn't answer within {} minutes, so nothing was granted. Ask again \
                     when its owner is there.",
                    gimmecores_node::grants_flow::DECISION_TIMEOUT.as_secs() / 60
                );
                return Ok(ExitCode::from(EXIT_NO_ANSWER));
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
            // The owner's speed setting, to say whether a request asks for more.
            let setting = client(&paths)
                .await?
                .get_status(l::GetStatusRequest {})
                .await
                .ok()
                .and_then(|s| gimmecores_node::grants_flow::speed_from(s.into_inner().task_speed))
                .unwrap_or(gimmecores_core::Speed::DEFAULT);
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
                let images = g.grant.as_ref().map_or(0, |x| x.images_bytes);
                if images > 0 {
                    println!(
                        "  Images:   may send its own container images, up to {} of your disk \
                         (run like any container here; removed when its grants end)",
                        gib(images)
                    );
                }
                let asked = g
                    .grant
                    .as_ref()
                    .and_then(|x| gimmecores_node::grants_flow::speed_from(x.speed));
                println!(
                    "  Speed:    {}",
                    match asked {
                        None => format!(
                            "your setting (`gmc speed`), now {}",
                            gimmecores_node::speed::describe(setting)
                        ),
                        Some(s) if s > setting => format!(
                            "{}: FASTER than your setting ({}), fixed for this grant",
                            gimmecores_node::speed::describe(s),
                            gimmecores_node::speed::describe(setting)
                        ),
                        Some(s) => format!(
                            "{}, fixed for this grant",
                            gimmecores_node::speed::describe(s)
                        ),
                    }
                );
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
                let trusted = g
                    .grant
                    .as_ref()
                    .is_some_and(|x| x.trust == pb::TrustLevel::Trusted as i32);
                // A standing grant from this request: Standard grants only (standing.rs).
                let always = accept
                    && !trusted
                    && confirm(
                        "Also accept requests like this from that device without asking, for 30 \
                         days (each grant at most 8 hours; `gmc standing off` ends it)?",
                    )?;
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
                    always,
                })
                .await
                .map_err(status_err)?;
                println!(
                    "{}",
                    match (accept, always) {
                        (true, true) =>
                            "Accepted, and requests like this are now accepted without asking (`gmc standing`).",
                        (true, false) => "Accepted.",
                        _ => "Declined.",
                    }
                );
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
        Cmd::Bench { peer } => bench::run(&paths, &peer).await?,
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

/// A paired device's name, or its fingerprint when it cannot be looked up.
async fn peer_label(paths: &Paths, fingerprint: &str) -> String {
    let found = async {
        let peers = client(paths)
            .await?
            .list_peers(l::ListPeersRequest {
                include_discovered: false,
            })
            .await?
            .into_inner()
            .peers;
        anyhow::Ok(
            peers
                .into_iter()
                .find(|p| p.fingerprint == fingerprint)
                .map(|p| p.device_name),
        )
    };
    found
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| fingerprint.to_string())
}

/// Fetches `--deps` here (with this computer's network) and adds them to what the task gets.
async fn prepare_deps(args: &mut RunArgs, project: &Path) -> Result<()> {
    use gimmecores_node::deps::{self, Kind};
    let mut kinds: Vec<Kind> = Vec::new();
    for d in &args.deps {
        let found = if d == "auto" {
            Kind::detect(project)
        } else {
            Kind::parse(d)?
        };
        for k in found {
            if !kinds.contains(&k) {
                kinds.push(k);
            }
        }
    }
    if kinds.is_empty() {
        if !args.deps.is_empty() {
            eprintln!("gmc: --deps auto: no Cargo.lock, package-lock.json or go.mod here");
        }
        return Ok(());
    }
    let tty = std::io::stderr().is_terminal();
    for k in kinds {
        if tty {
            eprintln!("gmc: getting {k:?} dependencies here (once per lockfile)...");
        }
        let (dir, cache) = (project.to_path_buf(), deps::cache_root());
        let p =
            tokio::task::spawn_blocking(move || deps::prepare(k, &dir, &cache, false)).await??;
        args.deps_env.extend(p.env);
        args.deps_files
            .extend(p.attachments.into_iter().map(|a| l::Attachment {
                local_path: a.local.display().to_string(),
                path: a.path,
                packages: a.packages,
                published: match a.published {
                    gimmecores_node::tree::Published::Cargo => l::attachment::Published::Cargo,
                    gimmecores_node::tree::Published::Npm => l::attachment::Published::Npm,
                    gimmecores_node::tree::Published::None => l::attachment::Published::None,
                } as i32,
                at_project_path: a.at_project_path,
            }));
    }
    Ok(())
}

/// `gmc run`: here, on another device, or split into shards over several (placement.rs).
async fn run_task(paths: &Paths, mut args: RunArgs) -> Result<ExitCode> {
    use placement::{Shard, Slot, Where};
    let project: PathBuf = std::env::current_dir()?;
    let wh = Where::parse(&args.place)?;
    // A run here has its own network and tools: dependencies are only fetched for devices.
    if wh != Where::Local {
        prepare_deps(&mut args, &project).await?;
    }
    let n = args.shards.max(1);
    let out = std::sync::Arc::new(placement::Out::new());
    let tty = std::io::stderr().is_terminal();
    // One task, remote: as before, any device that granted resources (or `--peer`).
    if n == 1 && wh == Where::Remote {
        let code = run_there(
            paths,
            &args,
            &project,
            Shard { k: 1, n: 1 },
            args.peer.clone(),
            &out,
        )
        .await;
        return Ok(ExitCode::from(code));
    }
    let mode = match args.runtime.as_deref() {
        Some("container") => pb::ExecutionMode::Container,
        Some("sandbox") => pb::ExecutionMode::Sandbox,
        _ => pb::ExecutionMode::Unspecified,
    };
    let rooms = if wh == Where::Local {
        Vec::new()
    } else {
        let mut c = client(paths).await?;
        let grants = c
            .list_grants(l::ListGrantsRequest {
                include_inactive: false,
            })
            .await
            .map_err(status_err)?
            .into_inner()
            .grants;
        let names: Vec<(String, String)> = c
            .list_peers(l::ListPeersRequest {
                include_discovered: false,
            })
            .await
            .map_err(status_err)?
            .into_inner()
            .peers
            .into_iter()
            .map(|p| (p.fingerprint, p.device_name))
            .collect();
        placement::rooms(
            &grants,
            &names,
            args.cpus * 1000,
            mode,
            args.peer.as_deref(),
        )
    };
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let idle = if wh == Where::Auto {
        tokio::task::spawn_blocking(placement::idle_cores).await?
    } else {
        0.0
    };
    // A container needs a device: running here would use this computer's own tools instead.
    let container = args.image.is_some() || args.runtime.as_deref() == Some("container");
    let wh = match wh {
        Where::Local if container => anyhow::bail!(
            "--where local runs the command here without a container: drop --image and \
             --runtime container, or run it on a device"
        ),
        Where::Auto if container => Where::Remote,
        other => other,
    };
    let (slots, why) = placement::plan(wh, &rooms, n, args.cpus, idle, cores)?;
    if tty {
        if n == 1 {
            eprintln!("gmc: running {why}");
        } else {
            let mut places: Vec<(String, usize)> = Vec::new();
            for s in &slots {
                match places.iter_mut().find(|(p, _)| p == s.label()) {
                    Some((_, c)) => *c += 1,
                    None => places.push((s.label().to_string(), 1)),
                }
            }
            let list: Vec<String> = places
                .iter()
                .map(|(p, c)| format!("{p} ({c} at once)"))
                .collect();
            eprintln!("gmc: {n} shards over {}", list.join(", "));
        }
    }
    let queue = std::sync::Arc::new(std::sync::Mutex::new(
        (1..=n)
            .map(|k| Shard { k, n })
            .collect::<std::collections::VecDeque<_>>(),
    ));
    let args = std::sync::Arc::new(args);
    let mut workers = tokio::task::JoinSet::new();
    for slot in slots {
        let (queue, args, out, paths, project) = (
            queue.clone(),
            args.clone(),
            out.clone(),
            paths.clone(),
            project.clone(),
        );
        workers.spawn(async move {
            let mut done = Vec::new();
            let mut retries = std::collections::BTreeMap::new();
            loop {
                let Some(shard) = queue.lock().unwrap_or_else(|e| e.into_inner()).pop_front()
                else {
                    break;
                };
                let code = match &slot {
                    Slot::Here => run_here(&args, &project, shard, &out).await,
                    Slot::There { fingerprint, .. } => {
                        run_there(
                            &paths,
                            &args,
                            &project,
                            shard,
                            Some(fingerprint.clone()),
                            &out,
                        )
                        .await
                    }
                };
                // That device's grant was full: the shard waits for room (a few tries).
                if code == placement::EXIT_BUSY {
                    let tries = retries.entry(shard.k).or_insert(0u32);
                    *tries += 1;
                    if *tries <= 30 {
                        queue
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push_back(shard);
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    }
                    eprintln!("{}gmc: that device's grant stayed full", shard.prefix());
                }
                let code = if code == placement::EXIT_BUSY {
                    placement::EXIT_GMC
                } else {
                    code
                };
                done.push((shard.k, slot.label().to_string(), code));
            }
            done
        });
    }
    let mut results = Vec::new();
    while let Some(r) = workers.join_next().await {
        results.extend(r?);
    }
    results.sort();
    if tty && n > 1 {
        for (k, place, code) in &results {
            eprintln!(
                "gmc: shard {k}/{n} on {place}: {}",
                if *code == 0 {
                    "ok".to_string()
                } else {
                    format!("exit {code}")
                }
            );
        }
    }
    let codes: Vec<u8> = results.iter().map(|r| r.2).collect();
    Ok(ExitCode::from(placement::worst(&codes)))
}

/// One task built from `gmc run`'s arguments: `argv` and `env` for its shard, outputs into
/// `output_dir` (default: this folder), on `peer` (default: any device that granted you
/// resources).
fn inline_task(
    args: &RunArgs,
    argv: Vec<String>,
    env: Vec<(String, String)>,
    output_dir: Option<&Path>,
    peer: Option<String>,
) -> Result<l::InlineTask> {
    let mode = match args.runtime.as_deref() {
        Some("container") => pb::ExecutionMode::Container as i32,
        Some("sandbox") => pb::ExecutionMode::Sandbox as i32,
        _ => pb::ExecutionMode::Unspecified as i32,
    };
    Ok(l::InlineTask {
        name: "run".into(),
        mode,
        speed: gimmecores_node::grants_flow::speed_to(
            args.speed
                .as_deref()
                .and_then(gimmecores_core::Speed::from_name),
        ) as i32,
        env: args.image.clone().map(|r| pb::Environment {
            kind: Some(pb::environment::Kind::Image(pb::ImageEnv {
                reference: r,
                ..Default::default()
            })),
        }),
        work: Some(l::inline_task::Work::Command(pb::Command {
            argv,
            working_directory: String::new(),
            environment: env
                .into_iter()
                .chain(args.deps_env.iter().cloned())
                .collect(),
        })),
        attachments: args.deps_files.clone(),
        outputs: args.outputs.clone(),
        excludes: args.excludes.clone(),
        caches: args.caches.clone(),
        output_dir: output_dir.map_or_else(String::new, |d| d.display().to_string()),
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
        peers: peer.into_iter().collect(),
        shards: 1,
        ..Default::default()
    })
}

/// Runs one task on another device; its output goes to `out` for `shard`. Returns its exit
/// code (125: it could not run).
async fn run_there(
    paths: &Paths,
    args: &RunArgs,
    project: &Path,
    shard: placement::Shard,
    peer: Option<String>,
    out: &placement::Out,
) -> u8 {
    let output_dir = (shard.n > 1).then(|| project.join("out").join(format!("shard-{}", shard.k)));
    // A shard refused only because the device's grant is full goes back in the queue.
    let busy = |why: &str| shard.n > 1 && why.contains("too many tasks at once");
    let attempt = async {
        let task = inline_task(
            args,
            shard.argv(&args.command),
            shard.env(),
            output_dir.as_deref(),
            peer,
        )?;
        let job = l::JobSpec {
            project_root: project.display().to_string(),
            inline_tasks: vec![task],
            confirmed_sensitive_paths: args.allow_secrets.clone(),
            ..Default::default()
        };
        let mut stream = client(paths)
            .await?
            .submit_job(job)
            .await
            .map_err(status_err)?
            .into_inner();
        let mut code = placement::EXIT_GMC;
        while let Some(ev) = stream.message().await.map_err(status_err)? {
            match ev.event {
                Some(l::job_event::Event::Task(t)) => match t.event {
                    // Where and how fast it runs, for a person watching (never into the output).
                    Some(pb::task_event::Event::Started(s))
                        if shard.n == 1 && std::io::stderr().is_terminal() =>
                    {
                        if let Some(level) = gimmecores_node::grants_flow::speed_from(s.speed) {
                            eprintln!(
                                "gmc: started on {}, speed: {}{}",
                                peer_label(paths, &ev.peer_fingerprint).await,
                                level.name(),
                                if s.speed_applied {
                                    ""
                                } else {
                                    " (not applied to containers yet)"
                                }
                            );
                        }
                    }
                    Some(pb::task_event::Event::Log(log)) => {
                        out.write(
                            shard,
                            log.stream == pb::log_chunk::Stream::Stderr as i32,
                            &log.data,
                        );
                    }
                    Some(pb::task_event::Event::Finished(r)) => {
                        let status = pb::task_result::Status::try_from(r.status)
                            .unwrap_or(pb::task_result::Status::Failed);
                        code = match status {
                            pb::task_result::Status::Succeeded => 0,
                            pb::task_result::Status::Failed => {
                                u8::try_from(r.exit_code.clamp(1, 255)).unwrap_or(1)
                            }
                            other => {
                                let why = r.error.map(|e| e.message).unwrap_or_default();
                                out.flush(shard);
                                if busy(&why) {
                                    return Ok(placement::EXIT_BUSY);
                                }
                                eprintln!(
                                    "{}gmc: task {}: {why}",
                                    shard.prefix(),
                                    other
                                        .as_str_name()
                                        .trim_start_matches("STATUS_")
                                        .to_lowercase()
                                );
                                placement::EXIT_GMC
                            }
                        };
                    }
                    _ => {}
                },
                Some(l::job_event::Event::Done(_)) => break,
                _ => {}
            }
        }
        anyhow::Ok(code)
    };
    let code = match attempt.await {
        Ok(c) => c,
        Err(e) if busy(&format!("{e:#}")) => placement::EXIT_BUSY,
        Err(e) => {
            out.flush(shard);
            eprintln!("{}gmc: {e:#}", shard.prefix());
            placement::EXIT_GMC
        }
    };
    out.flush(shard);
    code
}

/// Runs one task here, as a normal program in this folder. Returns its exit code.
async fn run_here(
    args: &RunArgs,
    project: &Path,
    shard: placement::Shard,
    out: &placement::Out,
) -> u8 {
    use tokio::io::AsyncReadExt;
    let argv = shard.argv(&args.command);
    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .current_dir(project)
        .envs(shard.env())
        .kill_on_drop(true);
    let piped = shard.n > 1;
    if piped {
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{}gmc: cannot start {:?} here: {e}",
                shard.prefix(),
                argv[0]
            );
            return placement::EXIT_GMC;
        }
    };
    let pump = |r: Option<Box<dyn tokio::io::AsyncRead + Unpin + Send>>, stderr: bool| async move {
        let Some(mut r) = r else { return };
        let mut buf = vec![0u8; 16 << 10];
        while let Ok(n) = r.read(&mut buf).await {
            if n == 0 {
                break;
            }
            out.write(shard, stderr, &buf[..n]);
        }
    };
    let so = child
        .stdout
        .take()
        .map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>);
    let se = child
        .stderr
        .take()
        .map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>);
    let run = async {
        let (_, _, st) = tokio::join!(pump(so, false), pump(se, true), child.wait());
        st
    };
    let code = match tokio::time::timeout(std::time::Duration::from_secs(args.timeout), run).await {
        Ok(Ok(st)) => st.code().map_or(placement::EXIT_GMC, |c| {
            u8::try_from(c.clamp(0, 255)).unwrap_or(1)
        }),
        Ok(Err(e)) => {
            eprintln!("{}gmc: {e}", shard.prefix());
            placement::EXIT_GMC
        }
        Err(_) => {
            eprintln!("{}gmc: timed out after {} s", shard.prefix(), args.timeout);
            placement::EXIT_GMC
        }
    };
    out.flush(shard);
    code
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
