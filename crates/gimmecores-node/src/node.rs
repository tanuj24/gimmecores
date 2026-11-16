//! The running node: one iroh endpoint, an accept loop that admits every message before acting
//! on it, and the shared state used by the local API.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use gimmecores_core::pairing::{Confirmation, Initiator, PairingWindow, Responder, ShortCode};
use gimmecores_core::{ExecutionMode, GrantBook, PeerKey, PeerStatus, admit, pairing};
use gimmecores_net::{PEER_ALPN, lan_only_endpoint};
use gimmecores_proto::peer::v1::{
    Hello, PairChallenge, PairConfirm, PairRequest, PairReveal, error::Code, peer_message::Body,
};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr};
use tokio::sync::oneshot;

use crate::identity::peer_key;
use crate::paths::Paths;
use crate::trust::TrustList;
use crate::{now, wire};

pub const PROTOCOL_VERSION: u32 = 1;

/// Why this build cannot lend, if it cannot. Windows lends only through containers, and that
/// has not been tested on a real Windows PC yet (docs/design/windows.md): until it has, Windows
/// borrows but does not lend, refused here rather than only hidden in the app.
pub const LENDING_UNAVAILABLE: Option<&str> = if cfg!(windows) {
    Some(
        "lending from Windows is not available yet: this version of GimmeCores borrows from \
         other computers but does not lend this one",
    )
} else {
    None
};

pub struct NodeConfig {
    pub paths: Paths,
    pub device_name: String,
    pub bind: SocketAddr,
    /// The runners for each execution mode (container: Docker; sandbox: the OS sandbox).
    pub executors: crate::exec::Executors,
    /// How consent actions verify that the owner is present (the OS in production, I13).
    pub presence: Arc<dyn crate::presence::Presence>,
}

/// Why a consent action was not performed (I13).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PresenceRefused {
    #[error("not approved on this device: {0}")]
    Denied(String),
    #[error(
        "this device cannot confirm you are present ({0}). On a machine with no screen, start the daemon with `gmcd --no-presence`"
    )]
    Unavailable(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairStatus {
    Waiting,
    CompareCode,
    Paired,
    Failed(String),
}

/// What the UI shows for a pairing in progress.
#[derive(Clone, Debug)]
pub struct PairingView {
    pub id: u64,
    pub peer: PeerKey,
    pub peer_name: String,
    pub code: Option<ShortCode>,
    pub status: PairStatus,
    pub name_previously_seen_with_other_key: bool,
}

struct Session {
    view: PairingView,
    decide: Option<oneshot::Sender<bool>>,
}

pub(crate) struct State {
    pub trust: TrustList,
    pub window: PairingWindow,
    pub grants: GrantBook,
    sessions: BTreeMap<u64, Session>,
    next_session: u64,
    pub(crate) incoming: BTreeMap<gimmecores_core::GrantId, crate::grants_flow::Pending>,
    pub(crate) borrowed: BTreeMap<gimmecores_core::GrantId, crate::grants_flow::Borrowed>,
    /// The signed form of every grant this device gave (saved so grants survive a restart).
    pub(crate) issued: BTreeMap<gimmecores_core::GrantId, gimmecores_proto::peer::v1::SignedGrant>,
    /// Tasks running here for other devices: what they asked for, where they stand, what
    /// they use, and how to stop them (one record per task: listed means registered).
    pub(crate) running: BTreeMap<gimmecores_core::TaskId, crate::activity::Hosted>,
    /// This device's own tasks running on other devices (the borrower's side of activity).
    pub(crate) remote: BTreeMap<gimmecores_core::TaskId, crate::remote::Remote>,
    /// Devices holding a live grant may see how busy this whole computer is (saved).
    pub(crate) share_load: bool,
    /// How tasks from other devices run here, for grants that name no speed (saved).
    pub(crate) task_speed: gimmecores_core::Speed,
    /// Hold off idle sleep while tasks from other devices run (saved).
    pub(crate) keep_awake: bool,
    /// Grants covering the sandbox list this computer's tools (saved), and the last probe.
    pub(crate) share_tools: bool,
    pub(crate) tools: Vec<(String, String)>,
    /// Set by tests only: the probe leaves `tools` as they are.
    pub(crate) tools_fixed: bool,
    /// As a borrower: each lender's last answer about its whole computer, per grant held.
    pub(crate) lender_loads: BTreeMap<
        gimmecores_core::GrantId,
        (std::time::Instant, gimmecores_proto::local::v1::LenderLoad),
    >,
    /// Grants whose lender is being asked now (one question at a time).
    pub(crate) load_asking: std::collections::BTreeSet<gimmecores_core::GrantId>,
    /// When each lender's last question ended, and whether it was answered.
    pub(crate) load_asked: BTreeMap<gimmecores_core::GrantId, (std::time::Instant, bool)>,
    /// The version each paired device last said it runs, and when (in memory only).
    pub(crate) peer_versions: BTreeMap<PeerKey, (String, u64)>,
    /// As a lender: answers to queued requests, by request id, kept a day for the borrower.
    pub(crate) answered:
        BTreeMap<Vec<u8>, (PeerKey, gimmecores_proto::peer::v1::peer_message::Body, u64)>,
    /// As a borrower: requests the lender keeps for its owner (saved in requests.json).
    pub(crate) waiting: BTreeMap<Vec<u8>, crate::queued::Waiting>,
    /// As a borrower: when a task last ran under each held grant (standing.rs renews only
    /// grants in use), and the grants already renewed or tried.
    pub(crate) borrowed_used: BTreeMap<gimmecores_core::GrantId, u64>,
    pub(crate) renew_tried: std::collections::BTreeSet<gimmecores_core::GrantId>,
    /// What ran here recently (in memory only).
    pub(crate) history: crate::activity::History,
    /// Changes when a task appears, ends or changes phase; never for figures alone.
    pub(crate) activity_rev: u64,
    /// Master switch. Off after install (threat model principle 1).
    pub(crate) lending_enabled: bool,
    /// I13: consent actions need OS-verified presence (the saved preference).
    pub(crate) require_presence: bool,
    /// `gmcd --no-presence`: waived until the daemon stops. Never saved.
    pub(crate) presence_waived: bool,
    /// Ways of running tasks this user chose to lend (saved).
    pub(crate) lend_modes: gimmecores_core::Modes,
    /// Ways that work on this machine right now (probed at start and every 30 s).
    pub(crate) available_modes: gimmecores_core::Modes,
    /// Local discovery (saved).
    pub(crate) discovery_mode: crate::discovery::DiscoveryMode,
    /// Devices nearby that advertise they are ready to pair.
    pub(crate) nearby: BTreeMap<PeerKey, crate::discovery::Nearby>,
    pub(crate) protections: crate::power::Protections,
    /// Bytes in each running task's workspace (task -> grant, bytes), measured while it runs.
    /// Counted with the borrower's stored files against the grant's disk limit.
    pub(crate) workspace_bytes: BTreeMap<gimmecores_core::TaskId, (gimmecores_core::GrantId, u64)>,
    /// Kept package folders in use by running tasks (never evicted while in use).
    pub(crate) kept_in_use: BTreeMap<std::path::PathBuf, usize>,
    /// Container images loaded here for borrowers (saved in `images.json`).
    pub(crate) images: crate::images::Registry,
    /// Sent images in use by running tasks, by config digest (never removed while in use).
    pub(crate) images_in_use: BTreeMap<String, usize>,
    /// Last link test per peer (in memory).
    pub(crate) links: BTreeMap<PeerKey, crate::linktest::LinkStats>,
    /// Set while laptop protections pause lending: since when, why, which grants, and
    /// whether running tasks were already stopped for pausing too long.
    pub(crate) paused: Option<(
        std::time::Instant,
        String,
        Vec<gimmecores_core::GrantId>,
        bool,
    )>,
}

fn yes() -> bool {
    true
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Settings {
    #[serde(default)]
    lending_enabled: bool,
    #[serde(default = "yes")]
    pause_on_battery: bool,
    #[serde(default)]
    idle_only: bool,
    #[serde(default = "yes")]
    pause_when_hot: bool,
    /// I13. Turned off only explicitly, for machines that cannot show a prompt (servers, Pis).
    #[serde(default = "yes")]
    require_presence: bool,
    /// Which ways of running tasks this device lends (default: containers only).
    #[serde(default = "yes")]
    lend_container: bool,
    #[serde(default)]
    lend_sandbox: bool,
    /// Local discovery: paired devices only (rotating identifiers) by default.
    #[serde(default = "paired_only")]
    discovery: crate::discovery::DiscoveryMode,
    /// Devices holding a live grant may see how busy this whole computer is (default: no).
    #[serde(default)]
    share_load: bool,
    /// How tasks from other devices are scheduled here (default: the owner's apps first).
    #[serde(default = "default_speed")]
    task_speed: String,
    /// Hold off idle sleep while tasks from other devices run (default: yes).
    #[serde(default = "yes")]
    keep_awake: bool,
    /// Grants covering the sandbox list this computer's tools (default: yes; tools.rs).
    #[serde(default = "yes")]
    share_tools: bool,
}

fn default_speed() -> String {
    gimmecores_core::Speed::DEFAULT.name().to_string()
}

fn paired_only() -> crate::discovery::DiscoveryMode {
    crate::discovery::DiscoveryMode::PairedOnly
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            lending_enabled: false,
            pause_on_battery: true,
            idle_only: false,
            pause_when_hot: true,
            require_presence: true,
            lend_container: true,
            lend_sandbox: false,
            discovery: crate::discovery::DiscoveryMode::PairedOnly,
            share_load: false,
            task_speed: default_speed(),
            keep_awake: true,
            share_tools: true,
        }
    }
}

fn load_settings(paths: &Paths) -> Result<Settings> {
    let path = paths.settings_file();
    if !path.exists() {
        return Ok(Settings::default());
    }
    crate::fsutil::check_private(&path)?;
    Ok(serde_json::from_slice(&std::fs::read(&path)?)?)
}

/// How long a stopping node waits for its running tasks to end (launchd allows a job 20
/// seconds before it kills it).
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

pub(crate) struct Inner {
    pub endpoint: Endpoint,
    pub secret: iroh::SecretKey,
    pub me: PeerKey,
    pub name: String,
    pub paths: Paths,
    pub executors: crate::exec::Executors,
    pub presence: Arc<dyn crate::presence::Presence>,
    pub bind: SocketAddr,
    /// Wakes the discovery loop (pairing mode opened, mode changed).
    pub discovery_wake: Arc<tokio::sync::Notify>,
    /// One presence prompt at a time.
    presence_lock: tokio::sync::Mutex<()>,
    /// One image load at a time (two tasks sending the same image load it once).
    pub(crate) image_lock: tokio::sync::Mutex<()>,
    /// Set while borrowers' images are being removed (one sweep at a time).
    pub(crate) images_sweeping: std::sync::atomic::AtomicBool,
    /// When Docker's own list of this lender's image tags was last checked.
    pub(crate) images_checked: Mutex<Option<std::time::Instant>>,
    /// As a borrower: one image being sent to each lender at a time.
    pub(crate) image_sends: Mutex<BTreeMap<PeerKey, Arc<tokio::sync::Mutex<()>>>>,
    pub blobs: crate::blobs::BlobStore,
    /// The program this service started from, to notice when it is removed while it runs.
    program: Option<std::path::PathBuf>,
    /// One standing-grant acceptance at a time, so their sum is checked (standing.rs).
    pub(crate) standing_lock: Mutex<()>,
    /// The system tool holding off idle sleep while lent tasks run (awake.rs).
    pub(crate) awake: Mutex<crate::awake::Holder>,
    /// How long a grant request waits for this device's owner (milliseconds; tests shorten it).
    pub(crate) decision_timeout_ms: std::sync::atomic::AtomicU64,
    /// How the system schedules this service (read once at start).
    scheduling: crate::power::Scheduling,
    /// When this node started (Unix seconds): activity history begins here.
    pub started_at: u64,
    /// This computer's CPU, memory and GPU readings, taken when a listing is read.
    pub(crate) machine: crate::machine::Machine,
    /// The single-instance lock; released on shutdown (or when the process ends).
    instance: Mutex<Option<std::fs::File>>,
    audit: Mutex<crate::audit::AuditLog>,
    state: Mutex<State>,
}

/// `Node::start` found another daemon holding this state directory.
#[derive(Debug)]
pub struct AlreadyRunning(pub std::path::PathBuf);

impl std::fmt::Display for AlreadyRunning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "another gmcd is already running for {} (stop it first, or set GMC_HOME for a separate one)",
            self.0.display()
        )
    }
}

impl std::error::Error for AlreadyRunning {}

/// Takes the state directory's exclusive lock, or explains that a daemon already runs.
pub(crate) fn acquire_instance_lock(paths: &Paths) -> Result<std::fs::File> {
    let path = paths.lock_file();
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => {
            Err(AlreadyRunning(paths.root().to_path_buf()).into())
        }
        Err(std::fs::TryLockError::Error(e)) => {
            Err(anyhow::Error::new(e).context(format!("locking {}", path.display())))
        }
    }
}

/// A handle to the running node. Cheap to clone.
#[derive(Clone)]
pub struct Node {
    pub(crate) inner: Arc<Inner>,
}

impl Node {
    pub async fn start(cfg: NodeConfig) -> Result<Self> {
        cfg.paths.ensure()?;
        // Before touching any state: two daemons on one state directory would race on its
        // files and take over each other's sockets.
        let instance = acquire_instance_lock(&cfg.paths)?;
        let secret = crate::identity::load(&cfg.paths)?;
        let me = peer_key(&secret.public());
        let trust = TrustList::load(cfg.paths.peers_file())?;
        let settings = load_settings(&cfg.paths)?;
        let audit = crate::audit::AuditLog::open(cfg.paths.audit_log())?;
        let images = crate::images::Registry::load(&cfg.paths.images_file());
        let endpoint = lan_only_endpoint(secret.clone(), cfg.bind).await?;
        let node = Node {
            inner: Arc::new(Inner {
                endpoint,
                secret,
                me,
                name: wire::clean_name(&cfg.device_name),
                blobs: crate::blobs::BlobStore::new(cfg.paths.blobs_dir()),
                program: std::env::current_exe().ok(),
                awake: Mutex::new(crate::awake::Holder::default()),
                standing_lock: Mutex::new(()),
                decision_timeout_ms: std::sync::atomic::AtomicU64::new(
                    u64::try_from(crate::grants_flow::DECISION_TIMEOUT.as_millis())
                        .unwrap_or(u64::MAX),
                ),
                scheduling: crate::power::own_scheduling(),
                started_at: now(),
                machine: crate::machine::Machine::default(),
                instance: Mutex::new(Some(instance)),
                audit: Mutex::new(audit),
                executors: cfg.executors,
                presence: cfg.presence,
                bind: cfg.bind,
                discovery_wake: Arc::new(tokio::sync::Notify::new()),
                presence_lock: tokio::sync::Mutex::new(()),
                image_lock: tokio::sync::Mutex::new(()),
                images_sweeping: std::sync::atomic::AtomicBool::new(false),
                images_checked: Mutex::new(None),
                image_sends: Mutex::new(BTreeMap::new()),
                paths: cfg.paths,
                state: Mutex::new(State {
                    trust,
                    window: PairingWindow::closed(),
                    grants: GrantBook::new(),
                    sessions: BTreeMap::new(),
                    next_session: 1,
                    incoming: BTreeMap::new(),
                    borrowed: BTreeMap::new(),
                    issued: BTreeMap::new(),
                    running: BTreeMap::new(),
                    remote: BTreeMap::new(),
                    share_load: settings.share_load,
                    keep_awake: settings.keep_awake,
                    share_tools: settings.share_tools,
                    tools: Vec::new(),
                    tools_fixed: false,
                    // An unknown name in the file (a newer version's) reads as the slowest.
                    task_speed: gimmecores_core::Speed::from_name(&settings.task_speed)
                        .unwrap_or(gimmecores_core::Speed::Background),
                    lender_loads: BTreeMap::new(),
                    load_asking: std::collections::BTreeSet::new(),
                    load_asked: BTreeMap::new(),
                    peer_versions: BTreeMap::new(),
                    answered: BTreeMap::new(),
                    waiting: BTreeMap::new(),
                    borrowed_used: BTreeMap::new(),
                    renew_tried: std::collections::BTreeSet::new(),
                    history: crate::activity::History::default(),
                    activity_rev: 1,
                    // Lending from Windows is not available yet (see LENDING_UNAVAILABLE).
                    lending_enabled: settings.lending_enabled && LENDING_UNAVAILABLE.is_none(),
                    require_presence: settings.require_presence,
                    presence_waived: false,
                    lend_modes: gimmecores_core::Modes {
                        container: settings.lend_container,
                        sandbox: settings.lend_sandbox,
                        native: false,
                    },
                    available_modes: gimmecores_core::Modes::NONE,
                    discovery_mode: settings.discovery,
                    nearby: BTreeMap::new(),
                    protections: crate::power::Protections {
                        pause_on_battery: settings.pause_on_battery,
                        idle_only: settings.idle_only,
                        pause_when_hot: settings.pause_when_hot,
                    },
                    paused: None,
                    workspace_bytes: BTreeMap::new(),
                    kept_in_use: BTreeMap::new(),
                    images,
                    images_in_use: BTreeMap::new(),
                    links: BTreeMap::new(),
                }),
            }),
        };
        if let Err(e) = node.load_grants() {
            tracing::warn!("saved grants were not restored: {e:#}");
        }
        if let Err(e) = node.load_waiting() {
            tracing::warn!("requests waiting for an answer were not restored: {e:#}");
        }
        // Restored grants must not run while laptop protections would pause them.
        if node.lending_enabled() {
            let reading = crate::power::read().await;
            let reason = crate::power::pause_reason(node.protections(), reading);
            node.apply_protection(reason).await;
        }
        tokio::spawn(crate::machine::detect());
        tokio::spawn(node.clone().accept_loop());
        tokio::spawn(node.clone().expiry_loop());
        tokio::spawn(node.clone().protection_loop());
        node.refresh_available_modes().await;
        tokio::spawn(node.clone().probe_loop());
        tokio::spawn(node.clone().discovery_loop());
        if let Some(why) = node.slow_reason() {
            tracing::warn!("tasks will run slowly here: {why}");
        }
        if !settings.require_presence {
            tracing::warn!(
                "presence checks are OFF: requests are approved without Touch ID / password"
            );
            node.audit_best_effort(
                "presence",
                None,
                "started with presence checks OFF",
                serde_json::json!({ "required": false }),
            );
        }
        Ok(node)
    }

    pub(crate) fn state(&self) -> MutexGuard<'_, State> {
        // A panic while holding the lock is a bug; keep serving with the last consistent state.
        self.inner.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn key(&self) -> PeerKey {
        self.inner.me
    }

    pub fn name(&self) -> &str {
        &self.inner.name
    }

    pub fn addr(&self) -> EndpointAddr {
        self.inner.endpoint.addr()
    }

    pub fn paths(&self) -> &Paths {
        &self.inner.paths
    }

    /// Appends to the hash-chained audit log (I11).
    pub(crate) fn audit(
        &self,
        kind: &str,
        peer: Option<&PeerKey>,
        summary: impl Into<String>,
        details: serde_json::Value,
    ) -> Result<()> {
        let mut log = self.inner.audit.lock().unwrap_or_else(|p| p.into_inner());
        log.append(now(), kind, peer, summary, details)?;
        Ok(())
    }

    /// Like [`Node::audit`] but only warns on failure (for events that already happened).
    pub(crate) fn audit_best_effort(
        &self,
        kind: &str,
        peer: Option<&PeerKey>,
        summary: impl Into<String>,
        details: serde_json::Value,
    ) {
        if let Err(e) = self.audit(kind, peer, summary, details) {
            tracing::warn!("could not write the audit log: {e:#}");
        }
    }

    /// Display name of a paired device (or its fingerprint).
    pub(crate) fn peer_name(&self, peer: &PeerKey) -> String {
        self.state()
            .trust
            .get(peer)
            .map_or_else(|| peer.fingerprint(), |p| p.name.clone())
    }

    /// A paired device by name or fingerprint.
    pub fn find_peer(&self, name_or_fingerprint: &str) -> Option<PeerKey> {
        self.state().trust.find(name_or_fingerprint)
    }

    /// The last link test result for a peer, if any.
    pub fn last_link(&self, peer: &PeerKey) -> Option<crate::linktest::LinkStats> {
        self.state().links.get(peer).cloned()
    }

    /// Paired devices with name and pairing time.
    pub fn paired_peers_detailed(&self) -> Vec<(PeerKey, String, gimmecores_core::UnixSeconds)> {
        self.state()
            .trust
            .list()
            .map(|(k, p)| (*k, p.name.clone(), p.paired_at))
            .collect()
    }

    pub fn lending_enabled(&self) -> bool {
        self.state().lending_enabled
    }

    /// Turns lending on or off (persisted). Turning it off revokes every grant and kills
    /// running tasks ("Stop all lending", I3). [I13: enabling needs user presence.]
    pub fn set_lending(&self, enabled: bool) -> Result<Vec<gimmecores_core::TaskId>> {
        if enabled && let Some(why) = LENDING_UNAVAILABLE {
            bail!("{why}");
        }
        let killed = {
            let mut s = self.state();
            s.lending_enabled = enabled;
            self.save_settings(&s)?;
            if enabled {
                Vec::new()
            } else {
                s.grants.stop_all()
            }
        };
        self.cancel_tasks(&killed, crate::activity::EndCause::LendingOff);
        self.save_grants();
        self.audit_best_effort(
            "lending",
            None,
            if enabled {
                "lending turned on".to_string()
            } else {
                format!(
                    "lending turned off; {} running task(s) stopped",
                    killed.len()
                )
            },
            serde_json::json!({ "enabled": enabled, "stopped_tasks": killed.len() }),
        );
        if !enabled {
            self.sweep_blobs();
        }
        Ok(killed)
    }

    pub fn protections(&self) -> crate::power::Protections {
        self.state().protections
    }

    /// Changes laptop protections (persisted).
    pub(crate) fn save_settings(&self, s: &State) -> Result<()> {
        let data = serde_json::to_vec_pretty(&Settings {
            lending_enabled: s.lending_enabled,
            pause_on_battery: s.protections.pause_on_battery,
            idle_only: s.protections.idle_only,
            pause_when_hot: s.protections.pause_when_hot,
            require_presence: s.require_presence,
            lend_container: s.lend_modes.container,
            lend_sandbox: s.lend_modes.sandbox,
            discovery: s.discovery_mode,
            share_load: s.share_load,
            task_speed: s.task_speed.name().to_string(),
            keep_awake: s.keep_awake,
            share_tools: s.share_tools,
        })?;
        crate::fsutil::write_private(&self.inner.paths.settings_file(), &data)
    }

    /// Whether consent actions need OS-verified presence (I13), and how it is checked.
    pub fn presence(&self) -> (bool, &'static str) {
        let s = self.state();
        (
            s.require_presence && !s.presence_waived,
            self.inner.presence.method(),
        )
    }

    /// I13: asks the OS to confirm that the owner is present and approves `reason` (completes
    /// "GimmeCores is trying to ..."). Every refusal is audited: a script or agent trying to
    /// approve on the owner's behalf shows up in the log.
    pub async fn require_presence(&self, reason: &str) -> Result<(), PresenceRefused> {
        use crate::presence::Outcome;
        if !self.presence().0 {
            return Ok(());
        }
        let _one_at_a_time = self.inner.presence_lock.lock().await;
        let refused = match self.inner.presence.verify(reason).await {
            Outcome::Verified => return Ok(()),
            Outcome::Denied(why) => PresenceRefused::Denied(why),
            Outcome::Unavailable(why) => PresenceRefused::Unavailable(why),
        };
        self.audit_best_effort(
            "presence",
            None,
            format!("not approved: {reason} ({refused})"),
            serde_json::json!({}),
        );
        Err(refused)
    }

    /// Turns the presence requirement on or off (persisted, audited). Turning it off needs a
    /// verified presence check: if the OS cannot verify presence, nothing reaching the socket can
    /// switch the check off. Machines with no screen use [`Self::waive_presence_for_this_run`].
    pub async fn set_require_presence(&self, required: bool) -> Result<(), PresenceRefused> {
        if !required {
            self.require_presence("stop asking for confirmation before approving requests")
                .await?;
        }
        {
            let mut s = self.state();
            s.require_presence = required;
            self.save_settings(&s)
                .map_err(|e| PresenceRefused::Unavailable(format!("{e:#}")))?;
        }
        self.audit_best_effort(
            "presence",
            None,
            if required {
                "presence checks turned on".to_string()
            } else {
                "presence checks turned OFF: requests are approved without Touch ID / password"
                    .to_string()
            },
            serde_json::json!({ "required": required }),
        );
        Ok(())
    }

    pub fn discovery_mode(&self) -> crate::discovery::DiscoveryMode {
        self.state().discovery_mode
    }

    /// Off or paired devices only (saved). Pairing mode advertises this device by itself.
    pub fn set_discovery_mode(&self, mode: crate::discovery::DiscoveryMode) -> Result<()> {
        {
            let mut s = self.state();
            s.discovery_mode = mode;
            self.save_settings(&s)?;
        }
        self.inner.discovery_wake.notify_one();
        Ok(())
    }

    /// Ways of running tasks this user lends, and which of them work here now.
    pub fn lend_modes(&self) -> (gimmecores_core::Modes, gimmecores_core::Modes) {
        let s = self.state();
        (s.lend_modes, s.available_modes)
    }

    /// Changes which ways of running tasks this device lends (saved, audited). The caller (the
    /// Control API) checks presence when this adds a mode. Grants already given keep only the
    /// modes still lent: new tasks in a withdrawn mode are refused; running ones finish.
    pub fn set_lend_modes(&self, modes: gimmecores_core::Modes) -> Result<()> {
        anyhow::ensure!(
            !modes.native,
            "running as you without a sandbox is not available yet"
        );
        {
            let mut s = self.state();
            s.lend_modes = modes;
            self.save_settings(&s)?;
        }
        let names: Vec<&str> = modes.iter().map(crate::exec::mode_name).collect();
        self.audit_best_effort(
            "lending",
            None,
            format!(
                "lends tasks in: {}",
                if names.is_empty() {
                    "nothing".into()
                } else {
                    names.join(", ")
                }
            ),
            serde_json::json!({ "modes": names }),
        );
        Ok(())
    }

    pub async fn refresh_available_modes(&self) {
        let modes = self.inner.executors.probe().await;
        self.state().available_modes = modes;
    }

    /// Re-probes runners (Docker may start or stop at any time).
    async fn probe_loop(self) {
        let weak = Arc::downgrade(&self.inner);
        drop(self);
        let mut rounds: u64 = 0;
        loop {
            // This computer's tools: at start, then every 10 minutes (tools.rs).
            if rounds.is_multiple_of(20) {
                let tools = crate::tools::probe().await;
                let Some(inner) = weak.upgrade() else { return };
                let node = Node { inner };
                let mut s = node.state();
                if !s.tools_fixed {
                    s.tools = tools;
                }
            }
            rounds += 1;
            tokio::time::sleep(Duration::from_secs(30)).await;
            let Some(inner) = weak.upgrade() else { return };
            Node { inner }.refresh_available_modes().await;
        }
    }

    /// For machines that cannot show a prompt (servers, Pis): approve consent actions without a
    /// presence check until the daemon stops. Only the process that starts the daemon can do
    /// this (`gmcd --no-presence`), never a caller of the local API. Not persisted; audited.
    pub fn waive_presence_for_this_run(&self) {
        self.state().presence_waived = true;
        self.audit_best_effort(
            "presence",
            None,
            "presence checks OFF for this run (gmcd --no-presence)",
            serde_json::json!({ "required": false, "persisted": false }),
        );
    }

    pub fn set_protections(&self, p: crate::power::Protections) -> Result<()> {
        let mut s = self.state();
        s.protections = p;
        self.save_settings(&s)?;
        drop(s);
        self.audit_best_effort(
            "lending",
            None,
            format!(
                "protections: pause on battery {}, idle only {}",
                p.pause_on_battery, p.idle_only
            ) + &format!(", pause when hot {}", p.pause_when_hot),
            serde_json::json!({
                "pause_on_battery": p.pause_on_battery,
                "idle_only": p.idle_only,
                "pause_when_hot": p.pause_when_hot,
            }),
        );
        Ok(())
    }

    /// Why lending is paused right now, if it is.
    pub fn pause_reason(&self) -> Option<String> {
        self.state().paused.as_ref().map(|p| p.1.clone())
    }

    /// Every task running here: id, runner name and way of running.
    fn running_names(s: &State) -> Vec<(gimmecores_core::TaskId, String, ExecutionMode)> {
        s.running
            .iter()
            .map(|(t, h)| (*t, format!("gmc-{}", hex::encode(t.0)), h.info.mode))
            .collect()
    }

    /// Freezes or thaws each task through its own runner, and records which were frozen:
    /// a task is shown frozen only when its runner confirmed it.
    async fn freeze_tasks(
        &self,
        tasks: &[(gimmecores_core::TaskId, String, ExecutionMode)],
        freeze: bool,
    ) -> usize {
        let mut done = 0;
        for (id, name, mode) in tasks {
            let Some(exec) = self.inner.executors.get(*mode).cloned() else {
                continue;
            };
            let ok = if freeze {
                exec.freeze(name).await
            } else {
                exec.thaw(name).await
            };
            done += usize::from(ok);
            self.mark_task(*id, |h| {
                if freeze && ok {
                    h.frozen_since.get_or_insert_with(std::time::Instant::now);
                } else if !freeze {
                    h.frozen_ms = h.frozen_total_ms();
                    h.frozen_since = None;
                }
            });
        }
        done
    }

    /// Applies laptop protections: pause (freeze tasks, refuse new ones), resume, or stop tasks
    /// that stayed frozen too long. Public so tests can drive it without a real battery.
    pub async fn apply_protection(&self, reason: Option<&str>) {
        type Tasks = Vec<(gimmecores_core::TaskId, String, ExecutionMode)>;
        enum Act {
            None,
            Pause(Tasks, String),
            StopFrozen(Tasks, Vec<gimmecores_core::TaskId>),
            Resume(Tasks),
        }
        let act = {
            let mut s = self.state();
            match (reason, s.paused.take()) {
                (Some(r), None) => {
                    let ids: Vec<_> = s
                        .grants
                        .list()
                        .into_iter()
                        .filter(|g| g.2 == gimmecores_core::GrantState::Active)
                        .map(|g| g.0)
                        .collect();
                    for id in &ids {
                        let _ = s.grants.pause(*id);
                    }
                    s.paused = Some((std::time::Instant::now(), r.to_string(), ids, false));
                    Act::Pause(Self::running_names(&s), r.to_string())
                }
                (Some(_), Some((since, r, ids, stopped))) => {
                    let overdue = !stopped && since.elapsed() > crate::power::MAX_PAUSE;
                    s.paused = Some((since, r, ids, stopped || overdue));
                    if overdue {
                        Act::StopFrozen(
                            Self::running_names(&s),
                            s.running.keys().copied().collect(),
                        )
                    } else {
                        Act::None
                    }
                }
                (None, Some((_, _, ids, _))) => {
                    let t = now();
                    for id in ids {
                        let _ = s.grants.resume(id, t);
                    }
                    Act::Resume(Self::running_names(&s))
                }
                (None, None) => Act::None,
            }
        };
        match act {
            Act::None => {}
            Act::Pause(names, r) => {
                let frozen = self.freeze_tasks(&names, true).await;
                self.audit_best_effort(
                    "lending",
                    None,
                    format!("paused: {r}; {frozen} task(s) frozen"),
                    serde_json::json!({}),
                );
            }
            Act::StopFrozen(names, tasks) => {
                self.freeze_tasks(&names, false).await;
                self.cancel_tasks(&tasks, crate::activity::EndCause::PausedTooLong);
                self.audit_best_effort(
                    "lending",
                    None,
                    format!("paused too long; {} task(s) stopped", tasks.len()),
                    serde_json::json!({}),
                );
            }
            Act::Resume(names) => {
                self.freeze_tasks(&names, false).await;
                self.audit_best_effort("lending", None, "resumed", serde_json::json!({}));
            }
        }
    }

    async fn protection_loop(self) {
        let weak = Arc::downgrade(&self.inner);
        drop(self);
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let Some(inner) = weak.upgrade() else { return };
            let node = Node { inner };
            if !node.lending_enabled() {
                continue;
            }
            let reading = crate::power::read().await;
            let reason = crate::power::pause_reason(node.protections(), reading);
            node.apply_protection(reason).await;
        }
    }

    /// Pairing ticket for manual pairing: `gmc1:<key-hex>@<ip:port>[,<ip:port>…]`.
    /// Empty until the endpoint knows at least one usable address (shortly after start).
    /// IPv6 link-local addresses are left out: other machines cannot dial them reliably.
    pub fn ticket(&self) -> Option<String> {
        let addrs: Vec<String> = self
            .addr()
            .ip_addrs()
            .filter(|a| match a.ip() {
                std::net::IpAddr::V4(_) => true,
                std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) != 0xfe80,
            })
            .map(ToString::to_string)
            .collect();
        (!addrs.is_empty()).then(|| format!("gmc1:{}@{}", self.key().to_hex(), addrs.join(",")))
    }

    /// Why tasks run here slower than this computer can, if the system holds this service back.
    pub fn slow_reason(&self) -> Option<String> {
        crate::power::slow_reason(self.inner.scheduling)
    }

    /// When this node started (Unix seconds).
    pub fn inner_started_at(&self) -> u64 {
        self.inner.started_at
    }

    /// What runs here and what ran recently, as the Control socket lists it.
    pub fn activity(&self) -> gimmecores_proto::local::v1::Activity {
        crate::activity_api::listing(self)
    }

    /// [`Self::activity`], with this device's own tasks on other devices and what they use on
    /// each lender, as the lenders report.
    pub fn activity_with_there(&self) -> gimmecores_proto::local::v1::Activity {
        crate::activity_api::listing_with(self, true)
    }

    /// This computer as a whole, and what tasks from other devices use of it (Control socket).
    pub async fn machine_load(&self) -> gimmecores_proto::local::v1::MachineLoad {
        let load = self.inner.machine.sample().await;
        crate::activity_api::machine_row(self, load)
    }

    /// The speed level reported with every task's figures.
    pub fn service_speed(&self) -> gimmecores_proto::peer::v1::ServiceSpeed {
        use crate::power::Scheduling as S;
        use gimmecores_proto::peer::v1::ServiceSpeed as P;
        match self.inner.scheduling {
            S::Normal => P::Normal,
            S::BelowNormal => P::Reduced,
            S::Background => P::Background,
        }
    }

    /// Tasks currently running here for other devices.
    pub fn running_task_count(&self) -> usize {
        self.state().running.len()
    }

    pub fn is_paired(&self, peer: &PeerKey) -> bool {
        self.state().trust.is_paired(peer)
    }

    pub fn paired_peers(&self) -> Vec<(PeerKey, String)> {
        self.state()
            .trust
            .list()
            .map(|(k, p)| (*k, p.name.clone()))
            .collect()
    }

    /// Stops this node. Every task running here is stopped first: a service that is told to
    /// stop (by launchd, systemd, the app, logging out) must never leave a task running with
    /// nothing watching its limits, its time or its grant. Their borrowers are told the task
    /// was cancelled; then the network is closed.
    pub async fn shutdown(&self) {
        self.inner
            .awake
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .release();
        let deadline = tokio::time::Instant::now() + SHUTDOWN_GRACE;
        let mut stopped = 0usize;
        loop {
            // Again on every round: a task admitted a moment ago is stopped too.
            let tasks: Vec<gimmecores_core::TaskId> =
                self.state().running.keys().copied().collect();
            if tasks.is_empty() || tokio::time::Instant::now() >= deadline {
                break;
            }
            stopped = stopped.max(tasks.len());
            self.cancel_tasks(&tasks, crate::activity::EndCause::ServiceStopping);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if stopped > 0 {
            let left = self.running_task_count();
            self.audit_best_effort(
                "task",
                None,
                format!("stopping: {stopped} running task(s) stopped, {left} did not end in time"),
                serde_json::json!({ "stopped": stopped, "left": left }),
            );
        }
        self.inner.endpoint.close().await;
        self.inner
            .instance
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }

    fn peer_status(&self, peer: &PeerKey) -> PeerStatus {
        let s = self.state();
        if s.trust.is_paired(peer) {
            PeerStatus::Paired
        } else {
            PeerStatus::Unpaired {
                pairing_open: s.window.is_open(now()),
            }
        }
    }

    /// Ends expired grants and kills their tasks (I3).
    async fn expiry_loop(self) {
        let weak = Arc::downgrade(&self.inner);
        drop(self);
        let mut ticks: u64 = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let Some(inner) = weak.upgrade() else { return };
            let node = Node { inner };
            // Awake while lent tasks run (#30).
            node.keep_awake_tick();
            // Standing grants that lapsed or no longer verify (#22), and, as a borrower,
            // renewing the grants they gave this device while in use (every 30 s).
            node.standing_sweep();
            ticks += 1;
            if ticks.is_multiple_of(15) {
                let n = node.clone();
                tokio::spawn(async move {
                    n.renew_standing_grants().await;
                });
            }
            // Requests a lender keeps for this device: ask about them every minute (#23); as
            // a lender, answers kept for a day.
            if ticks.is_multiple_of(30) {
                let t = now();
                node.state()
                    .answered
                    .retain(|_, (.., at)| t.saturating_sub(*at) < 86_400);
                if !node.state().waiting.is_empty() {
                    let n = node.clone();
                    tokio::spawn(async move {
                        n.poll_waiting().await;
                    });
                }
            }
            // Trusted mode lapses after 30 days unless confirmed again.
            let lapsed: Vec<PeerKey> = {
                let (s, t) = (node.state(), now());
                s.trust
                    .list()
                    .filter(|(_, p)| p.trusted_until.is_some_and(|u| u <= t))
                    .map(|(k, _)| *k)
                    .collect()
            };
            for peer in lapsed {
                node.withdraw_trust(&peer, "lapsed after 30 days");
            }
            let before = node.state().grants.list();
            let killed = node.state().grants.expire_due(now());
            node.cancel_tasks(&killed, crate::activity::EndCause::GrantExpired);
            node.sweep_blobs();
            let expired_any = before.iter().any(|(id, ..)| {
                node.state().grants.state(*id) == Some(gimmecores_core::GrantState::Expired)
                    && !before.iter().any(|(i, _, st, ..)| {
                        i == id && *st == gimmecores_core::GrantState::Expired
                    })
            });
            let borrowed_expired = {
                let mut s = node.state();
                let n = s.borrowed.len();
                let t = now();
                s.borrowed.retain(|_, b| b.terms.not_after > t);
                s.borrowed.len() != n
            };
            if expired_any || borrowed_expired {
                node.save_grants();
            }
            for (id, borrower, state, _, _) in before {
                let was_live = matches!(
                    state,
                    gimmecores_core::GrantState::Active | gimmecores_core::GrantState::Paused
                );
                if was_live
                    && node.state().grants.state(id) == Some(gimmecores_core::GrantState::Expired)
                {
                    node.audit_best_effort(
                        "grant",
                        Some(&borrower),
                        format!("grant {} expired", hex::encode(id.0)),
                        serde_json::json!({}),
                    );
                }
            }
        }
    }

    /// Cancels running tasks (they report REVOKED/CANCELLED and are cleaned up).
    /// Stops `tasks`, recording why (the first reason recorded for a task is kept).
    pub(crate) fn cancel_tasks(
        &self,
        tasks: &[gimmecores_core::TaskId],
        cause: crate::activity::EndCause,
    ) {
        let mut s = self.state();
        let mut changed = false;
        for t in tasks {
            if let Some(h) = s.running.get_mut(t) {
                h.stop(cause);
                changed = true;
            }
        }
        if changed {
            s.activity_rev += 1;
        }
    }

    /// Changes one running task's record (and the activity revision).
    pub(crate) fn mark_task(
        &self,
        task: gimmecores_core::TaskId,
        f: impl FnOnce(&mut crate::activity::Hosted),
    ) {
        let mut s = self.state();
        if let Some(h) = s.running.get_mut(&task) {
            f(h);
            s.activity_rev += 1;
        }
    }

    /// The lender's owner stops one task running here (reduce-only: no presence). The grant
    /// and the device's other tasks are untouched.
    pub fn stop_task(&self, task: gimmecores_core::TaskId) -> Result<()> {
        let (peer, name, argv) = {
            let mut s = self.state();
            let h = s
                .running
                .get_mut(&task)
                .context("no such task is running here")?;
            h.stop(crate::activity::EndCause::OwnerStopped);
            let out = (
                h.info.peer,
                h.info.peer_name.clone(),
                h.info.command.args.join(" "),
            );
            s.activity_rev += 1;
            out
        };
        self.audit_best_effort(
            "task",
            Some(&peer),
            format!(
                "stopped by the owner: task {} for {name}",
                &hex::encode(task.0)[..8]
            ),
            serde_json::json!({ "task": hex::encode(task.0), "argv": crate::wire::clean_text(&argv, 160) }),
        );
        Ok(())
    }

    /// Deletes the stored files of every borrower that no longer holds a live grant (revoked,
    /// expired, declined, unpaired, or lending turned off). Nothing can read them any more (I14),
    /// so keeping them would only hold someone else's code on this disk.
    pub(crate) fn sweep_blobs(&self) {
        let at = now();
        for ns in self.inner.blobs.namespaces() {
            if self.state().grants.has_live_grant(ns, at) {
                continue;
            }
            let bytes = self.inner.blobs.usage(&ns);
            match self.inner.blobs.clear(&ns) {
                Ok(()) if bytes > 0 => self.audit_best_effort(
                    "storage",
                    Some(&ns),
                    format!("deleted {bytes} bytes of files from a borrower with no live grant"),
                    serde_json::json!({ "bytes": bytes }),
                ),
                Ok(()) => {}
                Err(e) => tracing::warn!("could not delete a borrower's files: {e:#}"),
            }
        }
        // Its container images too (they need Docker, so in the background).
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            let node = self.clone();
            rt.spawn(async move { node.sweep_images().await });
        }
    }

    // ------------------------------------------------------------------ accept loop

    async fn accept_loop(self) {
        while let Some(incoming) = self.inner.endpoint.accept().await {
            let node = self.clone();
            let from = match incoming.remote_addr() {
                iroh::endpoint::IncomingAddr::Ip(sa) => Some(sa),
                _ => None,
            };
            tokio::spawn(async move {
                if let Ok(conn) = incoming.await {
                    node.handle_connection(conn, from).await;
                }
            });
        }
    }

    async fn handle_connection(&self, conn: Connection, from: Option<SocketAddr>) {
        let remote = peer_key(&conn.remote_id());
        if let Some(addr) = from {
            self.remember_addr(&remote, addr);
        }
        // Unpaired devices are dropped right after the handshake unless pairing mode is open.
        if let PeerStatus::Unpaired {
            pairing_open: false,
        } = self.peer_status(&remote)
        {
            conn.close(1u32.into(), b"pairing closed");
            return;
        }
        while let Ok((send, recv)) = conn.accept_bi().await {
            let node = self.clone();
            tokio::spawn(async move {
                if let Err(e) = node.handle_stream(remote, from, send, recv).await {
                    tracing::debug!("stream from {remote:?} ended: {e:#}");
                }
            });
        }
    }

    async fn handle_stream(
        &self,
        remote: PeerKey,
        from_addr: Option<SocketAddr>,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<()> {
        let body = wire::recv(&mut recv).await?;
        // I2: decide with the *current* status for every stream, not the one at connect time.
        if let Err(denied) = admit(wire::kind(&body), self.peer_status(&remote)) {
            let code = match denied {
                gimmecores_core::Denied::PairingClosed => Code::PairingClosed,
                gimmecores_core::Denied::NotPaired => Code::NotPaired,
                _ => Code::Invalid,
            };
            return wire::send_error(&mut send, code, "not allowed").await;
        }
        match body {
            Body::Hello(h) => {
                self.note_version(&remote, &h);
                wire::send(&mut send, Body::Hello(self.hello_for(&remote))).await?;
                send.finish()?;
                Ok(())
            }
            Body::PairRequest(req) => {
                self.respond_to_pairing(remote, req, send, recv).await?;
                if let Some(addr) = from_addr {
                    self.remember_addr(&remote, addr);
                }
                Ok(())
            }
            Body::GrantRequest(req) => self.handle_grant_request(remote, req, send).await,
            Body::GrantRevoke(r) => self.handle_remote_revoke(remote, r),
            Body::GrantPoll(p) => self.handle_grant_poll(remote, p, send).await,
            // A lender's answer to a queued request of this device (#23).
            Body::GrantOffer(_) | Body::GrantDecline(_) => {
                self.handle_pushed_answer(remote, body).await;
                Ok(())
            }
            Body::FindMissing(f) => self.handle_blob_upload(remote, f, send, recv).await,
            Body::ImageQuery(q) => self.handle_image_query(remote, q, send).await,
            Body::BlobGet(g) => self.handle_blob_get(remote, g, send, recv).await,
            Body::SubmitTask(t) => self.handle_submit(remote, t, send).await,
            Body::CancelTask(c) => self.handle_cancel(remote, c),
            Body::LoadRequest(r) => self.handle_load_request(remote, r, send).await,
            Body::LinkTestRequest(r) => self.handle_link_test(r, send, recv).await,
            Body::Unpair(_) => {
                self.forget_peer(&remote)?;
                Ok(())
            }
            _ => wire::send_error(&mut send, Code::Invalid, "unsupported message").await,
        }
    }

    /// What this device says about itself to `peer`.
    fn hello_for(&self, peer: &PeerKey) -> Hello {
        Hello {
            protocol_version: PROTOCOL_VERSION,
            software_version: crate::software_version().to_string(),
            device_name: self.inner.name.clone(),
            capabilities: None,
            // Only to a device this computer's owner lets wake it (wake.rs).
            wake_macs: self.wake_macs_for(peer),
        }
    }

    /// The program this service started from, when it is no longer on disk (the app or
    /// package was removed while the service ran).
    pub fn program_removed(&self) -> Option<&std::path::Path> {
        self.inner
            .program
            .as_deref()
            .filter(|p| std::fs::metadata(p).is_err())
    }

    /// Remembers which version a paired device runs (shown in `gmc peers`).
    fn note_version(&self, peer: &PeerKey, h: &Hello) {
        let v = wire::clean_text(&h.software_version, 64);
        let mut s = self.state();
        // The addresses it lets this device wake it with; none means forget them.
        if let Err(e) = s
            .trust
            .set_wake_macs(peer, crate::wake::clean_macs(&h.wake_macs))
        {
            tracing::warn!("could not save wake addresses: {e:#}");
        }
        if !v.is_empty() && s.trust.get(peer).is_some() {
            s.peer_versions.insert(*peer, (v, now()));
        }
    }

    /// Swaps versions with a paired device on an open connection (best effort, a few seconds
    /// at most): both sides learn which version the other runs.
    pub(crate) async fn exchange_hello(&self, peer: &PeerKey, conn: &Connection) {
        let swap = async {
            let (mut send, mut recv) = conn.open_bi().await?;
            wire::send(&mut send, Body::Hello(self.hello_for(peer))).await?;
            send.finish()?;
            if let Body::Hello(h) = wire::recv(&mut recv).await? {
                self.note_version(peer, &h);
            }
            anyhow::Ok(())
        };
        if let Ok(Err(e)) = tokio::time::timeout(Duration::from_secs(3), swap).await {
            tracing::debug!("no version from {peer:?}: {e:#}");
        }
    }

    /// The version a paired device last said it runs, and when.
    pub fn peer_version(&self, peer: &PeerKey) -> Option<(String, u64)> {
        self.state().peer_versions.get(peer).cloned()
    }

    // ------------------------------------------------------------------ pairing

    /// The local user opened pairing mode (2 minutes). Returns when it closes.
    pub fn open_pairing(&self) -> u64 {
        let t = now();
        self.state().window.open(t);
        // Advertise "ready to pair" right away (while the window is open).
        self.inner.discovery_wake.notify_one();
        t + pairing::WINDOW_SECONDS
    }

    /// Starts pairing with a nearby device that advertised it is ready to pair.
    pub async fn start_pairing_nearby(&self, fingerprint: &str) -> Result<u64> {
        let n = self
            .nearby()
            .into_iter()
            .find(|n| n.key.fingerprint() == fingerprint)
            .context("that device is no longer nearby and ready to pair")?;
        let pk = iroh::PublicKey::from_bytes(&n.key.0)?;
        let addr = EndpointAddr::from_parts(pk, n.addrs.into_iter().map(iroh::TransportAddr::Ip));
        self.start_pairing(addr).await
    }

    pub fn pairing(&self, id: u64) -> Option<PairingView> {
        self.state().sessions.get(&id).map(|s| s.view.clone())
    }

    pub fn pairings(&self) -> Vec<PairingView> {
        self.state()
            .sessions
            .values()
            .map(|s| s.view.clone())
            .collect()
    }

    /// The local user compared the codes. `true` = they match.
    pub fn confirm_pairing(&self, id: u64, codes_match: bool) -> Result<()> {
        let mut s = self.state();
        let session = s.sessions.get_mut(&id).context("no such pairing")?;
        let tx = session
            .decide
            .take()
            .context("this pairing is not waiting for a decision")?;
        let _ = tx.send(codes_match);
        Ok(())
    }

    fn new_session(&self, peer: PeerKey, peer_name: String) -> (u64, oneshot::Receiver<bool>) {
        let (tx, rx) = oneshot::channel();
        let mut s = self.state();
        let id = s.next_session;
        s.next_session += 1;
        let name_reuse = s.trust.name_used_by_other_key(&peer_name, &peer);
        s.sessions.insert(
            id,
            Session {
                view: PairingView {
                    id,
                    peer,
                    peer_name,
                    code: None,
                    status: PairStatus::Waiting,
                    name_previously_seen_with_other_key: name_reuse,
                },
                decide: Some(tx),
            },
        );
        (id, rx)
    }

    fn update_session(&self, id: u64, f: impl FnOnce(&mut PairingView)) {
        if let Some(s) = self.state().sessions.get_mut(&id) {
            f(&mut s.view);
        }
    }

    /// Device A: pair with the device at `addr`. Returns the session id immediately; the code
    /// appears in [`Node::pairing`] once both nonces are exchanged.
    pub async fn start_pairing(&self, addr: EndpointAddr) -> Result<u64> {
        let peer = PeerKey(*addr.id.as_bytes());
        let dialed: Vec<SocketAddr> = addr.ip_addrs().copied().collect();
        let conn = tokio::time::timeout(
            Duration::from_secs(10),
            self.inner.endpoint.connect(addr, PEER_ALPN),
        )
        .await
        .context("connection timed out")??;
        let (mut send, mut recv) = conn.open_bi().await?;
        let (mut initiator, commitment) = Initiator::start(self.inner.me, peer, wire::random32()?);
        wire::send(
            &mut send,
            Body::PairRequest(PairRequest {
                commitment: commitment.to_vec(),
                device_name: self.inner.name.clone(),
            }),
        )
        .await?;
        let Body::PairChallenge(ch) = wire::recv(&mut recv).await? else {
            return Err(anyhow!("expected PairChallenge"));
        };
        let (id, decision) = self.new_session(peer, wire::clean_name(&ch.device_name));
        let (my_nonce, code) = initiator.on_challenge(&wire::nonce32(&ch.nonce)?)?;
        let dkey = initiator
            .discovery_key()
            .context("no discovery key after the challenge")?;
        wire::send(
            &mut send,
            Body::PairReveal(PairReveal {
                nonce: my_nonce.to_vec(),
            }),
        )
        .await?;
        let node = self.clone();
        tokio::spawn(async move {
            let result = node
                .finish_pairing(id, code, dkey, decision, dialed, send, recv)
                .await;
            if let Err(e) = result {
                node.update_session(id, |v| v.status = PairStatus::Failed(format!("{e:#}")));
            }
            drop(conn);
        });
        Ok(id)
    }

    /// Device B: answer a pairing request (the admission gate already checked pairing mode).
    async fn respond_to_pairing(
        &self,
        remote: PeerKey,
        req: PairRequest,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<()> {
        let commitment = wire::nonce32(&req.commitment)?;
        let my_nonce = wire::random32()?;
        let started = {
            let mut s = self.state();
            Responder::on_request(
                &mut s.window,
                now(),
                self.inner.me,
                remote,
                commitment,
                my_nonce,
            )
        };
        let mut responder = match started {
            Ok((r, _)) => r,
            Err(e) => return wire::send_error(&mut send, Code::RateLimited, &e.to_string()).await,
        };
        let (id, decision) = self.new_session(remote, wire::clean_name(&req.device_name));
        wire::send(
            &mut send,
            Body::PairChallenge(PairChallenge {
                nonce: my_nonce.to_vec(),
                device_name: self.inner.name.clone(),
            }),
        )
        .await?;
        let result = async {
            let Body::PairReveal(rev) = wire::recv(&mut recv).await? else {
                return Err(anyhow!("expected PairReveal"));
            };
            let code = {
                let mut s = self.state();
                responder.on_reveal(&mut s.window, &wire::nonce32(&rev.nonce)?)?
            };
            let dkey = responder
                .discovery_key()
                .context("no discovery key after the reveal")?;
            self.finish_pairing(id, code, dkey, decision, Vec::new(), send, recv)
                .await
        }
        .await;
        if let Err(e) = &result {
            self.update_session(id, |v| v.status = PairStatus::Failed(format!("{e:#}")));
        }
        result
    }

    /// Both sides: show the code, wait for the local user and the peer, then trust the peer
    /// only if both confirmed.
    #[allow(clippy::too_many_arguments)]
    async fn finish_pairing(
        &self,
        id: u64,
        code: ShortCode,
        discovery_key: [u8; 32],
        decision: oneshot::Receiver<bool>,
        dialed: Vec<SocketAddr>,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<()> {
        self.update_session(id, |v| {
            v.code = Some(code);
            v.status = PairStatus::CompareCode;
        });
        let deadline = Duration::from_secs(pairing::WINDOW_SECONDS);
        let local = async {
            let ok = decision.await.unwrap_or(false);
            wire::send(&mut send, Body::PairConfirm(PairConfirm { accepted: ok })).await?;
            send.finish()?;
            // Wait until the peer has actually read our answer. Closing earlier can drop it in
            // flight, leaving the peer without our confirmation (one-sided pairing).
            send.stopped().await?;
            anyhow::Ok(ok)
        };
        let remote = async {
            match wire::recv(&mut recv).await? {
                Body::PairConfirm(c) => anyhow::Ok(c.accepted),
                _ => Err(anyhow!("expected PairConfirm")),
            }
        };
        let (local, remote) = tokio::time::timeout(deadline, async { tokio::join!(local, remote) })
            .await
            .context("pairing timed out")?;
        let mut confirmation = Confirmation::default();
        confirmation.set_local(local?);
        confirmation.set_remote(remote?);
        match confirmation.outcome() {
            Some(Ok(())) => {
                let (peer, name) = {
                    let s = self.state();
                    let v = &s.sessions.get(&id).context("session vanished")?.view;
                    (v.peer, v.peer_name.clone())
                };
                let mut s = self.state();
                s.trust.add(peer, name, now())?;
                s.trust.set_discovery_key(&peer, &discovery_key)?;
                if !dialed.is_empty() {
                    s.trust.set_addrs(&peer, dialed)?;
                }
                s.window.close();
                drop(s);
                self.update_session(id, |v| v.status = PairStatus::Paired);
                let name = self.peer_name(&peer);
                self.audit_best_effort(
                    "pair",
                    Some(&peer),
                    format!("paired with {name}"),
                    serde_json::json!({ "code": code.to_string() }),
                );
                Ok(())
            }
            Some(Err(e)) => {
                self.state().window.close();
                let peer = self.pairing(id).map(|v| (v.peer, v.peer_name));
                if let Some((peer, name)) = peer {
                    self.audit_best_effort(
                        "pair",
                        Some(&peer),
                        format!("pairing with {name} rejected"),
                        serde_json::json!({}),
                    );
                }
                Err(e.into())
            }
            None => Err(anyhow!("pairing incomplete")),
        }
    }

    /// Remembers where a paired peer can be reached (only for already-paired peers).
    fn remember_addr(&self, peer: &PeerKey, addr: SocketAddr) {
        let mut s = self.state();
        let known = s.trust.get(peer).map(|p| p.last_addrs.contains(&addr));
        if known == Some(false) {
            let _ = s.trust.set_addrs(peer, vec![addr]);
        }
    }

    /// Opens a connection to a paired peer using its last known addresses.
    /// A raw connection to a paired peer, for tests that play a hostile peer.
    #[doc(hidden)]
    pub async fn dial_raw(&self, peer: &PeerKey) -> Result<Connection> {
        self.dial(peer).await
    }

    pub(crate) async fn dial(&self, peer: &PeerKey) -> Result<Connection> {
        let addrs = self
            .state()
            .trust
            .get(peer)
            .map(|p| p.last_addrs.clone())
            .context("not paired with that device")?;
        anyhow::ensure!(!addrs.is_empty(), "no known address for that device");
        let pk = iroh::PublicKey::from_bytes(&peer.0)?;
        let addr = EndpointAddr::from_parts(pk, addrs.into_iter().map(iroh::TransportAddr::Ip));
        let conn = tokio::time::timeout(
            Duration::from_secs(10),
            self.inner.endpoint.connect(addr, PEER_ALPN),
        )
        .await
        .context("connection timed out")??;
        Ok(conn)
    }

    /// Trusted mode is on, on this device, for this peer right now (one side of two).
    pub fn is_trusted(&self, peer: &PeerKey) -> bool {
        self.state().trust.is_trusted(peer, now())
    }

    /// When this device's Trusted mode for `peer` lapses (if it is on).
    pub fn trusted_until(&self, peer: &PeerKey) -> Option<gimmecores_core::UnixSeconds> {
        let t = now();
        self.state()
            .trust
            .get(peer)
            .and_then(|p| p.trusted_until)
            .filter(|u| t < *u)
    }

    /// Turns this device's side of Trusted mode with a paired peer on (for 30 days) or off.
    /// [I13: the Control API verifies presence, with the warning shown, before enabling.]
    /// Turning it off revokes every Trusted grant between the two devices, in both directions.
    pub fn set_trusted_mode(&self, peer: &PeerKey, enabled: bool) -> Result<()> {
        if !enabled {
            self.withdraw_trust(peer, "turned off");
            return Ok(());
        }
        anyhow::ensure!(
            self.is_paired(peer),
            "Trusted mode is only for paired devices"
        );
        let until = now() + crate::trust::TRUSTED_MODE_DAYS * 24 * 3600;
        let name = self.peer_name(peer);
        // Recorded before it takes effect (strict).
        self.audit(
            "trust",
            Some(peer),
            format!("Trusted mode turned on for {name} until {until}"),
            serde_json::json!({ "until": until }),
        )?;
        self.state().trust.set_trusted_until(peer, Some(until))
    }

    /// Ends Trusted mode with `peer` on this device: clears the setting, revokes the Trusted
    /// grants this device gave it (killing their tasks) and drops the ones it gave this device.
    pub(crate) fn withdraw_trust(&self, peer: &PeerKey, why: &str) {
        let (had, killed, dropped) = {
            let mut s = self.state();
            let had = s.trust.get(peer).is_some_and(|p| p.trusted_until.is_some());
            if had {
                let _ = s.trust.set_trusted_until(peer, None);
            }
            let lent: Vec<gimmecores_core::GrantId> = s
                .grants
                .list()
                .into_iter()
                .filter(|(_, b, st, t, _)| {
                    b == peer
                        && !st.is_terminal()
                        && t.trust == gimmecores_core::TrustLevel::Trusted
                })
                .map(|(id, ..)| id)
                .collect();
            let killed = s.grants.revoke_trusted(*peer);
            let dropped: Vec<gimmecores_core::GrantId> = s
                .borrowed
                .iter()
                .filter(|(_, b)| {
                    b.lender == *peer && b.terms.trust == gimmecores_core::TrustLevel::Trusted
                })
                .map(|(id, _)| *id)
                .collect();
            for id in &dropped {
                s.borrowed.remove(id);
            }
            (had, killed, [lent, dropped].concat())
        };
        self.cancel_tasks(&killed, crate::activity::EndCause::TrustEnded);
        if !(had || !dropped.is_empty()) {
            return;
        }
        self.save_grants();
        self.audit_best_effort(
            "trust",
            Some(peer),
            format!(
                "Trusted mode with {} {why}; {} running task(s) stopped",
                self.peer_name(peer),
                killed.len()
            ),
            serde_json::json!({ "grants_ended": dropped.len() }),
        );
        self.sweep_blobs();
        // Tell the other side (best effort): locally these grants are already gone, and this
        // device will neither run nor decode Trusted work under them either way.
        for id in dropped {
            let node = self.clone();
            let peer = *peer;
            tokio::spawn(async move {
                let _ = node.notify_revoke(&peer, id).await;
            });
        }
    }

    /// Unpair: remove the key and revoke everything it holds here (I3).
    pub fn forget_peer(&self, peer: &PeerKey) -> Result<Vec<gimmecores_core::TaskId>> {
        let name = self.peer_name(peer);
        let killed = {
            let mut s = self.state();
            s.trust.remove(peer)?;
            s.borrowed.retain(|_, b| b.lender != *peer);
            s.waiting.retain(|_, w| w.lender != *peer);
            s.answered.retain(|_, (b, ..)| b != peer);
            s.grants.revoke_peer(*peer)
        };
        self.state().history.forget(peer);
        self.cancel_tasks(&killed, crate::activity::EndCause::Unpaired);
        self.save_grants();
        self.save_waiting();
        self.audit_best_effort(
            "unpair",
            Some(peer),
            format!("unpaired {name}; {} running task(s) stopped", killed.len()),
            serde_json::json!({}),
        );
        self.sweep_blobs();
        Ok(killed)
    }
}
