//! The GimmeCores desktop app: a window for lending, requests, grants and pairing, a menu-bar
//! icon, and notifications when a device asks to use this computer.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use gimmecores_desktop::applog;
use gimmecores_desktop::daemon::{self, PairingView, Snapshot, Ticket};
use gimmecores_desktop::update::{self, UpdateStatus};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent, Wry};
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_updater::{Update, UpdaterExt};

/// The daemon's state directory (GMC_HOME or the platform default). Read-only for the app.
struct Home(PathBuf);

/// The latest snapshot (for the tray menu) and what was already announced.
#[derive(Default)]
struct Seen {
    last: Option<Snapshot>,
    notified_requests: BTreeSet<String>,
    notified_pairings: BTreeSet<String>,
}

struct Tray {
    status: MenuItem<Wry>,
    lend: MenuItem<Wry>,
}

type CmdResult<T> = Result<T, String>;

fn err(e: anyhow::Error) -> String {
    format!("{e:#}")
}

#[tauri::command]
async fn snapshot(home: State<'_, Home>) -> CmdResult<Snapshot> {
    Ok(daemon::snapshot(&home.0).await)
}

#[tauri::command]
async fn activity(home: State<'_, Home>) -> CmdResult<daemon::ActivityView> {
    daemon::activity(&home.0).await.map_err(err)
}

#[tauri::command]
async fn stop_task(home: State<'_, Home>, task: String) -> CmdResult<()> {
    daemon::stop_task(&home.0, &task).await.map_err(err)
}

#[tauri::command]
async fn set_lending(
    home: State<'_, Home>,
    enabled: bool,
    idle_only: bool,
    allow_on_battery: bool,
    allow_when_hot: bool,
) -> CmdResult<()> {
    daemon::set_lending(
        &home.0,
        enabled,
        idle_only,
        allow_on_battery,
        allow_when_hot,
    )
    .await
    .map_err(err)
}

#[tauri::command]
async fn set_lend_modes(home: State<'_, Home>, modes: Vec<String>) -> CmdResult<()> {
    daemon::set_lend_modes(&home.0, &modes).await.map_err(err)
}

#[tauri::command]
async fn service_state() -> CmdResult<gimmecores_desktop::service::ServiceState> {
    Ok(gimmecores_desktop::service::state())
}

#[tauri::command]
async fn set_start_at_login(enabled: bool) -> CmdResult<()> {
    let done = tauri::async_runtime::spawn_blocking(move || {
        if enabled {
            gimmecores_desktop::service::start_at_login()
        } else {
            gimmecores_desktop::service::stop_at_login()
        }
    })
    .await
    .map_err(|e| e.to_string())?;
    let what = if enabled { "start" } else { "stop" };
    applog::note(&match &done {
        Ok(()) => format!("service: {what} at login, done"),
        Err(e) => format!("service: {what} at login, failed: {e:#}"),
    });
    done.map_err(err)
}

#[tauri::command]
async fn install_cli() -> CmdResult<()> {
    tauri::async_runtime::spawn_blocking(gimmecores_desktop::service::install_cli)
        .await
        .map_err(|e| e.to_string())?
        .map_err(err)
}

#[tauri::command]
async fn stop_all(home: State<'_, Home>) -> CmdResult<()> {
    daemon::stop_all(&home.0).await.map_err(err)
}

#[tauri::command]
async fn respond(home: State<'_, Home>, grant_id: String, accept: bool) -> CmdResult<()> {
    daemon::respond(&home.0, &grant_id, accept)
        .await
        .map_err(err)
}

#[tauri::command]
async fn revoke(home: State<'_, Home>, grant_id: String) -> CmdResult<()> {
    daemon::revoke(&home.0, &grant_id).await.map_err(err)
}

#[tauri::command]
async fn open_pairing(home: State<'_, Home>) -> CmdResult<Ticket> {
    daemon::open_pairing(&home.0).await.map_err(err)
}

#[tauri::command]
async fn start_pairing(home: State<'_, Home>, ticket: String) -> CmdResult<PairingView> {
    daemon::start_pairing(&home.0, &ticket).await.map_err(err)
}

#[tauri::command]
async fn start_pairing_nearby(
    home: State<'_, Home>,
    fingerprint: String,
) -> CmdResult<PairingView> {
    daemon::start_pairing_nearby(&home.0, &fingerprint)
        .await
        .map_err(err)
}

#[tauri::command]
async fn set_task_speed(home: State<'_, Home>, speed: String) -> CmdResult<()> {
    daemon::set_task_speed(&home.0, &speed).await.map_err(err)
}

#[tauri::command]
async fn set_keep_awake(home: State<'_, Home>, enabled: bool) -> CmdResult<()> {
    daemon::set_keep_awake(&home.0, enabled).await.map_err(err)
}

#[tauri::command]
async fn set_share_load(home: State<'_, Home>, enabled: bool) -> CmdResult<()> {
    daemon::set_share_load(&home.0, enabled).await.map_err(err)
}

#[tauri::command]
async fn set_discovery(home: State<'_, Home>, on: bool) -> CmdResult<()> {
    daemon::set_discovery(&home.0, on).await.map_err(err)
}

#[tauri::command]
async fn confirm_pairing(
    home: State<'_, Home>,
    session: String,
    codes_match: bool,
) -> CmdResult<()> {
    daemon::confirm_pairing(&home.0, &session, codes_match)
        .await
        .map_err(err)
}

#[tauri::command]
async fn set_trusted_mode(
    home: State<'_, Home>,
    fingerprint: String,
    enabled: bool,
) -> CmdResult<()> {
    daemon::set_trusted_mode(&home.0, &fingerprint, enabled)
        .await
        .map_err(err)
}

#[tauri::command]
async fn unpair(home: State<'_, Home>, fingerprint: String) -> CmdResult<()> {
    daemon::unpair(&home.0, &fingerprint).await.map_err(err)
}

// ------------------------------------------------------------------ updates
//
// GimmeCores contacts the internet only here, and only when the user clicks: it reads the
// latest release's manifest from GitHub and, when the user agrees, downloads the update the
// manifest names. See update.rs for what is checked before the app is replaced.

/// The update the last check found, until it is installed.
#[derive(Default)]
struct Found(Mutex<Option<Update>>);

fn update_state(app: &AppHandle) -> UpdateStatus {
    let found = app.state::<Found>();
    let found = found.0.lock().unwrap_or_else(|p| p.into_inner());
    let available = found.as_ref().map(|u| update::Available {
        version: u.version.clone(),
        notes: update::clean_notes(u.body.as_deref().unwrap_or("")),
        date: u.date.map(|d| d.date().to_string()).unwrap_or_default(),
    });
    let here = update::this_app();
    UpdateStatus {
        current: app.package_info().version.to_string(),
        build: env!("GMC_VERSION_SUFFIX").to_string(),
        can_update: here.is_ok(),
        why_not: here.err().unwrap_or_default(),
        available,
    }
}

/// Reads the release manifest: a newer version signed with the update key, or nothing.
async fn find_update(app: &AppHandle) -> anyhow::Result<Option<Update>> {
    let exe = update::this_app().map_err(anyhow::Error::msg)?;
    let updater = app
        .updater_builder()
        .pubkey(update::pubkey())
        .endpoints(vec![update::endpoint().parse()?])?
        .executable_path(&exe)
        .timeout(Duration::from_secs(600))
        .build()?;
    Ok(updater.check().await?)
}

/// Downloads the update (the updater refuses one not signed with the update key, or signed
/// for another version), checks what is inside, and replaces this app with it.
async fn install(app: &AppHandle, update: Update) -> anyhow::Result<()> {
    update::check_download_url(update.download_url.as_str(), update::TEST_BUILD)?;
    let progress = app.clone();
    let mut received = 0u64;
    let mut shown: Option<Instant> = None;
    let bytes = update
        .download(
            move |chunk, total| {
                received += chunk as u64;
                if shown.is_none_or(|t| t.elapsed() >= Duration::from_millis(200)) {
                    shown = Some(Instant::now());
                    let _ = progress.emit("gmc-update-progress", (received, total));
                }
            },
            || {},
        )
        .await
        .context("the update could not be downloaded, or is not signed by GimmeCores")?;
    update::check_archive(&bytes, &update.version)?;
    tauri::async_runtime::spawn_blocking(move || update.install(bytes))
        .await
        .context("the update was interrupted")?
        .context("the update could not be installed")?;
    Ok(())
}

/// After an update: the background service runs the new version too (when it runs this
/// app's own copy), and the app opens again as the new version.
fn restart_updated(app: &AppHandle, exe: &Path) -> ! {
    if !update::TEST_BUILD {
        let launched = std::env::current_exe()
            .ok()
            .and_then(|e| update::bundle_of(&e));
        let resolved = update::bundle_of(exe);
        let bundles: Vec<&Path> = [launched.as_deref(), resolved.as_deref()]
            .into_iter()
            .flatten()
            .collect();
        if let Err(e) = gimmecores_desktop::service::restart_after_update(&bundles) {
            eprintln!("error: {e:#}");
        }
    }
    app.restart()
}

#[tauri::command]
async fn update_status(app: AppHandle) -> CmdResult<UpdateStatus> {
    Ok(update_state(&app))
}

#[tauri::command]
async fn check_update(app: AppHandle) -> CmdResult<UpdateStatus> {
    let found = find_update(&app).await.map_err(|e| {
        applog::note(&format!("update check failed: {e:#}"));
        format!("Could not check for updates: {e:#}")
    })?;
    applog::note(&match &found {
        Some(u) => format!("update check: {} offered", u.version),
        None => "update check: this is the latest version".to_string(),
    });
    *app.state::<Found>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = found;
    Ok(update_state(&app))
}

/// Installs the version the user was shown (and nothing else), then restarts.
#[tauri::command]
async fn install_update(app: AppHandle, version: String) -> CmdResult<()> {
    let exe = update::this_app()?;
    let found = app
        .state::<Found>()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let Some(update) = found.filter(|u| u.version == version) else {
        return Err("Check for updates again first.".into());
    };
    applog::note(&format!(
        "installing update {version} over {}",
        update::bundle_of(&exe)
            .unwrap_or_else(|| exe.clone())
            .display()
    ));
    install(&app, update).await.map_err(|e| {
        applog::note(&format!("update to {version} failed: {e:#}"));
        format!("Not updated: {e:#}")
    })?;
    applog::note(&format!("installed update {version}; restarting"));
    restart_updated(&app, &exe)
}

/// `update-test` builds only: with GMC_UPDATE_TEST_RUN set, checks and installs at once,
/// writes what happened to GMC_UPDATE_TEST_RESULT and quits (scripts/test-self-update.sh).
#[cfg(feature = "update-test")]
fn update_test_run(app: &AppHandle) -> bool {
    if std::env::var_os("GMC_UPDATE_TEST_RUN").is_none() {
        return false;
    }
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.hide();
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let outcome = async {
            let update = find_update(&app).await?.context("no update offered")?;
            let version = update.version.clone();
            install(&app, update).await?;
            anyhow::Ok(version)
        }
        .await;
        let text = match outcome {
            Ok(v) => format!("installed {v}\n"),
            Err(e) => format!("refused: {e:#}\n"),
        };
        if let Some(path) = std::env::var_os("GMC_UPDATE_TEST_RESULT") {
            let _ = std::fs::write(path, text);
        }
        app.exit(0);
    });
    true
}

fn show_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn notify(app: &AppHandle, title: &str, body: &str) {
    let _ = app.notification().builder().title(title).body(body).show();
}

/// Follows the daemon: keeps the tray menu and window current and announces new requests and
/// pairings as soon as the daemon reports a change (WatchEvents), checking every
/// FALLBACK_REFRESH anyway, and every 2 s while the daemon is not running.
async fn watch(app: AppHandle) {
    const FALLBACK_REFRESH: Duration = Duration::from_secs(15);
    let mut events: Option<tonic::Streaming<gimmecores_proto::local::v1::Event>> = None;
    loop {
        let home = app.state::<Home>().0.clone();
        let snap = daemon::snapshot(&home).await;
        update_tray(&app, &snap);
        let mut fresh = Vec::new();
        {
            let seen = app.state::<Mutex<Seen>>();
            let mut seen = seen.lock().unwrap_or_else(|p| p.into_inner());
            for r in &snap.requests {
                if seen.notified_requests.insert(r.id.clone()) {
                    fresh.push((
                        format!("{} wants to use this computer", r.peer_name),
                        format!(
                            "{} cores, {:.1} GiB memory. Open GimmeCores to accept or decline.",
                            r.cores, r.memory_gib
                        ),
                    ));
                }
            }
            for p in snap.pairings.iter().filter(|p| p.state == "compare") {
                if seen.notified_pairings.insert(p.session.clone()) {
                    fresh.push((
                        format!("Pairing with {}", p.peer_name),
                        format!("Check that both devices show {}.", p.code),
                    ));
                }
            }
            seen.last = Some(snap);
        }
        for (title, body) in fresh {
            notify(&app, &title, &body);
        }
        let _ = app.emit("gmc-changed", ());
        if events.is_none() {
            events = daemon::events(&home).await.ok();
        }
        match events.as_mut() {
            None => tokio::time::sleep(Duration::from_secs(2)).await,
            Some(s) => match tokio::time::timeout(FALLBACK_REFRESH, s.message()).await {
                Ok(Ok(Some(_))) => {
                    // A burst of changes (a grant and the status it changed): take them all
                    // before refreshing once.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    while let Ok(Ok(Some(_))) =
                        tokio::time::timeout(Duration::from_millis(1), s.message()).await
                    {
                    }
                }
                Ok(_) => {
                    // The daemon stopped or restarted: subscribe again on the next round.
                    events = None;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(_) => {} // quiet: refresh anyway
            },
        }
    }
}

fn update_tray(app: &AppHandle, snap: &Snapshot) {
    let tray = app.state::<Tray>();
    let (status, lend, lend_enabled) = match &snap.status {
        None => (
            "GimmeCores is not running".to_string(),
            "Turn lending on",
            false,
        ),
        Some(s) if !s.lending => ("Lending is off".to_string(), "Turn lending on", true),
        Some(s) if !s.pause_reason.is_empty() => (
            format!("Lending paused: {}", s.pause_reason),
            "Turn lending off",
            true,
        ),
        Some(s) => (
            format!("Lending on: {} task(s) running", s.running_for_others),
            "Turn lending off",
            true,
        ),
    };
    let waiting = snap.requests.len();
    let status = if waiting > 0 {
        format!("{status} · {waiting} request(s) waiting")
    } else {
        status
    };
    let _ = tray.status.set_text(status);
    let _ = tray.lend.set_text(lend);
    let _ = tray.lend.set_enabled(lend_enabled);
}

fn toggle_lending(app: &AppHandle) {
    let last = app
        .state::<Mutex<Seen>>()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .last
        .clone();
    let Some(status) = last.and_then(|s| s.status) else {
        return;
    };
    let home = app.state::<Home>().0.clone();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let r = daemon::set_lending(
            &home,
            !status.lending,
            status.idle_only,
            !status.pause_on_battery,
            !status.pause_when_hot,
        )
        .await;
        if let Err(e) = r {
            notify(&app, "Lending was not changed", &format!("{e:#}"));
        }
    });
}

fn stop_all_from_tray(app: &AppHandle) {
    let home = app.state::<Home>().0.clone();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        match daemon::stop_all(&home).await {
            Ok(()) => notify(
                &app,
                "Stopped all lending",
                "Every grant was revoked and running tasks were stopped.",
            ),
            Err(e) => notify(&app, "Could not stop lending", &format!("{e:#}")),
        }
    });
}

fn main() {
    let home = match gimmecores_client::home() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
    };
    let result = tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(Home(home))
        .manage(Mutex::new(Seen::default()))
        .manage(Found::default())
        .invoke_handler(tauri::generate_handler![
            snapshot,
            activity,
            stop_task,
            set_lending,
            set_lend_modes,
            set_share_load,
            set_keep_awake,
            set_task_speed,
            service_state,
            set_start_at_login,
            install_cli,
            stop_all,
            respond,
            revoke,
            open_pairing,
            start_pairing,
            start_pairing_nearby,
            set_discovery,
            confirm_pairing,
            unpair,
            set_trusted_mode,
            update_status,
            check_update,
            install_update
        ])
        .setup(|app| {
            #[cfg(feature = "update-test")]
            if update_test_run(app.handle()) {
                return Ok(());
            }
            applog::note(&format!(
                "started GimmeCores {}{} from {}",
                app.package_info().version,
                env!("GMC_VERSION_SUFFIX"),
                std::env::current_exe()
                    .ok()
                    .and_then(|e| update::bundle_of(&e).or(Some(e)))
                    .map_or_else(|| "?".to_string(), |p| p.display().to_string())
            ));
            let status = MenuItem::with_id(app, "status", "GimmeCores", false, None::<&str>)?;
            let lend = MenuItem::with_id(app, "lend", "Turn lending on", false, None::<&str>)?;
            let stop = MenuItem::with_id(app, "stop", "Stop all lending", true, None::<&str>)?;
            let open = MenuItem::with_id(app, "open", "Open GimmeCores", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(
                app,
                &[
                    &status,
                    &PredefinedMenuItem::separator(app)?,
                    &lend,
                    &stop,
                    &PredefinedMenuItem::separator(app)?,
                    &open,
                    &quit,
                ],
            )?;
            TrayIconBuilder::with_id("main")
                .icon(tauri::include_image!("icons/tray.png"))
                .icon_as_template(true)
                .tooltip("GimmeCores")
                .menu(&menu)
                .show_menu_on_left_click(true)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "lend" => toggle_lending(app),
                    "stop" => stop_all_from_tray(app),
                    "open" => show_window(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;
            app.manage(Tray { status, lend });
            tauri::async_runtime::spawn(watch(app.handle().clone()));
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window keeps GimmeCores in the menu bar; Quit is in the tray menu.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!());
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
