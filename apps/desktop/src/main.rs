//! The GimmeCores desktop app: a window for lending, requests, grants and pairing, a menu-bar
//! icon, and notifications when a device asks to use this computer.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use gimmecores_desktop::daemon::{self, PairingView, Snapshot, Ticket};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, State, WindowEvent, Wry};
use tauri_plugin_notification::NotificationExt;

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
async fn set_lending(
    home: State<'_, Home>,
    enabled: bool,
    idle_only: bool,
    allow_on_battery: bool,
) -> CmdResult<()> {
    daemon::set_lending(&home.0, enabled, idle_only, allow_on_battery)
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
    tauri::async_runtime::spawn_blocking(move || {
        if enabled {
            gimmecores_desktop::service::start_at_login()
        } else {
            gimmecores_desktop::service::stop_at_login()
        }
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(err)
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
async fn unpair(home: State<'_, Home>, fingerprint: String) -> CmdResult<()> {
    daemon::unpair(&home.0, &fingerprint).await.map_err(err)
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

/// Polls the daemon: keeps the tray menu current and announces new requests and pairings.
async fn watch(app: AppHandle) {
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
        tokio::time::sleep(Duration::from_secs(2)).await;
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
        .manage(Home(home))
        .manage(Mutex::new(Seen::default()))
        .invoke_handler(tauri::generate_handler![
            snapshot,
            set_lending,
            set_lend_modes,
            service_state,
            set_start_at_login,
            install_cli,
            stop_all,
            respond,
            revoke,
            open_pairing,
            start_pairing,
            confirm_pairing,
            unpair
        ])
        .setup(|app| {
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
