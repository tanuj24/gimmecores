fn main() {
    // Only these commands exist for the window; each needs an explicit permission in
    // capabilities/default.json (nothing else from Tauri's core is granted).
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "snapshot",
            "set_lending",
            "set_lend_modes",
            "service_state",
            "set_start_at_login",
            "install_cli",
            "stop_all",
            "respond",
            "revoke",
            "open_pairing",
            "start_pairing",
            "start_pairing_nearby",
            "set_discovery",
            "confirm_pairing",
            "unpair",
            "set_trusted_mode",
        ]),
    ))
    .expect("failed to run tauri-build");
}
