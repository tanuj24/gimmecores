include!("../../crates/gimmecores-cli/build_info.rs");

fn main() {
    emit_build_info();
    // The update key's public half (base64), built into the app. Without the file the app
    // builds but cannot update itself (Settings says so).
    let key = std::path::Path::new("../../packaging/release/update-key.pub");
    println!("cargo:rerun-if-changed={}", key.display());
    let pubkey = std::fs::read_to_string(key).unwrap_or_default();
    println!("cargo:rustc-env=GMC_UPDATE_PUBKEY={}", pubkey.trim());
    // Only these commands exist for the window; each needs an explicit permission in
    // capabilities/default.json (nothing else from Tauri's core is granted).
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "snapshot",
            "activity",
            "stop_task",
            "set_lending",
            "set_lend_modes",
            "set_share_load",
            "set_task_speed",
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
            "update_status",
            "check_update",
            "install_update",
        ]),
    ))
    .expect("failed to run tauri-build");
}
