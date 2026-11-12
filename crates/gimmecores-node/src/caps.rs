//! What this device offers (shown to paired peers and in `gmc status`).

use gimmecores_proto::peer::v1 as pb;

pub fn os_name() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macos",
        "windows" => "windows",
        _ => "linux",
    }
}

pub fn capabilities(
    lending_enabled: bool,
    lend_modes: gimmecores_core::Modes,
    available: gimmecores_core::Modes,
) -> pb::Capabilities {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    pb::Capabilities {
        os: os_name().into(),
        arch: match std::env::consts::ARCH {
            "aarch64" => "arm64".into(),
            other => other.into(),
        },
        cpu_cores: std::thread::available_parallelism()
            .map(|n| u32::try_from(n.get()).unwrap_or(u32::MAX))
            .unwrap_or(1),
        memory_bytes: sys.total_memory(),
        gpus: vec![],
        container_runtimes: vec!["docker".into()],
        native_mode_available: false,
        on_battery: false,
        lending_enabled,
        lend_modes: crate::grants_flow::modes_to(lend_modes),
        available_modes: crate::grants_flow::modes_to(available),
    }
}
