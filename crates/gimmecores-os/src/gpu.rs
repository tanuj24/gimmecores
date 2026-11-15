//! Graphics adapters as Windows lists them (DXGI), for the "This computer" bars. macOS and
//! Linux read theirs in gimmecores-node (`ioreg`, `nvidia-smi`, `/sys`), so this is empty there.

/// One hardware graphics adapter (Windows' software renderer is left out).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adapter {
    /// As the driver names it; not cleaned (the caller does that).
    pub name: String,
    /// Its own memory; 0 when it has none (integrated graphics).
    pub memory_bytes: u64,
    /// Made by NVIDIA (PCI vendor 0x10DE).
    pub nvidia: bool,
}

pub fn adapters() -> Vec<Adapter> {
    #[cfg(windows)]
    {
        crate::windows::gpu_adapters()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}
