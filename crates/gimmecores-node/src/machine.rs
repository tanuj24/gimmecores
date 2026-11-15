//! This computer as a whole: how busy its CPU, memory and GPUs are, for the "This computer"
//! bars (docs/design/activity.md). Measured only when a listing is read, so an idle service
//! does no work for it. Every figure that could not be read is `None` ("not measured").

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use gimmecores_proto::peer::v1 as pb;

/// A CPU reading older than this is not a baseline for the next one: take a fresh pair.
const BASELINE_MAX_AGE: Duration = Duration::from_secs(5);

/// One graphics processor, found once at start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gpu {
    /// At most 64 characters, control characters removed.
    pub name: String,
    pub kind: pb::GpuKind,
    /// Its own memory; 0 when it shares the system's (Apple silicon) or it is not known.
    pub memory_bytes: u64,
    source: Source,
}

/// Where a GPU's busy figure comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Source {
    /// The n-th `IOAccelerator` in `ioreg` (macOS): its "Device Utilization %".
    Ioreg(usize),
    /// `nvidia-smi` index.
    Nvidia(u32),
    /// The card's `gpu_busy_percent` (Linux amdgpu).
    Sysfs(PathBuf),
    /// No source (Intel on Linux, Windows): busy is not measured.
    None,
}

/// This computer's load right now.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Load {
    pub cpu_cores: u32,
    /// All programs, this service and its tasks included. 1000 = one core.
    pub cpu_busy_millis: Option<u32>,
    pub memory_total_bytes: u64,
    /// Total minus what the system says is available.
    pub memory_used_bytes: Option<u64>,
    pub gpus: Vec<(Gpu, Option<u32>)>,
}

struct Cpu {
    sys: sysinfo::System,
    /// When `sys` last read CPU usage, and what it read then.
    last: Option<(Instant, Option<u32>)>,
}

pub struct Machine {
    cpu: Mutex<Cpu>,
    /// The last whole reading: readers within [`REUSE_FOR`] of it share it, so however many
    /// windows and devices ask, this computer reads itself at most about once a second.
    last: Mutex<Option<(Instant, Load)>>,
}

/// How long one whole reading is shared.
const REUSE_FOR: Duration = Duration::from_millis(900);

impl Default for Machine {
    fn default() -> Self {
        Self {
            cpu: Mutex::new(Cpu {
                sys: sysinfo::System::new(),
                last: None,
            }),
            last: Mutex::new(None),
        }
    }
}

fn cores() -> u32 {
    std::thread::available_parallelism()
        .map(|n| u32::try_from(n.get()).unwrap_or(u32::MAX))
        .unwrap_or(1)
}

fn millis(percent: f32, cores: u32) -> Option<u32> {
    if !percent.is_finite() || percent < 0.0 {
        return None;
    }
    let busy = f64::from(percent.min(100.0)) / 100.0 * f64::from(cores) * 1000.0;
    // Bounded above by cores * 1000, so it fits.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Some(busy.round() as u32)
}

impl Machine {
    /// Reads CPU, memory and GPUs. CPU use is measured between two readings; when there is no
    /// recent one, this takes a pair `MINIMUM_CPU_UPDATE_INTERVAL` apart. Readings closer
    /// together than that (two windows open) share the last result.
    pub async fn sample(&self) -> Load {
        if let Some((at, load)) = lock(&self.last).as_ref()
            && at.elapsed() < REUSE_FOR
        {
            return load.clone();
        }
        let load = self.read().await;
        *lock(&self.last) = Some((Instant::now(), load.clone()));
        load
    }

    async fn read(&self) -> Load {
        let cpu_cores = cores();
        let need_pair = {
            let mut c = lock(&self.cpu);
            match c.last {
                Some((at, _)) if at.elapsed() < BASELINE_MAX_AGE => false,
                _ => {
                    c.sys.refresh_cpu_usage();
                    c.last = Some((Instant::now(), None));
                    true
                }
            }
        };
        if need_pair {
            tokio::time::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL).await;
        }
        let (cpu_busy_millis, memory_total_bytes, memory_used_bytes) = {
            let mut c = lock(&self.cpu);
            let busy = match c.last {
                Some((at, value))
                    if !need_pair && at.elapsed() < sysinfo::MINIMUM_CPU_UPDATE_INTERVAL =>
                {
                    value
                }
                _ => {
                    c.sys.refresh_cpu_usage();
                    let v = millis(c.sys.global_cpu_usage(), cpu_cores);
                    c.last = Some((Instant::now(), v));
                    v
                }
            };
            c.sys.refresh_memory();
            let total = c.sys.total_memory();
            let available = c.sys.available_memory();
            let used = (total > 0 && available <= total).then(|| total - available);
            (busy, total, used)
        };
        Load {
            cpu_cores,
            cpu_busy_millis,
            memory_total_bytes,
            memory_used_bytes,
            gpus: gpu_load().await,
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ------------------------------------------------------------------ GPUs

static GPUS: OnceLock<Vec<Gpu>> = OnceLock::new();

/// The GPUs found at start (empty until [`detect`] ran, or when there are none).
pub fn gpus() -> Vec<Gpu> {
    GPUS.get().cloned().unwrap_or_default()
}

/// Finds this computer's GPUs once; later calls return at once.
pub async fn detect() {
    if GPUS.get().is_some() {
        return;
    }
    let found = if cfg!(target_os = "macos") {
        crate::power::output("ioreg", &["-r", "-c", "IOAccelerator", "-d", "1"])
            .await
            .map(|out| parse_ioreg(&out).into_iter().map(|(g, _)| g).collect())
            .unwrap_or_default()
    } else if cfg!(target_os = "linux") {
        let nvidia = crate::power::output(
            "nvidia-smi",
            &[
                "--query-gpu=index,name,memory.total",
                "--format=csv,noheader,nounits",
            ],
        )
        .await
        .map(|out| parse_nvidia_inventory(&out))
        .unwrap_or_default();
        let mut all = nvidia.clone();
        all.extend(linux_drm_gpus(
            Path::new("/sys/class/drm"),
            !nvidia.is_empty(),
        ));
        all
    } else if cfg!(windows) {
        gimmecores_os::gpu::adapters()
            .into_iter()
            .map(|a| Gpu {
                name: crate::wire::clean_text(&a.name, 64).trim().to_string(),
                kind: if a.nvidia {
                    pb::GpuKind::Cuda
                } else {
                    pb::GpuKind::Unspecified
                },
                memory_bytes: a.memory_bytes,
                source: Source::None,
            })
            .collect()
    } else {
        Vec::new()
    };
    let _ = GPUS.set(found);
}

/// Each GPU with how busy it is now (percent), where that can be read.
async fn gpu_load() -> Vec<(Gpu, Option<u32>)> {
    let gpus = gpus();
    if gpus.is_empty() {
        return Vec::new();
    }
    let ioreg = if gpus.iter().any(|g| matches!(g.source, Source::Ioreg(_))) {
        crate::power::output("ioreg", &["-r", "-c", "IOAccelerator", "-d", "1"])
            .await
            .map(|out| parse_ioreg(&out))
    } else {
        None
    };
    let nvidia = if gpus.iter().any(|g| matches!(g.source, Source::Nvidia(_))) {
        crate::power::output(
            "nvidia-smi",
            &[
                "--query-gpu=index,utilization.gpu",
                "--format=csv,noheader,nounits",
            ],
        )
        .await
        .map(|out| parse_nvidia_busy(&out))
    } else {
        None
    };
    gpus.into_iter()
        .map(|g| {
            let busy = match &g.source {
                Source::Ioreg(i) => ioreg.as_ref().and_then(|v| v.get(*i)).and_then(|(_, b)| *b),
                Source::Nvidia(i) => nvidia
                    .as_ref()
                    .and_then(|v| v.iter().find(|(n, _)| n == i))
                    .and_then(|(_, b)| *b),
                Source::Sysfs(p) => read_percent(p),
                Source::None => None,
            };
            (g, busy)
        })
        .collect()
}

fn percent(s: &str) -> Option<u32> {
    s.trim().parse::<u32>().ok().filter(|v| *v <= 100)
}

fn read_percent(p: &Path) -> Option<u32> {
    percent(&std::fs::read_to_string(p).ok()?)
}

/// `ioreg -r -c IOAccelerator -d 1`: one entry per GPU, each with a `"model"` (Apple GPUs)
/// and `"PerformanceStatistics" = {... "Device Utilization %"=12 ...}`.
fn parse_ioreg(out: &str) -> Vec<(Gpu, Option<u32>)> {
    let mut found = Vec::new();
    for (i, entry) in out.split("+-o ").skip(1).enumerate() {
        let model = entry.lines().find_map(|l| {
            let rest = l.trim().strip_prefix("\"model\" = ")?;
            // `"Apple M2 Max"` or `<"AMD Radeon Pro 5500M">`
            let rest = rest.trim_start_matches('<').trim_end_matches('>');
            Some(rest.trim_matches('"').to_string())
        });
        let busy = entry.find("\"Device Utilization %\"=").and_then(|at| {
            let digits: String = entry[at + "\"Device Utilization %\"=".len()..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            percent(&digits)
        });
        let name = crate::wire::clean_text(model.as_deref().unwrap_or("GPU"), 64)
            .trim()
            .to_string();
        let kind = if name.starts_with("Apple ") || entry.contains("AGXAccelerator") {
            pb::GpuKind::Metal
        } else {
            pb::GpuKind::Unspecified
        };
        found.push((
            Gpu {
                name: if name.is_empty() { "GPU".into() } else { name },
                kind,
                memory_bytes: 0,
                source: Source::Ioreg(i),
            },
            busy,
        ));
    }
    found
}

/// `nvidia-smi --query-gpu=index,name,memory.total --format=csv,noheader,nounits`
/// → `0, NVIDIA GeForce RTX 4090, 24564` (MiB).
fn parse_nvidia_inventory(out: &str) -> Vec<Gpu> {
    out.lines()
        .filter_map(|l| {
            let mut f = l.split(',').map(str::trim);
            let index = f.next()?.parse::<u32>().ok()?;
            let name = crate::wire::clean_text(f.next()?, 64).trim().to_string();
            let mib = f.next().and_then(|m| m.parse::<u64>().ok()).unwrap_or(0);
            Some(Gpu {
                name: if name.is_empty() {
                    "NVIDIA GPU".into()
                } else {
                    name
                },
                kind: pb::GpuKind::Cuda,
                memory_bytes: mib.saturating_mul(1024 * 1024),
                source: Source::Nvidia(index),
            })
        })
        .collect()
}

/// `nvidia-smi --query-gpu=index,utilization.gpu --format=csv,noheader,nounits` → `0, 37`.
fn parse_nvidia_busy(out: &str) -> Vec<(u32, Option<u32>)> {
    out.lines()
        .filter_map(|l| {
            let (i, b) = l.split_once(',')?;
            Some((i.trim().parse().ok()?, percent(b)))
        })
        .collect()
}

/// Linux GPUs from the kernel's display drivers: amdgpu (with memory and busy figures) and
/// Intel's i915/xe (no busy figure). Virtual and display-only adapters are left out, and so is
/// NVIDIA's own driver when `nvidia-smi` already listed its GPUs.
fn linux_drm_gpus(drm: &Path, nvidia_listed: bool) -> Vec<Gpu> {
    let Ok(dir) = std::fs::read_dir(drm) else {
        return Vec::new();
    };
    let mut cards: Vec<PathBuf> = dir
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_prefix("card"))
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        })
        .collect();
    cards.sort();
    cards
        .into_iter()
        .filter_map(|card| {
            let device = card.join("device");
            let driver = std::fs::read_link(device.join("driver")).ok()?;
            let driver = driver.file_name()?.to_str()?.to_string();
            let read = |f: &str| std::fs::read_to_string(device.join(f)).ok();
            let product = read("product_name")
                .map(|n| crate::wire::clean_text(&n, 64).trim().to_string())
                .filter(|n| !n.is_empty());
            match driver.as_str() {
                "amdgpu" => Some(Gpu {
                    name: product.unwrap_or_else(|| "AMD GPU".into()),
                    kind: pb::GpuKind::Unspecified,
                    memory_bytes: read("mem_info_vram_total")
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0),
                    source: Source::Sysfs(device.join("gpu_busy_percent")),
                }),
                "i915" | "xe" => Some(Gpu {
                    name: product.unwrap_or_else(|| "Intel GPU".into()),
                    kind: pb::GpuKind::Unspecified,
                    memory_bytes: 0,
                    source: Source::None,
                }),
                "nvidia" | "nouveau" if !nvidia_listed => Some(Gpu {
                    name: product.unwrap_or_else(|| "NVIDIA GPU".into()),
                    kind: pb::GpuKind::Cuda,
                    memory_bytes: 0,
                    source: Source::None,
                }),
                _ => None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const IOREG: &str = r#"+-o AGXAcceleratorG14X  <class AGXAcceleratorG14X, id 0x100000419, registered>
    {
      "IOClass" = "AGXAcceleratorG14X"
      "PerformanceStatistics" = {"Alloc system memory"=2297692160,"Tiler Utilization %"=3,"Device Utilization %"=17,"Renderer Utilization %"=12}
      "model" = "Apple M2 Max"
      "gpu-core-count" = 30
    }
+-o AMDRadeonX6000_AMDNavi14GraphicsAccelerator  <class AMDRadeonX6000_AMDNavi14GraphicsAccelerator>
    {
      "PerformanceStatistics" = {"Device Utilization %"=250}
    }
"#;

    #[test]
    fn apple_gpus_come_from_ioreg() {
        let found = parse_ioreg(IOREG);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].0.name, "Apple M2 Max");
        assert_eq!(found[0].0.kind, pb::GpuKind::Metal);
        assert_eq!(
            found[0].1,
            Some(17),
            "Device Utilization, not the tiler's or renderer's"
        );
        // No model: a plain name; a figure above 100 % is not believed.
        assert_eq!(found[1].0.name, "GPU");
        assert_eq!(found[1].0.kind, pb::GpuKind::Unspecified);
        assert_eq!(found[1].1, None);
        assert!(parse_ioreg("").is_empty());
    }

    #[test]
    fn gpu_names_are_cleaned_and_cut() {
        let out = format!(
            "+-o X\n      \"model\" = \"Evil\u{1b}[2J{}\"\n",
            "A".repeat(200)
        );
        let name = &parse_ioreg(&out)[0].0.name;
        assert!(!name.contains('\u{1b}'), "{name:?}");
        assert!(name.chars().count() <= 64, "{name:?}");
    }

    #[test]
    fn nvidia_smi_output_is_parsed() {
        let inv = parse_nvidia_inventory(
            "0, NVIDIA GeForce RTX 4090, 24564\n1, Tesla T4, 15360\nbad line\n",
        );
        assert_eq!(inv.len(), 2);
        assert_eq!(inv[0].name, "NVIDIA GeForce RTX 4090");
        assert_eq!(inv[0].kind, pb::GpuKind::Cuda);
        assert_eq!(inv[0].memory_bytes, 24564 * 1024 * 1024);
        assert_eq!(inv[1].source, Source::Nvidia(1));
        assert_eq!(
            parse_nvidia_busy("0, 37\n1, [N/A]\n"),
            vec![(0, Some(37)), (1, None)]
        );
    }

    #[cfg(unix)]
    #[test]
    fn linux_cards_by_driver() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let drm = root.path().join("drm");
        let card = |n: &str, driver: &str| {
            let dev = drm.join(n).join("device");
            std::fs::create_dir_all(&dev).unwrap();
            let target = root.path().join("drivers").join(driver);
            std::fs::create_dir_all(&target).unwrap();
            symlink(&target, dev.join("driver")).unwrap();
            dev
        };
        let amd = card("card1", "amdgpu");
        std::fs::write(amd.join("mem_info_vram_total"), "8573157376\n").unwrap();
        std::fs::write(amd.join("gpu_busy_percent"), "42\n").unwrap();
        card("card0", "i915");
        card("card2", "virtio-pci");
        card("card3", "nvidia");
        // A connector, not a card.
        std::fs::create_dir_all(drm.join("card1-HDMI-A-1")).unwrap();

        let found = linux_drm_gpus(&drm, true);
        let names: Vec<&str> = found.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(
            names,
            ["Intel GPU", "AMD GPU"],
            "virtual adapters and listed NVIDIA left out"
        );
        assert_eq!(found[1].memory_bytes, 8_573_157_376);
        assert_eq!(found[1].source, Source::Sysfs(amd.join("gpu_busy_percent")));
        assert_eq!(read_percent(&amd.join("gpu_busy_percent")), Some(42));
        assert_eq!(found[0].source, Source::None, "Intel: busy not measured");
        // Without nvidia-smi, NVIDIA's card is still listed, busy not measured.
        assert_eq!(linux_drm_gpus(&drm, false).len(), 3);
        assert!(linux_drm_gpus(&root.path().join("missing"), false).is_empty());
    }

    #[test]
    fn cpu_percent_to_millis() {
        assert_eq!(millis(50.0, 12), Some(6000));
        assert_eq!(millis(100.0, 8), Some(8000));
        assert_eq!(millis(150.0, 8), Some(8000), "never above all cores");
        assert_eq!(millis(f32::NAN, 8), None);
        assert_eq!(millis(-1.0, 8), None);
    }

    #[tokio::test]
    async fn this_computer_is_measured() {
        let m = Machine::default();
        let load = m.sample().await;
        assert!(load.cpu_cores >= 1);
        assert!(load.memory_total_bytes > 0);
        let busy = load.cpu_busy_millis.expect("CPU use is measured");
        assert!(busy <= load.cpu_cores * 1000);
        let used = load.memory_used_bytes.expect("memory use is measured");
        assert!(used <= load.memory_total_bytes);
        // A second reading right away reuses the last one instead of a 0-length interval.
        let again = m.sample().await;
        assert_eq!(again.cpu_busy_millis, load.cpu_busy_millis);
    }
}
