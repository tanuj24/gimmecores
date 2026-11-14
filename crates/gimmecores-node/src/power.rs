//! Laptop protections: is the machine on battery, is it hot, and is its user active?
//! (docs/design/consent-and-grants.md, threat model 5.1 "make the laptop unusable".)

use std::time::Duration;

use tokio::process::Command;

/// What the lender's machine looks like right now. `None` = could not tell.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PowerState {
    pub on_battery: Option<bool>,
    /// Seconds since the last keyboard/mouse input.
    pub idle_secs: Option<u64>,
    /// Running hot: macOS's thermal state is serious or critical, or a Linux sensor has
    /// reached the temperature where the system starts slowing itself down.
    pub hot: Option<bool>,
}

/// The lender's protection settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Protections {
    pub pause_on_battery: bool,
    /// Lend only while the user has been away for [`IDLE_THRESHOLD_SECS`].
    pub idle_only: bool,
    pub pause_when_hot: bool,
}

pub const IDLE_THRESHOLD_SECS: u64 = 120;
/// Paused longer than this: running tasks are stopped (they hold memory while frozen).
pub const MAX_PAUSE: Duration = Duration::from_secs(10 * 60);

/// Why lending should pause now, if it should. Unknown readings never pause (servers and Pis
/// have no battery and no keyboard).
pub fn pause_reason(p: Protections, s: PowerState) -> Option<&'static str> {
    if p.pause_on_battery && s.on_battery == Some(true) {
        return Some("on battery");
    }
    if p.pause_when_hot && s.hot == Some(true) {
        return Some("the computer is hot");
    }
    if p.idle_only && s.idle_secs.is_some_and(|i| i < IDLE_THRESHOLD_SECS) {
        return Some("the owner is using this computer");
    }
    None
}

async fn output(cmd: &str, args: &[&str]) -> Option<String> {
    let out = tokio::time::timeout(
        Duration::from_secs(3),
        Command::new(cmd).args(args).output(),
    )
    .await
    .ok()?
    .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `pmset -g batt` → "Now drawing from 'Battery Power'" / "'AC Power'".
pub fn parse_pmset(out: &str) -> Option<bool> {
    if out.contains("'Battery Power'") {
        Some(true)
    } else if out.contains("'AC Power'") {
        Some(false)
    } else {
        None
    }
}

/// `ioreg -c IOHIDSystem -d 4` → `"HIDIdleTime" = 1234567890` (nanoseconds).
pub fn parse_ioreg_idle(out: &str) -> Option<u64> {
    out.lines()
        .find(|l| l.contains("\"HIDIdleTime\""))
        .and_then(|l| l.split('=').nth(1))
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|ns| ns / 1_000_000_000)
}

/// Linux: on battery when a battery exists and no mains supply is online.
fn linux_on_battery() -> Option<bool> {
    let dir = std::fs::read_dir("/sys/class/power_supply").ok()?;
    let (mut has_battery, mut ac_online) = (false, false);
    for e in dir.flatten() {
        let p = e.path();
        let kind = std::fs::read_to_string(p.join("type")).unwrap_or_default();
        match kind.trim() {
            "Battery" => has_battery = true,
            "Mains" | "USB"
                if std::fs::read_to_string(p.join("online")).is_ok_and(|v| v.trim() == "1") =>
            {
                ac_online = true;
            }
            _ => {}
        }
    }
    has_battery.then_some(!ac_online)
}

/// Linux: hot when a thermal zone has reached its first "passive" trip point (where the kernel
/// starts throttling) or, without one, its "hot" trip point. No zones or trip points: unknown.
pub fn linux_hot_at(root: &std::path::Path) -> Option<bool> {
    let dir = std::fs::read_dir(root).ok()?;
    let mut known = false;
    for e in dir.flatten() {
        let zone = e.path();
        if !e.file_name().to_string_lossy().starts_with("thermal_zone") {
            continue;
        }
        let read = |name: &str| -> Option<i64> {
            std::fs::read_to_string(zone.join(name))
                .ok()?
                .trim()
                .parse()
                .ok()
        };
        let Some(temp) = read("temp") else { continue };
        let mut trips: Vec<(String, i64)> = Vec::new();
        for i in 0..32 {
            let Ok(kind) = std::fs::read_to_string(zone.join(format!("trip_point_{i}_type")))
            else {
                break;
            };
            if let Some(t) = read(&format!("trip_point_{i}_temp")) {
                trips.push((kind.trim().to_string(), t));
            }
        }
        let limit = ["passive", "hot"].iter().find_map(|k| {
            trips
                .iter()
                .filter(|(t, v)| t == k && *v > 0)
                .map(|(_, v)| *v)
                .min()
        });
        if let Some(limit) = limit {
            known = true;
            if temp >= limit {
                return Some(true);
            }
        }
    }
    known.then_some(false)
}

pub async fn read() -> PowerState {
    if cfg!(target_os = "macos") {
        PowerState {
            on_battery: output("pmset", &["-g", "batt"])
                .await
                .as_deref()
                .and_then(parse_pmset),
            idle_secs: output("ioreg", &["-c", "IOHIDSystem", "-d", "4"])
                .await
                .as_deref()
                .and_then(parse_ioreg_idle),
            hot: gimmecores_presence::thermal_hot(),
        }
    } else if cfg!(target_os = "linux") {
        // Idle time has no portable source on Linux (X11/Wayland differ); unknown never pauses.
        PowerState {
            on_battery: linux_on_battery(),
            idle_secs: None,
            hot: linux_hot_at(std::path::Path::new("/sys/class/thermal")),
        }
    } else {
        PowerState::default()
    }
}

// ------------------------------------------------------------------ held back by the system

/// How macOS schedules this service, and with it every task it starts (tasks inherit it).
/// Measured on an M2 Max (8 performance + 4 efficiency cores), a sandboxed task through
/// `gmc run`, by how launchd was told to start the service:
///
/// | job type      | `ps` priority | 1 process | 8 processes | the owner's own 8 meanwhile |
/// |---------------|---------------|-----------|-------------|-----------------------------|
/// | `Interactive` | 31            | 1.0 s     | 1.1 s       | 1.9 s (1.1 s alone)         |
/// | `Standard`    | 20            | 1.0 s     | 1.9 s       | 1.3 s                       |
/// | `Background`  | 4             | 6.2 s     | 15.6 s      | 1.0 s                       |
///
/// A terminal starts programs like `Interactive`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheduling {
    /// As any program the owner runs: tasks get the fast cores.
    Normal,
    /// Below normal (priority 20 or less): work on several cores runs about half as fast.
    BelowNormal,
    /// Throttled (priority 4 or less): efficiency cores only, slowed disk access.
    Background,
}

/// Reads what `ps -o pri=` printed for this process. Unknown text counts as normal: this
/// only ever adds a warning.
pub fn scheduling(ps_pri: &str) -> Scheduling {
    match ps_pri.trim().parse::<i32>() {
        Ok(p) if p <= 4 => Scheduling::Background,
        Ok(p) if p <= 20 => Scheduling::BelowNormal,
        _ => Scheduling::Normal,
    }
}

/// Why tasks here run slower than this computer can, if the system is holding this service
/// back; shown in status so a slow lender is never a silent one. Read once at start: it
/// follows from how the service was started and does not change while it runs.
pub fn slow_reason() -> Option<String> {
    // Elsewhere tasks do not inherit a scheduling class from the service this way (on Linux
    // they are niced, which costs nothing while cores are free).
    if !cfg!(target_os = "macos") {
        return None;
    }
    let out = std::process::Command::new("/bin/ps")
        .args(["-o", "pri=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    let fix = "Restart it from the GimmeCores app; with Homebrew, upgrade and run \
               `brew services restart gimmecores`.";
    match scheduling(&String::from_utf8_lossy(&out.stdout)) {
        Scheduling::Normal => None,
        Scheduling::BelowNormal => Some(format!(
            "macOS runs this service below normal priority, so tasks that use several cores \
             run about half as fast. {fix}"
        )),
        Scheduling::Background => Some(format!(
            "macOS runs this service at background priority, so tasks get only the \
             efficiency cores and run several times slower. {fix}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduling_is_read_from_the_priority_ps_prints() {
        // What `ps -o pri=` prints for: a background job, a standard service, a terminal.
        for (pri, want) in [
            ("4", Scheduling::Background),
            ("  4\n", Scheduling::Background),
            ("0", Scheduling::Background),
            ("5", Scheduling::BelowNormal),
            ("20", Scheduling::BelowNormal),
            ("21", Scheduling::Normal),
            ("31", Scheduling::Normal),
            ("47", Scheduling::Normal),
            ("", Scheduling::Normal),
            ("abc", Scheduling::Normal),
        ] {
            assert_eq!(scheduling(pri), want, "{pri:?}");
        }
    }

    const LAPTOP: Protections = Protections {
        pause_on_battery: true,
        idle_only: false,
        pause_when_hot: true,
    };

    #[test]
    fn battery_pauses_only_when_known_and_enabled() {
        let batt = PowerState {
            on_battery: Some(true),
            idle_secs: None,
            hot: None,
        };
        assert_eq!(pause_reason(LAPTOP, batt), Some("on battery"));
        let ac = PowerState {
            on_battery: Some(false),
            idle_secs: None,
            hot: None,
        };
        assert_eq!(pause_reason(LAPTOP, ac), None);
        assert_eq!(
            pause_reason(LAPTOP, PowerState::default()),
            None,
            "unknown never pauses"
        );
        let off = Protections {
            pause_on_battery: false,
            idle_only: false,
            pause_when_hot: true,
        };
        assert_eq!(pause_reason(off, batt), None);
    }

    #[test]
    fn idle_only_pauses_while_the_owner_is_active() {
        let p = Protections {
            pause_on_battery: true,
            idle_only: true,
            pause_when_hot: true,
        };
        let active = PowerState {
            on_battery: Some(false),
            idle_secs: Some(5),
            hot: None,
        };
        let away = PowerState {
            on_battery: Some(false),
            idle_secs: Some(600),
            hot: None,
        };
        assert_eq!(
            pause_reason(p, active),
            Some("the owner is using this computer")
        );
        assert_eq!(pause_reason(p, away), None);
        assert_eq!(pause_reason(LAPTOP, active), None, "idle-only is opt-in");
    }

    #[test]
    fn heat_pauses_only_when_known_and_enabled() {
        let hot = PowerState {
            hot: Some(true),
            ..PowerState::default()
        };
        assert_eq!(pause_reason(LAPTOP, hot), Some("the computer is hot"));
        let cool = PowerState {
            hot: Some(false),
            ..PowerState::default()
        };
        assert_eq!(pause_reason(LAPTOP, cool), None);
        let off = Protections {
            pause_when_hot: false,
            ..LAPTOP
        };
        assert_eq!(pause_reason(off, hot), None);
    }

    #[test]
    fn linux_zones_are_hot_at_their_throttling_point() {
        let d = tempfile::tempdir().unwrap();
        let zone = |name: &str, temp: i64, trips: &[(&str, i64)]| {
            let z = d.path().join(name);
            std::fs::create_dir_all(&z).unwrap();
            std::fs::write(z.join("temp"), format!("{temp}\n")).unwrap();
            for (i, (kind, t)) in trips.iter().enumerate() {
                std::fs::write(z.join(format!("trip_point_{i}_type")), format!("{kind}\n"))
                    .unwrap();
                std::fs::write(z.join(format!("trip_point_{i}_temp")), format!("{t}\n")).unwrap();
            }
        };
        assert_eq!(linux_hot_at(d.path()), None, "no zones: unknown");
        zone("thermal_zone0", 50_000, &[]);
        assert_eq!(linux_hot_at(d.path()), None, "no trip points: unknown");
        zone(
            "thermal_zone1",
            70_000,
            &[("critical", 105_000), ("passive", 95_000)],
        );
        assert_eq!(linux_hot_at(d.path()), Some(false));
        zone(
            "thermal_zone2",
            96_000,
            &[("hot", 99_000), ("passive", 95_000)],
        );
        assert_eq!(linux_hot_at(d.path()), Some(true), "at the passive point");
        std::fs::remove_dir_all(d.path().join("thermal_zone2")).unwrap();
        zone(
            "thermal_zone3",
            99_500,
            &[("hot", 99_000), ("critical", 105_000)],
        );
        assert_eq!(
            linux_hot_at(d.path()),
            Some(true),
            "no passive point: the hot one"
        );
        std::fs::remove_dir_all(d.path().join("thermal_zone3")).unwrap();
        zone("cooling_device0", 200_000, &[("passive", 1)]);
        assert_eq!(
            linux_hot_at(d.path()),
            Some(false),
            "only thermal zones count"
        );
    }

    #[test]
    fn parses_macos_tool_output() {
        let batt = "Now drawing from 'Battery Power'\n -InternalBattery-0 (id=1)\t82%; discharging";
        let ac = "Now drawing from 'AC Power'\n -InternalBattery-0 (id=1)\t100%; charged";
        assert_eq!(parse_pmset(batt), Some(true));
        assert_eq!(parse_pmset(ac), Some(false));
        assert_eq!(parse_pmset("nothing"), None);
        let ioreg = "    |   \"HIDIdleTime\" = 125000000000\n";
        assert_eq!(parse_ioreg_idle(ioreg), Some(125));
        assert_eq!(parse_ioreg_idle("no idle here"), None);
    }
}
