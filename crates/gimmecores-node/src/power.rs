//! Laptop protections: is the machine on battery, and is its user active?
//! (docs/design/consent-and-grants.md, threat model 5.1 "make the laptop unusable".)

use std::time::Duration;

use tokio::process::Command;

/// What the lender's machine looks like right now. `None` = could not tell.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PowerState {
    pub on_battery: Option<bool>,
    /// Seconds since the last keyboard/mouse input.
    pub idle_secs: Option<u64>,
}

/// The lender's protection settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Protections {
    pub pause_on_battery: bool,
    /// Lend only while the user has been away for [`IDLE_THRESHOLD_SECS`].
    pub idle_only: bool,
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
        }
    } else if cfg!(target_os = "linux") {
        // Idle time has no portable source on Linux (X11/Wayland differ); unknown never pauses.
        PowerState {
            on_battery: linux_on_battery(),
            idle_secs: None,
        }
    } else {
        PowerState::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAPTOP: Protections = Protections {
        pause_on_battery: true,
        idle_only: false,
    };

    #[test]
    fn battery_pauses_only_when_known_and_enabled() {
        let batt = PowerState {
            on_battery: Some(true),
            idle_secs: None,
        };
        assert_eq!(pause_reason(LAPTOP, batt), Some("on battery"));
        let ac = PowerState {
            on_battery: Some(false),
            idle_secs: None,
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
        };
        assert_eq!(pause_reason(off, batt), None);
    }

    #[test]
    fn idle_only_pauses_while_the_owner_is_active() {
        let p = Protections {
            pause_on_battery: true,
            idle_only: true,
        };
        let active = PowerState {
            on_battery: Some(false),
            idle_secs: Some(5),
        };
        let away = PowerState {
            on_battery: Some(false),
            idle_secs: Some(600),
        };
        assert_eq!(
            pause_reason(p, active),
            Some("the owner is using this computer")
        );
        assert_eq!(pause_reason(p, away), None);
        assert_eq!(pause_reason(LAPTOP, active), None, "idle-only is opt-in");
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
