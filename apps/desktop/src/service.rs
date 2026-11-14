//! Running `gmcd` in the background (a LaunchAgent on macOS, a systemd user service on Linux),
//! and putting `gmc` on the PATH. Everything here happens only when the user clicks for it.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;

pub const LABEL: &str = "dev.gimmecores.gmcd";

#[derive(Clone, Debug, Default, Serialize)]
pub struct ServiceState {
    /// gmcd starts at login (a LaunchAgent is installed).
    pub start_at_login: bool,
    /// A `gmcd` was found next to the app (false when run from a development build).
    pub bundled: bool,
    /// `gmc` is on the PATH (linked in /usr/local/bin, or by Homebrew).
    pub cli_installed: bool,
    /// gmcd is started by `brew services` instead (the app leaves that one alone).
    pub homebrew_service: bool,
    /// The installed login item asks macOS for reduced scheduling (an older version wrote it),
    /// so tasks run slower than this computer can: starting it again replaces it.
    pub reduced: bool,
}

/// The LaunchAgent `brew services start gimmecores` installs.
const HOMEBREW_LABEL: &str = "homebrew.mxcl.gimmecores";

fn homebrew_plist() -> Result<PathBuf> {
    Ok(home()?
        .join("Library/LaunchAgents")
        .join(format!("{HOMEBREW_LABEL}.plist")))
}

/// Homebrew keeps each version in `<prefix>/Cellar/<name>/<version>/` and removes it on
/// upgrade; `<prefix>/opt/<name>/` always points at the current one. A login item must use
/// the lasting path.
pub fn lasting_path(p: &Path) -> PathBuf {
    let parts: Vec<_> = p.components().collect();
    let Some(i) = parts.iter().position(|c| c.as_os_str() == "Cellar") else {
        return p.to_path_buf();
    };
    if parts.len() < i + 4 {
        return p.to_path_buf();
    }
    let mut out: PathBuf = parts[..i].iter().collect();
    out.push("opt");
    out.push(parts[i + 1]);
    out.extend(&parts[i + 3..]);
    out
}

/// `gmcd` and `gmc` ship next to the app's own executable (Contents/MacOS).
pub fn bundled_binary(name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let p = lasting_path(&exe.parent()?.join(name));
    p.is_file().then_some(p)
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

pub fn plist_path() -> Result<PathBuf> {
    Ok(home()?
        .join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist")))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// launchd starts agents with only the system PATH; tasks and runtimes (Docker Desktop,
/// Homebrew's tools) should be found as they are in a terminal.
const SERVICE_PATH: &str = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

/// The LaunchAgent: start `gmcd` at login, restart it if it crashes (not after a clean stop),
/// log to ~/Library/Logs/GimmeCores.
///
/// `ProcessType` is `Interactive`: tasks inherit how macOS schedules the service, and only
/// this type runs them as fast as a program the owner starts. Measured on an M2 Max through
/// `gmc run`: a `Background` job made tasks 6 to 15 times slower (efficiency cores only), a
/// `Standard` one halved work on several cores. The price: while a lent task uses every core,
/// the owner's own heavy work shares them (the lending switches are the owner's control).
pub fn launch_agent_plist(gmcd: &Path, logs: &Path) -> String {
    let gmcd = xml_escape(&gmcd.to_string_lossy());
    let out = xml_escape(&logs.join("gmcd.log").to_string_lossy());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key><array><string>{gmcd}</string></array>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>{SERVICE_PATH}</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>{out}</string>
  <key>StandardErrorPath</key><string>{out}</string>
</dict>
</plist>
"#
    )
}

/// Whether a login item's text asks launchd for anything but `Interactive` scheduling (a
/// missing `ProcessType` means `Standard`).
pub fn asks_for_reduced_scheduling(plist: &str) -> bool {
    let Some(at) = plist.find("<key>ProcessType</key>") else {
        return true;
    };
    let rest = plist[at + "<key>ProcessType</key>".len()..].trim_start();
    !rest.starts_with("<string>Interactive</string>")
}

/// Waits until launchd has let go of the job: a running `gmcd` takes a moment to stop, and
/// starting it again before that fails.
fn wait_until_unloaded(target: &str) {
    for _ in 0..50 {
        let known = std::process::Command::new("launchctl")
            .args(["print", target])
            .output()
            .is_ok_and(|o| o.status.success());
        if !known {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn uid() -> Result<String> {
    let o = std::process::Command::new("id").arg("-u").output()?;
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// The systemd user unit (the same name packaging/linux/install.sh uses, so either can manage
/// it).
pub const SYSTEMD_UNIT: &str = "gmcd.service";

fn systemd_dir() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or(home()?.join(".config"));
    Ok(base.join("systemd/user"))
}

/// The unit file: start `gmcd` at login, restart it if it crashes.
pub fn systemd_unit(gmcd: &Path) -> String {
    // systemd unit syntax: quote the path, double % (specifier) and escape quotes/backslashes.
    let path = gmcd
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    format!(
        "# Written by the GimmeCores app. Lending stays off until you turn it on.\n\
         [Unit]\n\
         Description=GimmeCores: lend this computer to your paired devices, with your consent\n\
         After=network-online.target\n\n\
         [Service]\n\
         ExecStart=\"{path}\"\n\
         Restart=on-failure\n\
         RestartSec=5\n\n\
         [Install]\n\
         WantedBy=default.target\n"
    )
}

/// `gmcd` for the Linux service: next to the app, else ~/.local/bin (install.sh), else PATH.
fn linux_gmcd() -> Option<PathBuf> {
    bundled_binary("gmcd")
        .or_else(|| {
            let p = home().ok()?.join(".local/bin/gmcd");
            p.is_file().then_some(p)
        })
        .or_else(|| {
            std::env::split_paths(&std::env::var_os("PATH")?)
                .map(|d| d.join("gmcd"))
                .find(|p| p.is_file())
        })
}

fn systemctl(args: &[&str]) -> Result<()> {
    let out = std::process::Command::new("systemctl")
        .arg("--user")
        .args(args)
        .output()
        .context("systemctl is not available (GimmeCores' Linux service needs systemd)")?;
    if !out.status.success() {
        bail!(
            "systemctl --user {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

pub fn state() -> ServiceState {
    if cfg!(target_os = "linux") {
        let local = home().map(|h| h.join(".local/bin/gmc")).ok();
        return ServiceState {
            start_at_login: systemd_dir()
                .is_ok_and(|d| d.join("default.target.wants").join(SYSTEMD_UNIT).exists()),
            bundled: bundled_binary("gmcd").is_some(),
            cli_installed: local.is_some_and(|p| p.exists())
                || ["/usr/local/bin/gmc", "/usr/bin/gmc"]
                    .iter()
                    .any(|p| Path::new(p).exists()),
            homebrew_service: false,
            reduced: false,
        };
    }
    ServiceState {
        start_at_login: plist_path().is_ok_and(|p| p.exists()),
        reduced: plist_path()
            .and_then(|p| Ok(std::fs::read_to_string(p)?))
            .is_ok_and(|text| asks_for_reduced_scheduling(&text)),
        bundled: bundled_binary("gmcd").is_some(),
        cli_installed: ["/usr/local/bin/gmc", "/opt/homebrew/bin/gmc"]
            .iter()
            .any(|p| Path::new(p).exists()),
        homebrew_service: homebrew_plist().is_ok_and(|p| p.exists()),
    }
}

/// Linux: writes the systemd user unit (unless install.sh's is there) and starts it now.
fn linux_start_at_login() -> Result<()> {
    let dir = systemd_dir()?;
    let unit = dir.join(SYSTEMD_UNIT);
    if !unit.exists() {
        let gmcd = linux_gmcd().context(
            "gmcd was not found (next to the app, in ~/.local/bin or on PATH); install it with \
             packaging/linux/install.sh",
        )?;
        std::fs::create_dir_all(&dir)?;
        std::fs::write(&unit, systemd_unit(&gmcd))?;
    }
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", "--now", SYSTEMD_UNIT])
}

/// Installs the LaunchAgent (macOS) or systemd user service (Linux) and starts `gmcd` now.
pub fn start_at_login() -> Result<()> {
    if cfg!(target_os = "linux") {
        return linux_start_at_login();
    }
    if !cfg!(target_os = "macos") {
        bail!("starting gmcd at login is not supported on this system yet");
    }
    if homebrew_plist().is_ok_and(|p| p.exists()) {
        bail!("gmcd is already started by Homebrew (`brew services info gimmecores`)");
    }
    let gmcd = bundled_binary("gmcd")
        .context("gmcd was not found next to the app; start it from a terminal with `gmcd`")?;
    // A login item must point at a lasting location, not the mounted disk image or the
    // temporary copy macOS runs downloaded apps from.
    let p = gmcd.to_string_lossy();
    if p.starts_with("/Volumes/") || p.contains("/AppTranslocation/") {
        bail!("move GimmeCores to your Applications folder first, then open it from there");
    }
    let logs = home()?.join("Library/Logs/GimmeCores");
    std::fs::create_dir_all(&logs)?;
    let plist = plist_path()?;
    if let Some(dir) = plist.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Replace any previous registration (the app may have moved, or an older version wrote
    // it): stop that one, wait until it is gone, then start this one.
    let target = format!("gui/{}/{LABEL}", uid()?);
    let _ = std::process::Command::new("launchctl")
        .args(["bootout", &target])
        .output();
    wait_until_unloaded(&target);
    std::fs::write(&plist, launch_agent_plist(&gmcd, &logs))?;
    let out = std::process::Command::new("launchctl")
        .args(["bootstrap", &format!("gui/{}", uid()?)])
        .arg(&plist)
        .output()?;
    if !out.status.success() {
        bail!(
            "launchctl could not start gmcd: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Stops the background `gmcd` and no longer starts it at login.
pub fn stop_at_login() -> Result<()> {
    if cfg!(target_os = "linux") {
        return systemctl(&["disable", "--now", SYSTEMD_UNIT]);
    }
    let _ = std::process::Command::new("launchctl")
        .args(["bootout", &format!("gui/{}/{LABEL}", uid()?)])
        .output();
    let plist = plist_path()?;
    if plist.exists() {
        std::fs::remove_file(plist)?;
    }
    Ok(())
}

/// Links `gmc` and `gimmecores` into /usr/local/bin (macOS asks for an administrator) or
/// ~/.local/bin (Linux; no administrator needed).
pub fn install_cli() -> Result<()> {
    let gmc = bundled_binary("gmc").context("gmc was not found next to the app")?;
    let full = bundled_binary("gimmecores").unwrap_or_else(|| gmc.clone());
    if cfg!(target_os = "linux") {
        let bin = home()?.join(".local/bin");
        std::fs::create_dir_all(&bin)?;
        for (name, target) in [("gmc", &gmc), ("gimmecores", &full)] {
            let link = bin.join(name);
            if std::fs::symlink_metadata(&link).is_ok() {
                std::fs::remove_file(&link)?;
            }
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, &link)?;
        }
        return Ok(());
    }
    let q = |p: &Path| format!("'{}'", p.to_string_lossy().replace('\'', "'\\''"));
    let script = format!(
        "mkdir -p /usr/local/bin && ln -sf {} /usr/local/bin/gmc && ln -sf {} /usr/local/bin/gimmecores",
        q(&gmc),
        q(&full)
    );
    let apple = format!(
        "do shell script \"{}\" with administrator privileges",
        script.replace('\\', "\\\\").replace('"', "\\\"")
    );
    let out = std::process::Command::new("osascript")
        .args(["-e", &apple])
        .output()?;
    if !out.status.success() {
        bail!(
            "the command-line tool was not installed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_agent_runs_the_bundled_daemon_and_escapes_paths() {
        let p = launch_agent_plist(
            Path::new("/Applications/Gimme & Cores.app/Contents/MacOS/gmcd"),
            Path::new("/Users/x/Library/Logs/GimmeCores"),
        );
        assert!(p.contains("<string>dev.gimmecores.gmcd</string>"));
        assert!(p.contains("Gimme &amp; Cores.app/Contents/MacOS/gmcd"));
        assert!(p.contains("<key>RunAtLoad</key><true/>"));
        assert!(p.contains("gmcd.log"));
        assert!(p.contains("<key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:"));
    }

    /// macOS gives a `Background` job, and every task it starts, only the efficiency cores
    /// (5 to 14 times slower); a lender must never be set up that way, on any system.
    #[test]
    fn no_service_definition_asks_for_reduced_scheduling() {
        let p = launch_agent_plist(Path::new("/x/gmcd"), Path::new("/x/logs"));
        assert!(
            p.contains("<key>ProcessType</key><string>Interactive</string>"),
            "{p}"
        );
        assert!(!asks_for_reduced_scheduling(&p));
        // What older versions wrote, a hand-edited file, and one with no type at all.
        for old in ["Background", "Standard", "Adaptive"] {
            let text = p.replace("Interactive", old);
            assert!(asks_for_reduced_scheduling(&text), "{old}");
        }
        let spaced = p.replace(
            "<key>ProcessType</key><string>",
            "<key>ProcessType</key>\n    <string>",
        );
        assert!(!asks_for_reduced_scheduling(&spaced));
        let untyped = p.replace("<key>ProcessType</key><string>Interactive</string>", "");
        assert!(asks_for_reduced_scheduling(&untyped));
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let formula = std::fs::read_to_string(root.join("Formula/gimmecores.rb")).unwrap();
        let code: Vec<&str> = formula
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect();
        let types: Vec<&str> = code
            .iter()
            .filter(|l| l.contains("process_type"))
            .map(|l| l.trim())
            .collect();
        assert_eq!(types, ["process_type :interactive"], "the Homebrew service");
        let packaged = std::fs::read_to_string(root.join("packaging/linux/gmcd.service")).unwrap();
        for unit in [systemd_unit(Path::new("/x/gmcd")), packaged] {
            for key in [
                "Nice=",
                "CPUSchedulingPolicy=",
                "IOSchedulingClass=",
                "CPUWeight=",
                "CPUQuota=",
            ] {
                assert!(!unit.contains(key), "{key} would slow lent tasks:\n{unit}");
            }
        }
    }

    #[test]
    fn login_items_use_homebrews_lasting_path() {
        let p = Path::new(
            "/opt/homebrew/Cellar/gimmecores/HEAD-a965edc/GimmeCores.app/Contents/MacOS/gmcd",
        );
        assert_eq!(
            lasting_path(p),
            Path::new("/opt/homebrew/opt/gimmecores/GimmeCores.app/Contents/MacOS/gmcd")
        );
        let q = Path::new("/Applications/GimmeCores.app/Contents/MacOS/gmcd");
        assert_eq!(lasting_path(q), q);
        assert_eq!(
            lasting_path(Path::new("/x/Cellar/y")),
            Path::new("/x/Cellar/y")
        );
    }

    #[test]
    fn the_systemd_unit_quotes_the_path_and_restarts_on_failure() {
        let u = systemd_unit(Path::new("/opt/Gimme Cores/100%/gmcd"));
        assert!(
            u.contains("ExecStart=\"/opt/Gimme Cores/100%%/gmcd\""),
            "{u}"
        );
        assert!(u.contains("Restart=on-failure"));
        assert!(u.contains("WantedBy=default.target"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_accepts_the_launch_agent_file() {
        let dir = std::env::temp_dir().join(format!("gmc-plist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("agent.plist");
        std::fs::write(&f, launch_agent_plist(Path::new("/x/gmcd"), &dir)).unwrap();
        let ok = std::process::Command::new("plutil")
            .arg("-lint")
            .arg(&f)
            .status()
            .unwrap()
            .success();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(ok);
    }
}
