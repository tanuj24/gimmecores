//! Running `gmcd` in the background (macOS LaunchAgent), and putting `gmc` on the PATH.
//! Everything here happens only when the user clicks for it.

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
    /// `gmc` is on the PATH (linked in /usr/local/bin).
    pub cli_installed: bool,
}

/// `gmcd` and `gmc` ship next to the app's own executable (Contents/MacOS).
pub fn bundled_binary(name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let p = exe.parent()?.join(name);
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

/// The LaunchAgent: start `gmcd` at login, restart it if it crashes (not after a clean stop),
/// log to ~/Library/Logs/GimmeCores.
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
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>{out}</string>
  <key>StandardErrorPath</key><string>{out}</string>
</dict>
</plist>
"#
    )
}

fn uid() -> Result<String> {
    let o = std::process::Command::new("id").arg("-u").output()?;
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
}

pub fn state() -> ServiceState {
    ServiceState {
        start_at_login: plist_path().is_ok_and(|p| p.exists()),
        bundled: bundled_binary("gmcd").is_some(),
        cli_installed: std::fs::read_link("/usr/local/bin/gmc").is_ok(),
    }
}

/// Installs the LaunchAgent and starts `gmcd` now.
pub fn start_at_login() -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("on Linux, use packaging/linux/install.sh (a systemd user service)");
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
    // Replace any previous registration (the app may have moved).
    let _ = std::process::Command::new("launchctl")
        .args(["bootout", &format!("gui/{}/{LABEL}", uid()?)])
        .output();
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
    let _ = std::process::Command::new("launchctl")
        .args(["bootout", &format!("gui/{}/{LABEL}", uid()?)])
        .output();
    let plist = plist_path()?;
    if plist.exists() {
        std::fs::remove_file(plist)?;
    }
    Ok(())
}

/// Links `gmc` and `gimmecores` into /usr/local/bin (macOS asks for an administrator).
pub fn install_cli() -> Result<()> {
    let gmc = bundled_binary("gmc").context("gmc was not found next to the app")?;
    let full = bundled_binary("gimmecores").unwrap_or_else(|| gmc.clone());
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
