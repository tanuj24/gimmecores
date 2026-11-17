//! Keeps the lender awake while tasks from other devices run (#30).
//!
//! A lender that goes to idle sleep mid-task stalls or loses it. While at least one lent task
//! runs, and lending is not paused, the service holds off idle sleep with the system's own
//! tool, run as a child process that ends with the service:
//!
//! - macOS: `caffeinate -i -w <this pid>` (prevents idle system sleep; exits when gmcd does).
//! - Linux: `systemd-inhibit --what=idle:sleep --mode=block ... tail --pid=<this pid> -f
//!   /dev/null` (released when gmcd ends, or when the child is stopped).
//!
//! Nothing is held while no task runs or while laptop protections pause lending. The owner can
//! turn it off (`gmc keep-awake off`, Settings); turning it back on is like loosening a laptop
//! protection, so it needs presence. Closing a laptop's lid still sleeps it: no tool here can
//! prevent that, and the docs say so.

use std::process::{Child, Command, Stdio};

use crate::node::{Node, PresenceRefused};

impl Node {
    /// The owner's choice: hold off idle sleep while tasks from other devices run.
    pub fn keep_awake(&self) -> bool {
        self.state().keep_awake
    }

    /// Whether this computer is being kept awake right now.
    pub fn keeping_awake(&self) -> bool {
        self.inner
            .awake
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .holding()
    }

    /// Changes the choice (saved, audited). Turning it on is like loosening a laptop
    /// protection, so it needs presence; turning it off never does.
    pub async fn set_keep_awake(&self, enabled: bool) -> Result<(), PresenceRefused> {
        if enabled && !self.keep_awake() {
            self.require_presence("keep this computer awake while tasks from other devices run")
                .await?;
        }
        {
            let mut s = self.state();
            s.keep_awake = enabled;
            self.save_settings(&s)
                .map_err(|e| PresenceRefused::Unavailable(format!("{e:#}")))?;
        }
        self.keep_awake_tick();
        self.audit_best_effort(
            "lending",
            None,
            if enabled {
                "this computer stays awake while tasks from other devices run".to_string()
            } else {
                "this computer may sleep while tasks from other devices run".to_string()
            },
            serde_json::json!({ "keep_awake": enabled }),
        );
        Ok(())
    }

    /// Starts or stops holding off sleep to match what runs now (every 2 s, and on changes).
    pub(crate) fn keep_awake_tick(&self) {
        let want = {
            let s = self.state();
            wanted(s.keep_awake, s.running.len(), s.paused.is_some())
        };
        self.inner
            .awake
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .set(want);
    }
}

/// Whether to hold off sleep now.
pub fn wanted(enabled: bool, running_tasks: usize, paused: bool) -> bool {
    enabled && running_tasks > 0 && !paused
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn held_only_while_tasks_run_unpaused_and_the_owner_allows_it() {
        assert!(wanted(true, 1, false));
        assert!(!wanted(true, 0, false));
        assert!(!wanted(true, 2, true), "paused for battery or heat");
        assert!(!wanted(false, 2, false), "turned off by the owner");
    }
}

/// The command that holds off idle sleep until it is stopped or `pid` ends, if this system
/// has one.
pub fn command(pid: u32) -> Option<Command> {
    if cfg!(target_os = "macos") {
        let mut c = Command::new("/usr/bin/caffeinate");
        c.args(["-i", "-w", &pid.to_string()]);
        Some(c)
    } else if cfg!(target_os = "linux") {
        let tool = ["/usr/bin/systemd-inhibit", "/bin/systemd-inhibit"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists())?;
        let mut c = Command::new(tool);
        c.args([
            "--what=idle:sleep",
            "--who=GimmeCores",
            "--why=Tasks from other devices are running",
            "--mode=block",
            "tail",
            &format!("--pid={pid}"),
            "-f",
            "/dev/null",
        ]);
        Some(c)
    } else {
        None
    }
}

/// The child holding the system awake, while there is one.
#[derive(Default)]
pub struct Holder {
    child: Option<Child>,
    /// The tool ended by itself (no session for systemd-inhibit, say): not started again until
    /// holding is no longer wanted, so it is tried once per stretch of tasks, not every 2 s.
    gave_up: bool,
}

impl Holder {
    /// Starts or stops holding, as `want` says. Returns whether it now holds.
    pub fn set(&mut self, want: bool) -> bool {
        // A child that ended by itself (tool refused, killed) is forgotten, and not retried.
        if let Some(c) = &mut self.child
            && !matches!(c.try_wait(), Ok(None))
        {
            self.child = None;
            self.gave_up = true;
            tracing::warn!("the tool keeping this computer awake stopped by itself");
        }
        if !want {
            self.gave_up = false;
        }
        match (want, self.child.is_some()) {
            (true, false) if !self.gave_up => {
                self.child = command(std::process::id()).and_then(|mut c| {
                    // Its own process group: stopping it also stops what it started (Linux:
                    // systemd-inhibit's `tail`).
                    #[cfg(unix)]
                    std::os::unix::process::CommandExt::process_group(&mut c, 0);
                    c.stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .ok()
                });
                self.gave_up = self.child.is_none();
            }
            (false, true) => self.release(),
            _ => {}
        }
        self.child.is_some()
    }

    pub fn release(&mut self) {
        if let Some(mut c) = self.child.take() {
            #[cfg(unix)]
            let _ = Command::new("kill")
                .args(["-TERM", "--", &format!("-{}", c.id())])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// Whether it holds the system awake now.
    pub fn holding(&self) -> bool {
        self.child.is_some()
    }
}

impl Drop for Holder {
    fn drop(&mut self) {
        self.release();
    }
}
