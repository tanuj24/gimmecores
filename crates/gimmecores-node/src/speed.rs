//! How lent tasks are scheduled against the lender's own apps (docs/design/task-speed.md).
//!
//! The lender's owner chooses a level (default: their apps first). A grant may name a level,
//! fixed when the owner approved it; a grant that names none follows the owner's setting when
//! each task starts, so lowering the setting applies at once. A task may ask for a slower
//! level than its grant's, never a faster one. The lender decides the level itself; a level a
//! task could undo is not offered (the sandbox refuses `setpriority`, checked by tests).

use gimmecores_core::Speed;

use crate::node::{Node, PresenceRefused};

/// The level a task runs at: its grant's (or, when the grant names none, the owner's setting
/// now), lowered to what the task asked for.
pub fn effective(grant: Option<Speed>, setting: Speed, asked: Option<Speed>) -> Speed {
    let base = grant.unwrap_or(setting);
    asked.map_or(base, |a| base.slower(a))
}

/// What the owner reads (also in prompts: "… let tasks run at full speed").
pub fn describe(s: Speed) -> &'static str {
    match s {
        Speed::Full => "full speed (like your own apps)",
        Speed::AppsFirst => "your apps first",
        Speed::Background => "background (idle time only)",
    }
}

impl Node {
    /// The owner's level for grants that name none.
    pub fn task_speed(&self) -> Speed {
        self.state().task_speed
    }

    /// Changes the owner's level (saved, audited). A faster one needs presence, as loosening
    /// any lending protection does; a slower one never does.
    pub async fn set_task_speed(&self, speed: Speed) -> Result<(), PresenceRefused> {
        let before = self.task_speed();
        if speed > before {
            self.require_presence(&format!(
                "let tasks from other devices run at {}",
                describe(speed)
            ))
            .await?;
        }
        {
            let mut s = self.state();
            s.task_speed = speed;
            self.save_settings(&s)
                .map_err(|e| PresenceRefused::Unavailable(format!("{e:#}")))?;
        }
        self.audit_best_effort(
            "lending",
            None,
            format!("tasks from other devices now run at {}", describe(speed)),
            serde_json::json!({ "task_speed": speed.name(), "was": before.name() }),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Speed::{AppsFirst as A, Background as B, Full as F};

    #[test]
    fn the_slowest_of_grant_or_setting_and_ask() {
        for (grant, setting, asked, want) in [
            // A grant naming no level follows the setting, whatever it is now.
            (None, A, None, A),
            (None, F, None, F),
            (None, B, None, B),
            // A named level is what the owner approved, even above the setting now.
            (Some(F), A, None, F),
            (Some(A), F, None, A),
            // A task may ask for less, never more.
            (Some(F), A, Some(B), B),
            (Some(A), F, Some(F), A),
            (None, A, Some(F), A),
            (None, F, Some(A), A),
            (Some(B), F, Some(F), B),
        ] {
            assert_eq!(
                effective(grant, setting, asked),
                want,
                "{grant:?} {setting:?} {asked:?}"
            );
        }
    }
}
