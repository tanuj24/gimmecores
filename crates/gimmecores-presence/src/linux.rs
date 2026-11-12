//! Linux: polkit. `pkcheck` asks the session's authentication agent to confirm the action
//! `dev.gimmecores.consent` for this process. The policy shipped in
//! `packaging/linux/dev.gimmecores.policy` requires the user's own password every time.

use tokio::process::Command;

use crate::Outcome;

pub(crate) const ACTION: &str = "dev.gimmecores.consent";

pub(crate) async fn verify(_reason: &str) -> Outcome {
    // polkit shows the message from the installed policy; it cannot show a per-request reason.
    let out = Command::new("pkcheck")
        .args([
            "--action-id",
            ACTION,
            "--process",
            &std::process::id().to_string(),
            "--allow-user-interaction",
        ])
        .kill_on_drop(true)
        .output()
        .await;
    let out = match out {
        Ok(o) => o,
        Err(e) => return Outcome::Unavailable(format!("polkit (pkcheck) is not available: {e}")),
    };
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    classify(out.status.code(), &stderr)
}

/// Exit codes from pkcheck(1).
pub(crate) fn classify(code: Option<i32>, stderr: &str) -> Outcome {
    match code {
        Some(0) => Outcome::Verified,
        Some(1) => Outcome::Denied("not authorized".into()),
        Some(3) => Outcome::Denied("cancelled".into()),
        Some(2) => Outcome::Unavailable(format!(
            "no polkit authentication agent in this session ({stderr})"
        )),
        _ if stderr.contains("does not exist") || stderr.contains("not registered") => {
            Outcome::Unavailable(format!(
                "the GimmeCores polkit policy is not installed ({ACTION}); see packaging/linux"
            ))
        }
        _ => Outcome::Unavailable(format!("polkit check failed: {stderr}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcheck_exit_codes() {
        assert_eq!(classify(Some(0), ""), Outcome::Verified);
        assert!(matches!(classify(Some(1), ""), Outcome::Denied(_)));
        assert!(matches!(classify(Some(3), ""), Outcome::Denied(_)));
        assert!(matches!(classify(Some(2), ""), Outcome::Unavailable(_)));
        assert!(matches!(
            classify(Some(127), "Action dev.gimmecores.consent is not registered"),
            Outcome::Unavailable(m) if m.contains("not installed")
        ));
    }
}
