//! Which tools this computer has, for borrowers whose tasks would use them (#28).
//!
//! The sandbox runtime uses the lender's installed tools, so a borrower (or an agent) found out
//! that `node` was missing, or that `python3` was another version, only when its task failed.
//! The lender probes a fixed list of tools for their versions at start and every 10 minutes,
//! and puts them in the grants it signs (`Grant.tools`), only when the grant covers its
//! sandbox (a holder can then run `node --version` there anyway; a container sees the
//! image's tools, not these) and only while the owner shares them (default on; `gmc
//! share-tools`). On macOS, Apple's placeholder `python3`, `git`, `make` and friends open an
//! "install the command line tools" dialog when run; they are probed only once the tools are
//! installed, and `java` only once a Java is.

use std::path::{Path, PathBuf};
use std::time::Duration;

use gimmecores_core::GrantTerms;
use gimmecores_proto::peer::v1 as pb;

use crate::node::{Node, PresenceRefused};

impl Node {
    /// Whether grants covering the sandbox list this computer's tools.
    pub fn share_tools(&self) -> bool {
        self.state().share_tools
    }

    /// This computer's tools, as last probed.
    pub fn tools(&self) -> Vec<(String, String)> {
        self.state().tools.clone()
    }

    /// The tools a grant with `terms` lists: only when it covers the sandbox and the owner
    /// shares them.
    pub(crate) fn tools_for(&self, terms: &GrantTerms) -> Vec<pb::ToolVersion> {
        let s = self.state();
        if s.share_tools && terms.modes.sandbox {
            to_proto(&s.tools)
        } else {
            Vec::new()
        }
    }

    /// Changes the choice (saved, audited). Turning it on needs presence, as sharing anything
    /// more does; turning it off never does.
    pub async fn set_share_tools(&self, enabled: bool) -> Result<(), PresenceRefused> {
        if enabled && !self.share_tools() {
            self.require_presence(
                "let devices you lend your sandbox to see which tools this computer has",
            )
            .await?;
        }
        {
            let mut s = self.state();
            s.share_tools = enabled;
            self.save_settings(&s)
                .map_err(|e| PresenceRefused::Unavailable(format!("{e:#}")))?;
        }
        self.audit_best_effort(
            "lending",
            None,
            if enabled {
                "grants for the sandbox list this computer's tools".to_string()
            } else {
                "grants no longer list this computer's tools".to_string()
            },
            serde_json::json!({ "share_tools": enabled }),
        );
        Ok(())
    }

    /// Test-only: sets the probed tools.
    #[cfg(feature = "insecure-test-executor")]
    pub fn set_tools_for_tests(&self, tools: Vec<(String, String)>) {
        let mut s = self.state();
        s.tools = tools;
        s.tools_fixed = true;
    }
}

/// The tools probed, with the arguments that print their version.
pub const TOOLS: &[(&str, &[&str])] = &[
    ("python3", &["--version"]),
    ("node", &["--version"]),
    ("npm", &["--version"]),
    ("uv", &["--version"]),
    ("cargo", &["--version"]),
    ("rustc", &["--version"]),
    ("go", &["version"]),
    ("java", &["-version"]),
    ("make", &["--version"]),
    ("cmake", &["--version"]),
    ("gcc", &["--version"]),
    ("clang", &["--version"]),
    ("git", &["--version"]),
];

/// At most this long per tool.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// The first version-looking token ("3.13.2", "1.22.4", "v22.11.0" as "22.11.0").
pub fn version_of(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // A version starts after a space or punctuation, or "v" / "go" ("v22.11.0",
        // "go1.23.4"); never inside another number or word.
        let starts = i == 0
            || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'.')
            || matches!(bytes[i - 1], b'v' | b'o');
        if bytes[i].is_ascii_digit() && starts {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            let v = text[start..i].trim_end_matches('.');
            if v.contains('.') && v.len() <= 32 {
                return Some(v.to_string());
            }
        } else {
            i += 1;
        }
    }
    None
}

fn which(tool: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?
        .to_str()?
        .split(':')
        .map(|d| Path::new(d).join(tool))
        .find(|p| p.is_file())
}

/// Apple's placeholders in /usr/bin that open an install dialog when the real tools are missing.
fn would_prompt(path: &Path, tool: &str) -> bool {
    if !cfg!(target_os = "macos") || !path.starts_with("/usr/bin") {
        return false;
    }
    let check = |prog: &str, args: &[&str]| {
        std::process::Command::new(prog)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    match tool {
        "java" => !check("/usr/libexec/java_home", &[]),
        "python3" | "git" | "make" | "gcc" | "clang" => !check("/usr/bin/xcode-select", &["-p"]),
        _ => false,
    }
}

/// This computer's tools and versions, in [`TOOLS`] order; tools not found are left out.
pub async fn probe() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (tool, args) in TOOLS {
        let Some(path) = which(tool) else { continue };
        if would_prompt(&path, tool) {
            continue;
        }
        let run = tokio::process::Command::new(&path)
            .args(*args)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output();
        let Ok(Ok(o)) = tokio::time::timeout(PROBE_TIMEOUT, run).await else {
            continue;
        };
        let text = format!(
            "{}\n{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        if let Some(v) = version_of(text.lines().find(|l| !l.trim().is_empty()).unwrap_or("")) {
            out.push(((*tool).to_string(), v));
        }
    }
    out
}

pub fn to_proto(tools: &[(String, String)]) -> Vec<pb::ToolVersion> {
    tools
        .iter()
        .map(|(n, v)| pb::ToolVersion {
            name: n.clone(),
            version: v.clone(),
        })
        .collect()
}

/// A lender's list as received: known tool names only, versions cleaned.
pub fn from_proto(tools: &[pb::ToolVersion]) -> Vec<(String, String)> {
    tools
        .iter()
        .filter(|t| TOOLS.iter().any(|(n, _)| *n == t.name))
        .filter_map(|t| Some((t.name.clone(), version_of(&t.version)?)))
        .take(TOOLS.len())
        .collect()
}

/// "3.13" from "3.13.2": what usually has to match between two machines.
pub fn major_minor(v: &str) -> String {
    v.split('.').take(2).collect::<Vec<_>>().join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_read_from_the_usual_outputs() {
        for (text, want) in [
            ("Python 3.13.2", "3.13.2"),
            ("v22.11.0", "22.11.0"),
            ("cargo 1.99.0 (abc 2026-10-01)", "1.99.0"),
            ("go version go1.23.4 darwin/arm64", "1.23.4"),
            ("openjdk version \"21.0.5\" 2024-10-15", "21.0.5"),
            ("GNU Make 3.81", "3.81"),
            ("git version 2.39.5 (Apple Git-154)", "2.39.5"),
            ("uv 0.9.2 (Homebrew 2026-01-01)", "0.9.2"),
        ] {
            assert_eq!(version_of(text).as_deref(), Some(want), "{text}");
        }
        assert_eq!(version_of("no version here"), None);
        assert_eq!(version_of("x86_64 7"), None);
        assert_eq!(major_minor("3.13.2"), "3.13");
    }

    #[test]
    fn a_received_list_keeps_known_tools_and_clean_versions() {
        let got = from_proto(&[
            pb::ToolVersion {
                name: "python3".into(),
                version: "3.12.1".into(),
            },
            pb::ToolVersion {
                name: "evil".into(),
                version: "1.0".into(),
            },
            pb::ToolVersion {
                name: "node".into(),
                version: "v22.1.0 <script>".into(),
            },
            // Not a clean version: dropped.
            pb::ToolVersion {
                name: "go".into(),
                version: "\u{1b}[31m1.2.3".into(),
            },
        ]);
        assert_eq!(
            got,
            [
                ("python3".into(), "3.12.1".into()),
                ("node".into(), "22.1.0".into())
            ]
        );
    }
}
