//! Pre-upload secret scan (threat model I7, second half).
//!
//! File-name excludes already keep `.env`, keys and credential files out. This scan looks
//! *inside* the files about to be sent for high-confidence secret formats, so a token pasted
//! into an ordinary file is caught too. Matches block the upload unless the user explicitly
//! allows that file. Patterns are deliberately specific to keep false alarms rare.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

/// Files larger than this are not scanned (secrets live in small text files).
pub const MAX_SCAN_BYTES: u64 = 2 << 20;

static PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    [
        (
            "private key",
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
        ),
        ("AWS access key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        (
            "GitHub token",
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b",
        ),
        ("GitLab token", r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
        ("Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
        ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
        ("Stripe live key", r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b"),
        ("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        (
            "OpenAI API key",
            r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b",
        ),
        ("Hugging Face token", r"\bhf_[A-Za-z0-9]{34,}\b"),
        ("npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
        ("PyPI token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b"),
    ]
    .into_iter()
    .filter_map(|(name, re)| Regex::new(re).ok().map(|r| (name, r)))
    .collect()
});

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// Path relative to the project root.
    pub path: PathBuf,
    pub line: usize,
    pub kind: &'static str,
}

/// Scans one file's text. Binary or oversized content is skipped.
pub fn scan_text(rel: &Path, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        for (kind, re) in PATTERNS.iter() {
            if re.is_match(line) {
                out.push(Finding {
                    path: rel.to_path_buf(),
                    line: i + 1,
                    kind,
                });
            }
        }
    }
    out
}

/// Scans the given files (absolute path, path relative to `root`).
pub fn scan_files<'a>(files: impl Iterator<Item = (&'a Path, &'a Path)>) -> Vec<Finding> {
    let mut out = Vec::new();
    for (abs, rel) in files {
        let Ok(meta) = std::fs::metadata(abs) else {
            continue;
        };
        if meta.len() > MAX_SCAN_BYTES {
            continue;
        }
        let Ok(bytes) = std::fs::read(abs) else {
            continue;
        };
        if bytes.contains(&0) {
            continue; // binary
        }
        out.extend(scan_text(rel, &String::from_utf8_lossy(&bytes)));
    }
    out
}

/// Human-readable refusal message.
pub fn describe(findings: &[Finding]) -> String {
    let mut s = String::from("possible secrets found; nothing was sent:\n");
    for f in findings.iter().take(20) {
        s.push_str(&format!("  {}:{}  {}\n", f.path.display(), f.line, f.kind));
    }
    if findings.len() > 20 {
        s.push_str(&format!("  … and {} more\n", findings.len() - 20));
    }
    s.push_str(
        "Remove them, list the files in .gmcignore, or allow a file explicitly with --allow-secret <path>.",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<&'static str> {
        scan_text(Path::new("f"), text)
            .into_iter()
            .map(|f| f.kind)
            .collect()
    }

    #[test]
    fn detects_common_secret_formats() {
        // Fixture strings are assembled at runtime so this file itself does not look like it
        // contains secrets.
        let gh = format!("token = \"ghp_{}\"", "a".repeat(36));
        let aws = format!("key={}{}", "AKIA", "ABCDEFGHIJKLMNOP");
        let pem = format!("-----BEGIN {}PRIVATE KEY-----", "OPENSSH ");
        let stripe = format!("{}{}", "sk_live_", "x".repeat(24));
        let anthropic = format!("{}{}", "sk-ant-", "y".repeat(30));
        assert_eq!(kinds(&gh), ["GitHub token"]);
        assert_eq!(kinds(&aws), ["AWS access key"]);
        assert_eq!(kinds(&pem), ["private key"]);
        assert_eq!(kinds(&stripe), ["Stripe live key"]);
        assert_eq!(kinds(&anthropic), ["Anthropic API key"]);
    }

    #[test]
    fn ordinary_code_is_not_flagged() {
        for text in [
            "fn main() { println!(\"hello\"); }",
            "API_KEY = os.environ[\"API_KEY\"]",
            "-----BEGIN PUBLIC KEY-----",
            "sk_test_short",
            "the AKIA prefix alone",
            "ghp_tooshort",
        ] {
            assert!(kinds(text).is_empty(), "false alarm on {text:?}");
        }
    }

    #[test]
    fn findings_report_line_numbers() {
        let text = format!("a\nb\n{}{}\n", "AKIA", "ABCDEFGHIJKLMNOP");
        let f = scan_text(Path::new("config/app.py"), &text);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].line, 3);
        assert!(describe(&f).contains("config/app.py:3"));
    }
}
