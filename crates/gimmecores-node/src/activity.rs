//! What runs, shown safely: the text rules for commands, labels and image names that come from
//! another device (docs/design/activity.md, section 3.6).
//!
//! Command text is untrusted and may carry a secret typed on a command line. Every argument is
//! shown on its own (boundaries kept), control and invisible characters are escaped (never
//! deleted, so two words never merge), each is cut to a fixed length, and likely secrets are
//! hidden first. Hiding is a heuristic: screens say so.

/// Arguments shown per command.
pub const SHOWN_ARGS: usize = 12;
/// Characters shown per argument or label.
pub const SHOWN_CHARS: usize = 64;
/// What replaces a likely secret.
pub const HIDDEN: &str = "[hidden: looks like a secret]";

/// Characters that change how text reads without being seen: escaped, never shown raw.
fn invisible(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x061C | 0x180E
        | 0x200B..=0x200F
        | 0x2028..=0x202E
        | 0x2060..=0x206F
        | 0xFEFF
        | 0xFFF9..=0xFFFB
        | 0xE0000..=0xE007F)
}

/// One argument (or label) as it may be shown: escaped and cut to `max` characters.
pub fn escape(raw: &str, max: usize) -> String {
    let mut out = String::new();
    let mut shown = 0usize;
    for c in raw.chars() {
        let piece = match c {
            '\\' => "\\\\".to_string(),
            '\n' => "\\n".to_string(),
            '\t' => "\\t".to_string(),
            '\r' => "\\r".to_string(),
            '\u{1b}' => "\\e".to_string(),
            c if c.is_control() => format!("\\x{{{:02X}}}", c as u32),
            c if invisible(c) => format!("\\u{{{:04X}}}", c as u32),
            c => c.to_string(),
        };
        let n = piece.chars().count();
        if shown + n > max {
            out.push('…');
            return out;
        }
        out.push_str(&piece);
        shown += n;
    }
    out
}

/// An argument as shown: escaped, at most [`SHOWN_CHARS`] characters.
pub fn show_arg(raw: &str) -> String {
    escape(raw, SHOWN_CHARS)
}

/// A label chosen by the other device (an SDK function name): escaped and cut; anything over
/// 256 bytes is treated as no label.
pub fn show_label(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 256 {
        return None;
    }
    Some(escape(raw, SHOWN_CHARS))
}

/// Words that mark an option or variable as holding a secret, compared with whole parts of
/// its name (split on `-`, `_` and `.`), so `--max_tokens` and `--author` are not hidden.
const SECRET_PARTS: [&str; 7] = [
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "credentials",
    "bearer",
];

fn secret_name(name: &str) -> bool {
    let parts: Vec<String> = name
        .trim_start_matches('-')
        .split(['-', '_', '.'])
        .filter(|p| !p.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    if parts
        .iter()
        .any(|p| SECRET_PARTS.contains(&p.as_str()) || p == "apikey")
    {
        return true;
    }
    parts.windows(2).any(|w| {
        matches!(
            (w[0].as_str(), w[1].as_str()),
            ("api", "key") | ("access", "key") | ("private", "key")
        )
    })
}

/// The arguments with likely secrets replaced by [`HIDDEN`]: a known token shape anywhere in
/// an argument, the value of `--name=value` or `NAME=value` and the argument after a bare
/// `--name` when the name says it holds a secret. Only the first [`SHOWN_ARGS`] arguments are
/// looked at (the rest are never shown).
pub fn mask_args(argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len().min(SHOWN_ARGS));
    let mut hide_next = false;
    for a in argv.iter().take(SHOWN_ARGS) {
        let head: String = a.chars().take(4096).collect();
        if hide_next {
            hide_next = false;
            out.push(HIDDEN.to_string());
            continue;
        }
        if !crate::secrets::scan_text(std::path::Path::new("argv"), &head).is_empty() {
            out.push(HIDDEN.to_string());
            continue;
        }
        if let Some((name, _)) = head.split_once('=')
            && !name.is_empty()
            && !name.contains(char::is_whitespace)
            && secret_name(name)
        {
            out.push(format!("{name}={HIDDEN}"));
            continue;
        }
        if head.starts_with('-') && !head.contains('=') && secret_name(&head) {
            hide_next = true;
        }
        out.push(a.clone());
    }
    out
}

/// A command as shown: likely secrets hidden, each argument escaped and cut; also how many
/// arguments there were and whether any was cut or left out.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShownCommand {
    pub args: Vec<String>,
    pub total: usize,
    pub hidden: usize,
    pub cut: bool,
}

pub fn show_command(argv: &[String]) -> ShownCommand {
    let masked = mask_args(argv);
    let hidden = masked.iter().filter(|a| a.contains(HIDDEN)).count();
    let mut cut = argv.len() > SHOWN_ARGS;
    let args = masked
        .iter()
        .map(|a| {
            if a.contains(HIDDEN) {
                return a.clone();
            }
            let s = show_arg(a);
            cut |= s.ends_with('…') && !a.ends_with('…');
            s
        })
        .collect();
    ShownCommand {
        args,
        total: argv.len(),
        hidden,
        cut,
    }
}

/// A container image reference is refused, not cleaned: a cleaned name would be a different
/// image. At most 255 bytes of `[A-Za-z0-9._/:@-]`, starting with a letter or digit.
pub fn validate_image(reference: &str) -> anyhow::Result<()> {
    let ok = !reference.is_empty()
        && reference.len() <= 255
        && reference
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && reference
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._/:@-".contains(c));
    anyhow::ensure!(ok, "not a valid container image name");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn arguments_keep_boundaries_and_escape_controls() {
        let c = show_command(&v(&[
            "sh",
            "-c",
            "echo a b",
            "x\ny",
            "e\u{1b}[31m",
            "a\u{202e}b",
        ]));
        assert_eq!(
            c.args,
            ["sh", "-c", "echo a b", "x\\ny", "e\\e[31m", "a\\u{202E}b"]
        );
        assert_eq!(c.total, 6);
        assert!(!c.cut && c.hidden == 0);
        // Nothing is deleted: escapes are visible and words never merge.
        assert_eq!(show_arg("a\u{200b}b"), "a\\u{200B}b");
        assert_eq!(show_arg("a\\b"), "a\\\\b");
        assert_eq!(show_arg("\u{7}"), "\\x{07}");
    }

    #[test]
    fn long_arguments_and_commands_are_cut() {
        let long = "x".repeat(200);
        let shown = show_arg(&long);
        assert_eq!(shown.chars().count(), SHOWN_CHARS + 1);
        assert!(shown.ends_with('…'));
        let many: Vec<String> = (0..40).map(|i| format!("a{i}")).collect();
        let c = show_command(&many);
        assert_eq!(c.args.len(), SHOWN_ARGS);
        assert_eq!(c.total, 40);
        assert!(c.cut);
        // An escape is never split by the cut.
        let near = format!("{}\n", "y".repeat(SHOWN_CHARS - 1));
        assert!(show_arg(&near).ends_with('…'));
        assert!(!show_arg(&near).contains("\\n"));
    }

    #[test]
    fn likely_secrets_are_hidden_but_ordinary_flags_are_not() {
        let key = format!("{}{}", "AKIA", "ABCDEFGHIJKLMNOP");
        let ghp = format!("{}{}", "ghp_", "a".repeat(36));
        let c = show_command(&v(&[
            "deploy",
            "--token=s3cr3t-value",
            "--api-key",
            "plainvalue",
            "API_KEY=abc",
            &key,
            &format!("https://x:{ghp}@example.com"),
            "--max_tokens=512",
            "--tokenizer",
            "bert",
            "--author=Ada",
            "/very/long/path/to/some/file/that/is/not/a/secret/at/all.txt",
        ]));
        assert_eq!(c.args[0], "deploy");
        assert_eq!(c.args[1], format!("--token={HIDDEN}"));
        assert_eq!(c.args[2], "--api-key");
        assert_eq!(c.args[3], HIDDEN);
        assert_eq!(c.args[4], format!("API_KEY={HIDDEN}"));
        assert_eq!(c.args[5], HIDDEN);
        assert_eq!(c.args[6], HIDDEN);
        assert_eq!(c.args[7], "--max_tokens=512");
        assert_eq!(c.args[8], "--tokenizer");
        assert_eq!(c.args[9], "bert");
        assert_eq!(c.args[10], "--author=Ada");
        assert!(c.args[11].starts_with("/very/long/path"));
        assert_eq!(c.hidden, 5);
    }

    #[test]
    fn labels_are_escaped_or_absent() {
        assert_eq!(show_label("square"), Some("square".into()));
        assert_eq!(show_label("  "), None);
        assert_eq!(show_label(&"x".repeat(300)), None);
        assert_eq!(show_label("a\u{202e}b").as_deref(), Some("a\\u{202E}b"));
    }

    #[test]
    fn image_names_are_validated() {
        for ok in ["python:3.12-slim", "ghcr.io/x/y@sha256:abc", "alpine"] {
            validate_image(ok).unwrap();
        }
        let long = "a".repeat(256);
        for bad in ["", ":x", "a b", "a\u{202e}b", "a;rm", long.as_str(), "-x"] {
            assert!(validate_image(bad).is_err(), "{bad:?}");
        }
    }
}
