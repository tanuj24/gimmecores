// Which commit a build came from, for `--version`, `gmc status` and the app's Settings (#18).
// Shared by crates/gimmecores-cli/build.rs and apps/desktop/build.rs (`include!`).
//
// Sets GMC_VERSION_SUFFIX to " (<commit> <commit date>)", e.g. " (943d37b 2026-11-16)", or to
// "" when the source is not a git checkout of this repository (a source tarball). The commit's
// own date is used, not the build time, so one commit always builds the same binaries.

fn emit_build_info() {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    let here = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let git = |args: &[&str]| -> Option<String> {
        let out = Command::new("git")
            .args(args)
            .current_dir(&here)
            .output()
            .ok()
            .filter(|o| o.status.success())?;
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!s.is_empty()).then_some(s)
    };
    // Only this repository's own checkout: a tarball unpacked inside some other git repository
    // must not report that repository's commit.
    let ours = |top: &str| {
        let top = Path::new(top).canonicalize().ok();
        let mine = here
            .ancestors()
            .find(|d| d.join("spec/proto/gimmecores").is_dir())
            .and_then(|d| d.canonicalize().ok());
        top.is_some() && top == mine
    };
    let commit = git(&["rev-parse", "--show-toplevel"])
        .filter(|top| ours(top))
        .and_then(|_| {
            for f in ["HEAD", "packed-refs"] {
                if let Some(p) = git(&["rev-parse", "--git-path", f]) {
                    println!("cargo:rerun-if-changed={}", here.join(p).display());
                }
            }
            if let Some(r) = git(&["symbolic-ref", "-q", "HEAD"])
                && let Some(p) = git(&["rev-parse", "--git-path", &r])
            {
                println!("cargo:rerun-if-changed={}", here.join(p).display());
            }
            Some((
                git(&["rev-parse", "--short=7", "HEAD"])?,
                git(&["show", "-s", "--format=%cs", "HEAD"])?,
            ))
        });
    let suffix = commit.map_or(String::new(), |(c, d)| format!(" ({c} {d})"));
    println!("cargo:rustc-env=GMC_VERSION_SUFFIX={suffix}");
    println!("cargo:rerun-if-changed=build.rs");
}
