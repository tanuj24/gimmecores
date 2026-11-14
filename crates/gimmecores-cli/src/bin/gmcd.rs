// Windows: a windowed program, so starting it at login opens no console window (its output
// goes to the terminal that started it, or to gmcd.log: see `daemon_main`).
#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() -> std::process::ExitCode {
    gimmecores_cli::daemon_main()
}
