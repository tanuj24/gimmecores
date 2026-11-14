# Windows

Status: **in progress**. `gmc` and `gmcd` build for Windows and run on Windows 11 (ARM64, in a
test VM); the local API and private files are tested there (`scripts/windows/test-windows.sh`). Nothing ships for Windows until every row below is "built" and tested on
Windows itself, or the feature it protects is refused there.

## Rule

No protection becomes a no-op on Windows. Each one has a Windows implementation, or `gmcd`
refuses the feature it protects (not just a hidden button). A compiled fallback that does
nothing is a bug.

## Protections

| Protection (threat model) | macOS / Linux | Windows | Status |
|---|---|---|---|
| Local API reachable only by this user (I10, I13) | Unix sockets, mode 0600, in an owner-only folder | Named pipes: an access list allowing only this user, remote clients refused, created only if the name is free (a random name per start, kept in an owner-only file), and the client checks the server runs as the same user before sending anything | Built; tested on Windows (`scripts/windows/test-windows.sh`): another account cannot open the pipe, and `gmc` sends nothing to a pipe another account serves |
| Secrets readable only by this user (identity key, trust list, grants, audit log) | Mode 0600/0700; a file readable by group/others is refused | Protected access list (this user and SYSTEM); a file any other account may read is refused | Built; tested on Windows: every file `gmcd` writes is owner-only, and a key others may read stops it |
| A device's identity stays on the device | Platform data folder | `%LOCALAPPDATA%\GimmeCores` (not the roaming profile) | Built |
| File names from another device are safe to write (I8) | Separators, `.`/`..`, control characters, trailing dot/space, reserved names, case-only duplicates refused | The same rules, plus `:` (drives, alternate data streams), `<>"|?*`, `CONIN$`/`CONOUT$`, superscript COM/LPT, `NUL .txt`; applied on every platform | Built |
| Approvals need the owner present (I13) | Touch ID / password (macOS), polkit (Linux) | Windows Hello (PIN, face, fingerprint) | Planned. Until then presence is "unavailable" and approvals are refused (fail closed); `gmcd --no-presence` stays the only override |
| Stopping a task stops everything it started | Containers: `docker kill`; sandbox: the process group | Containers: `docker kill` (the same) | Built (containers are Windows' only runtime; "as you" is refused on every platform, the test-only process runner never ships) |
| Pausing tasks (laptop protections) | `docker pause`; SIGSTOP/SIGCONT for the sandbox | `docker pause` | Built (containers), to test on a real Windows PC |
| Laptop protections (battery, idle, heat) | pmset/ioreg, `/sys` | Battery: `GetSystemPowerStatus`; idle: `GetLastInputInfo` (in the owner's session); heat: no Windows source | Battery and idle built, tested on Windows. Heat: unknown, never pauses; the app shows "When hot" unticked and "(not measured here)", `gmc status` says "heat not measured on Windows" |
| Tasks isolated from the owner's files | Seatbelt (macOS), bubblewrap (Linux), containers | Containers (Docker Desktop, WSL 2). No OS sandbox runtime | Sandbox refused on Windows; containers to test on a real Windows PC (this Mac's VM cannot run Docker) |
| Background service starts at login, in the owner's session | launchd LaunchAgent, systemd user unit | This user's Run key (`HKCU\...\Run`, no administrator needed) starts `gmcd.exe`, a windowed program (no console window), in the owner's session; output to `gmcd.log` in its owner-only home; one `gmcd` per user | Built; tested on Windows (start, a second one exits, stop removes the entry and stops it) |
| Usage figures | `ps`, `/proc` (sandbox); containers not measured yet | Containers not measured yet, as elsewhere | Same as macOS/Linux containers |
| Identity key in the OS key store (opt-in) | macOS Keychain | Windows Credential Manager or DPAPI | Later; the owner-only file is used |

## Packaging

`packaging/windows/build-installer.sh` builds `GimmeCores-<version>-x64-setup.exe` on a Mac or
Linux (MinGW and NSIS in Docker). Tested on Windows 11 (ARM64, through x64 emulation):
- Installs into Program Files (one administrator prompt): the app `GimmeCores.exe`, `gmcd.exe`
  and `WebView2Loader.dll` side by side, the commands `gmc` and `gimmecores` in `bin\` on the
  PATH (Windows names ignore case: `gimmecores.exe` would overwrite `GimmeCores.exe` in one
  folder), a Start menu entry for every user, an Apps & features entry.
- Firewall: `gmcd` may accept connections on private and work networks; an explicit rule
  refuses public networks, so Windows never asks and lending cannot be reached there.
- The app is never started as administrator. Uninstalling stops GimmeCores and removes the
  files, Start menu entry, firewall rules, PATH entry, Apps & features entry and the sign-in
  entry, and keeps `%LOCALAPPDATA%\GimmeCores` (identity, paired devices, settings).
- Unsigned: SmartScreen asks once. No in-app updates on Windows yet (install the new version
  over the old one).

Seen on Windows 11 (ARM64, x64 build): the desktop app runs on Windows' WebView2 and shows the
daemon's state. Builds made with the MinGW toolchain need Microsoft's `WebView2Loader.dll` (signed,
redistributable) next to the app; Microsoft's own toolchain links it in. To do before a release:

The desktop app (Tauri, WebView2) and `gmc`/`gmcd` in an installer for x64 and ARM64. Unsigned
at first: SmartScreen shows "Windows protected your PC" until the user chooses More info > Run
anyway (like the macOS Open Anyway step). The in-app updater is macOS-only for now.

## Testing

- Compile: `scripts/ci/Dockerfile.windows` cross-compiles the workspace on a Mac (mingw-w64, no
  Microsoft SDK licence).
- Behaviour: a Windows 11 Pro (ARM64) VM in UTM, installed unattended (local administrator,
  User Account Control on), reached over SSH with a key used only for it. Pairing and borrowing
  are tested between the VM and the Mac.
- Not testable on this Mac: Docker inside Windows (nested virtualization needs an M3 or newer).
  Lending through containers is tested on a real Windows PC before it ships.
