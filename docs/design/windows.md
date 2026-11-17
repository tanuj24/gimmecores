# Windows

Status: **in progress**. **On Windows this version borrows only:** `gmcd` refuses to turn lending
on (`LENDING_UNAVAILABLE` in gimmecores-node), and the app and `gmc status` say so, until lending
through containers is tested on a real Windows PC with Docker Desktop. `gmc` and `gmcd` build for Windows and run on Windows 11 (ARM64, in a
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
| Approvals need the owner present (I13) | Touch ID / password (macOS), polkit (Linux) | Windows Hello (PIN, face, fingerprint) through `UserConsentVerifier`. Where Windows Hello is not set up, the Windows password on the secure screen Windows opens after Ctrl+Alt+Delete (`CredUIPromptForWindowsCredentials` with `CREDUIWIN_SECURE_PROMPT`): other programs cannot see that screen, read its keys or type into it. Windows seals the password; GimmeCores never reads it and hands it to Windows' own sign-in check (`LsaLogonUser`), which must sign in exactly the account `gmcd` runs as. Prompts open only from the owner's visible desktop | Built; tested on Windows 11. Windows Hello with the installed `gmcd`: the PIN approves, Cancel refuses. The password (`scripts/windows/password-approval.sh`, an account with a password and no PIN): the right password approves, through `gmcd` too (`gmc runtimes container`); a wrong one and Cancel are refused; another account's valid password, through the prompt's "Use a different account", is refused (removing the account comparison makes that case approve). A blank password never counts: Windows refuses it outside its sign-in screen, and where that rule ("Limit local account use of blank passwords to console logon only") is off, the password is not offered. Over SSH or as a service (no visible desktop) it refuses at once instead of waiting on a prompt nobody sees. `gmcd --no-presence` remains the only override |
| Stopping a task stops everything it started | Containers: `docker kill`; sandbox: the process group | Containers: `docker kill` (the same) | Built (containers are Windows' only runtime; "as you" is refused on every platform, the test-only process runner never ships) |
| Pausing tasks (laptop protections) | `docker pause`; SIGSTOP/SIGCONT for the sandbox | `docker pause` | Built (containers), to test on a real Windows PC |
| Laptop protections (battery, idle, heat) | pmset/ioreg, `/sys` | Battery: `GetSystemPowerStatus`; idle: `GetLastInputInfo` (in the owner's session); heat: no Windows source | Battery and idle built, tested on Windows. Heat: unknown, never pauses; the app shows "When hot" unticked and "(not measured here)", `gmc status` says "heat not measured on Windows" |
| Tasks isolated from the owner's files | Seatbelt (macOS), bubblewrap (Linux), containers | Containers (Docker Desktop, WSL 2). No OS sandbox runtime | Sandbox refused on Windows; containers to test on a real Windows PC (this Mac's VM cannot run Docker) |
| Background service starts at login, in the owner's session | launchd LaunchAgent, systemd user unit | This user's Run key (`HKCU\...\Run`, no administrator needed) starts `gmcd.exe`, a windowed program (no console window), in the owner's session; output to `gmcd.log` in its owner-only home; one `gmcd` per user | Built; tested on Windows (start, a second one exits, stop removes the entry and stops it) |
| Usage figures | `ps`, `/proc` (sandbox); containers not measured yet | Containers not measured yet, as elsewhere | Same as macOS/Linux containers |
| "This computer" bars (local only) | CPU and memory (sysinfo); GPUs from `ioreg`, `nvidia-smi`, `/sys` | CPU and memory (sysinfo); GPUs from DXGI (name, own memory), use not measured; the software renderer left out | Built; seen on Windows 11 (the VM: 4 cores, 8 GiB, no hardware GPU). A real GPU not checked yet |
| Identity key in the OS key store (opt-in) | macOS Keychain | Windows Credential Manager or DPAPI | Later; the owner-only file is used |

## Networks

Windows marks a network it does not know as **Public**, and the installer refuses incoming
connections to `gmcd` there. Tested with the installed build:

| | Windows starts the pairing (`gmc pair <the other device's ticket>`) | The other device starts it (Windows' ticket) |
|---|---|---|
| Public network | works (Windows dials out) | refused (the firewall rule) |
| Private network | works | works (Windows Hello confirmed it) |

Borrowing works on either, since Windows dials out. Incoming connections stay refused on public
networks (decided 2026-11-15): on a cafe or airport network nobody should be able to reach `gmcd`,
and to pair from the other device the owner marks a trusted network as Private (Settings >
Network & internet > the network > Private).

## What 0.1.1 added, on Windows

Checked from the Windows VM, borrowing from the Linux lender VM (`scripts/windows/e2e-borrow.sh`):

| Feature | On Windows | Checked |
|---|---|---|
| Standing grants (#22) | A lender's standing grant accepts Windows' requests without asking. Windows does not lend, so `gmc standing set` there is refused before any Windows Hello prompt | Both |
| Requests that wait (#23) | `--no-wait` leaves the request with the owner. Waiting requests are kept in `requests.json` (protected access list) and survive a restart of `gmcd`; the answer arrives by itself | Yes |
| `--where local` / `auto` (#24) | Runs the command on Windows itself, as typed (no shell: built-ins need `cmd /c`). Containers always go to a device | Yes |
| `--shards` (#25), `--cache` (#26) | The same as elsewhere; the cache stays on the lender | Yes |
| `--deps` (#27) | Runs `cargo vendor`, `npm ci` or `go mod vendor` on Windows | Not tried (the VM has none of these tools) |
| Tools (#28) | `gmc peers` and `gmc doctor --peer` show the lender's tools. The "here" column stays empty on Windows: the probe looks only where a lender's sandbox finds tools | Yes |
| `gmc bench` (#29) | Runs the same Python program on both sides, so it needs Python 3 on Windows (`python` or `py -3`); without it, it says to install it | Both cases (Python's embeddable build) |
| Keep awake (#30) | Nothing to do: Windows does not lend | — |
| Wake-on-LAN (#30) | Windows can let a device wake it (its network adapters' addresses) and can wake others | Packets sent both ways. Waking a sleeping Windows PC was not tried (a VM) |

## Not checked yet

- A real x64 PC (only Windows 11 on ARM, through x64 emulation, so far), and SmartScreen on a
  downloaded installer (the tests copied it over SSH, so it carried no "downloaded" mark).
- The pipe's "first instance only" and "no remote clients" flags are set but not attacked.
- `gmc mcp`'s folder rules on Windows paths (drive roots, `%USERPROFILE%`, `\\?\` paths, case).
- Lending (containers) on a real PC with Docker Desktop; refused until then.
- Password approvals with a Microsoft account, a work or school (Entra ID) account, or a domain
  account (only a local account so far), and over Remote Desktop (Ctrl+Alt+End there).

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
