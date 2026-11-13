# Roadmap

v1 = M0 through M5. Each milestone is usable on its own. Security work is part of every
milestone, not only M5; invariant IDs refer to [`design/threat-model.md`](design/threat-model.md).

## M0 — Specification

- [x] Architecture overview, feasibility summary, link/performance expectations
- [x] Threat model with security invariants I1–I14 and residual risks
- [x] Pairing protocol (commit-then-reveal short code)
- [x] Grant lifecycle and consent screen content
- [x] `gmc.toml` schema v1
- [x] Peer protocol and local API drafts (`spec/proto`)
- [x] Python SDK design, including Trusted mode
- [x] Licence (Apache-2.0), DCO, security policy
- [ ] Review of the specs; resolve open questions in threat model section 8

## M1 — Core engine (macOS + Linux) — in progress on `v1`

Done:
- [x] LAN-only iroh networking (no relays, no address publishing, no router port mapping;
      listens only on the configured address)
- [x] Protocol types generated from `spec/proto`; 4 MiB frame limit
- [x] Identity key (owner-only file; refused if readable by others) and trust list
- [x] Pairing over the network with the 6-digit code; test vectors shared with Python (I2)
- [x] Lending switch, off after install; grants with limits, expiry, revoke, stop-all (I1, I3)
- [x] Signed grants; reduce-only acceptance in v1
- [x] Content-addressed blob store, per-borrower namespaces, quotas (I14)
- [x] Default secret excludes, .gitignore/.gmcignore, safe output writing (I7, I8)
- [x] Docker executor with hardened flags; `network = none` (I4, I5)
- [x] Remote runs: upload only missing files, live logs, outputs returned, exit codes
- [x] Revoke / stop-all / expiry / unpair kill running tasks within seconds (I3)
- [x] Local API on separate owner-only Client and Control sockets (I10)
- [x] `gmcd` daemon and `gmc` / `gimmecores` CLI

Still to do in M1:
- [x] OS-verified user presence for consent actions (I13), enforced in the daemon's Control
      handlers: Touch ID / login password (macOS LocalAuthentication), polkit `auth_self`
      (Linux, policy in `packaging/linux`). Refusals are audited. Machines that cannot show a
      prompt start the daemon with `gmcd --no-presence` (that run only, audited); nothing on
      the socket can switch the check off without a verified prompt. Loosening laptop
      protections also needs presence; an approval is bound to the terms the prompt showed
- [x] Hands-on check of the real Touch ID / password prompt on macOS (2026-11-12: Verified)
- [ ] Hands-on check of the real polkit prompt on a Linux desktop (tests simulate it)
- [x] The lender chooses how tasks may run (`gmc runtimes`, desktop app): `container`
      and/or `sandbox`; containers only after install; adding one needs presence. Grants
      allow only requested ∩ lent; each task names its mode and is refused if the grant, the
      lender's current choice or a working runner does not cover it (no fallback). Runners
      are probed at start and every 30 s and advertised
- [x] Sandbox runner (no container runtime); hostile tests pass on macOS and Linux CI
      (2026-11-12). macOS: Seatbelt, deny by default, runs as the lender's user; hostile tests
      pass (no files outside the task folder, no network incl. localhost and Unix sockets, no
      AppleEvents/clipboard/keychain/other processes, scrubbed environment, memory limit,
      process cap, everything stopped with the task). Linux: bubblewrap in new namespaces
      (needs `bwrap`); its PID namespace also stops processes that detach themselves
- [ ] macOS sandbox gap: a process that deliberately detaches (double fork + setsid) can
      outlive its task, still sandboxed. Fix: run tasks as a dedicated `gmc-guest` account
      (needs a privileged helper) and stop every process of that account
- [x] Hash-chained audit log on both sides; `gmc audit [--verify]` (I11)
- [x] Secret-pattern scan of the upload set before sending; `--allow-secret` override (I7)
- [x] Discovery (mDNS): paired devices find each other by rotating identifiers only they
      recognise (no name, no permanent key); pairing mode advertises name + key for its 2
      minutes so nearby devices pair without a ticket (`gmc nearby`, `gmc pair <name>`, app);
      `gmc discovery off` = no adverts, no listening
- [x] Laptop protections: pause on battery (default), lend only while idle (opt-in, macOS); frozen tasks resume or stop after 10 minutes
- [ ] Pause when hot (thermal state)
- [ ] OS keychain backend for the identity key
- [x] Link test: `gmc link-test <peer>` (RTT min/median/p95, encrypted up/down speed, link type, "good for")
- [ ] Bulk-transfer speed: one stream reaches ~1.4 Gbps (release build, loopback); use parallel streams and fewer copies so Thunderbolt/10 GbE are not limited by GimmeCores
- [x] Show the last link test on each peer (`gmc peers`)
- [x] Run the Docker executor end to end on a real machine (macOS Docker Desktop; Linux in CI)
- [x] CI on GitHub: fmt, clippy -D warnings, tests on Linux + macOS, cargo-deny, the Python SDK
      against two real daemons, the desktop app

Known gaps found in review (must be closed before lending to anyone but your own devices):
- [x] A grant's disk limit covers its stored files plus every running task's workspace.
      This is a polled check, not a hard cap: the workspace is measured every 1-5 s, so a task
      can overshoot by what it writes in one interval before it is stopped (LIMIT_EXCEEDED).
      Unmeasurable workspaces (unreadable directories, more than 500k entries) stop the task.
      Inputs count twice (stored copy + unpacked copy), so a project needs a disk limit of
      at least twice its size. Outputs stream into the store instead of the daemon's memory
- [ ] Hard disk cap: a size-limited volume per task (with the Docker end-to-end pass)
- [x] Container runner verified with real Docker (macOS Docker Desktop; Linux in CI): attack
      tests (no network, no capabilities, read-only system, only the task folder visible,
      memory and process caps, stop removes the container, freeze/thaw, never downloads) and an
      end-to-end run through two daemons. Fixed on the way: tasks had no writable home and could
      not run what they built in /tmp; on Linux, files the container created could not be
      cleaned up (ownership is handed back after each task)
- [x] A borrower's stored files are deleted once it holds no live grant (revoke, expiry,
      unpair, lending off); audited
- [x] Grants survive a daemon restart (`grants.json`, owner-only, signed grants re-verified
      on load; expired, unpaired, lending-off and withdrawn-mode grants dropped; saved right
      after every revoke/expiry/stop/unpair; one laptop-protection check before connections)
- [x] The Control socket enforces consent itself (I13 above); the CLI's typed "yes" is a second layer
- [ ] Verified only on one machine over loopback: test two physical machines (Wi-Fi,
      Ethernet, Thunderbolt)

## M2 — Python SDK

First cut (2026-11-12, `python/`): `import gimmecores as gmc`; `@gmc.task(cpus, memory,
timeout)`, `gmc.Pool().map / imap_unordered`, `gmc.Executor`, `gmc.RemoteError`,
`gmc.grants()`; Standard mode only (functions by import name, JSON arguments and results,
nothing unpickled, per-task random result tag); parallelism sized from the active grants;
local process-pool fallback without a grant; runs in the lender's sandbox or a container image.
Tested against two real daemons in CI (Linux + macOS). Still to do below.

Trusted mode (2026-11-13): `gmc trust <device> on|off` and the app's per-device switch
(warning shown and acknowledged, OS presence check, 30-day lapse, audited); Trusted grants only
when both sides have it on (signed `TrustLevel`; never upgraded; withdrawn both ways when either
side turns it off, lapses or unpairs; not restored after a restart once off); the borrower's
daemon alone vouches for results (`JobDone.trusted_results`, checked again at the end of the
task); `gmc.Pool(trusted=True)` / `gmc.Executor(trusted=True)` with cloudpickle shipped from the
borrower and a Python version check on the lender. Hostile-lender tests: forged pickle results
are never loaded by a standard pool, without this device's Trusted mode, with only a standard
grant, or after it is turned off mid-task.

- [x] `@gmc.task`, `gmc.Pool`, `gmc.Executor`
- [x] `gmc.File` / `gmc.Dir` (2026-11-13): passed files and folders travel as attachments
      (excludes and secret scan apply); returned ones come back as declared outputs through I8
      into `results_dir`, and the borrower accepts a returned reference only if it names a file
      that arrived under that task's output folder (hostile-lender tests); Standard and Trusted
      mode; local fallback unchanged
- [x] `gmc.Secret` / `@gmc.task(secrets=[...])` (2026-11-13): values travel as task
      environment variables (encrypted; never in a file, a command line or a log; audit logs
      record names only; Docker gets names only); the lender refuses variables that would
      replace its own (`PATH`, `HOME`, `TMPDIR`, `LANG`, `DEVELOPER_DIR`, `LD_*`, `DYLD_*`).
      Standard-mode arguments moved from the lender's command line into a scanned file
- [x] **Packages from the project's lockfile** (2026-11-13): `uv.lock`, `requirements.txt` or
      `pyproject.toml` dependencies (`env=gmc.Lockfile(path)`, `env=None`). The lender reports its
      Python and platform in a probe task (strictly validated); the borrower resolves and
      installs wheels for it with uv (no source builds, no package code runs on the borrower),
      byte-compiles them for the lender's Python, caches the folder and sends it as an
      attachment under `.gmc-sdk/env`. Files matching their package's `RECORD` hash skip the
      secret scan and name excludes; everything else gets both. The task runs with `-S` (the
      lender's own site-packages left out). Works with the sandbox and with container images
      (built for the image's Linux). Path/URL/VCS requirements refused for now
- [x] A macOS sandbox lender keeps a borrower's packages between tasks (macOS checks every new
      native library on first load: NumPy + pandas took ~5 s per task, now ~0.6 s): one copy
      per borrower and package digest inside its blob namespace, blobs hash-checked when
      unpacked, read-only in the sandbox (write, chmod, unlink, rename, hard link all refused:
      hostile test), unreadable to other borrowers, counted in the disk quota (else a per-task
      copy), at most 3 per borrower, deleted with the namespace
- Lender-side offline image build and cache
- Warm containers per grant; automatic batching from measured RTT
- Safe serialization (I6); `RemoteError`
- [x] **Trusted mode**: two-sided enablement, `trusted=True`, cloudpickle, version checks, 30-day expiry
- [x] joblib backend (Trusted mode, 2026-11-13): `gmc.register_joblib()`, then
      `backend="gimmecores"`; sends only the calls (no joblib or gimmecores on the lender),
      network-sized auto-batching, original exceptions, grant-sized concurrency
- [x] Jupyter: `%load_ext gimmecores` and `%gmc` (devices, Trusted mode both ways, grants, what
      to run); Trusted mode is never turned on from a notebook (presence needed)
- PyPI Trusted Publishing

## M3 — Interfaces

- Web dashboard served by `gmcd` (I10: Host/Origin/CSRF/session checks, strict CSP)
- [x] Tauri 2 desktop app, first cut (macOS, `apps/desktop`): lending switch and
      protections, requests (accept/decline), lent and borrowed grants (revoke), Stop all,
      devices (unpair), pairing (ticket + code comparison), menu-bar icon, notifications.
      Own workspace + CI job + dependency policy (macOS targets only for now). Polls the
      daemon every 2 s (WatchEvents is not implemented yet)
- [x] macOS `.app`/`.dmg` (packaging/macos/build-app.sh, built in CI): the app starts `gmcd`
      as a LaunchAgent on request (and at login, switchable), installs `gmc` into
      /usr/local/bin on request; Linux install script + systemd user service
- [ ] Developer ID signing + notarization (needs an Apple Developer account)
- [ ] Desktop app: hands-on check of the window, menu-bar icon, notifications and the
      Start/at-login flow; Linux desktop build (Tauri's Linux stack needs an advisory review)
- Activity and laptop-protection status in the UI (enforcement lands in M1)

## M4 — Windows + Raspberry Pi

- WSL2 container backend; Windows service; named-pipe local API with user ACL
- ARM64 Linux builds; Pi-friendly defaults
- `network = internet` and online environment builds, with LAN blocking per platform (I5)
- User presence on Windows (Windows Hello / password) for consent actions (I13)
- Native mode with dedicated `gmc-guest` account (all platforms)
- Thunderbolt/USB4 interface detection; GPU job routing (CUDA in containers, Metal native)

## M5 — Hardening for release

- External security review of pairing, grant enforcement and sandboxing
- Fuzzing every protocol decoder in CI
- Cross-OS test matrix on real machines and real links (Wi-Fi, Ethernet, Thunderbolt)
- Signed releases, SBOM, build provenance; signed auto-update (I12)
- Installers: Homebrew, winget, apt/rpm, PyPI; docs site

## After v1

- JavaScript/TypeScript SDK; Go/Rust/Java/C# client libraries generated from the protocol
- Hosting exo / llama.cpp RPC / prima.cpp inside grants
- Hosting Dask / Ray workers inside grants (Trusted mode, two-way trust)
- Redundant execution (verify results on two peers)
- Stronger isolation options (gVisor / Kata / microVMs)
- Mobile apps (Tauri mobile + UniFFI): consent, control, submit
- Premium: hosted relays for peers on different networks, team admin, SSO, policies, central
  revoke, audit export, fleet dashboard
