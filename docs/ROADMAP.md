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
      outlive its task, still sandboxed. Proposed fix (awaiting decision, needs a one-time
      admin step): a pool of hidden guest accounts, one per running task, every process of the
      account killed when the task ends ([design](design/guest-accounts.md))
- [x] Hash-chained audit log on both sides; `gmc audit [--verify]` (I11)
- [x] Activity, this computer's side ([design](design/activity.md)): each task other devices
      run here, with its command (secrets hidden, boundaries kept), what it asked for and what
      it uses, measured from outside it (CPU now and CPU time, memory now and peak, processes,
      its folder's size; "not measured" is never shown as zero); finished tasks grouped, in
      memory only; why each ended (a cause added to the result, statuses unchanged); the owner
      stops one task (`gmc tasks stop`, the app's Stop task; reduce-only). `gmc tasks`, and
      the app's new Activity / Devices / Settings views with live cards updated in place.
      Frozen is shown only when the runner confirmed it
- [x] "This computer" bars (2026-11-15): CPU, memory and GPUs in use, and the share tasks
      from other devices use (striped "not measured" while one runs in a container), in the
      app's Activity view and at the top of `gmc tasks`; measured only while read
- [ ] Activity, the borrower's side: the lender's figures while a task runs, per-job phases,
      `CancelJob` from any client, the lender's speed level, bars per lender (stage 2)
- [ ] A lender's whole-machine load for its borrowers: a lender setting, off by default
- [ ] Devices view with reachability, and held grants that cannot look usable once dead;
      container figures from the runtime's stats (stage 3)
- [x] The audit log cannot be filled by a device without a grant: tasks are admitted before
      they are recorded and refusals record nothing; commands are logged cut, with likely
      secrets hidden; request reasons are cleaned and cut; only a grant's holder learns why
      lending is paused. An idle lender sends no events (grant listings no longer re-stamp
      their issue time every call)
- [x] Secret-pattern scan of the upload set before sending; `--allow-secret` override (I7)
- [x] Discovery (mDNS): paired devices find each other by rotating identifiers only they
      recognise (no name, no permanent key); pairing mode advertises name + key for its 2
      minutes so nearby devices pair without a ticket (`gmc nearby`, `gmc pair <name>`, app);
      `gmc discovery off` = no adverts, no listening
- [x] Laptop protections: pause on battery (default), lend only while idle (opt-in, macOS); frozen tasks resume or stop after 10 minutes
- [x] Pause when hot (default on; `gmc lend on --when-hot` / the app to keep lending, which
      needs presence like the other loosening): macOS thermal state serious/critical
      (`NSProcessInfo`), Linux thermal zones at their passive (else hot) trip point; unknown never
      pauses
- [x] Lent tasks run at full speed on macOS: the background service is an `Interactive`
      launchd job (app and Homebrew), because tasks inherit how macOS schedules the service.
      Measured on an M2 Max through `gmc run`: as a `Background` job tasks ran 6 to 15 times
      slower (efficiency cores only), as a `Standard` one work on several cores ran at half
      speed. The price, also measured: while a lent task uses every core, the owner's own
      heavy work shares them (1.9 s instead of 1.1 s). `gmc status` and the app say when the
      system holds the service back, and the app restarts an older login item with one click
- [x] Stopping the service stops its tasks: on SIGTERM (launchd, systemd, the app's switch,
      `brew services stop`, logging out), SIGHUP and Ctrl-C every running task is ended, its
      borrower is told, and the stop is audited. Before, only Ctrl-C was handled and a task's
      child processes kept running with nothing supervising them
- [ ] macOS: a daemon that is killed outright (`kill -9`, a crash) still leaves its tasks
      running, sandboxed, until they finish (Linux ends them: bubblewrap `--die-with-parent`)
- [ ] macOS: an owner's choice to keep their own apps fast while lending (measured: a utility
      clamp costs the owner's work 14% instead of 70 to 90%, and makes lent work on several
      cores 2 to 4 times slower)
- [x] OS keychain backend for the identity key (macOS, opt-in): `gmcd --identity-store
      keychain` moves the key file into the login Keychain once and never exports it; a
      missing item is an error, never a silent new identity; a denied or locked Keychain stops
      gmcd cleanly (no restart loop). Its access list names only the creating `gmcd` by code
      hash, so ad-hoc builds are asked again after each upgrade: make it the default once
      releases are Developer ID signed. Linux keeps the owner-only file (the Secret Service
      gives secrets to any same-user program); Windows with M4
- [x] Link test: `gmc link-test <peer>` (RTT min/median/p95, encrypted up/down speed, link type, "good for")
- [x] Uploads stream files in chunks (memory stays at one chunk; a file changed mid-send is
      refused), large uploads use 4 parallel streams, and the lender unpacks by verified
      copy-on-write clone (hash checked once per blob, cached by inode/ctime): 1 GiB unpacks in
      ~0.6 s. Measured 2026-11-13 (release, loopback, macOS): uploads ~0.9-1.0 Gbit/s, the
      transport's own ceiling (`gmc link-test` ~1.1 Gbit/s). Neither parallel connections nor
      larger QUIC windows raised it, and larger windows broke re-finding a moved device, so
      iroh's defaults stay. Enough for Wi-Fi and gigabit Ethernet
- [ ] Faster than ~1 Gbit/s (Thunderbolt, 10 GbE) needs work inside iroh's transport on macOS
      (no UDP segmentation offload there); measure on real links first
- [x] Show the last link test on each peer (`gmc peers`)
- [x] Run the Docker executor end to end on a real machine (macOS Docker Desktop; Linux in CI)
- [x] CI on GitHub: fmt, clippy -D warnings, tests on Linux + macOS, cargo-deny, the Python SDK
      against two real daemons, the desktop app
- [x] `gmc mcp`: an MCP server for AI agents (tools `devices`, `run`, `job`, `jobs`, `cancel`;
      both MCP eras, 2024-11-05 to 2025-11-25 with `initialize` and 2026-07-28 with
      `server/discover`). Client socket only, four calls; no grant requests or approvals; folders
      inside a fixed root; no secret-scan override, env, attachments, Trusted mode or network.
      Tested with the official MCP client against two real daemons
- [x] Cancelling works end to end: a client that hangs up (Ctrl-C in `gmc run`, an SDK process
      that exits, an agent session that ends) stops its task on the lender
- [x] The same CI on your own machine, free (`scripts/ci-local.sh`): macOS natively, Linux in a
      bookworm container (arm64, or x86_64 emulated), cargo-deny, actionlint, fuzzing, the .deb.
      All of it passes on macOS arm64, Linux arm64 and Linux x86_64 (emulated). Hosted CI is
      paused (manual runs only) to stay free; pull requests carry their local results

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
- [x] Automatic batching from measured task times (2026-11-13): batches start at one call and
      aim for ~2 s of work per task, capped at a fair share of what is left
- Warm containers per grant: not now. A container kept for a grant would have to mount a
  shared parent folder (mounts cannot change once it runs), so tasks would see each other's
  folders; with automatic batching (~2 s per task) the ~0.5 s container start matters less
- Safe serialization (I6); `RemoteError`
- [x] **Trusted mode**: two-sided enablement, `trusted=True`, cloudpickle, version checks, 30-day expiry
- [x] joblib backend (Trusted mode, 2026-11-13): `gmc.register_joblib()`, then
      `backend="gimmecores"`; sends only the calls (no joblib or gimmecores on the lender),
      network-sized auto-batching, original exceptions, grant-sized concurrency
- [x] Jupyter: `%load_ext gimmecores` and `%gmc` (devices, Trusted mode both ways, grants, what
      to run); Trusted mode is never turned on from a notebook (presence needed)
- [x] PyPI Trusted Publishing workflow (`release-python.yml`): OIDC, attestations, tag must
      match the version, a required-reviewer `pypi` environment; the sdist lists exactly what
      ships. Not yet used: needs the owner to register the publisher on PyPI and push a tag

## M3 — Interfaces

- Web dashboard served by `gmcd` (I10: Host/Origin/CSRF/session checks, strict CSP)
- [x] Tauri 2 desktop app, first cut (macOS, `apps/desktop`): lending switch and
      protections, requests (accept/decline), lent and borrowed grants (revoke), Stop all,
      devices (unpair), pairing (ticket + code comparison), menu-bar icon, notifications.
      Own workspace + CI job + dependency policy (macOS targets only for now). Follows the
      daemon's `WatchEvents` stream (requests, grants, pairing, activity and status, within
      ~250 ms), with a slow fallback refresh
- [x] macOS `.app`/`.dmg` (packaging/macos/build-app.sh, built in CI): the app starts `gmcd`
      as a LaunchAgent on request (and at login, switchable), installs `gmc` into
      /usr/local/bin on request; Linux install script + systemd user service
- [ ] Developer ID signing + notarization (needs an Apple Developer account)
- [ ] Desktop app: hands-on check of the window, menu-bar icon, notifications and the
      Start/at-login flow
- [x] Linux desktop build (2026-11-13): builds, lints and tests on Linux (arm64, in Docker);
      systemd user service and `~/.local/bin` CLI install from the app; dependency policy
      covers Linux (four "unmaintained" advisories reviewed); `packaging/linux/build-deb.sh`
      builds a `.deb` (app, daemon, CLI, polkit policy, user unit not enabled)
- Activity and laptop-protection status in the UI (enforcement lands in M1)

## M4 — Windows + Raspberry Pi

- [x] Named-pipe local API with a user-only access list, and `gmcd` started at sign-in from the
      user's Run key (2026-11-15; docs/design/windows.md)
- [x] User presence on Windows (2026-11-15): Windows Hello, or where it is not set up the
      Windows password on the secure screen after Ctrl+Alt+Delete, checked by Windows for the
      same account (I13)
- WSL2 container backend (lending from Windows; refused until tested on a real PC)
- ARM64 Linux builds; Pi-friendly defaults
- `network = internet` and online environment builds, with LAN blocking per platform (I5)
- Native mode with dedicated `gmc-guest` account (all platforms)
- Thunderbolt/USB4 interface detection; GPU job routing (CUDA in containers, Metal native)

## M5 — Hardening for release

- External security review of pairing, grant enforcement and sandboxing
- [x] Fuzzing every decoder of peer-controlled bytes (2026-11-13): `fuzz/` cargo-fuzz targets
      (frames, directory listings and returned outputs, package RECORDs, tickets, signed grants,
      mDNS adverts, display text and the secret scan) with invariants, a nightly CI job
      (60 s per target), the same entry points on stable in `fuzz_smoke.rs`, and randomized
      tests of the SDK's parsers of lender output (`test_hostile_parsers.py`)
- Cross-OS test matrix on real machines and real links (Wi-Fi, Ethernet, Thunderbolt)
- [x] Release workflow (`release.yml`, tag `v*`): macOS arm64 and Linux x86_64/arm64 binaries,
      SHA-256 checksums, CycloneDX SBOMs and signed build provenance (GitHub attestations,
      Sigstore keyless; `gh attestation verify`), the ad-hoc-signed macOS app, all on a DRAFT
      release a maintainer publishes. Not yet run (needs a tag, and Actions minutes)
- [x] The macOS app updates itself (I12, [releasing](RELEASING.md)): Settings > Updates checks
      only when clicked; an update must be signed with the maintainer's update key (kept on
      their Mac, never in CI) for exactly the announced, newer version, come from this
      project's release files and hold only GimmeCores; the service restarts with it.
      `gmc-release` signs; `scripts/release-mac.sh` checks the tag and the CI build's
      provenance, signs and publishes on confirmation; a Homebrew cask installs the app in
      Applications. Tested end to end with a throwaway key; not yet run on a real release
- Developer ID signing and notarization (deferred: Homebrew first)
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
