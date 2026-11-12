# Roadmap

v1 = M0 through M5. Each milestone is usable on its own. Security work is part of every
milestone, not only M5; invariant IDs refer to [`design/threat-model.md`](design/threat-model.md).

## M0 — Specification (current)

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
- [x] Hash-chained audit log on both sides; `gmc audit [--verify]` (I11)
- [x] Secret-pattern scan of the upload set before sending; `--allow-secret` override (I7)
- [ ] Discovery: listen-only mDNS by default, rotating-ID advert for paired devices
- [x] Laptop protections: pause on battery (default), lend only while idle (opt-in, macOS); frozen tasks resume or stop after 10 minutes
- [ ] Pause when hot (thermal state)
- [ ] OS keychain backend for the identity key
- [x] Link test: `gmc link-test <peer>` (RTT min/median/p95, encrypted up/down speed, link type, "good for")
- [ ] Bulk-transfer speed: one stream reaches ~1.4 Gbps (release build, loopback); use parallel streams and fewer copies so Thunderbolt/10 GbE are not limited by GimmeCores
- [x] Show the last link test on each peer (`gmc peers`)
- [ ] Run the Docker executor end to end on a real machine (needs Docker running)
- [ ] CI: workflow written (fmt, clippy -D warnings, tests on Linux + macOS, cargo-deny); not yet
      run on GitHub (pushing workflows needs the `workflow` token scope)

Known gaps found in review (must be closed before lending to anyone but your own devices):
- [x] A grant's disk limit covers its stored files plus every running task's workspace.
      This is a polled check, not a hard cap: the workspace is measured every 1-5 s, so a task
      can overshoot by what it writes in one interval before it is stopped (LIMIT_EXCEEDED).
      Unmeasurable workspaces (unreadable directories, more than 500k entries) stop the task.
      Inputs count twice (stored copy + unpacked copy), so a project needs a disk limit of
      at least twice its size. Outputs stream into the store instead of the daemon's memory
- [ ] Hard disk cap: a size-limited volume per task (with the Docker end-to-end pass)
- [ ] Linux + Docker: files the container (uid 65534) creates in subdirectories may be
      unmeasurable or undeletable by the daemon user; needs the Docker end-to-end pass
- [x] A borrower's stored files are deleted once it holds no live grant (revoke, expiry,
      unpair, lending off); audited
- [ ] Grants live in memory only: a daemon restart drops them (borrower must ask again)
- [x] The Control socket enforces consent itself (I13 above); the CLI's typed "yes" is a second layer
- [ ] Verified only on one Mac over loopback: test two physical machines (Wi-Fi, Ethernet,
      Thunderbolt) and a full run inside the Docker sandbox

## M2 — Python SDK

- `@gmc.task`, `gmc.Pool`, `gmc.Executor`, `gmc.File`, `gmc.Secret`
- Environment capture from lockfiles; borrower downloads Linux wheels and ships them; lender-side offline image build and cache
- Warm containers per grant; automatic batching from measured RTT
- Safe serialization (I6); `RemoteError`
- **Trusted mode**: two-sided enablement, `trusted=True`, cloudpickle, version checks, 30-day expiry
- Jupyter extension (Trusted mode); joblib backend (Trusted mode)
- PyPI Trusted Publishing

## M3 — Interfaces

- Web dashboard served by `gmcd` (I10: Host/Origin/CSRF/session checks, strict CSP)
- [x] Tauri 2 desktop app, first cut (macOS, `apps/desktop`): lending switch and
      protections, requests (accept/decline), lent and borrowed grants (revoke), Stop all,
      devices (unpair), pairing (ticket + code comparison), menu-bar icon, notifications.
      Own workspace + CI job + dependency policy (macOS targets only for now). Polls the
      daemon every 2 s (WatchEvents is not implemented yet)
- [ ] Desktop app: hands-on check of the window, menu-bar icon and notifications; .app bundle
      and signing; Linux build (Tauri's Linux stack needs an advisory review)
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
