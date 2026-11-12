# Architecture overview

Status: draft (M0).

GimmeCores lets a developer use CPU, RAM and GPU on nearby machines (same Wi-Fi/LAN, or a
Thunderbolt/USB4/Ethernet cable) by **bundling work into tasks** that run on a peer and send
results back. It does not make remote RAM or GPUs look local to arbitrary programs; see
[`feasibility.md`](feasibility.md) for why.

## Components

```
 Borrower machine                                   Lender machine
┌────────────────────────────────────┐            ┌────────────────────────────────────┐
│ Your code                          │            │                                    │
│  ├─ gmc CLI  (gmc run …)           │            │  Dashboard / desktop app (consent) │
│  ├─ Python SDK (import gimmecores) │            │            │ local API              │
│  └─ any language via local API     │            │            ▼                        │
│            │ local API (UDS/pipe)  │            │  gmcd ──── grant enforcement        │
│            ▼                       │  QUIC/TLS  │     │          audit log            │
│  gmcd ─────────────────────────────┼───(iroh)───┼─▶   ├─ blob store (content hashes)  │
│   ├─ peers & trust list            │            │     └─ executor                     │
│   ├─ scheduler                     │            │          ├─ container (Docker/Podman)│
│   ├─ blob store (content hashes)   │            │          └─ native (guest account)   │
│   └─ audit log                     │            │                                    │
└────────────────────────────────────┘            └────────────────────────────────────┘
```

Every machine runs the same `gmcd`; any machine can borrow, lend, or both.

| Component | Responsibility |
|---|---|
| `gmcd` | Identity, discovery, pairing, grants, link tests, blob store, scheduling, execution, audit log. Runs as the normal user. |
| `gimmecores` CLI (short alias `gmc`) | Thin client for the local API: `pair`, `peers`, `grants`, `run`, `stop`, `dashboard`, `audit`. Consent commands use the Control socket and ask for user presence. |
| Dashboard | Web UI served by `gmcd` on `127.0.0.1` (see threat model 5.5). |
| Desktop app | Tauri 2 shell around the dashboard; tray icon, notifications for incoming requests. |
| SDKs | Talk only to the local `gmcd`, never to the network. Python in v1. |

## Layers and what makes GimmeCores "universal"

1. **Protocol + task file** (language-neutral, versioned): `spec/proto/` and
   [`spec/gmc-toml.md`](../../spec/gmc-toml.md). Anyone can write a client or a second
   implementation from these.
2. **Core engine** (Rust): one codebase for macOS, Linux, Windows, Raspberry Pi; embeddable in
   iOS/Android apps later through UniFFI.
3. **Interfaces**: CLI, web dashboard, Tauri desktop app; Tauri mobile later.

Integration levels for developers:

| Level | How | Languages |
|---|---|---|
| 1 | `gmc run -- <cmd>` + `gmc.toml`, no code changes | All |
| 2 | Local API (gRPC over a Unix socket / named pipe; JSON gateway) | All |
| 3 | Native SDK (`import gimmecores as gmc`, `@gmc.task`, `Pool.map`) | Python (v1), JS/TS next |

Compiled languages (Go, Rust, Java, C#, C++) submit **commands or built programs** at levels 1–2;
a program must match the lender's OS/CPU or be built inside a container on the lender.

## Stack

| Concern | Choice | Notes |
|---|---|---|
| Core language | Rust | Memory-safe, single binary everywhere, mobile embedding via UniFFI. Go is the fallback. |
| Peer networking | iroh 1.x (QUIC, TLS 1.3, dial by public key) | mDNS local discovery via `iroh-mdns-address-lookup`. v1 is LAN-only: iroh's default relay and global address publishing are disabled. Opt-in relays later (premium). |
| Wire format | Protocol Buffers (`prost`) | Length-prefixed messages on QUIC streams; strict size limits. |
| Local API | gRPC (`tonic`) over UDS / named pipe, JSON gateway for the dashboard | Two services on separate sockets: **Client** (submit work) and **Control** (consent, with OS user presence). |
| Hashing | SHA-256 | Matches OCI image digests and Bazel REAPI. `digest_function` field leaves room for BLAKE3. |
| Containers | Docker or Podman (OCI) | Linux native; macOS via Docker Desktop / Podman machine; Windows via WSL2. |
| Desktop UI | Tauri 2 + web dashboard | Same UI in browser and app. |
| Python SDK | Pure Python package `gimmecores` on PyPI (free as of 2026-11-12), imported as `import gimmecores as gmc`. The PyPI name `gmc` is taken, so `gmc` is only the import alias. | Talks gRPC to `gmcd`. |
| Names | Crates `gimmecores`, `gimmecores-*`; binaries `gimmecores`, `gmc` (alias), `gmcd` (service) | `gimmecores` is free on PyPI, crates.io, npm and as a GitHub name (2026-11-12). The installer adds the `gmc` alias only if no other `gmc` command exists; `gimmecores` always works. Use "gmc" only as a lowercase command, never as a brand or logo (GMC is a General Motors trademark). |

## Task flow (`gmc run` or `Pool.map`)

1. **Plan**: read `gmc.toml` / SDK call → list of tasks (command or `module:function`,
   environment, inputs, outputs, resources).
2. **Choose peers**: active grants that fit the resources, GPU kind and OS; rank by measured
   link speed, free capacity and what each peer already has cached.
3. **Upload only what's missing**: build a content-addressed input tree; ask the peer which
   hashes it lacks; send only those.
4. **Environment**: peer builds or reuses the environment (image, or lockfile → image), cached by
   digest.
5. **Run**: peer checks the grant, starts or reuses a warm container, runs the task, streams logs.
6. **Return**: outputs come back as content-addressed files and safe-format values; written only
   inside declared output paths.
7. **Recover**: on peer loss, revoke or timeout, retry on another peer or locally (tasks must be
   safe to repeat).

## Related documents

- [`threat-model.md`](threat-model.md): security principles, invariants, residual risks
- [`pairing.md`](pairing.md): device identity and pairing protocol
- [`consent-and-grants.md`](consent-and-grants.md): grant lifecycle and consent screens
- [`python-sdk.md`](python-sdk.md): Python SDK design
- [`links-and-performance.md`](links-and-performance.md): link speeds and the link test
- [`feasibility.md`](feasibility.md): what can and cannot be built, with sources
- [`../ROADMAP.md`](../ROADMAP.md): milestones
