# Consent and grants

Status: draft (M0).

A **grant** is the lender's permission for one borrower to use a bounded amount of its machine
for a bounded time. Grants are the only thing that allows code to run on a lender
(threat model invariant I1).

## Grant contents

| Field | Meaning | Default |
|---|---|---|
| `grant_id` | Random 128-bit ID | — |
| `lender`, `borrower` | Public keys | — |
| `not_after` | Expiry | 2 hours (max 30 days) |
| `cpus` | CPU cores (fractional allowed) | half of the lender's cores |
| `memory` | RAM cap; no swap | 25% of the lender's RAM |
| `disk` | Workspace + cache quota | 10 GB |
| `gpu` | `none`, `cuda`, `metal` | `none` |
| `max_concurrent_tasks` | Parallel tasks | = `cpus`, rounded down |
| `modes` | `container`; `native` only if the lender ticks it (available from M4, when the guest account exists) | `container` |
| `network` | `none`, or `internet` (internet without lender LAN/localhost; from M4) | `none` |
| `env_build_network` | May the environment build step download packages? Same LAN-blocking rule as `internet`; unavailable on a platform until LAN blocking exists there | `false` until M4 (borrower ships packages); then `true`, shown on screen |
| `schedule` | `always` or `idle_only` | `idle_only` on laptops, `always` on desktops/Pis |
| `pause_on_battery`, `pause_when_hot` | Laptop protection | `true` |
| `trust` | `standard` or `trusted` (see Trusted mode) | `standard` |
| `speed` | `full`, `apps_first` or `background`: how its tasks share the lender's cores ([task speed](task-speed.md)). Unset: the lender's own setting when each task starts | unset |
| `signature` | Lender's Ed25519 signature over the exact serialized grant bytes (`SignedGrant` in `peer.proto`) | — |

The lender stores the grant and enforces it. The signature lets the borrower show it and lets
future team features verify it; enforcement never depends on the borrower's copy.

## Lifecycle

> **v1 behaviour:** acceptance is *reduce-only*. The lender accepts as asked or with smaller
> limits / shorter time (never more), and the grant is final at once; the OFFERED state and
> borrower counter-offers below are reserved for later versions.

```
            borrower asks                lender edits limits
 (none) ───────────────▶ REQUESTED ─────────────────────▶ OFFERED ──┐
                            │  ▲                              │       │ borrower declines
                 lender     │  └──────── borrower counters ───┘       ▼
                 declines   ▼                                      DECLINED
                         DECLINED          lender accepts
                            REQUESTED/OFFERED ─────────────▶ ACTIVE
                                                              │  ▲
               lender active / on battery / too hot / busy    │  │ conditions clear
                                                              ▼  │
                                                            PAUSED
          ACTIVE or PAUSED ── not_after reached ──▶ EXPIRED
          ACTIVE or PAUSED ── either side revokes / Stop all lending / unpair ──▶ REVOKED
```

- **REQUESTED → ACTIVE** requires a human action on the lender, verified by OS user presence
  (Touch ID / password / Windows Hello / polkit; threat model I13), or a standing rule the lender
  created the same way, e.g. "auto-accept my own devices up to 4 cores until 18:00".
- **PAUSED**: running tasks are frozen (cgroup freezer / `docker pause` / job suspension); new
  tasks are queued, not refused. Frozen tasks still hold their memory, so they are stopped
  immediately if the lender's machine comes under memory pressure, and after 10 minutes paused
  in any case; the borrower reschedules them.
- **REVOKED / EXPIRED**: running tasks get SIGTERM, then SIGKILL after 10 s; workspaces are
  deleted; the borrower is notified (invariant I3). Caches keyed by content digest may be kept
  for reuse by a future grant to the same borrower, within the disk quota, unless the lender
  chooses "forget everything".

## What every consent screen must show

Incoming request (lender side), in plain language:

> **Maya's MacBook Pro** wants to use this computer.
> Fingerprint `K7QX-2M4P-…` · Paired 3 days ago · Link: Wi-Fi 6, ~180 Mbps, 14 ms
>
> - Up to **4 CPU cores** and **8 GB RAM**, no GPU
> - Runs inside a **container**. It cannot see your files or other apps.
> - **No network** while running. Packages are sent by the requester; nothing is downloaded.
>   (From M4, where LAN blocking exists: "May download packages from the internet while
>   setting up. Cannot reach devices on your network.")
> - Only while this computer is **idle** and **plugged in**
> - Until **18:00 today**
>
> [Decline] [Edit limits] [Accept]

Extra lines appear when they apply:
- Native mode: "Runs directly on this computer as the GimmeCores guest account, **not** in a
  container. Package install scripts run on this computer."
- Native mode on macOS: "Memory limits are enforced by stopping the task after it goes over."
- GPU: "Can use your NVIDIA GPU" / "Can use this Mac's GPU (native mode only)."
- Hosted engines (exo, llama.cpp RPC): "llama.cpp RPC is experimental software; GimmeCores
  encrypts and restricts its traffic but cannot fix bugs in it."
- Trusted mode: the warning in the threat model, section 6.
- Speed, always: "Their tasks run at your setting: your apps first", or what the request names,
  marked when it is faster than the owner's setting ("Asks to run at full speed: faster than
  your setting, kept for this grant if you accept"). The approval prompt names a named level.

First submit (borrower side), once per peer:

> **This peer can see the code and data you send it.** GimmeCores never sends your environment
> variables or files like `.env` and private keys unless you include them.

## Always-visible controls

- Tray/menu-bar icon shows when any peer is using this machine, and who.
- **Stop all lending**: one click / `gmc stop` — revokes every active grant (I3).
- Activity view: live tasks, CPU/RAM per peer, history from the audit log.
- Discovery mode switch: Off / Paired devices only / Everyone for 10 minutes.

## Standing rules (optional, lender-defined)

To avoid approving every request for your own devices:
`gmc rule add --peer "My Desktop" --cpus 8 --memory 16g --until 18:00 --idle-only`
Rules can only be created by the lender's user through the Control API with user presence
(I13), are listed in the dashboard, and are recorded in the audit log. A rule never approves a
request that asks for a faster speed than the owner's setting.
