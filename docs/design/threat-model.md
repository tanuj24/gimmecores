# GimmeCores threat model

Status: draft (M0). Owner: core maintainers. Applies to: `gmcd`, `gimmecores`/`gmc` CLI, dashboard, desktop app, SDKs.

GimmeCores lets one person run code on another person's machine. That is the most sensitive thing
a developer tool can do, so security is a product feature, not an afterthought. This document
lists what we protect, who we protect it from, the controls we rely on, and the risks we
**cannot** remove — stated plainly so users can make informed decisions.

---

## 1. Principles

1. **Default deny.** Nothing runs on a lender's machine unless that machine's own user accepted a
   grant covering it. Lending is off after install.
2. **The lender enforces.** Every limit (CPU, RAM, GPU, disk, network, expiry) is checked and
   enforced on the lender. A borrower can never raise its own limits.
3. **Consent is informed.** Consent screens say, in plain language, what the peer will be able
   to do and see. If we cannot enforce something on a platform, the screen says so.
4. **Least privilege everywhere.** The daemon runs as a normal user. Jobs run in containers as a
   non-root user with no access to the host. Native jobs run under a separate low-privilege account.
5. **No silent trust upgrades.** Trust levels change only by explicit action on both devices.
6. **Everything is auditable.** Every pairing, grant change and job is recorded on both sides.
7. **Honest residual risk.** We document what we cannot protect against (section 7).

---

## 2. Assets

| Asset | Owner | Why it matters |
|---|---|---|
| Lender's files, credentials, browser sessions, SSH keys | Lender | A job must never read or change them. |
| Lender's home/office network (router, NAS, printers, other devices) | Lender | A job must not be a foothold into the lender's LAN. |
| Lender's machine availability (CPU, RAM, disk, battery, thermals) | Lender | Lending must never make the machine unusable or damage battery health. |
| Borrower's source code and data sent with a job | Borrower | Confidential IP; may contain secrets by accident. |
| Borrower's machine (when receiving results) | Borrower | Results must never be able to run code on the borrower (except in Trusted mode, by design). |
| Device identity keys | Both | Whoever holds a key *is* that device to its peers. |
| Integrity of results | Borrower | Wrong results can silently corrupt builds, tests or models. |

---

## 3. Threat actors

| ID | Actor | Capabilities assumed |
|---|---|---|
| **T1** | Malicious or compromised **borrower** (paired, holds a grant) | Submits arbitrary jobs within its grant. Crafts malformed protocol messages. |
| **T2** | Malicious or compromised **lender** (paired) | Full root on its own machine: can read, change or fake anything a job sends or returns. |
| **T3** | **Network attacker** on the same Wi-Fi/LAN (not paired) | Sees, drops, injects and replays packets; spoofs mDNS; runs its own GimmeCores nodes; floods. |
| **T4** | **Local attacker** on the same machine (malware running as another user, or a different local account) | Can connect to local sockets/ports it has permission for. |
| **T5** | **Malicious website** in the user's browser | Can make requests to `localhost`, attempt DNS rebinding and CSRF against the dashboard. |
| **T6** | **Supply-chain attacker** | Compromises a dependency, our CI, our release artifacts, PyPI package, or update channel. |
| **T7** | **Device theft / lost device** | Has the disk and possibly an unlocked session. |

---

## 4. Security invariants (each becomes an automated test)

| ID | Invariant | Defends against |
|---|---|---|
| **I1** | No task executes on a lender without a valid, unexpired grant that the lender's user accepted, issued to the exact key on the connection. | T1, T3 |
| **I2** | An unpaired device can do nothing except send pairing messages, and only while the lender's user has pairing mode open (max 2 minutes). | T3 |
| **I3** | Revoking a grant (or pressing **Stop all lending**) terminates every running task for it within 10 seconds and deletes its workspaces. | T1 |
| **I4** | A container task cannot read or write any lender path outside its own per-task workspace. | T1 |
| **I5** | A task's default network is **none**. `internet` mode, if granted, blocks the lender's LAN and localhost; if a platform cannot block the LAN, `internet` mode is unavailable there. | T1 |
| **I6** | The borrower decodes results only in the format **it** requested; a result declaring any other format is an error. It never deserializes an executable format (pickle) unless Trusted mode is enabled on **both** devices **and** requested in code. | T2 |
| **I7** | The borrower never sends its environment variables, and never sends files matching secret patterns, unless the user explicitly includes them. | T2 |
| **I8** | Returned files are written only inside the declared output directory: no absolute paths, no `..`, no symlinks escaping it, size-capped. Returned files are never executed automatically. | T2 |
| **I9** | `gmcd` runs without administrator/root rights. (One-time admin step only to create the native-mode guest account, if the user opts in.) | T1, T4 |
| **I10** | The local control API is reachable only by the same OS user; the dashboard rejects requests that fail Host, Origin and session-token checks. | T4, T5 |
| **I11** | Every pairing, trust change, grant change and task (who, what command, which image digest, which input digest, resources, duration, bytes, exit status) is appended to a hash-chained audit log on both devices. | All (detection) |
| **I12** | Release artifacts and auto-updates are signed; the updater refuses unsigned or downgraded builds. | T6 |
| **I13** | Actions that **increase** what others may do (accept or edit a grant, add a standing rule, confirm pairing, enable Trusted mode, enable native mode, turn lending on) require **user presence** verified by the OS (Touch ID / password on macOS, Windows Hello / password, polkit on Linux). Actions that **decrease** access (revoke, Stop all lending, unpair, decline) never need it. Job submission cannot reach consent actions at all (separate API scope). | T1, T4 |
| **I14** | Blob transfer requires a live grant (active, or paused by laptop protections) from the receiver to the sender; never an expired, revoked or declined one. Blobs are namespaced per borrower: a borrower can only query or fetch blobs it uploaded or its own tasks produced, and they count against its grant's disk quota. Once a borrower holds no live grant (revoked, expired, declined, unpaired, lending turned off), the lender deletes its whole namespace and records that in the audit log. | T1 |

---

## 5. Threats and controls

### 5.1 Malicious borrower attacking the lender (T1)

| Threat | Controls | Milestone |
|---|---|---|
| Run code without consent | I1. Grants are created only by the lender's user, stored on the lender, signed by the lender's key, bound to the borrower's key. | M1 |
| Read lender's files / steal credentials | Container mode: per-task workspace is the only mount; no host home, no Docker socket, no devices (GPU only if granted). Native mode: runs as dedicated `gmc-guest` OS account that has no access to the lender's home directory. | M1 / M4 |
| Escalate inside the container | Non-root UID, `no-new-privileges`, all capabilities dropped, default seccomp profile, read-only root filesystem, rootless runtime where available (Podman rootless on Linux). On macOS/Windows the container also sits inside a VM (Docker Desktop / Podman machine / WSL2). | M1 |
| Pivot into the lender's LAN | I5. Network `none` by default. `internet` mode blocks RFC 1918, link-local, CGNAT, loopback and the lender's own addresses. **The environment build step follows the same rule**: it runs borrower-chosen install scripts and URLs, so until LAN blocking exists on a platform, environment builds there are offline only (the borrower downloads packages and ships them as blobs). | M1 (`none`, offline builds), M4 (`internet` and online builds with LAN block) |
| Change packages kept between tasks, or read another borrower's | On a macOS sandbox lender a borrower's packages are unpacked once (every blob hash-checked) into its own blob namespace and linked into each task folder. The sandbox profile lets that task read only that one folder; writes, mode changes, unlinks, renames (of the folder or its parents) and hard links out of it are refused (hostile test), and other borrowers' tasks cannot read it. Counted in the borrower's disk quota; deleted with its namespace. | M2 |
| Fill the lender's disk or read another borrower's files through blob transfer | I14. Blob messages need an active grant; per-borrower namespaces; quota-counted; deleted as soon as the borrower holds no live grant (no cross-grant cache in v1: privacy over speed). | M1 |
| Exhaust CPU/RAM/disk, fork bombs | Hard caps from the grant: `--cpus`, `--memory` = `--memory-swap` (no swap), `--pids-limit`, tmpfs and workspace size quotas, per-task timeout, max concurrent tasks. | M1 |
| Make the laptop unusable / drain battery | Defaults on laptops: **idle-only**, **pause on battery**, **pause when hot**. Lender's own activity pauses tasks. Tray icon always shows when a peer is using the machine. | M1 (enforcement), M3 (tray icon) |
| Exploit our parser with malformed messages | Rust with `#![forbid(unsafe_code)]` in our crates; message size limits; strict protobuf decoding; per-peer rate limits and timeouts; fuzzing of every decoder (cargo-fuzz) in CI. | M1 / M5 |
| Install-time scripts in native mode | Consent screen states: "Package installs run their scripts as the guest account on this machine." Native mode is a separate per-peer opt-in. | M4 |
| Container-runtime or kernel 0-day escape | Residual risk (section 7). Optional stronger isolation (gVisor / Kata / microVM) to evaluate for v1.x. | — |

### 5.2 Malicious lender attacking the borrower (T2)

| Threat | Controls | Milestone |
|---|---|---|
| Read borrower's code/data | **Cannot be prevented** (lender has root). Disclosed on every first submit: "This peer can see the code and data you send it." | M1 |
| Steal secrets sent by accident | I7. Default excludes: `.env*`, `*.pem`, `*.key`, `id_*`, `.aws/`, `.ssh/`, `.npmrc`, `.pypirc`, `.netrc`, `*.p12`, credential files; secret-pattern scan of the upload set warns before sending. Private-index credentials are never forwarded; the borrower downloads packages and ships them instead. | M1 / M2 |
| Steer the borrower's package build | The lender reports its Python and platform in a probe task; the borrower accepts only known values (Python 3.x, CPython, listed architectures, glibc/musl/macOS version patterns) before any of it reaches a command line. Packages are wheels only (`--no-build`: nothing from a package runs on the borrower), pinned, hash-checked when the index provides hashes, from the borrower's own index settings. A lying lender can only make the borrower download other wheels for it. | M2 |
| Learn the borrower's secrets from other accounts on the lender | Task data never goes on a command line (which other local accounts can list): Standard-mode arguments travel as a file in the task folder, secrets named with `gmc.Secret` as environment variables of the task (Docker gets the names only and reads the values from its own environment). Audit logs on both sides record secret names, never values. | M2 |
| Learn secrets from the shipped packages | Only installed package files are sent (paths, URLs and VCS sources in the package list are refused). In the package folder, a file whose SHA-256 matches its package's `RECORD` is published package content and skips the secret scan and name excludes (packages carry example keys and CA bundles); every other file there gets both. Entry-point scripts (which name a borrower path) and `direct_url.json` are removed. A credential written into a project file as `scheme://user:password@host` is caught by the secret scan. | M2 |
| Return results that execute code on the borrower | I6 (no pickle by default; safe formats only: JSON, msgpack, Arrow, `.npy` with `allow_pickle=False`, files). I8 for files. | M2 |
| Return wrong results | Content-addressed outputs; optional **redundant execution** (run on two peers, compare digests) for critical tasks. | v1.x |
| Hold tasks hostage / slow down | Timeouts, retries on another peer or locally, per-peer health scoring. | M2 |
| Fake capabilities (claims a GPU it lacks) | Capabilities are hints; scheduling verifies by outcome; misbehaving peers are flagged in the dashboard. | M2 |

### 5.3 Network attacker on the same Wi-Fi (T3)

| Threat | Controls | Milestone |
|---|---|---|
| Eavesdrop / tamper | All traffic is QUIC + TLS 1.3 (iroh). Each device's Ed25519 public key *is* its TLS identity, so every connection is mutually authenticated. | M1 |
| Man-in-the-middle during pairing | Pairing uses a **commit-then-reveal short authentication string** (see `pairing.md`): both screens show the same 6-digit code, and both users confirm. An active attacker has a 1-in-1,000,000 chance per attempt; attempts are rate-limited. | M1 |
| Pairing spam / social engineering | Pairing requests are accepted only while the user has opened pairing mode (2-minute window). Max 3 attempts per window. Incoming requests show the requester's device name **and** key fingerprint. | M1 |
| Spoofed discovery adverts | Discovery is only a hint. Identity is proven by the key at connection time; a spoofed advert cannot impersonate a paired device. | M1 |
| Tracking the user across networks via mDNS | Discovery modes: **Off**, **Paired devices only** (default), **Everyone for 10 minutes** (for pairing). iroh's mDNS module (`iroh-mdns-address-lookup` 0.6) advertises the device's **permanent public key** as its mDNS instance name, which would let anyone on the network track a device. So we do not use it. **Built (M1):** our own `_gimmecores._udp` adverts (`mdns-sd`). "Paired devices only" (default) advertises, per paired device, a 16-byte identifier `SHA-256(label ‖ k ‖ advertiser ‖ 15-min window)` under a per-pair key `k` derived from the pairing nonces (never sent; a man in the middle would have failed the code check). No device name, no permanent key, host name = the identifier. Only **while the user has pairing mode open** (2 minutes) does the device also advertise its name and key, so a nearby device can pair without a ticket. **Off** = no adverts, no listening. Adverts are hints only: a matching identifier updates a paired device's address; identity is still proven by its key on connect. Devices paired before this change have no key and are not discovered until paired again. | M1 |
| Leaking presence or metadata to third-party servers | iroh by default connects to a relay and publishes the endpoint to n0's DNS service. **v1 disables both**, verified in iroh 1.4 source: we never apply the `N0` preset (the only place relays and Pkarr/DNS publishing are added), set `RelayMode::Disabled`, clear address lookup, and compile iroh **without** its `portmapper` feature so it never asks the router to open ports (UPnP/NAT-PMP/PCP). A test asserts the endpoint advertises only IP addresses. Hosted relays come later as an opt-in premium feature; relays see only encrypted traffic plus who-talks-to-whom metadata, which will be disclosed. | M1 |
| Replay of old messages | TLS 1.3 per-connection keys; grants carry IDs and expiry; task IDs are single-use. | M1 |
| Denial of service | Connection and request rate limits per source; unpaired connections are closed right after the handshake unless pairing mode is open. | M1 |

### 5.4 Local attacker on the same machine (T4)

| Threat | Controls | Milestone |
|---|---|---|
| Another local user drives your daemon | Local API on a Unix domain socket in the user's runtime directory with `0600` permissions; Windows named pipe with an ACL for the current user only. | M1 |
| A script, an SDK dependency, or a native task running as you approves its own grant | Two API scopes on separate sockets: **Client** (submit jobs, request grants, read status) and **Control** (consent actions). Consent-increasing Control calls require OS-verified user presence (I13). Native tasks normally run as the `gmc-guest` account and cannot open either socket. | M1 (scopes), M1 macOS/Linux + M4 Windows (user presence) |
| An AI agent (through `gmc mcp`) is talked into misusing what it was given, e.g. by a prompt injected in a file, a web page or a task's own output | `gmc mcp` (the MCP server agents use) reaches the daemon only through four Client calls: status, peers, grants and submitting a job; never the Control socket, `RequestGrant`, `StopAllLending` or `LinkTest` (a test checks the code for them). So it cannot ask for, approve or widen access: grants still come from the user and the person at the lender, with presence (I13). It sends only folders inside the roots fixed when it starts (default: its starting folder; `/` and the home folder are refused; symlinks resolved), keeps the secret scan and default excludes (no `--allow-secret`), and cannot send environment variables, extra files or attachments, write outputs outside the folder, use Trusted mode or give a task network access; unknown arguments are refused. Tool output is labelled as untrusted text from another machine. Ending the agent session cancels its running tasks on the lender, as does Ctrl-C in `gmc run`. Limits, stated plainly: an agent that can also run shell commands has the whole `gmc` CLI (including `--allow-secret`) and your files anyway, so these limits bind agents that have only the MCP tools; approvals rely on presence, which `gmcd --no-presence` turns off; and what a task prints is chosen by code running on the lender. | M1 |
| Malware running as you | Out of scope to fully prevent (it already has your privileges). Mitigated by: identity key stored in the OS keychain (macOS login Keychain: built, opt-in with `gmcd --identity-store keychain`; the key file is moved in, read back before the file is deleted, and never exported again, so the trusted `gmcd` binary cannot be used to read it out. Verified on the item's access list: only the creating `gmcd` (by code hash) may decrypt, so other programs get a Keychain prompt. Because ad-hoc-signed builds change that hash, macOS asks again after every upgrade; it becomes the default once releases are Developer ID signed. A denied or locked Keychain stops `gmcd` cleanly, so launchd does not restart it into repeated prompts. Windows Credential Manager/DPAPI later. Linux keeps the `0600` file: the Secret Service hands secrets to any program of the same user without asking), and audit log visibility. | M1 |

### 5.5 Malicious website attacking the dashboard (T5)

| Threat | Controls | Milestone |
|---|---|---|
| CSRF from a web page to `localhost` | Dashboard binds to `127.0.0.1` on a random port; opened only via `gmc dashboard`, which passes a one-time token exchanged for an `HttpOnly; SameSite=Strict` session cookie; state-changing requests require a CSRF token and matching `Origin`. | M3 |
| DNS rebinding | Reject any request whose `Host` header is not exactly `127.0.0.1:<port>` or `localhost:<port>`. | M3 |
| XSS in peer-supplied strings (device names, logs) | Strict Content-Security-Policy; all peer-supplied text rendered as text, never HTML; length limits. | M3 |
| Desktop app | Tauri app talks to the daemon over the local socket/IPC, not over HTTP; Tauri capability allow-list limits what the web view can call. | M3 |

### 5.6 Supply chain (T6)

| Control | Milestone |
|---|---|
| Minimal dependencies; `cargo-deny` (licences, advisories, duplicate crates) and `cargo-audit` in CI; Dependabot/Renovate with review. | M1 |
| Signed releases (Sigstore/cosign or minisign) with published checksums and SLSA build provenance from CI. | M5 |
| Auto-updater pins the release-signing public key; refuses unsigned or older builds (I12). | M5 |
| PyPI publishing via Trusted Publishing (OIDC) with attestations; no long-lived tokens. | M2 |
| SBOM (CycloneDX) per release; reproducible builds as a goal. | M5 |
| Branch protection, required reviews, signed tags for releases, DCO sign-off on commits. | M0 |

### 5.7 Stolen or lost device (T7)

| Control | Milestone |
|---|---|
| Keys in the OS keychain (protected by the login password / Secure Enclave or TPM where the OS provides it). | M1 |
| Remove a device from any other paired device: deletes its key from the trust list and revokes all its grants. | M1 |
| Grants expire by default (default 2 hours, max 30 days); trusted relationships require re-confirmation every 30 days. | M1 / M2 |
| Premium (later): central revoke for team devices. | v1.x |

---

## 6. Trusted mode (in v1)

Trusted mode lets Python code use `cloudpickle` so lambdas, closures, notebook cells and live
objects work, and lets GimmeCores host frameworks that pickle in both directions (joblib, Dask, Ray).
**Pickle is code.** A peer that can send you a pickle can run any code on your machine.

Rules:
- It is a property of a **pair** of devices, enabled on **both** devices, each showing the warning:
  *"Trusted mode lets this device run any code on your machine through returned results. Only
  enable it between your own devices or someone you trust completely."*
- It must also be requested in code: `gmc.Pool(trusted=True)`. Neither side alone is enough.
- It expires after 30 days unless re-confirmed, and is shown with a distinct badge everywhere.
- Python `major.minor` and `cloudpickle` versions must match; otherwise the task is refused (prevents
  confusing failures, not attacks).
- Containers on the lender are unchanged: Trusted mode lowers the **borrower's** protection, not
  the lender's sandbox.
- Premium team policy (later) can forbid Trusted mode between devices of different owners.
- Implementation (M2): each side's flag lives only on that device; the lender issues a Trusted
  grant only while its own flag is on, the borrower asks for and accepts one only while its own
  is. The decision to unpickle is made by the borrower's daemon (`JobDone.trusted_results`,
  re-checked when the task ends), never by anything the lender sends; a standard pool has no
  pickle decoder. Turning it off, lapsing or unpairing ends Trusted grants both ways.
- The pickled payload is scanned for secrets like project files (a captured notebook variable
  can hold an API key); sending a flagged payload needs an explicit opt-in in code.

There is no technical control that makes Trusted mode safe against a malicious trusted peer.
That is by design and is stated in the UI.

---

## 7. Residual risks we cannot remove

| Risk | Why it remains | What we tell users |
|---|---|---|
| A lender can read everything you send it | The lender controls its hardware and OS. Confidential-computing hardware is not available on consumer laptops in a usable form. | "Only send code and data you are comfortable sharing with this peer." |
| Container or kernel escape 0-days | All sandboxes have bugs. On macOS/Windows a VM boundary adds a layer; on Linux the kernel is shared. | Keep your container runtime and OS updated; optional stronger isolation planned. |
| CPU side-channel attacks (Spectre-class) between a task and the lender's own processes | Inherent to sharing a CPU. | Do not lend a machine while it handles highly sensitive work. |
| A malicious peer in Trusted mode | By design (section 6). | Only between your own devices. |
| Wrong results from a dishonest lender | Detection needs redundant execution. | Use redundant execution for results that matter (v1.x). |
| macOS cannot hard-cap memory for native tasks | No enforced per-process memory limit on macOS. | Native tasks on macOS get a watchdog (kills over-limit tasks after the fact); use container mode for hard caps. |

---

## 8. Open security questions (to resolve in M1)

1. Can a dedicated `gmc-guest` account on macOS use the GPU (Metal) from a non-GUI session? If not, native Metal tasks must run as the lender's own user, and the consent screen must say so (I13 still protects consent actions).
2. Per-platform implementation of `internet`-without-LAN egress filtering inside Docker Desktop's VM, Podman machine and WSL2 — and on Linux **without root**, since `gmcd` runs unprivileged (I9). Candidates: user-mode networking (pasta/slirp4netns) with an allow/deny policy, or a userspace egress proxy.
3. Rootless Docker vs Podman as the default Linux runtime.
4. Secret-scanning rule set: adopt an existing open rule set (e.g. gitleaks rules) or ship a minimal one.
5. ~~iroh configuration~~ — **resolved (iroh 1.4.1)**: relays and n0 publishing are opt-in and disabled; port mapping is compiled out; the mDNS module exposes the stable public key, so we listen only by default and build our own rotating-ID advert (see 5.3). Still open: whether iroh lets us prefer a specific interface (Thunderbolt over Wi-Fi); it accepts a custom path selector and per-socket `bind_addr`, to evaluate in the link-test work.
6. Cross-platform file-name rules for blob trees: Windows reserved names (`CON`, `NUL`, …), backslashes, trailing dots/spaces, and case-insensitive collisions on macOS/Windows — reject at plan time (by M4).
7. User-presence APIs per platform (LocalAuthentication, Windows Hello, polkit) for a background daemon, and the fallback for headless Linux/Pi (CLI password prompt or "consent only from another paired device"). **M1 answer:** macOS uses LocalAuthentication (device-owner policy: Touch ID or login password) and Linux uses polkit `auth_self` from the daemon. A machine that cannot show a prompt is started with `gmcd --no-presence`: that run only, audited, never saved. Through the socket, `SetPresence(false)` succeeds only after a *verified* prompt, so a script cannot wait for the OS check to be unavailable and then switch it off. Peer-chosen names shown in prompts lose control and bidi/zero-width characters and quotes. Residual risk, stated plainly: presence stops scripts, dependencies and AI agents that only reach the socket; anything that can run commands as you can also restart the daemon with `--no-presence` or edit `settings.json` (see "Malware running as you"); the daemon records "presence checks OFF" in the audit log and warns at every such start.

## 9. Reporting vulnerabilities

See [`SECURITY.md`](../../SECURITY.md).
