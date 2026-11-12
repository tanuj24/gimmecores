# Feasibility: what GimmeCores can and cannot do

Status: research summary, 2026-11-12. Confidence levels reflect the evidence found at that date.

## Can build

| Capability | Confidence |
|---|---|
| Discovery on the same LAN (mDNS) plus manual address / pairing code | High |
| Pairing, grants with limits and expiry, revoke; CLI + dashboard + desktop app | High |
| Content-addressed task bundling; upload only missing files; stream logs; return outputs | High (Bazel REAPI precedent) |
| Container execution with hard CPU/RAM caps (Linux; macOS/Windows via VM) | High |
| Native execution with explicit consent | High |
| Whole GPU jobs: NVIDIA in containers (Linux/WSL2); Apple GPU native only | High / Medium |
| Spreading already-split work across peers (test shards, build steps, batches) | High |
| Any language via CLI + task file and local API; Python SDK | High |
| Combined RAM for software that splits itself (exo, llama.cpp RPC, prima.cpp) — capacity, not speed | High that it works |
| Framework-level GPU remoting (llama.cpp RPC, MLX distributed) on cable links | Medium-High |
| Frameworks that split themselves (Ray, Dask, PyTorch distributed) on trusted peers | Medium |
| Link test, per-peer speed labels, per-job transfer estimates | High |

## Cannot build

| Item | Confidence | Reason |
|---|---|---|
| Another machine's RAM as memory for **any** program | High | Needs ~4–5 µs per access; Wi-Fi ≥ 4 ms, Thunderbolt ~300 µs, TB5 RDMA < 50 µs (and two-sided only). No remote-swap mechanism on macOS/Windows; on Linux over Thunderbolt it is only about as fast as local SSD swap. |
| A remote GPU that looks local to any program (per-call) | High | Needs 5–20 µs round trips; rCUDA ~114% overhead on 1 GbE; per-call remoting exists only for CUDA. |
| Splitting any running program across machines | High | Needs kernel changes (MOSIX-style, abandoned — general knowledge, not re-checked); sequential programs cannot be auto-parallelised. |
| Live-migrating running processes across machines/OSes | High | CRIU is Linux-only (general knowledge, not re-checked); process state is not portable across OSes. |
| macOS-only jobs on Linux/Windows peers | High | macOS licence allows VMs only on Apple hardware, max 2 per Mac. |
| CUDA jobs on Macs | High | No NVIDIA GPUs on Apple silicon. (One model *can* span Mac + NVIDIA via llama.cpp RPC.) |
| Sandboxed Apple-GPU jobs | Medium-High | Docker on Mac has no Metal passthrough; Podman/libkrun offers Vulkan compute only. |
| Hard RAM caps for native jobs on macOS | Medium-High | macOS does not enforce per-process memory limits; watchdog only. |
| Cross-platform RDMA over Thunderbolt | Medium | Apple's RDMA is Mac-only (TB5, macOS 26.2+). |
| Reliable Mac↔Windows Thunderbolt | Medium (best-effort) | Windows 11 supports USB4 networking; one failure report on macOS 26.2. |
| Discovery across routers or on client-isolated guest Wi-Fi | Medium-High | mDNS does not cross routers (general knowledge); manual address instead. |
| Bundling with no environment declared | High | The lender needs your interpreter and packages. |
| Guaranteed exactly-once execution | High | A basic distributed-systems limit; tasks are made safe to retry. |
| Hiding the borrower's data from the lender | High | Lender has root; no usable confidential computing on consumer hardware (general knowledge). |

## Device roles

| Device | Role |
|---|---|
| macOS, Linux, Windows desktops/laptops | Borrow and lend |
| Raspberry Pi (ARM64 Linux) | Lend light jobs (small RAM, slow storage) |
| iPhone | Consent, control, submit; lend only built-in fixed task types (App Store guideline 2.5.2, per developer-forum and secondary sources) |
| Android | Same via Play Store (Play policy on downloaded code — general knowledge, not checked); more freedom via sideloading/F-Droid |

## Sources

- Apple TN3205, RDMA over Thunderbolt: https://developer.apple.com/documentation/technotes/tn3205-low-latency-communication-with-rdma-over-thunderbolt
- GPU remoting network requirements (2024): https://arxiv.org/html/2401.13354v1
- rCUDA over GbE vs InfiniBand (2013): https://riunet.upv.es/bitstream/10251/67332/1/reano_cluster2013_autor.pdf
- Juice FAQ: https://juice-labs.github.io/juice-docs/docs/juice/faq
- sccache distributed quickstart: https://docs.rs/crate/sccache/0.17.0/source/docs/DistributedQuickstart.md
- Bazel REAPI v2: https://pkg.go.dev/github.com/bazelbuild/remote-apis/build/bazel/remote/execution/v2
- Wasmtime security: https://docs.wasmtime.dev/security.html
- exo README: https://github.com/exo-explore/exo/blob/main/README.md
- Jeff Geerling, RDMA over TB5: https://jeffgeerling.com/blog/2025/15-tb-vram-on-mac-studio-rdma-over-thunderbolt-5
- llama.cpp distributed benchmarks (10 GbE): https://github.com/kjaiswal/llama-cpp-distributed-benchmarks
- llama.cpp RPC README: https://sources.debian.org/src/llama.cpp/8064%2Bdfsg-1/tools/rpc/README.md
- prima.cpp: https://arxiv.org/html/2504.08791v2
- Petals: https://arxiv.org/html/2312.08361
- Thunderbolt networking Mac↔Linux: https://personal-website-production.pages.dev/blog/thunderbolt-networking-is-underused
- netdev thread on thunderbolt-net throughput: https://lists.openwall.net/netdev/2025/05/27/110
- Microsoft USB4 interdomain: https://learn.microsoft.com/en-us/windows-hardware/design/component-guidelines/usb4-interdomain-connections
- Mac→Windows TB failure on 26.2: https://developer.apple.com/forums/thread/812612
- 10 GbE latency paper: https://cs.uwaterloo.ca/~brecht/servers/readings-new/hoti11_17_Hurwitz_G-USE_THIS_ONE.pdf
- macOS VM limits: https://eclecticlight.co/2022/08/04/virtualisation-on-apple-silicon-macs-8-how-apple-limits-vms/
- macOS RLIMIT_RSS: https://developer.apple.com/forums/thread/742328
- Podman GPU on macOS: https://developers.redhat.com/articles/2025/06/05/how-we-improved-ai-inference-macos-podman-containers
- Ray token auth: https://docs.ray.io/en/latest/ray-security/token-auth.html
- App Store guideline 2.5.2 discussion: https://developer.apple.com/forums/thread/826166
- iroh local discovery: https://docs.iroh.computer/connecting/local-address-lookup
- UniFFI: https://github.com/mozilla/uniffi-rs
- Tauri 2.0: https://v2.tauri.app/blog/tauri-20/
- RustCrypto spake2: https://docs.rs/spake2
