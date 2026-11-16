# Links and performance

Status: draft (M0). Numbers below are **expected ranges from public reports**, not promises.
GimmeCores measures every link itself (see "Link test") and shows real numbers per peer.

## Supported links

| Link | v1 | Typical throughput | Typical round trip | Confidence |
|---|---|---|---|---|
| Wi-Fi 5/6/6E/7 | Yes | Wi-Fi 6 at 80 MHz, 576 Mbps link rate: estimated **~150–200 Mbps** device-to-device. Vendors claim 1–2 Gbps for a single Wi-Fi 7 device. | Measured on one Wi-Fi 6 Mac: **4.2 / 13.1 / 73 ms** (min/avg/max to router); device-to-device roughly double | Latency measured; throughput **estimated**, no public device-to-device test found |
| Ethernet 1 / 2.5 GbE | Yes | ~0.94 / ~2.35 Gbps | ~0.1–0.3 ms | General knowledge, not sourced |
| Ethernet 10 GbE | Yes | 9.41 Gbps (iperf3) | 10–21 µs app-to-app in papers; ping shows more | Sourced |
| Thunderbolt 3 (IP) | Yes | ~9 Gbps (Linux) | ~0.3 ms (assumed same as TB4) | Throughput sourced; latency assumed |
| Thunderbolt 4 / USB4 (IP) | Yes (Mac↔Windows best-effort) | 9–19 Gbps (Mac↔Linux 15.9/18.8; Linux 9–11; Win↔Win 12–16.6) | ~0.3 ms | Community reports |
| Thunderbolt 5 (IP) | Yes | Not yet measured (80 Gbps signalling) | — | Gap |
| Thunderbolt 5 RDMA (Mac↔Mac) | No (via exo/MLX later) | — | Reported < 50 µs | Secondhand |
| USB 3 "data transfer" bridge cables | No | 5 Gbps advertised, ~1 Gbps reported | — | No evidence they expose a network interface |

Known issue: one report of Mac→Windows IP over Thunderbolt failing on macOS 26.2.

**Encryption must not be the bottleneck.** SSH/SCP over a ~18 Gbps Thunderbolt link reached
only ~460 MB/s. GimmeCores' QUIC transport must use hardware-accelerated AEAD and multiple
streams; the link test reports encrypted throughput, which is what users actually get.

### Measured so far (GimmeCores itself)

| Build | Link | Round trip (median) | Encrypted throughput |
|---|---|---|---|
| release, M1 | loopback, one Mac | 0.15 ms | ~1.4 Gbps up and down |
| 0.1.0 (2026-11-15) | Wi-Fi, two Macs on the same network | 35.4 ms (min 12.4, p95 242.8) | 37 Mbps up, 25 Mbps down |

On that Wi-Fi pair, an empty task (`gmc run -- true`) took about 0.22 s from start to finish;
uploading changed files comes on top of that.

One QUIC stream with per-chunk copies is enough for Wi-Fi and 1 GbE but would cap Thunderbolt and
10 GbE; parallel streams and zero-copy chunking are on the roadmap.

## What each link is good for

| Workload | Wi-Fi | 1 GbE | 10 GbE / Thunderbolt |
|---|---|---|---|
| Whole jobs: tests, scripts, builds, containers, batch GPU jobs | Good if inputs are small or cached | Good | Excellent |
| Many small tasks (per-file compile steps) | Marginal (latency per task) | Good | Good |
| Model sharding by layers (exo, llama.cpp RPC, prima.cpp) | Works, slow | Bottleneck | Good |
| Tensor parallelism | No | No | Thunderbolt 5 RDMA / 10 GbE+ |
| Distributed training (gradient sync) | No | Communication-bound | Marginal |
| Transparent remote RAM / GPU | No | No | No |

## Link test

Run automatically at pairing and on demand (`gmc link-test <peer>`), over GimmeCores' own
encrypted channel:

1. Link type detection (interface: Wi-Fi, Ethernet, Thunderbolt Bridge / USB4 network).
2. Round-trip time: 50 small request/response pairs → min, median, p95.
3. Throughput: 2 s upload and 2 s download with parallel QUIC streams.
4. Stored per peer per interface, refreshed in the background with tiny probes.

Shown on the peer card, e.g.
`Thunderbolt 4 · 16.8 Gbps · 0.3 ms · good for: builds, tests, containers, model sharding`.

Before a job, the planner shows an estimate:
"Uploading 1.2 GB not already on the peer: ~55 s over Wi-Fi / ~0.6 s over Thunderbolt."

Goal: when several links reach the same peer, prefer the fastest measured one. Whether iroh lets us choose the interface is an open question (threat model section 8).

## Sources

See [`feasibility.md`](feasibility.md#sources).
