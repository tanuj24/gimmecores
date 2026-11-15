# GPU lending

Status: **design, not built**. Waiting for the owner's decisions in "To decide" before any
code. Today GPUs are detected and their use is shown ("This computer" bars), but nothing is
lent: grants carry no GPU, and neither sandbox gives a task a GPU (checked below).

## What it would let a borrower do

Run work that needs a GPU on a lender that has one: model training and inference (PyTorch with
Apple's Metal backend, MPS, on a Mac; CUDA on Linux with an NVIDIA card), rendering, simulation.
The grant names the GPU, the lender's owner sees it in the request, and approves it like CPU and
memory.

## Why it is not just one more resource

A CPU task talks to the kernel through system calls the sandboxes already filter. A GPU task
also talks to the **graphics driver**, a large body of kernel code that was written for the
owner's own apps, not for code from another device. Driver bugs are a known route out of a
sandbox (GPU drivers on every platform have had privilege-escalation bugs). So GPU lending adds
attack surface on the lender, and the design has to keep that surface as small as the work
allows, say so plainly in the request, and stay off unless the owner chooses it.

## Checked on this Mac (M2 Max, macOS 27), 2026-11-15

A small Metal compute job (two arrays added on the GPU, shader compiled from source at run
time, as PyTorch's MPS backend does):

| Sandbox profile | Result |
|---|---|
| Today's task profile (`sandbox.rs`), unchanged | No GPU at all: `MTLCreateSystemDefaultDevice()` returns nothing |
| + `(allow iokit-open)` (any driver client) | The GPU opens; compiling the shader fails: the sandbox blocks Apple's shader compiler service |
| + `(allow mach-lookup)` (any service) only | No GPU |
| + `(allow iokit-open (iokit-user-client-class "AGXDeviceUserClient"))` and `(allow mach-lookup (global-name "com.apple.MTLCompilerService"))` | **Works**: right answer from the GPU |

So Metal compute needs exactly two openings, both narrow:

- `AGXDeviceUserClient`: the GPU driver's per-process client. Not `IOSurfaceRootUserClient`,
  which lets a process look up graphics surfaces by number, including other apps' and the
  screen's. It was not needed and stays closed.
- `com.apple.MTLCompilerService`: Apple's shader compiler, which runs in its own process under
  Apple's own sandbox. The task's shader source reaches it.

PyTorch 2 with its Metal backend (MPS), from a folder the task can read, run with the
lender's Homebrew Python: under today's profile it says "no supported Metal GPU was found";
with exactly the two rules above a 2048 × 2048 matrix product runs on the GPU and is right.
Not checked yet: other frameworks (MLX, JAX), a Mac with an AMD or Intel GPU.

**Measuring a task's GPU use on macOS:** each GPU client lists the process that created it
and its accumulated GPU time (`ioreg -c AGXDeviceUserClient`: `IOUserClientCreator`
"pid N, name" and `AppUsage` → `accumulatedGPUTime`). Summed over the task's processes and
sampled like CPU time, that gives the task's own GPU use, not just the whole GPU's.

**Memory on macOS: today's measure misses GPU memory.** A process holding 4 GiB on the GPU
(PyTorch MPS) showed **326 MiB** of resident memory in `ps` (what the sandbox watches and
enforces today) and **4.1 GiB** of physical footprint (`vmmap`; the kernel's
`phys_footprint`, readable with `proc_pid_rusage` for the owner's own processes). Apple silicon
shares memory between CPU and GPU, so with today's measure a GPU task could use far more memory
than its grant. Metal lending therefore needs the memory limit enforced on physical footprint
first. (Footprint is also the better measure for CPU-only tasks: it counts compressed memory,
which resident memory does not.)

## Linux and NVIDIA (not checkable here)

- **Containers:** Docker with NVIDIA's container toolkit (`--gpus device=N`): the container
  gets the device nodes and the driver's user-space libraries. The other protections stay
  (no new privileges, capabilities dropped, read-only root, no network by default).
- **bubblewrap sandbox:** would need `/dev/nvidia*` (or `/dev/dri/renderD*`) bound in, plus the
  driver libraries: the same driver surface without Docker. Containers first.
- **Measuring:** `nvidia-smi --query-compute-apps=pid,used_memory` (per-process GPU memory),
  `nvidia-smi pmon` (per-process use); matched to the task's processes or container.
- **GPU memory cap:** NVIDIA cannot cap one process's GPU memory on consumer cards (MIG and MPS
  limits exist on data-center cards only). So a GPU is lent **whole**: one GPU task at a time,
  and the grant says so.
- No NVIDIA machine is available here, so by the project's rule CUDA lending stays refused
  until it is tested on real hardware.

## Proposal

1. **The borrower asks for it; off by default** (decided 2026-11-15). A grant request carries
   no GPU unless the borrower asks for one (`gmc grants request <device> --gpu`, a "GPU"
   choice in the app and SDK, off unless chosen). The lender's owner sees it on its own line
   in the request: "and its GPU: their code will use this computer's graphics driver". They
   approve it like the rest of the request (with presence), or accept the request without the
   GPU. A grant without a GPU never gives a task one.
2. **Whole GPU, one task at a time.** A grant with a GPU admits one GPU task at a time on that
   GPU; others wait. No splitting a GPU between borrowers.
3. **Narrowest opening.** macOS: the two rules above, added to the profile only for a task
   whose grant includes the GPU and that itself asked for it; every other task, under any
   grant, keeps today's profile.
   Linux: container mode with one named device; sandbox mode later, if ever.
4. **Measured and shown.** The task's own GPU time (macOS: per client; NVIDIA: per process)
   next to CPU and memory, on both sides; "not measured" where it cannot be read.
5. **Owner protection.** GPU tasks pause while the owner uses the computer by default (a GPU
   at full load makes the screen stutter), and on battery and heat as today.
6. **Memory by footprint.** On macOS the sandbox's memory limit moves from resident memory to
   physical footprint (above) before any GPU task runs; a task over its grant is stopped as
   today.
7. **Threat model.** New T1 rows: a driver bug used to leave the sandbox (residual risk,
   narrowed by 3 and by refusing GPU unless the owner chose it); reading another app's GPU
   memory or the screen (driver isolation per process; IOSurface lookups stay closed); using
   more memory than granted through the GPU (6).

## Decided

- The borrower asks for a GPU in its request; off by default (owner, 2026-11-15).

## To decide (the owner)

- Build Metal (macOS) first? It can be tested here; CUDA cannot.
- Is "one GPU task at a time, whole GPU" acceptable?
- Should GPU tasks pause while the owner uses the computer by default?
- An NVIDIA Linux machine for testing CUDA: is one available?
