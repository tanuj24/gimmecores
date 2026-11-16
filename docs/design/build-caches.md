# Build caches on the lender

Status: built on `v2` (issue #26). Owner's decision (2026-11-16): a cache lives only while the
borrower holds a live grant.

## Why

Every `gmc run` started cold: `target/`, `node_modules`, `.gradle`, ccache and the like were
rebuilt each time, which wiped out the gain for Rust, Node and JVM projects.

## What it is

```console
$ gmc run --cache target -- cargo build --release
$ gmc run --cache .cache/npm --cache node_modules -- npm test
```

A cache is a folder of the project (at most 8 per task) that the lender keeps for that borrower
and that project between tasks. The MCP `run` tool takes `caches` too.

- **Not uploaded.** The borrower leaves the cache's path out of what it sends (an exclude anchored
  at the project's root, like `/target` in `.gitignore`), so a local `target/` stays local.
- **Kept per borrower and per project**, in the borrower's own namespace on the lender:
  `blobs/<borrower>/caches/<key>`, where the key is a hash of the project (a hash of the
  borrower's folder path, never the path itself), how the task runs (the OS sandbox or a
  container: their builds differ) and the cache's path. Another borrower, or another project
  of the same borrower, never sees it.
- **Only while a grant lives.** It is part of the borrower's namespace: counted against its
  grant's disk limit and deleted with everything else of that borrower's once it holds no live
  grant (I14 unchanged). The next grant starts cold.
- **Comes back only if asked**: list it with `--out` too to get its contents back here.

## File times

A task folder is made anew from the upload each time, so every file in it would look just
edited, and tools that compare file times (Cargo, make) would rebuild everything, cache or not.
The first real-size check showed exactly that: a warm `cargo build` of GimmeCores recompiled
all 328 crates.

So the lender keeps, beside each cache, when each file of the task folder last got its content,
by the lender's own clock (`<key>.times`, written and read by the daemon only, counted in the
namespace). When a task with caches starts, a file whose content is what the cache's last build
saw gets that time back; every other file, including one changed back to an older content, gets
the time the task starts, which is later than any earlier build. Folders follow the same rule
by their whole content (a build script may watch a folder: blake3's does). The borrower's clock
is never used, so a borrower whose clock is behind cannot make a changed file look older than
the build. Times are set without following links, from a time read back from the file system
(Linux stamps files from a coarser clock than the system's).

## Where a Cargo cache helps (0.1.1)

Cargo also rebuilds a vendored crate (`--deps cargo`) when the folder it sits in moves, and it
compares the times it sets itself. What was seen:

| Lender runs the task in | Warm `cargo build` | Seen |
| --- | --- | --- |
| a container, Linux lender | nothing rebuilt (expected) | emulated only: GimmeCores itself in a Linux container, the task folder made anew at the same path with the times the lender gives, built again in 0.24 s after 80 s cold. Not yet run through `gmc run` on a Linux lender (the test VM's disk is too small for `rust:1`). |
| a container, Docker Desktop on macOS | most crates rebuilt | `gmc run --deps cargo --cache target --image rust:1-bookworm` on GimmeCores, between two daemons on one Mac: the warm runs were not faster. Docker Desktop keeps a time a program sets only to the whole second in shared folders, so files Cargo writes later in the same second look newer than its own records. This happens with a plain `docker run` too. |
| the OS sandbox (macOS, Linux) | vendored crates rebuilt (expected) | Not run. Each task runs in a folder of its own path (`work/<task>`), and moving the same build between two folders made Cargo rebuild every vendored crate ("the path to the source changed"). |

A cache still holds what the task left (`target/` comes back as it was); it is the build tool
that decides to redo the work. Tools that neither compare file times nor record the folder's
path are not affected by any of this. Making the sandbox case work would mean running a
project's tasks at a fixed path; that changes what a leftover process on macOS could reach
(see below), so it is left for the owner to decide.

## How it stays safe

No sandbox gains a new opening. Before a task runs, its cache folder is **moved** into the task
folder at its path (one rename on the same disk); after the task, once its outputs are
collected, it is moved back. During the task it is simply part of the task folder, under the
same rules as before (the OS sandbox, or the container's only mount).

- **Moving back goes through real folders only, by file descriptor.** If the task replaced the
  cache's path, or any folder above it, with a link (to the lender's own files, say), the cache
  is dropped instead: nothing outside the task folder is ever moved. Every folder is opened from
  the one above it without following links, and the move is kept only if what arrived is the
  very folder that was checked (same device and inode). On macOS a process a task left behind
  can keep writing in its folder even after the folder moves; this is what stops it from
  swapping a folder for a link between the check and the move (tested with such a process).
- **What a task locked is opened again** (folders the daemon owns back to owner-only `0700`,
  never following links) when the cache goes back, so the next task's folder can still be
  measured against the disk limit. On Linux, files a container makes belong to the container's
  unprivileged user; the hand-back step has already opened those to everyone, and they are
  kept as they are.
- **Within the disk limit.** A cache that would take the borrower over its grant's disk limit is
  dropped, and so is the cache of a task stopped on the disk limit.
- **One task at a time.** A cache is held by the task it was moved into; another task that wants
  it meanwhile starts cold, and its copy is discarded with its folder.
- **Kept only while the grant lives**: a cache whose borrower has no live grant when its task ends
  is discarded, not stored back.

Lenders older than 0.1.1 ignore the cache fields: tasks run as before, cold.

Tested with the test runner and with the real macOS sandbox, Docker Desktop on macOS and Docker
on Linux (a cache with a locked folder in it, carried to the next task, then deleted with the
namespace), and file times across tasks (unchanged, changed, changed back).
