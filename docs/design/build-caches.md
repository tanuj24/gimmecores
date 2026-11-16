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
by their whole content (a build script may watch a folder: blake3's does). The borrower's clock is never
used, so a borrower whose clock is behind cannot make a changed file look older than the build.
Times are set without following links. Tools that hash content (Go, Gradle, Bazel) do not need
this and are not affected.

Measured on GimmeCores itself (`cargo build -p gimmecores-cli`, about 24,000 dependency files):
on a Linux file system, the warm build after a cold one (about 80 s) finished in 0.24 s with
nothing rebuilt.

**Docker Desktop on macOS** keeps a file time that a program sets only to the whole second in the
folders it shares with containers. Cargo sets its own reference times that way, so in such a
container Cargo rebuilds even on a second run in the same folder, with or without GimmeCores.
A Mac lender's containers therefore gain little from a Cargo cache; its sandbox, and Linux
lenders, gain fully. Caches of tools that do not rely on set times (npm, Go, Gradle)
are not affected.

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
