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
  borrower's folder path, never the path itself) and the cache's path. Another borrower, or
  another project of the same borrower, never sees it.
- **Only while a grant lives.** It is part of the borrower's namespace: counted against its
  grant's disk limit and deleted with everything else of that borrower's once it holds no live
  grant (I14 unchanged). The next grant starts cold.
- **Comes back only if asked**: list it with `--out` too to get its contents back here.

## How it stays safe

No sandbox gains a new opening. Before a task runs, its cache folder is **moved** into the task
folder at its path (one rename on the same disk); after the task, once its outputs are
collected, it is moved back. During the task it is simply part of the task folder, under the
same rules as before (the OS sandbox, or the container's only mount).

- **Moving back goes through real folders only.** If the task replaced the cache's path, or any
  folder above it, with a link (to the lender's own files, say), the cache is dropped instead:
  nothing outside the task folder is ever moved. Tested with links at both places, and the test
  fails without the check.
- **What a task locked is opened again** (folders back to owner-only `0700`, never following
  links) when the cache goes back, so the next task's folder can still be measured against the
  disk limit.
- **One task at a time.** A cache is held by the task it was moved into; another task that wants
  it meanwhile starts cold, and its copy is discarded with its folder.
- **Kept only while the grant lives**: a cache whose borrower has no live grant when its task ends
  is discarded, not stored back.

Lenders older than 0.1.1 ignore the cache fields: tasks run as before, cold.

Tested with the test runner and with the real macOS sandbox and real Docker (a cache with a locked
folder in it, carried to the next task, then deleted with the namespace).
