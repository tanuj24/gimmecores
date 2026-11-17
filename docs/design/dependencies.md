# Dependencies without network on the lender

Status: built on `v2` (issue #27).

Tasks have no network (I5), so `npm ci`, `cargo build` with crates.io dependencies or `go build`
with modules could not fetch anything on the lender. The Python SDK already solves this for
Python: it installs from the lockfile on the borrower and sends the packages. `gmc run --deps`
does the same for Cargo, npm and Go, and keeps the no-network guarantee.

```console
$ gmc run --deps cargo -- cargo test
$ gmc run --deps npm -- sh -c "npm ci && npm test"
$ gmc run --deps auto -- make        # whichever of Cargo.lock, package-lock.json, go.mod are here
```

## How

The **borrower** fetches what its lockfile names, with its own network, into a cache of its own
(`~/Library/Caches/GimmeCores/deps` on macOS, `$XDG_CACHE_HOME/gimmecores/deps` on Linux),
keyed by the lockfile's hash, so an unchanged lockfile is fetched once. The project folder is
never written. The dependencies go with the task like any upload (only what the lender lacks
travels), and the tool on the lender finds them offline. Nothing changes on the lender.

| Tool | Fetched here with | Sent as | The task gets |
|---|---|---|---|
| Cargo | `cargo vendor --locked` | `.gmc-sdk/deps/cargo`, plus a Cargo home whose config replaces crates.io with it | `CARGO_HOME=.gmc-sdk/deps/cargo-home`, `CARGO_NET_OFFLINE=true` |
| Go | `go mod vendor -o` | the task's `vendor/` (only if the project has none of its own) | `GOFLAGS=-mod=vendor`, `GOPROXY=off`, `GOTOOLCHAIN=local` |
| npm | `npm ci --ignore-scripts` on a copy of `package.json` and `package-lock.json`, with a cache of its own | that cache, under `.gmc-sdk/deps/npm` | `npm_config_cache` there, `npm_config_offline=true` |

No install script runs on the borrower (`--ignore-scripts`; `cargo vendor` and `go mod vendor`
run no package code).

## Published content and the secret scan

Dependencies carry test keys and certificates that the secret scan and the `*.pem` exclude would
otherwise stop (and a crate with a file missing fails Cargo's checksum check). As for Python
packages, a file matching the checksum its package manager recorded is published content and is
sent as it is: each crate's `.cargo-checksum.json` (SHA-256 per file), and an npm cache's content
files (named by their own SHA-512). Every other file, Go's vendored sources included, gets the
default excludes and the secret scan like the project.

## Limits

- Cargo: run cargo from the project's root (the Cargo home is given relative to it). Only
  crates.io dependencies: git dependencies and other registries are refused here, before
  anything is sent (they would be fetched on the lender, which has no network for tasks).
- npm: packages with prebuilt binaries for one platform (optional dependencies such as esbuild's)
  need the same OS and CPU on both sides, or a container.
- The lender's own tools are used in the sandbox: a Rust installed with `rustup` in the owner's
  home is not visible to sandboxed tasks (by design: `~/.cargo` can hold a registry token). Use
  a system-wide install (Homebrew, a distribution's package) or a container image such as
  `rust:1`. `gmc peers` and `gmc doctor --peer` show what a lender's sandbox has.
- The MCP server does not fetch dependencies: it never runs anything on this computer.

Tested: a crate with a crates.io dependency built offline on the lender (test runner and a
`rust:1-bookworm` container under `--network none`), npm's offline install (also with real
packages from the registry), a Go module vendored here and built there with an empty module
cache and `GOPROXY=off`, checksum-verified files sent past the scan while unlisted keys are left
out. At real size: GimmeCores itself (about 24,000 files of dependencies) built offline with
`--deps cargo --image rust:1-bookworm` between two daemons on one Mac (about 100 s; the upload
of those files takes about 10 s). For what `--cache target` adds, see build-caches.md.
