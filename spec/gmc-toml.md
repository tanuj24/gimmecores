# `gmc.toml` specification

Status: draft (M0), schema version 1.

`gmc.toml` describes tasks in a language-neutral way. The CLI reads it; SDKs generate the
same structure in memory. It lives at the project root.

## Example

```toml
version = 1

[env]                               # default environment for all tasks
lock = "uv.lock"                    # exactly one of: lock, image, native

[task.test]
run       = "pytest -q {shard}"     # shell-free argv split; {shard} filled per shard
shards    = 4                       # split into N parallel tasks
inputs    = ["src/**", "tests/**", "pyproject.toml", "uv.lock"]
outputs   = ["reports/"]
resources = { cpus = 2, memory = "4g" }
timeout   = "30m"
retry     = 2

[task.render]
call      = "app.render:render"     # Python SDK entry point (module:function)
inputs    = ["src/**", "assets/**"]
outputs   = ["out/"]
resources = { cpus = 4, memory = "8g", gpu = "cuda" }
env       = { image = "pytorch/pytorch:2.5.1-cuda12.4-cudnn9-runtime" }
```

## Top level

| Key | Type | Required | Meaning |
|---|---|---|---|
| `version` | int | yes | Schema version. Must be `1`. |
| `env` | table | no | Default environment (see below). |
| `exclude` | array of globs | no | Extra excludes added to the defaults for every task. |
| `task.<name>` | table | at least one | Task definitions. Names: `[a-z0-9][a-z0-9_-]*`. |

## `env`

Exactly one of:

| Key | Type | Meaning |
|---|---|---|
| `image` | string | OCI image reference. Resolved to a digest at plan time; the digest is what runs. |
| `lock` | string | Path to a lockfile (`uv.lock`, `poetry.lock`, `requirements.txt`, `package-lock.json`, …). The lender builds an image from it once, cached by digest. |
| `native` | table | `{ os = "macos" \| "linux" \| "windows", arch = "arm64" \| "x86_64", tools = { python = "3.12" } }`. Runs only on peers with a matching OS/arch whose lender allowed native mode. Available from M4. |

Optional with `image`/`lock`: `python = "3.12"` (interpreter for lock builds), `offline = true`
(ship dependencies from the borrower; no network during the build). Until M4, `offline = true` is
the only supported mode.

## `task.<name>`

Exactly one of `run` or `call`.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `run` | string or array | — | Command. A string is split into argv with POSIX shell-word rules but **not** run through a shell. Use an array to be explicit. To use a shell, write `["sh", "-c", "…"]`. |
| `call` | string | — | `module:function` for SDK tasks. |
| `shards` | int | 1 | Run N copies with `{shard}` = `1/N … N/N` and env `GMC_SHARD`, `GMC_SHARDS`. Built as `gmc run --shards N` and the MCP `run` tool's `shards` (the CLI does not read `gmc.toml` yet). |
| `inputs` | array of globs | `["**"]` | Files to send, relative to the project root. |
| `exclude` | array of globs | `[]` | Added to the default excludes. |
| `outputs` | array of paths | `[]` | Files/directories returned. Must be relative, no `..`. |
| `resources` | table | `{ cpus = 1, memory = "1g" }` | `cpus` (number), `memory` (`"512m"`, `"8g"`), `gpu` (`"cuda"`, `"metal"`), `disk` (`"10g"`). |
| `env` | table | top-level `env` | Per-task environment override. |
| `environment` | table of strings | `{}` | Environment variables set **explicitly** for the task. Values starting with `secret:` (`"secret:HF_TOKEN"`) are read from the borrower's environment and shown to the user before sending. |
| `network` | `"none"` \| `"internet"` | `"none"` | Network while running. Requires a grant that allows it. `internet` available from M4. |
| `timeout` | duration | `"1h"` | Per task. |
| `retry` | int | 2 | Retries on another peer or locally after failure or peer loss. |
| `peers` | array of strings | any | Restrict to these peer names or fingerprints. |
| `deps` | array | `[]` | `cargo`, `npm`, `go`: fetch the lockfile's dependencies on the borrower and send them (built as `gmc run --deps`). |
| `local_fallback` | bool | true | Run locally when no peer can take the task. Built as `gmc run --where auto` (the CLI's default stays `remote`). |

## Default excludes (always applied)

`.git/`, `.env`, `.env.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`, `id_ed25519*`,
`id_ecdsa*`, `.ssh/`, `.aws/`, `.azure/`, `.gcloud/`, `.config/gcloud/`, `.kube/`, `.docker/config.json`,
`.npmrc`, `.pypirc`, `.netrc`, `*.keystore`, `credentials*.json`, `service-account*.json`,
plus everything in `.gitignore` and `.gmcignore`.

A file matched by these can only be sent by naming it explicitly in `inputs`, and the CLI asks for
confirmation. The upload set is also scanned for secret patterns before sending (threat model I7).

## Validation rules

- Unknown keys are errors (catches typos).
- `outputs` paths must be relative and must not contain `..` or start with `/`.
- `cpus`, `memory`, `disk` must be positive; `shards` 1–10,000; `retry` 0–10.
- `call` tasks require an environment with a Python interpreter.
- `gpu = "metal"` requires `env.native` with `os = "macos"`.
