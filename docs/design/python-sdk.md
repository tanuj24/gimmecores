# Python SDK

Status: draft (M0). Target: M2. Package: `gimmecores` on PyPI (free as of 2026-11-12), imported as `import gimmecores as gmc`.

## Example

```python
import gimmecores as gmc

@gmc.task(cpus=2, memory="4g")
def render(frame: int) -> dict:
    ...
    return {"frame": frame, "ms": 412}

if __name__ == "__main__":
    with gmc.Pool() as pool:                 # peers with active grants
        results = pool.map(render, range(500))
```

Also provided: `gmc.Executor` with the `concurrent.futures.Executor` interface
(`submit`, `map`, `shutdown`), and `pool.imap_unordered` for streaming results.

## What happens

1. **Code**: the project root (nearest `pyproject.toml`, else the script's directory) is hashed
   file by file. `.gitignore`, `.gmcignore` and the default secret excludes apply
   (threat model I7). Only files the peer lacks are uploaded.
2. **Environment**: from `uv.lock`, `poetry.lock`, `requirements*.txt` or `pyproject.toml`, in
   that order; or `env=gmc.Image("…")`; or `env=gmc.Native(os="macos")` (from M4). The
   lender builds it once in a Linux container and caches it by digest. Until LAN blocking exists
   (M4), the **borrower downloads the packages** for the lender's platform (Linux wheels) and
   ships them; the lender's build runs offline.
3. **Calls**: each call is `module:function` plus arguments in a safe format.
4. **Batching**: calls are grouped (like `multiprocessing`'s `chunksize`, chosen automatically
   from measured round-trip time and task duration) and run in warm containers kept for the grant.
5. **Results**: returned in safe formats; exceptions come back as `gmc.RemoteError` with the
   remote type name, message and traceback text.
6. **Recovery**: failed or lost calls retry on another peer or locally (`retry=2` default).
   With no peers, everything runs locally in a process pool, so the same code always works.

## Serialization

| Mode | Formats | When |
|---|---|---|
| Standard (default) | JSON, msgpack; NumPy arrays as `.npy` (`allow_pickle=False`); pandas/Arrow tables as Arrow IPC; `gmc.File` for files | Always available |
| Trusted | `cloudpickle` for functions, arguments and results | Only if Trusted mode is enabled on **both** devices **and** `gmc.Pool(trusted=True)` |

Standard mode never unpickles anything from a peer, and results are decoded only in the format
the borrower requested; a result claiming another format is an error (threat model I6).

## Rules for users (standard mode)

| Rule | Reason |
|---|---|
| Functions must be importable from a module; scripts need `if __name__ == "__main__":` | The lender imports the function by name. Same rule as `multiprocessing` with the `spawn` start method (default on macOS and Windows). |
| No lambdas, closures, or functions defined in notebook cells | They cannot be imported by name. Use Trusted mode for these. |
| Arguments and results must be safe-format data or `gmc.File` | No pickle from peers. |
| Local files must be passed with `gmc.File(path)`; outputs returned or declared with `outputs=` | The lender cannot see your disk, localhost services or databases. |
| Tasks must be safe to run more than once | Retries after peer loss. |
| Environment variables are never sent; pass secrets explicitly with `gmc.Secret("NAME")` (shown to the user before sending) | Avoid accidental leaks. |
| Mac-only packages fail in Linux containers | Use cross-platform lockfiles, or `env=gmc.Native(os="macos")` to target Mac peers. |
| Small tasks gain little | Each batch costs at least one network round trip plus transfer time. **Estimate**: tasks under ~1 s of compute gain little over Wi-Fi unless batched; the SDK measures and warns. |

## Packages and private indexes

- Until M4, the borrower downloads packages (Linux wheels for the lender's CPU) and ships them;
  the lender never goes online to build. Packages that only exist as source distributions are
  built offline on the lender from the shipped sources.
- From M4, where the platform supports LAN blocking, lenders may download public packages during
  the build step (shown on the consent screen).
- Private indexes: credentials are **never** forwarded. The borrower downloads the wheels
  locally and ships them as content-addressed blobs.

## Trusted mode extras

- Lambdas, closures, notebook cells (`%load_ext gimmecores` in Jupyter).
- joblib backend: `with joblib.parallel_backend("gimmecores"): ...` (joblib supports custom
  backends; exact integration to be validated in M2).
- Dask / Ray (after v1): GimmeCores starts their workers inside grants; documented as two-way trust.
- Python `major.minor` and `cloudpickle` versions must match between the two sides.

## Public API sketch

```python
gmc.task(cpus=1, memory="1g", gpu=None, env=None, timeout="1h", retry=2)   # decorator
gmc.Pool(peers=None, trusted=False, local_fallback=True, max_workers=None)
gmc.Executor(...)                       # concurrent.futures compatible
gmc.File(path) / gmc.Dir(path)      # inputs and outputs
gmc.Secret(name)                        # explicit, visible secret forwarding
gmc.Image(ref) / gmc.Lockfile(path) / gmc.Native(os=..., tools=...)
gimmecores.peers()                             # list peers, grants, link stats
gmc.RemoteError                         # remote exception wrapper
```
