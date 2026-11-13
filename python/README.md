# gimmecores (Python)

Run Python functions on your other devices' spare cores, with their owner's consent.

```python
import gimmecores as gmc

@gmc.task(cpus=1, memory="1g")
def render(frame: int) -> dict:
    return {"frame": frame, "pixels": frame * 1000}

if __name__ == "__main__":
    with gmc.Pool() as pool:                    # uses your active grants
        results = pool.map(render, range(100))  # in order, like multiprocessing
```

Requires a running `gmcd` on this computer with an active grant from another device
(`gmc grants request <device>`). Without one, the same code runs locally in a process pool.

## Standard mode (the default)

- Functions are called by name: define them in a module (scripts need
  `if __name__ == "__main__":`), not as lambdas, closures or notebook cells.
- Arguments and results travel as JSON. Nothing from another device is ever unpickled; a
  non-JSON result is an error.
- Exceptions come back as `gmc.RemoteError` with the remote type, message and traceback.
- Calls are batched automatically: batches start at one call and grow or shrink from measured
  task times towards about 2 s of work per task (so a network round trip and a task start are
  not paid per call), never more than a fair share of what is left. `chunksize=` fixes it.
- The project folder (nearest `pyproject.toml`, else the script's folder) is sent, minus
  `.gitignore`d files, secrets and `.gmcignore`; only changed files are re-sent.
- Where it runs depends on what the lender lends: its sandbox (its installed Python) or a
  container (pass `image="python:3.12-slim"`, which must already be on the lender).
- In the sandbox, the lender's `python3` comes from Homebrew, python.org's installer, the
  system or Xcode's tools; a Python installed inside the lender's home folder (pyenv, conda)
  is not visible to tasks.

## Files (`gmc.File`, `gmc.Dir`)

```python
@gmc.task
def thumbnail(photo):                         # a gmc.File: open(photo), photo.read_bytes()
    out = photo.name + ".thumb.jpg"
    ...                                       # write it in the task's folder
    return gmc.File(out)                      # comes back as a gmc.File on this device

with gmc.Pool() as pool:
    thumbs = pool.map(thumbnail, [gmc.File(p) for p in photos])
```

- Files and folders you pass (also inside lists, tuples and dicts) are sent with the task and
  checked like project files: a folder gets the default excludes, and every file is scanned for
  secrets; a match stops the task. A file you name explicitly is sent even if its name looks
  sensitive (`server.pem`), but its content is still scanned.
- The lender cannot see anything else on your disk: only what you pass travels.
- A function that returns `gmc.File`/`gmc.Dir` sends that file or folder back. It is checked like
  every returned file (size cap, no paths outside the results folder, no symlinks) and saved
  under `Pool(results_dir=...)` (default: a new temporary folder, kept after the pool closes).
  A result can only name a file that actually came back from that task.
- Without a lender the same code runs locally and receives your own files.

## Secrets (`gmc.Secret`)

```python
pool.map(partial(download, token=gmc.Secret("HF_TOKEN")), urls)   # the function gets the value

@gmc.task(secrets=["HF_TOKEN"])         # or: set HF_TOKEN for the task, for libraries that
def fetch(name): ...                    # read it themselves
```

- Your environment variables are never sent unless you name them like this.
- The value travels encrypted as an environment variable of the task: never in a file, on a
  command line (where other accounts on the lender could list it) or in a log. Both devices'
  audit logs record the name only. The pool says on stderr, once, which secret goes to which
  device.
- The lender can read it: send it only to devices you trust with it.
- A secret written straight into an argument is caught by the secret scan (arguments travel as
  a file, scanned like any other) and stops the task; `Pool(send_flagged_payload=True)` sends it
  anyway once you are sure.

## Packages

The project's packages go with it. GimmeCores reads `uv.lock`, else `requirements.txt`, else the
`dependencies` in `pyproject.toml` (or `Pool(env=gmc.Lockfile("path"))`; `env=None` for none):

```sh
pip install 'gimmecores[envs]'      # uv, which resolves and installs them on this device
```

- **The lender never goes online.** This device asks the lender which Python and platform it
  runs, resolves the packages for that (not for this device), downloads the wheels with your
  own index settings, installs them into a cache folder here and sends that folder with the
  task. Credentials for private indexes stay in your uv/pip settings on this device and are
  never sent. A credential written into a project file (`https://user:token@...`) is caught by
  the secret scan and stops the task.
- **Nothing from a package runs on this device.** Wheels only: packages that exist only as
  source are refused, never built here. Paths, URLs and git sources in the package list are
  refused for now (they can pull in local folders or record credentialed URLs).
- **Bytecode for the lender's Python is made here** (with that Python version, found or fetched
  by uv) so large packages import quickly on the lender. Compiling translates the source; it
  does not run it.
- **Cached on both sides.** Built folders are kept in `~/Library/Caches/gimmecores/envs` (macOS)
  or `~/.cache/gimmecores/envs` (set `GMC_CACHE_DIR` to move it); the lender keeps the files it
  received while you hold a grant, so later tasks send nothing again.
- **On the lender** the task sees the standard library, your project and these packages only:
  the lender's own site-packages are left out, so results don't depend on what its owner
  installed. Package files count against the grant's disk limit: stored once, plus unpacked
  once (kept, on macOS sandbox lenders) or once per running task (elsewhere).
- With `image=`, the image is the environment and nothing is added; pass `env=gmc.Lockfile(...)`
  to install on top of the image's Python (built for the image's Linux).
- A macOS lender keeps your packages unpacked between your tasks (macOS checks every new
  native library on first load, which would cost seconds per task): one copy per package set,
  every file hash-checked when it is unpacked, readable by your tasks and changeable by none of
  them, invisible to other devices' tasks, counted against your grant's disk limit and deleted
  with your grant. NumPy + pandas: about 0.6 s per task after the first.

## Trusted mode (`trusted=True`)

For lambdas, closures, notebook functions and results that are not JSON (sets, objects, NumPy
arrays...): functions, arguments and results travel as pickles (`cloudpickle`).

**Pickles are code.** A device you trust this way can run anything on yours through the
results it returns. Use it only between your own devices or with someone you trust completely.

```sh
pip install 'gimmecores[trusted]'
gmc trust <device> on                       # on BOTH devices (asks Touch ID / password)
gmc grants request <device> --trusted       # a Trusted grant, which its owner approves
```

```python
k = 10
with gmc.Pool(trusted=True) as pool:
    pool.map(lambda x: x * k, range(5))     # [0, 10, 20, 30, 40]
```

- Both devices must turn it on for each other; it lapses after 30 days, and turning it off on
  either side ends every Trusted grant between them (running tasks stop).
- Results are decoded only when this device's own daemon confirms that Trusted mode was on here,
  under a Trusted grant, for the whole task. Nothing the lender sends can make that true, and a
  standard `Pool` has no way to unpickle at all.
- The lender's sandbox (or container) is unchanged: Trusted mode lowers the borrower's
  protection, not the lender's.
- Python `major.minor` must match on both sides (checked by the lender before anything is
  loaded). The borrower's own `cloudpickle` is sent with each task, so its version always
  matches. Exceptions come back as `gmc.RemoteError` with the original in `.exception`.
- What is sent is scanned for secrets (tokens, private keys) like any project file, including
  the pickled function, the variables it captures and its arguments; a match stops the task.
  `Pool(trusted=True, send_flagged_payload=True)` sends it anyway, once you are sure.
- Without a Trusted grant (and with `local_fallback=True`), the same code runs locally.

### joblib and Jupyter (Trusted mode)

```python
import joblib, gimmecores as gmc

gmc.register_joblib()
with joblib.parallel_config(backend="gimmecores"):          # Pool options go here too
    results = joblib.Parallel(n_jobs=-1)(joblib.delayed(f)(x) for x in xs)
```

- Only the calls travel: the lender needs neither joblib nor gimmecores. Batches are sized for
  a network round trip (1-10 s of work each). A remote error is raised as the original
  exception. `require="sharedmem"` makes joblib run threads on this computer instead.
- The calling script's project (nearest `pyproject.toml`) is sent so its modules import on the
  lender; pass `project=` to choose, or `project=False` to send none.

In Jupyter, `%load_ext gimmecores` adds `%gmc`: your devices, whether Trusted mode is on for each
side, and your grants. Functions defined in cells need Trusted mode, which a notebook cannot
turn on (it needs your Touch ID or password); `%gmc` says what to run.
