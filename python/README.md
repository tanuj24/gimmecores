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
- The project folder (nearest `pyproject.toml`, else the script's folder) is sent, minus
  `.gitignore`d files, secrets and `.gmcignore`; only changed files are re-sent.
- Where it runs depends on what the lender lends: its sandbox (its installed Python) or a
  container (pass `image="python:3.12-slim"`, which must already be on the lender).
- In the sandbox, the lender's `python3` comes from Homebrew, python.org's installer, the
  system or Xcode's tools; a Python installed inside the lender's home folder (pyenv, conda)
  is not visible to tasks.

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
- Without a Trusted grant (and with `local_fallback=True`), the same code runs locally.

Not yet: environments built from lockfiles, `gmc.File`, a Jupyter extension and a joblib
backend.
