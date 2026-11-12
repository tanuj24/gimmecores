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

## Standard mode (the only mode in this version)

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

Not yet: Trusted mode (cloudpickle, lambdas, notebooks), environments built from lockfiles,
`gmc.File`.
