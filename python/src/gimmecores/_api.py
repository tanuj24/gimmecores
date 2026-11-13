"""Public API: `task`, `Pool`, `Executor`, `RemoteError`, `grants`."""

from __future__ import annotations

import base64
import concurrent.futures as cf
import importlib
import json
import os
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

import grpc

from . import _daemon, _env
from ._proto.gimmecores.local.v1 import local_pb2 as l
from ._proto.gimmecores.peer.v1 import peer_pb2 as pb
from ._worker import MARK, SDK_DIR, SOURCE, TRUSTED_SOURCE

#: Largest encoded argument set per task (they travel on the lender's command line).
MAX_ARGS_BYTES = 96 * 1024
#: Largest pickled function and arguments per task in Trusted mode (sent as a file).
MAX_TRUSTED_BYTES = 48 << 20


class GimmeCoresError(Exception):
    """GimmeCores could not run the work (no daemon, no grant, the lender refused, ...)."""


class RemoteError(Exception):
    """Your function raised on another device. `type`, `message` and `traceback` describe it.
    In Trusted mode, `exception` is the original exception object (also its `__cause__`)."""

    def __init__(
        self,
        type: str,
        message: str,
        traceback: str = "",
        peer: str = "",
        exception: BaseException | None = None,
    ):
        self.type, self.message, self.traceback, self.peer = type, message, traceback, peer
        self.exception = exception
        self.__cause__ = exception
        where = f" (on {peer})" if peer else ""
        super().__init__(f"{type}: {message}{where}")


def _size(s: str | int) -> int:
    if isinstance(s, int):
        return s
    units = {"k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40}
    s = s.strip().lower().rstrip("b").rstrip("i")
    return int(float(s[:-1]) * units[s[-1]]) if s and s[-1] in units else int(s)


@dataclass(frozen=True)
class _Options:
    cpus: float = 1
    memory: int = 1 << 30
    timeout: int = 3600


def task(
    fn: Callable | None = None,
    *,
    cpus: float = 1,
    memory: str | int = "1g",
    timeout: int = 3600,
):
    """Marks a function's resource needs. The function itself is unchanged (call it locally as
    usual); `Pool.map` and `Executor.submit` use these values."""

    def mark(f: Callable) -> Callable:
        f.__gmc_options__ = _Options(cpus=cpus, memory=_size(memory), timeout=int(timeout))
        return f

    return mark(fn) if fn is not None else mark


def _options(fn: Callable) -> _Options:
    return getattr(fn, "__gmc_options__", _Options())


def _source_file(fn: Callable) -> Path:
    mod = sys.modules.get(fn.__module__)
    file = getattr(mod, "__file__", None)
    if not file:
        raise GimmeCoresError(
            f"{fn.__qualname__} has no source file (defined in a notebook or console?); "
            "Standard mode calls functions by import name"
        )
    return Path(file).resolve()


def _project_root(fn: Callable, explicit: Path | None) -> Path:
    """The folder that is sent: `project=` if given, else the nearest folder holding
    pyproject.toml above the function's file. Without either, refuse rather than send a whole
    folder such as Downloads."""
    file = _source_file(fn)
    if explicit is not None:
        root = explicit.resolve()
        if root not in file.parents:
            raise GimmeCoresError(f"{file} is not inside the project folder {root}")
        return root
    for d in file.parents:
        if (d / "pyproject.toml").is_file():
            return d
    raise GimmeCoresError(
        f"no pyproject.toml above {file}; pass project=<folder> to choose what is sent"
    )


def _import_name(fn: Callable, root: Path) -> tuple[str, str, str]:
    """(module, qualname, import folder relative to the project) the lender uses. Scripts are
    imported by their file name; packages under src/ get src/ on the import path."""
    if "<locals>" in fn.__qualname__ or fn.__name__ == "<lambda>":
        raise GimmeCoresError(
            f"{fn.__qualname__} is a lambda or a nested function; Standard mode calls functions "
            "by import name, so define it at the top level of a module"
        )
    file = _source_file(fn)
    module = fn.__module__
    if module == "__main__":
        module = file.stem
    # The folder the module path starts from: strip one parent per package level.
    depth = module.count(".") + (1 if file.name == "__init__.py" else 0)
    base = file.parent
    for _ in range(depth):
        base = base.parent
    try:
        rel = base.relative_to(root).as_posix()
    except ValueError:
        raise GimmeCoresError(f"{file} is not inside the project folder {root}") from None
    return module, fn.__qualname__, rel


def _encode(
    module: str, qualname: str, base: str, calls: list, tag: str, env: bool = False
) -> str:
    try:
        spec = json.dumps(
            {"module": module, "qualname": qualname, "base": base, "calls": calls, "tag": tag,
             "env": env}
        )
    except (TypeError, ValueError) as e:
        raise GimmeCoresError(
            f"arguments must be JSON-serializable in Standard mode: {e}"
        ) from None
    data = base64.b64encode(spec.encode()).decode()
    if len(data) > MAX_ARGS_BYTES:
        raise GimmeCoresError(
            f"arguments for one task are too large ({len(data)} bytes encoded; limit "
            f"{MAX_ARGS_BYTES}); use a smaller chunksize or pass files in the project folder"
        )
    return data


def _parse_results(stdout: str, n: int, peer: str, tag: str) -> list:
    """Strictly decodes the lender's tagged result line (lender output is untrusted)."""
    prefix = f"{MARK}{tag} "
    line = next((x for x in reversed(stdout.splitlines()) if x.startswith(prefix)), None)
    if line is None:
        raise GimmeCoresError("the lender returned no results")
    try:
        items = json.loads(line[len(prefix):])
    except ValueError:
        raise GimmeCoresError("the lender returned malformed results") from None
    if not isinstance(items, list) or len(items) != n:
        raise GimmeCoresError("the lender returned the wrong number of results")
    out = []
    for it in items:
        if isinstance(it, dict) and set(it) == {"ok"}:
            out.append(("ok", it["ok"]))
        elif isinstance(it, dict) and set(it) == {"error"} and isinstance(it["error"], dict):
            e = it["error"]
            out.append(
                (
                    "error",
                    RemoteError(
                        str(e.get("type", "Error")),
                        str(e.get("message", "")),
                        str(e.get("traceback", "")),
                        peer,
                    ),
                )
            )
        else:
            raise GimmeCoresError("the lender returned malformed results")
    return out


def _python_version() -> list:
    """Trusted mode needs the same Python major.minor on both sides (pickles do not travel
    between versions); the lender checks it before loading anything."""
    return list(sys.version_info[:2])


def _cloudpickle():
    try:
        import cloudpickle
    except ImportError:
        raise GimmeCoresError(
            "Trusted mode needs cloudpickle: pip install 'gimmecores[trusted]'"
        ) from None
    return cloudpickle


def _call_pickled(data: bytes):
    """Runs a cloudpickled call in a local worker process (Trusted mode's local fallback, so
    lambdas work there too). Local only: these bytes never come from another device."""
    import pickle

    fn, args, kwargs = pickle.loads(data)
    return fn(*args, **kwargs)


def _cloudpickle_files() -> list:
    """The borrower's own cloudpickle, sent with each Trusted task (pure Python), so both sides
    use exactly the same version."""
    cp = _cloudpickle()
    pkg = Path(cp.__file__).resolve().parent
    files = []
    for f in sorted(pkg.rglob("*.py")):
        rel = f.relative_to(pkg.parent).as_posix()
        files.append(l.InlineFile(path=f"{SDK_DIR}/lib/{rel}", data=f.read_bytes()))
    return files


def _parse_trusted(stdout: str, n: int, peer: str, tag: str, vouched: bool) -> list:
    """Trusted results: decoded with pickle ONLY if this device's own daemon vouched for them
    (Trusted mode on here, under a Trusted grant, for the whole task). Nothing the lender sends
    can make that true."""
    prefix = f"{MARK}{tag} "
    line = next((x for x in reversed(stdout.splitlines()) if x.startswith(prefix)), None)
    if line is None:
        raise GimmeCoresError("the lender returned no results")
    body = line[len(prefix):]
    if body.startswith("{"):
        try:
            why = json.loads(body).get("refused", "the lender refused the task")
        except (ValueError, AttributeError):
            why = "the lender returned malformed results"
        raise GimmeCoresError(str(why))
    if not vouched:
        raise GimmeCoresError(
            "not decoding the results: this device no longer confirms Trusted mode with "
            f"{peer or 'the lender'} (it was turned off or lapsed during the task)"
        )
    import pickle

    try:
        items = pickle.loads(base64.b64decode(body, validate=True))
    except Exception as e:
        raise GimmeCoresError(f"the lender's results could not be decoded: {e}") from None
    if not isinstance(items, list) or len(items) != n:
        raise GimmeCoresError("the lender returned the wrong number of results")
    out = []
    for it in items:
        if isinstance(it, tuple) and len(it) == 2 and it[0] == "ok":
            out.append(("ok", it[1]))
        elif isinstance(it, tuple) and len(it) == 3 and it[0] == "error":
            exc, tb = it[1], str(it[2])
            out.append(
                (
                    "error",
                    RemoteError(type(exc).__name__, str(exc), tb, peer, exception=exc)
                    if isinstance(exc, BaseException)
                    else RemoteError("Error", str(exc), tb, peer),
                )
            )
        else:
            raise GimmeCoresError("the lender returned malformed results")
    return out


def _active_grants(stub) -> list:
    resp = stub.ListGrants(l.ListGrantsRequest(include_inactive=False))
    return [g for g in resp.grants if not g.as_lender and g.state == pb.GRANT_STATE_ACTIVE]


def grants(home: str | os.PathLike | None = None) -> list[dict]:
    """Grants other devices gave this one:
    [{"peer", "cores", "memory_bytes", "modes", "trusted"}]."""
    stub = _daemon.client(_daemon.home(home))
    out = []
    for g in _active_grants(stub):
        lim = g.grant.limits
        out.append(
            {
                "peer": g.peer_fingerprint,
                "cores": lim.cpu_millis / 1000,
                "memory_bytes": lim.memory_bytes,
                "modes": [pb.ExecutionMode.Name(m) for m in g.grant.modes],
                "trusted": g.grant.trust == pb.TRUST_LEVEL_TRUSTED,
            }
        )
    return out


class Pool:
    """Runs calls on devices that granted you resources, or locally when none did.

    `peers`: device names or fingerprints to use (default: any with an active grant).
    `image`: run in this container image on the lender (it must already be there); default:
    the lender's sandbox with its installed Python. `max_workers`: tasks in flight at once.

    `env`: the Python packages your functions need. "auto" (default): the project's `uv.lock`,
    else `requirements.txt`, else the dependencies in `pyproject.toml`. Or `gmc.Lockfile(path)`,
    or None for only what the lender's Python has installed. This device resolves and downloads
    them (wheels only, with your own index settings; the lender never goes online), for the
    lender's Python and platform, and sends them with the task. They are cached here and on the
    lender, so later tasks send only what changed. Needs `uv` (pip install 'gimmecores[envs]').
    With `image=`, "auto" adds no packages (the image is the environment); a `gmc.Lockfile`
    installs on top of the image's Python, built for the image's platform.

    `trusted=True`: Trusted mode. Functions, arguments and results travel as pickles
    (cloudpickle), so lambdas, closures and notebook functions work. Pickles are code: a device
    you trust this way can run anything on yours through its results. It needs Trusted mode
    turned on for each other on both devices (`gmc trust <device> on`), a Trusted grant
    (`gmc grants request <device> --trusted`), and the same Python version on both.
    """

    def __init__(
        self,
        peers: list[str] | None = None,
        *,
        image: str | None = None,
        local_fallback: bool = True,
        max_workers: int | None = None,
        home: str | os.PathLike | None = None,
        project: str | os.PathLike | None = None,
        echo_output: bool = True,
        trusted: bool = False,
        send_flagged_payload: bool = False,
        env: Any = "auto",
    ):
        self.trusted = bool(trusted)
        self.env = env
        # Per lender: its Python (probed once) and the packages built for it.
        self._targets: dict = {}
        self._packages_for: dict = {}
        self._probe_locks: dict = {}
        # The daemon scans what is sent for secrets (tokens, keys) and refuses to send them.
        # In Trusted mode that includes the pickled function, its captured variables and its
        # arguments; True sends them anyway (you confirm they may leave this device).
        self.send_flagged_payload = bool(send_flagged_payload)
        self._scratch: Path | None = None
        if self.trusted:
            _cloudpickle()
        self.peers = list(peers or [])
        self.project = Path(project) if project is not None else None
        self.image = image
        self.local_fallback = local_fallback
        self.home = _daemon.home(home)
        self.echo_output = echo_output
        self._stub = None
        self._remote = False
        self._grants: list = []
        try:
            self._stub = _daemon.client(self.home)
            self._grants = self._usable_grants()
            self._remote = bool(self._grants)
        except (GimmeCoresError, grpc.RpcError):
            self._remote = False
        if not self._remote and not local_fallback:
            raise GimmeCoresError(
                "no active Trusted grant from another device (turn on Trusted mode on both "
                "devices with `gmc trust <device> on`, then `gmc grants request <device> "
                "--trusted`)"
                if self.trusted
                else "no active grant from another device (ask with `gmc grants request <device>`)"
            )
        self.max_workers = max_workers or (4 if self._remote else os.cpu_count() or 2)
        self._threads = cf.ThreadPoolExecutor(self.max_workers)
        self._local: cf.ProcessPoolExecutor | None = None
        self._lock = threading.Lock()

    def _usable_grants(self) -> list:
        grants = _active_grants(self._stub)
        peers = self._stub.ListPeers(l.ListPeersRequest()).peers
        if self.trusted:
            # The daemon enforces this too; here it only sizes the pool correctly.
            mine = {p.fingerprint for p in peers if p.trusted_mode_local}
            grants = [
                g
                for g in grants
                if g.grant.trust == pb.TRUST_LEVEL_TRUSTED and g.peer_fingerprint in mine
            ]
        if not self.peers:
            return grants
        wanted = {w.lower() for w in self.peers}
        fps = {
            p.fingerprint
            for p in peers
            if p.device_name.lower() in wanted or p.fingerprint.lower() in wanted
        }
        return [g for g in grants if g.peer_fingerprint in fps]

    @property
    def remote(self) -> bool:
        """True when calls go to other devices, False when they run locally."""
        return self._remote

    def __enter__(self) -> Pool:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self._threads.shutdown(wait=True)
        if self._local:
            self._local.shutdown(wait=True)
        if self._scratch is not None:
            import shutil

            shutil.rmtree(self._scratch, ignore_errors=True)

    # -------------------------------------------------------------- running chunks

    def _run_local(self, fn: Callable, calls: list) -> list:
        with self._lock:
            if self._local is None:
                self._local = cf.ProcessPoolExecutor()
        if self.trusted:
            cp = _cloudpickle()
            futs = [self._local.submit(_call_pickled, cp.dumps((fn, a, k))) for a, k in calls]
        else:
            futs = [self._local.submit(fn, *a, **k) for a, k in calls]
        out = []
        for f in futs:
            try:
                out.append(("ok", f.result()))
            except Exception as e:  # same contract as remote calls
                out.append(("error", e))
        return out

    def _empty_dir(self) -> Path:
        """An empty folder to send when there is no project (one per pool)."""
        with self._lock:
            if self._scratch is None:
                import tempfile

                self._scratch = Path(tempfile.mkdtemp(prefix="gmc-empty-"))
            return self._scratch

    def _trusted_root(self, fn: Callable) -> tuple:
        """(project folder or None, import folder) for a Trusted task. The project is still
        sent when there is one, so functions in its modules import as usual; lambdas and
        notebook functions travel by value."""
        root, base = None, "."
        try:
            root = _project_root(fn, self.project)
            file = _source_file(fn)
            module = fn.__module__ if fn.__module__ != "__main__" else file.stem
            depth = module.count(".") + (1 if file.name == "__init__.py" else 0)
            b = file.parent
            for _ in range(depth):
                b = b.parent
            base = b.relative_to(root).as_posix()
        except (GimmeCoresError, ValueError):
            if self.project is not None:
                root = Path(self.project).resolve()
        return root, base

    def _trusted_task(
        self, fn: Callable, calls: list, tag: str, root: Path | None, base: str, env: bool
    ) -> tuple:
        """(folder to send, argv, files) for a Trusted task."""
        cp = _cloudpickle()
        if root is None:
            root = self._empty_dir()  # nothing to send but the SDK's own files
        try:
            call = cp.dumps((fn, calls))
        except Exception as e:
            raise GimmeCoresError(f"the function or its arguments cannot be pickled: {e}") from None
        if len(call) > MAX_TRUSTED_BYTES:
            raise GimmeCoresError(
                f"the pickled function and arguments are {len(call) >> 20} MiB (limit "
                f"{MAX_TRUSTED_BYTES >> 20} MiB); use a smaller chunksize"
            )
        spec = json.dumps({"tag": tag, "python": _python_version(), "base": base, "env": env})
        files = [
            l.InlineFile(path=f"{SDK_DIR}/spec.json", data=spec.encode()),
            l.InlineFile(path=f"{SDK_DIR}/call.pkl", data=call),
            *_cloudpickle_files(),
        ]
        python = ["python3", "-S"] if env else ["python3"]
        return root, [*python, "-c", TRUSTED_SOURCE], files

    # -------------------------------------------------------------- packages

    def _mode(self) -> int:
        return pb.EXECUTION_MODE_CONTAINER if self.image else pb.EXECUTION_MODE_SANDBOX

    def _target(self, peer_fp: str) -> _env.Target:
        """The lender's Python and platform, asked once per lender, in the same way of running
        (sandbox or this image) the tasks will use."""
        with self._lock:
            lock = self._probe_locks.setdefault(peer_fp, threading.Lock())
        with lock:
            if peer_fp in self._targets:
                return self._targets[peer_fp]
            tag = os.urandom(8).hex()
            task = l.InlineTask(
                name="python probe",
                command=pb.Command(argv=["python3", "-c", _env.PROBE_SOURCE, tag]),
                resources=pb.Limits(cpu_millis=1000, memory_bytes=256 << 20),
                peers=[peer_fp],
                mode=self._mode(),
            )
            task.timeout.seconds = 120
            if self.image:
                task.env.image.reference = self.image
            job = l.JobSpec(project_root=str(self._empty_dir()), inline_tasks=[task])
            stdout, stderr, peer, finished, _ = self._submit(job, "", echo=False)
            self._check_finished(finished, stderr, peer)
            try:
                target = _env.parse_probe("".join(stdout), tag)
            except _env.EnvError as e:
                raise GimmeCoresError(str(e)) from None
            self._targets[peer_fp] = target
            return target

    def _packages(self, root: Path | None, peer_fp: str) -> Path | None:
        """The installed-packages folder to send to this lender, or None."""
        try:
            # An image is its own environment: "auto" adds nothing to it. An explicit
            # Lockfile still installs on top of the image's Python.
            env = None if self.image and self.env == "auto" else self.env
            source = _env.find_source(root, env)
            if source is None:
                return None
            target = self._target(peer_fp)
            key = (str(source), peer_fp)
            if key not in self._packages_for:
                self._packages_for[key] = _env.build(source, target)
            return self._packages_for[key]
        except _env.EnvError as e:
            raise GimmeCoresError(f"preparing packages: {e}") from None

    # -------------------------------------------------------------- one task

    def _check_finished(self, finished, stderr: list, peer: str) -> None:
        if finished is None:
            raise GimmeCoresError("the task ended without a result")
        if finished.status != pb.TaskResult.STATUS_SUCCEEDED:
            # The task itself did not complete (refused, timed out, revoked, crashed before
            # returning results): not an exception from the function.
            name = pb.TaskResult.Status.Name(finished.status).removeprefix("STATUS_").lower()
            detail = (finished.error.message or "".join(stderr)[-2000:]).strip()
            raise GimmeCoresError(f"the task on {peer or 'the lender'} ended: {name}: {detail}")

    def _submit(self, job, tag: str, echo: bool) -> tuple:
        """Runs a job; returns (stdout parts, stderr parts, lender, TaskFinished, vouched)."""
        stdout, stderr, peer, finished, vouched = [], [], "", None, False
        try:
            for ev in self._stub.SubmitJob(job):
                peer = ev.peer_fingerprint or peer
                kind = ev.WhichOneof("event")
                if kind == "task":
                    te = ev.task
                    which = te.WhichOneof("event")
                    if which == "log":
                        text = te.log.data.decode("utf-8", "replace")
                        if te.log.stream == pb.LogChunk.STREAM_STDERR:
                            stderr.append(text)
                            if echo:
                                sys.stderr.write(text)
                        else:
                            stdout.append(text)
                            if echo:
                                for line in text.splitlines(keepends=True):
                                    if not line.startswith(f"{MARK}{tag} "):
                                        sys.stdout.write(line)
                    elif which == "finished":
                        finished = te.finished
                elif kind == "done":
                    # Set by this device's own daemon, never by the lender.
                    vouched = ev.done.trusted_results
                    break
        except grpc.RpcError as e:
            raise GimmeCoresError(e.details() or str(e)) from None
        return stdout, stderr, peer, finished, vouched

    def _run_remote(self, fn: Callable, calls: list, peer_fp: str) -> list:
        opts = _options(fn)
        tag = os.urandom(8).hex()
        qualname = getattr(fn, "__qualname__", "call")
        if self.trusted:
            project, base = self._trusted_root(fn)
        else:
            project = _project_root(fn, self.project)
            module, qualname, base = _import_name(fn, project)
        packages = self._packages(project, peer_fp)
        if self.trusted:
            root, argv, files = self._trusted_task(
                fn, calls, tag, project, base, packages is not None
            )
        else:
            root = project
            python = ["python3", "-S"] if packages else ["python3"]
            argv = [*python, "-c", SOURCE,
                    _encode(module, qualname, base, calls, tag, packages is not None)]
            files = []
        attachments = (
            [l.Attachment(local_path=str(packages), path=f"{SDK_DIR}/env", packages=True)]
            if packages
            else []
        )
        task = l.InlineTask(
            name=qualname,
            command=pb.Command(argv=argv),
            files=files,
            attachments=attachments,
            resources=pb.Limits(
                cpu_millis=int(opts.cpus * 1000), memory_bytes=int(opts.memory)
            ),
            peers=[peer_fp],
            mode=self._mode(),
        )
        task.timeout.seconds = opts.timeout
        if self.image:
            task.env.image.reference = self.image
        job = l.JobSpec(
            project_root=str(root),
            inline_tasks=[task],
            trusted=self.trusted,
            confirmed_sensitive_paths=(
                [f"{SDK_DIR}/call.pkl"] if self.trusted and self.send_flagged_payload else []
            ),
        )
        stdout, stderr, peer, finished, vouched = self._submit(job, tag, self.echo_output)
        self._check_finished(finished, stderr, peer)
        if self.trusted:
            return _parse_trusted("".join(stdout), len(calls), peer, tag, vouched)
        # Standard mode has no way to decode a pickle: only the strict JSON decoder.
        return _parse_results("".join(stdout), len(calls), peer, tag)

    def _run(self, fn: Callable, calls: list, peer_fp: str = "") -> list:
        return self._run_remote(fn, calls, peer_fp) if self._remote else self._run_local(fn, calls)

    # -------------------------------------------------------------- public

    def _slots(self, fn: Callable) -> list[str]:
        """One entry per task of `fn` that may run at once, naming the lender it runs on: each
        grant gets as many as its cores, memory and task count allow (never more)."""
        if not self._remote:
            return [""] * self.max_workers
        o = _options(fn)
        cpu, mem = max(1, int(o.cpus * 1000)), max(1, int(o.memory))
        slots: list[str] = []
        for g in self._grants:
            lim = g.grant.limits
            n = min(lim.max_concurrent_tasks or 1, lim.cpu_millis // cpu, lim.memory_bytes // mem)
            slots += [g.peer_fingerprint] * n
        if not slots:
            raise GimmeCoresError(
                f"{fn.__qualname__} needs {o.cpus} cores and {o.memory >> 20} MiB per call, "
                "more than any grant allows"
            )
        return slots[: self.max_workers]

    def _capacity(self, fn: Callable) -> int:
        return len(self._slots(fn))

    def _chunks(self, items: list, chunksize: int | None, parallel: int) -> list:
        if chunksize is None:
            chunksize = max(1, -(-len(items) // (parallel * 4)))
        return [items[i : i + chunksize] for i in range(0, len(items), chunksize)]

    def _limited(self, fn: Callable) -> Callable:
        """Runs a chunk once a slot is free, on that slot's lender."""
        import queue

        free: queue.Queue = queue.Queue()
        for s in self._slots(fn):
            free.put(s)

        def run(chunk):
            peer = free.get()
            try:
                return self._run(fn, chunk, peer)
            finally:
                free.put(peer)

        return run

    def map(self, fn: Callable, iterable: Iterable, chunksize: int | None = None) -> list:
        """Like `multiprocessing.Pool.map`: results in order; the first error is raised."""
        calls = [((x,), {}) for x in iterable]
        parallel = self._capacity(fn)
        run = self._limited(fn)
        results: list = []
        for part in self._threads.map(run, self._chunks(calls, chunksize, parallel)):
            for kind, value in part:
                if kind == "error":
                    raise value
                results.append(value)
        return results

    def imap_unordered(
        self, fn: Callable, iterable: Iterable, chunksize: int = 1
    ) -> Iterator[Any]:
        """Results as they finish (any order)."""
        calls = [((x,), {}) for x in iterable]
        parallel = self._capacity(fn)
        run = self._limited(fn)
        futs = [self._threads.submit(run, c) for c in self._chunks(calls, chunksize, parallel)]
        for f in cf.as_completed(futs):
            for kind, value in f.result():
                if kind == "error":
                    raise value
                yield value


class Executor(cf.Executor):
    """`concurrent.futures.Executor` backed by a `Pool` (one call per task)."""

    def __init__(self, **pool_options):
        self._pool = Pool(**pool_options)
        self._runners: dict = {}
        self._lock = threading.Lock()

    def submit(self, fn, /, *args, **kwargs) -> cf.Future:
        with self._lock:
            run = self._runners.get(fn)
            if run is None:
                run = self._runners[fn] = self._pool._limited(fn)

        def one():
            kind, value = run([(list(args), kwargs)])[0]
            if kind == "error":
                raise value
            return value

        return self._pool._threads.submit(one)

    def shutdown(self, wait: bool = True, *, cancel_futures: bool = False) -> None:
        self._pool.close()
