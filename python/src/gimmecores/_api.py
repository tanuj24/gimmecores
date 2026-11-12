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

from . import _daemon
from ._proto.gimmecores.local.v1 import local_pb2 as l
from ._proto.gimmecores.peer.v1 import peer_pb2 as pb
from ._worker import MARK, SOURCE

#: Largest encoded argument set per task (they travel on the lender's command line).
MAX_ARGS_BYTES = 96 * 1024


class GimmeCoresError(Exception):
    """GimmeCores could not run the work (no daemon, no grant, the lender refused, ...)."""


class RemoteError(Exception):
    """Your function raised on another device. `type`, `message` and `traceback` describe it."""

    def __init__(self, type: str, message: str, traceback: str = "", peer: str = ""):
        self.type, self.message, self.traceback, self.peer = type, message, traceback, peer
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


def _project_root(fn: Callable) -> Path:
    """Nearest folder holding pyproject.toml above the function's file, else that file's folder."""
    mod = sys.modules.get(fn.__module__)
    file = getattr(mod, "__file__", None)
    if not file:
        raise GimmeCoresError(
            f"{fn.__qualname__} has no source file (defined in a notebook or console?); "
            "Standard mode calls functions by import name"
        )
    start = Path(file).resolve().parent
    for d in [start, *start.parents]:
        if (d / "pyproject.toml").is_file():
            return d
    return start


def _import_name(fn: Callable, root: Path) -> tuple[str, str]:
    """(module, qualname) the lender imports. Scripts are imported by their file name."""
    if "<locals>" in fn.__qualname__ or fn.__name__ == "<lambda>":
        raise GimmeCoresError(
            f"{fn.__qualname__} is a lambda or a nested function; Standard mode calls functions "
            "by import name, so define it at the top level of a module"
        )
    module = fn.__module__
    if module == "__main__":
        file = Path(sys.modules["__main__"].__file__).resolve()
        rel = file.relative_to(root).with_suffix("")
        module = ".".join(rel.parts)
    return module, fn.__qualname__


def _encode(module: str, qualname: str, calls: list, tag: str) -> str:
    try:
        spec = json.dumps({"module": module, "qualname": qualname, "calls": calls, "tag": tag})
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


def _active_grants(stub) -> list:
    resp = stub.ListGrants(l.ListGrantsRequest(include_inactive=False))
    return [g for g in resp.grants if not g.as_lender and g.state == pb.GRANT_STATE_ACTIVE]


def grants(home: str | os.PathLike | None = None) -> list[dict]:
    """Grants other devices gave this one: [{"peer", "cores", "memory_bytes", "modes"}]."""
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
            }
        )
    return out


class Pool:
    """Runs calls on devices that granted you resources, or locally when none did.

    `peers`: device names or fingerprints to use (default: any with an active grant).
    `image`: run in this container image on the lender (it must already be there); default:
    the lender's sandbox with its installed Python. `max_workers`: tasks in flight at once.
    """

    def __init__(
        self,
        peers: list[str] | None = None,
        *,
        image: str | None = None,
        local_fallback: bool = True,
        max_workers: int | None = None,
        home: str | os.PathLike | None = None,
        echo_output: bool = True,
    ):
        self.peers = list(peers or [])
        self.image = image
        self.local_fallback = local_fallback
        self.home = _daemon.home(home)
        self.echo_output = echo_output
        self._stub = None
        self._remote = False
        self._grants: list = []
        try:
            self._stub = _daemon.client(self.home)
            self._grants = _active_grants(self._stub)
            self._remote = bool(self._grants)
        except (GimmeCoresError, grpc.RpcError):
            self._remote = False
        if not self._remote and not local_fallback:
            raise GimmeCoresError(
                "no active grant from another device (ask with `gmc grants request <device>`)"
            )
        self.max_workers = max_workers or (4 if self._remote else os.cpu_count() or 2)
        self._threads = cf.ThreadPoolExecutor(self.max_workers)
        self._local: cf.ProcessPoolExecutor | None = None
        self._lock = threading.Lock()

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

    # -------------------------------------------------------------- running chunks

    def _run_local(self, fn: Callable, calls: list) -> list:
        with self._lock:
            if self._local is None:
                self._local = cf.ProcessPoolExecutor()
        futs = [self._local.submit(fn, *a, **k) for a, k in calls]
        out = []
        for f in futs:
            try:
                out.append(("ok", f.result()))
            except Exception as e:  # same contract as remote calls
                out.append(("error", e))
        return out

    def _run_remote(self, fn: Callable, calls: list) -> list:
        root = _project_root(fn)
        module, qualname = _import_name(fn, root)
        opts = _options(fn)
        tag = os.urandom(8).hex()
        payload = _encode(module, qualname, calls, tag)
        task = l.InlineTask(
            name=qualname,
            command=pb.Command(argv=["python3", "-c", SOURCE, payload]),
            resources=pb.Limits(
                cpu_millis=int(opts.cpus * 1000), memory_bytes=int(opts.memory)
            ),
            peers=self.peers,
            mode=pb.EXECUTION_MODE_CONTAINER if self.image else pb.EXECUTION_MODE_SANDBOX,
        )
        task.timeout.seconds = opts.timeout
        if self.image:
            task.env.image.reference = self.image
        job = l.JobSpec(project_root=str(root), inline_tasks=[task])
        stdout, stderr, peer, finished = [], [], "", None
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
                            if self.echo_output:
                                sys.stderr.write(text)
                        else:
                            stdout.append(text)
                            if self.echo_output:
                                for line in text.splitlines(keepends=True):
                                    if not line.startswith(f"{MARK}{tag} "):
                                        sys.stdout.write(line)
                    elif which == "finished":
                        finished = te.finished
                elif kind == "done":
                    break
        except grpc.RpcError as e:
            raise GimmeCoresError(e.details() or str(e)) from None
        if finished is None:
            raise GimmeCoresError("the task ended without a result")
        if finished.status != pb.TaskResult.STATUS_SUCCEEDED:
            name = pb.TaskResult.Status.Name(finished.status)
            detail = finished.error.message or "".join(stderr)[-2000:]
            raise RemoteError(name, detail.strip(), "".join(stderr)[-8000:], peer)
        return _parse_results("".join(stdout), len(calls), peer, tag)

    def _run(self, fn: Callable, calls: list) -> list:
        return self._run_remote(fn, calls) if self._remote else self._run_local(fn, calls)

    # -------------------------------------------------------------- public

    def _capacity(self, fn: Callable) -> int:
        """Tasks of `fn` that fit in the grants at once (never more than was granted)."""
        if not self._remote:
            return self.max_workers
        o = _options(fn)
        cpu, mem = max(1, int(o.cpus * 1000)), max(1, int(o.memory))
        total = 0
        for g in self._grants:
            lim = g.grant.limits
            total += min(
                lim.max_concurrent_tasks or 1, lim.cpu_millis // cpu, lim.memory_bytes // mem
            )
        if total == 0:
            raise GimmeCoresError(
                f"{fn.__qualname__} needs {o.cpus} cores and {o.memory >> 20} MiB per call, "
                "more than any grant allows"
            )
        return max(1, min(total, self.max_workers))

    def _chunks(self, items: list, chunksize: int | None, parallel: int) -> list:
        if chunksize is None:
            chunksize = max(1, -(-len(items) // (parallel * 4)))
        return [items[i : i + chunksize] for i in range(0, len(items), chunksize)]

    def _limited(self, fn: Callable, parallel: int) -> Callable:
        gate = threading.Semaphore(parallel)

        def run(chunk):
            with gate:
                return self._run(fn, chunk)

        return run

    def map(self, fn: Callable, iterable: Iterable, chunksize: int | None = None) -> list:
        """Like `multiprocessing.Pool.map`: results in order; the first error is raised."""
        calls = [((x,), {}) for x in iterable]
        parallel = self._capacity(fn)
        run = self._limited(fn, parallel)
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
        run = self._limited(fn, parallel)
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
        self._gates: dict = {}
        self._gate_lock = threading.Lock()

    def submit(self, fn, /, *args, **kwargs) -> cf.Future:
        with self._gate_lock:
            gate = self._gates.get(fn)
            if gate is None:
                gate = self._gates[fn] = threading.Semaphore(self._pool._capacity(fn))

        def one():
            with gate:
                kind, value = self._pool._run(fn, [(list(args), kwargs)])[0]
            if kind == "error":
                raise value
            return value

        return self._pool._threads.submit(one)

    def shutdown(self, wait: bool = True, *, cancel_futures: bool = False) -> None:
        self._pool.close()
