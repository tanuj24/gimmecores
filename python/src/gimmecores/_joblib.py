"""joblib backend: `joblib.Parallel` on your other devices' cores (Trusted mode).

    import joblib
    import gimmecores as gmc

    gmc.register_joblib()
    with joblib.parallel_config(backend="gimmecores"):
        results = joblib.Parallel(n_jobs=-1)(joblib.delayed(f)(x) for x in xs)

joblib hands the backend arbitrary functions and arguments (NumPy arrays, estimators), so it
runs in Trusted mode only: see `Pool(trusted=True)` for what that means and how to turn it on.
The lender needs neither joblib nor gimmecores: only the calls themselves are sent.
"""

from __future__ import annotations

import concurrent.futures as cf
import queue
import threading

from joblib._parallel_backends import AutoBatchingMixin, ParallelBackendBase

from . import _api


def _main_project():
    import sys
    from pathlib import Path

    main = getattr(sys.modules.get("__main__"), "__file__", None)
    if not main:
        return None
    for d in Path(main).resolve().parents:
        if (d / "pyproject.toml").is_file():
            return d
    return None


def _run_items(items):
    """Runs one joblib batch on the lender (sent by value: the lender has no gimmecores)."""
    return [func(*args, **kwargs) for func, args, kwargs in items]


class GimmeCoresBackend(AutoBatchingMixin, ParallelBackendBase):
    """`backend="gimmecores"`. Keyword arguments go to `gmc.Pool` (`peers`, `home`, `project`,
    `env`, `local_fallback`, ...); `trusted` is always True."""

    supports_retrieve_callback = True
    supports_sharedmem = False
    uses_threads = False
    # Each batch costs a network round trip and a task start: aim for a few seconds of work.
    MIN_IDEAL_BATCH_DURATION = 1.0
    MAX_IDEAL_BATCH_DURATION = 10.0

    def __init__(self, nesting_level=None, inner_max_num_threads=None, **pool_options):
        super().__init__(nesting_level=nesting_level, inner_max_num_threads=inner_max_num_threads)
        pool_options.pop("trusted", None)
        if "project" not in pool_options:
            # The calling program's project (so its modules import on the lender), never this
            # package's own folder; none for notebooks, whose functions travel by value.
            pool_options["project"] = _main_project() or False
        self._pool_options = {"echo_output": False, **pool_options}
        self._pool: _api.Pool | None = None
        self._threads: cf.ThreadPoolExecutor | None = None
        self._free: queue.Queue | None = None
        self.parallel = None

    def _ensure_pool(self) -> _api.Pool:
        if self._pool is None:
            import cloudpickle
            import sys

            # Batches run through this module's _run_items; the lender cannot import it.
            cloudpickle.register_pickle_by_value(sys.modules[__name__])
            self._pool = _api.Pool(trusted=True, **self._pool_options)
            slots = self._pool._slots(_run_items)
            self._free = queue.Queue()
            for s in slots:
                self._free.put(s)
            self._threads = cf.ThreadPoolExecutor(len(slots))
        return self._pool

    def effective_n_jobs(self, n_jobs):
        if n_jobs == 0:
            raise ValueError("n_jobs == 0 in Parallel has no meaning")
        capacity = len(self._ensure_pool()._slots(_run_items))
        if n_jobs is None or n_jobs < 0:
            return capacity
        return max(1, min(n_jobs, capacity))

    def configure(self, n_jobs=1, parallel=None, prefer=None, require=None, **kwargs):
        self.parallel = parallel
        return self.effective_n_jobs(n_jobs)

    def submit(self, func, callback=None):
        pool = self._ensure_pool()
        items = [(f, tuple(a), dict(k)) for f, a, k in func.items]

        def one():
            peer = self._free.get()
            try:
                (kind, value), = pool._run(_run_items, [((items,), {})], peer)
            finally:
                self._free.put(peer)
            if kind == "error":
                # The original exception where there is one, as joblib would raise locally.
                raise getattr(value, "exception", None) or value
            return value

        fut = self._threads.submit(one)
        if callback is not None:
            fut.add_done_callback(callback)
        return fut

    def retrieve_result_callback(self, future):
        return future.result()

    def abort_everything(self, ensure_ready=True):
        self.terminate()

    def terminate(self):
        if self._threads is not None:
            self._threads.shutdown(wait=False, cancel_futures=True)
            self._threads = None
        if self._pool is not None:
            self._pool.close()
            self._pool = None
        self.reset_batch_stats()


def register_joblib() -> None:
    """Makes `backend="gimmecores"` available to joblib (`joblib.parallel_config`)."""
    from joblib import register_parallel_backend

    register_parallel_backend("gimmecores", GimmeCoresBackend)
