"""GimmeCores: run Python functions on your other devices' spare cores, with their owner's
consent.

    import gimmecores as gmc

    @gmc.task(cpus=1, memory="1g")
    def square(x):
        return x * x

    if __name__ == "__main__":
        with gmc.Pool() as pool:
            print(pool.map(square, range(10)))
"""

from ._api import Executor, GimmeCoresError, Pool, RemoteError, grants, task
from ._env import Lockfile
from ._files import Dir, File, Secret



def register_joblib() -> None:
    """Makes `joblib.parallel_config(backend="gimmecores")` available (Trusted mode; needs
    joblib and cloudpickle: pip install 'gimmecores[trusted]' joblib)."""
    from ._joblib import register_joblib as register

    register()


def load_ipython_extension(ipython) -> None:
    """`%load_ext gimmecores` in Jupyter: adds `%gmc` (devices, Trusted mode, grants)."""
    from ._jupyter import load_ipython_extension as load

    load(ipython)


__version__ = "0.1.1"
__all__ = [
    "Dir", "Executor", "File", "GimmeCoresError", "Lockfile", "Pool", "RemoteError", "Secret",
    "grants", "register_joblib", "task",
]
