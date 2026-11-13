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

__version__ = "0.1.0"
__all__ = ["Executor", "GimmeCoresError", "Lockfile", "Pool", "RemoteError", "grants", "task"]
