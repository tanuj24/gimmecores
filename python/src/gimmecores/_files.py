"""`gmc.File` and `gmc.Dir`: local files and folders passed to remote functions, and files they
return. Self-contained (standard library only): the lender's worker runs this same source when
gimmecores is not installed there.

    @gmc.task
    def count_lines(f):                  # f behaves like a path on either device
        with open(f) as fh:
            return sum(1 for _ in fh)

    pool.map(count_lines, [gmc.File("a.csv"), gmc.File("b.csv")])

    def thumbnail(f):
        out = "thumb.png"
        ...                              # write it in the task folder
        return gmc.File(out)             # comes back as a gmc.File on this device
"""

import os

#: Key of the JSON object that stands for a file or folder while it travels.
MARKER = "__gmc_file__"


class _Path(os.PathLike):
    __gmc_kind__ = ""

    def __init__(self, path):
        self.path = os.fspath(path)

    def __fspath__(self):
        return self.path

    def __str__(self):
        return self.path

    def __repr__(self):
        return "gmc.%s(%r)" % (type(self).__name__, self.path)

    def __eq__(self, other):
        return type(self) is type(other) and self.path == other.path

    def __hash__(self):
        return hash((type(self).__name__, self.path))

    @property
    def name(self):
        return os.path.basename(self.path.rstrip("/"))


class File(_Path):
    """A file: `open(f)`, `f.read_bytes()`, `f.read_text()`, `f.path`."""

    __gmc_kind__ = "file"

    def open(self, mode="r", **kwargs):
        return open(self.path, mode, **kwargs)

    def read_bytes(self):
        with open(self.path, "rb") as fh:
            return fh.read()

    def read_text(self, encoding="utf-8"):
        with open(self.path, encoding=encoding) as fh:
            return fh.read()


class Dir(_Path):
    """A folder: `os.listdir(d)`, `pathlib.Path(d)`, `d.path`."""

    __gmc_kind__ = "dir"


def kind_of(x):
    """'file' or 'dir' for a File or Dir from any copy of this module, else None."""
    k = getattr(type(x), "__gmc_kind__", None)
    return k if k in ("file", "dir") and isinstance(getattr(x, "path", None), str) else None


def walk(x, f):
    """Applies `f` to every File/Dir inside lists, tuples and dicts (other containers are left
    alone). Dicts that already use the marker key are refused: it is reserved."""
    if kind_of(x):
        return f(x)
    if isinstance(x, list):
        return [walk(v, f) for v in x]
    if isinstance(x, tuple):
        return tuple(walk(v, f) for v in x)
    if isinstance(x, dict):
        if MARKER in x:
            raise ValueError("%r is reserved for gmc.File and gmc.Dir" % MARKER)
        return {k: walk(v, f) for k, v in x.items()}
    return x


def unwalk(x, f):
    """Applies `f(path, is_dir)` to every marker inside lists, tuples and dicts."""
    if isinstance(x, dict):
        if MARKER in x:
            if set(x) != {MARKER, "dir"} or not isinstance(x[MARKER], str):
                raise ValueError("malformed file marker")
            return f(x[MARKER], x["dir"] is True)
        return {k: unwalk(v, f) for k, v in x.items()}
    if isinstance(x, list):
        return [unwalk(v, f) for v in x]
    if isinstance(x, tuple):
        return tuple(unwalk(v, f) for v in x)
    return x


#: Where a task puts the files its function returns (declared as the task's output).
OUT_DIR = ".gmc-out"


def returned(x, call):
    """Lender side: copies every File/Dir in call number `call`'s result into OUT_DIR (so it
    comes back) and puts a marker in its place."""
    import shutil

    count = [0]

    def keep(p):
        count[0] += 1
        src = p.path
        name = os.path.basename(os.path.normpath(src)) or "file"
        dest = os.path.join(OUT_DIR, str(call), str(count[0]), name)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if kind_of(p) == "dir":
            shutil.copytree(src, dest, symlinks=True)
        else:
            shutil.copyfile(src, dest)
        return {MARKER: dest.replace(os.sep, "/"), "dir": kind_of(p) == "dir"}

    return walk(x, keep)
