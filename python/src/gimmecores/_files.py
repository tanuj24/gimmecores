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
#: ... and for a secret (its value travels separately, as an environment variable).
SECRET_MARKER = "__gmc_secret__"
#: Prefix of the environment variable that carries a gmc.Secret argument's value.
SECRET_ENV = "GMC_SECRET_"


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


class Secret:
    """A secret from this device's environment, sent by name:

        pool.map(download, urls, ...)              # with download(url, token)
        pool.map(partial(download, token=gmc.Secret("HF_TOKEN")), urls)

    The function receives the value (a str). It travels as an environment variable of the task,
    encrypted, never in a file, a command line or a log, and the pool says on stderr which
    secret it sends to which device. The lender can read it: send it only to devices you
    trust with it. (`@gmc.task(secrets=["HF_TOKEN"])` sets it as the task's own HF_TOKEN.)"""

    __gmc_kind__ = "secret"

    def __init__(self, name):
        if not (isinstance(name, str) and is_env_name(name)):
            raise ValueError("a secret is named like an environment variable: %r" % (name,))
        self.name = name

    def __repr__(self):
        return "gmc.Secret(%r)" % self.name  # never the value

    def __eq__(self, other):
        return type(self) is type(other) and self.name == other.name

    def __hash__(self):
        return hash(("Secret", self.name))


def is_env_name(name):
    return (
        0 < len(name) <= 100
        and not name[0].isdigit()
        and all(c.isascii() and (c.isalnum() or c == "_") for c in name)
    )


def kind_of(x):
    """'file', 'dir' or 'secret' for a File, Dir or Secret from any copy of this module."""
    k = getattr(type(x), "__gmc_kind__", None)
    if k in ("file", "dir") and isinstance(getattr(x, "path", None), str):
        return k
    if k == "secret" and isinstance(getattr(x, "name", None), str):
        return k
    return None


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
        if MARKER in x or SECRET_MARKER in x:
            raise ValueError("%r and %r are reserved keys" % (MARKER, SECRET_MARKER))
        return {k: walk(v, f) for k, v in x.items()}
    return x


def unwalk(x, f, secret=None):
    """Applies `f(path, is_dir)` to every file marker and `secret(name)` to every secret marker
    inside lists, tuples and dicts. Secret markers are an error where `secret` is None."""
    if isinstance(x, dict):
        if MARKER in x:
            if set(x) != {MARKER, "dir"} or not isinstance(x[MARKER], str):
                raise ValueError("malformed file marker")
            return f(x[MARKER], x["dir"] is True)
        if SECRET_MARKER in x:
            if secret is None or set(x) != {SECRET_MARKER} or not isinstance(x[SECRET_MARKER], str):
                raise ValueError("unexpected secret marker")
            return secret(x[SECRET_MARKER])
        return {k: unwalk(v, f, secret) for k, v in x.items()}
    if isinstance(x, list):
        return [unwalk(v, f, secret) for v in x]
    if isinstance(x, tuple):
        return tuple(unwalk(v, f, secret) for v in x)
    return x


def secret_arrived(name):
    """Lender side: a gmc.Secret argument's value, from the task's environment."""
    value = os.environ.get(SECRET_ENV + name)
    if value is None:
        raise RuntimeError("the secret %s did not arrive" % name)
    return value


#: Where a task puts the files its function returns (declared as the task's output).
OUT_DIR = ".gmc-out"


def returned(x, call):
    """Lender side: copies every File/Dir in call number `call`'s result into OUT_DIR (so it
    comes back) and puts a marker in its place."""
    import shutil

    count = [0]

    def keep(p):
        if kind_of(p) == "secret":
            raise TypeError("a result cannot contain gmc.Secret")
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
