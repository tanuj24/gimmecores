"""Python packages for remote tasks, built on this device from the project's lockfile.

The lender never goes online: this device resolves the project's dependencies for the lender's
Python and platform (which the lender reports in a probe task), downloads the wheels with this
device's own index settings and credentials, installs them into a folder here, and sends that
folder with the task. Only wheels are used: nothing from a package runs on this device (no
source builds, no byte-compiling), and nothing but installed package files leaves it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

#: Bumped whenever the layout of a built environment changes (old cache entries are ignored).
FORMAT = 1

#: The probe prints this, then one JSON object, so the result cannot be confused with output.
PROBE_SOURCE = r'''
import json, platform, sys, sysconfig
tag = sys.argv[1]
info = {
    "python": list(sys.version_info[:2]),
    "impl": sys.implementation.name,
    "system": sys.platform,
    "machine": platform.machine(),
    "mac": platform.mac_ver()[0] if sys.platform == "darwin" else "",
    "libc": list(platform.libc_ver()) if sys.platform.startswith("linux") else ["", ""],
    "free_threaded": bool(sysconfig.get_config_var("Py_GIL_DISABLED")),
}
sys.stdout.write("GMC-PROBE-" + tag + " " + json.dumps(info) + "\n")
'''
PROBE_MARK = "GMC-PROBE-"


class EnvError(Exception):
    """The environment could not be prepared (raised as GimmeCoresError by the pool)."""


@dataclass(frozen=True)
class Lockfile:
    """Packages from this file: `uv.lock`, `requirements.txt` (or any `*.txt` in that format)
    or `pyproject.toml` (its `[project] dependencies`)."""

    path: str | os.PathLike

    def resolve(self) -> Path:
        p = Path(self.path).expanduser().resolve()
        if not p.is_file():
            raise EnvError(f"{p} not found")
        return p


@dataclass(frozen=True)
class Target:
    """The lender's Python, as its probe reported it (validated; the lender is untrusted)."""

    python: tuple[int, int]
    free_threaded: bool
    platform: str  # uv's --python-platform
    macos: str  # MACOSX_DEPLOYMENT_TARGET, or ""

    @property
    def python_version(self) -> str:
        return f"{self.python[0]}.{self.python[1]}" + ("t" if self.free_threaded else "")

    def describe(self) -> str:
        return f"Python {self.python_version} on {self.platform}"


# uv's manylinux targets (`uv pip install --help`, --python-platform).
_MANYLINUX = [17, 28, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40]
_ARCH = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64", "amd64": "x86_64"}


def parse_probe(stdout: str, tag: str) -> Target:
    """Strictly decodes the lender's probe. Everything here ends up in a command line on this
    device, so each value is checked against a short list or a tight pattern."""
    prefix = f"{PROBE_MARK}{tag} "
    line = next((x for x in reversed(stdout.splitlines()) if x.startswith(prefix)), None)
    if line is None:
        raise EnvError("the lender did not report its Python")
    try:
        info = json.loads(line[len(prefix):])
    except ValueError:
        raise EnvError("the lender's Python report is malformed") from None
    if not isinstance(info, dict):
        raise EnvError("the lender's Python report is malformed")
    py = info.get("python")
    if not (
        isinstance(py, list)
        and len(py) == 2
        and all(type(x) is int for x in py)
        and py[0] == 3
        and 8 <= py[1] <= 40
    ):
        raise EnvError("the lender reported an unsupported Python version")
    if info.get("impl") != "cpython":
        raise EnvError("packages are supported only with CPython on the lender")
    arch = _ARCH.get(str(info.get("machine", "")).lower())
    if arch is None:
        raise EnvError("the lender's processor type is not supported for packages")
    system, macos = info.get("system"), ""
    if system == "darwin":
        platform = f"{arch}-apple-darwin"
        m = re.fullmatch(r"(\d{1,2})(?:\.(\d{1,2}))?(?:\.\d{1,2})?", str(info.get("mac", "")))
        if not m:
            raise EnvError("the lender reported an unknown macOS version")
        macos = f"{m.group(1)}.{m.group(2) or 0}"
    elif system == "linux":
        libc = info.get("libc")
        if not (isinstance(libc, list) and len(libc) == 2):
            raise EnvError("the lender's Python report is malformed")
        m = re.fullmatch(r"2\.(\d{1,3})", str(libc[1])) if libc[0] == "glibc" else None
        if m:
            minor = int(m.group(1))
            fit = [v for v in _MANYLINUX if v <= minor]
            if not fit:
                raise EnvError(f"the lender's glibc 2.{minor} is too old for packages")
            platform = f"{arch}-manylinux_2_{fit[-1]}"
        elif libc == ["", ""]:
            platform = f"{arch}-unknown-linux-musl"
        else:
            raise EnvError("the lender reported an unknown C library")
    else:
        raise EnvError("packages are supported only on macOS and Linux lenders")
    return Target(
        python=(py[0], py[1]),
        free_threaded=info.get("free_threaded") is True,
        platform=platform,
        macos=macos,
    )


# ---------------------------------------------------------------------------- the source


def find_source(root: Path | None, env) -> Path | None:
    """The file that lists the project's packages, or None for no packages.
    env: "auto" (uv.lock, then requirements.txt, then pyproject.toml dependencies, in the
    project folder), None/False, a Lockfile, or a path."""
    if env is None or env is False:
        return None
    if isinstance(env, Lockfile):
        return env.resolve()
    if isinstance(env, (str, os.PathLike)) and env != "auto":
        return Lockfile(env).resolve()
    if env != "auto":
        raise EnvError(f"env must be 'auto', None or gmc.Lockfile(path), not {env!r}")
    if root is None:
        return None
    for name in ("uv.lock", "requirements.txt"):
        if (root / name).is_file():
            return root / name
    pp = root / "pyproject.toml"
    if pp.is_file() and _pyproject_deps(pp):
        return pp
    return None


def _pyproject_deps(path: Path) -> list:
    try:
        import tomllib
    except ImportError:  # Python < 3.11
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            # Cannot tell without a TOML parser; let uv read it.
            return ["?"] if "dependencies" in path.read_text(errors="replace") else []
    try:
        data = tomllib.loads(path.read_text())
    except (ValueError, OSError) as e:
        raise EnvError(f"{path}: {e}") from None
    deps = (data.get("project") or {}).get("dependencies") or []
    return list(deps) if isinstance(deps, list) else []


# ---------------------------------------------------------------------------- uv


def find_uv() -> str:
    try:
        from uv import find_uv_bin  # the `uv` package from PyPI

        return find_uv_bin()
    except (ImportError, FileNotFoundError):
        pass
    found = shutil.which("uv")
    if found:
        return found
    raise EnvError(
        "this project lists packages, which GimmeCores installs for the lender with uv; "
        "install it (pip install 'gimmecores[envs]'), or pass env=None to use only the "
        "lender's own Python packages"
    )


def _uv_env(target: Target) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("UV_COMPILE")}
    env["UV_NO_PROGRESS"] = "1"
    if target.macos:
        env["MACOSX_DEPLOYMENT_TARGET"] = target.macos
    else:
        env.pop("MACOSX_DEPLOYMENT_TARGET", None)
    return env


def _run(cmd: list, env: dict, what: str) -> str:
    p = subprocess.run(cmd, env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    if p.returncode != 0:
        detail = (p.stderr or p.stdout).strip()[-3000:]
        raise EnvError(f"{what} failed:\n{detail}")
    return p.stdout


_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[A-Za-z0-9._,-]+\])?==([A-Za-z0-9._+!-]+)\s*(;.*)?$")


def check_pins(text: str) -> list[str]:
    """The pinned requirements, one per package, each `name==version` (optionally with markers
    and hashes). Anything that would install from a path, a URL or version control is refused:
    those can pull in local folders or record credentialed URLs, and this cut sends only
    packages from an index."""
    pins, logical = [], ""
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].rstrip() if not raw.lstrip().startswith("#") else ""
        if line.endswith("\\"):
            logical += line[:-1] + " "
            continue
        logical += line
        item, logical = logical.strip(), ""
        if not item:
            continue
        req = item.split(" --hash", 1)[0].strip()
        if req.startswith("-"):
            raise EnvError(f"unsupported line in the package list: {req.split()[0]} ...")
        if not _PIN.match(req):
            shown = re.sub(r"//[^/@\s]*@", "//…@", req)[:200]
            raise EnvError(
                f"'{shown}' is not a package from an index; GimmeCores sends only index "
                "packages (paths, URLs and git sources are not supported yet)"
            )
        pins.append(item)
    return pins


def _all_hashed(reqs: str) -> bool:
    pins = check_pins(reqs)
    return bool(pins) and all("--hash" in p for p in pins)


def pinned(source: Path, target: Target, uv: str) -> str:
    """The source's packages pinned (with hashes) for the target."""
    env = _uv_env(target)
    if source.name == "uv.lock":
        out = _run(
            [uv, "export", "--frozen", "--no-dev", "--no-emit-project", "--no-emit-workspace",
             "--no-editable", "--no-header", "--no-annotate", "--format", "requirements-txt",
             "--project", str(source.parent)],
            env, "reading uv.lock",
        )
    else:
        out = _run(
            [uv, "pip", "compile", str(source), "--python-platform", target.platform,
             "--python-version", target.python_version, "--no-build",
             "--generate-hashes", "--no-header", "--no-annotate", "--quiet"],
            env, f"resolving {source.name} for {target.describe()}",
        )
    return "\n".join(check_pins(out)) + "\n"


def cache_root() -> Path:
    base = os.environ.get("GMC_CACHE_DIR")
    if base:
        root = Path(base)
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Caches" / "gimmecores"
    else:
        root = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "gimmecores"
    root = root / "envs"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


def _compile(uv: str, site: Path, target: Target, cwd: Path) -> None:
    """Byte-compiles the packages with the lender's Python version (found or fetched by uv on
    this device), so the lender does not compile them again for every task: a fresh task
    folder has no byte-code, and importing a large package without it takes seconds.
    Compiling only translates the source; no package code runs. Hash-checked byte-code stays
    valid on the lender, where the files get new modification times. If no such Python can be
    found, the packages still work, only slower to import."""
    import warnings

    p = subprocess.run(
        [uv, "run", "--no-project", "--quiet", "--python", target.python_version, "python",
         "-m", "compileall", "-q", "-j0", "--invalidation-mode", "checked-hash", str(site)],
        env=_uv_env(target), cwd=cwd, capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    if not any(site.rglob("*.pyc")):
        warnings.warn(
            f"could not byte-compile packages for Python {target.python_version} "
            f"({(p.stderr or p.stdout).strip()[-300:]}); the lender compiles them on each "
            "import, which is slower",
            stacklevel=3,
        )


_locks: dict = {}
_locks_lock = threading.Lock()


def build(source: Path, target: Target) -> Path | None:
    """The installed-packages folder for `source` on `target`, from the cache or built now.
    None when the source lists no packages."""
    data = source.read_bytes()
    key = hashlib.sha256(
        json.dumps(
            [FORMAT, source.name, data.hex(), target.platform, target.python_version, target.macos]
        ).encode()
    ).hexdigest()[:32]
    root = cache_root()
    final = root / key
    with _locks_lock:
        lock = _locks.setdefault(key, threading.Lock())
    with lock:
        if (final / ".gmc-env.json").is_file():
            return None if (final / ".empty").exists() else final / "site"
        uv = find_uv()
        reqs = pinned(source, target, uv)
        tmp = Path(tempfile.mkdtemp(prefix="tmp-", dir=root))
        try:
            site = tmp / "site"
            if reqs.strip():
                (tmp / "requirements.txt").write_text(reqs)
                _run(
                    [uv, "pip", "install", "--target", str(site), "--python-platform",
                     target.platform, "--python-version", target.python_version,
                     "--no-build", "--no-deps", "--quiet", "-r", str(tmp / "requirements.txt"),
                     # Index packages come with hashes (checked); a lock made from a local
                     # wheel folder may have none, and its exact pins are used as they are.
                     *(["--require-hashes"] if _all_hashed(reqs) else [])],
                    _uv_env(target), f"installing packages for {target.describe()}",
                )
                # Entry-point scripts are not needed to import packages and name a Python on
                # this device in their first line.
                shutil.rmtree(site / "bin", ignore_errors=True)
                for f in site.rglob("direct_url.json"):
                    f.unlink()
                # Byte-code compiled here by uv's compile-bytecode setting is for this device's
                # Python; replace it with byte-code for the lender's.
                for d in list(site.rglob("__pycache__")):
                    shutil.rmtree(d, ignore_errors=True)
                _compile(uv, site, target, tmp)
            else:
                (tmp / ".empty").write_text("")
            (tmp / ".gmc-env.json").write_text(
                json.dumps({"source": str(source), "target": target.describe()})
            )
            try:
                os.rename(tmp, final)
            except OSError:
                # Another process finished first; use its copy.
                if not (final / ".gmc-env.json").is_file():
                    raise
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return None if (final / ".empty").exists() else final / "site"
