"""Packages from the project's lockfile, built on the borrower for the lender's Python and
platform and sent with the task."""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import os
import platform
import socket
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import pytest

import gimmecores as gmc
from gimmecores import _env
from gimmecores._proto.gimmecores.peer.v1 import peer_pb2 as pb

from conftest import ask_grant, paired_daemons

# ---------------------------------------------------------------------------- unit: probe


def probe_line(tag="t", **over):
    info = {
        "python": [3, 13],
        "impl": "cpython",
        "system": "linux",
        "machine": "x86_64",
        "mac": "",
        "libc": ["glibc", "2.39"],
        "free_threaded": False,
    }
    info.update(over)
    return f"noise\nGMC-PROBE-{tag} {json.dumps(info)}\n"


def test_probe_maps_to_uv_platforms():
    t = _env.parse_probe(probe_line(), "t")
    assert (t.platform, t.python_version, t.macos) == ("x86_64-manylinux_2_39", "3.13", "")
    t = _env.parse_probe(probe_line(libc=["glibc", "2.29"], machine="aarch64"), "t")
    assert t.platform == "aarch64-manylinux_2_28"
    t = _env.parse_probe(probe_line(libc=["glibc", "2.99"]), "t")
    assert t.platform == "x86_64-manylinux_2_40"
    t = _env.parse_probe(probe_line(libc=["", ""]), "t")
    assert t.platform == "x86_64-unknown-linux-musl"
    t = _env.parse_probe(
        probe_line(system="darwin", machine="arm64", mac="15.3.1", libc=["", ""]), "t"
    )
    assert (t.platform, t.macos) == ("aarch64-apple-darwin", "15.3")
    t = _env.parse_probe(probe_line(free_threaded=True), "t")
    assert t.python_version == "3.13t"


@pytest.mark.parametrize(
    "over",
    [
        {"python": [3, "13; rm -rf /"]},
        {"python": [2, 7]},
        {"python": [3, 13, 1]},
        {"python": [3, True]},
        {"impl": "pypy"},
        {"machine": "x86_64 --index-url http://evil"},
        {"machine": "riscv64"},
        {"system": "win32"},
        {"system": "darwin", "mac": "15.0 --no-index"},
        {"libc": ["glibc", "2.39 --find-links /"]},
        {"libc": ["glibc", "2.5"]},
        {"libc": ["uclibc", "1.0"]},
        {"libc": "glibc"},
    ],
)
def test_a_hostile_probe_is_refused(over):
    with pytest.raises(_env.EnvError):
        _env.parse_probe(probe_line(**over), "t")


def test_a_probe_needs_the_tag_and_valid_json():
    with pytest.raises(_env.EnvError):
        _env.parse_probe(probe_line(tag="other"), "t")
    with pytest.raises(_env.EnvError):
        _env.parse_probe("GMC-PROBE-t {not json\n", "t")
    with pytest.raises(_env.EnvError):
        _env.parse_probe("GMC-PROBE-t [1, 2]\n", "t")


# ---------------------------------------------------------------------------- unit: pins


def test_pins_from_uv_export_are_accepted():
    text = (
        "numpy==2.1.0 \\\n    --hash=sha256:aa \\\n    --hash=sha256:bb\n"
        "tzdata==2024.1 ; sys_platform == 'win32' \\\n    --hash=sha256:cc\n"
        "requests[socks]==2.32.3 --hash=sha256:dd\n"
        "# a comment\n\n"
    )
    pins = _env.check_pins(text)
    assert [p.split("==")[0] for p in pins] == ["numpy", "tzdata", "requests[socks]"]


@pytest.mark.parametrize(
    "line",
    [
        "-e ./mylib",
        "./mylib",
        "/abs/path/pkg",
        "file:///Users/me/pkg",
        "pkg @ https://user:token@example.com/pkg-1.0.whl",
        "pkg @ git+https://github.com/x/y",
        "git+https://github.com/x/y#egg=y",
        "--index-url https://user:token@example.com/simple",
        "-r other.txt",
        "numpy>=2",
    ],
)
def test_anything_but_index_pins_is_refused(line):
    with pytest.raises(_env.EnvError) as e:
        _env.check_pins(line + "\n")
    assert "token" not in str(e.value), "credentials are not repeated in the message"


def test_find_source_prefers_the_lockfile(tmp_path):
    assert _env.find_source(tmp_path, "auto") is None
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "0"\n')
    assert _env.find_source(tmp_path, "auto") is None, "no dependencies, no packages"
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0"\ndependencies = ["six"]\n'
    )
    assert _env.find_source(tmp_path, "auto") == tmp_path / "pyproject.toml"
    (tmp_path / "requirements.txt").write_text("six==1.17.0\n")
    assert _env.find_source(tmp_path, "auto") == tmp_path / "requirements.txt"
    (tmp_path / "uv.lock").write_text("")
    assert _env.find_source(tmp_path, "auto") == tmp_path / "uv.lock"
    assert _env.find_source(tmp_path, None) is None
    other = tmp_path / "reqs-gpu.txt"
    other.write_text("")
    assert _env.find_source(tmp_path, gmc.Lockfile(other)) == other
    with pytest.raises(_env.EnvError):
        _env.find_source(tmp_path, gmc.Lockfile(tmp_path / "missing.txt"))


# ---------------------------------------------------------------------------- end to end

PY_MINORS = range(8, 16)
PLATFORMS = ["macosx_11_0_arm64", "macosx_10_12_x86_64", "manylinux_2_17_x86_64",
             "manylinux_2_17_aarch64"]


def make_wheel(out: Path, name: str, version: str, tag: str, files: dict) -> None:
    """A minimal wheel, by hand (no build tools)."""
    dist = f"{name}-{version}.dist-info"
    files = dict(files)
    files[f"{dist}/METADATA"] = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    files[f"{dist}/WHEEL"] = (
        f"Wheel-Version: 1.0\nGenerator: gmc-test\nRoot-Is-Purelib: false\nTag: {tag}\n"
    )
    record = []
    for path, text in files.items():
        data = text.encode()
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        record.append(f"{path},sha256={digest},{len(data)}")
    record.append(f"{dist}/RECORD,,")
    files[f"{dist}/RECORD"] = "\n".join(record) + "\n"
    with zipfile.ZipFile(out / f"{name}-{version}-{tag}.whl", "w") as z:
        for path, text in files.items():
            z.writestr(path, text)


@pytest.fixture(scope="module")
def tag_index():
    """A local package index holding `tagpkg` built for many Pythons and platforms, each copy
    reporting its own tag, so a test can tell which one the lender got."""
    d = Path(tempfile.mkdtemp(prefix="gmc-wheels"))
    for minor in PY_MINORS:
        for plat in PLATFORMS:
            tag = f"cp3{minor}-cp3{minor}-{plat}"
            make_wheel(d, "tagpkg", "1.0", tag, {
                "tagpkg/__init__.py": f"TAG = {tag!r}\n",
                # Looks like a key; it is published package content, so it is sent as is.
                "tagpkg/example.py": "EXAMPLE = '" + "AKIA" + "IOSFODNN7EXAMPLE'\n",
                "tagpkg/cacert.pem": "not really a certificate\n",
            })
    return d


_n = [0]


def make_project(files: dict):
    """A project folder with a uniquely named module; returns the imported module."""
    _n[0] += 1
    name = f"envmod{_n[0]}"
    d = Path(tempfile.mkdtemp(prefix="gmc-envproj"))
    (d / "pyproject.toml").write_text('[project]\nname = "envdemo"\nversion = "0"\n')
    for rel, text in files.items():
        (d / rel).write_text(text)
    (d / f"{name}.py").write_text(MODULE)
    sys.path.insert(0, str(d))
    try:
        return importlib.import_module(name)
    finally:
        sys.path.remove(str(d))


MODULE = '''
import os, sys


def tag(_):
    import tagpkg
    here = os.path.realpath(tagpkg.__file__)
    return {
        "tag": tagpkg.TAG,
        "from_task": here.startswith(os.path.realpath(".gmc-sdk/env")),
        "pem": os.path.exists(os.path.join(os.path.dirname(here), "cacert.pem")),
        "python": list(sys.version_info[:2]),
    }


def lender_site_hidden(_):
    import site, sysconfig
    theirs = {os.path.realpath(p) for p in site.getsitepackages() + [site.getusersitepackages()]}
    theirs.add(os.path.realpath(sysconfig.get_paths()["purelib"]))
    return not any(os.path.realpath(p) in theirs for p in sys.path)


def speedups(_):
    import markupsafe
    from markupsafe import _speedups
    return [str(markupsafe.escape("<a>")), _speedups.__file__.endswith((".so", ".pyd"))]
'''


def host_platform_tag() -> str:
    m = platform.machine().lower()
    if sys.platform == "darwin":
        return "macosx_11_0_arm64" if m == "arm64" else "macosx_10_12_x86_64"
    return "manylinux_2_17_aarch64" if m in ("aarch64", "arm64") else "manylinux_2_17_x86_64"


@pytest.fixture
def offline_index(tag_index, tmp_path, monkeypatch):
    monkeypatch.setenv("UV_NO_INDEX", "1")
    monkeypatch.setenv("UV_FIND_LINKS", str(tag_index))
    monkeypatch.setenv("GMC_CACHE_DIR", str(tmp_path / "cache"))
    return tmp_path / "cache"


def test_the_lender_gets_packages_built_for_its_own_python_and_platform(granted, offline_index):
    mod = make_project({"requirements.txt": "tagpkg==1.0\n"})
    with gmc.Pool(home=granted["borrower"]) as pool:
        assert pool.remote
        (got,) = pool.map(mod.tag, [0])
        (hidden,) = pool.map(mod.lender_site_hidden, [0])
    py = got["python"]
    # The lender's Python, not this one (CI runs a different version here on purpose, so a
    # pool that targeted this device would pick the wrong copy).
    if os.environ.get("GMC_REQUIRE_DISTINCT_PYTHON"):
        assert tuple(py) != sys.version_info[:2], "this test proves nothing with equal Pythons"
    assert got["tag"] == f"cp{py[0]}{py[1]}-cp{py[0]}{py[1]}-{host_platform_tag()}", got
    assert got["from_task"], "imported from the packages sent with the task"
    assert got["pem"], "package files the default excludes would stop are sent when verified"
    assert hidden, "the lender's own site-packages are not on the path"


def test_built_packages_are_reused(granted, offline_index, monkeypatch):
    mod = make_project({"requirements.txt": "tagpkg==1.0\n"})
    with gmc.Pool(home=granted["borrower"]) as pool:
        pool.map(mod.tag, [0])
    built = [p for p in offline_index.iterdir() if not p.name.startswith("tmp-")]
    assert len(built) == 1

    def no_uv():
        raise AssertionError("uv was run again")

    monkeypatch.setattr(_env, "find_uv", no_uv)
    with gmc.Pool(home=granted["borrower"]) as pool:
        assert pool.map(mod.tag, [1])[0]["from_task"]
    assert [p for p in offline_index.iterdir() if not p.name.startswith("tmp-")] == built


def test_env_none_sends_no_packages(granted, offline_index):
    mod = make_project({"requirements.txt": "tagpkg==1.0\n"})
    with gmc.Pool(home=granted["borrower"], env=None) as pool:
        with pytest.raises(gmc.RemoteError) as e:
            pool.map(mod.tag, [0])
    assert e.value.type in ("ModuleNotFoundError", "ImportError")


def test_paths_and_urls_in_the_package_list_are_refused(granted, offline_index):
    mod = make_project({"requirements.txt": "./somewhere\n"})
    with gmc.Pool(home=granted["borrower"]) as pool:
        with pytest.raises(gmc.GimmeCoresError, match="preparing packages"):
            pool.map(mod.tag, [0])


def test_a_credentialed_index_url_in_the_project_does_not_leave_this_device(granted, tmp_path):
    # Credentials belong in uv's or pip's own settings on this device. A requirements file in
    # the project that carries them is part of the project, and the daemon refuses to send it.
    mod = make_project(
        {"requirements.txt": "--index-url https://me:" + "s3cr3tpassw0rd" + "@pypi.example.com/simple\n"}
    )
    with gmc.Pool(home=granted["borrower"], env=None) as pool:
        with pytest.raises(gmc.GimmeCoresError, match="password in a URL"):
            pool.map(mod.tag, [0])


def _pypi_reachable() -> bool:
    try:
        socket.create_connection(("pypi.org", 443), timeout=3).close()
        return True
    except OSError:
        return False


@pytest.mark.skipif(
    not _pypi_reachable() and not os.environ.get("CI"), reason="needs pypi.org"
)
def test_a_compiled_wheel_from_pypi_loads_in_the_lenders_sandbox(granted, tmp_path, monkeypatch):
    monkeypatch.setenv("GMC_CACHE_DIR", str(tmp_path / "cache"))
    mod = make_project({"requirements.txt": "markupsafe==3.0.3\n"})
    with gmc.Pool(home=granted["borrower"]) as pool:
        assert pool.map(mod.speedups, [0]) == [["&lt;a&gt;", True]]


# ---------------------------------------------------------------------------- the build itself


def _build_for(tmp_path, monkeypatch, tag_index, source: Path, target: _env.Target) -> str:
    monkeypatch.setenv("UV_NO_INDEX", "1")
    monkeypatch.setenv("UV_FIND_LINKS", str(tag_index))
    monkeypatch.setenv("GMC_CACHE_DIR", str(tmp_path / "cache"))
    site = _env.build(source, target)
    assert site is not None and (site / "tagpkg" / "cacert.pem").is_file()
    assert not (site / "bin").exists() and not list(site.rglob("direct_url.json"))
    ns: dict = {}
    exec((site / "tagpkg" / "__init__.py").read_text(), ns)
    return ns["TAG"]


# Built for another platform than this one, so the test cannot pass by luck; the Python is
# this one, so byte-compiling needs nothing downloaded.
HERE = (sys.version_info[0], sys.version_info[1])
LINUX = _env.Target(python=HERE, free_threaded=False, platform="x86_64-manylinux_2_28", macos="")
WANT = f"cp{HERE[0]}{HERE[1]}-cp{HERE[0]}{HERE[1]}-manylinux_2_17_x86_64"


def test_build_from_a_pyproject(tmp_path, monkeypatch, tag_index):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "pyproject.toml").write_text(
        '[project]\nname = "p"\nversion = "0"\ndependencies = ["tagpkg==1.0"]\n'
    )
    assert _build_for(tmp_path, monkeypatch, tag_index, proj / "pyproject.toml", LINUX) == WANT


def test_build_from_a_uv_lock(tmp_path, monkeypatch, tag_index):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "pyproject.toml").write_text(
        '[project]\nname = "p"\nversion = "0"\nrequires-python = ">=3.8"\n'
        'dependencies = ["tagpkg==1.0"]\n'
    )
    env = dict(os.environ, UV_NO_INDEX="1", UV_FIND_LINKS=str(tag_index))
    subprocess.run([_env.find_uv(), "lock", "--quiet"], cwd=proj, env=env, check=True)
    assert (proj / "uv.lock").is_file()
    assert _env.find_source(proj, "auto") == proj / "uv.lock"
    assert _build_for(tmp_path, monkeypatch, tag_index, proj / "uv.lock", LINUX) == WANT


def test_packages_are_byte_compiled_for_the_lenders_python(tmp_path, monkeypatch, tag_index):
    reqs = tmp_path / "requirements.txt"
    reqs.write_text("tagpkg==1.0\n")
    _build_for(tmp_path, monkeypatch, tag_index, reqs, LINUX)
    site = _env.build(reqs, LINUX)
    tag = sys.implementation.cache_tag
    assert (site / "tagpkg" / "__pycache__" / f"__init__.{tag}.pyc").is_file()


# ---------------------------------------------------------------------------- containers

IMAGE = os.environ.get("GMC_TEST_PY_IMAGE", "python:3.12-slim")


@pytest.fixture(scope="module")
def container_granted():
    import shutil

    if not shutil.which("docker"):
        if os.environ.get("GMC_REQUIRE_CONTAINER"):
            pytest.fail("docker is not installed")
        pytest.skip("docker is not installed")
    if subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode:
        if os.environ.get("GMC_REQUIRE_CONTAINER"):
            pytest.fail(f"image {IMAGE} is not on this machine")
        pytest.skip(f"image {IMAGE} is not on this machine (set GMC_TEST_PY_IMAGE)")
    modes = (pb.EXECUTION_MODE_CONTAINER,)
    lender, borrower, fp = paired_daemons(modes=modes)
    try:
        ask_grant(lender, borrower, fp, modes=modes)
        yield {"borrower": borrower.home, "lender": lender.home}
    finally:
        lender.stop()
        borrower.stop()


def test_a_lockfile_installs_into_a_container_image_for_its_linux(
    container_granted, offline_index
):
    mod = make_project({"requirements.txt": "tagpkg==1.0\n"})
    lock = Path(mod.__file__).parent / "requirements.txt"
    home = container_granted["borrower"]
    # "auto" adds nothing to an image: the image is the environment.
    with gmc.Pool(home=home, image=IMAGE) as pool:
        with pytest.raises(gmc.RemoteError) as e:
            pool.map(mod.tag, [0])
        assert e.value.type in ("ModuleNotFoundError", "ImportError")
    with gmc.Pool(home=home, image=IMAGE, env=gmc.Lockfile(lock)) as pool:
        (got,) = pool.map(mod.tag, [0])
    py = got["python"]
    arch = "aarch64" if platform.machine().lower() in ("arm64", "aarch64") else "x86_64"
    assert got["tag"] == f"cp{py[0]}{py[1]}-cp{py[0]}{py[1]}-manylinux_2_17_{arch}", got
    assert got["from_task"] and got["pem"]
