"""gmc.File / gmc.Dir: local files sent with a task, and files a remote function returns."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

import gimmecores as gmc

from test_env import make_project

MODULE_EXTRA = r'''

import gimmecores as gmc


def count_lines(f):
    with open(f) as fh:
        return [type(f).__name__, sum(1 for _ in fh), f.name]


def list_dir(d):
    return sorted(os.listdir(d))


def make_file(text):
    with open("out.txt", "w") as fh:
        fh.write(text)
    return gmc.File("out.txt")


def make_dir(n):
    os.makedirs("outdir/sub", exist_ok=True)
    for i in range(n):
        with open(f"outdir/sub/{i}.txt", "w") as fh:
            fh.write(str(i))
    return {"dir": gmc.Dir("outdir"), "files": [make_file("one"), gmc.File("outdir/sub/0.txt")]}


@gmc.task(secrets=["GMC_TEST_TASK_TOKEN"])
def use_secret(token):
    leftover = [k for k in os.environ if k.startswith("GMC_SECRET_")]
    return [type(token).__name__, len(token), os.environ.get("GMC_TEST_TASK_TOKEN"), leftover]


def echo(x):
    return x


def forge(rel):
    """A hostile lender: prints a result line naming a file outside the results folder."""
    import json, sys
    tag = json.load(open(".gmc-sdk/spec.json"))["tag"]
    sys.stdout.write("GMC-RESULT-" + tag + " " + json.dumps(
        [{"ok": {"__gmc_file__": rel, "dir": False}}]) + "\n")
    sys.stdout.flush()
    os._exit(0)
'''


@pytest.fixture(scope="module")
def mod():
    from test_env import MODULE
    import test_env

    old = test_env.MODULE
    test_env.MODULE = MODULE + MODULE_EXTRA
    try:
        return make_project({})
    finally:
        test_env.MODULE = old


def test_files_and_folders_go_with_the_task(granted, mod, tmp_path):
    a, b = tmp_path / "a.csv", tmp_path / "b.csv"
    a.write_text("1\n2\n3\n")
    b.write_text("x\n")
    d = tmp_path / "data"
    (d / "inner").mkdir(parents=True)
    (d / "inner" / "z.txt").write_text("z")
    (d / "y.txt").write_text("y")
    with gmc.Pool(home=granted["borrower"]) as pool:
        assert pool.remote
        got = pool.map(mod.count_lines, [gmc.File(a), gmc.File(b), gmc.File(a)])
        assert got == [["File", 3, "a.csv"], ["File", 1, "b.csv"], ["File", 3, "a.csv"]]
        assert pool.map(mod.list_dir, [gmc.Dir(d)]) == [["inner", "y.txt"]]


def test_returned_files_come_back(granted, mod, tmp_path):
    with gmc.Pool(home=granted["borrower"], results_dir=tmp_path / "results") as pool:
        (f,) = pool.map(mod.make_file, ["hello"])
        assert isinstance(f, gmc.File) and f.read_text() == "hello"
        assert Path(f.path).is_relative_to(tmp_path / "results")
        (got,) = pool.map(mod.make_dir, [3])
    assert isinstance(got["dir"], gmc.Dir)
    assert sorted(p.name for p in Path(got["dir"]).joinpath("sub").iterdir()) == [
        "0.txt", "1.txt", "2.txt"]
    assert [x.read_text() for x in got["files"]] == ["one", "0"]


def test_nothing_returned_leaves_no_folders(granted, mod, tmp_path):
    results = tmp_path / "results"
    with gmc.Pool(home=granted["borrower"], results_dir=results) as pool:
        pool.map(mod.list_dir, [gmc.Dir(tmp_path)])
    assert list(results.iterdir()) == []


def test_a_file_with_a_secret_is_not_sent(granted, mod, tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("key = " + "AKIA" + "ABCDEFGHIJKLMNOP\n")
    with gmc.Pool(home=granted["borrower"]) as pool:
        with pytest.raises(gmc.GimmeCoresError, match="possible secrets"):
            pool.map(mod.count_lines, [gmc.File(f)])


def test_missing_or_wrong_kind_is_refused_before_sending(granted, mod, tmp_path):
    with gmc.Pool(home=granted["borrower"]) as pool:
        with pytest.raises(gmc.GimmeCoresError, match="not a file"):
            pool.map(mod.count_lines, [gmc.File(tmp_path / "missing.txt")])
        with pytest.raises(gmc.GimmeCoresError, match="not a folder"):
            pool.map(mod.list_dir, [gmc.Dir(tmp_path / "missing")])
        with pytest.raises(gmc.GimmeCoresError, match="reserved"):
            pool.map(mod.list_dir, [{"__gmc_file__": "x", "dir": False}])


@pytest.mark.parametrize(
    "rel",
    [
        "../../../../etc/hosts",
        ".gmc-out/../../../etc/hosts",
        "/etc/hosts",
        ".gmc-out/0/1/never-sent.txt",
        "mathy.py",
    ],
)
def test_a_lender_cannot_point_a_result_outside_what_it_returned(granted, mod, tmp_path, rel):
    with gmc.Pool(home=granted["borrower"], results_dir=tmp_path) as pool:
        with pytest.raises(gmc.GimmeCoresError, match="file"):
            pool.map(mod.forge, [rel])


def test_files_work_the_same_without_a_lender(mod, tmp_path, monkeypatch):
    # Local worker processes import the module by name, like any multiprocessing pool.
    monkeypatch.syspath_prepend(str(Path(mod.__file__).parent))
    a = tmp_path / "a.txt"
    a.write_text("1\n2\n")
    with gmc.Pool(home=tmp_path / "nodaemon") as pool:
        assert not pool.remote
        assert pool.map(mod.count_lines, [gmc.File(a)]) == [["File", 2, "a.txt"]]


def test_file_objects():
    f = gmc.File("/tmp/x.txt")
    assert str(f) == "/tmp/x.txt" and f.name == "x.txt" and repr(f) == "gmc.File('/tmp/x.txt')"
    assert f == gmc.File("/tmp/x.txt") != gmc.Dir("/tmp/x.txt")
    assert Path(f) == Path("/tmp/x.txt")


# ---------------------------------------------------------------------------- secrets

SECRET = "v-" + "9f8e7d6c5b4a" * 3


def _files_containing(root: Path, needle: bytes) -> list:
    hits = []
    for p in root.rglob("*"):
        try:
            if p.is_file() and needle in p.read_bytes():
                hits.append(str(p))
        except OSError:
            pass
    return hits


def test_secrets_reach_the_function_and_nothing_else(granted, mod, monkeypatch, capsys):
    monkeypatch.setenv("GMC_TEST_ARG_TOKEN", SECRET)
    monkeypatch.setenv("GMC_TEST_TASK_TOKEN", "task-" + SECRET)
    with gmc.Pool(home=granted["borrower"]) as pool:
        got = pool.map(mod.use_secret, [gmc.Secret("GMC_TEST_ARG_TOKEN")] * 2)
    assert got == [["str", len(SECRET), "task-" + SECRET, []]] * 2, got
    err = capsys.readouterr().err
    assert "sending the secret GMC_TEST_ARG_TOKEN to Lender" in err
    assert err.count("GMC_TEST_ARG_TOKEN") == 1, "said once per pool"
    assert SECRET not in err
    # Not in any file on either device: audit logs, stored inputs, saved grants.
    for home in (granted["lender"], granted["borrower"]):
        assert _files_containing(Path(home), SECRET.encode()) == []
        assert _files_containing(Path(home), b"GMC_TEST_ARG_TOKEN"), "the name is recorded"


def test_a_missing_secret_stops_before_anything_is_sent(granted, mod, monkeypatch):
    monkeypatch.delenv("GMC_TEST_ARG_TOKEN", raising=False)
    monkeypatch.setenv("GMC_TEST_TASK_TOKEN", "x")
    with gmc.Pool(home=granted["borrower"]) as pool:
        with pytest.raises(gmc.GimmeCoresError, match="GMC_TEST_ARG_TOKEN is not set"):
            pool.map(mod.use_secret, [gmc.Secret("GMC_TEST_ARG_TOKEN")])


def test_secret_names_are_checked():
    for bad in ["PATH", "LD_PRELOAD", "A-B", "", "1A"]:
        with pytest.raises(ValueError):
            gmc.task(secrets=[bad])(lambda: None)
    for bad in ["A-B", "", "1A", None]:
        with pytest.raises(ValueError):
            gmc.Secret(bad)
    assert "x" not in repr(gmc.Secret("X_TOKEN").__repr__().replace("X_TOKEN", ""))


def test_a_secret_written_into_an_argument_is_caught(granted, mod):
    key = "AKIA" + "ABCDEFGHIJKLMNOP"
    with gmc.Pool(home=granted["borrower"]) as pool:
        with pytest.raises(gmc.GimmeCoresError, match="possible secrets"):
            pool.map(mod.echo, [key])
    with gmc.Pool(home=granted["borrower"], send_flagged_payload=True) as pool:
        assert pool.map(mod.echo, [key]) == [key]


def test_secrets_work_the_same_without_a_lender(mod, tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(mod.__file__).parent))
    monkeypatch.setenv("GMC_TEST_ARG_TOKEN", SECRET)
    monkeypatch.setenv("GMC_TEST_TASK_TOKEN", "t")
    with gmc.Pool(home=tmp_path / "nodaemon") as pool:
        got = pool.map(mod.use_secret, [gmc.Secret("GMC_TEST_ARG_TOKEN")])
    assert got[0][:3] == ["str", len(SECRET), "t"]


def test_the_notebook_extension_shows_devices_and_grants(granted, monkeypatch, capsys):
    from gimmecores import _jupyter

    registered = {}

    class FakeIPython:
        def register_magic_function(self, fn, magic_kind, magic_name):
            registered[magic_name] = (fn, magic_kind)

    monkeypatch.setenv("GMC_HOME", str(granted["borrower"]))
    gmc.load_ipython_extension(FakeIPython())
    fn, kind = registered["gmc"]
    assert kind == "line"
    fn("")
    out = capsys.readouterr().out
    assert "Lender" in out and "standard" in out and "Trusted mode off" in out, out
    monkeypatch.setenv("GMC_HOME", "/nonexistent-gmc-home")
    assert "no daemon" in _jupyter.status_text()
