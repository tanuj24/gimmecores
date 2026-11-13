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


def forge(rel):
    """A hostile lender: prints a result line naming a file outside the results folder."""
    import base64, json, sys
    tag = json.loads(base64.b64decode(sys.argv[1]))["tag"]
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
