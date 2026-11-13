import os
from pathlib import Path

import pytest

import gimmecores as gmc


def test_map_runs_on_the_lender_in_order(granted, project):
    with gmc.Pool(home=granted["borrower"]) as pool:
        assert pool.remote
        assert pool.map(project.square, range(20), chunksize=5) == [x * x for x in range(20)]
        # It really ran on the lender, inside its task folder.
        (cwd,) = pool.map(project.where, [0])
        assert str(Path(granted["lender"]).resolve()) in str(Path(cwd).resolve()), cwd


def test_imap_unordered_and_executor(granted, project):
    with gmc.Pool(home=granted["borrower"]) as pool:
        assert sorted(pool.imap_unordered(project.square, range(6))) == [0, 1, 4, 9, 16, 25]
    with gmc.Executor(home=granted["borrower"]) as ex:
        assert ex.submit(project.square, 7).result() == 49


def test_remote_exceptions_come_back_as_remote_error(granted, project):
    with gmc.Pool(home=granted["borrower"]) as pool:
        with pytest.raises(gmc.RemoteError) as e:
            pool.map(project.boom, [3])
    assert e.value.type == "ValueError"
    assert "bad 3" in e.value.message
    assert "Traceback" in e.value.traceback


def test_results_must_be_json(granted, project):
    with gmc.Pool(home=granted["borrower"]) as pool:
        with pytest.raises(gmc.RemoteError) as e:
            pool.map(project.not_json, [1])
    assert e.value.type == "TypeError" and "JSON" in e.value.message


def test_the_lender_sandbox_hides_its_owners_files(granted, project):
    secret = Path(os.path.expanduser("~")) / ".gmc-sdk-test-secret"
    secret.write_text("TOP-SECRET")
    try:
        with gmc.Pool(home=granted["borrower"]) as pool:
            with pytest.raises(gmc.RemoteError) as e:
                pool.map(project.read_home_secret, [str(secret)])
        assert "TOP-SECRET" not in str(e.value) + e.value.traceback
    finally:
        secret.unlink()


def test_lambdas_are_refused_in_standard_mode(granted):
    with gmc.Pool(home=granted["borrower"]) as pool:
        with pytest.raises(gmc.GimmeCoresError, match="lambda"):
            pool.map(lambda x: x, [1])


def test_without_a_daemon_it_runs_locally(project, tmp_path):
    with gmc.Pool(home=tmp_path) as pool:
        assert not pool.remote
        assert pool.map(project.square, range(5)) == [0, 1, 4, 9, 16]
    with pytest.raises(gmc.GimmeCoresError):
        gmc.Pool(home=tmp_path, local_fallback=False)


def test_src_layout_packages_import_on_the_lender(granted, project):
    import pkgx.calc

    with gmc.Pool(home=granted["borrower"]) as pool:
        assert pool.map(pkgx.calc.triple, [1, 2]) == [3, 6]


def test_without_pyproject_nothing_is_sent_unless_a_folder_is_named(granted, tmp_path):
    import importlib
    import sys

    (tmp_path / "loose.py").write_text("def ident(x):\n    return x\n")
    sys.path.insert(0, str(tmp_path))
    loose = importlib.import_module("loose")
    with gmc.Pool(home=granted["borrower"]) as pool:
        with pytest.raises(gmc.GimmeCoresError, match="pyproject"):
            pool.map(loose.ident, [1])
    with gmc.Pool(home=granted["borrower"], project=tmp_path) as pool:
        assert pool.map(loose.ident, [5]) == [5]


def test_batches_grow_for_quick_calls_and_keep_order(monkeypatch, tmp_path):
    """Automatic batching without a lender: many tiny calls end up in few, larger batches."""
    import gimmecores._api as api

    sizes = []
    real = api.Pool._run_local

    def spy(self, fn, calls):
        sizes.append(len(calls))
        return real(self, fn, calls)

    monkeypatch.setattr(api.Pool, "_run_local", spy)
    with gmc.Pool(home=tmp_path, max_workers=2) as pool:
        assert pool.map(abs, range(-300, 0)) == list(range(300, 0, -1))
        assert sorted(pool.imap_unordered(abs, range(-50, 0))) == list(range(1, 51))
    assert sizes[0] == 1, "starts small"
    assert max(sizes) > 8, f"grew: {sizes[:20]}"
    assert len(sizes) < 150, f"far fewer tasks than calls: {len(sizes)}"
    sizes.clear()
    with gmc.Pool(home=tmp_path, max_workers=2) as pool:
        pool.map(abs, range(-30, 0), chunksize=10)
    assert sizes == [10, 10, 10], "an explicit chunksize wins"
