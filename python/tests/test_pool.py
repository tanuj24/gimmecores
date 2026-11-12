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
