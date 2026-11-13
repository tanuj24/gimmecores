"""Trusted mode (threat model, section 6) against two real daemons: lambdas and live objects
work once both devices turn it on, and nothing a lender sends can get itself unpickled
otherwise. A hostile lender is simulated by a task that prints a forged result line (a pickle
that, if loaded, would create a marker file on the borrower)."""

import base64
import os
import pickle
import sys
import time

import pytest

import gimmecores as gmc
from gimmecores import _api
from gimmecores._proto.gimmecores.local.v1 import local_pb2 as l
from gimmecores._proto.gimmecores.peer.v1 import peer_pb2 as pb

from conftest import ask_grant, paired_daemons


class Evil:
    """Unpickling this opens (creates) the marker file: proof that a pickle was loaded."""

    def __init__(self, path):
        self.path = path

    def __reduce__(self):
        return (open, (self.path, "w"))


def forged(marker) -> str:
    return base64.b64encode(pickle.dumps(Evil(str(marker)))).decode()


class Pair:
    def __init__(self):
        self.lender, self.borrower, self.lender_fp = paired_daemons()
        self.borrower_fp = self.borrower.client.GetStatus(l.GetStatusRequest()).fingerprint

    def trust(self, on: bool, *, lender: bool = True, borrower: bool = True):
        if lender:
            self.lender.control.SetTrustedMode(
                l.SetTrustedModeRequest(
                    peer_fingerprint=self.borrower_fp, enabled=on, warning_acknowledged=on
                )
            )
        if borrower:
            self.borrower.control.SetTrustedMode(
                l.SetTrustedModeRequest(
                    peer_fingerprint=self.lender_fp, enabled=on, warning_acknowledged=on
                )
            )

    def grant(self, trusted: bool):
        return ask_grant(self.lender, self.borrower, self.lender_fp, trusted=trusted)

    def pool(self, **kw):
        return gmc.Pool(home=self.borrower.home, echo_output=False, **kw)

    def stop(self):
        self.lender.stop()
        self.borrower.stop()


@pytest.fixture(scope="module")
def pair():
    p = Pair()
    yield p
    p.stop()


@pytest.fixture(scope="module")
def same_python(pair, project):
    """Trusted mode needs the same Python version on both sides; here the lender's sandbox
    runs the system Python. CI runs these tests with that Python (GMC_REQUIRE_TRUSTED=1)."""
    pair.grant(trusted=False)
    with pair.pool() as pool:
        (theirs,) = pool.map(project.python_version, [0])
    ours = list(sys.version_info[:2])
    if theirs != ours:
        msg = f"the lender runs Python {theirs}, these tests run {ours}"
        if os.environ.get("GMC_REQUIRE_TRUSTED") == "1":
            pytest.fail(msg)
        pytest.skip(msg + " (run pytest with the lender's Python to test Trusted mode)")


def test_a_standard_pool_never_unpickles_what_a_lender_sends(pair, project, tmp_path):
    pair.grant(trusted=False)
    marker = tmp_path / "unpickled"
    with pair.pool() as pool:
        with pytest.raises(gmc.GimmeCoresError, match="malformed"):
            pool.map(project.forge_result, [forged(marker)])
    assert not marker.exists()


def test_without_trusted_mode_here_a_trusted_pool_runs_nothing_remotely(pair):
    with pytest.raises(gmc.GimmeCoresError, match="Trusted"):
        pair.pool(trusted=True, local_fallback=False)
    # With the local fallback, lambdas still work (on this device only).
    with pair.pool(trusted=True) as pool:
        assert not pool.remote
        k = 3
        assert pool.map(lambda x: x * k, [1, 2]) == [3, 6]


def test_trusted_mode_on_with_only_a_standard_grant_is_not_enough(pair):
    pair.trust(True)
    try:
        with pytest.raises(gmc.GimmeCoresError, match="Trusted"):
            pair.pool(trusted=True, local_fallback=False)
        # Asked of the daemon directly, it refuses too.
        job = l.JobSpec(
            project_root="/tmp",
            trusted=True,
            inline_tasks=[l.InlineTask(name="t", command=pb.Command(argv=["true"]))],
        )
        with pytest.raises(Exception, match="no Trusted grant"):
            list(pair.borrower.client.SubmitJob(job))
    finally:
        pair.trust(False)


def test_only_one_side_on_gets_no_trusted_grant(pair):
    pair.trust(True, lender=False)
    try:
        with pytest.raises(AssertionError):
            pair.grant(trusted=True)  # declined by the lender
    finally:
        pair.trust(False)


def test_lambdas_closures_and_live_objects_once_both_sides_agree(pair, same_python, project):
    pair.trust(True)
    try:
        g = pair.grant(trusted=True)
        assert g.grant.trust == pb.TRUST_LEVEL_TRUSTED
        with pair.pool(trusted=True, local_fallback=False) as pool:
            assert pool.remote
            k = 10
            assert pool.map(lambda x: x * k, range(5)) == [0, 10, 20, 30, 40]
            # Not JSON: sets, tuples, bytes come back as themselves.
            assert pool.map(lambda x: ({x, x + 1}, (x,), b"b"), [1]) == [({1, 2}, (1,), b"b")]
            # It ran on the lender.
            (cwd,) = pool.map(lambda _: os.getcwd(), [0])
            assert str(pair.lender.home.resolve()) in os.path.realpath(cwd), cwd

            def boom(x):
                raise KeyError(x)

            with pytest.raises(gmc.RemoteError) as e:
                pool.map(boom, ["k"])
            assert isinstance(e.value.exception, KeyError)
            assert e.value.type == "KeyError"
        with gmc.Executor(home=pair.borrower.home, trusted=True, echo_output=False) as ex:
            assert ex.submit(lambda a, b: a + b, 2, b=3).result() == 5
    finally:
        pair.trust(False)


def test_a_different_python_is_refused_before_anything_is_loaded(
    pair, same_python, monkeypatch
):
    pair.trust(True)
    try:
        pair.grant(trusted=True)
        monkeypatch.setattr(_api, "_python_version", lambda: [2, 7])
        with pair.pool(trusted=True, local_fallback=False) as pool:
            with pytest.raises(gmc.GimmeCoresError, match="same Python version"):
                pool.map(lambda x: x, [1])
    finally:
        pair.trust(False)


def test_turned_off_here_during_the_task_nothing_is_unpickled(pair, same_python, tmp_path):
    pair.trust(True)
    pair.grant(trusted=True)
    marker = tmp_path / "unpickled"
    payload = forged(marker)

    def slow_forge(p):
        import os as _os
        import sys as _sys
        import time as _time

        _time.sleep(2)
        import json

        tag = json.load(open(".gmc-sdk/spec.json"))["tag"]
        _sys.stdout.write("GMC-RESULT-" + tag + " " + p + "\n")
        _sys.stdout.flush()
        _os._exit(0)

    with pair.pool(trusted=True, local_fallback=False) as pool:
        fut = pool._threads.submit(pool.map, slow_forge, [payload])
        time.sleep(0.8)
        pair.trust(False, lender=False)  # only this device's own switch
        with pytest.raises(gmc.GimmeCoresError):
            fut.result(30)
    assert not marker.exists()
    pair.trust(False)
