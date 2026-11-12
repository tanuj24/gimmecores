"""Two real gmcd daemons on loopback (lender lends its sandbox), paired and granted through the
local API. Approvals use `gmcd --no-presence` (no Touch ID in tests)."""

from __future__ import annotations

import os
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest

from gimmecores._daemon import channel
from gimmecores._proto.gimmecores.local.v1 import local_pb2 as l
from gimmecores._proto.gimmecores.local.v1 import local_pb2_grpc as rpc
from gimmecores._proto.gimmecores.peer.v1 import peer_pb2 as pb

REPO = Path(__file__).resolve().parents[2]
BIN = Path(os.environ.get("GMC_BIN_DIR", REPO / "target" / "debug"))


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Daemon:
    def __init__(self, name: str):
        # Short path: Unix socket paths are length-limited.
        self.home = Path(tempfile.mkdtemp(prefix="gmc", dir="/tmp"))
        env = dict(os.environ, GMC_HOME=str(self.home))
        self.proc = subprocess.Popen(
            [str(BIN / "gmcd"), "--name", name, "--listen", f"127.0.0.1:{free_port()}", "--no-presence"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(200):
            if (self.home / "run" / "control.sock").exists():
                break
            time.sleep(0.05)
        else:
            raise RuntimeError(f"gmcd did not start (binary: {BIN / 'gmcd'})")
        self.client = rpc.ClientStub(channel(self.home / "run" / "client.sock"))
        self.control = rpc.ControlStub(channel(self.home / "run" / "control.sock"))

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def _until(f, secs=20.0):
    end = time.time() + secs
    while time.time() < end:
        v = f()
        if v:
            return v
        time.sleep(0.1)
    raise TimeoutError("condition not met")


@pytest.fixture(scope="session")
def granted():
    if not (BIN / "gmcd").exists():
        pytest.skip(f"no gmcd at {BIN} (cargo build -p gimmecores-cli, or set GMC_BIN_DIR)")
    lender, borrower = Daemon("Lender"), Daemon("Borrower")
    try:
        lender.control.SetLending(l.SetLendingRequest(enabled=True))
        lender.control.SetLendModes(l.SetLendModesRequest(modes=[pb.EXECUTION_MODE_SANDBOX]))
        st = lender.client.GetStatus(l.GetStatusRequest())
        if pb.EXECUTION_MODE_SANDBOX not in st.available_modes:
            pytest.skip("no working sandbox on this machine")
        ticket = lender.control.OpenPairing(l.OpenPairingRequest()).ticket
        borrower.control.StartPairing(l.StartPairingRequest(ticket=ticket))
        for d in (borrower, lender):
            s = _until(
                lambda d=d: next(
                    (x for x in d.control.ListPairings(l.ListPairingsRequest()).sessions if x.code),
                    None,
                )
            )
            d.control.ConfirmPairing(l.ConfirmPairingRequest(session_id=s.session_id, codes_match=True))
        lender_fp = st.fingerprint
        _until(lambda: any(p.paired for p in borrower.client.ListPeers(l.ListPeersRequest()).peers))

        result = {}

        def ask():
            req = pb.GrantRequest(
                limits=pb.Limits(cpu_millis=2000, memory_bytes=2 << 30, disk_bytes=1 << 30, max_concurrent_tasks=4),
                modes=[pb.EXECUTION_MODE_SANDBOX],
                reason="python sdk tests",
            )
            req.duration.seconds = 3600
            result["grant"] = borrower.client.RequestGrant(
                l.RequestGrantRequest(peer_fingerprint=lender_fp, request=req)
            )

        t = threading.Thread(target=ask)
        t.start()
        pending = _until(
            lambda: next(
                (g for g in lender.client.ListGrants(l.ListGrantsRequest()).grants
                 if g.state == pb.GRANT_STATE_REQUESTED),
                None,
            )
        )
        lender.control.RespondToGrant(
            l.RespondToGrantRequest(grant_id=pending.grant_id, decision=l.RespondToGrantRequest.DECISION_ACCEPT)
        )
        t.join(20)
        assert result["grant"].state == pb.GRANT_STATE_ACTIVE
        yield {"borrower": borrower.home, "lender": lender.home}
    finally:
        lender.stop()
        borrower.stop()


PROJECT_FILES = {
    "pyproject.toml": '[project]\nname = "demo"\nversion = "0"\n',
    "mathy.py": '''
import os

import gimmecores as gmc


@gmc.task(cpus=1, memory="256m")
def square(x):
    print(f"squaring {x}")
    return x * x


def boom(x):
    raise ValueError(f"bad {x}")


def not_json(x):
    return {1, 2}


def where(_):
    return os.getcwd()


def read_home_secret(path):
    return open(path).read()
''',
}


@pytest.fixture(scope="session")
def project():
    import importlib
    import sys

    d = Path(tempfile.mkdtemp(prefix="gmc-proj"))
    for name, text in PROJECT_FILES.items():
        (d / name).write_text(text)
    sys.path.insert(0, str(d))
    return importlib.import_module("mathy")
