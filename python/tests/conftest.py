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


def paired_daemons(modes=(pb.EXECUTION_MODE_SANDBOX,)):
    """Two daemons, paired; the lender lends `modes` (default: its sandbox).
    Returns (lender, borrower, lender_fp)."""
    if not (BIN / "gmcd").exists():
        pytest.skip(f"no gmcd at {BIN} (cargo build -p gimmecores-cli, or set GMC_BIN_DIR)")
    lender, borrower = Daemon("Lender"), Daemon("Borrower")
    try:
        lender.control.SetLending(l.SetLendingRequest(enabled=True, allow_on_battery=True))
        lender.control.SetLendModes(l.SetLendModesRequest(modes=list(modes)))
        st = _until(lambda: lender.client.GetStatus(l.GetStatusRequest()))
        missing = [m for m in modes if m not in st.available_modes]
        if missing:
            lender.stop()
            borrower.stop()
            pytest.skip(f"no working {pb.ExecutionMode.Name(missing[0])} runner on this machine")
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
        # Both sides: the lender refuses requests until its own side of the pairing is saved.
        for d in (borrower, lender):
            _until(lambda d=d: any(p.paired for p in d.client.ListPeers(l.ListPeersRequest()).peers))
    except BaseException:
        lender.stop()
        borrower.stop()
        raise
    return lender, borrower, st.fingerprint


def ask_grant(
    lender: Daemon, borrower: Daemon, lender_fp: str, trusted: bool = False,
    modes=(pb.EXECUTION_MODE_SANDBOX,),
):
    """The borrower asks; the lender's owner accepts. Returns the borrower's GrantInfo."""
    result = {}

    def ask():
        req = pb.GrantRequest(
            limits=pb.Limits(cpu_millis=2000, memory_bytes=2 << 30, disk_bytes=1 << 30, max_concurrent_tasks=4),
            modes=list(modes),
            reason="python sdk tests",
            trust=pb.TRUST_LEVEL_TRUSTED if trusted else pb.TRUST_LEVEL_STANDARD,
        )
        req.duration.seconds = 3600
        try:
            result["grant"] = borrower.client.RequestGrant(
                l.RequestGrantRequest(peer_fingerprint=lender_fp, request=req)
            )
        except Exception as e:  # noqa: BLE001 (reported below)
            result["error"] = e

    t = threading.Thread(target=ask)
    t.start()
    try:
        # Either the request reaches the lender's owner, or it is answered without them.
        pending = _until(
            lambda: ("answered" if result else None) or next(
                (g for g in lender.client.ListGrants(l.ListGrantsRequest()).grants
                 if g.state == pb.GRANT_STATE_REQUESTED),
                None,
            )
        )
        if pending != "answered":
            lender.control.RespondToGrant(
                l.RespondToGrantRequest(grant_id=pending.grant_id, decision=l.RespondToGrantRequest.DECISION_ACCEPT)
            )
    finally:
        t.join(20)
    if "error" in result:
        raise result["error"]
    assert result["grant"].state == pb.GRANT_STATE_ACTIVE, result["grant"]
    return result["grant"]


@pytest.fixture(scope="session")
def granted():
    lender, borrower, lender_fp = paired_daemons()
    try:
        ask_grant(lender, borrower, lender_fp)
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


def python_version(_):
    import sys

    return list(sys.version_info[:2])


def python_executable(_):
    import sys

    return sys.executable


def forge_result(payload_b64):
    """A hostile lender: print a result line of its own (a pickle that, if loaded, writes a
    marker file) with the task's real tag, then exit before the real result is printed."""
    import json, os, sys

    if os.path.exists(".gmc-sdk/spec.json"):
        tag = json.load(open(".gmc-sdk/spec.json"))["tag"]
    else:
        import base64

        tag = json.loads(base64.b64decode(sys.argv[1]))["tag"]
    sys.stdout.write("GMC-RESULT-" + tag + " " + payload_b64 + "\\n")
    sys.stdout.flush()
    os._exit(0)
''',
    "src/pkgx/__init__.py": "",
    "src/pkgx/calc.py": "def triple(x):\n    return 3 * x\n",
}


@pytest.fixture(scope="session")
def project():
    import importlib
    import sys

    d = Path(tempfile.mkdtemp(prefix="gmc-proj"))
    for name, text in PROJECT_FILES.items():
        (d / name).parent.mkdir(parents=True, exist_ok=True)
        (d / name).write_text(text)
    sys.path.insert(0, str(d))
    sys.path.insert(0, str(d / "src"))
    return importlib.import_module("mathy")
