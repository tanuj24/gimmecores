"""`gmc mcp` with the official MCP client, against two real daemons: what an agent can do
(run, check, cancel) and what it cannot (send folders outside its root, override the secret
scan, reach anything but its five tools). Cancelling, or the session ending, must stop the task
on the lender."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest

mcp = pytest.importorskip("mcp", reason="the MCP client needs Python 3.10+")
from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

from conftest import BIN, _until  # noqa: E402
from gimmecores._daemon import channel  # noqa: E402
from gimmecores._proto.gimmecores.local.v1 import local_pb2 as l  # noqa: E402
from gimmecores._proto.gimmecores.local.v1 import local_pb2_grpc as rpc  # noqa: E402


def lender_tasks(granted) -> int:
    stub = rpc.ClientStub(channel(Path(granted["lender"]) / "run" / "client.sock"))
    return stub.GetStatus(l.GetStatusRequest()).active_lent_tasks


@contextlib.asynccontextmanager
async def session(granted, root: Path, *, modern: bool = True):
    """An MCP session with `gmc mcp` serving `root`, as the borrower."""
    params = StdioServerParameters(
        command=str(BIN / "gmc"),
        args=["mcp", "--root", str(root)],
        env={**os.environ, "GMC_HOME": str(granted["borrower"])},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as s:
            await (s.discover() if modern else s.initialize())
            yield s


async def call(s, tool: str, args: dict) -> tuple[dict, bool]:
    r = await s.call_tool(tool, args)
    return json.loads(r.content[0].text), bool(r.is_error)


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    (root / "input.txt").write_text("forty-two\n")
    return root


@pytest.mark.parametrize("modern", [True, False], ids=["2026-07-28", "2025-11-25"])
def test_an_agent_sees_five_tools_and_the_granted_device(granted, project, modern):
    async def go():
        async with session(granted, project, modern=modern) as s:
            assert s.protocol_version == ("2026-07-28" if modern else "2025-11-25")
            tools = await s.list_tools()
            assert [t.name for t in tools.tools] == ["devices", "run", "job", "jobs", "cancel"]
            devices, err = await call(s, "devices", {})
            assert not err, devices
            assert devices["this_device"] == "Borrower"
            (lender,) = devices["devices"]
            assert lender["name"] == "Lender"
            assert lender["granted_to_you"][0]["runtimes"] == ["sandbox"]

    asyncio.run(go())


def test_run_streams_output_and_brings_back_outputs(granted, project):
    async def go():
        async with session(granted, project) as s:
            job, err = await call(s, "run", {
                "command": ["sh", "-c", "cat input.txt; mkdir -p out; echo done > out/r.txt"],
                "outputs": ["out"],
            })
            assert not err, job
            assert job["state"] == "succeeded", job
            assert job["exit_code"] == 0
            assert "forty-two" in job["output"]
            assert job["device"] == "Lender"
            assert (project / "out" / "r.txt").read_text() == "done\n"

            failed, err = await call(s, "run", {"command": ["sh", "-c", "echo oops >&2; exit 3"]})
            assert not err and failed["state"] == "failed" and failed["exit_code"] == 3
            assert "oops" in failed["output"]

            listed, _ = await call(s, "jobs", {})
            assert [j["state"] for j in listed["jobs"]] == ["succeeded", "failed"]

    asyncio.run(go())


def test_an_agent_cannot_send_outside_its_root_or_past_the_secret_scan(granted, project, tmp_path):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (project / "creds.txt").write_text("key = " + "AKIA" + "ABCDEFGHIJKLMNOP\n")

    async def go():
        async with session(granted, project) as s:
            for directory in [str(outside), "..", str(project.parent)]:
                r, err = await call(s, "run", {"command": ["true"], "directory": directory})
                assert err and "outside the folders" in r["error"], r
            r, err = await call(s, "run", {"command": ["true"]})
            assert err and r["state"] == "error", r
            assert "possible secrets" in r["error"] and "cannot send flagged files" in r["error"]
            for hostile in [{"trusted": True}, {"allow_secret": ["creds.txt"]},
                            {"env": {"A": "b"}}, {"output_dir": str(outside)}]:
                r, err = await call(s, "run", {"command": ["true"], **hostile})
                assert err and "unknown argument" in r["error"], r
            # Excluding the file is the way forward, and works.
            r, err = await call(s, "run", {"command": ["true"], "exclude": ["creds.txt"]})
            assert not err and r["state"] == "succeeded", r
        assert not list(outside.iterdir())

    asyncio.run(go())


def test_cancel_stops_the_task_on_the_lender(granted, project):
    async def go():
        async with session(granted, project) as s:
            job, err = await call(s, "run", {
                "command": ["sh", "-c", "echo started; sleep 60"], "wait_seconds": 0,
            })
            assert not err and job["state"] == "running", job
            await asyncio.to_thread(_until, lambda: lender_tasks(granted) == 1)
            t0 = time.monotonic()
            done, err = await call(s, "cancel", {"job": job["job"]})
            assert not err and done["state"] == "cancelled", done
            await asyncio.to_thread(_until, lambda: lender_tasks(granted) == 0, 15)
            assert time.monotonic() - t0 < 15

    asyncio.run(go())


def test_ending_the_session_stops_its_tasks(granted, project):
    async def go():
        async with session(granted, project) as s:
            job, err = await call(s, "run", {"command": ["sleep", "60"], "wait_seconds": 0})
            assert not err, job
            await asyncio.to_thread(_until, lambda: lender_tasks(granted) == 1)
        # The agent went away: its task does not keep the lender busy.
        await asyncio.to_thread(_until, lambda: lender_tasks(granted) == 0, 15)

    asyncio.run(go())


def test_ctrl_c_in_gmc_run_stops_the_task_on_the_lender(granted, project):
    proc = subprocess.Popen(
        [str(BIN / "gmc"), "run", "--", "sleep", "60"],
        cwd=project,
        env={**os.environ, "GMC_HOME": str(granted["borrower"])},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _until(lambda: lender_tasks(granted) == 1)
        proc.send_signal(signal.SIGINT)
        proc.wait(10)
        _until(lambda: lender_tasks(granted) == 0, 15)
    finally:
        proc.kill()
