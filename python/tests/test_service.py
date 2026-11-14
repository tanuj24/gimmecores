"""Stopping the lender's service must stop the tasks it is running: nothing may keep running
with no daemon watching its limits, its time or its grant. launchd, systemd, the app's switch
and `brew services stop` all stop it with SIGTERM; a closed terminal sends SIGHUP."""

from __future__ import annotations

import os
import signal
import subprocess
import time

import pytest

from conftest import BIN, _until, ask_grant, paired_daemons


def processes(marker: str) -> list[str]:
    out = subprocess.run(
        ["ps", "-A", "-o", "pid=,command="], capture_output=True, text=True, check=True
    ).stdout
    # The sleeps themselves, not the shells and wrappers whose command lines mention them.
    return [line.strip() for line in out.splitlines() if line.split(None, 1)[1:] == [f"sleep {marker}"]]


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT, signal.SIGHUP], ids=lambda s: s.name)
def test_stopping_the_service_stops_its_tasks(sig, tmp_path):
    lender, borrower, lender_fp = paired_daemons()
    # A sleep length no other process uses: the marker to look for.
    marker = f"3{os.getpid() % 100000:05d}{int(sig):02d}"
    try:
        ask_grant(lender, borrower, lender_fp)
        project = tmp_path / "project"
        project.mkdir()
        (project / "a.txt").write_text("x\n")
        # A process tree: a background child and a foreground one.
        run = subprocess.Popen(
            [str(BIN / "gmc"), "run", "--", "sh", "-c", f"sleep {marker} & sleep {marker}; wait"],
            cwd=project,
            env={**os.environ, "GMC_HOME": str(borrower.home)},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            _until(lambda: len(processes(marker)) == 2)
            t0 = time.monotonic()
            lender.proc.send_signal(sig)
            assert lender.proc.wait(15) == 0, "a requested stop is a clean exit"
            assert time.monotonic() - t0 < 12
            _until(lambda: not processes(marker), 5)
            # The borrower is told, instead of waiting out its timeout.
            assert run.wait(15) != 0
            assert "cancelled" in run.stderr.read().lower()
        finally:
            run.kill()
            for line in processes(marker):
                os.kill(int(line.split()[0]), signal.SIGKILL)
    finally:
        lender.stop()
        borrower.stop()
