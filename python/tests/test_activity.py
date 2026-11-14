"""`gmc tasks` on a real lender with its real sandbox: the borrower's command, what it asked
for and what it uses, measured; the owner stopping one task; the finished list."""

from __future__ import annotations

import os
import re
import subprocess
import time

from conftest import BIN, _until

# Busy for about five seconds on any shell (dash is several times faster than bash).
BUSY = ("end=$(( $(date +%s) + 5 )); while [ $(date +%s) -lt $end ]; do "
        "i=0; while [ $i -lt 20000 ]; do i=$((i+1)); done; done")


def gmc(home, *args):
    return subprocess.run(
        [str(BIN / "gmc"), *args],
        env={**os.environ, "GMC_HOME": str(home)},
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_the_lender_sees_and_stops_a_borrowers_task(granted, tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "data.txt").write_text("x\n")
    run = subprocess.Popen(
        [str(BIN / "gmc"), "run", "--cpus", "2", "--memory", "512m", "--",
         "sh", "-c", BUSY + "; echo done"],
        cwd=project,
        env={**os.environ, "GMC_HOME": str(granted["borrower"])},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        def measured():
            out = gmc(granted["lender"], "tasks").stdout
            return out if re.search(r"cpu +[\d.]+ cores? now, \d+[ms]", out) and "MiB" in out else None

        text = _until(measured, 30)
        assert "Running here for other devices" in text
        assert "for Borrower  sandbox" in text
        assert "end=$(( $(date +%s) + 5 ))" in text
        assert "asked   2 cores, 512 MiB" in text
        assert re.search(r"memory  [\d.]+ MiB now, peak [\d.]+ MiB", text), text
        assert "disk" in text
        assert all(len(line) <= 80 for line in text.splitlines()), text

        task_id = re.search(r"^  ([0-9a-f]{8})  running", text, re.M).group(1)
        stopped = gmc(granted["lender"], "tasks", "stop", task_id)
        assert stopped.returncode == 0, stopped.stderr
        assert "Its grant is unchanged" in stopped.stdout

        out, err = run.communicate(timeout=20)
        assert run.returncode != 0
        assert "stopped by the lender's owner" in err, err
        assert "done" not in out

        finished = _until(
            lambda: (t := gmc(granted["lender"], "tasks", "--all").stdout)
            and "stopped by you" in t and t,
            10,
        )
        assert "Nothing is running" in finished
        assert re.search(r"ran \d+[ms]", finished), finished
    finally:
        run.kill()


def test_stopping_an_unknown_task_says_so(granted):
    r = gmc(granted["lender"], "tasks", "stop", "abcdef12")
    assert r.returncode != 0
    assert "no task running here" in r.stderr
