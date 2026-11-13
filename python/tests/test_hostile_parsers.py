"""Everything the SDK reads from a lender (its result line, its platform report, returned file
references) under random and mutated input: only GimmeCores' own errors, never another
exception, and never an unpickle unless this device's daemon vouched for the task."""

from __future__ import annotations

import base64
import json
import pickle
import random
from pathlib import Path

import pytest

from gimmecores import _api, _env
from gimmecores._api import GimmeCoresError

TAG = "0123456789abcdef"
SEEDS = [
    f"GMC-RESULT-{TAG} " + json.dumps([{"ok": 1}, {"error": {"type": "E", "message": "m"}}]),
    f"GMC-RESULT-{TAG} " + json.dumps([{"ok": {"__gmc_file__": ".gmc-out/0/1/a", "dir": False}}]),
    f"GMC-RESULT-{TAG} " + base64.b64encode(pickle.dumps([("ok", 1)])).decode(),
    f"GMC-RESULT-{TAG} " + json.dumps({"refused": "nope"}),
    "GMC-PROBE-t " + json.dumps({"python": [3, 13], "impl": "cpython", "system": "linux",
                                 "machine": "x86_64", "mac": "", "libc": ["glibc", "2.39"],
                                 "free_threaded": False}),
]


def mutations(rng: random.Random, n: int):
    for _ in range(n):
        s = list(rng.choice(SEEDS))
        for _ in range(rng.randint(1, 4)):
            op = rng.randrange(4)
            if op == 0 and s:
                s[rng.randrange(len(s))] = chr(rng.choice([0, 10, 34, 44, 58, 91, 93, 123, 125,
                                                            rng.randrange(32, 0x2FF)]))
            elif op == 1:
                del s[rng.randrange(len(s) + 1):]
            elif op == 2:
                i = rng.randrange(len(s) + 1)
                s[i:i] = rng.choice(['{"ok":', '[', ']', '"__gmc_file__"', "..", "/", "null",
                                     '{"refused":1}', "\n", "9" * 400])
            else:
                s = list("".join(s).upper())
        yield "".join(s)


def test_the_json_result_decoder_only_raises_its_own_errors():
    rng = random.Random(1)
    for text in mutations(rng, 3000):
        try:
            _api._parse_results("noise\n" + text, 2, "peer", TAG)
        except GimmeCoresError:
            pass


def test_an_unvouched_trusted_result_is_never_unpickled(monkeypatch):
    def never(*a, **k):
        raise AssertionError("unpickled without the daemon's say-so")

    monkeypatch.setattr(pickle, "loads", never)
    rng = random.Random(2)
    for text in mutations(rng, 3000):
        try:
            _api._parse_trusted(text, 1, "peer", TAG, vouched=False)
        except GimmeCoresError:
            pass


def test_the_platform_probe_only_raises_its_own_errors():
    rng = random.Random(3)
    for text in mutations(rng, 3000):
        try:
            t = _env.parse_probe(text.replace(f"GMC-RESULT-{TAG}", "GMC-PROBE-t"), "t")
        except _env.EnvError:
            continue
        # Whatever got through is safe to put on a command line.
        assert t.platform.replace("-", "").replace("_", "").isalnum(), t
        assert all(c.isdigit() or c in ".t" for c in t.python_version + t.macos), t


def test_returned_file_references_stay_inside_the_task_folder(tmp_path):
    out = tmp_path / "task"
    (out / ".gmc-out" / "0" / "1").mkdir(parents=True)
    (out / ".gmc-out" / "0" / "1" / "a").write_text("x")
    (tmp_path / "secret").write_text("s")
    rng = random.Random(4)
    names = [".gmc-out/0/1/a", ".gmc-out/../secret", "../secret", "/etc/hosts", ".gmc-out",
             ".gmc-out/0/1/a/..", ".gmc-out//0/1/a", ".gmc-out/0/1/a\x00", "a", ""]
    for _ in range(2000):
        rel = rng.choice(names)
        if rng.random() < 0.5:
            rel = rel.replace("/", rng.choice(["/", "//", "/./", "\\"]))
        value = {"__gmc_file__": rel, "dir": rng.random() < 0.2}
        try:
            ((kind, got),) = _api.Pool._received([("ok", [value])], out)
        except GimmeCoresError:
            continue
        (f,) = got
        assert out.resolve() in Path(f.path).resolve().parents, (rel, f.path)


def test_requirement_lists_only_ever_yield_index_pins():
    rng = random.Random(5)
    seeds = ["numpy==2.1.0 \\\n  --hash=sha256:aa\n", "x @ https://u:p@h/x.whl\n", "-e ./a\n",
             "pkg[extra]==1.0 ; python_version < '3.12'\n", "git+https://h/r\n"]
    for _ in range(3000):
        s = list(rng.choice(seeds))
        for _ in range(rng.randint(1, 3)):
            i = rng.randrange(len(s) + 1)
            s[i:i] = rng.choice(["@", "/", "./", "==", " ", "\\\n", "#", ";", "-", "file:"])
        try:
            pins = _env.check_pins("".join(s))
        except _env.EnvError:
            continue
        for p in pins:
            req = p.split(" --hash", 1)[0]
            assert "@" not in req.split(";")[0] and "/" not in req.split(";")[0], p
