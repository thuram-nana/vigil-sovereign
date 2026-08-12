"""
Console benchmark action (`/api/benchmark/run`) — run the CRUCIBLE-only soundness benchmark LIVE.

The Brain > Benchmark screen surfaces this as an on-demand "prove the soundness now" button. It is an
EXECUTION surface, so the properties it must hold are the ones asserted here (every test patches
`subprocess.run` so the REAL benchmark never runs — fast + deterministic, and it lets us inspect the exact
argv/kwargs the action would spawn):

  * FIXED argv — nothing from the request body reaches the subprocess (no injection). Only
    `benchmark --no-incumbents` with tmp report/json paths, so it can never run an arbitrary tool/target.
  * incumbent-free — `--no-incumbents` is always present (no sqlmap/wapiti/nikto invoked).
  * BOUNDED — every spawn carries a `timeout=` (generous, but finite), so a wedged run can't pin the
    console request thread forever.
  * fail-soft — a non-zero exit, a timeout, or a non-dict body is reported as an error / tolerated, never a
    raise (the console never 500s on an action).
  * the CRUCIBLE row is extracted from the JSON snapshot the run writes.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from framework.v2.console import actions


def _fake_run_writing(results: dict, *, returncode: int = 0):
    """A subprocess.run stand-in: record the call, write `results` to the run's `--json` path, and return a
    CompletedProcess. Mirrors what the real `benchmark --json <path>` does, so benchmark_run can read it back."""
    seen: dict = {}

    def _run(cmd, *a, **kw):
        seen["cmd"] = list(cmd)
        seen["kwargs"] = kw
        # honour the fixed `--json <path>` the action passes so the reader finds a result
        if "--json" in cmd:
            jp = Path(cmd[cmd.index("--json") + 1])
            jp.parent.mkdir(parents=True, exist_ok=True)
            jp.write_text(json.dumps(results), encoding="utf-8")
        return subprocess.CompletedProcess(cmd, returncode, stdout="ok", stderr="")

    return _run, seen


_CLEAN = {"corpus": "in-process benchmark app (11 planted bugs, 5 safe controls)",
          "results": [{"tool": "crucible", "tp": 11, "fp": 0, "fn": 0,
                       "precision": 1.0, "recall": 1.0, "f1": 1.0, "elapsed_s": 3.2}]}


def test_benchmark_run_returns_the_crucible_row(monkeypatch) -> None:
    run, _ = _fake_run_writing(_CLEAN)
    monkeypatch.setattr(actions.subprocess, "run", run)
    r = actions.benchmark_run({})
    assert r["ok"] is True
    assert r["result"]["tp"] == 11 and r["result"]["fp"] == 0 and r["result"]["f1"] == 1.0


def test_benchmark_argv_is_fixed_and_ignores_the_body(monkeypatch) -> None:
    # A hostile body must NOT reach the subprocess: the argv is fixed (benchmark --no-incumbents + tmp paths).
    run, seen = _fake_run_writing(_CLEAN)
    monkeypatch.setattr(actions.subprocess, "run", run)
    actions.benchmark_run({"target": "http://evil/", "extra": "; rm -rf /", "incumbents": True,
                           "report": "/etc/passwd", "argv": ["--corpus"]})
    cmd = seen["cmd"]
    assert cmd[1:4] == ["-m", "framework.v2", "benchmark"]
    assert "--no-incumbents" in cmd                       # incumbent-free, always
    assert "--corpus" not in cmd                           # a body "argv" can't add flags
    # NOTHING request-derived reached the argv
    for bad in ("http://evil/", "; rm -rf /", "/etc/passwd", "--corpus", "True"):
        assert not any(bad in str(tok) for tok in cmd), f"request value {bad!r} leaked into argv"


def test_benchmark_run_is_timeout_bounded(monkeypatch) -> None:
    run, seen = _fake_run_writing(_CLEAN)
    monkeypatch.setattr(actions.subprocess, "run", run)
    actions.benchmark_run({})
    t = seen["kwargs"].get("timeout")
    assert t is not None and t >= 60          # bounded, and generously (a real corpus scan takes seconds-minutes)


def test_benchmark_run_fail_soft_on_nonzero_exit(monkeypatch) -> None:
    run, _ = _fake_run_writing({"results": []}, returncode=1)
    monkeypatch.setattr(actions.subprocess, "run", run)
    r = actions.benchmark_run({})
    assert r["ok"] is False and "error" in r


def test_benchmark_run_fail_soft_on_timeout(monkeypatch) -> None:
    def _boom(cmd, *a, **kw):
        raise subprocess.TimeoutExpired(cmd, kw.get("timeout", 1))
    monkeypatch.setattr(actions.subprocess, "run", _boom)
    r = actions.benchmark_run({})
    assert r["ok"] is False and "error" in r
    assert "stopped" in r["error"] or "exceeded" in r["error"]


def test_benchmark_run_tolerates_a_non_dict_body(monkeypatch) -> None:
    # _read_body can return ANY JSON value; a non-dict body must NOT raise (the never-raises contract).
    run, _ = _fake_run_writing(_CLEAN)
    monkeypatch.setattr(actions.subprocess, "run", run)
    for bad in ([], None, "x", 123, True):
        r = actions.benchmark_run(bad)
        assert isinstance(r, dict) and r["ok"] is True


def test_benchmark_run_reports_missing_crucible_row(monkeypatch) -> None:
    run, _ = _fake_run_writing({"results": [{"tool": "sqlmap", "tp": 1}]})
    monkeypatch.setattr(actions.subprocess, "run", run)
    r = actions.benchmark_run({})
    assert r["ok"] is False and "no CRUCIBLE result" in r["error"]
