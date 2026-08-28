"""Wave 2 (parity) — the console `run_verify` wrapper that shells `vigil verify-integrity|verify-ledger|verify`.

Fail-closed on a bad kind / unresolvable bin / non-JSON; parses `--json` for integrity; surfaces the exit code
+ text for the text verbs. The verbs' own correctness is covered by their CLI suites; this checks the wrapper.
"""
from __future__ import annotations

import subprocess

from framework.v2.console import actions


def test_run_verify_rejects_a_bad_kind():
    r = actions.run_verify("nonsense")
    assert r["ok"] is False and "kind" in r["error"]


def test_run_verify_failclosed_when_vigil_missing(monkeypatch):
    monkeypatch.setattr(actions, "_vigil_bin", lambda: None)
    r = actions.run_verify("integrity")
    assert r["ok"] is False and "resolvable" in r["error"]


def test_run_verify_integrity_parses_json(monkeypatch):
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")

    class _P:
        returncode = 0
        stdout = '{"ok": true, "checks": [{"id": "x", "ok": true, "detail": "d"}]}'
        stderr = ""
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _P())
    r = actions.run_verify("integrity")
    assert r["ok"] is True and r["kind"] == "integrity" and r.get("checks")


def test_run_verify_integrity_failure_exit_is_not_ok(monkeypatch):
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")

    class _P:
        returncode = 1
        stdout = '{"ok": false, "checks": []}'
        stderr = ""
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _P())
    assert actions.run_verify("integrity")["ok"] is False


def test_run_verify_text_verb_surfaces_exit_code(monkeypatch):
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")

    class _P:
        returncode = 3
        stdout = "ledger: 5 records — FAILED: torn tail"
        stderr = ""
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _P())
    r = actions.run_verify("ledger")
    assert r["ok"] is False and r["exit_code"] == 3 and "torn tail" in r["text"]
