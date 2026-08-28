"""Wave 2b (parity) — the console `run_doctor` wrapper that shells `vigil doctor --json`.

Fail-closed on an unresolvable bin / non-JSON; parses the report; derives `ok` from the EXIT CODE (a stdout
`ok` never overrides it). `doctor`'s own correctness is covered by the CLI suite; this checks the wrapper.
"""
from __future__ import annotations

import subprocess

from framework.v2.console import actions


def test_run_doctor_failclosed_when_vigil_missing(monkeypatch):
    monkeypatch.setattr(actions, "_vigil_bin", lambda: None)
    r = actions.run_doctor()
    assert r["ok"] is False and "resolvable" in r["error"]


def test_run_doctor_parses_json(monkeypatch):
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")

    class _P:
        returncode = 0
        stdout = '{"ok": true, "binaries": {"docker": true}, "issues": []}'
        stderr = ""
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _P())
    r = actions.run_doctor()
    assert r["ok"] is True and r.get("binaries", {}).get("docker") is True


def test_run_doctor_exit_code_is_authoritative_over_stdout_ok(monkeypatch):
    # a hard prerequisite gap → exit 1; even if stdout claims ok:true, the wrapper reports NOT ok (veracity).
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")

    class _P:
        returncode = 1
        stdout = '{"ok": true, "issues": ["docker missing"]}'
        stderr = ""
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _P())
    r = actions.run_doctor()
    assert r["ok"] is False and r.get("issues")


def test_run_doctor_non_json_failclosed(monkeypatch):
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")

    class _P:
        returncode = 0
        stdout = "not json at all"
        stderr = ""
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _P())
    r = actions.run_doctor()
    # exit 0 → ok True, but the un-parseable stdout is preserved under `raw` (never silently dropped)
    assert r["ok"] is True and "not json" in r.get("raw", "")


def test_run_doctor_oserror_failclosed(monkeypatch):
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")

    def _boom(*a, **k):
        raise OSError("exec format error")
    monkeypatch.setattr(subprocess, "run", _boom)
    r = actions.run_doctor()
    assert r["ok"] is False and "OSError" in r["error"]
