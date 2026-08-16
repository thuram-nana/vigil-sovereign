"""Phase D3 — run a cloned codebase's tests in the network-isolated sandbox. Running arbitrary test code
is A3, so ``run_codebase_tests`` does not exec it directly — it launches the already-gated ``vigil
sandbox`` verb (no-net bwrap, A3 owner-approval, signed record) with the workspace CONFINED to the chat's
own clone. These tests pin: path-confinement, kill-switch refusal, the ``--approve`` (operator-present)
A3 leg, workspace confinement in the argv, and honest pass/fail reporting (a green test is a LEAD).

The ``vigil sandbox`` subprocess is faked — no real bwrap, no real exec.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod


CHAT = "test-chat"


@pytest.fixture(autouse=True)
def _iso(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    yield tmp_path


def _wire(monkeypatch, tmp_path, result: dict, *, killswitch=False):
    """Point run_codebase_tests at a confined dir + a fake `vigil sandbox` that prints `result` as JSON."""
    wd = tmp_path / "clone"
    wd.mkdir(exist_ok=True)
    monkeypatch.setattr(actions_mod, "_confined_clone_path", lambda cid, p: str(wd))
    monkeypatch.setattr(actions_mod, "_vigil_bin", lambda: "/opt/vigil/bin/vigil")
    monkeypatch.setattr(actions_mod, "_chat_killswitch_tripped", lambda cid: killswitch)
    seen = {}

    class _P:
        def __init__(self):
            self.stdout = json.dumps(result)
            self.stderr = ""
            self.returncode = 0

    def _run(argv, **kw):
        seen["argv"] = argv
        return _P()

    monkeypatch.setattr(actions_mod.subprocess, "run", _run)
    return str(wd), seen


def test_run_tests_reports_pass(monkeypatch, tmp_path):
    wd, seen = _wire(monkeypatch, tmp_path, {"ran": True, "exit_code": 0, "stdout": "5 passed", "stderr": ""})
    out = actions_mod.run_codebase_tests(CHAT, wd, "pytest -q", operator_present=True)
    assert out["ok"] is True and out["passed"] is True and out["exit_code"] == 0
    assert "LEAD" in out["note"]                                  # a green test is not a FACT


def test_run_tests_reports_failure(monkeypatch, tmp_path):
    wd, seen = _wire(monkeypatch, tmp_path, {"ran": True, "exit_code": 1, "stdout": "1 failed", "stderr": ""})
    out = actions_mod.run_codebase_tests(CHAT, wd, "pytest -q", operator_present=True)
    assert out["ok"] is True and out["passed"] is False and out["exit_code"] == 1


def test_run_tests_queued_when_not_approved(monkeypatch, tmp_path):
    # the sandbox verb QUEUES an A3 without --approve → ran:False; we surface it honestly, not as a pass
    wd, seen = _wire(monkeypatch, tmp_path, {"ran": False, "outcome": "queue", "reason": "A3 queued", "tier": "A3"})
    out = actions_mod.run_codebase_tests(CHAT, wd, "pytest -q", operator_present=False)
    assert out["ok"] is False and "did not run" in out["error"]
    assert "--approve" not in seen["argv"], "a background caller must not pass the A3 approval leg"


def test_argv_is_confined_and_carries_the_approve_leg(monkeypatch, tmp_path):
    wd, seen = _wire(monkeypatch, tmp_path, {"ran": True, "exit_code": 0, "stdout": "", "stderr": ""})
    actions_mod.run_codebase_tests(CHAT, wd, "make test", operator_present=True)
    argv = seen["argv"]
    assert argv[:2] == ["/opt/vigil/bin/vigil", "sandbox"]
    assert "make test" in argv and "--workspace" in argv
    assert argv[argv.index("--workspace") + 1] == wd            # runs in the CLONE, not elsewhere
    assert "--approve" in argv                                  # operator-present A3 leg


def test_outside_path_is_refused(tmp_path, monkeypatch):
    # the REAL _confined_clone_path: an edit/test may only touch a repo THIS chat cloned
    assert actions_mod.run_codebase_tests(CHAT, "/etc", "pytest -q", operator_present=True)["ok"] is False


def test_killswitch_refuses_the_run(monkeypatch, tmp_path):
    wd, seen = _wire(monkeypatch, tmp_path, {"ran": True, "exit_code": 0}, killswitch=True)
    out = actions_mod.run_codebase_tests(CHAT, wd, "pytest -q", operator_present=True)
    assert out["ok"] is False and "kill-switch" in out["error"] and "argv" not in seen  # never launched
