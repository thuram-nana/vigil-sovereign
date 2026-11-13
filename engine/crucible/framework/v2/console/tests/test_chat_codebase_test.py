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


def test_the_command_is_positional_after_end_of_options(monkeypatch, tmp_path):
    """CQ-1: the command goes LAST, after `--`, so text that begins with `-` (`--approve`, `--workspace=/`)
    can never be read as one of the sandbox's own options — e.g. self-granting the A3 approval leg."""
    for present in (True, False):
        wd, seen = _wire(monkeypatch, tmp_path, {"ran": False, "outcome": "queue", "reason": "q", "tier": "A3"})
        actions_mod.run_codebase_tests(CHAT, wd, "--approve", operator_present=present)
        argv = seen["argv"]
        assert argv[-2:] == ["--", "--approve"]
        assert ("--approve" in argv[:-2]) is present          # only the operator leg ever adds the real flag


# --- an edit is never applied while the clone's own code runs (one lock per clone) ------------------------

def test_the_clone_is_locked_while_its_tests_run_and_released_after(monkeypatch, tmp_path):
    wd, seen = _wire(monkeypatch, tmp_path, {"ran": True, "exit_code": 0, "stdout": "", "stderr": ""})
    real_run = actions_mod.subprocess.run

    def _run(argv, **kw):
        seen["locked_during_run"] = actions_mod._clone_lock(wd).locked()
        return real_run(argv, **kw)

    monkeypatch.setattr(actions_mod.subprocess, "run", _run)
    assert actions_mod.run_codebase_tests(CHAT, wd, "pytest -q", operator_present=True)["ok"] is True
    assert seen["locked_during_run"] is True, "the clone's tests ran without holding the clone lock"
    assert actions_mod._clone_lock(wd).locked() is False, "the clone lock was not released"


def test_the_clone_lock_is_released_when_the_sandbox_cannot_run(monkeypatch, tmp_path):
    wd, _seen = _wire(monkeypatch, tmp_path, {})

    def _boom(argv, **kw):
        raise OSError("no such file")

    monkeypatch.setattr(actions_mod.subprocess, "run", _boom)
    assert actions_mod.run_codebase_tests(CHAT, wd, "pytest -q", operator_present=True)["ok"] is False
    assert actions_mod._clone_lock(wd).locked() is False


def test_tests_are_refused_while_the_clone_is_busy(monkeypatch, tmp_path):
    wd, seen = _wire(monkeypatch, tmp_path, {"ran": True, "exit_code": 0, "stdout": "", "stderr": ""})
    lock = actions_mod._clone_lock(wd)
    assert lock.acquire(blocking=False)                  # an apply (or another test run) holds this clone
    try:
        out = actions_mod.run_codebase_tests(CHAT, wd, "pytest -q", operator_present=True)
    finally:
        lock.release()
    assert out["ok"] is False and "busy" in out["error"]
    assert "argv" not in seen, "the sandbox was launched on a busy clone"
