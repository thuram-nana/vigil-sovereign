"""B3/H10 — the console PROPOSE-ONLY brain endpoint (``actions.brain_propose``).

Contract: it PLANS (spawns ``vigil engage --brain hexstrike --plan-only``) and NEVER executes. The spawned
argv MUST carry ``--plan-only``, pin ``--scope 127.0.0.1``, and carry NEITHER ``--brain-execute-via-body``
NOR ``--approve-offense`` (either would turn planning into execution). Every off-path input — an unknown /
executing brain, a bad objective, a non-loopback or missing target, no resolvable ``vigil`` entrypoint — is a
clean, fail-closed refusal returned BEFORE any spawn (never a traceback). The happy path is hermetic: the
child subprocess is simulated (it writes the proposal artifact), so this needs no live ``vigil`` binary and
sends no traffic.
"""
from __future__ import annotations

import json
import types
from pathlib import Path

import pytest

from framework.v2.console import actions


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    # run dirs + meta land under a tmp console dir (run_dir + _write_meta both route through console_dir);
    # a resolvable entrypoint so the happy path reaches the (mocked) spawn — overridden per-test where needed.
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path / ".console")
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/vigil")


def _capture_spawn(monkeypatch, *, rc: int = 0, write: bool = True) -> list:
    """Replace subprocess.run with a recorder that SIMULATES the plan-only child: it writes a valid
    brain-proposal.json into the run dir named by --proposal-out and returns ``rc`` — no real process, no
    traffic. Returns the list of captured argv lists."""
    calls: list = []

    def _fake_run(cmd, *a, **kw):
        calls.append(list(cmd))
        rd = Path(cmd[cmd.index("--proposal-out") + 1]) if "--proposal-out" in cmd else None
        if write and rd is not None:
            rd.mkdir(parents=True, exist_ok=True)
            (rd / "brain-proposal.json").write_text(
                json.dumps({"target": "http://127.0.0.1:8080/", "objective": "comprehensive",
                            "posture": "live", "profile": {}, "steps": [{"tool": "nmap", "priority": 1}]}),
                encoding="utf-8")
        return types.SimpleNamespace(returncode=rc, stdout="", stderr=("" if rc == 0 else "boom"))

    monkeypatch.setattr(actions.subprocess, "run", _fake_run)
    return calls


def test_happy_path_spawns_plan_only_and_returns_run_id(monkeypatch):
    calls = _capture_spawn(monkeypatch)
    res = actions.brain_propose({"brain": "hexstrike", "target": "http://127.0.0.1:8080/",
                                 "objective": "comprehensive"})
    assert res.get("ok") is True, res
    assert res.get("run_id"), res
    assert len(calls) == 1, calls
    argv = calls[0]
    # PROPOSE-ONLY: plan-only present, loopback scope pinned, the propose-only brain wired.
    assert "--plan-only" in argv
    assert argv[argv.index("--scope") + 1] == "127.0.0.1"
    assert argv[argv.index("--brain") + 1] == "hexstrike"
    assert argv[argv.index("--proposal-out") + 1]   # a real destination is passed
    # NEVER an execute flag — this endpoint plans, it does not drive.
    assert "--brain-execute-via-body" not in argv
    assert "--approve-offense" not in argv


def test_default_objective_is_comprehensive(monkeypatch):
    calls = _capture_spawn(monkeypatch)
    res = actions.brain_propose({"brain": "hexstrike", "target": "http://127.0.0.1:8080/"})
    assert res.get("ok") is True and res.get("objective") == "comprehensive"
    assert calls[0][calls[0].index("--brain-objective") + 1] == "comprehensive"


def test_executing_brain_strix_refused_before_any_spawn(monkeypatch):
    calls = _capture_spawn(monkeypatch)
    res = actions.brain_propose({"brain": "strix", "target": "http://127.0.0.1:8080/"})
    assert "error" in res and "run_id" not in res
    assert calls == []   # refused BEFORE spawning anything


def test_bad_objective_refused_before_any_spawn(monkeypatch):
    calls = _capture_spawn(monkeypatch)
    res = actions.brain_propose({"brain": "hexstrike", "target": "http://127.0.0.1:8080/",
                                 "objective": "everything"})
    assert "error" in res and calls == []


def test_non_loopback_target_refused_before_any_spawn(monkeypatch):
    calls = _capture_spawn(monkeypatch)
    res = actions.brain_propose({"brain": "hexstrike", "target": "http://example.com/"})
    assert "error" in res and calls == []


def test_missing_target_refused_before_any_spawn(monkeypatch):
    calls = _capture_spawn(monkeypatch)
    res = actions.brain_propose({"brain": "hexstrike", "target": ""})
    assert "error" in res and calls == []


def test_no_vigil_entrypoint_refused_before_any_spawn(monkeypatch):
    monkeypatch.setattr(actions, "_vigil_bin", lambda: None)
    calls = _capture_spawn(monkeypatch)
    res = actions.brain_propose({"brain": "hexstrike", "target": "http://127.0.0.1:8080/"})
    assert "error" in res and calls == []


def test_child_produced_no_proposal_is_a_clean_error(monkeypatch):
    # rc==0 but the child wrote no artifact ⇒ still an error (never a false "ok").
    calls = _capture_spawn(monkeypatch, rc=0, write=False)
    res = actions.brain_propose({"brain": "hexstrike", "target": "http://127.0.0.1:8080/"})
    assert res.get("ok") is not True and "error" in res
    assert len(calls) == 1   # it DID spawn; the missing artifact is the failure


def test_child_nonzero_rc_is_a_clean_error(monkeypatch):
    calls = _capture_spawn(monkeypatch, rc=2, write=False)
    res = actions.brain_propose({"brain": "hexstrike", "target": "http://127.0.0.1:8080/"})
    assert res.get("ok") is not True and "error" in res
    assert len(calls) == 1


def test_target_is_canonicalized_no_raw_user_bytes_on_argv(monkeypatch):
    # userinfo / query / fragment / an odd path are DROPPED — the argv target is rebuilt from validated
    # scheme+host+port(+safe path), so no raw user string reaches the spawn.
    calls = _capture_spawn(monkeypatch)
    res = actions.brain_propose({"brain": "hexstrike",
                                 "target": "http://evil:secret@127.0.0.1:8080/a b?q=1#frag"})
    assert res.get("ok") is True, res
    argv = calls[0]
    spawned_target = argv[argv.index("engage") + 1]
    assert spawned_target == "http://127.0.0.1:8080/"   # userinfo/query/fragment gone; unsafe path (space) → "/"
    assert "secret" not in spawned_target and "evil" not in spawned_target


def test_non_http_scheme_refused_before_any_spawn(monkeypatch):
    calls = _capture_spawn(monkeypatch)
    res = actions.brain_propose({"brain": "hexstrike", "target": "file://127.0.0.1/etc/passwd"})
    assert "error" in res and calls == []


def test_non_string_slug_is_a_clean_value_not_a_traceback(monkeypatch):
    # A hand-crafted same-origin body with a non-string truthy slug must not raise (the docstring promises a
    # clean result, never a traceback). str()-coercion makes it a plain slug value; the run still proposes.
    calls = _capture_spawn(monkeypatch)
    res = actions.brain_propose({"brain": "hexstrike", "target": "http://127.0.0.1:8080/", "slug": ["x", "y"]})
    assert res.get("ok") is True, res   # coerced, not crashed
    assert len(calls) == 1


def test_route_is_rbac_gated_run():
    rbac = pytest.importorskip("vigil_core.rbac")
    assert rbac.OFFENSE_ACTION_PERM.get("/api/brain/propose") == "run_engagement"
