"""W0-11 (#406) — the STANDING (keyless) operator approval is PER-ACTION + single-use.

The vulnerability: ``--approve-offense`` set ``owner_approves_offense`` and the engine wrapped the gate in a
BLANKET boolean (``_approval_gate``) that upgraded EVERY queued WARDEN action to allow. One flag therefore
auto-fired every future action an autonomous agent proposed — an autonomously-proposed ``terminal.run``
executed with NO per-action click, falsifying "an autonomous agent can never auto-fire" / "nothing the AI
proposes runs on its own".

The fix binds the standing grant to the ONE action it authorizes and SPENDS it there (:class:`StandingApproval`):
the approval gate promotes a WARDEN ``queue`` to ``allow`` only for the exact bound action, single-use — a
second, distinct queued action is never auto-promoted by the same standing approval.

These tests drive the REAL wiring (``build_engine`` → ``run_tool`` → the executor → ``_approval_gate`` →
``StandingApproval``) with a deterministic echo runner, so no live model / API is involved — they exercise the
governed execution path directly. ``framework`` co-loads the offense env, so this module runs in the OFFENSE
CI leg (it is listed there); it SKIPS in the sovereign leg.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("framework.v2.authority.charter", reason="CRUCIBLE (offense) not importable here")

from vigil_integration.agent.state import Phase, ToolCall  # noqa: E402
from vigil_integration.live.wiring import (  # noqa: E402
    EngineConfig,
    StandingApproval,
    _approval_gate,
    build_engine,
    provision_authority,
)


def _echo_runner(argv, *, timeout=0, output_cap=1 << 20, cwd=None):
    """A deterministic stand-in for the live subprocess (network tool AND terminal): never spawns anything."""
    return SimpleNamespace(exit_code=0, stdout="hello world", stderr="", timed_out=False, truncated=False)


@pytest.fixture()
def hermetic_root(tmp_path, monkeypatch):
    monkeypatch.setenv("CRUCIBLE_ROOT", str(tmp_path / "crucible-root"))
    return tmp_path


def _engine(tmp_path, *, owner_approves=True):
    prov = provision_authority(slug="loopback", scope=["127.0.0.1"])
    cfg = EngineConfig(slug="loopback", base_dir=str(tmp_path / "live"), provisioned=prov,
                       runner=_echo_runner, max_iterations=6, owner_approves_offense=owner_approves)
    return build_engine(cfg)


def _terminal(command: str) -> ToolCall:
    # terminal.run classifies WARDEN A2, so under the A1 offense ceiling the conjunctive gate QUEUES it: it
    # runs only under the operator's approval. Two DISTINCT commands share the gate key ("terminal.run",
    # "127.0.0.1"), so ONLY the single-use standing grant distinguishes them — the purest per-action check.
    return ToolCall(tool_name="terminal.run", tool_args={"command": command})


# ---------------------------------------------------------------------------------------------------
# the W0-11 property, end-to-end through the real wiring
# ---------------------------------------------------------------------------------------------------


def test_standing_approval_runs_the_approved_action_but_blocks_an_unrelated_one(hermetic_root, tmp_path):
    # The specifically-approved action runs; a SECOND, un-approved queued action stays blocked (single-use).
    # WITHOUT the fix the blanket ``_approval_gate`` upgrades EVERY queue to allow, so BOTH run — this test
    # FAILS on that code (the second terminal command wrongly executes with no per-action approval).
    engine = _engine(tmp_path, owner_approves=True)
    run_tool = engine.seams.run_tool

    approved = run_tool(_terminal("cat /etc/hostname"), Phase.INFORMATIONAL, 0, approved=True)
    assert approved.ran is True and approved.outcome == "ran"      # the approved action DID run

    unrelated = run_tool(_terminal("id"), Phase.INFORMATIONAL, 1, approved=True)
    assert unrelated.ran is False                                  # the unrelated action did NOT run
    assert unrelated.outcome == "deny"
    assert "owner appr" in (unrelated.reason or "").lower()        # it stayed queued (WARDEN human leg unmet)


def test_the_approve_one_workflow_is_preserved(hermetic_root, tmp_path):
    # Guard against over-fixing: an operator CAN approve an action and it runs. A single approved offense
    # action must execute (the standing grant is spent on exactly it).
    engine = _engine(tmp_path, owner_approves=True)
    res = engine.seams.run_tool(_terminal("cat /etc/hostname"), Phase.INFORMATIONAL, 0, approved=True)
    assert res.ran is True and res.outcome == "ran"


def test_no_standing_grant_never_promotes(hermetic_root, tmp_path):
    # The fail-closed default: with no ``--approve-offense`` (owner_approves_offense=False) the standing grant
    # is not granted, so even an ``approved=True`` call is never promoted — the queue stays a queue.
    engine = _engine(tmp_path, owner_approves=False)
    res = engine.seams.run_tool(_terminal("cat /etc/hostname"), Phase.INFORMATIONAL, 0, approved=True)
    assert res.ran is False and res.outcome == "deny"


# ---------------------------------------------------------------------------------------------------
# NEGATIVE CONTROL — the discriminating power of the fix, isolated at the gate
# ---------------------------------------------------------------------------------------------------


def _queue_gate(tool_name, target, destructive=False, **kw):
    """A stand-in conjunctive gate that puts every in-envelope action in the WARDEN ``queue`` (needs the
    human leg) — the exact state ``_approval_gate`` is meant to upgrade only for a specifically-approved action."""
    from vigil_core.gate import GateVerdict
    return GateVerdict(False, "queue", "in envelope, WARDEN needs owner approval", True, None)


def test_negative_control_action_binding_is_what_blocks_not_a_blanket_deny(hermetic_root):
    # Prove the block in the main test is because the grant is BOUND+SPENT on one action — not because the
    # gate denies everything. A fresh grant bound to an action DOES promote that exact action to allow.
    sa = StandingApproval(True)
    gate = _approval_gate(_queue_gate, sa)

    sa.bind("terminal.run", "127.0.0.1", "sha256:AAAA")
    first = gate("terminal.run", "127.0.0.1")
    assert first.outcome == "allow"                                # the bound (approved) action IS promoted

    # single-use: the SAME gate call, grant now spent, stays queued (no auto-promote of a further action).
    sa.bind("terminal.run", "127.0.0.1", "sha256:BBBB")
    second = gate("terminal.run", "127.0.0.1")
    assert second.outcome == "queue"                               # a second action is NOT auto-promoted


def test_negative_control_a_blanket_source_would_promote_the_unrelated_action(hermetic_root):
    # This is EXACTLY the reverted/vulnerable shape: a source whose ``authorize`` always says yes makes
    # ``_approval_gate`` upgrade EVERY queue to allow — an unrelated, never-bound action wrongly runs. It is
    # what the W0-11 fix removes; if the guard regresses to this, the main test above fails.
    class _Blanket:
        def authorize(self, tool_name, target):
            return True

    gate = _approval_gate(_queue_gate, _Blanket())
    # two DISTINCT actions, neither individually approved — both are blanket-promoted (the bug).
    assert gate("terminal.run", "127.0.0.1").outcome == "allow"
    assert gate("httpx", "127.0.0.1").outcome == "allow"
