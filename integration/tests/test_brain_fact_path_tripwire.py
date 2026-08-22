"""FP-0 — the FACT-path tripwire canary.

This canary must be updated tool-by-tool as H8f-* enables FACTs; never wholesale.

WHY THIS EXISTS. The hexstrike brain is PROPOSE-ONLY: on the production path
(``vigil engage --brain hexstrike`` -> ``engine_think.BrainThink`` -> the live engine) it mints ZERO
FACTs today, by construction. A FACT is minted only by a VIGIL-owned live re-drive over the target's own
bytes (``run_external_tool``'s ``Redrive`` -> ``verdict.admit()``), NEVER from a tool's self-report. This
test is the tripwire that goes RED the day any future change:

  (1) makes the brain's production run mint a FACT, or
  (2) routes brain-path execution through the agent body's own ``execute`` (``body.execute`` /
      ``run_external_tool`` on the body) instead of the live engine's governed executor + oracle, or
  (3) flips ``tool_intake`` to assert ``exploit_succeeded`` (which would fire the oracle from
      producer-supplied bytes).

When an H8f-* slice DELIBERATELY enables a FACT for one tool, this canary must be updated for THAT tool —
never blanket-relaxed. A wholesale edit that just makes the asserts pass is the exact regression this
guards against.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

pytest.importorskip("framework")  # offense leg only — the sovereign leg lacks engine/crucible on the path

from vigil_integration.brains.engine_think import BrainThink
from vigil_integration.brains.hexstrike_brain import HexstrikeBrain

TARGET = "http://127.0.0.1/"

# A well-formed nuclei JSONL sample, so the intake-derivation guard below is NON-VACUOUS (it really parses
# proposals and then checks they can never claim exploitation).
NUCLEI = "\n".join(json.dumps({
    "template-id": "exposed-panel", "info": {"severity": "medium", "name": "Panel"},
    "matched-at": f"http://target.example/admin{i}", "host": "target.example",
}) for i in range(3))


# ---------------------------------------------------------------------------------------------------
# INVARIANT 1 — the brain supplies NO exploit claim, so its production run mints NO FACT today
# ---------------------------------------------------------------------------------------------------
def test_brain_supplies_no_exploit_claim_so_it_mints_no_fact():
    """The seam-level equivalent of "a `vigil engage --brain hexstrike` run reports fact_count == 0", and
    ROBUST against cross-test engine-state pollution (a full ``engage()`` here is order-dependent and would
    make the canary flaky). The engine mints a FACT on the deterministic path only if the decision carries an
    ``output_analysis`` whose ``exploit_succeeded`` is True (``live/engine.py``: ``_analysis =
    decision.output_analysis``, then ``intake_result`` fires the oracle on that claim). The brain has NO LLM,
    so it carries NO ``output_analysis`` at all — the fact-minting seam is never fed. If a future change makes
    BrainThink emit an ``output_analysis`` (the way a FACT would ever reach this path), this goes RED —
    update the canary tool-by-tool for the tool that was enabled, never wholesale."""
    bt = BrainThink(HexstrikeBrain(), target=TARGET)
    state = SimpleNamespace(objective=TARGET)
    use_tool = 0
    for _ in range(64):
        dec = bt(state)
        if getattr(dec, "tool", None) is None:
            break
        use_tool += 1
        assert getattr(dec, "output_analysis", None) is None, (
            "a brain decision carried an output_analysis — the engine mints a FACT when its "
            "exploit_succeeded is True. The brain must carry no exploit claim on its production path. Update "
            "THIS canary tool-by-tool if this is an intended H8f-* enablement, never wholesale."
        )
    assert use_tool, "the brain proposed no USE_TOOL steps — the canary would be vacuous"


# ---------------------------------------------------------------------------------------------------
# INVARIANT 2 — the production path only PLANS; it does not route execution through body.execute
# ---------------------------------------------------------------------------------------------------
def test_brain_production_path_only_plans_never_executes_via_body(monkeypatch):
    """BrainThink (the production think-seam) must drive the body's ``plan`` only. Execution belongs to the
    live engine's governed executor + oracle — NOT the agent body's own ``execute``/``run_external_tool``.
    Spy on the body's ``execute`` and prove it is never reached by driving BrainThink to exhaustion."""
    from vigil_integration.brains import hexstrike_body

    calls = {"execute": 0}
    orig = hexstrike_body.HexstrikeAgentBody.execute

    def _spy(self, action, decision):
        calls["execute"] += 1
        return orig(self, action, decision)

    monkeypatch.setattr(hexstrike_body.HexstrikeAgentBody, "execute", _spy)

    bt = BrainThink(HexstrikeBrain(), target=TARGET)
    state = SimpleNamespace(objective=TARGET)
    proposed = 0
    for _ in range(64):
        dec = bt(state)
        if getattr(dec, "tool", None) is None:
            break
        proposed += 1

    assert proposed, "BrainThink proposed no steps — the canary would be vacuous"
    assert calls["execute"] == 0, (
        "BrainThink routed execution through HexstrikeAgentBody.execute. The brain production path must only "
        "PLAN (body.plan); execution + fact-minting belong to the live engine's governed executor + oracle. "
        "If a future change intentionally converges execution onto the body, update THIS canary."
    )


# ---------------------------------------------------------------------------------------------------
# INVARIANT 3 — the tool-output intake seam can never assert exploitation (never fires the oracle)
# ---------------------------------------------------------------------------------------------------
def test_tool_intake_never_asserts_exploit_succeeded():
    """The brain path's tool output becomes LEADs via ``analysis_from_tool_output``; it hard-sets
    ``exploit_succeeded=False`` so the oracle is never fired from producer-supplied bytes. If this ever
    returns True a FACT could be minted from a tool's say-so — update THIS canary tool-by-tool if intended.

    Driven in a SUBPROCESS: the nuclei parser initializes global engine state that leaks into a later
    live-engine ``engage()`` (a pre-existing order-fragility shared with the base ``test_tool_intake.py``).
    Isolating the call keeps this tripwire from polluting any sibling test in any collection order."""
    import os
    import subprocess
    import sys

    code = (
        "import json, sys\n"
        "from vigil_integration.live.tool_intake import analysis_from_tool_output\n"
        "a = analysis_from_tool_output('nuclei', json.loads(sys.stdin.read()))\n"
        "print('FINDINGS=' + repr(bool(a is not None and a.findings)))\n"
        "print('EXPLOIT_SUCCEEDED=' + repr(a.exploit_succeeded))\n"
    )
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    proc = subprocess.run(
        [sys.executable, "-c", code], input=json.dumps(NUCLEI),
        capture_output=True, text=True, env=env, timeout=180,
    )
    assert proc.returncode == 0, ("intake subprocess failed", proc.stdout, proc.stderr)
    assert "FINDINGS=True" in proc.stdout, ("sample must parse or the guard is vacuous", proc.stdout)
    assert "EXPLOIT_SUCCEEDED=False" in proc.stdout, (
        "tool_intake asserted exploit_succeeded — that would fire the oracle from tool-supplied bytes and "
        "mint a FACT on the brain path. Update THIS canary tool-by-tool if this is an intended enablement.",
        proc.stdout,
    )


def test_negative_control_a_true_exploit_claim_would_fire_the_oracle():
    """Prove the intake seam CAN fire the oracle when exploit_succeeded is True — so invariant 3's False is
    load-bearing, not a seam that structurally cannot mint anything."""
    from vigil_integration.agent.react import intake_result
    from vigil_integration.agent.state import OutputAnalysis

    result = intake_result("raw", OutputAnalysis(exploit_succeeded=True, findings=[]),
                           oracle=lambda raw, a: "evidence-ref", source="llm")
    assert result.facts, "the intake seam cannot mint a fact at all — invariant 3 would be vacuous"
