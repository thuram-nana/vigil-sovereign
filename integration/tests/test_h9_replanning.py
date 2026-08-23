"""H9 — bounded adaptive re-planning driven through the production think-seam (``engine_think.BrainThink``).

Before H9 the seam built its chain ONCE and thereafter only advanced an index — ``state`` was read a single
time and ignored. These pin the adaptive behaviour end-to-end AND the two honesty guarantees it must not
break:

  * RE-PLANS on a new observation (a discovered surface changes WHAT is proposed) — not a fixed chain.
  * BUILD-ONCE preserved: a run with no new observation drives the byte-identical chain (no gratuitous churn).
  * A FAILED PATH is remembered and deprioritized across cycles.
  * FP-0 stays green: re-planning mints ZERO facts — the brain carries no LLM claim, so the engine's
    fact-minting seam is never fed. Re-planning changes WHAT is proposed, never mints.
  * Unverified prose that shapes the plan is a PRIOR, never a durable FACT (the memory's admission gate).
  * DETERMINISTIC: identical drive sequences produce identical proposals (no wallclock / rng).

Offense leg only (``BrainThink._ensure_body`` imports ``framework.v2.agent_body.interface``); the module-top
``importorskip("framework")`` makes it skip cleanly in the sovereign leg. It is registered in the offense
file list of ``.github/workflows/ci.yml``.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

pytest.importorskip("framework")  # offense leg only — the body imports the framework agent-body interface

from vigil_integration.agent.state import AgentState, Finding
from vigil_integration.brains.engine_think import BrainThink
from vigil_integration.brains.hexstrike_brain import HexstrikeBrain
from vigil_integration.brains.planner_memory import Verdict

TARGET = "http://target.example/"
_WEB = {"target_type": "web_application"}


def _drive(bt: BrainThink, state, *, n: int = 64) -> list[str]:
    """Drive the seam exactly as the engine does — call until COMPLETE — collecting the proposed tools, and
    asserting on EVERY decision that the brain sets no ``output_analysis`` (the FP-0 fact-minting seam is
    never fed)."""
    tools: list[str] = []
    for _ in range(n):
        dec = bt(state)
        assert getattr(dec, "output_analysis", None) is None, (
            "a brain decision carried an output_analysis — the engine mints a FACT when its "
            "exploit_succeeded is True. Re-planning must never feed the fact-minting seam.")
        tc = getattr(dec, "tool", None)
        if tc is None:  # COMPLETE
            break
        tools.append(tc.tool_name)
    return tools


# ===================================================================================================
# RE-PLANS on a new observation — not a fixed chain
# ===================================================================================================
def test_planner_replans_on_a_new_observation_not_a_fixed_chain():
    # baseline: a plain web app never earns a wpscan step
    control = BrainThink(HexstrikeBrain(), target=TARGET, objective="comprehensive", observations=_WEB)
    control_tools = _drive(control, AgentState(objective=TARGET))
    assert control_tools, "control proposed nothing — the fixture is broken"
    assert "wpscan" not in control_tools

    # adaptive: two steps in, an ORACLE-CONFIRMED observation reveals WordPress → the plan must change
    bt = BrainThink(HexstrikeBrain(), target=TARGET, objective="comprehensive", observations=_WEB)
    st = AgentState(objective=TARGET)
    before = [bt(st).tool.tool_name for _ in range(2)]
    replans_before = bt._replan_count
    st.record_fact(Finding(ref="orc:cms", bug_class="cms", title="WordPress detected", severity="info",
                           source="httpx"), evidence_ref="cert:wp")
    after = _drive(bt, st)

    # it RE-PLANNED (not a fixed chain) and the new surface produced a new step the control never had
    assert bt._replan_count > replans_before, "the seam did not re-plan on the new observation"
    assert "wpscan" in (before + after), "the discovered WordPress surface did not re-shape the plan"
    # and the new observation is durable knowledge — a FACT (it carried a signed certificate)
    assert any(e.verdict == Verdict.FACT.value and e.certificate_digest == "cert:wp"
               for e in bt._memory.ledger), "the oracle-confirmed observation was not recorded as a FACT"


def test_a_static_run_is_build_once_byte_identical():
    """A run with NO new observation re-plans exactly once and drives the identical chain — no gratuitous
    churn from the adaptive machinery (build-once is preserved as the empty-observation special case)."""
    baseline = _drive(
        BrainThink(HexstrikeBrain(), target=TARGET, objective="comprehensive", observations=_WEB),
        AgentState(objective=TARGET))

    bt = BrainThink(HexstrikeBrain(), target=TARGET, objective="comprehensive", observations=_WEB)
    static = _drive(bt, SimpleNamespace(objective=TARGET))  # a state that never accretes an observation
    assert static == baseline, (static, baseline)
    assert bt._replan_count == 1, ("a static run must build the plan exactly once", bt._replan_count)


# ===================================================================================================
# FAILED-PATH memory across cycles
# ===================================================================================================
def test_a_failed_path_is_remembered_and_deprioritized_end_to_end():
    """A tool the memory learned FAILED on a prior cycle (here: denied at the gate) is deprioritized — it is
    still proposed (deprioritized, not dropped) but AFTER the tools that have not failed. The control, with
    no failure recorded, proposes it in its normal (first) position."""
    control = BrainThink(HexstrikeBrain(), target=TARGET, objective="comprehensive", observations=_WEB)
    control_tools = _drive(control, AgentState(objective=TARGET))
    assert control_tools[0] == "nmap", ("nmap is normally the first proposed step", control_tools)

    bt = BrainThink(HexstrikeBrain(), target=TARGET, objective="comprehensive", observations=_WEB)
    st = AgentState(objective=TARGET)
    # a prior cycle's outcome the engine would have appended: nmap was denied at the gate (a failed path)
    st.execution_trace.append(
        {"iteration": 0, "action": "use_tool", "tool": "nmap", "outcome": "deny", "reason": "A2 floor"})
    tools = _drive(bt, st)

    assert "nmap" in tools, "a deprioritized tool must still be proposed, not dropped"
    assert tools[0] != "nmap", "the failed path was not deprioritized"
    assert tools.index("nmap") > tools.index("httpx"), ("nmap should fall behind a non-failed tool", tools)
    assert "nmap" in bt._memory.failed_paths


# ===================================================================================================
# FP-0 — re-planning mints ZERO facts (a fact needs the oracle, never the brain)
# ===================================================================================================
def test_re_planning_mints_zero_facts_through_the_seam():
    """Even a heavily re-planned run (a new observation on every cycle) carries no exploit claim, so the
    engine's fact-minting path is never fed. This is the FP-0 canary under adaptive re-planning."""
    bt = BrainThink(HexstrikeBrain(), target=TARGET, objective="comprehensive", observations=_WEB)
    st = AgentState(objective=TARGET)
    minted_any_analysis = False
    for i in range(40):
        dec = bt(st)
        if getattr(dec, "output_analysis", None) is not None:
            minted_any_analysis = True
        # feed a NEW lead every cycle to force a re-plan each time
        st.record_lead(Finding(ref=f"lead:{i}", bug_class="info", title=f"observation {i}"))
        if getattr(dec, "tool", None) is None:
            break
    assert not minted_any_analysis, "re-planning fed the fact-minting seam (output_analysis was set)"
    assert bt._replan_count > 1, "the run did not actually re-plan (canary would be vacuous)"


def test_unverified_prose_through_the_seam_never_becomes_a_durable_fact():
    """A LEAD-only run (only unverified prose observed) shapes the plan as a PRIOR but yields NO durable
    FACT; a fact-carrying run does. This ties the memory admission gate to the real driven seam."""
    bt = BrainThink(HexstrikeBrain(), target=TARGET, objective="comprehensive", observations=_WEB)
    st = AgentState(objective=TARGET)
    st.record_lead(Finding(ref="llm:sqli", bug_class="sqli", title="model thinks SQLi (prose)"))
    _drive(bt, st)
    assert not bt._memory.facts(), "unverified prose entered durable knowledge as a FACT"
    assert any(e.verdict == Verdict.LEAD.value for e in bt._memory.ledger), "the lead was not recorded at all"


# ===================================================================================================
# DETERMINISM + persistence
# ===================================================================================================
def test_the_driven_seam_is_deterministic():
    def run() -> list[str]:
        bt = BrainThink(HexstrikeBrain(), target=TARGET, objective="comprehensive", observations=_WEB)
        st = AgentState(objective=TARGET)
        out = [bt(st).tool.tool_name for _ in range(2)]
        st.record_fact(Finding(ref="orc:cms", bug_class="cms", title="WordPress detected"),
                       evidence_ref="cert:wp")
        return out + _drive(bt, st)

    assert run() == run(), "identical drive sequences produced different proposals (non-deterministic)"


def test_persisted_proposal_carries_the_replanning_block_and_keeps_the_contract(tmp_path):
    """The persisted ``brain-proposal.json`` keeps the ``{target,objective,posture,profile,steps}`` contract
    the panel reads AND gains an additive ``replanning`` block (count + planner-memory snapshot)."""
    rd = tmp_path / "run"
    bt = BrainThink(HexstrikeBrain(), target=TARGET, objective="comprehensive", observations=_WEB,
                    proposal_out=rd)
    st = AgentState(objective=TARGET)
    bt(st); bt(st)
    st.record_fact(Finding(ref="orc:cms", bug_class="cms", title="WordPress detected"), evidence_ref="cert:wp")
    _drive(bt, st)

    doc = json.loads((rd / "brain-proposal.json").read_text(encoding="utf-8"))
    # the reader's contract is intact
    assert {"target", "objective", "posture", "profile", "steps"} <= set(doc), doc.keys()
    assert doc["objective"] == "comprehensive" and doc["posture"] == "live"
    assert [s["tool"] for s in doc["steps"]], "steps must be present"
    # the H9 additive block
    rp = doc["replanning"]
    assert rp["count"] >= 2, ("the persisted proposal must record the re-plan count", rp)
    assert "world_digest" in rp and "deprioritized" in rp and "tool_stats" in rp, rp
    # the discovered WordPress surface is reflected in the snapshot (a fact was consumed)
    assert rp["n_facts"] >= 1, rp
