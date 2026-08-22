"""H1 — ONE canonical hexstrike body: the production think-seam delegates to HexstrikeAgentBody.

The divergence this slice closes (docs/BRAIN-SLOT-INTEGRATION.md step 6): two implementations built the
brain's plan. ``HexstrikeAgentBody`` (the pluggable AgentBody, with the runner-owned oracle re-drive +
normalized Observation + typed outcome taxonomy) had ZERO production callers, while ``engine_think.BrainThink``
— the ``vigil engage --brain hexstrike`` production path — re-implemented the profile+chain construction at
the engine seam. This slice makes the body the ONE canonical proposal source and reduces BrainThink to a thin
adapter that delegates to ``HexstrikeAgentBody.plan``.

What is pinned here:
  * DELEGATION (fail-before/pass-after): driving BrainThink calls ``HexstrikeAgentBody.plan`` — before the
    slice it called ``brain.create_attack_chain`` directly and never touched the body.
  * ONE SOURCE / PARITY: the ordered (tool, params) chain BrainThink emits is byte-for-byte the chain the
    canonical body's ``plan`` returns for the same observation, and the body's own ``propose`` loop agrees —
    a single implementation drives every consumer.
  * STRUCTURAL negative control: the chain build (``create_attack_chain``) lives in the body module and NOT
    in the adapter — reverting the convergence would restore it to the adapter and fail this.
  * PRESERVED capabilities: objective is still normalized at construction (fail-closed on an unknown label)
    and ``danger_floor`` still exists on the adapter for the engine's gate.

Offense leg only (constructing the body imports ``framework.v2.agent_body.interface``); the module-top
``importorskip("framework")`` makes it skip cleanly in the sovereign leg.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("framework")  # offense leg only — the body imports the framework agent-body interface

from vigil_integration.brains.engine_think import BrainThink
from vigil_integration.brains.hexstrike_brain import HexstrikeBrain

TARGET = "http://127.0.0.1/"
# A non-trivial seed: a WordPress web app with open ports → a longer, param-carrying chain to compare on.
_OBS = {"target_type": "web_application", "open_ports": [80, 443], "cms_type": "wordpress"}

_REPO = Path(__file__).resolve().parents[2]
_ADAPTER = _REPO / "integration/vigil_integration/brains/engine_think.py"
_BODY = _REPO / "integration/vigil_integration/brains/hexstrike_body.py"


def _drive(bt: BrainThink, state, *, n: int = 64) -> tuple[list[str], list[dict]]:
    """Drive the seam exactly as the engine does — call until COMPLETE — collecting the proposed chain."""
    tools: list[str] = []
    args: list[dict] = []
    for _ in range(n):
        dec = bt(state)
        tc = getattr(dec, "tool", None)
        if tc is None:  # COMPLETE
            break
        tools.append(tc.tool_name)
        args.append(dict(tc.tool_args))
    assert tools, "the seam proposed no steps — fixture/brain broken"
    return tools, args


# ---------------------------------------------------------------------------------------------------
# DELEGATION — driving the production seam goes through the ONE canonical body's plan()
# ---------------------------------------------------------------------------------------------------
def test_brainthink_delegates_to_the_canonical_body_plan(monkeypatch):
    import vigil_integration.brains.hexstrike_body as body_mod

    calls: list = []
    orig = body_mod.HexstrikeAgentBody.plan

    def _spy(self, observation):
        calls.append(observation)
        return orig(self, observation)

    monkeypatch.setattr(body_mod.HexstrikeAgentBody, "plan", _spy)

    bt = BrainThink(HexstrikeBrain(), target=TARGET, objective="comprehensive", observations=_OBS)
    _drive(bt, SimpleNamespace(objective=TARGET))

    assert calls, "BrainThink did not delegate to HexstrikeAgentBody.plan (the convergence is missing)"
    # the body is retained (a real delegation, not a throwaway) and is the canonical type
    assert isinstance(bt._body, body_mod.HexstrikeAgentBody)


# ---------------------------------------------------------------------------------------------------
# ONE SOURCE / PARITY — the adapter, plan(), and propose() all yield the identical chain
# ---------------------------------------------------------------------------------------------------
def test_adapter_chain_equals_the_bodys_plan_and_propose():
    from framework.v2.agent_body.interface import Observation
    from vigil_integration.brains.hexstrike_body import HexstrikeAgentBody

    # what the production adapter emits
    bt = BrainThink(HexstrikeBrain(), target=TARGET, objective="comprehensive", observations=_OBS)
    adapter_tools, adapter_args = _drive(bt, SimpleNamespace(objective=TARGET))
    # the adapter puts the scannable target into tool_args; strip it to compare against the raw step params
    adapter_params = [{k: v for k, v in a.items() if k != "target"} for a in adapter_args]

    # what the canonical body's plan() returns for the same observation
    body = HexstrikeAgentBody(brain=HexstrikeBrain(), objective="comprehensive")
    _profile, steps = body.plan(Observation(state={**_OBS, "target": TARGET}))
    plan_tools = [s.tool for s in steps]
    plan_params = [dict(s.params) for s in steps]

    assert adapter_tools == plan_tools, (adapter_tools, plan_tools)
    assert adapter_params == plan_params, (adapter_params, plan_params)

    # and the body's OWN propose() loop (its run_cycle consumer, one step per cycle) yields the same ordered
    # tools — proving the single _build_chain source feeds every consumer, not two coincidentally-equal code
    # paths. propose() refills its queue when exhausted (its per-cycle contract, caller-bounded), so we draw
    # exactly len(plan_tools) steps rather than looping to a None that never comes.
    body2 = HexstrikeAgentBody(brain=HexstrikeBrain(), objective="comprehensive")
    thought = body2.think(Observation(state={**_OBS, "target": TARGET}))
    propose_tools = [body2.propose(thought).kind for _ in range(len(plan_tools))]
    assert propose_tools == plan_tools, (propose_tools, plan_tools)


# ---------------------------------------------------------------------------------------------------
# STRUCTURAL negative control — the chain build lives in the body, not the adapter
# ---------------------------------------------------------------------------------------------------
def test_chain_build_lives_in_the_body_not_the_adapter():
    adapter_src = _ADAPTER.read_text(encoding="utf-8")
    body_src = _BODY.read_text(encoding="utf-8")
    assert ".create_attack_chain(" in body_src, "the canonical body no longer owns the chain build"
    assert ".create_attack_chain(" not in adapter_src, (
        "the adapter re-implements the chain build — it must delegate to HexstrikeAgentBody.plan (H1)"
    )
    # the adapter must actually reference the canonical body's plan seam
    assert ".plan(" in adapter_src and "HexstrikeAgentBody" in adapter_src, \
        "the adapter no longer delegates to the canonical body"


# ---------------------------------------------------------------------------------------------------
# PRESERVED capabilities — the adapter still owns objective normalization + danger_floor
# ---------------------------------------------------------------------------------------------------
def test_objective_still_normalizes_at_construction():
    assert BrainThink(HexstrikeBrain(), target=TARGET, objective="")._objective == "comprehensive"
    with pytest.raises(ValueError):
        BrainThink(HexstrikeBrain(), target=TARGET, objective="not-a-real-objective")


def test_danger_floor_still_present_on_the_adapter():
    from vigil_integration.brains.hexstrike_brain import ToolDanger, _TOOL_DANGER
    from vigil_integration.live.wiring import default_classify

    floored = BrainThink(HexstrikeBrain(), target=TARGET).danger_floor(default_classify)
    assert _TOOL_DANGER["nuclei"] is ToolDanger.ACTIVE
    assert floored("nuclei") == "A2", "the raise-only ACTIVE floor was lost in the convergence"
