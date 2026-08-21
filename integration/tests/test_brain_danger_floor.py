"""H1 — the planner's danger class must survive the engine seam (raise-only).

The brain classifies every tool it may propose as RECON or ACTIVE, but that judgement was DROPPED at the
engine seam: BrainThink puts it only in the reasoning string, and the tier is re-derived from the
executor's own ``default_classify`` — whose curated ``_RECON`` set contains ``nuclei``, a tool the brain
calls ACTIVE and which sends attack templates rather than merely observing. So a brain-proposed ACTIVE step
could classify A1 and become auto-eligible. Two VIGIL-owned tables disagreed and the weaker one won.
"""
from __future__ import annotations

import pytest

from vigil_integration.brains.engine_think import BrainThink
from vigil_integration.brains.hexstrike_brain import HexstrikeBrain, ToolDanger, _TOOL_DANGER
from vigil_integration.live.wiring import default_classify

_ORDER = {"A0": 0, "A1": 1, "A2": 2, "A3": 3}


@pytest.fixture()
def floored():
    return BrainThink(HexstrikeBrain(), target="http://target.example/").danger_floor(default_classify)


def test_an_active_tool_the_base_classifier_calls_recon_is_raised(floored):
    """The concrete defect: nuclei is ACTIVE to the brain and auto-eligible to the executor."""
    assert _TOOL_DANGER["nuclei"] is ToolDanger.ACTIVE
    assert default_classify("nuclei") == "A1", "base classifier no longer treats nuclei as recon"
    assert floored("nuclei") == "A2", "a brain-proposed ACTIVE tool must not stay auto-eligible"


@pytest.mark.parametrize("tool", ["nmap", "httpx"])
def test_recon_tools_are_untouched(floored, tool):
    assert _TOOL_DANGER[tool] is ToolDanger.RECON
    assert floored(tool) == default_classify(tool)


def test_the_floor_never_lowers_a_tier(floored):
    """A danger-token name is A3; the ACTIVE floor must not pull it down to A2."""
    assert default_classify("git.push") == "A3"
    assert floored("git.push") == "A3"


def test_every_active_tool_lands_at_or_above_a2(floored):
    """Swept over the whole curated map, so a future ACTIVE addition cannot slip through as auto-eligible."""
    offenders = [t for t, d in _TOOL_DANGER.items()
                 if d is ToolDanger.ACTIVE and _ORDER[floored(t)] < _ORDER["A2"]]
    assert not offenders, f"these ACTIVE tools remain auto-eligible: {offenders}"


def test_the_floor_only_ever_raises(floored):
    """Sweep the whole map: the floored tier is never below the base tier."""
    lowered = [t for t in _TOOL_DANGER if _ORDER[floored(t)] < _ORDER[default_classify(t)]]
    assert not lowered, f"the floor lowered these tools: {lowered}"


def test_a_tool_the_brain_does_not_know_is_untouched(floored):
    assert floored("some-unregistered-tool") == default_classify("some-unregistered-tool")


def test_non_brain_runs_are_unaffected():
    """The floor applies only where a brain is driving; default_classify itself is not modified."""
    assert default_classify("nuclei") == "A1", (
        "default_classify was mutated — non-brain engagements would change behaviour, which this slice "
        "deliberately does not do"
    )


def test_the_gate_is_built_with_the_brain_floor_when_a_brain_is_wired():
    """Pin the wiring: duck-typed, so a brain without the hook changes nothing."""
    from pathlib import Path

    src = Path(__file__).resolve().parents[1].joinpath(
        "vigil_integration/live/wiring.py").read_text(encoding="utf-8")
    assert 'getattr(config.brain, "danger_floor", None)' in src
    assert "classify=_classify" in src, "the computed classifier must reach _build_gate"


def test_negative_control_the_sweep_would_catch_an_auto_eligible_active_tool(floored):
    """Prove the sweep is not vacuous by checking it against a deliberately wrong classifier."""
    bad = BrainThink(HexstrikeBrain(), target="t").danger_floor(lambda name: "A1")
    offenders = [t for t, d in _TOOL_DANGER.items()
                 if d is ToolDanger.ACTIVE and _ORDER[bad(t)] < _ORDER["A2"]]
    assert offenders == [], (
        "with an all-A1 base the floor must still raise every ACTIVE tool to A2 — if this list is "
        "non-empty the floor is not doing its job"
    )
    assert bad("httpx") == "A1", "a RECON tool must remain at whatever the base said"
