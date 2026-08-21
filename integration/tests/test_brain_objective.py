"""H0 — the planner's objective label must equal the plan it built, and it is not the engagement goal.

THE DEFECT THIS PINS. ``vigil engage --brain hexstrike`` took ``--objective``, which defaults to ``""``.
``create_attack_chain`` branched on ``objective == "comprehensive"``, so the shipped default fell to the
else-branch and built the SHORT plan — while the chain, the docs and the persisted ``brain-proposal.json``
all labelled it "comprehensive". The same flag was ALSO passed to ``engine.engage(objective=...)`` as the
engagement's free-text goal, so one flag carried two incompatible meanings and no test pinned either.

An objective that lies about the plan corrupts every measurement taken downstream (coverage, tool counts,
effectiveness priors), which is why this is fixed before the rest of the HexStrike work.
"""
from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from vigil_integration.brains.hexstrike_brain import (
    DEFAULT_OBJECTIVE,
    HexstrikeBrain,
    Objective,
    TargetType,
    parse_objective,
)

_REPO = Path(__file__).resolve().parents[2]


@pytest.fixture()
def brain() -> HexstrikeBrain:
    return HexstrikeBrain()


def _chain(brain: HexstrikeBrain, objective, target: str = "http://target.example/"):
    return brain.create_attack_chain(brain.analyze_target(target), objective)


# --- the core invariant: the label equals the behaviour ------------------------------------------------

def test_the_recorded_label_equals_the_plan_that_was_built(brain):
    """For EVERY objective, the chain's label must be the objective the chain was actually built from.

    Built as a comparison between the two distinct plans, so it cannot pass vacuously: if the members ever
    collapse to the same plan, the enum is claiming a distinction the planner does not make.
    """
    per_objective = {}
    for objective in Objective:
        chain = _chain(brain, objective)
        assert chain.objective == objective.value, (
            f"chain built from {objective.value!r} is labelled {chain.objective!r}"
        )
        per_objective[objective] = tuple(step.tool for step in chain.steps)

    assert per_objective[Objective.QUICK] != per_objective[Objective.COMPREHENSIVE], (
        "quick and comprehensive produced the SAME plan — the enum would be claiming a distinction the "
        "planner does not implement, which is the defect this suite exists to prevent"
    )
    assert len(per_objective[Objective.COMPREHENSIVE]) > len(per_objective[Objective.QUICK])


@pytest.mark.parametrize("empty", ["", "   ", None])
def test_an_empty_objective_resolves_to_the_documented_default_and_builds_it(brain, empty):
    """The original bug: an empty objective silently built the short plan under the long plan's name."""
    assert parse_objective(empty) is DEFAULT_OBJECTIVE
    chain = _chain(brain, empty)
    assert chain.objective == DEFAULT_OBJECTIVE.value
    reference = _chain(brain, DEFAULT_OBJECTIVE)
    assert [s.tool for s in chain.steps] == [s.tool for s in reference.steps], (
        "an empty objective did not build the same plan as its documented default"
    )


def test_an_unknown_objective_is_refused_not_silently_degraded(brain):
    """Anything unrecognised must raise — never fall through to a different plan."""
    with pytest.raises(ValueError) as excinfo:
        _chain(brain, "anything-else")
    message = str(excinfo.value)
    for member in Objective:
        assert member.value in message, "the error must name the accepted objectives"
    assert "--brain-objective" in message and "--objective" in message, (
        "the error must disambiguate the planner objective from the engagement goal — that confusion is "
        "the second half of this defect"
    )


def test_a_free_text_engagement_goal_is_refused_by_the_planner(brain):
    """`--objective "find RCE"` reaching the planner is exactly the double-purpose bug; it must not plan."""
    with pytest.raises(ValueError):
        _chain(brain, "find an RCE in the admin panel")


# --- the two chain defects found by running it --------------------------------------------------------

@pytest.mark.parametrize("target,kind", [
    ("http://target.example/", TargetType.WEB_APPLICATION),
    ("http://target.example/api", TargetType.API_ENDPOINT),
])
def test_no_tool_is_proposed_twice_in_one_chain(brain, target, kind):
    """A comprehensive chain concatenates two playbooks; a tool in both was emitted twice.

    Duplicate steps mean the same scan is proposed, gated, approved and run twice — wasted target traffic
    and a doubled approval burden.
    """
    assert brain.analyze_target(target).target_type is kind
    for objective in Objective:
        tools = [s.tool for s in _chain(brain, objective, target).steps]
        duplicates = sorted({t for t in tools if tools.count(t) > 1})
        assert not duplicates, f"{objective.value} chain proposes {duplicates} more than once"


@pytest.mark.parametrize("target", ["http://target.example/", "http://target.example/api",
                                    "10.0.0.5", "aws://acct"])
def test_step_priorities_stay_a_contiguous_ordering(brain, target):
    """Skipping a row must not leave a hole in the 1..N ordering the proposal contract promises.

    Found by the pre-existing suite while fixing the duplicate defect: priority was the index of the SOURCE
    row, so every skipped row (a non-curated tool, or now a de-duplicated one) left a gap. Pinned here for
    every objective and target type, not just the one case that happened to catch it.
    """
    for objective in Objective:
        steps = _chain(brain, objective, target).steps
        assert [s.priority for s in steps] == list(range(1, len(steps) + 1)), (
            f"{objective.value} chain for {target} has non-contiguous priorities: "
            f"{[s.priority for s in steps]}"
        )


def test_the_playbook_s_own_parameters_reach_the_proposal(brain):
    """`optimize_parameters` received the step's params as context and dropped them for most tools."""
    steps = {s.tool: s.params for s in _chain(brain, Objective.COMPREHENSIVE).steps}
    assert "katana" in steps, "expected katana in the web chain"
    assert steps["katana"].get("depth") == 3 and steps["katana"].get("js_crawl") is True, (
        f"katana's curated playbook params were dropped: {steps['katana']}"
    )


def test_curated_per_tool_params_still_win_over_the_playbook_context(brain):
    """The merge must not let context override the drift-reviewed per-tool block."""
    profile = brain.analyze_target("http://target.example/")
    params = brain.optimize_parameters("nuclei", profile, {"severity": "info", "extra": 1})
    assert params["severity"] != "info", "context overrode the curated severity"
    assert params.get("extra") == 1, "context-only keys should still be carried"


# --- the CLI seam: two flags, two meanings ------------------------------------------------------------

def test_the_cli_exposes_a_separate_closed_planner_objective():
    source = (_REPO / "integration" / "vigil_integration" / "cli.py").read_text(encoding="utf-8")
    assert '"--brain-objective"' in source, "the planner objective needs its own flag"
    assert 'choices=("quick", "comprehensive")' in source, (
        "the planner objective must be a closed set at the CLI boundary too"
    )
    assert "objective=getattr(args, \"brain_objective\", None)" in source, (
        "the brain must be constructed from --brain-objective, not from the engagement's --objective"
    )


def test_brain_think_normalises_at_construction():
    from vigil_integration.brains.engine_think import BrainThink

    assert BrainThink(HexstrikeBrain(), target="http://t.example/", objective="")._objective == \
        DEFAULT_OBJECTIVE.value
    with pytest.raises(ValueError):
        BrainThink(HexstrikeBrain(), target="http://t.example/", objective="free text goal")


# --- honesty: the enum only claims what the planner implements ----------------------------------------

def test_the_enum_claims_no_objective_the_planner_does_not_implement():
    """Members that all produced the same plan would re-create label-does-not-equal-behaviour.

    ``create_attack_chain`` makes exactly one objective-driven distinction, so the enum has exactly two
    members. Adding cloud/source/api/network here without planner support is the failure mode to avoid —
    target TYPE already selects those playbooks.
    """
    assert {o.value for o in Objective} == {"quick", "comprehensive"}
    body = inspect.getsource(HexstrikeBrain.create_attack_chain)
    assert "Objective.COMPREHENSIVE" in body, "the branch must compare against the enum, not a bare string"


# --- negative controls --------------------------------------------------------------------------------

def test_negative_control_the_duplicate_detector_detects_a_duplicate():
    tools = ["nmap", "nuclei", "httpx", "nuclei"]
    assert sorted({t for t in tools if tools.count(t) > 1}) == ["nuclei"]


def test_negative_control_the_label_check_would_catch_a_mislabelled_chain(brain):
    """Prove the label assertion is not vacuous by mislabelling a chain by hand."""
    chain = _chain(brain, Objective.QUICK)
    chain.objective = "comprehensive"
    assert chain.objective != Objective.QUICK.value, (
        "the equality used by the label test cannot distinguish a mislabelled chain"
    )
