"""
Tests for URK.

Acceptance test per FORGE PROTOCOL § 3.8: every v1 cognitive document
has a corresponding URK function that, given a representative input,
produces output structurally consistent with what a careful operator
would produce.

These tests run against the DryRun backend so they don't need network.
A separate live-backend test would activate when ANTHROPIC_API_KEY or
Ollama is available — out of scope for this session.
"""

from __future__ import annotations

import os

import pytest

from framework.v2.common import docs
from framework.v2.kernel import (
    critique,
    decide,
    hypothesize,
    opsec,
    pivot,
    threat_model,
)
from framework.v2.kernel.llm import get_backend, reset_cache
from framework.v2.kernel.models import (
    CritiqueResult,
    HypothesisSet,
    OpsecGuidance,
    PivotProposal,
    SeverityDecision,
    ThreatModel,
)


# --- backend selection ---------------------------------------------------


def test_dryrun_is_active(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CRUCIBLE_LLM_BACKEND", "dryrun")
    reset_cache()
    be = get_backend()
    assert be.name == "dryrun"
    assert be.is_dryrun


# --- section anchors all resolve in real cognitive docs ------------------

# These mirror the section_anchors lists in each binding file. If the
# binding adds or removes an anchor, update here too.
_BINDING_ANCHORS: dict[str, list[str]] = {
    "hypothesis-driven": [
        "1-the-hypothesis-form",
        "2-generating-hypotheses-forcing-breadth",
        "3-cheap-test-design",
        "4-falsifiability-what-evidence-would-change-my-mind",
    ],
    "self-critique": [
        "1-quick-critique-5-minutes-run-often",
        "21-coverage-check",
        "4-final-critique-before-declaring-done",
        "5-anti-patterns-the-routine-catches",
    ],
    "pivot-protocols": [
        "1-the-two-minute-reset",
        "2-surface-pivot-same-class-different-surface",
        "3-class-pivot-same-surface-different-class",
        "4-adversary-pivot-what-would-x-do-here",
        "5-layer-pivot-go-up-or-go-down",
    ],
    "decision-frameworks": [
        "1-severity-cvss-plus-contextual-adjustment",
        "11-when-to-override-cvss-up",
        "12-when-to-override-cvss-down",
        "13-severity-ladder-pragmatic-definitions",
        "5-the-explain-it-to-a-regulator-test",
        "6-when-to-surface-immediately-vs-hold",
    ],
    "opsec-discipline": [
        "1-three-postures",
        "2-test-posture-the-defaults",
        "3-audit-posture-additions",
        "4-emulate-posture-additions",
        "7-what-you-do-not-do-ever-in-any-posture",
    ],
    "threat-modeling": [
        "1-what-a-threat-model-contains",
        "2-assets-whats-worth-attacking",
        "3-actors-whos-actually-attacking",
        "4-trust-boundaries-where-you-focus",
        "5-stride-per-boundary",
        "6-attack-trees",
    ],
}


@pytest.mark.parametrize(
    "stem,anchor",
    [(s, a) for s, anchors in _BINDING_ANCHORS.items() for a in anchors],
)
def test_section_anchor_resolves(stem: str, anchor: str) -> None:
    doc = docs.cognitive(stem)
    available = {s.anchor for s in doc.sections}
    assert anchor in available, (
        f"binding for {stem} references missing anchor {anchor!r}; "
        f"available: {sorted(available)}"
    )


# --- per-binding acceptance tests ----------------------------------------


def test_hypothesize_returns_doctrine_compliant_set() -> None:
    hs, trace = hypothesize(
        observation="GET /api/orders/{id} returns another user's order body with 200",
        surface="/api/orders/{id}",
    )
    assert isinstance(hs, HypothesisSet)
    # Doctrine: at least 5 hypotheses (hypothesis-driven.md § 2)
    assert hs.doctrine_compliant()
    # Each hypothesis has the four required parts plus refute_on / cheap_test
    for h in hs.hypotheses:
        assert h.given and h.if_action and h.then_observation and h.because_model
        assert h.refute_on and h.cheap_test
        assert 0.0 <= h.confidence <= 1.0
    # Diversity — at least 3 distinct bug classes among the first 5
    classes = {h.bug_class for h in hs.hypotheses[:5]}
    assert len(classes) >= 3
    assert trace.cognitive_doc.endswith("hypothesis-driven.md")


def test_critique_returns_decision() -> None:
    cr, trace = critique(
        claim="I think the IDOR is exploitable",  # hedged → more_evidence_needed
        evidence="changed the id once and got back data",
    )
    assert isinstance(cr, CritiqueResult)
    assert cr.decision in ("confirm", "objections", "more_evidence_needed")
    # deception_check is required (self-critique.md § 1.5)
    assert cr.deception_check.strip()
    assert trace.cognitive_doc.endswith("self-critique.md")


def test_critique_strong_claim_is_confirmed() -> None:
    cr, _ = critique(
        claim=(
            "Reproduced twice end-to-end with a working PoC: "
            "POST /payment/cb with arbitrary user_id credits balance; confirmed."
        ),
        evidence="curl shows balance increment on staging; logs confirm.",
    )
    assert cr.decision == "confirm"


def test_pivot_returns_diverse_moves() -> None:
    pp, _ = pivot(
        stuck_thread="Spent an hour on /admin path bypass; all variants 401",
        last_observation="every X-Original-URL variant returns identical 401",
    )
    assert isinstance(pp, PivotProposal)
    assert len(pp.moves) >= 3
    kinds = {m.kind for m in pp.moves}
    # Diversity check: at least 3 distinct kinds
    assert len(kinds) >= 3
    # recommended index is valid
    assert 0 <= pp.recommended < len(pp.moves)


def test_decide_classifies_severity() -> None:
    sd, _ = decide(
        finding_summary=(
            "Webhook callback accepts forged deposits without signature, "
            "crediting balance to any user_id from the request body."
        ),
        affected_endpoint="POST /payment/cryptomus/callback",
        preconditions="none — endpoint is unauthenticated by design",
        impact_observed="$100 balance credit per forged request",
    )
    assert isinstance(sd, SeverityDecision)
    assert sd.severity in ("Critical", "High", "Medium", "Low", "Info")
    assert 0.0 <= sd.cvss_base <= 10.0
    assert sd.regulator_paragraph.strip()
    # Webhook + balance → at least High in the heuristic
    assert sd.severity in ("Critical", "High")


def test_opsec_blocks_destructive() -> None:
    og, _ = opsec(
        action_summary="run sqlmap with --os-shell to drop a webshell",
        posture="TEST",
    )
    assert isinstance(og, OpsecGuidance)
    assert not og.allowed
    assert og.pre_approval_required


def test_opsec_allows_normal_action() -> None:
    og, _ = opsec(
        action_summary="curl a single GET against /api/v2/users/1 with low-priv cookie",
        posture="TEST",
    )
    assert og.allowed


def test_opsec_emulate_changes_recommendations() -> None:
    test_g, _ = opsec(action_summary="probe an endpoint", posture="TEST")
    emul_g, _ = opsec(action_summary="probe an endpoint", posture="EMULATE")
    assert test_g.user_agent_recommendation != emul_g.user_agent_recommendation


def test_threat_model_returns_full_structure() -> None:
    tm, _ = threat_model(
        target_name="mrbeanpanel",
        business_context="SMM reseller panel; balance-based; users report ATOs",
        archetype="PHP-Smarty SMM-panel fork",
        known_concerns=["users reporting account takeovers"],
    )
    assert isinstance(tm, ThreatModel)
    assert len(tm.assets) >= 1
    assert len(tm.actors) >= 1
    assert len(tm.trust_boundaries) >= 1
    assert tm.attack_tree.label.strip()
    assert tm.catastrophic_outcomes


# --- call traces are populated ------------------------------------------


def test_call_trace_populated() -> None:
    _, trace = hypothesize(observation="x", surface="/y")
    assert trace.backend == "dryrun"
    assert trace.is_dryrun
    assert trace.cognitive_doc
    assert trace.cognitive_sections
    assert trace.timestamp
