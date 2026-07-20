"""Tests for defender.scoring and defender.posture, including the
capability gate and the no-evasion policy line."""

from __future__ import annotations

import pytest

from ...common.errors import EntitlementViolation
from ...entitlement import policy as ent_policy
from ..models import ActionDescriptor, ActionKind, Posture
from ..posture import annotate_action
from ..scoring import score_action


def test_injection_is_loud() -> None:
    score = score_action(
        ActionDescriptor(kind=ActionKind.INJECTION_PROBE, target_surface="/s")
    )
    assert score.loudest_severity == "high"
    assert score.detectability > 0.5
    assert any(h.rule_id == "R-WAF-INJECTION" for h in score.hits)


def test_plain_get_is_quiet_apart_from_intended_ua() -> None:
    score = score_action(ActionDescriptor(kind=ActionKind.HTTP_REQUEST, target_surface="/"))
    # Only the info-level OBSIDIAN UA "detection" fires.
    non_info = [h for h in score.hits if h.severity != "info"]
    assert non_info == []
    assert score.detectability < 0.1


def test_detectability_is_noisy_or_monotonic() -> None:
    quiet = score_action(ActionDescriptor(kind=ActionKind.HTTP_REQUEST, target_surface="/"))
    loud = score_action(
        ActionDescriptor(
            kind=ActionKind.INJECTION_PROBE,
            target_surface="/s",
            attributes={"failed_count": "0"},
        )
    )
    assert loud.detectability > quiet.detectability


def test_score_gated_under_enforcement(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CRUCIBLE_ENTITLEMENT_ENFORCED", "1")
    ent_policy.reset_policy()
    with pytest.raises(EntitlementViolation):
        score_action(ActionDescriptor(kind=ActionKind.HTTP_REQUEST, target_surface="/"))


def test_check_capability_false_bypasses_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CRUCIBLE_ENTITLEMENT_ENFORCED", "1")
    ent_policy.reset_policy()
    score = score_action(
        ActionDescriptor(kind=ActionKind.HTTP_REQUEST, target_surface="/"),
        check_capability=False,
    )
    assert score.signals_emitted == 1


# ---- posture --------------------------------------------------------------


def test_test_posture_emphasises_correlatability() -> None:
    ann = annotate_action(
        ActionDescriptor(kind=ActionKind.HTTP_REQUEST, target_surface="/"), Posture.TEST
    )
    joined = " ".join(ann.guidance).lower()
    assert "correlat" in joined
    assert ann.posture is Posture.TEST


def test_emulate_posture_reports_detectability_without_evasion() -> None:
    ann = annotate_action(
        ActionDescriptor(kind=ActionKind.INJECTION_PROBE, target_surface="/s"), Posture.EMULATE
    )
    joined = " ".join(ann.guidance).lower()
    # Honest self-assessment is present...
    assert "detectable" in joined
    assert "does not generate evasion" in joined
    # ...and no evasion vocabulary leaks into guidance.
    for banned in ("bypass", "evade", "obfuscat", "encode the payload", "waf bypass"):
        assert banned not in joined


def test_emulate_quiet_action_notes_lower_bound() -> None:
    ann = annotate_action(
        ActionDescriptor(kind=ActionKind.HTTP_REQUEST, target_surface="/"), Posture.EMULATE
    )
    joined = " ".join(ann.guidance).lower()
    assert "lower bound" in joined or "not proof of stealth" in joined
