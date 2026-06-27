"""Tests for improve.merge_gate — the gated deployment authority.

Exercises the full three-part gate: capability (Pillar 2), eval-green
(M2), and threshold approvals over the proposal content (reusing the
entitlement crypto).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ...entitlement import policy as ent_policy
from ...entitlement import provision
from ...entitlement.crypto import sign
from ...entitlement.models import AuthorizerKey, Signature, TrustRoot
from ...eval.models import RegressionReport
from ..canonical import proposal_signing_bytes
from ..merge_gate import evaluate_merge
from ..models import GapKind, ImprovementProposal
from ..patcher import draft_proposals
from ..models import CapabilityGap

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _proposal() -> ImprovementProposal:
    gap = CapabilityGap(
        id="gap-horizon-cve-1", kind=GapKind.HORIZON, priority=90,
        title="Horizon: CVE-1", source="horizon:nvd", discovered_at=_NOW,
    )
    return draft_proposals([gap], now=_NOW)[0]


def _authority(n: int, threshold: int) -> tuple[TrustRoot, dict[str, str]]:
    authorizers: list[AuthorizerKey] = []
    privs: dict[str, str] = {}
    for i in range(n):
        ak, priv = provision.new_authorizer(f"auth-{i}", f"Authoriser {i}")
        authorizers.append(ak)
        privs[f"auth-{i}"] = priv
    return provision.build_trust_root(authorizers, threshold), privs


def _approve(proposal: ImprovementProposal, privs: dict[str, str], *key_ids: str) -> list[Signature]:
    msg = proposal_signing_bytes(proposal)
    return [Signature(key_id=k, signature_b64=sign(privs[k], msg)) for k in key_ids]


def _passed_report() -> RegressionReport:
    return RegressionReport(
        baseline_run_id="b", candidate_run_id="c", passed=True,
        detection_rate_delta=0.1, precision_delta=0.0,
    )


def _failed_report() -> RegressionReport:
    return RegressionReport(
        baseline_run_id="b", candidate_run_id="c", passed=False,
        detection_rate_delta=-0.2, precision_delta=0.0,
        reasons=["detection rate dropped"],
    )


def test_authorised_when_all_three_hold() -> None:
    # Ungoverned entitlement dir -> capability permissive (present).
    ent_policy.reset_policy()
    proposal = _proposal()
    tr, privs = _authority(3, 2)
    approvals = _approve(proposal, privs, "auth-0", "auth-1")
    decision = evaluate_merge(proposal, _passed_report(), approvals, tr, now=_NOW)
    assert decision.approved is True
    assert decision.eval_passed is True
    assert decision.threshold_met is True
    assert decision.capability_present is True
    assert set(decision.valid_approvers) == {"auth-0", "auth-1"}


def test_denied_when_eval_failed() -> None:
    proposal = _proposal()
    tr, privs = _authority(1, 1)
    approvals = _approve(proposal, privs, "auth-0")
    decision = evaluate_merge(proposal, _failed_report(), approvals, tr, now=_NOW)
    assert decision.approved is False
    assert decision.eval_passed is False


def test_denied_when_threshold_not_met() -> None:
    proposal = _proposal()
    tr, privs = _authority(3, 2)
    approvals = _approve(proposal, privs, "auth-0")  # only 1 of required 2
    decision = evaluate_merge(proposal, _passed_report(), approvals, tr, now=_NOW)
    assert decision.approved is False
    assert decision.threshold_met is False


def test_approval_over_different_proposal_does_not_count() -> None:
    proposal = _proposal()
    other = proposal.model_copy(update={"title": "a different proposal entirely"})
    tr, privs = _authority(1, 1)
    # Sign the OTHER proposal's bytes, present against `proposal`.
    approvals = _approve(other, privs, "auth-0")
    decision = evaluate_merge(proposal, _passed_report(), approvals, tr, now=_NOW)
    assert decision.threshold_met is False
    assert decision.approved is False


def test_denied_when_capability_absent_under_enforcement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Force entitlement enforcement with no grant -> SELF_IMPROVEMENT_MERGE
    # (ADVANCED tier) is denied, so the gate must refuse even with eval
    # green and a full threshold of approvals.
    monkeypatch.setenv("CRUCIBLE_ENTITLEMENT_ENFORCED", "1")
    ent_policy.reset_policy()
    proposal = _proposal()
    tr, privs = _authority(1, 1)
    approvals = _approve(proposal, privs, "auth-0")
    decision = evaluate_merge(proposal, _passed_report(), approvals, tr, now=_NOW)
    assert decision.capability_present is False
    assert decision.approved is False


def test_check_capability_false_bypasses_capability_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # With check_capability=False the capability is treated as present
    # (offline policy modelling), but eval + threshold still gate.
    monkeypatch.setenv("CRUCIBLE_ENTITLEMENT_ENFORCED", "1")
    ent_policy.reset_policy()
    proposal = _proposal()
    tr, privs = _authority(1, 1)
    approvals = _approve(proposal, privs, "auth-0")
    decision = evaluate_merge(
        proposal, _passed_report(), approvals, tr, now=_NOW, check_capability=False
    )
    assert decision.capability_present is True
    assert decision.approved is True
