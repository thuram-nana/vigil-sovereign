"""
improve.merge_gate — authorise (never apply) a self-improvement merge.

The never-stop loop generates proposals continuously; this gate is where
deployment is held. A proposal MAY be merged only when all three hold:

  1. capability — the deployment holds SELF_IMPROVEMENT_MERGE (Pillar 2).
  2. eval-green — the candidate build's regression verdict passed (M2).
  3. threshold approvals — at least the trust root's threshold of
     governance authorisers signed the proposal's content digest
     (reusing the Pillar-2 entitlement crypto).

The gate returns a `MergeDecision`. It does NOT touch the working tree:
authorisation and application are separate, deliberately. A human (or a
controlled deploy step) applies a proposal the gate authorised. An
uncertifiable, unattributable, self-mutating offensive tool is exactly
what this gate exists to prevent.
"""

from __future__ import annotations

from datetime import datetime

from ..entitlement import Capability, is_capability_available
from ..entitlement.crypto import verify_threshold
from ..entitlement.models import Signature, TrustRoot
from ..eval.models import RegressionReport
from .canonical import proposal_signing_bytes
from .models import ImprovementProposal, MergeDecision


def evaluate_merge(
    proposal: ImprovementProposal,
    regression_report: RegressionReport,
    approvals: list[Signature],
    trust_root: TrustRoot,
    *,
    now: datetime,
    check_capability: bool = True,
) -> MergeDecision:
    """Authorise or refuse a merge. Pure: makes no change to disk or the
    framework. `check_capability=False` is for offline policy modelling
    only; production leaves it True."""
    reasons: list[str] = []

    capability_present = (
        is_capability_available(Capability.SELF_IMPROVEMENT_MERGE)
        if check_capability
        else True
    )
    if not capability_present:
        reasons.append(
            "deployment does not hold SELF_IMPROVEMENT_MERGE capability"
        )

    eval_passed = regression_report.passed
    if not eval_passed:
        reasons.append(
            "eval regression gate failed: " + "; ".join(regression_report.reasons)
        )

    thr = verify_threshold(proposal_signing_bytes(proposal), approvals, trust_root)
    if not thr.satisfied:
        reasons.append(f"approval threshold not met: {thr.reason}")

    approved = capability_present and eval_passed and thr.satisfied
    if approved:
        reasons.append(
            f"authorised: {len(thr.valid_signers)}/{trust_root.threshold} approvals, "
            f"eval green, capability present — apply by hand or via the gated deploy step"
        )

    return MergeDecision(
        proposal_id=proposal.id,
        approved=approved,
        capability_present=capability_present,
        eval_passed=eval_passed,
        threshold_met=thr.satisfied,
        valid_approvers=list(thr.valid_signers),
        reasons=reasons,
        evaluated_at=now,
    )
