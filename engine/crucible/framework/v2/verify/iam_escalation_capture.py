"""verify.iam_escalation_capture — the confirmation seam for the E2 IAM privilege-escalation PRIMITIVE oracle
(BUILD-PLAN §E2).

A DEFENSIVE VERIFICATION oracle, NOT an attack runner. A cloud/CSPM sensor's "principal X can escalate" is a
heuristic LEAD; it becomes an achieved-escalation FACT only when a deterministic oracle re-derives, over the
RETAINED IAM-policy capture ALONE, that the retained statements grant the base principal an UNCONDITIONAL
escalation PRIMITIVE from a FIXED, auditable set that STRICTLY increases what it can reach — the target is
reachable in the escalation-CLOSED closure but NOT in the base closure (an EXPLICIT differential of two
BFS closures, the central anti-overclaim guard). This module routes a retained capture through the pure
``iam_escalation_oracle`` and returns a re-verifiable verdict.

The ACHIEVED-ESCALATION dual of ``verify.policy_path`` (which proves mere REACHABILITY): this proves a
STRONGER claim on its own evidence branch. Like ``verify.policy_path`` there is NO network and NO gate here —
the "capture" is a pure, offline re-derivation over the operator's own retained policy. The FACT is a
CAPABILITY over the retained configuration (identity policy + permissions boundary + SCP permit the
primitive); a resource-based policy (a KMS key policy, an S3 bucket policy, the target role's trust Deny) NOT
present in the capture could still nullify it — the oracle's verdict is worded accordingly. No secret is ever
retained (only IAM ids / actions / resources), so a confirmed FACT re-verifies OFFLINE from its certificate
(``verify.reverify``) with no cloud.
"""

from __future__ import annotations

from typing import Any, Mapping

from .adapter import FindingContext
from .models import VerificationResult
from .verifier import OracleVerifier


def iam_escalation_capture_context(capture: Mapping[str, Any]) -> dict:
    """The verifier context for a retained IAM-escalation capture — routes to the E2 escalation oracle."""
    return FindingContext.from_iam_escalation_capture(dict(capture or {})).to_verifier_context()


def confirm_iam_escalation_capture(
    capture: Mapping[str, Any], *, verifier: OracleVerifier | None = None
) -> VerificationResult:
    """Judge a retained IAM-escalation capture with the deterministic oracle: ``confirmed`` iff the capture
    PROVES the retained IAM configuration UNCONDITIONALLY PERMITS the base principal an escalation primitive
    from the fixed set (trust-policy rewrite = sts:AssumeRole + iam:UpdateAssumeRolePolicy; iam:PassRole to a
    compute service; self policy-attach = iam:AttachUserPolicy / iam:PutUserPolicy; add-to-privileged-group =
    iam:AddUserToGroup; create-credential-for-target = iam:CreateAccessKey / iam:CreateLoginProfile) that
    STRICTLY increases what the base principal reaches. A statement with a Condition, a NotAction, an explicit
    Deny (deny-precedence), a restricting boundary/SCP, or a resource wildcard that does not cover the target
    contributes NO edge; a target already reachable in the base closure is NOT escalation (stays an honest
    LEAD). No cloud call is made and no attack is performed — a pure re-derivation over already-retained
    policy evidence, so the same verdict re-verifies offline from the finding's certificate."""
    return (verifier or OracleVerifier()).confirm(iam_escalation_capture_context(capture))
