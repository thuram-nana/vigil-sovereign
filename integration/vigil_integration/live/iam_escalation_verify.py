"""iam_escalation_verify — VIGIL-owned admission / certification route for an IAM privilege-escalation
PRIMITIVE FACT (BUILD-PLAN §E2 — the PRODUCER for the E2 oracle, mirroring ``secret_verify`` for E5).

A cloud/CSPM sensor (or an operator IAM export) produces a RETAINED IAM-policy capture; this module routes
that capture through the deterministic ``iam_escalation_primitive`` oracle, ADMITS it against the registered
``cloud_exploit.iam.privilege_escalation`` evidence branch (``verdict.admit`` — a fired oracle over a
fact-capable, precondition-holding branch is a FACT, anything else a LEAD), and — on a FACT — mints the signed
D2 certificate via ``oracle_adapter.certify_admitted`` (the ONLY sanctioned mint path; a sovereign ``live/*``
module must never call ``build_certificate`` / ``confirm_and_certify`` directly).

A confirmed FACT then re-verifies OFFLINE from its certificate (``verify.reverify`` re-fires the same oracle)
and its retained ``oracle_context`` re-executes under the veracity firewall — BOTH engage automatically (the
cert builder and the firewall are generic over any finding carrying an ``oracle_context``).

The FACT is a CAPABILITY over the RETAINED configuration: the identity policy + permissions boundary + SCP
PERMIT the escalation primitive. A resource-based policy (a KMS key policy, an S3 bucket policy, the target
role's trust Deny) NOT present in the capture could still nullify it — the oracle's verdict and the branch
limitation say so. The ACHIEVED-ESCALATION dual of the ``policy_path`` reachability half: this proves the
STRONGER strict-gain claim on its OWN evidence branch.

INERT on scan/engage: nothing on the scan/engage/benchmark path mints an ``iam_escalation_primitive`` finding
(the oracle is kept OUT of the frozen ``_ALL_ORACLES`` fallback), so the capability fires ONLY when this
producer is called EXPLICITLY over a retained capture — preserving the no-auto-fire gate.

FATAL-2: every framework import is FUNCTION-LOCAL; at module scope this is pure stdlib only, so importing it
co-loads no offense engine (mirrors ``secret_verify`` / ``imds_verify``). No secret is retained (only IAM ids
/ actions / resources), so the certificate re-verifies offline with no live credential.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# The registered IAM-escalation-primitive evidence branch (docs/capability-matrix/evidence-branches.json).
# fact_capable (a retained config that PERMITS an unconditional strict-gain escalation primitive is an
# achieved-escalation FACT); clean_capable:false (one capture cannot prove no escalation path exists).
_BRANCH = "cloud_exploit.iam.privilege_escalation"


@dataclass
class IamEscalationVerifyResult:
    """The outcome of routing ONE retained IAM-escalation capture through oracle -> admission -> (on FACT)
    certificate."""

    primitive: str
    verdict: str = "LEAD"                  # the admitted verdict value (FACT / LEAD / INCONCLUSIVE)
    is_fact: bool = False
    reason: str = ""
    finding_ref: str = ""
    finding: "dict | None" = None          # {check_id, bug_class, oracle_context} — the re-verifiable finding
    oracle_context: "dict | None" = None   # secret-free; the retained proof reverify / the firewall re-fire
    certificate: Any = None                # the signed AdapterResult (None unless is_fact)
    admission: "tuple | None" = None       # (branch_id, verdict, reason) — the admission trail


def _oracle_signal(oracle_context: dict) -> "tuple[bool, bool]":
    """Run the deterministic E2 oracle over the retained ctx and return ``(fired, conclusive)`` WITHOUT
    minting. All framework imports are function-local (FATAL-2), exactly like ``secret_verify``."""
    from framework.v2.scanner.engine import probe_verdict  # noqa: PLC0415
    from framework.v2.verify.confirmation import adjudicate_finding, confirmed_from_result  # noqa: PLC0415
    from framework.v2.verify.verifier import OracleVerifier  # noqa: PLC0415

    verifier = OracleVerifier()
    finding = {"bug_class": "iam_escalation_primitive", "oracle_context": oracle_context}
    result = adjudicate_finding(finding, oracle_context, verifier)
    fired = confirmed_from_result(result, finding, verifier) is not None
    verdict, _kinds = probe_verdict(result)
    conclusive = fired or verdict == "clean"
    return fired, conclusive


def _capture_wellformed(capture: Any) -> bool:
    """The branch precondition this producer can evaluate over the capture bytes ALONE: a dict carrying a
    base_principal, a target_resource, a policy graph, and an escalation object with a primitive. The ORACLE,
    not this, decides fired/conclusive — this only STRUCTURAL-gates so an unparseable / partial capture
    cannot be admitted as a FACT."""
    if not isinstance(capture, dict):
        return False
    esc = capture.get("escalation")
    return (bool(str(capture.get("base_principal", "")).strip())
            and bool(str(capture.get("target_resource", "")).strip())
            and isinstance(capture.get("graph"), dict)
            and isinstance(esc, dict)
            and bool(str(esc.get("primitive", "")).strip()))


def _binding(cap: dict) -> dict:
    """The D2 fields to bind into the signed cert (allowlist-filtered by oracle_adapter). Config-identity
    metadata only — NEVER a secret (the capture holds none). The real tamper-evidence is the automatic
    ``oracle_context_digest`` binding over the retained evidence."""
    esc = cap.get("escalation") if isinstance(cap.get("escalation"), dict) else {}
    return {"capture_method": "retained_config:iam_policy",
            "primitive": str(esc.get("primitive", "") or "")[:64], "completeness": "partial"}


def iam_escalation_verify(capture, *, engagement_slug: str = "iam", signers: "list | None" = None,
                          seq: int = 0) -> IamEscalationVerifyResult:
    """Route a retained IAM-escalation capture through oracle -> admission -> (on FACT) signed certificate.
    Returns an :class:`IamEscalationVerifyResult`; NEVER raises on a malformed capture (it is admitted as a
    LEAD/INCONCLUSIVE, never a FACT). A returned FACT carries a signed certificate whose retained
    ``oracle_context`` re-verifies offline (``verify.reverify``) and re-executes under the veracity firewall.

    No cloud call is ever made and no attack is performed — this is a pure re-derivation over an already-
    retained IAM policy capture (the FACT is a capability over the retained configuration)."""
    from framework.v2.verify.iam_escalation_capture import iam_escalation_capture_context  # noqa: PLC0415 (FATAL-2: fn-local)
    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (the ONLY sanctioned mint path)
    from .verdict import admit  # noqa: PLC0415 (pure stdlib module)

    signers = signers or []
    cap = capture if isinstance(capture, dict) else {}
    esc = cap.get("escalation") if isinstance(cap.get("escalation"), dict) else {}
    primitive = str(esc.get("primitive", "") or "").strip().lower() or "unknown"
    res = IamEscalationVerifyResult(primitive=primitive)

    oracle_context = iam_escalation_capture_context(cap)
    res.oracle_context = oracle_context
    finding = {
        "check_id": f"iam:{primitive}:privilege_escalation",
        "bug_class": "iam_escalation_primitive",
        "insertion_point": f"iam:{primitive}:base-principal",
        "oracle_context": oracle_context,
    }
    res.finding = finding

    fired, conclusive = _oracle_signal(oracle_context)
    observed = {"capture_wellformed": _capture_wellformed(cap)}
    admitted = admit(_BRANCH, fired=fired, conclusive=conclusive, observed=observed)
    res.admission = (_BRANCH, admitted.verdict.value, admitted.reason)
    res.verdict = admitted.verdict.value
    res.reason = admitted.reason

    out = certify_admitted(finding, admitted, engagement_slug=engagement_slug, signers=signers, seq=seq,
                           provenance="reproduced", binding=_binding(cap))
    res.finding_ref = out.finding_ref
    res.is_fact = out.is_fact
    if out.is_fact:
        res.certificate = out
    return res
