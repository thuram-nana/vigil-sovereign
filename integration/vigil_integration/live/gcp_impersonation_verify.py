"""gcp_impersonation_verify — VIGIL-owned admission / certification route for a GCP service-account
IMPERSONATION FACT (BUILD-PLAN §E3 — the PRODUCER for the E3 oracle, mirroring ``secret_verify`` for E5).

A WARDEN-gated impersonation runner (a follow-on slice) produces a RETAINED, secret-safe capture; this module
routes that capture through the deterministic ``gcp_sa_impersonation`` oracle, ADMITS it against the registered
``cloud_exploit.gcp.sa_impersonation`` evidence branch (``verdict.admit`` — a fired oracle over a fact-capable,
precondition-holding branch is a FACT, anything else a LEAD), and — on a FACT — mints the signed D2 certificate
via ``oracle_adapter.certify_admitted`` (the ONLY sanctioned mint path; a sovereign ``live/*`` module must
never call ``build_certificate``/``confirm_and_certify`` directly).

A confirmed FACT then re-verifies OFFLINE from its certificate (``verify.reverify`` re-fires the same oracle)
and its retained ``oracle_context`` re-executes under the veracity firewall — BOTH engage automatically (the
cert builder and the firewall are generic over any finding carrying an ``oracle_context``).

INERT on scan/engage: nothing on the scan/engage/benchmark path mints a ``gcp_sa_impersonation`` finding (the
oracle is kept OUT of the frozen ``_ALL_ORACLES`` fallback), so the capability fires ONLY when this producer is
called EXPLICITLY over a runner capture — preserving the no-auto-fire gate.

FATAL-2: every framework import is FUNCTION-LOCAL; at module scope this is pure stdlib only, so importing it
co-loads no offense engine (mirrors ``secret_verify`` / ``imds_verify``). The capture is SECRET-SAFE (the
minted token is redacted to a presence marker by ``FindingContext.from_gcp_impersonation_capture``), so the
certificate carries NO live token yet re-verifies offline. Real-transport LIVE-FIRE (running the impersonation
runner against real GCP endpoints) is deferred on an operator-provisioned credential.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# The registered GCP SA-impersonation evidence branch (docs/capability-matrix/evidence-branches.json).
# fact_capable (a minted token proven valid AS the target SA is an achieved-effect FACT); clean_capable:false
# (one confirming call cannot prove no impersonation path exists).
_BRANCH = "cloud_exploit.gcp.sa_impersonation"


@dataclass
class GcpImpersonationVerifyResult:
    """The outcome of routing ONE retained GCP SA-impersonation capture through oracle -> admission -> (on
    FACT) certificate."""

    target_sa: str
    verdict: str = "LEAD"                 # the admitted verdict value (FACT / LEAD / INCONCLUSIVE)
    is_fact: bool = False
    reason: str = ""
    finding_ref: str = ""
    finding: "dict | None" = None         # {check_id, bug_class, oracle_context} — the re-verifiable finding
    oracle_context: "dict | None" = None  # secret-safe; the retained proof reverify / the firewall re-fire
    certificate: Any = None               # the signed AdapterResult (None unless is_fact)
    admission: "tuple | None" = None      # (branch_id, verdict, reason) — the admission trail


def _oracle_signal(oracle_context: dict) -> "tuple[bool, bool]":
    """Run the deterministic E3 oracle over the retained ctx and return ``(fired, conclusive)`` WITHOUT
    minting. All framework imports are function-local (FATAL-2), exactly like ``secret_verify``."""
    from framework.v2.scanner.engine import probe_verdict  # noqa: PLC0415
    from framework.v2.verify.confirmation import adjudicate_finding, confirmed_from_result  # noqa: PLC0415
    from framework.v2.verify.verifier import OracleVerifier  # noqa: PLC0415

    verifier = OracleVerifier()
    finding = {"bug_class": "gcp_sa_impersonation", "oracle_context": oracle_context}
    result = adjudicate_finding(finding, oracle_context, verifier)
    fired = confirmed_from_result(result, finding, verifier) is not None
    verdict, _kinds = probe_verdict(result)
    conclusive = fired or verdict == "clean"
    return fired, conclusive


def _capture_wellformed(capture: Any) -> bool:
    """The branch precondition this producer can evaluate over the capture bytes ALONE: a dict carrying a
    mint object + a confirming_call. The ORACLE, not this, decides fired/conclusive — this only
    STRUCTURAL-gates so an unparseable / partial capture cannot be admitted as a FACT."""
    return (isinstance(capture, dict)
            and isinstance(capture.get("mint"), dict)
            and isinstance(capture.get("confirming_call"), dict))


def _target_of(cap: dict) -> str:
    """The named target SA (an identifier — an email / uid, never a secret), for the finding slug/evidence."""
    mint = cap.get("mint") if isinstance(cap.get("mint"), dict) else {}
    for obj in (mint, cap):
        for k in ("target_service_account", "target", "target_sa", "target_email"):
            v = obj.get(k)
            if v not in (None, ""):
                return str(v).strip()
    return "unknown"


def _binding(cap: dict) -> dict:
    """The D2 fields to bind into the signed cert (allowlist-filtered by oracle_adapter). Secret-safe: only
    capture-identity metadata + partial-completeness — NEVER a token value. The real tamper-evidence is the
    automatic ``oracle_context_digest`` binding over the retained (secret-safe) evidence."""
    return {"capture_method": "live_capture:gcp_sa_impersonation", "completeness": "partial"}


def gcp_impersonation_verify(capture, *, engagement_slug: str = "gcp-impersonation",
                             signers: "list | None" = None, seq: int = 0) -> GcpImpersonationVerifyResult:
    """Route a retained GCP SA-impersonation capture through oracle -> admission -> (on FACT) signed
    certificate. Returns a :class:`GcpImpersonationVerifyResult`; NEVER raises on a malformed capture (it is
    admitted as a LEAD/INCONCLUSIVE, never a FACT). A returned FACT carries a signed certificate whose retained
    ``oracle_context`` re-verifies offline (``verify.reverify``) and re-executes under the veracity firewall.

    No live mint/introspect call is ever made here — this is pure re-derivation over already-captured,
    WARDEN-gated, SECRET-SAFE evidence (the minted token is redacted to a presence marker)."""
    from framework.v2.verify.gcp_impersonation_capture import (  # noqa: PLC0415 (FATAL-2: fn-local)
        gcp_impersonation_capture_context,
    )
    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (the ONLY sanctioned mint path)
    from .verdict import admit  # noqa: PLC0415 (pure stdlib module)

    signers = signers or []
    cap = capture if isinstance(capture, dict) else {}
    target_sa = _target_of(cap)
    res = GcpImpersonationVerifyResult(target_sa=target_sa)

    oracle_context = gcp_impersonation_capture_context(cap)
    res.oracle_context = oracle_context
    finding = {
        "check_id": f"gcp:{target_sa}:sa_impersonation",
        "bug_class": "gcp_sa_impersonation",
        "insertion_point": f"gcp:{target_sa}:impersonation-token",
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
