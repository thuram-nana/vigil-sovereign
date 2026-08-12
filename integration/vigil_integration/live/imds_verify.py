"""imds_verify — VIGIL-owned admission / certification route for an IMDS/metadata credential-capture FACT
(BUILD-PLAN §E1, E1-Slice3 — the PRODUCER the E1 oracle was missing).

The WARDEN-A2- + D5-scope-gated runner (``imds_runner.run_imds_capture``) produces a RETAINED, secret-safe
capture; this module routes that capture through the deterministic ``imds_credential_capture`` oracle, ADMITS
it against the registered ``cloud_exploit.imds.credential_capture`` evidence branch (``verdict.admit`` — a
fired oracle over a fact-capable, precondition-holding branch is a FACT, anything else a LEAD), and — on a
FACT — mints the signed D2 certificate via ``oracle_adapter.certify_admitted`` (the ONLY sanctioned mint
path; a sovereign ``live/*`` module must never call ``build_certificate``/``confirm_and_certify`` directly).

A confirmed FACT then re-verifies OFFLINE from its certificate (``verify.reverify`` re-fires the same oracle)
and its retained ``oracle_context`` re-executes under the veracity firewall — BOTH engage automatically
because the cert builder and the firewall are generic over any finding carrying an ``oracle_context``; no
change to those layers is needed.

INERT on scan/engage: nothing on the scan/engage/benchmark path mints an ``imds_credential_capture`` finding
(the oracle is deliberately kept OUT of the frozen ``_ALL_ORACLES`` fallback), so the capability fires ONLY
when this producer is called EXPLICITLY over a runner capture — preserving the no-auto-fire gate.

FATAL-2: every framework import is FUNCTION-LOCAL; at module scope this is pure stdlib only, so importing it
co-loads no offense engine (mirrors ``cloud_live_posture``). LIVE-FIRE (the real runner transport against an
authorized lab metadata endpoint) is deferred on an operator-provisioned credential; this module + its
fixtures are the offline, credential-free half.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# The registered LIVE-capture evidence branch (docs/capability-matrix/evidence-branches.json). fact_capable
# (a metadata credential retrieved AND authenticated is an achieved-effect FACT), clean_capable:false (one
# capture cannot prove no capturable credential exists).
_BRANCH = "cloud_exploit.imds.credential_capture"


@dataclass
class IMDSVerifyResult:
    """The outcome of routing ONE retained IMDS capture through oracle → admission → (on FACT) certificate."""

    provider: str
    verdict: str = "LEAD"                 # the admitted verdict value (FACT / LEAD / INCONCLUSIVE)
    is_fact: bool = False
    reason: str = ""
    finding_ref: str = ""
    finding: "dict | None" = None         # {check_id, bug_class, oracle_context} — the re-verifiable finding
    oracle_context: "dict | None" = None  # secret-safe; the retained proof reverify / the firewall re-fire
    certificate: Any = None               # the signed AdapterResult (None unless is_fact)
    admission: "tuple | None" = None      # (branch_id, verdict, reason) — the admission trail


def _oracle_signal(oracle_context: dict) -> "tuple[bool, bool]":
    """Run the deterministic IMDS oracle over the retained ctx and return ``(fired, conclusive)`` WITHOUT
    minting. All framework imports are function-local (FATAL-2), exactly like ``cloud_live_posture``."""
    from framework.v2.scanner.engine import probe_verdict  # noqa: PLC0415
    from framework.v2.verify.confirmation import adjudicate_finding, confirmed_from_result  # noqa: PLC0415
    from framework.v2.verify.verifier import OracleVerifier  # noqa: PLC0415

    verifier = OracleVerifier()
    finding = {"bug_class": "imds_credential_capture", "oracle_context": oracle_context}
    result = adjudicate_finding(finding, oracle_context, verifier)
    fired = confirmed_from_result(result, finding, verifier) is not None
    verdict, _kinds = probe_verdict(result)
    conclusive = fired or verdict == "clean"
    return fired, conclusive


def _capture_wellformed(capture: Any) -> bool:
    """The branch precondition this producer can evaluate over the capture bytes ALONE: a dict carrying the
    two evidence halves. The ORACLE, not this, decides fired/conclusive — this only STRUCTURAL-gates so an
    unparseable/partial capture cannot be admitted as a FACT (a missing precondition ⇒ never a FACT)."""
    return (isinstance(capture, dict)
            and isinstance(capture.get("credential"), dict)
            and isinstance(capture.get("confirming_call"), dict))


def _binding(cap: dict) -> dict:
    """The D2 fields to bind into the signed cert (allowlist-filtered by oracle_adapter). Secret-safe: only
    capture-identity metadata + partial-completeness — NEVER a secret value. The real tamper-evidence is the
    automatic ``oracle_context_digest`` binding over the retained (secret-safe) evidence."""
    return {"capture_method": "live_capture:imds", "completeness": "partial"}


def imds_verify(capture, *, engagement_slug: str = "imds", signers: "list | None" = None,
                seq: int = 0) -> IMDSVerifyResult:
    """Route a retained IMDS/metadata credential-capture through oracle → admission → (on FACT) signed
    certificate. Returns an :class:`IMDSVerifyResult`; NEVER raises on a malformed capture (it is admitted as
    a LEAD/INCONCLUSIVE, never a FACT). A returned FACT carries a signed certificate whose retained
    ``oracle_context`` re-verifies offline (``verify.reverify``) and re-executes under the veracity firewall.

    ``signers`` are governance (key_id, private_key_b64) pairs (empty ⇒ no signed cert, still a typed
    verdict). No live IMDS/STS call is ever made here — this is pure re-derivation over already-captured,
    WARDEN-gated evidence."""
    from framework.v2.verify.imds_capture import imds_capture_context  # noqa: PLC0415 (FATAL-2: fn-local)
    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (the ONLY sanctioned mint path)
    from .verdict import admit  # noqa: PLC0415 (pure stdlib module)

    signers = signers or []
    cap = capture if isinstance(capture, dict) else {}
    provider = str(cap.get("provider", "") or "") or "unknown"
    res = IMDSVerifyResult(provider=provider)

    oracle_context = imds_capture_context(cap)
    res.oracle_context = oracle_context
    finding = {
        "check_id": f"imds:{provider}:credential_capture",
        "bug_class": "imds_credential_capture",
        "insertion_point": f"imds:{provider}:metadata-endpoint",
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
