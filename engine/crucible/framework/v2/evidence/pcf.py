"""evidence.pcf — Proof-Carrying Findings (PCF v0.1) over CRUCIBLE's real evidence layer.

PCF (`AEGIS-CRUCIBLE-package/publications/PCF-spec-v0.1.md`) is an open standard: a certificate that lets
any party re-establish a finding's truth OFFLINE by re-running a deterministic oracle over retained evidence
and getting the same verdict. CRUCIBLE's signed `EvidenceCertificate` already implements the *substance* of
this. This module is the thin bridge:

  * :func:`to_pcf` PROJECTS an existing ``SignedEvidence`` into the PCF v0.1 JSON wire format — reusing the
    certificate's own signed fields, materialising the derived PCF members (``id``, ``verdict.fired``,
    ``claim.vocabulary``, the evidence digest-set, ``oracle.binding``), and EMBEDDING the authoritative signed
    certificate (the object CRUCIBLE's signature actually covers) plus the retained ``oracle_context`` value
    (so the certificate is re-runnable, PCF §4.5 "complete").
  * :func:`verify_pcf` runs PCF §6's five ordered, fail-closed steps — each DELEGATING to a real primitive,
    never a reimplementation: (1) schema+vocabulary via ``require_known_bug_class``; (2) the m-of-n Ed25519
    signature over the domain-separated signed bytes via ``verify_threshold`` (+ a consistency check that the
    PCF view cannot misrepresent the signed certificate); (3) evidence-digest integrity; (4) oracle
    reproduction via ``verify.reverify.reverify_context`` PLUS the oracle ``id@version`` staleness check
    (``verify.oracle_version``); (5) claim-grounded via ``verify.verifier.oracle_confirms_class``.

Fail-closed: any tamper, an out-of-vocabulary class, a stale oracle version, or an absent/insufficient trust
root rejects. Pure + deterministic; no wall-clock, no network. This lives beside the rest of ``evidence/``,
off the ``make gate`` path.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from .canonical import digest_payload, evidence_signing_bytes
from .models import EvidenceCertificate, SignedEvidence

PCF_VERSION = "0.1"
PCF_VOCABULARY = "pcf-classes/1"
_SIG_DOMAIN = "crucible-evidence-v1"   # the label in evidence.canonical._EVIDENCE_DOMAIN

_REQUIRED_MEMBERS = ("pcf_version", "id", "claim", "subject", "evidence", "oracle",
                     "verdict", "provenance", "grounding", "signature")


def pcf_vocabulary() -> dict[str, Any]:
    """The controlled, versioned vocabulary a PCF certificate's ``claim.class`` is drawn from — the oracle-
    provable bug classes the substrate knows. Pinned by ``PCF_VOCABULARY`` so a class's meaning is fixed at
    issue time."""
    from ..verify.verifier import known_bug_classes
    return {"version": PCF_VOCABULARY, "classes": sorted(known_bug_classes())}


# The collecting authority for a certificate the evidence layer emits. FIXED (not a caller argument) so it
# is re-derivable from the signed certificate alone and thus authenticated by the view-consistency check —
# an unbound free field is a lying-wrapper hole (per-sensor collector identity, if ever needed, is bound
# into the certificate, never passed unsigned to the projector).
_COLLECTED_BY = "crucible/evidence"


def _project_view(cert: EvidenceCertificate, oracle_context: dict[str, Any]) -> dict[str, Any]:
    """The cert-DERIVED PCF fields — EVERYTHING the signature authenticates — WITHOUT the signature block or
    the embedded certificate. :func:`to_pcf` adds those; :func:`verify_pcf` RE-DERIVES this from the
    reconstructed certificate and compares the presented view against it field-for-field, so no PCF view
    field (claim.statement, grounding, subject.context, oracle.binding, artifact entries, …) can be mutated
    into a lying wrapper. Every field here is a pure function of the signed certificate (grounding is always
    FACT — an EvidenceCertificate exists only for a confirmed finding — and collected_by is fixed)."""
    from ..verify.verifier import canonical_oracle_for
    # Evidence digest-set (PCF §4.5): the oracle_context is ONE evidence item (bound by the signed
    # oracle_context_digest); each raw artifact is another item (per-file digested + signed). The
    # oracle_context VALUE is carried so a verifier can re-run the oracle (PCF "complete").
    evidence_items: dict[str, Any] = {
        "oracle_context": {"digest": cert.oracle_context_digest, "value": dict(oracle_context)},
    }
    for a in cert.artifacts:
        evidence_items[a.path] = {"digest": f"sha256:{a.sha256}", "size": a.size, "by_reference": True}
    canonical = canonical_oracle_for(cert.bug_class)
    statement = (cert.report_claims[0].sentence if cert.report_claims
                 else f"{cert.bug_class or 'finding'} confirmed by {cert.confirmed_by or 'oracle'}")
    return {
        "pcf_version": PCF_VERSION,
        "id": cert.cert_digest,
        "claim": {"class": cert.bug_class, "vocabulary": PCF_VOCABULARY, "statement": statement},
        "subject": {"identifier": cert.finding_ref,
                    "context": {"surface": cert.surface, "engagement": cert.engagement_slug}},
        "evidence": evidence_items,
        "oracle": {"id": cert.confirmed_by, "version": cert.oracle_version,
                   "binding": f"crucible/verify:{canonical.value if canonical else cert.confirmed_by}"},
        "verdict": {"fired": True, "confidence": cert.confidence},
        "provenance": {"collected_by": _COLLECTED_BY, "sequence": cert.seq},
        "grounding": "FACT",
    }


def to_pcf(signed: SignedEvidence, *, oracle_context: dict[str, Any]) -> dict[str, Any]:
    """Project a signed ``EvidenceCertificate`` into the PCF v0.1 wire format. ``oracle_context`` is the
    retained evidence the oracle re-runs over (its digest must equal the cert's ``oracle_context_digest``;
    :func:`verify_pcf` re-checks). A CRUCIBLE ``EvidenceCertificate`` exists only for a CONFIRMED finding, so
    the projection is a FACT (``verdict.fired`` True). The view is a pure projection of the signed cert (see
    :func:`_project_view`) plus the signature and the authoritative embedded certificate."""
    cert = signed.certificate
    view = _project_view(cert, oracle_context)
    view["signature"] = {"scheme": "ed25519", "domain": _SIG_DOMAIN,
                         "signatures": [{"key_id": s.key_id, "sig": s.signature_b64} for s in signed.signatures]}
    # The authoritative signed object: CRUCIBLE's signature covers exactly this certificate's canonical
    # bytes. verify_pcf reconstructs it, re-derives the signed bytes + the view above, and rejects any drift.
    view["_crucible"] = {"certificate": cert.model_dump(mode="json")}
    return view


class PcfVerification(BaseModel):
    """A PCF verification verdict: ``verified`` iff all five steps passed; else the failing ``step`` +
    ``reason`` (PCF §6 requires the failing step be reportable)."""

    model_config = ConfigDict(extra="forbid")
    verified: bool
    step: str = ""
    reason: str = ""


def _reject(step: str, reason: str) -> PcfVerification:
    return PcfVerification(verified=False, step=step, reason=reason)


def verify_pcf(pcf_cert: Any, trust_root: Any, *, evidence_root: Any = None) -> PcfVerification:
    """PCF §6's five ordered, fail-closed steps over the real primitives. Never raises — a malformed
    certificate is a rejection, not a crash. Rejects fail-closed when ``trust_root`` is absent (ungoverned)."""
    if not isinstance(pcf_cert, dict):
        return _reject("schema", "certificate is not an object")

    # 1. SCHEMA + VOCABULARY -------------------------------------------------------------------------
    for m in _REQUIRED_MEMBERS:
        if m not in pcf_cert:
            return _reject("schema", f"missing required member {m!r}")
    if pcf_cert.get("pcf_version") != PCF_VERSION:
        return _reject("schema", f"unsupported pcf_version {pcf_cert.get('pcf_version')!r}")
    # type-guard every structured member so a malformed certificate is a REJECTION, never a crash.
    for m in ("claim", "subject", "evidence", "oracle", "verdict", "provenance", "signature"):
        if not isinstance(pcf_cert.get(m), dict):
            return _reject("schema", f"member {m!r} must be an object")
    claim = pcf_cert["claim"]
    if claim.get("vocabulary") != PCF_VOCABULARY:
        return _reject("vocabulary", f"unknown vocabulary {claim.get('vocabulary')!r}")
    from ..verify.verifier import oracle_confirms_class, require_known_bug_class
    try:
        require_known_bug_class(str(claim.get("class", "")))
    except ValueError as e:
        return _reject("vocabulary", str(e))

    # Reconstruct the authoritative signed certificate the PCF view projects.
    try:
        cert = EvidenceCertificate.model_validate((pcf_cert.get("_crucible") or {}).get("certificate"))
    except Exception as e:
        return _reject("schema", f"embedded certificate did not parse: {type(e).__name__}")

    # 2. SIGNATURE (over the domain-separated signed bytes, m-of-n) -----------------------------------
    if trust_root is None:
        return _reject("signature", "no trust root provisioned (ungoverned) — fail-closed")
    from ..entitlement.crypto import verify_threshold
    from ..entitlement.models import Signature
    sig_block = pcf_cert["signature"]
    raw_sigs = sig_block.get("signatures")
    if not isinstance(raw_sigs, list):
        return _reject("signature", "signature.signatures must be a list")
    try:
        sigs = [Signature(key_id=s["key_id"], signature_b64=s["sig"]) for s in raw_sigs]
    except Exception:
        return _reject("signature", "malformed signature entry")
    thr = verify_threshold(evidence_signing_bytes(cert.model_dump(mode="json")), sigs, trust_root)
    if not thr.satisfied:
        return _reject("signature", f"threshold not met ({thr.reason})")
    # PCF requires a fact to name oracle.version (else the exact-procedure guarantee is unmet).
    if not cert.oracle_version:
        return _reject("schema", "oracle.version is required for a FACT certificate")
    # 2b. FAITHFUL PROJECTION — the presented view MUST equal the view RE-DERIVED from the signed cert,
    # field-for-field (no lying wrapper). Compare every authenticated field except the oracle_context VALUE
    # (authenticated separately by its digest in step 3) — its digest, and all other view fields, must match.
    oc = (pcf_cert["evidence"].get("oracle_context") or {})
    oc_value = oc.get("value")
    expected = _project_view(cert, oc_value if isinstance(oc_value, dict) else {})

    def _without_context_value(view: dict[str, Any]) -> dict[str, Any]:
        import copy as _copy
        v = _copy.deepcopy(view)
        ev = v.get("evidence")
        if isinstance(ev, dict) and isinstance(ev.get("oracle_context"), dict):
            ev["oracle_context"].pop("value", None)
        return v

    presented_view = {k: pcf_cert.get(k) for k in expected}   # only the authenticated (cert-derived) keys
    if _without_context_value(presented_view) != _without_context_value(expected):
        return _reject("signature", "PCF view is not a faithful projection of the signed certificate "
                                    "(a field was mutated)")

    # 3. EVIDENCE INTEGRITY (recompute the retained-context digest; artifacts under the evidence root) --
    oc = oc_value
    if not isinstance(oc, dict):
        return _reject("evidence", "evidence.oracle_context.value missing — certificate is not re-runnable")
    if digest_payload(oc) != cert.oracle_context_digest:
        return _reject("evidence", "oracle_context digest mismatch — evidence altered")
    if cert.artifacts:
        if evidence_root is None:
            return _reject("evidence", "artifacts claimed but no evidence root to re-check — fail-closed")
        from pathlib import Path

        from .manifest import verify_manifest
        if any(not r.ok for r in verify_manifest(cert.artifacts, root=Path(evidence_root))):
            return _reject("evidence", "an artifact failed its digest/manifest check")

    # 4. ORACLE REPRODUCTION (re-run the pure oracle offline) + id@version staleness -------------------
    from ..verify.oracle_version import oracle_version as _oracle_version
    from ..verify.reverify import reverify_context
    rr = reverify_context(oc, bug_class=cert.bug_class, claimed_confirmed_by=cert.confirmed_by,
                          claimed_confidence=cert.confidence, ref=cert.finding_ref)
    if not rr.ok:
        return _reject("oracle", f"oracle did not reproduce the verdict ({rr.note or 'no re-fire'})")
    current = _oracle_version(cert.confirmed_by)
    if not current:
        return _reject("oracle", f"cannot resolve current version for oracle {cert.confirmed_by!r}")
    if cert.oracle_version != current:
        return _reject("oracle", "oracle version mismatch — the oracle body changed since this certificate "
                                 "was issued; re-verification would use a different procedure")

    # 5. CLAIM-GROUNDED (the fired oracle is a valid confirmer for the claimed class) ------------------
    if not oracle_confirms_class(cert.confirmed_by, cert.bug_class):
        return _reject("claim", f"oracle {cert.confirmed_by!r} is not a confirmer for class "
                                f"{cert.bug_class!r} — claim not grounded")

    return PcfVerification(verified=True, step="all", reason="all five PCF steps passed")
