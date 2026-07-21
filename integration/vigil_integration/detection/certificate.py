"""
detection.certificate — the signed, offline-re-verifiable PCF detection certificate.

Every FACT-grade detection is minted as a :class:`DetectionCertificate`: the retained telemetry evidence
(redacted), the oracle that fired, the signature family, the verdict, and an Ed25519 signature over the
canonical payload. It is the defensive mirror of CRUCIBLE's evidence certificate — an analyst RE-RUNS it
instead of trusting it.

Sovereign properties (the red-pen attacks exactly these):

  * **Signed via the shared seam.** The signing bytes are the vigil_core domain-tagged canonical JSON
    (``evidence_signing_bytes``) of the payload MINUS the signature — byte-identical for signer and
    verifier, so any tamper (evidence, verdict, oracle) breaks the signature. Signing is done by an
    INJECTED signer (``Callable[[bytes], str]``); verification is ``vigil_core.crypto.verify_one``.
  * **Secret-free.** Evidence lines are scrubbed through the ONE F3 free-string redactor
    (``mcp_registry._redact_str``) BEFORE they enter the certificate, so no credential lands on the spine.
  * **Content-addressed.** ``cert_id`` is the sha256 of the signing bytes — a stable id used as the
    ``Finding.evidence_ref`` (the type-level FACT requirement).
  * **Deterministic.** No wallclock/RNG here; ``seq`` is injected. The same evidence + oracle + seq +
    signer produce a byte-identical certificate.

Re-verification (signature + evidence-digest + a live RE-RUN of the oracle) lives in ``detection.base``
so it can resolve the oracle to re-execute — this module owns the model + crypto only, staying free of any
oracle import (no cycle).

Import-clean: pydantic + stdlib + vigil_core.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from pydantic import BaseModel, Field

from vigil_core import digest_payload, evidence_signing_bytes, sha256_hex, verify_one

from ..tools.mcp_registry import _redact_str

# A signer maps the canonical certificate bytes → a base64 Ed25519 signature. Fail-closed: returning a
# non-str/empty value or raising means NO certificate is minted (the caller falls back to a LEAD).
CertSigner = Callable[[bytes], str]


def redact_evidence(lines: Any) -> list[str]:
    """Scrub a list of raw log lines through the single F3 free-string redactor before they enter a
    signed certificate. Total: a non-iterable / non-str element degrades to ``""``; never raises."""
    if not isinstance(lines, (list, tuple)):
        return []
    out: list[str] = []
    for ln in lines:
        try:
            out.append(_redact_str(ln) if isinstance(ln, str) else "")
        except Exception:  # noqa: BLE001 — redaction must never crash certificate minting
            out.append("")
    return out


def evidence_digest(evidence: Any) -> str:
    """The canonical sha256 digest of the (already-redacted) evidence list. Deterministic + total."""
    lines = list(evidence) if isinstance(evidence, (list, tuple)) else []
    return digest_payload([str(x) for x in lines])


class DetectionCertificate(BaseModel):
    """A proof-carrying detection certificate. Everything a verifier needs to re-prove the detection
    OFFLINE: the oracle id, the signature family, the verdict, the redacted evidence + its digest, the
    reproduction params, the injected ``seq``, the signer ``key_id``, and the Ed25519 ``signature``."""

    oracle: str
    verdict: str = "fact"          # a certificate is only ever minted for a FACT-grade fire
    signature_kind: str = ""       # the fired signature family (e.g. "sql-tautology")
    bug_class: str = ""
    severity: str = ""
    evidence_kind: str = ""        # "access_log" | "auth_log" | "conn_log"
    evidence: list[str] = Field(default_factory=list)   # redacted raw telemetry lines (the proof)
    evidence_digest_hex: str = ""
    summary: str = ""
    source: str = ""               # the firing source (IP) when applicable — provenance only
    params: dict[str, Any] = Field(default_factory=dict)  # thresholds/axis used → exact reproduction
    seq: int = 0
    key_id: str = ""
    signature: str = ""

    def signing_payload(self) -> dict:
        """The exact dict that is signed/verified: the model MINUS the signature field."""
        d = self.model_dump(mode="json")
        d.pop("signature", None)
        return d

    def signing_bytes(self) -> bytes:
        """Domain-tagged canonical bytes (reuses the vigil_core evidence-signing seam)."""
        return evidence_signing_bytes(self.signing_payload())

    @property
    def cert_id(self) -> str:
        """Stable content id (sha256 of the signing bytes) — the ``Finding.evidence_ref``."""
        return sha256_hex(self.signing_bytes())


def build_certificate(
    *,
    oracle: str,
    signature_kind: str,
    bug_class: str,
    severity: str,
    evidence_kind: str,
    evidence_lines: Any,
    summary: str,
    source: str = "",
    params: Optional[dict] = None,
    seq: int = 0,
) -> DetectionCertificate:
    """Assemble an UNSIGNED certificate over redacted evidence. Pure/deterministic; the evidence is
    scrubbed and digested here so the digest always matches what a verifier recomputes."""
    ev = redact_evidence(evidence_lines)
    return DetectionCertificate(
        oracle=str(oracle), verdict="fact", signature_kind=str(signature_kind),
        bug_class=str(bug_class), severity=str(severity), evidence_kind=str(evidence_kind),
        evidence=ev, evidence_digest_hex=evidence_digest(ev),
        summary=_redact_str(str(summary)), source=str(source),
        params=dict(params or {}), seq=int(seq),
    )


def sign_certificate(
    cert: DetectionCertificate, signer: Optional[CertSigner], *, key_id: str = "",
) -> Optional[DetectionCertificate]:
    """Sign a certificate with the INJECTED signer. FAIL-CLOSED: no signer wired, a signer that raises,
    or a non-str/blank signature → ``None`` (the caller degrades to a LEAD). Returns a NEW, frozen-in-
    intent signed certificate (append-only; the unsigned input is never mutated)."""
    if not callable(signer):
        return None
    stamped = cert.model_copy(update={"key_id": str(key_id)})
    try:
        sig = signer(stamped.signing_bytes())
    except Exception:  # noqa: BLE001 — any signer error mints no certificate (fail-closed)
        return None
    if not isinstance(sig, str) or not sig.strip():
        return None
    return stamped.model_copy(update={"signature": sig})


def verify_certificate_signature(cert: Any, public_key_b64: object) -> bool:
    """True iff ``cert`` carries a valid Ed25519 signature over its canonical payload under
    ``public_key_b64``. Total/fail-closed: a non-certificate, a missing signature, malformed key
    material, or any error → False (never a false-positive verify, never a raise)."""
    if not isinstance(cert, DetectionCertificate):
        return False
    if not isinstance(public_key_b64, str) or not public_key_b64.strip():
        return False
    if not (cert.signature or "").strip():
        return False
    try:
        return verify_one(public_key_b64, cert.signing_bytes(), cert.signature)
    except Exception:  # noqa: BLE001 — malformed key/sig material verifies nothing
        return False
