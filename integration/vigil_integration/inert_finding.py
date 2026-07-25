"""
inert_finding — the sovereign side of the offense→personal data seam (FATAL-2).

A confirmed offensive finding crosses from env-offense to env-sovereign as INERT SIGNED DATA
only — never code, never a governance action. This module is what the sovereign side uses to
receive it, and it is deliberately importable in the offense-free env: it depends on
``vigil_core`` alone (the shared, sovereign-safe integrity core) and NEVER on ``framework.*``
(CRUCIBLE) or ``strix.*``. That is what lets the personal core stay offense-free-by-construction
(``sigil.reuse.assert_no_offense``) while still ingesting oracle-confirmed findings.

The inertness guarantee is structural: the inbound blob is parsed with ``json.loads`` ONLY —
never pickle/eval/yaml — so no code path can execute, whatever a compromised offense worker
sends. On top of that the envelope is size-bounded and strictly shaped, and the finding's
m-of-n CRUCIBLE-governance signature is verified with ``vigil_core.verify_threshold`` over the
exact same ``evidence_signing_bytes`` CRUCIBLE signed (anchor 1 of the two-anchor trust model;
the owner-signed spine head is anchor 2, added when the sovereign side appends the record).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from vigil_core import Signature, TrustRoot, evidence_signing_bytes, verify_threshold

SCHEMA = "vigil.inert-finding.v1"
MAX_ENVELOPE_BYTES = 256 * 1024  # a finding envelope larger than this is refused (DoS bound)

# The certificate identity fields the sovereign side requires. It does NOT re-impose the full schema —
# the certificate is opaque, signed DATA; the signature (not a local schema) is the integrity anchor.
# These just let the record be addressed/deduped on the spine. A FINDING (CRUCIBLE oracle, m-of-n
# governance-signed) uses finding_ref+oracle_context_digest; a DETECTION FACT (Detection Mirror,
# offense-spine-signed) uses oracle+evidence_digest_hex (S7c). Both cross the SAME inert seam.
_REQUIRED_CERT_FIELDS = ("finding_ref", "oracle_context_digest")
_DETECTION_REQUIRED_FIELDS = ("oracle", "evidence_digest_hex")

# Per-PROFILE top-level allowlists. The FINDING set is byte-identical to the pre-S7c seam (NO "kind" — a
# finding envelope carrying an unexpected "kind" is still rejected); DETECTION adds a REQUIRED "kind":"detection"
# so the two envelope shapes are structurally distinct and "kind" is authoritative, not decorative.
_FINDING_ALLOWED_TOP = {"schema", "certificate", "signatures"}
_DETECTION_ALLOWED_TOP = {"schema", "kind", "certificate", "signatures"}
_ALLOWED_SIG_KEYS = {"key_id", "signature_b64"}


class InertFindingError(ValueError):
    """The inbound blob is not a valid, inert finding envelope. Always fail closed."""


def _reject(msg: str) -> "None":
    raise InertFindingError(msg)


@dataclass(frozen=True)
class ValidatedFinding:
    """A structurally-validated, inert finding envelope, ready to verify + append."""

    certificate: dict
    signatures: tuple[dict, ...]
    raw: dict

    @property
    def finding_ref(self) -> str:
        return str(self.certificate.get("finding_ref", ""))

    @property
    def oracle_context_digest(self) -> str:
        return str(self.certificate.get("oracle_context_digest", ""))

    @property
    def engagement_slug(self) -> str:
        """The engagement scope the finding declares in its own SIGNED certificate. Empty string if the
        cert omits it. The sovereign receiver binds this to the owner-delegated scope so a delegation for
        one engagement cannot launder findings under another engagement's label (S4)."""
        return str(self.certificate.get("engagement_slug", ""))

    def verify_signature(self, trust_root: TrustRoot) -> bool:
        """True iff the CRUCIBLE governance root's m-of-n threshold signed this certificate.

        Anchor 1 of the two-anchor model. Uses ONLY vigil_core — no ``framework`` import — over
        the exact bytes CRUCIBLE signed: ``evidence_signing_bytes(certificate)``. A finding whose
        signature does not satisfy the trust root must NOT be treated as a confirmed fact.
        """
        sigs = [Signature(key_id=s["key_id"], signature_b64=s["signature_b64"]) for s in self.signatures]
        return verify_threshold(evidence_signing_bytes(self.certificate), sigs, trust_root).satisfied

    def to_spine_payload(self) -> dict:
        """The inert payload for ``spine.append(kind="finding", ...)`` on the sovereign side.

        Pure JSON types only. The actual append (with the owner-signed head as anchor 2) is the
        sovereign side's job (P10); this is the vetted datum it appends.
        """
        return {
            "schema": SCHEMA,
            "finding_ref": self.finding_ref,
            "oracle_context_digest": self.oracle_context_digest,
            "certificate": self.certificate,
            "signatures": [dict(s) for s in self.signatures],
        }


@dataclass(frozen=True)
class ValidatedDetection:
    """A structurally-validated, inert DETECTION-FACT envelope (S7c), ready to verify + append. Same seam and
    same anchor-1 verify as a finding — the certificate is opaque signed DATA — but its identity fields are
    the Detection Mirror's (``oracle`` + ``evidence_digest_hex``) and its anchor-1 signer is the owner-
    delegated OFFENSE-SPINE identity (the Detection PCF signer), not the m-of-n governance authority."""

    certificate: dict
    signatures: tuple[dict, ...]
    raw: dict

    @property
    def oracle(self) -> str:
        return str(self.certificate.get("oracle", ""))

    @property
    def evidence_digest_hex(self) -> str:
        return str(self.certificate.get("evidence_digest_hex", ""))

    @property
    def bug_class(self) -> str:
        return str(self.certificate.get("bug_class", ""))

    @property
    def engagement_slug(self) -> str:
        """The engagement scope the detection FACT declares in its own SIGNED certificate (empty if absent).
        Bound to the owner-delegated scope by the receiver, exactly like a finding (S4/S7b)."""
        return str(self.certificate.get("engagement_slug", ""))

    def verify_signature(self, trust_root: TrustRoot) -> bool:
        """True iff the owner-delegated OFFENSE-SPINE root signed this certificate — the SAME anchor-1 check
        (``verify_threshold`` over ``evidence_signing_bytes(certificate)``, vigil_core only) as a finding; only
        the trust root differs (the delegated spine key, not the governance m-of-n)."""
        sigs = [Signature(key_id=s["key_id"], signature_b64=s["signature_b64"]) for s in self.signatures]
        return verify_threshold(evidence_signing_bytes(self.certificate), sigs, trust_root).satisfied

    def to_spine_payload(self) -> dict:
        """The inert payload for ``spine.append(kind="detection", ...)`` on the sovereign side."""
        return {
            "schema": SCHEMA,
            "oracle": self.oracle,
            "evidence_digest_hex": self.evidence_digest_hex,
            "bug_class": self.bug_class,
            "certificate": self.certificate,
            "signatures": [dict(s) for s in self.signatures],
        }


def validate_inert_finding(blob: "str | bytes") -> ValidatedFinding:
    """Parse + validate an inbound FINDING envelope as INERT DATA (CRUCIBLE oracle; m-of-n governance-signed).
    Fail-closed on anything off. See :func:`_parse_envelope` for the guarantees."""
    cert, sigs, env = _parse_envelope(blob, required_fields=_REQUIRED_CERT_FIELDS,
                                      allowed_top=_FINDING_ALLOWED_TOP)
    return ValidatedFinding(certificate=cert, signatures=sigs, raw=env)


def validate_inert_detection(blob: "str | bytes") -> "ValidatedDetection":
    """Parse + validate an inbound DETECTION-FACT envelope as INERT DATA (Detection Mirror; offense-spine-
    signed, S7c). Same seam, same fail-closed guarantees — the required certificate fields differ
    (``oracle``+``evidence_digest_hex`` vs a finding's ``finding_ref``+``oracle_context_digest``) AND a
    ``kind:"detection"`` top-level tag is REQUIRED, so a finding envelope can never be mis-parsed as a detection."""
    cert, sigs, env = _parse_envelope(blob, required_fields=_DETECTION_REQUIRED_FIELDS,
                                      allowed_top=_DETECTION_ALLOWED_TOP, expect_kind="detection")
    return ValidatedDetection(certificate=cert, signatures=sigs, raw=env)


def _parse_envelope(blob: "str | bytes", *, required_fields: "tuple[str, ...]",
                    allowed_top: "set[str]", expect_kind: "str | None" = None) -> "tuple[dict, tuple[dict, ...], dict]":
    """Parse + validate an inbound inert envelope; return ``(certificate, signatures, raw)``. Fail-closed.

    Guarantees on success: the input was decoded as UTF-8 and parsed with ``json.loads`` only (no code can
    execute), was within the size bound, and is a JSON object with ONLY the ``allowed_top`` keys (per profile —
    findings forbid "kind", detections require ``kind == expect_kind``), a certificate object carrying the
    non-empty string ``required_fields``, and a non-empty list of ``{key_id, signature_b64}`` string signatures.
    """
    # A non-(str|bytes) input (e.g. someone passing a live/pickled object) is refused outright.
    if isinstance(blob, (bytes, bytearray)):
        if len(blob) > MAX_ENVELOPE_BYTES:
            _reject(f"envelope exceeds {MAX_ENVELOPE_BYTES} bytes")
        try:
            text = bytes(blob).decode("utf-8")
        except UnicodeDecodeError as e:
            _reject(f"envelope is not valid utf-8: {e}")
    elif isinstance(blob, str):
        if len(blob.encode("utf-8")) > MAX_ENVELOPE_BYTES:
            _reject(f"envelope exceeds {MAX_ENVELOPE_BYTES} bytes")
        text = blob
    else:
        _reject(f"envelope must be str or bytes, got {type(blob).__name__}")

    try:
        env = json.loads(text)  # JSON ONLY — never pickle/eval; the inertness guarantee
    except (json.JSONDecodeError, ValueError) as e:
        _reject(f"envelope is not valid JSON: {e}")
    except RecursionError:
        # a deeply-nested blob is a DoS attempt, not a finding — fail closed, don't propagate
        _reject("envelope nesting is too deep")

    if not isinstance(env, dict):
        _reject("envelope must be a JSON object")
    extra = set(env) - allowed_top
    if extra:
        _reject(f"unexpected top-level keys: {sorted(extra)}")
    if expect_kind is not None and env.get("kind") != expect_kind:
        _reject(f"kind must be {expect_kind!r}, got {env.get('kind')!r}")
    if env.get("schema") != SCHEMA:
        _reject(f"schema must be {SCHEMA!r}, got {env.get('schema')!r}")

    cert = env.get("certificate")
    if not isinstance(cert, dict):
        _reject("certificate must be a JSON object")
    for fld in required_fields:
        val = cert.get(fld)
        if not isinstance(val, str) or not val:
            _reject(f"certificate.{fld} must be a non-empty string")

    sigs = env.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        _reject("signatures must be a non-empty list")
    norm: list[dict] = []
    for i, s in enumerate(sigs):
        if not isinstance(s, dict):
            _reject(f"signatures[{i}] must be an object")
        if set(s) - _ALLOWED_SIG_KEYS:
            _reject(f"signatures[{i}] has unexpected keys: {sorted(set(s) - _ALLOWED_SIG_KEYS)}")
        if not isinstance(s.get("key_id"), str) or not isinstance(s.get("signature_b64"), str):
            _reject(f"signatures[{i}] key_id and signature_b64 must both be strings")
        norm.append({"key_id": s["key_id"], "signature_b64": s["signature_b64"]})

    return cert, tuple(norm), env


def build_envelope(certificate: dict, signatures: "list[dict]") -> str:
    """Build the inert JSON envelope from a plain certificate dict + signature dicts.

    Sovereign-safe (no ``framework`` import); the offense worker calls this after serialising its
    ``SignedEvidence`` with ``model_dump(mode="json")`` so the sovereign receiver can re-derive
    ``evidence_signing_bytes`` byte-identically and verify the m-of-n signature.
    """
    env = {
        "schema": SCHEMA,
        "certificate": certificate,
        "signatures": [
            {"key_id": s["key_id"], "signature_b64": s["signature_b64"]} for s in signatures
        ],
    }
    return json.dumps(env, ensure_ascii=False, sort_keys=True)


def build_detection_envelope(certificate: dict, signatures: "list[dict]") -> str:
    """Build the inert JSON envelope for a DETECTION FACT (S7c). Identical shape to a finding envelope plus a
    self-describing ``kind="detection"``; ``certificate`` is the DetectionCertificate's ``signing_payload()``
    (the signed bytes) so the sovereign receiver re-derives ``evidence_signing_bytes`` byte-identically and
    verifies the offense-spine signature. Sovereign-safe (no ``framework`` import)."""
    env = {
        "schema": SCHEMA,
        "kind": "detection",
        "certificate": certificate,
        "signatures": [
            {"key_id": s["key_id"], "signature_b64": s["signature_b64"]} for s in signatures
        ],
    }
    return json.dumps(env, ensure_ascii=False, sort_keys=True)
