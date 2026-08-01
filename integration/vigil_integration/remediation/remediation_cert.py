"""remediation.remediation_cert — the portable, offline-verifiable REMEDIATION CERTIFICATE (VIGIL VF-1a).

This is the *negative* proof-carrying artifact: it certifies that the ORIGINAL exploit oracle went SILENT over
the patched build's re-captured bytes — i.e. "the exploit that provably worked is now provably dead." It is the
mirror of the positive proof-carrying finding, and it is verified the SAME way: by re-execution, offline, with
no target and no trust in the tool that produced it.

Soundness reuses ``fix_oracle`` end-to-end — a remediation is EARNED by oracle silence, never asserted:
  * :func:`mint_remediation_certificate` refuses (raises) unless the oracle GENUINELY re-fires over the patched
    ``oracle_context`` and does NOT confirm (a still-firing context can never be certified as remediated), then
    signs the ``vigil-remediation-v1`` attestation (``fix_oracle.build_fix_signer``).
  * :func:`verify_remediation_certificate` re-derives the verdict independently: (1) re-fire the oracle over the
    retained patched context → must be SILENT; (2) the context digest must match the signed payload; (3) the
    Ed25519 signature must verify against the pinned governance public key. All three ⇒ ``ok``.

The certificate PAIRS the negative with the positive: ``original_finding_cert_digest`` references the signed
POSITIVE finding certificate (the proof the exploit worked before), so a verifier sees the full lifecycle
"exploitable → remediated" bound together.

FATAL-2: every ``framework.v2`` import is LAZY (function-local); module scope pulls only stdlib + vigil_core.
Determinism: no wallclock / rng.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Optional

from vigil_core import IntegrityError, verify_one
from vigil_core.crypto import load_public_key

_CERT_SCHEMA = "vigil-remediation-cert-v1"
_PAYLOAD_SCHEMA = "vigil-remediation-v1"          # the signed inner payload (matches fix_oracle.build_fix_signer)
_SILENT_VERDICT = "oracle-silent"


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _context_digest(patched_context: dict) -> str:
    """The raw hexdigest of the canonical patched context — byte-identical to fix_oracle.build_fix_signer."""
    return hashlib.sha256(_canon(patched_context)).hexdigest()


def _signing_bytes(engagement_slug: str, finding_ref: str, bug_class: str, ctx_digest: str) -> bytes:
    """Reconstruct the EXACT message fix_oracle.build_fix_signer signed (domain-separated canonical payload)."""
    payload = {
        "schema": _PAYLOAD_SCHEMA,
        "engagement_slug": str(engagement_slug or ""),
        "finding_ref": str(finding_ref or ""),
        "bug_class": str(bug_class or ""),
        "patched_context_sha256": ctx_digest,
        "verdict": _SILENT_VERDICT,
    }
    return _PAYLOAD_SCHEMA.encode("utf-8") + b"\x00" + _canon(payload)


def _parse_ref(signature_ref: str) -> Optional[tuple[str, str, str]]:
    """Parse ``remediation:<digest24>:<key_id>:<sig_b64>`` → (digest24, key_id, sig). None if malformed.
    ``split(":", 3)`` keeps the base64 signature intact (base64 has no ':')."""
    if not isinstance(signature_ref, str):
        return None
    parts = signature_ref.split(":", 3)
    if len(parts) != 4 or parts[0] != "remediation" or not (parts[2] and parts[3]):
        return None
    return parts[1], parts[2], parts[3]


def _is_silent(patched_context: dict, bug_class: str, ref: str) -> bool:
    """True iff the oracle RE-FIRES over the patched context and does NOT confirm (genuine silence). Any
    reverify error is treated as NOT-silent (fail-closed — a context we cannot re-fire is not proven dead)."""
    from framework.v2.verify.reverify import reverify_context      # lazy — FATAL-2
    try:
        return not reverify_context(patched_context, bug_class=bug_class, ref=ref).reproduced
    except Exception:  # noqa: BLE001 — unbuildable/erroring context is not a proven silence
        return False


def mint_remediation_certificate(
    *,
    finding_ref: str,
    bug_class: str,
    patched_oracle_context: dict,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    original_finding_cert_digest: str = "",
) -> dict:
    """Mint a portable RemediationCertificate from a PATCHED-build oracle_context that is oracle-SILENT.

    Refuses (raises) if the context still fires (a still-vulnerable build can never be certified remediated) —
    earned-by-silence, never asserted. Signs the ``vigil-remediation-v1`` attestation via
    :func:`fix_oracle.build_fix_signer` and packages the signed ref + the patched context + the paired positive
    certificate digest into a self-contained, offline-verifiable certificate dict."""
    from .fix_oracle import build_fix_signer                       # sibling — import-clean

    bc = str(bug_class or "").strip()
    if not bc:
        raise ValueError("mint_remediation_certificate: a bug_class is required to re-fire the oracle")
    if not isinstance(patched_oracle_context, dict) or not patched_oracle_context:
        raise ValueError("mint_remediation_certificate: a patched oracle_context is required")
    if not _is_silent(patched_oracle_context, bc, str(finding_ref)):
        raise ValueError("refusing to certify remediation: the oracle STILL fires over the patched context "
                         "(a still-vulnerable build is not remediated — fail-closed)")

    ctx_digest = _context_digest(patched_oracle_context)
    signature_ref = build_fix_signer(engagement_slug=engagement_slug, signers=signers)(
        str(finding_ref), bc, patched_oracle_context)
    if not (isinstance(signature_ref, str) and signature_ref.strip()):
        raise ValueError("mint_remediation_certificate: signer produced no certificate (fail-closed)")

    return {
        "schema": _CERT_SCHEMA,
        "engagement_slug": str(engagement_slug or ""),
        "finding_ref": str(finding_ref or ""),
        "bug_class": bc,
        "verdict": _SILENT_VERDICT,
        "patched_context_sha256": ctx_digest,
        "patched_oracle_context": patched_oracle_context,
        "signature_ref": signature_ref,
        "original_finding_cert_digest": str(original_finding_cert_digest or ""),
    }


class RemediationVerification:
    """The layered, offline verdict on a RemediationCertificate. ``ok`` requires ALL of:
    ``silent`` (the oracle re-fired over the patched context and did not confirm), ``bound`` (the retained
    context hashes to the signed digest), ``authentic`` (the Ed25519 signature verifies against the pinned
    governance key)."""

    __slots__ = ("silent", "bound", "authentic", "reason")

    def __init__(self, *, silent: bool, bound: bool, authentic: bool, reason: str = "") -> None:
        self.silent = silent
        self.bound = bound
        self.authentic = authentic
        self.reason = reason

    @property
    def ok(self) -> bool:
        return self.silent and self.bound and self.authentic

    def __repr__(self) -> str:
        return (f"RemediationVerification(ok={self.ok}, silent={self.silent}, bound={self.bound}, "
                f"authentic={self.authentic}, reason={self.reason!r})")


def verify_remediation_certificate(cert: dict, *, signer_pubkeys: "dict[str, str]") -> RemediationVerification:
    """Independently verify a RemediationCertificate offline. ``signer_pubkeys`` maps key_id → Ed25519 public
    key (b64) — the pinned governance keys (from the trust root). Fail-closed: any malformation is a failed
    layer, never an exception a caller could swallow into ``ok``."""
    if not isinstance(cert, dict) or cert.get("schema") != _CERT_SCHEMA:
        return RemediationVerification(silent=False, bound=False, authentic=False,
                                       reason="not a vigil-remediation-cert-v1")
    bug_class = str(cert.get("bug_class") or "")
    finding_ref = str(cert.get("finding_ref") or "")
    ctx = cert.get("patched_oracle_context")
    if not (bug_class and isinstance(ctx, dict) and ctx):
        return RemediationVerification(silent=False, bound=False, authentic=False,
                                       reason="missing bug_class / patched_oracle_context")

    # (1) silent — the oracle re-fires over the retained patched context and does NOT confirm.
    silent = _is_silent(ctx, bug_class, finding_ref)

    # (2) bound — the retained context hashes to the digest that was signed.
    recomputed = _context_digest(ctx)
    bound = (recomputed == str(cert.get("patched_context_sha256") or ""))

    # (3) authentic — the Ed25519 signature verifies against the pinned governance key.
    authentic = False
    reason = ""
    parsed = _parse_ref(str(cert.get("signature_ref") or ""))
    if parsed is None:
        reason = "malformed signature_ref"
    else:
        digest24, key_id, sig = parsed
        msg = _signing_bytes(cert.get("engagement_slug", ""), finding_ref, bug_class, recomputed)
        # integrity of the ref's own content-address (the digest24 rides on the signed msg).
        if digest24 != hashlib.sha256(msg).hexdigest()[:24]:
            reason = "signature_ref content-address does not match the signed payload"
        else:
            pub = signer_pubkeys.get(key_id) if isinstance(signer_pubkeys, dict) else None
            if not pub:
                reason = f"no pinned public key for signer {key_id!r}"
            else:
                try:
                    load_public_key(pub)     # reject non-canonical / low-order keys before verifying
                    authentic = bool(verify_one(pub, msg, sig))
                    if not authentic:
                        reason = "signature invalid (forged/tampered/wrong key)"
                except (IntegrityError, TypeError, ValueError):
                    authentic = False
                    reason = "malformed signature/key material — fail closed"

    if not reason:
        reason = ("verified: exploit oracle silent over the patched build, context-bound, governance-signed"
                  if (silent and bound and authentic) else
                  ("oracle STILL fires (not remediated)" if not silent else
                   "context digest mismatch" if not bound else "signature not authentic"))
    return RemediationVerification(silent=silent, bound=bound, authentic=authentic, reason=reason)
