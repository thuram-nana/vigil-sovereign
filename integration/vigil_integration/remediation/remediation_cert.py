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

from vigil_core import IntegrityError, sign, verify_one
from vigil_core.crypto import load_public_key

_CERT_SCHEMA = "vigil-remediation-cert-v2"
_SILENT_VERDICT = "oracle-silent"
_CERT_DOMAIN = b"vigil-remediation-cert-v2\x00"    # domain tag for the whole-cert signature (binds the controls)

# Response-bearing keys in a FindingContext — a NON-EMPTY value means the target produced observable output
# (it ANSWERED the exploit). This is the liveness control's heuristic evidence: silence with NO response is
# "unreachable" (INDETERMINATE), not "fixed". A stronger nonce-echo liveness is populated by the live driver.
_RESPONSE_KEYS = frozenset({
    "error_observed", "mutated", "baseline", "eval_response", "reflection", "reflected_in",
    "reflection_context", "probe_rounds", "oob_hits", "handshake", "achieved_state", "response",
    "body", "observed", "treatment_latencies", "baseline_latencies",
})


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _context_digest(patched_context: dict) -> str:
    """The raw hexdigest of the canonical patched context — byte-identical to fix_oracle.build_fix_signer."""
    return hashlib.sha256(_canon(patched_context)).hexdigest()


def _cert_signing_bytes(cert_without_sig: dict) -> bytes:
    """Domain-separated canonical bytes over the ENTIRE certificate minus its ``signature`` — so the signature
    binds EVERY field (patched context, positive control, the controls block, digests). Stripping or editing
    any control therefore breaks authenticity (the negative-proof controls cannot be removed post-hoc)."""
    return _CERT_DOMAIN + _canon(cert_without_sig)


def _is_silent(patched_context: dict, bug_class: str, ref: str) -> bool:
    """True iff the oracle RE-FIRES over the patched context and does NOT confirm (genuine silence). Any
    reverify error is treated as NOT-silent (fail-closed — a context we cannot re-fire is not proven dead)."""
    from framework.v2.verify.reverify import reverify_context      # lazy — FATAL-2
    try:
        return not reverify_context(patched_context, bug_class=bug_class, ref=ref).reproduced
    except Exception:  # noqa: BLE001 — unbuildable/erroring context is not a proven silence
        return False


def _fires(context: dict, bug_class: str, ref: str) -> bool:
    """True iff the oracle RE-FIRES over ``context`` and CONFIRMS — the positive-control check. Any reverify
    error is treated as NOT-firing (fail-closed: a control we cannot re-fire cannot vouch for the harness)."""
    from framework.v2.verify.reverify import reverify_context      # lazy — FATAL-2
    try:
        return bool(reverify_context(context, bug_class=bug_class, ref=ref).reproduced)
    except Exception:  # noqa: BLE001
        return False


def _has_live_response(context: dict) -> bool:
    """Liveness heuristic: True iff the context carries a NON-EMPTY response-bearing field — evidence the
    target actually ANSWERED. Silence with no captured response is 'unreachable' (INDETERMINATE), never a
    proven fix. (The stronger form — a fresh nonce echoed by the target — is populated by the live driver.)"""
    if not isinstance(context, dict):
        return False
    return any(context.get(k) not in (None, "", [], {}) for k in _RESPONSE_KEYS)


def mint_remediation_certificate(
    *,
    finding_ref: str,
    bug_class: str,
    patched_oracle_context: dict,
    positive_control_context: dict,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    surface: str = "",
    original_finding_cert_digest: str = "",
    freshness_nonce: str = "",
    repeats: int = 1,
) -> dict:
    """Mint a CONTROLLED, portable RemediationCertificate — a NEGATIVE proof with the controls that make
    "silent" mean "fixed" rather than "didn't reach". Every control is enforced fail-closed at mint:

      * POSITIVE CONTROL (twin): the SAME oracle MUST re-fire on ``positive_control_context`` (the pre-fix
        build / a known-vulnerable reference). Without it, silence on the patched build is indistinguishable
        from a broken or blocked probe — so a control that does not fire is REFUSED.
      * SILENCE: the oracle re-fires over ``patched_oracle_context`` and does NOT confirm (earned, not asserted).
      * LIVENESS: the patched context carries a captured response (the target ANSWERED) — silence with no
        response is 'unreachable' (INDETERMINATE), never 'fixed'.

    The WHOLE certificate (incl. the controls + both contexts) is signed, so no control can be stripped. The
    ``freshness_nonce`` (a fresh challenge echoed by the target) and ``repeats`` (consistent silences) are the
    live driver's stronger controls; they ride in the signed ``controls`` block when supplied."""
    bc = str(bug_class or "").strip()
    if not bc:
        raise ValueError("mint_remediation_certificate: a bug_class is required to re-fire the oracle")
    if not (isinstance(patched_oracle_context, dict) and patched_oracle_context):
        raise ValueError("mint_remediation_certificate: a patched oracle_context is required")
    if not (isinstance(positive_control_context, dict) and positive_control_context):
        raise ValueError("mint_remediation_certificate: a positive_control_context is required (the negative "
                         "proof needs a twin the oracle DOES fire on — else silence is not a proof)")
    if not signers:
        raise ValueError("mint_remediation_certificate: governance signers are required (never an unsigned proof)")

    # CONTROL 1 — the positive control MUST fire (the harness/oracle is demonstrably capable of firing NOW).
    if not _fires(positive_control_context, bc, str(finding_ref)):
        raise ValueError("refusing to certify remediation: the positive control does NOT fire — silence on the "
                         "patched build cannot be distinguished from a broken/blocked probe (fail-closed)")
    # CONTROL 2 — the patched build MUST be silent (earned-by-silence).
    if not _is_silent(patched_oracle_context, bc, str(finding_ref)):
        raise ValueError("refusing to certify remediation: the oracle STILL fires over the patched context "
                         "(a still-vulnerable build is not remediated — fail-closed)")
    # CONTROL 3 — liveness: the patched build actually ANSWERED (silence != unreachable).
    if not _has_live_response(patched_oracle_context):
        raise ValueError("refusing to certify remediation: the patched context carries no captured response — "
                         "silence is indistinguishable from an unreachable target (INDETERMINATE, fail-closed)")

    cert = {
        "schema": _CERT_SCHEMA,
        "engagement_slug": str(engagement_slug or ""),
        "finding_ref": str(finding_ref or ""),
        "bug_class": bc,
        "surface": str(surface or ""),
        "verdict": _SILENT_VERDICT,
        "patched_context_sha256": _context_digest(patched_oracle_context),
        "patched_oracle_context": patched_oracle_context,
        "positive_control_sha256": _context_digest(positive_control_context),
        "positive_control_context": positive_control_context,
        "controls": {
            "positive_control": True,
            "liveness": True,
            "freshness_nonce": str(freshness_nonce or ""),
            "repeats": int(repeats) if isinstance(repeats, int) and repeats > 0 else 1,
        },
        "original_finding_cert_digest": str(original_finding_cert_digest or ""),
    }
    key_id, priv = signers[0]
    cert["signature"] = {"key_id": str(key_id), "sig": sign(priv, _cert_signing_bytes(cert))}
    return cert


class RemediationVerification:
    """The layered, offline verdict on a controlled RemediationCertificate. ``ok`` requires ALL of:
    ``silent`` (the oracle re-fires over the patched context and does NOT confirm), ``control_fires`` (the
    SAME oracle DOES re-fire over the positive-control/twin context — the harness is capable of firing, so
    silence is meaningful), ``live`` (the patched context carries a captured response — the target answered),
    ``bound`` (both contexts hash to the signed digests), and ``authentic`` (the whole-cert Ed25519 signature
    verifies against the pinned governance key — no control was stripped)."""

    __slots__ = ("silent", "control_fires", "live", "bound", "authentic", "reason")

    def __init__(self, *, silent: bool, control_fires: bool, live: bool, bound: bool, authentic: bool,
                 reason: str = "") -> None:
        self.silent = silent
        self.control_fires = control_fires
        self.live = live
        self.bound = bound
        self.authentic = authentic
        self.reason = reason

    @property
    def ok(self) -> bool:
        return self.silent and self.control_fires and self.live and self.bound and self.authentic

    def __repr__(self) -> str:
        return (f"RemediationVerification(ok={self.ok}, silent={self.silent}, "
                f"control_fires={self.control_fires}, live={self.live}, bound={self.bound}, "
                f"authentic={self.authentic}, reason={self.reason!r})")


def _fail(reason: str) -> RemediationVerification:
    return RemediationVerification(silent=False, control_fires=False, live=False, bound=False,
                                   authentic=False, reason=reason)


def _authentic(cert: dict, signer_pubkeys: "dict[str, str]") -> tuple[bool, str]:
    """Verify the whole-cert Ed25519 signature over the canonical cert-minus-signature against a pinned key."""
    sigblk = cert.get("signature")
    if not (isinstance(sigblk, dict) and sigblk.get("key_id") and sigblk.get("sig")):
        return False, "missing/malformed signature block"
    key_id, sig = str(sigblk["key_id"]), str(sigblk["sig"])
    pub = signer_pubkeys.get(key_id) if isinstance(signer_pubkeys, dict) else None
    if not pub:
        return False, f"no pinned public key for signer {key_id!r}"
    msg = _cert_signing_bytes({k: v for k, v in cert.items() if k != "signature"})
    try:
        load_public_key(pub)     # reject non-canonical / low-order keys before verifying
        if verify_one(pub, msg, sig):
            return True, ""
        return False, "signature invalid (forged/tampered/stripped-control/wrong key)"
    except (IntegrityError, TypeError, ValueError):
        return False, "malformed signature/key material — fail closed"


def verify_remediation_certificate(cert: dict, *, signer_pubkeys: "dict[str, str]") -> RemediationVerification:
    """Independently verify a controlled RemediationCertificate offline, by re-execution. ``signer_pubkeys``
    maps key_id → Ed25519 public key (b64) — the pinned governance keys (from the trust root). Fail-closed:
    any malformation is a failed layer, never an exception a caller could swallow into ``ok``."""
    if not isinstance(cert, dict) or cert.get("schema") != _CERT_SCHEMA:
        return _fail("not a vigil-remediation-cert-v2")
    bug_class = str(cert.get("bug_class") or "")
    finding_ref = str(cert.get("finding_ref") or "")
    patched = cert.get("patched_oracle_context")
    control = cert.get("positive_control_context")
    if not (bug_class and isinstance(patched, dict) and patched and isinstance(control, dict) and control):
        return _fail("missing bug_class / patched_oracle_context / positive_control_context")

    # (1) silent — the oracle re-fires over the patched context and does NOT confirm.
    silent = _is_silent(patched, bug_class, finding_ref)
    # (2) control_fires — the SAME oracle DOES fire over the twin (the harness can fire → silence is meaningful).
    control_fires = _fires(control, bug_class, finding_ref)
    # (3) live — the patched build actually answered (silence != unreachable).
    live = _has_live_response(patched)
    # (4) bound — both retained contexts hash to their signed digests.
    bound = (_context_digest(patched) == str(cert.get("patched_context_sha256") or "")
             and _context_digest(control) == str(cert.get("positive_control_sha256") or ""))
    # (5) authentic — the whole-cert signature verifies (so no control was stripped/edited).
    authentic, auth_reason = _authentic(cert, signer_pubkeys)

    if silent and control_fires and live and bound and authentic:
        reason = "verified: oracle silent on the patched build, positive control fires, target live, signed"
    elif not silent:
        reason = "oracle STILL fires on the patched build (not remediated)"
    elif not control_fires:
        reason = "positive control does NOT fire — silence is not a proof (broken/blocked probe?)"
    elif not live:
        reason = "no captured response in the patched context — unreachable, not a proven fix (INDETERMINATE)"
    elif not bound:
        reason = "context digest mismatch (patched or positive-control tampered)"
    else:
        reason = auth_reason or "signature not authentic"
    return RemediationVerification(silent=silent, control_fires=control_fires, live=live, bound=bound,
                                   authentic=authentic, reason=reason)
