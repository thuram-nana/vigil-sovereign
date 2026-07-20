"""Shared authentication for governance events (Phase 6). Every state-changing governance event
(promotion grant/revoke, kill engage/release, approval approve/deny) carries an Ed25519 signature by
the OWNER key over its canonical authenticated CORE fields, plus the signer's pubkey. Verification is
fail-closed: no trusted key, no signature, a pubkey that isn't the trusted owner key, or a tampered
core → NOT authentic. This is the primitive that makes "zero unauthorized A2/A3" provable from the
log rather than promised (a forged governance event never verifies, so it is ignored)."""
from __future__ import annotations

from typing import Optional, Sequence

from ..reuse import IntegrityError, canonical_json, sign, verify_one


def _canon(core: dict) -> bytes:
    m = canonical_json(core)
    return m if isinstance(m, bytes) else m.encode()


def signed_payload(core: dict, owner_key) -> dict:
    """core = the authenticated fields (must be JSON-canonicalizable). Returns core + {sig, pubkey}.
    With no owner key, sig/pubkey are None → the event will never verify (a caller that requires
    authentication must reject it)."""
    sig = sign(owner_key.private_key_b64, _canon(core)) if owner_key else None
    return {**core, "sig": sig, "pubkey": owner_key.public_key_b64 if owner_key else None}


def verify_signed(payload: dict, core_fields: Sequence[str], trusted_pubkey: Optional[str]) -> bool:
    """True iff `payload` carries a valid owner signature over its declared core fields. Fail-closed."""
    if not trusted_pubkey:
        return False
    sig = payload.get("sig")
    # A hostile spine payload can carry any JSON type for "sig" (number/list/object/bool). Reject
    # a non-str sig up front: the b64 decoder raises TypeError (not IntegrityError) on non-str/bytes,
    # which would otherwise propagate out of the fold and brick the gate/kill-switch/approval evals.
    if not sig or not isinstance(sig, str) or payload.get("pubkey") != trusted_pubkey:
        return False
    core = {k: payload.get(k) for k in core_fields}
    try:
        return verify_one(trusted_pubkey, _canon(core), sig)
    except (IntegrityError, TypeError):
        # malformed base64 / wrong-length / non-decodable sig or key material → NOT authentic
        # (fail-closed contract; a hostile append-only event must never raise out of the fold).
        return False
