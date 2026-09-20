"""
authority.signing — sign and verify engagement authorities.

The signer + verifier now live in the shared integrity core (``vigil_core.authority``) so the SOVEREIGN
plane can owner-sign WITHOUT importing ``framework`` (the two-env boundary, FATAL-2) and this engine
verifies the byte-identical form. These are thin re-exports so the sovereign signer and this engine's
verifier are literally the SAME code — they agree by construction, and the core's hardening (a fail-closed
``(ok, reason)`` contract that never raises, plus rejection of a quorum-collapsing duplicate-pubkey trust
root) applies to the offense launch gate too.

Reuses the entitlement layer's Ed25519 m-of-n threshold crypto and the same governance ``TrustRoot``: the
panel that authorises which capabilities a deployment may run also signs what a given engagement may do.
Signing is a provisioning act (operator side); the runtime only verifies.
"""

from __future__ import annotations

from vigil_core.authority import sign_engagement_authority, verify_engagement_authority
from vigil_core.models import TrustRoot

from .models import EngagementAuthority, SignedAuthority


def sign_authority(
    document: EngagementAuthority, signers: dict[str, str]
) -> SignedAuthority:
    """Sign an authority with each (key_id -> private_key_b64). The caller supplies at least the trust
    root's threshold of authorised signers. Delegates to the shared core."""
    return sign_engagement_authority(document, signers)


def verify_authority(
    signed: SignedAuthority, trust_root: TrustRoot
) -> tuple[bool, str]:
    """Return (ok, reason). True iff at least the threshold of distinct trust-root authorisers validly
    signed the authority's canonical form. Fail-closed (never raises); rejects a duplicate-pubkey trust
    root that would collapse the m-of-n quorum. Delegates to the shared core."""
    return verify_engagement_authority(signed, trust_root)


__all__ = ["sign_authority", "verify_authority"]
