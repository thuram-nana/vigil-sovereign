"""
authority.signing — sign and verify engagement authorities.

Reuses the entitlement layer's Ed25519 m-of-n threshold crypto and the
same governance TrustRoot: the panel that authorises which capabilities a
deployment may run also signs what a given engagement may do. Signing is
a provisioning act (operator side); the runtime only verifies.
"""

from __future__ import annotations

from ..entitlement.crypto import sign, verify_threshold
from ..entitlement.models import Signature, TrustRoot
from .canonical import authority_signing_bytes
from .models import EngagementAuthority, SignedAuthority


def sign_authority(
    document: EngagementAuthority, signers: dict[str, str]
) -> SignedAuthority:
    """Sign an authority with each (key_id -> private_key_b64). The caller
    supplies at least the trust root's threshold of authorised signers."""
    msg = authority_signing_bytes(document)
    signatures = [
        Signature(key_id=key_id, signature_b64=sign(priv_b64, msg))
        for key_id, priv_b64 in signers.items()
    ]
    return SignedAuthority(document=document, signatures=signatures)


def verify_authority(
    signed: SignedAuthority, trust_root: TrustRoot
) -> tuple[bool, str]:
    """Return (ok, reason). True iff at least the threshold of distinct
    trust-root authorisers validly signed the authority's canonical
    form."""
    result = verify_threshold(
        authority_signing_bytes(signed.document), signed.signatures, trust_root
    )
    return result.satisfied, result.reason
