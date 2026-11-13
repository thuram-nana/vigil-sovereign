"""Engagement-completion settle signal: schema, canonical signing bytes, signer + verifier (K4-5b).

The FATAL-2 SEAM CONTRACT for CUSTOMER-RUN SETTLEMENT: defined ONCE here in the shared integrity core so the
keyless OFFENSE plane (which knows a customer run reached a terminal state, and signs this signal with the
owner-DELEGATED offense-governance key) and the SOVEREIGN settle-drain (which holds the owner key, verifies
the identical bytes against the owner-signed ``OFFENSE_GOVERNANCE_ROLE`` delegation, and alone may mint a
refund via ``settle_launch``) agree BY CONSTRUCTION, never by a drift-catching test.

An ``EngagementCompletion`` binds ONE customer engagement (``engagement_slug`` == ``cust_<hash>``) and ONE
launch (``nonce``) to a terminal ``outcome``. It carries NO consumed amount: the sovereign drain derives the
billable units from the OWNER-SIGNED ``CreditLaunchLease``'s ``units_reserved`` (flat-per-run), so a forged
signal can never assert an amount — and because ``settle_launch`` clamps consumed to that signed reserved,
even a signal that somehow passed verify could never over-charge. The ``nonce`` binds the settle to the exact
launch, so a completion for an OLD lease can never settle a newer re-lease.

It is signed by the owner-DELEGATED offense-governance signers and verified against the delegation-derived
``TrustRoot`` (the SAME anchor-1 root ``finding_receiver.from_delegation`` derives) — NOT the owner key
directly, so the keyless offense worker can emit it without ever holding the owner key. The DISTINCT domain
tag (``engagement-completion`` in :data:`spine_domains.DOMAIN_TAGS`) makes the separation CRYPTOGRAPHIC: a
completion signature can never satisfy a finding / credit-lease / authority check, or vice-versa.

Pure, validated data + Ed25519 over a domain-separated canonical core — mirrors ``monitoring_authority.py`` /
``credit_lease.py`` exactly (same canonical form, same fail-closed verify; the private key is used only inside
:func:`sign` and is never persisted or returned)."""
from __future__ import annotations

import enum

from pydantic import BaseModel, ConfigDict, Field

from .canonical import canonical_json
from .crypto import IntegrityError, sign, verify_threshold
from .models import Signature, TrustRoot
from .spine_domains import DOMAIN_TAGS

# Domain-separation prefix — distinct from finding / credit-lease / authority / every other signed purpose,
# so a completion signature can never be replayed as (or satisfied by) any other kind. Sourced from the ONE
# registry; never change without a schema bump + migration (it invalidates every existing signature).
_ENGAGEMENT_COMPLETION_DOMAIN = DOMAIN_TAGS["engagement-completion"]


class EngagementOutcome(str, enum.Enum):
    """The terminal state of a customer engagement, which maps (flat-per-run) to billable consumption at the
    sovereign settle-drain: COMPLETED ⇒ the full reserved units are consumed (no refund); CANCELED / FAILED ⇒
    0 consumed (full refund). The signal attests ONLY the outcome; the drain owns the metric + the amount."""

    COMPLETED = "completed"
    CANCELED = "canceled"
    FAILED = "failed"


class EngagementCompletion(BaseModel):
    """The per-launch settle signal: one ``(engagement_slug, nonce)`` reached ``outcome``. Carries NO amount —
    the sovereign drain derives consumed from the owner-signed lease's ``units_reserved`` (flat-per-run)."""

    model_config = ConfigDict(extra="forbid")

    engagement_slug: str = Field(min_length=1, description="The customer engagement (cust_<hash>) that completed.")
    nonce: str = Field(min_length=1, description="The launch nonce — binds the settle to THIS lease, so a "
                       "completion for an old lease can never settle a newer re-lease of the same slug.")
    outcome: EngagementOutcome = Field(description="Terminal outcome; the drain maps it to consumed units.")


class SignedEngagementCompletion(BaseModel):
    """A completion signal plus offense-governance signatures over its canonical form, verified against the
    delegation-derived ``TrustRoot``. A tampered slug / nonce / outcome is detected (every field is signed)."""

    model_config = ConfigDict(extra="forbid")

    document: EngagementCompletion
    signatures: list[Signature] = Field(min_length=1)


def engagement_completion_signing_bytes(document: EngagementCompletion) -> bytes:
    """The exact bytes a signer signs / a verifier checks: the domain tag followed by the compact, sorted-key
    UTF-8 JSON of the document (byte-identical shape to ``monitoring_authority_signing_bytes`` / credit-lease)."""
    return _ENGAGEMENT_COMPLETION_DOMAIN + canonical_json(document.model_dump(mode="json"))


def sign_engagement_completion(
    document: EngagementCompletion, signers: dict[str, str]
) -> SignedEngagementCompletion:
    """Sign a completion signal with each ``key_id -> private_key_b64``. Offense-side (the owner-DELEGATED
    governance signers sign; the owner key is NEVER here). The private key is used only inside :func:`sign`
    and never persisted or returned."""
    msg = engagement_completion_signing_bytes(document)
    signatures = [
        Signature(key_id=key_id, signature_b64=sign(priv_b64, msg))
        for key_id, priv_b64 in signers.items()
    ]
    return SignedEngagementCompletion(document=document, signatures=signatures)


def verify_engagement_completion(
    signed: SignedEngagementCompletion, trust_root: TrustRoot
) -> tuple[bool, str]:
    """Return ``(ok, reason)``. True iff at least the threshold of DISTINCT trust-root authorisers validly
    signed the completion's canonical form. ``trust_root`` is the delegation-derived offense-governance root
    (the sovereign settle-drain builds it from the owner-signed ``OFFENSE_GOVERNANCE_ROLE`` delegation).
    Verify-only (no private material). Fail-CLOSED and contract-honouring: never raises. Rejects a
    quorum-collapsing trust root (duplicate authorizer public keys under distinct key_ids) exactly as the
    monitoring-authority / credit-lease primitives do, and a malformed / weak-key signature is a refusal."""
    pubkeys = [a.public_key_b64 for a in trust_root.authorizers]
    if len(set(pubkeys)) != len(pubkeys):
        return False, "trust root has duplicate authorizer public keys (would collapse the m-of-n quorum)"
    try:
        result = verify_threshold(
            engagement_completion_signing_bytes(signed.document), signed.signatures, trust_root
        )
    except (IntegrityError, TypeError, ValueError) as e:   # ValueError: a document that cannot be UTF-8 encoded
        return False, f"engagement-completion signature material is malformed or uses a weak key: {e}"
    return result.satisfied, result.reason
