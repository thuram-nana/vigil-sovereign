"""Credit-launch-lease schema, canonical signing bytes, and an owner-side signer (Slice G).

The FATAL-2 SEAM CONTRACT for the credit + launch gate: defined ONCE here in the shared integrity core so
the SOVEREIGN plane (which holds the owner key and mints the lease after composing membership + ownership
proof + a verifying EngagementAuthority + a sufficient credit balance) and the keyless OFFENSE plane (which
verifies the identical bytes before any traffic) agree BY CONSTRUCTION, never by a drift-catching test.

A ``CreditLaunchLease`` reserves ``units_reserved`` credits for ONE engagement (``engagement_slug``) against
ONE ``scope_host`` within a bounded ``[not_before, not_after)`` window, for one tenant (``org_id``). It is a
SEPARATE conjunct from the ``EngagementAuthority`` (testing authorization): the lease authorizes SPEND +
LAUNCH, the authority authorizes the TARGET scope. The offense launch gate requires BOTH to verify under the
owner trust root.

Domain-separated (``credit-launch-lease`` in :data:`spine_domains.DOMAIN_TAGS`) so a signature under one
purpose can never replay as another. Pure, validated data + Ed25519 over a domain-separated canonical core —
no crypto decision beyond the signature math; the owner private key is used only inside :func:`sign` and is
never persisted or returned. Mirrors ``authority.py`` exactly (same canonical form, same fail-closed verify).
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .canonical import canonical_json
from .crypto import IntegrityError, sign, verify_threshold
from .models import Signature, TrustRoot
from .spine_domains import DOMAIN_TAGS

# Domain-separation prefix — distinct from authority / evidence / delegation / every other signed purpose,
# so a credit-lease signature can never be replayed as (or satisfied by) any other kind. Sourced from the ONE
# registry (the plan's "define the domain tag once in vigil_core"); never change without a schema bump.
_LEASE_DOMAIN = DOMAIN_TAGS["credit-launch-lease"]


class CreditLaunchLease(BaseModel):
    """The per-launch credit reservation an offense launch is checked against (alongside its authority)."""

    model_config = ConfigDict(extra="forbid")

    engagement_slug: str = Field(min_length=1, description="The one engagement this lease reserves credit for.")
    org_id: str = Field(min_length=1, description="The tenant whose credits are reserved (== CRUCIBLE_TENANT).")
    scope_host: str = Field(min_length=1, description="The single host the launch is authorized against; MUST "
                            "match the EngagementAuthority scope (bound here so a lease cannot be re-aimed).")
    units_reserved: int = Field(ge=1, description="Credits reserved for this launch (the pre-authorized spend "
                                "cap; completed units debit against it, the unused remainder is released).")
    not_before: datetime
    not_after: datetime
    nonce: str = Field(min_length=1, description="Single-use uniqueness so two launches cannot share a lease.")
    issued_at: float = Field(default=0.0, description="Mint anchor (anti-replay high-water on the minting spine).")

    @model_validator(mode="after")
    def _check_window(self) -> "CreditLaunchLease":
        if self.not_after <= self.not_before:
            raise ValueError("not_after must be strictly after not_before")
        return self


class SignedCreditLaunchLease(BaseModel):
    """A credit-launch lease plus governance signatures over its canonical form, verified against the same
    ``TrustRoot`` the authority layer uses (the owner key). A tampered units/scope/window/org is detected."""

    model_config = ConfigDict(extra="forbid")

    document: CreditLaunchLease
    signatures: list[Signature] = Field(min_length=1)


def credit_lease_signing_bytes(lease: CreditLaunchLease) -> bytes:
    """The exact bytes a signer signs / a verifier checks: the domain tag followed by the compact, sorted-key
    UTF-8 JSON of the document (byte-identical shape to ``authority_signing_bytes``)."""
    return _LEASE_DOMAIN + canonical_json(lease.model_dump(mode="json"))


def sign_credit_launch_lease(
    document: CreditLaunchLease, signers: dict[str, str]
) -> SignedCreditLaunchLease:
    """Sign a lease with each ``key_id -> private_key_b64``. Sovereign-side (the OWNER signs); the private key
    is used only inside :func:`sign` and never persisted or returned."""
    msg = credit_lease_signing_bytes(document)
    signatures = [
        Signature(key_id=key_id, signature_b64=sign(priv_b64, msg))
        for key_id, priv_b64 in signers.items()
    ]
    return SignedCreditLaunchLease(document=document, signatures=signatures)


def verify_credit_launch_lease(
    signed: SignedCreditLaunchLease, trust_root: TrustRoot
) -> tuple[bool, str]:
    """Return ``(ok, reason)``. True iff at least the threshold of DISTINCT trust-root authorisers validly
    signed the lease's canonical form. Verify-only (no private material; safe on either plane). Fail-CLOSED
    and contract-honouring: never raises. Rejects a quorum-collapsing trust root (duplicate authorizer public
    keys under distinct key_ids) exactly as the authority/delegation primitives do, and a malformed/weak-key
    signature is a refusal, never an uncaught crash in the keyless offense launch gate."""
    pubkeys = [a.public_key_b64 for a in trust_root.authorizers]
    if len(set(pubkeys)) != len(pubkeys):
        return False, "trust root has duplicate authorizer public keys (would collapse the m-of-n quorum)"
    try:
        result = verify_threshold(
            credit_lease_signing_bytes(signed.document), signed.signatures, trust_root
        )
    except IntegrityError as e:
        return False, f"credit-lease signature material is malformed or uses a weak key: {e}"
    return result.satisfied, result.reason
