"""Engagement-authority schema, canonical signing bytes, and an owner-side signer.

VENDORED from CRUCIBLE ``framework/v2/authority/{models,canonical,signing}.py`` into the shared
integrity core so the SOVEREIGN plane — which never installs ``framework`` (the two-env boundary,
FATAL-2) — can OWNER-SIGN an engagement authority using ``vigil_core`` alone, and the OFFENSE plane
VERIFIES the identical bytes. ``framework.v2.authority.{models,canonical}`` re-export these names, so
there is ONE definition: the sovereign signer and the offense verifier agree BY CONSTRUCTION, not by a
drift-catching test that a schema change could out-run.

Byte-identical to the prior framework-local canonical form (same domain tag + the same compact
sorted-key JSON of ``model_dump(mode="json")``), so authorities signed before this lift still verify.

Pure, validated data + Ed25519 over a domain-separated canonical core — no crypto decision is made here
beyond the signature math; the runtime trust decision (scope / window / kill-switch) stays in the
offense engine's ``authority`` layer. The owner private key is used only inside :func:`sign` and is
never persisted or returned.
"""
from __future__ import annotations

import enum
from datetime import datetime
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .canonical import canonical_json
from .crypto import sign, verify_threshold
from .models import Signature, TrustRoot

# Domain-separation prefix — distinct from the evidence / entitlement / revocation / proposal /
# delegation / spine-head domains, so an authority signature can never be replayed as any other kind.
# Byte-identical to the prior ``framework.v2.authority.canonical`` value; never change without a schema
# bump + migration (it would invalidate every existing authority signature).
_AUTHORITY_DOMAIN: Final[bytes] = b"crucible-authority-v1\x00"


class TargetEnvironment(str, enum.Enum):
    """Where the engagement's target lives. TWIN is a replica/digital twin (safe to be destructive);
    STAGING is a non-production deploy; LIVE is real production (destructive actions require a
    deliberate second acknowledgement)."""

    TWIN = "twin"
    STAGING = "staging"
    LIVE = "live"


class EngagementAuthority(BaseModel):
    """The per-engagement authorization an action is checked against."""

    model_config = ConfigDict(extra="forbid")

    engagement_slug: str = Field(min_length=1)
    environment: TargetEnvironment
    scope: list[str] = Field(min_length=1, description="In-scope host patterns.")
    not_before: datetime
    not_after: datetime
    allow_destructive: bool = Field(
        default=False, description="Destructive actions permitted at all."
    )
    live_destructive_acknowledged: bool = Field(
        default=False,
        description="Second, explicit acknowledgement required for destructive actions against a LIVE "
        "environment. allow_destructive alone is not enough on LIVE.",
    )
    max_actions: int = Field(default=10_000, ge=1, description="Action budget.")
    issued_by: str = Field(default="", description="Operator who issued this authority.")
    note: str = Field(default="")

    @model_validator(mode="after")
    def _check_window(self) -> "EngagementAuthority":
        if self.not_after <= self.not_before:
            raise ValueError("not_after must be strictly after not_before")
        return self


class SignedAuthority(BaseModel):
    """An engagement authority plus governance signatures over its canonical form. Verified against the
    same ``TrustRoot`` the entitlement layer uses. A high-assurance deployment requires the signature so a
    tampered scope, window, or destructive flag is detected."""

    model_config = ConfigDict(extra="forbid")

    document: EngagementAuthority
    signatures: list[Signature] = Field(min_length=1)


def authority_signing_bytes(authority: EngagementAuthority) -> bytes:
    """The exact bytes an authoriser signs / a verifier checks: the domain tag followed by the compact,
    sorted-key UTF-8 JSON of the document. Byte-identical to the prior framework-local form."""
    return _AUTHORITY_DOMAIN + canonical_json(authority.model_dump(mode="json"))


def sign_engagement_authority(
    document: EngagementAuthority, signers: dict[str, str]
) -> SignedAuthority:
    """Sign an authority with each ``key_id -> private_key_b64``. Sovereign-side (the OWNER signs); the
    private key is used only inside :func:`sign` and never persisted or returned. The caller supplies at
    least the trust root's threshold of authorised signers."""
    msg = authority_signing_bytes(document)
    signatures = [
        Signature(key_id=key_id, signature_b64=sign(priv_b64, msg))
        for key_id, priv_b64 in signers.items()
    ]
    return SignedAuthority(document=document, signatures=signatures)


def verify_engagement_authority(
    signed: SignedAuthority, trust_root: TrustRoot
) -> tuple[bool, str]:
    """Return ``(ok, reason)``. True iff at least the threshold of DISTINCT trust-root authorisers validly
    signed the authority's canonical form. Verify-only — no private material, safe on either plane."""
    result = verify_threshold(
        authority_signing_bytes(signed.document), signed.signatures, trust_root
    )
    return result.satisfied, result.reason
