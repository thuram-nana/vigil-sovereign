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

import math
import os
from datetime import datetime
from typing import Any, Final, Optional

from pydantic import (BaseModel, ConfigDict, Field, SerializerFunctionWrapHandler, model_serializer,
                      model_validator)

from .canonical import canonical_json
from .crypto import IntegrityError, sign, verify_threshold
from .models import Signature, TrustRoot
from .spine_domains import DOMAIN_TAGS

# Domain-separation prefix — distinct from authority / evidence / delegation / every other signed purpose,
# so a credit-lease signature can never be replayed as (or satisfied by) any other kind. Sourced from the ONE
# registry (the plan's "define the domain tag once in vigil_core"); never change without a schema bump.
_LEASE_DOMAIN = DOMAIN_TAGS["credit-launch-lease"]


def _env_int(name: str, default: int) -> int:
    try:
        v = int(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        return default
    return v if v >= 1 else default


# EC-4 — the credit->token envelope conversion `E`: how many Anthropic tokens one VIGIL credit's HARD-CAPPED
# cost envelope buys. Defined ONCE here, beside CreditLaunchLease.units_reserved (the credits the envelope is
# derived from), so BOTH planes agree BY CONSTRUCTION — the sovereign plane computes envelope = units * E when
# it reserves; the keyless engine reads the same E for its hard run-budget — with NO cross-plane import (the
# credit-lease seam-contract precedent). After reserve, the SIGNED reserved envelope is the source of truth
# (settle clamps to it), so a later E change can never retro-resize a minted reservation.
#
# PLACEHOLDER default — this is an OWNER money-doctrine number. Ratify it (and the per-model-tier $ cost rate in
# the catalog) before any production go-live; operator-overridable via VIGIL_ENVELOPE_TOKENS_PER_CREDIT for
# staging. The cost ledger it feeds is default-OFF (not wired into the live launch-gate money path yet).
ENVELOPE_TOKENS_PER_CREDIT: Final[int] = _env_int("VIGIL_ENVELOPE_TOKENS_PER_CREDIT", 100_000)

#: The OPTIONAL lease fields added after the first lease format. A field whose value is None is omitted from the
#: serialized document and from the signing bytes (the precedent: the version-conditional chain-head payload), so
#: every lease that sets none of them serializes, signs and verifies byte-identically to a pre-v2 lease. A set field
#: is part of the signed document: changing, adding or stripping it breaks the owner signature.
LEASE_V2_OPTIONAL_FIELDS: Final[tuple[str, ...]] = ("run_tier", "plan_reserved", "plan_period_end", "continue_of")


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
    # --- optional v2 fields (see ``LEASE_V2_OPTIONAL_FIELDS``) -----------------------------------------------
    # Each is None unless the minting code stamps it. A None field is left out of the serialized document AND out
    # of the signing bytes, so a lease that stamps none of them is byte-identical to a lease minted before they
    # existed (an older verifier keeps accepting it); a stamped field is covered by the owner signature.
    run_tier: Optional[str] = Field(default=None, description="The launch product's run tier (a run_tier.RUN_TIERS "
                                    "value), when the lease names it explicitly.")
    plan_reserved: Optional[int] = Field(default=None, ge=0, description="How many of units_reserved the reserve "
                                         "took from the tenant's plan-credit tranche (the rest came from the wallet); "
                                         "None when the lease does not record the split.")
    plan_period_end: Optional[float] = Field(default=None, description="The period_end of the plan tranche the "
                                             "plan share came from; set exactly when plan_reserved > 0.")
    continue_of: Optional[str] = Field(default=None, min_length=1, description="The nonce of the same engagement's "
                                       "earlier launch this one continues, when it is a continuation.")

    @model_validator(mode="after")
    def _check_window(self) -> "CreditLaunchLease":
        if self.not_after <= self.not_before:
            raise ValueError("not_after must be strictly after not_before")
        return self

    @model_validator(mode="after")
    def _check_v2_fields(self) -> "CreditLaunchLease":
        if self.run_tier is not None:
            from .run_tier import RUN_TIERS
            if self.run_tier not in RUN_TIERS:
                raise ValueError(f"run_tier must be one of {RUN_TIERS}")
        if self.plan_reserved is not None and self.plan_reserved > self.units_reserved:
            raise ValueError("plan_reserved cannot exceed units_reserved")
        if self.plan_reserved:                              # a plan share names the tranche it came from
            pe = self.plan_period_end
            if pe is None or not math.isfinite(pe) or pe <= 0.0:
                raise ValueError("plan_period_end must be a finite positive number when plan_reserved > 0")
        elif self.plan_period_end is not None:
            raise ValueError("plan_period_end is set only together with plan_reserved > 0")
        return self

    @model_serializer(mode="wrap")
    def _drop_unset_v2_fields(self, handler: SerializerFunctionWrapHandler) -> Any:
        data = handler(self)
        if isinstance(data, dict):
            for key in LEASE_V2_OPTIONAL_FIELDS:
                if key in data and data[key] is None:
                    del data[key]
        return data


class SignedCreditLaunchLease(BaseModel):
    """A credit-launch lease plus governance signatures over its canonical form, verified against the same
    ``TrustRoot`` the authority layer uses (the owner key). A tampered units/scope/window/org is detected."""

    model_config = ConfigDict(extra="forbid")

    document: CreditLaunchLease
    signatures: list[Signature] = Field(min_length=1)


def credit_lease_signing_bytes(lease: CreditLaunchLease) -> bytes:
    """The exact bytes a signer signs / a verifier checks: the domain tag followed by the compact, sorted-key
    UTF-8 JSON of the document (byte-identical shape to ``authority_signing_bytes``). The document's serializer
    leaves out every ``LEASE_V2_OPTIONAL_FIELDS`` entry whose value is None, so a lease without them signs the
    same bytes as a pre-v2 lease, and a lease with one of them set covers it with the signature."""
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
    except (IntegrityError, TypeError, ValueError) as e:   # ValueError: a document that cannot be UTF-8 encoded
        return False, f"credit-lease signature material is malformed or uses a weak key: {e}"
    return result.satisfied, result.reason
