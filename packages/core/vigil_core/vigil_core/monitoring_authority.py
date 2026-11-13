"""Monitoring-authority schema, canonical signing bytes, and an owner-side signer (AEGIS-SaaS).

The FATAL-2 SEAM CONTRACT for DEFENSIVE live monitoring: defined ONCE here in the shared integrity core so
the SOVEREIGN plane (which holds the owner key and mints the grant after an ownership proof + a recorded
monitoring attestation) and the keyless AEGIS data plane (which verifies the identical bytes before it
inspects a tenant's traffic) agree BY CONSTRUCTION, never by a drift-catching test.

A ``MonitoringAuthority`` authorizes AEGIS to run DEFENSIVE monitoring for ONE tenant (``org_id``) against
ONE exact ``host`` (no wildcard / subdomain inheritance) within a bounded ``[not_before, not_after)`` window,
in a given ``mode``. It is a DISTINCT capability from the offense-test ``EngagementAuthority``: proving you
own a host, or being authorized to ATTACK it, is NOT authority to OBSERVE its live traffic, which is NOT
authority to BLOCK it — ``own != offense-test != observe != block``. The distinct domain tag
(``monitoring-authority`` in :data:`spine_domains.DOMAIN_TAGS`) makes that separation CRYPTOGRAPHIC: a
monitoring-authority signature can never satisfy an offense-test (or credit-lease) check, or vice versa.

An OBSERVE grant NEVER permits a block: ``mode`` is inside the owner-signed canonical bytes, so a tenant
cannot flip observe->block without a FRESH owner signature, and BLOCK is NECESSARY-NOT-SUFFICIENT — the data
plane still gates enforcement per-request (continuous re-authorization + the ``AEGIS_RESPOND`` entitlement).

Pure, validated data + Ed25519 over a domain-separated canonical core — no crypto decision beyond the
signature math; the owner private key is used only inside :func:`sign` and is never persisted or returned.
Mirrors ``authority.py`` / ``credit_lease.py`` exactly (same canonical form, same fail-closed verify)."""
from __future__ import annotations

import enum
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .canonical import canonical_json
from .crypto import IntegrityError, sign, verify_threshold
from .models import Signature, TrustRoot
from .spine_domains import DOMAIN_TAGS

# Domain-separation prefix — distinct from authority / credit-lease / evidence / every other signed purpose,
# so a monitoring-authority signature can never be replayed as (or satisfied by) any other kind. Sourced from
# the ONE registry; never change without a schema bump + migration (it invalidates every existing signature).
_MONITORING_AUTHORITY_DOMAIN = DOMAIN_TAGS["monitoring-authority"]


class MonitoringMode(str, enum.Enum):
    """OBSERVE = inspect + alert only; the gateway NEVER blocks under an OBSERVE grant. BLOCK = inline
    enforcement permitted — but still gated at the data plane by continuous per-request re-authorization +
    the ``AEGIS_RESPOND`` entitlement; this flag is NECESSARY, never SUFFICIENT, for a block."""

    OBSERVE = "observe"
    BLOCK = "block"


class MonitoringAuthority(BaseModel):
    """The per-tenant, per-host defensive-monitoring authorization AEGIS checks before inspecting traffic."""

    model_config = ConfigDict(extra="forbid")

    org_id: str = Field(min_length=1, description="The tenant this grant authorizes monitoring for.")
    host: str = Field(min_length=1, description="The single EXACT host authorized for monitoring; no wildcard "
                      "or subdomain inheritance (bound here so a grant cannot be re-aimed at another asset).")
    mode: MonitoringMode = Field(
        default=MonitoringMode.OBSERVE,
        description="OBSERVE (inspect + alert only, never blocks) | BLOCK (enforcement permitted, still gated "
        "per-request at the data plane). Inside the signed bytes: observe cannot become block without re-signing.")
    not_before: datetime
    not_after: datetime
    issued_by: str = Field(default="", description="Owner/provisioner that minted this grant.")
    note: str = Field(default="")

    @model_validator(mode="after")
    def _check_window(self) -> "MonitoringAuthority":
        if self.not_after <= self.not_before:
            raise ValueError("not_after must be strictly after not_before")
        return self


class SignedMonitoringAuthority(BaseModel):
    """A monitoring authority plus governance signatures over its canonical form, verified against the owner
    ``TrustRoot``. A tampered org / host / mode / window is detected (every field is in the signed bytes)."""

    model_config = ConfigDict(extra="forbid")

    document: MonitoringAuthority
    signatures: list[Signature] = Field(min_length=1)


def monitoring_authority_signing_bytes(authority: MonitoringAuthority) -> bytes:
    """The exact bytes a signer signs / a verifier checks: the domain tag followed by the compact, sorted-key
    UTF-8 JSON of the document (byte-identical shape to ``authority_signing_bytes`` / credit-lease)."""
    return _MONITORING_AUTHORITY_DOMAIN + canonical_json(authority.model_dump(mode="json"))


def sign_monitoring_authority(
    document: MonitoringAuthority, signers: dict[str, str]
) -> SignedMonitoringAuthority:
    """Sign a monitoring authority with each ``key_id -> private_key_b64``. Sovereign-side (the OWNER signs);
    the private key is used only inside :func:`sign` and never persisted or returned."""
    msg = monitoring_authority_signing_bytes(document)
    signatures = [
        Signature(key_id=key_id, signature_b64=sign(priv_b64, msg))
        for key_id, priv_b64 in signers.items()
    ]
    return SignedMonitoringAuthority(document=document, signatures=signatures)


def verify_monitoring_authority(
    signed: SignedMonitoringAuthority, trust_root: TrustRoot
) -> tuple[bool, str]:
    """Return ``(ok, reason)``. True iff at least the threshold of DISTINCT trust-root authorisers validly
    signed the authority's canonical form. Verify-only (no private material; safe on the keyless AEGIS plane).
    Fail-CLOSED and contract-honouring: never raises. Rejects a quorum-collapsing trust root (duplicate
    authorizer public keys under distinct key_ids) exactly as the authority / credit-lease primitives do, and
    a malformed / weak-key signature is a refusal, never an uncaught crash in the data-plane gate."""
    pubkeys = [a.public_key_b64 for a in trust_root.authorizers]
    if len(set(pubkeys)) != len(pubkeys):
        return False, "trust root has duplicate authorizer public keys (would collapse the m-of-n quorum)"
    try:
        result = verify_threshold(
            monitoring_authority_signing_bytes(signed.document), signed.signatures, trust_root
        )
    except (IntegrityError, TypeError, ValueError) as e:   # ValueError: a document that cannot be UTF-8 encoded
        return False, f"monitoring-authority signature material is malformed or uses a weak key: {e}"
    return result.satisfied, result.reason
