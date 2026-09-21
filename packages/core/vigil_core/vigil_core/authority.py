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
from .crypto import IntegrityError, sign, verify_threshold
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
    # VF-2b out-of-band OOB confirmation (Wave 1.2). DEDICATED fields, deliberately NOT in ``scope``:
    #   * ``oob_relay_host`` is a single bare hostname (the operator-hosted collaborator relay). It is NOT a
    #     scan TARGET — it is an EGRESS destination gated separately (authority.gate.authorize_oob_egress),
    #     never by the general host-scope matcher, so authorizing the relay does not widen the scan surface.
    #   * ``oob_collector_pubkey`` is base64 Ed25519 key material (contains ``+`` / ``/`` / ``=``) — it could
    #     not survive the offense-side bare-host scope re-validation, and it is an AUTHENTICITY pin, not a
    #     host. The verifier PINS it out-of-band to demand an independent collector receipt (VF-2b).
    # Both default to "" so an authority that does not use OOB is unchanged in meaning; adding the fields DOES
    # change the owner-signed canonical bytes (model_dump includes defaulted fields), so an authority signed
    # before this schema change re-verifies only after re-signing — expected, and both planes agree by
    # construction. ``_AUTHORITY_DOMAIN`` is deliberately untouched.
    oob_relay_host: str = Field(
        default="", description="Bare hostname of the operator-hosted OOB collaborator relay authorized as an "
        "OOB egress destination (separate gate; NOT a scan target, NOT in scope).")
    oob_collector_pubkey: str = Field(
        default="", description="Base64 Ed25519 public key of the OOB relay's independent collector, pinned "
        "out-of-band; the verifier checks each OOB receipt against it (VF-2b). Public material only.")
    # DNS out-of-band confirmation (Wave 1 DNS-OOB). DEDICATED fields mirroring the HTTP relay pair above,
    # deliberately NOT in ``scope``: ``oob_dns_domain`` is the operator-OWNED base domain whose NS records
    # delegate to the authoritative DNS collector (an OOB channel, never a scan target); ``oob_dns_collector_
    # pubkey`` is the DNS collector's independent Ed25519 pin (public material only), which — like the HTTP
    # collector pin — could not survive the bare-host scope re-validation and is an AUTHENTICITY pin, not a
    # host. Both default "" so a non-DNS-OOB authority is unchanged in meaning; adding them DOES change the
    # owner-signed canonical bytes (an authority signed before this schema change re-verifies only after
    # re-signing — expected; both planes agree by construction). ``_AUTHORITY_DOMAIN`` is untouched.
    oob_dns_domain: str = Field(
        default="", description="Operator-owned base domain (e.g. oob.op.example) whose NS records delegate to "
        "the authoritative DNS OOB collector. A DNS OOB channel; NOT a scan target, NOT in scope.")
    oob_dns_collector_pubkey: str = Field(
        default="", description="Base64 Ed25519 public key of the DNS OOB collector, pinned out-of-band; the "
        "verifier checks each DNS receipt against it (VF-2b). Public material only.")
    # OOB receipt TTL / replay policy (Wave 1 DNS-OOB soundness fix). The DURATION + skew that bound a
    # receipt-bearing OOB hit's window are OWNER-SIGNED here, OUT-OF-BAND — NOT read from the producer-
    # controlled finding context. The verifier recomputes the window as ``[issued_at - oob_skew_seconds,
    # issued_at + oob_ttl_seconds + oob_skew_seconds]`` over the receipt's target-observed ``received_at``,
    # so a producer that WIDENS its context ``oob_expires_at`` / inflates its ``oob_skew`` cannot re-confirm a
    # stale/replayed receipt (the authority duration wins, live AND on offline re-verify). Defaults preserve a
    # non-OOB authority's meaning; ``0.0`` skew is a valid tight bound. (The producer-recorded mint anchor
    # ``issued_at`` itself is not cryptographically committed into the token — see
    # ``VIGIL-LIMIT:LIMIT-dns-oob-token-cleartext-broadcast``.)
    oob_ttl_seconds: float = Field(
        default=300.0, ge=0.0, description="Owner-signed TTL DURATION (seconds) bounding a receipt-bearing "
        "OOB hit's replay window; the verifier uses issued_at + this, ignoring any producer-widened expiry.")
    oob_skew_seconds: float = Field(
        default=5.0, ge=0.0, description="Owner-signed clock-skew tolerance (seconds) applied to both edges of "
        "the receipt window; taken out-of-band, never from the producer context.")

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
    signed the authority's canonical form. Verify-only — no private material, safe on either plane.

    Fail-CLOSED and contract-honouring: never raises, always returns ``(ok, reason)``. It rejects, at THIS
    layer, a quorum-collapsing trust root (duplicate authorizer PUBLIC KEYS under distinct key_ids would let
    fewer real keyholders satisfy m-of-n). ``TrustRoot`` itself deliberately permits duplicate pubkeys — the
    witness anti-rollback subsystem constructs a degenerate roster on purpose — so the consumer that cannot
    tolerate a collapsed quorum, an authority for a LIVE external engagement, rejects it here, exactly as the
    sibling ``delegation`` primitive does. A 1-of-1 owner root is unaffected (a single authorizer cannot
    duplicate)."""
    pubkeys = [a.public_key_b64 for a in trust_root.authorizers]
    if len(set(pubkeys)) != len(pubkeys):
        return False, "trust root has duplicate authorizer public keys (would collapse the m-of-n quorum)"
    try:
        result = verify_threshold(
            authority_signing_bytes(signed.document), signed.signatures, trust_root
        )
    except IntegrityError as e:
        # Malformed signature bytes, or a weak (low-order / non-canonical) key referenced by a submitted
        # signature, must be a fail-closed refusal that honours the (ok, reason) contract — never an
        # uncaught crash in the caller (e.g. framework's store.load_verified_authority / the launch gate).
        return False, f"authority signature material is malformed or uses a weak key: {e}"
    return result.satisfied, result.reason
