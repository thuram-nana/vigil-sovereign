"""Owner-signed TEST-CREDENTIAL records for an authorized engagement — the signed roster the W3
BOLA/IDOR autoseeder consumes instead of ad-hoc operator CLI flags.

Each record binds, per the IDOR/BOLA oracle's identity roles (attacker / victim / unauthorized-peer), the
HTTP auth material (header name/value pairs) the OWNER authorized for the engagement's PROVISIONED test
accounts. The owner signs the canonical form; the offense engine VERIFIES it against the same ``TrustRoot``
as the engagement authority, so the autoseeder can only ever use credentials the owner deliberately
provisioned — never an ad-hoc real account. The anonymous / logged-out baseline is NOT a credential here:
it is derived by STRIPPING auth headers.

This record holds authorization-sensitive material (session cookies / bearer tokens). Like the charter's
secrets (``targets/<slug>/loot/credentials.md``, gitignored) it is NEVER committed. Verifying it is a PURE
signature check — no runtime trust decision (scope / window / kill-switch) is made here; that stays in the
engage gate chain.

Mirrors :mod:`vigil_core.authority`: a DISTINCT domain tag over the same compact sorted-key JSON, Ed25519
m-of-n via ``verify_threshold``. Namespace-pure — imports no ``framework.*`` and no ``sigil.*`` (the
two-env boundary), so the sovereign owner signs and the offense engine verifies the IDENTICAL bytes.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .canonical import canonical_json
from .crypto import IntegrityError, sign, verify_threshold
from .models import Signature, TrustRoot

# Domain-separation prefix — distinct from authority / evidence / entitlement / delegation / spine-head,
# so a test-credential signature can never be replayed as any other kind. Never change without a schema
# bump + migration (it would invalidate every existing signed record).
_TARGET_CREDENTIALS_DOMAIN: Final[bytes] = b"crucible-target-credentials-v1\x00"

_MAX_HEADERS_PER_ROLE: Final[int] = 16   # a credential roster is small + operator-authored; cap the blob
_MAX_CREDENTIALS: Final[int] = 8


class CredentialRole(str, enum.Enum):
    """The provisioned TEST identities the IDOR/BOLA oracle's five views need. ATTACKER is the probing
    identity, VICTIM is the owner / ground-truth identity whose private object is targeted, and
    UNAUTHORIZED_PEER is a second authenticated-but-unauthorized account (the round-5 same-shape view).
    The logged-out baseline is NOT here — it is derived by stripping auth headers from the attacker send."""

    ATTACKER = "attacker"
    VICTIM = "victim"
    UNAUTHORIZED_PEER = "unauthorized_peer"


class CredentialHeader(BaseModel):
    """One HTTP auth header the identity presents (e.g. ``Cookie`` / ``Authorization``). The value is the
    secret the owner provisioned for the test account."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=256)
    value: str = Field(min_length=1, max_length=8192)


class AccountCredential(BaseModel):
    """One provisioned test identity: its role + the auth headers it presents."""

    model_config = ConfigDict(extra="forbid")

    role: CredentialRole
    auth_headers: list[CredentialHeader] = Field(min_length=1, max_length=_MAX_HEADERS_PER_ROLE)


class TargetCredentials(BaseModel):
    """The owner-authorized test-credential roster for one engagement. At most one credential per role. An
    optional validity window lets the owner expire a test-account set; the window is NOT enforced here
    (verify is a pure signature check) — the engage layer checks it at runtime against the request clock."""

    model_config = ConfigDict(extra="forbid")

    engagement_slug: str = Field(min_length=1, max_length=256)
    credentials: list[AccountCredential] = Field(min_length=1, max_length=_MAX_CREDENTIALS)
    not_before: "datetime | None" = None
    not_after: "datetime | None" = None

    @model_validator(mode="after")
    def _check(self) -> "TargetCredentials":
        roles = [c.role for c in self.credentials]
        if len(set(roles)) != len(roles):
            raise ValueError("duplicate credential role (at most one credential per role)")
        if (self.not_before is not None and self.not_after is not None
                and self.not_after <= self.not_before):
            raise ValueError("not_after must be strictly after not_before")
        return self

    def headers_for(self, role: CredentialRole) -> "list[tuple[str, str]]":
        """The ``(name, value)`` auth-header pairs for ``role``, or ``[]`` when the role is absent. The
        autoseeder maps these onto the gated send to build the victim / attacker / unauthorized identities."""
        for c in self.credentials:
            if c.role == role:
                return [(h.name, h.value) for h in c.auth_headers]
        return []


class SignedTargetCredentials(BaseModel):
    """A :class:`TargetCredentials` roster plus owner governance signatures over its canonical form.
    Verified against the same ``TrustRoot`` the engagement authority uses."""

    model_config = ConfigDict(extra="forbid")

    document: TargetCredentials
    signatures: list[Signature] = Field(min_length=1)


def target_credentials_signing_bytes(document: TargetCredentials) -> bytes:
    """The exact bytes an owner signs / a verifier checks: the domain tag followed by the compact,
    sorted-key UTF-8 JSON of the document."""
    return _TARGET_CREDENTIALS_DOMAIN + canonical_json(document.model_dump(mode="json"))


def sign_target_credentials(
    document: TargetCredentials, signers: dict[str, str]
) -> SignedTargetCredentials:
    """Sign a roster with each ``key_id -> private_key_b64`` (owner-side; the private key is used only
    inside :func:`sign` and never persisted or returned). The caller supplies at least the trust root's
    threshold of authorised signers."""
    msg = target_credentials_signing_bytes(document)
    signatures = [
        Signature(key_id=key_id, signature_b64=sign(priv_b64, msg))
        for key_id, priv_b64 in signers.items()
    ]
    return SignedTargetCredentials(document=document, signatures=signatures)


def verify_target_credentials(
    signed: SignedTargetCredentials, trust_root: TrustRoot
) -> "tuple[bool, str]":
    """Return ``(ok, reason)``. True iff at least the trust root's threshold of DISTINCT authorisers validly
    signed the roster's canonical form. Verify-only, fail-CLOSED, never raises — mirrors
    :func:`vigil_core.authority.verify_engagement_authority`, including rejecting a quorum-collapsing trust
    root (duplicate authorizer PUBLIC KEYS under distinct key_ids), so the consumer that cannot tolerate a
    collapsed m-of-n — an engagement's offense test identities — refuses it here."""
    pubkeys = [a.public_key_b64 for a in trust_root.authorizers]
    if len(set(pubkeys)) != len(pubkeys):
        return False, "trust root has duplicate authorizer public keys (would collapse the m-of-n quorum)"
    try:
        result = verify_threshold(
            target_credentials_signing_bytes(signed.document), signed.signatures, trust_root
        )
    except (IntegrityError, TypeError, ValueError) as e:   # ValueError: a document that cannot be UTF-8 encoded
        return False, f"test-credential signature material is malformed or uses a weak key: {e}"
    return result.satisfied, result.reason


__all__ = [
    "CredentialRole",
    "CredentialHeader",
    "AccountCredential",
    "TargetCredentials",
    "SignedTargetCredentials",
    "target_credentials_signing_bytes",
    "sign_target_credentials",
    "verify_target_credentials",
]
