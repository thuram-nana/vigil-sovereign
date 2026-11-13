"""vigil_core.model_grant — the owner-signed per-run MODEL GRANT (PRICING M1b; design §2.3).

A customer run's model requests go through the SOVEREIGN model gateway, never straight to the provider. The keyless
offense plane does not hold the provider API key; at launch the sovereign plane mints this grant and hands the
offense runner its token, which the runner presents to the gateway as its API key. The grant binds:

  * ONE launch — ``org_id``, ``engagement_slug`` and the launch ``nonce`` (the same nonce the credit lease and the
    settle signal carry), so the gateway's meter for this grant is the meter for that launch;
  * the ``model`` the run may use and the ``effort`` it runs at (the depth's effort, design §3);
  * ``cap_nano_usd`` — the most the run's model requests may cost VIGIL (``usd_cap_nano_for_credits`` of the
    reservation), so a run can never spend past what the customer approved;
  * ``not_after`` — the grant is useless after it.

``grant_id`` is 128 random bits: together with the owner signature it makes the token unguessable AND unforgeable.
The token is a bearer credential (whoever holds it can spend up to its cap until it expires), so it is handed only
to the runner of that launch and never logged; its spend is bounded by the cap and the expiry.

Token format (``vmg1``)::

    vmg1.<base64url(canonical JSON of the grant)>.<base64url(Ed25519 signature)>

The signature covers the distinct domain tag ``model-grant`` + the canonical JSON, so it can never verify as a lease,
a completion or an authority (or vice-versa). :func:`decode_token` is total and fail-closed: any malformed, oversized,
wrongly-signed or schema-invalid token is refused with a reason, never raised out of the gateway.

Pure, framework-free (FATAL-2), like the rest of ``vigil_core``.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .canonical import canonical_json
from .crypto import IntegrityError, sign, verify_one
from .spine_domains import DOMAIN_TAGS

__all__ = ["EFFORTS", "MAX_GRANT_LIFETIME_S", "ModelGrant", "TOKEN_PREFIX", "decode_token", "encode_token", "meter_id",
           "model_grant_signing_bytes", "new_grant_id"]

_MODEL_GRANT_DOMAIN = DOMAIN_TAGS["model-grant"]
TOKEN_PREFIX = "vmg1"
EFFORTS = ("high", "xhigh", "max")            # design §3: Quick = high, Deep = xhigh, Max / Fix = max
_MAX_TOKEN_CHARS = 4096                       # a real token is ~500 chars; anything far larger is refused unread
MAX_GRANT_LIFETIME_S = 7 * 86_400 + 3_600     # a launch lease lasts at most a week; a grant never outlives one


def new_grant_id() -> str:
    """128 random bits as 32 lowercase hex characters."""
    return secrets.token_hex(16)


def meter_id(engagement_slug: str, nonce: str) -> str:
    """The id of ONE launch's meter: 32 hex characters of ``sha256(engagement_slug NUL nonce)``. Every grant minted
    for the same launch meters into the same meter, and the settle step finds it from the owner-signed lease's
    ``(engagement_slug, nonce)`` alone — one tenant's spend can never land on another launch's bill."""
    if "\x00" in engagement_slug or "\x00" in nonce:
        raise ValueError("an engagement slug and a nonce never contain NUL (it separates them in the meter id)")
    return hashlib.sha256(f"{engagement_slug}\x00{nonce}".encode("utf-8")).hexdigest()[:32]


class ModelGrant(BaseModel):
    """One launch's permission to spend on the model, signed by the owner."""

    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    grant_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    org_id: str = Field(min_length=1, max_length=200)
    # no control characters: NUL separates the two in the meter id, so "a\0b" + "c" must never equal "a" + "b\0c"
    engagement_slug: str = Field(min_length=1, max_length=200, pattern=r"^[^\x00-\x1f\x7f]+$")
    nonce: str = Field(min_length=1, max_length=200, pattern=r"^[^\x00-\x1f\x7f]+$")
    model: str = Field(min_length=1, max_length=100)
    effort: str = Field(pattern=r"^(high|xhigh|max)$")
    cap_nano_usd: int = Field(ge=0, le=10 ** 15)        # at most $1,000,000 per run
    not_after: float = Field(gt=0)
    issued_at: float = Field(gt=0)

    @model_validator(mode="after")
    def _expires_after_issue(self) -> "ModelGrant":
        if self.not_after <= self.issued_at:
            raise ValueError("a model grant must expire after it is issued")
        if self.not_after - self.issued_at > MAX_GRANT_LIFETIME_S:
            raise ValueError("a model grant may last at most a week (its launch lease's longest life)")
        return self

    @property
    def meter_id(self) -> str:
        return meter_id(self.engagement_slug, self.nonce)


def model_grant_signing_bytes(grant: ModelGrant) -> bytes:
    return _MODEL_GRANT_DOMAIN + canonical_json(grant.model_dump(mode="json"))


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64u(text: str) -> bytes:
    if not text or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in text):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def encode_token(grant: ModelGrant, owner_private_key_b64: str) -> str:
    """Sign ``grant`` with the owner key and return its bearer token. Sovereign-side only."""
    body = canonical_json(grant.model_dump(mode="json"))
    sig = base64.b64decode(sign(owner_private_key_b64, _MODEL_GRANT_DOMAIN + body))
    return f"{TOKEN_PREFIX}.{_b64u(body)}.{_b64u(sig)}"


def decode_token(token: object, owner_public_key_b64: Optional[str]) -> "tuple[Optional[ModelGrant], str]":
    """``(grant, "")`` iff ``token`` is a well-formed ``vmg1`` token whose signature verifies under the owner key and
    whose body is a valid :class:`ModelGrant` in canonical form; otherwise ``(None, reason)``. Never raises.
    Expiry and spend are the gateway's checks, not this function's."""
    if not owner_public_key_b64:
        return None, "no owner public key to verify against"
    if not isinstance(token, str) or not token or len(token) > _MAX_TOKEN_CHARS:
        return None, "missing or oversized token"
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        return None, "not a model grant token"
    try:
        body, sig = _unb64u(parts[1]), _unb64u(parts[2])
    except (ValueError, binascii.Error):
        return None, "token is not valid base64url"
    if _b64u(body) != parts[1] or _b64u(sig) != parts[2]:
        return None, "token is not canonical base64url"      # one grant has exactly one token string
    if len(sig) != 64:
        return None, "token signature has the wrong length"
    try:
        ok = verify_one(owner_public_key_b64, _MODEL_GRANT_DOMAIN + body,
                        base64.b64encode(sig).decode("ascii"))
    except (IntegrityError, ValueError):
        return None, "token signature material is malformed"
    if not ok:
        return None, "token signature does not verify under the owner key"
    try:
        doc = json.loads(body.decode("utf-8"))
        grant = ModelGrant.model_validate(doc)
    except (ValueError, UnicodeDecodeError, ValidationError):
        return None, "token body is not a valid model grant"
    if canonical_json(grant.model_dump(mode="json")) != body:
        return None, "token body is not in canonical form"
    return grant, ""
