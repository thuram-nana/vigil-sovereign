"""Integrity + trust models.

VENDORED from CRUCIBLE `framework/v2/{entitlement,evidence}/models.py` (owner's own work),
copied verbatim so SIGIL is self-contained. Only the classes the spine chain needs.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

_GENESIS_PREV: str = "0" * 64


# --- trust (entitlement/models.py) ----------------------------------------------------
class Signature(BaseModel):
    """One authoriser signature over a canonicalised document."""
    model_config = ConfigDict(extra="forbid")
    key_id: str = Field(min_length=1)
    signature_b64: str = Field(min_length=1, description="base64(64-byte Ed25519 signature).")


class AuthorizerKey(BaseModel):
    """One authoriser's Ed25519 public key (base64 of the 32-byte raw pubkey)."""
    model_config = ConfigDict(extra="forbid")
    key_id: str = Field(min_length=1, description="Stable authoriser id.")
    name: str = Field(min_length=1, description="Human-readable authoriser name.")
    public_key_b64: str = Field(min_length=1, description="base64(32-byte Ed25519 pubkey).")


class TrustRoot(BaseModel):
    """The authoriser set + threshold a deployment trusts (m-of-n; 1 covers a solo owner)."""
    model_config = ConfigDict(extra="forbid")
    schema_version: int = Field(default=1, ge=1)
    threshold: int = Field(ge=1, description="m in m-of-n. 1 also covers FROST group keys.")
    authorizers: list[AuthorizerKey] = Field(min_length=1)

    @model_validator(mode="after")
    def _check(self) -> "TrustRoot":
        ids = [a.key_id for a in self.authorizers]
        if len(set(ids)) != len(ids):
            raise ValueError("trust root has duplicate authoriser key_ids")
        if self.threshold > len(self.authorizers):
            raise ValueError(f"threshold {self.threshold} exceeds authoriser count {len(self.authorizers)}")
        return self


# --- chain (evidence/models.py) -------------------------------------------------------
class ChainEntry(BaseModel):
    """One link in the tamper-evident spine. `entry_hash` chains prev+cert+seq."""
    model_config = ConfigDict(extra="forbid")
    seq: int = Field(ge=0)
    prev_hash: str = _GENESIS_PREV
    cert_digest: str
    entry_hash: str


class SignedChainHead(BaseModel):
    """The signed anchor of the spine. `last_seq` is monotonic (anti-rollback)."""
    model_config = ConfigDict(extra="forbid")
    schema_version: int = 1
    engagement_slug: str = ""   # SIGIL: the owner scope
    last_seq: int = Field(ge=0)
    entry_count: int = Field(ge=0)
    head_hash: str
    signatures: list[Signature] = Field(default_factory=list)
