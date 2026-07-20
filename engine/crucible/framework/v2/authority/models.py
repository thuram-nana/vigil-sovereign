"""
authority.models — schemas for engagement authority and action checks.
"""

from __future__ import annotations

import enum
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..entitlement.models import Signature


class TargetEnvironment(str, enum.Enum):
    """Where the engagement's target lives. TWIN is a replica/digital
    twin (safe to be destructive); STAGING is a non-production deploy;
    LIVE is real production (destructive actions require a deliberate
    second acknowledgement)."""

    TWIN = "twin"
    STAGING = "staging"
    LIVE = "live"


class AuthorityState(str, enum.Enum):
    ACTIVE = "active"
    HALTED = "halted"       # kill-switch tripped
    EXPIRED = "expired"     # outside validity window


class ActionRequest(BaseModel):
    """One action the framework wants to take against the target."""

    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, description="URL or host the action touches.")
    action_kind: str = Field(default="generic", description="recon | exploit | ...")
    destructive: bool = Field(
        default=False,
        description="Would this action change state irreversibly, delete "
        "data, or risk availability? Caller classifies conservatively.",
    )
    description: str = Field(default="")


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
        description="Second, explicit acknowledgement required for "
        "destructive actions against a LIVE environment. allow_destructive "
        "alone is not enough on LIVE.",
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
    """An engagement authority plus governance signatures over its
    canonical form. Verified against the same TrustRoot the entitlement
    layer uses. Optional: a deployment may run unsigned authorities at
    lower assurance, but a high-assurance deployment requires the
    signature so a tampered scope is detected."""

    model_config = ConfigDict(extra="forbid")

    document: EngagementAuthority
    signatures: list[Signature] = Field(min_length=1)


class AuthorizationDecision(BaseModel):
    """The verdict for one action against the authority + kill-switch."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    state: AuthorityState
    target: str
    reason: str
    denial_code: str = Field(
        default="",
        description="halted | expired | out_of_scope | destructive | "
        "live_destructive | budget — empty when allowed.",
    )
    checked_at: datetime
