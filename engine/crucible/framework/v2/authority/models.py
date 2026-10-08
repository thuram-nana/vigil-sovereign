"""
authority.models — schemas for engagement authority and action checks.

``EngagementAuthority``, ``SignedAuthority`` and ``TargetEnvironment`` now live in the shared integrity
core (``vigil_core.authority``) so the SOVEREIGN plane — which never installs ``framework`` (the two-env
boundary, FATAL-2) — can OWNER-SIGN an authority using ``vigil_core`` alone, and this engine verifies the
byte-identical form. They are re-exported here unchanged, so every framework caller keeps resolving
against the SINGLE definition. ``ActionRequest`` / ``AuthorityState`` / ``AuthorizationDecision`` are
runtime-check types the sovereign side never needs, so they stay local.
"""

from __future__ import annotations

import enum
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

# Re-export the shared, owner-signable authority schema (single source of truth: vigil_core.authority).
from vigil_core.authority import EngagementAuthority, SignedAuthority, TargetEnvironment


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
    bug_class: str = Field(
        default="",
        description="The normalized bug class of the finding this action acts on, if any. Keyed on "
        "by the OPT-IN witness-quorum veto (conjunct 6c): empty ⇒ the quorum is never enforced for "
        "this action (byte-identical). The caller/producer may set it, but it is never trusted as a "
        "corroboration claim — the quorum RE-EXECUTES the oracle over witness_context regardless.",
    )
    witness_context: dict | None = Field(
        default=None,
        description="The finding's retained oracle_context the action acts on; RE-EXECUTED, never "
        "trusted — the witness-quorum veto recounts how many DISTINCT oracle-witness kinds re-fire "
        "over it. None ⇒ the action is not tied to a finding, so the quorum is a no-op (byte-"
        "identical). Never a promoted FACT and never a producer-carried corroboration set.",
    )


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
        "live_destructive | budget | blast_radius | witness_quorum — empty when allowed.",
    )
    checked_at: datetime


__all__ = [
    "TargetEnvironment", "EngagementAuthority", "SignedAuthority",
    "AuthorityState", "ActionRequest", "AuthorizationDecision",
]
