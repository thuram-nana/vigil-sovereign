"""
authority — scoped, time-boxed engagement authority and the kill-switch.

This is the "fire at the twin first, and stop instantly if it goes
sideways" discipline, enforced in code. Two pieces:

  - **EngagementAuthority** — a per-engagement authorization carrying the
    in-scope hosts, a validity window, the target environment
    (TWIN / STAGING / LIVE), whether destructive actions are permitted,
    and an action budget. Every action is checked against it.
  - **KillSwitch** — a persistent, fail-closed hard stop. Tripping it
    halts all further authorization immediately and *survives a process
    restart* (it is a file on disk): once tripped, the engagement stays
    halted until a human clears it or issues a new authority.

Design stance (the opposite of an autonomous, unstoppable weapon): the
authority is narrow, the kill-switch is absolute, live-destructive
actions require a deliberate double acknowledgement, and high-risk work
is meant to run against a TWIN replica before a LIVE target. This is what
makes autonomy trustworthy rather than dangerous.

This composes with — and is distinct from — the entitlement layer:
entitlement says *which capabilities this deployment may run at all*;
authority says *what this specific engagement may do, to what, until
when, and with an instant off-switch*.

Public surface:

    from framework.v2.authority import (
        TargetEnvironment, AuthorityState, ActionRequest,
        EngagementAuthority, AuthorizationDecision,
        KillSwitch, authorize_action, require_authorization,
    )
"""

from __future__ import annotations

from .authorization import (
    EngagementAuthorization,
    EngagementAuthorizationDecision,
    EngagementExecutor,
    SignedEngagementAuthorization,
    action_danger,
    authorization_signing_bytes,
    authorize_engagement_action,
    sign_authorization,
    verify_authorization,
)
from .charter import authority_from_charter, authority_from_scope
from .crosscheck import (
    EnvelopeCrossCheck,
    ScopeCrossCheck,
    assert_envelope_consistent,
    assert_scope_consistent,
    crosscheck_envelope,
    crosscheck_scope,
    parse_envelope_declaration,
    parse_scope_table,
)
from .gate import authorize_action, require_authorization
from .killswitch import KillSwitch
from .models import (
    ActionRequest,
    AuthorityState,
    AuthorizationDecision,
    EngagementAuthority,
    SignedAuthority,
    TargetEnvironment,
)
from .signing import sign_authority, verify_authority

__all__ = [
    "TargetEnvironment",
    "AuthorityState",
    "ActionRequest",
    "EngagementAuthority",
    "SignedAuthority",
    "AuthorizationDecision",
    "KillSwitch",
    "authorize_action",
    "require_authorization",
    "sign_authority",
    "verify_authority",
    "authority_from_charter",
    "authority_from_scope",
    # W13-3 — signed EngagementAuthorization + executor + three-leg cross-check
    "EngagementAuthorization",
    "SignedEngagementAuthorization",
    "EngagementAuthorizationDecision",
    "EngagementExecutor",
    "authorize_engagement_action",
    "action_danger",
    "sign_authorization",
    "verify_authorization",
    "authorization_signing_bytes",
    "ScopeCrossCheck",
    "crosscheck_scope",
    "assert_scope_consistent",
    "parse_scope_table",
    "EnvelopeCrossCheck",
    "crosscheck_envelope",
    "assert_envelope_consistent",
    "parse_envelope_declaration",
]
