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

from .charter import authority_from_charter, authority_from_scope
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
]
