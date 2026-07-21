"""
vigil_integration.fireteam — governed parallel specialist sub-agents (VIGIL-FUSION F6, C5).

A port of redamon's fireteam subsystem (fan-out/fan-in ReAct wave) through the sovereign core. The
guarantees the whole package exists to enforce, all fail-closed and testable with injected callables:

  * a member carries a **capped WARDEN tier** that can never be A3; ``_strip_forbidden_actions``
    structurally removes ``deploy_fireteam`` / ``transition_phase`` / egress from a member's decision;
  * a member can NOT self-escalate its tier or self-authorize a dangerous tool — an over-cap or
    destructive tool becomes a QUEUED escalation resolved ONLY by an injected signed operator approval
    (``ConfirmationRegistry``), never auto;
  * a per-member **credit + deadline** bounds each run deterministically (injected sequence, no wallclock);
  * ALL member spine writes serialize behind ONE writer (``SingleWriterSpineQueue``) so the append-only
    signed chain is never interleaved; records are secret-redacted;
  * ``collect`` rolls up member findings as LEADs and promotes ONLY oracle-reconfirmed FACTs.

Import-clean: pydantic + stdlib, reusing the F2 (agent) / F3 (tools) seams; no framework/strix/network.
"""

from __future__ import annotations

from .collect import CollectOutcome, collect
from .confirmation import (
    ApproverFn,
    ConfirmationOutcome,
    ConfirmationRegistry,
    ConfirmationResolution,
    PendingConfirmation,
)
from .member import (
    FORBIDDEN_MEMBER_ACTIONS,
    FireteamMember,
    MemberBudget,
    MemberEdgeVerdict,
    MemberStepOutcome,
    authorize_member_edge,
    parse_member_decision,
    run_member_step,
)
from .models import (
    ALLOWED_MEMBER_TIERS,
    CONFIRMATION_DEADLINE_TICKS,
    DEFAULT_MEMBER_TIER,
    FIRETEAM_MAX_CONCURRENT,
    FIRETEAM_MAX_MEMBERS,
    FIRETEAM_MEMBER_MAX_ITERATIONS,
    MEMBER_TIER_CEILING,
    EscalationRequest,
    FireteamMemberSpec,
    FireteamPlan,
    MemberFindingClaim,
    MemberResult,
    MemberStatus,
    parse_fireteam_plan,
)
from .orchestrator import (
    FireteamOutcome,
    MemberRunContext,
    MemberRunner,
    run_fireteam,
)
from .spine_queue import QueuedWrite, SingleWriterSpineQueue

__all__ = [
    # models
    "FireteamMemberSpec", "FireteamPlan", "MemberResult", "MemberStatus", "MemberFindingClaim",
    "EscalationRequest", "parse_fireteam_plan",
    "FIRETEAM_MAX_MEMBERS", "FIRETEAM_MAX_CONCURRENT", "FIRETEAM_MEMBER_MAX_ITERATIONS",
    "ALLOWED_MEMBER_TIERS", "MEMBER_TIER_CEILING", "DEFAULT_MEMBER_TIER", "CONFIRMATION_DEADLINE_TICKS",
    # member
    "FireteamMember", "MemberBudget", "MemberEdgeVerdict", "MemberStepOutcome",
    "authorize_member_edge", "run_member_step", "parse_member_decision", "FORBIDDEN_MEMBER_ACTIONS",
    # confirmation
    "ConfirmationRegistry", "ConfirmationOutcome", "ConfirmationResolution", "PendingConfirmation",
    "ApproverFn",
    # spine queue
    "SingleWriterSpineQueue", "QueuedWrite",
    # collect + orchestrator
    "collect", "CollectOutcome", "run_fireteam", "FireteamOutcome", "MemberRunContext", "MemberRunner",
]
