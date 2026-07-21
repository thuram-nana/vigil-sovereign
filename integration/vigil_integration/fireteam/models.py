"""
fireteam.models — typed specs/results for the governed parallel specialist wave (VIGIL-FUSION F6, C5).

redamon's fireteam subsystem lets a root ReAct agent fan out 1-8 specialist sub-agents, run them
concurrently under caps, and merge results back. VIGIL keeps that SHAPE but bakes the sovereign
distinctions into the TYPES:

  * a ``FireteamMemberSpec`` carries a **capped WARDEN tier** that can NEVER be ``A3`` — post-
    exploitation/destructive authority (which requires the m-of-n threshold-destruction leg) is the
    parent's + operator's alone, never a sub-agent's. An out-of-range cap is refused fail-closed.
  * a ``FireteamPlan`` is validated whole: bounded member count, unique ids, and a singleton/mutex
    check so two members can't both claim a non-shareable resource (metasploit, burp, …). A malformed
    plan is refused (``parse_fireteam_plan`` returns ``None``) — never partially spawned.
  * every member finding is a proposal (``MemberResult.leads`` / ``.claims``); nothing here is a fact.
    ``fireteam.collect`` promotes a claim to a FACT only when the injected deterministic oracle
    re-fires (see :mod:`fireteam.collect`).

Import-clean: pydantic + stdlib, reusing the F2 phase/tier types and the F3 destructive-name floor.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..agent.state import Finding, OutputAnalysis
from ..tools.governance import is_destructive_tool

# --- caps / bounds (deterministic constants — never a wallclock) ---------------------------------

FIRETEAM_MAX_MEMBERS = 5            # a wave is bounded; a bigger plan is refused fail-closed
FIRETEAM_MAX_CONCURRENT = 3         # at most this many members run at once
FIRETEAM_MEMBER_MAX_ITERATIONS = 10  # default per-member credit budget (tool executions)
ALLOWED_MEMBER_TIERS = ("A0", "A1", "A2")  # a member can NEVER hold A3 (destructive/post-exploit)
MEMBER_TIER_CEILING = "A2"
DEFAULT_MEMBER_TIER = "A1"
# a confirmation escalation auto-REJECTS this many injected-sequence ticks after it is registered
# (ticks, NOT seconds — the whole subsystem is deterministic and free of the wallclock).
CONFIRMATION_DEADLINE_TICKS = 600

_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

# Singleton resources that two parallel members must not both claim (a static, pre-spawn mutex guard).
# Destructive tools are singletons too (via the F3 name floor), so the two families compose.
_SINGLETON_TOOLS = frozenset({
    "metasploit", "metasploit_console", "msfconsole", "msfdb", "msfvenom",
    "nessus", "openvas", "burpsuite", "burp", "zaproxy", "sqlmap",
})


def _is_singleton_tool(name: Any) -> bool:
    if not isinstance(name, str) or not name:
        return False
    return name.lower() in _SINGLETON_TOOLS or is_destructive_tool(name)


class MemberStatus(str, Enum):
    """Terminal status of a member run (mirrors redamon's set, deny-by-default framed)."""

    SUCCESS = "success"
    PARTIAL = "partial"
    COMPLETE = "complete"
    ERROR = "error"                    # the member crashed — isolated, never crashes the wave
    TIMEOUT = "timeout"                # ran past its deterministic deadline_seq
    DENIED = "denied"                  # the gate refused its action
    NEEDS_CONFIRMATION = "needs_confirmation"  # a dangerous/over-cap tool → queued for signed approval
    REFUSED = "refused"                # the member spec/plan was malformed → never spawned


class FireteamMemberSpec(BaseModel):
    """One specialist sub-agent's charter. FROZEN so a caller cannot mutate a validated cap after the
    fact. ``capped_tier`` is the member's WARDEN ceiling; ``credit`` bounds its tool executions and
    ``deadline_seq`` bounds it in the injected-sequence space (never in wallclock time)."""

    model_config = ConfigDict(frozen=True)

    member_id: str
    role: str = ""
    capped_tier: str = DEFAULT_MEMBER_TIER
    tools: tuple[str, ...] = ()        # declared/primary tools the member may reach
    credit: int = FIRETEAM_MEMBER_MAX_ITERATIONS
    deadline_seq: int = 0              # 0 ⇒ filled from the wave's seq window by the orchestrator

    @field_validator("member_id")
    @classmethod
    def _valid_id(cls, v: str) -> str:
        if not isinstance(v, str) or not _ID_RE.match(v):
            raise ValueError("member_id must be a short [A-Za-z0-9_.:-] token")
        return v

    @field_validator("capped_tier")
    @classmethod
    def _tier_in_range(cls, v: str) -> str:
        # A member can NEVER hold A3 (or an unknown tier) — that is the sovereign cap. Refuse fail-closed.
        if v not in ALLOWED_MEMBER_TIERS:
            raise ValueError(f"capped_tier {v!r} not in {ALLOWED_MEMBER_TIERS} "
                             "(a member can never hold A3 or an unknown tier)")
        return v

    @field_validator("tools", mode="before")
    @classmethod
    def _clean_tools(cls, v: Any) -> tuple[str, ...]:
        if isinstance(v, str):
            v = [v]
        if not isinstance(v, (list, tuple, set)):
            return ()
        out: list[str] = []
        for t in v:
            if isinstance(t, str) and t.strip():
                out.append(t.strip())
        return tuple(out)

    @field_validator("credit")
    @classmethod
    def _credit_bounded(cls, v: int) -> int:
        if not isinstance(v, int) or isinstance(v, bool) or v < 1 or v > FIRETEAM_MEMBER_MAX_ITERATIONS:
            raise ValueError(f"credit must be an int in 1..{FIRETEAM_MEMBER_MAX_ITERATIONS}")
        return v

    @field_validator("deadline_seq")
    @classmethod
    def _deadline_nonneg(cls, v: int) -> int:
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            raise ValueError("deadline_seq must be a non-negative int")
        return v


class FireteamPlan(BaseModel):
    """A validated fan-out plan. FROZEN. The whole plan is refused if any member is malformed, the
    count is out of ``1..FIRETEAM_MAX_MEMBERS``, ids collide, or two members claim the same singleton
    tool — there is no partial spawn."""

    model_config = ConfigDict(frozen=True)

    wave_id: str
    members: tuple[FireteamMemberSpec, ...]

    @field_validator("wave_id")
    @classmethod
    def _valid_wave(cls, v: str) -> str:
        if not isinstance(v, str) or not _ID_RE.match(v):
            raise ValueError("wave_id must be a short [A-Za-z0-9_.:-] token")
        return v

    @model_validator(mode="after")
    def _bounded_unique_mutex(self) -> "FireteamPlan":
        n = len(self.members)
        if n < 1:
            raise ValueError("a fireteam needs at least one member")
        if n > FIRETEAM_MAX_MEMBERS:
            raise ValueError(f"a fireteam is capped at {FIRETEAM_MAX_MEMBERS} members (got {n})")
        ids = [m.member_id for m in self.members]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate member_id in plan")
        counts: dict[str, int] = {}
        for m in self.members:
            for t in m.tools:
                if _is_singleton_tool(t):
                    counts[t.lower()] = counts.get(t.lower(), 0) + 1
        clashes = sorted(t for t, c in counts.items() if c > 1)
        if clashes:
            raise ValueError(f"mutex: singleton tool(s) {clashes} claimed by more than one member")
        return self


class MemberFindingClaim(BaseModel):
    """A member's raw tool output + its inline analysis CLAIMS. Never a fact — ``fireteam.collect``
    hands ``raw_output``/``analysis`` to the injected oracle (via ``agent.react.intake_result``); only
    an oracle confirmation over the retained raw output mints a FACT."""

    raw_output: str = ""
    analysis: OutputAnalysis = Field(default_factory=OutputAnalysis)
    source: str = ""


class EscalationRequest(BaseModel):
    """A member's request to run a dangerous / over-cap tool. It is QUEUED for a signed operator
    approval (never auto-run). FROZEN so its binding can't be tampered between register and resolve."""

    model_config = ConfigDict(frozen=True)

    wave_id: str
    member_id: str
    tool_name: str
    target: str = ""
    requested_tier: str = "A3"
    reason: str = ""
    seq: int = 0

    def binding_key(self) -> tuple[str, str, int]:
        """The deterministic identity of this escalation (no wallclock, no RNG). The injected approver
        MUST bind its signature to this tuple so one approval can't be replayed onto another edge."""
        return (self.wave_id, self.member_id, self.seq)


class MemberResult(BaseModel):
    """What a member run returns to the fan-in. Everything here is a PROPOSAL: ``leads`` are candidate
    findings and ``claims`` are raw-output+analysis pairs the oracle re-checks. ``collect`` downgrades
    any member-supplied finding to a LEAD regardless of the status it carries."""

    member_id: str
    status: MemberStatus = MemberStatus.COMPLETE
    leads: list[Finding] = Field(default_factory=list)
    claims: list[MemberFindingClaim] = Field(default_factory=list)
    escalations: list[EscalationRequest] = Field(default_factory=list)
    iterations_used: int = 0
    credit_used: int = 0
    notes: str = ""


def parse_fireteam_plan(obj: Any) -> "FireteamPlan | None":
    """Fail-closed plan intake: validate ``obj`` (a dict from the LLM's ``deploy_fireteam`` proposal,
    or a ready ``FireteamPlan``) into a bounded, mutex-checked plan. On ANY malformation return
    ``None`` — a broken plan is REFUSED, never partially spawned. Never raises."""
    if isinstance(obj, FireteamPlan):
        return obj
    try:
        return FireteamPlan.model_validate(obj)
    except Exception:  # noqa: BLE001 — a malformed plan is a refusal, not a crash
        return None
