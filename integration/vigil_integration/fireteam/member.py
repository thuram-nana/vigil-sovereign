"""
fireteam.member — a tier-scoped sub-agent step, structurally unable to escape its box (VIGIL-FUSION F6).

This is the sovereign heart of the fireteam. Three structural guarantees, each fail-closed:

  * ``_strip_forbidden_actions`` — a member's proposed decision is rewritten to COMPLETE *before* the
    edge is classified or any gate is consulted if it is a forbidden action. A member can NOT
    ``deploy_fireteam`` (no recursive fan-out → fan-out explosion is impossible by construction), NOT
    ``transition_phase`` (can't escalate the engagement), NOT ``ask_user``/``switch_skill`` (parent-
    level HITL/config), and NOT cross the egress gate (an egress-control tool is stripped). This is a
    structural bound on the DECISION, not a prompt instruction the model could talk past.
  * ``authorize_member_edge`` — a target-touching tool call is checked against the member's **capped
    WARDEN tier** BEFORE the injected conjunctive gate is consulted. If the tool's required tier
    exceeds the cap, or the tool is destructive (re-derived from the tool NAME via the F3 floor, never
    trusted from the member's own flag), the edge does NOT run — it becomes a QUEUED escalation for a
    signed operator approval. A member can never self-escalate its tier or self-authorize a dangerous
    tool. Only a within-cap, non-destructive edge reaches the gate, whose verdict then decides
    (fail-closed on a missing gate / a gate error).
  * a per-member **credit + deadline** bounds the run deterministically in the injected-sequence space
    (``seq``), never in wallclock time.

Reuses the F2 pure policy (``agent.react.classify_edge``, ``agent.phases.tool_tier``) and the F3
destructive-name floor (``tools.governance.is_destructive_tool``). Import-clean; the gate is injected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..agent.phases import TIER_ORDER, tool_tier
from ..agent.react import classify_edge, parse_decision
from ..agent.state import ActionType, LLMDecision, Phase
from ..tools.governance import is_destructive_tool
from .models import EscalationRequest, FireteamMemberSpec, MemberStatus

# Actions a member may NEVER take — rewritten to COMPLETE by _strip_forbidden_actions. deploy_fireteam
# and transition_phase are the load-bearing two (recursion + phase escalation); ask_user and
# switch_skill are parent-level and are stripped for the same structural-bound reason as redamon.
FORBIDDEN_MEMBER_ACTIONS = frozenset({
    ActionType.DEPLOY_FIRETEAM,
    ActionType.TRANSITION_PHASE,
    ActionType.ASK_USER,
    ActionType.SWITCH_SKILL,
})

# Tool names that OPEN/cross the egress gate. A member never authorizes egress itself; naming one of
# these (or any tool whose name carries "egress") is stripped to COMPLETE. Its legitimate target-
# touching work still flows through the injected conjunctive gate (which embeds the egress leg).
_EGRESS_CONTROL_TOOLS = frozenset({
    "open_egress", "egress", "egress_gate", "allow_egress", "egress_allow",
    "netns_egress", "open_egress_gate", "egress_open", "unblock_egress",
})


def _is_egress_control(name: Any) -> bool:
    if not isinstance(name, str) or not name:
        return False
    n = name.lower()
    return n in _EGRESS_CONTROL_TOOLS or "egress" in n


def _tier_index(t: Any) -> int:
    """Index of a WARDEN tier; an unknown tier resolves to STRICTER-than-A3 so it can only DENY."""
    try:
        return TIER_ORDER.index(t)
    except (ValueError, TypeError):
        return len(TIER_ORDER)


def _complete(reason: str) -> LLMDecision:
    return LLMDecision(action=ActionType.COMPLETE, reasoning=reason, summary=reason)


def _strip_forbidden_actions(decision: Any) -> tuple[LLMDecision, str]:
    """Rewrite a forbidden member action to COMPLETE, returning ``(safe_decision, stripped_reason)``.

    Total on untrusted input: a non-``LLMDecision`` (or a malformed one) degrades to a COMPLETE, never
    raises. The stripped_reason is empty when nothing was stripped."""
    if not isinstance(decision, LLMDecision):
        return _complete("malformed member decision → complete"), "malformed member decision"
    a = decision.action
    if a in FORBIDDEN_MEMBER_ACTIONS:
        reason = f"forbidden member action {a.value!r} stripped → complete"
        return _complete(reason), reason
    if a == ActionType.USE_TOOL and decision.tool is not None and _is_egress_control(decision.tool.tool_name):
        reason = f"member may not cross the egress gate (tool {decision.tool.tool_name!r}) → complete"
        return _complete(reason), reason
    if a == ActionType.PLAN_TOOLS and any(
        _is_egress_control(getattr(t, "tool_name", "")) for t in decision.plan
    ):
        reason = "member plan names an egress-control tool → complete"
        return _complete(reason), reason
    return decision, ""


def parse_member_decision(text: str) -> tuple[LLMDecision, str]:
    """Parse a raw member LLM response fail-closed (via the F2 ``parse_decision``) and THEN strip
    forbidden actions. Never yields a ``deploy_fireteam``/``transition_phase``/egress edge from a
    member, regardless of what the model emitted."""
    return _strip_forbidden_actions(parse_decision(text))


@dataclass(frozen=True)
class MemberEdgeVerdict:
    """The authorization outcome for one member decision. ``outcome`` ∈ {allow, queue, deny}. A
    ``queue`` carries an :class:`EscalationRequest` that MUST be resolved by a signed operator
    approval before the edge could ever run."""

    allowed: bool
    outcome: str
    reason: str
    tier: str = "A0"
    escalation: Optional[EscalationRequest] = None
    stripped: str = ""


def authorize_member_edge(
    member: "FireteamMember",
    decision: Any,
    *,
    gate: Optional[Callable[..., Any]] = None,
    seq: int = 0,
) -> MemberEdgeVerdict:
    """Authorize one member decision, fail-closed. Order: (1) strip forbidden actions; (2) classify the
    edge with the F2 pure policy; (3) an inert/denied edge resolves immediately; (4) a target-touching
    tool call is capped at the member's tier and re-checked for destructiveness — over-cap OR
    destructive → a QUEUED escalation (never auto-run); (5) an in-cap, non-destructive call reaches the
    injected gate, whose verdict decides (no gate / gate error → DENY). Never raises."""
    safe, stripped = _strip_forbidden_actions(decision)
    phase = member.phase
    spec = classify_edge(safe, phase)
    if spec.denied:
        return MemberEdgeVerdict(False, "deny", f"invalid member edge (fail-closed): {spec.reason}",
                                 spec.tier, stripped=stripped)
    if spec.inert:
        reason = stripped or spec.reason
        return MemberEdgeVerdict(True, "allow", reason, spec.tier, stripped=stripped)
    tool = safe.tool
    if tool is None:  # defensive — classify_edge already denies this, but never trust a single check
        return MemberEdgeVerdict(False, "deny", "target-touching edge without a tool (fail-closed)",
                                 spec.tier, stripped=stripped)
    # Re-derive destructiveness from the tool NAME (raise-only floor); NEVER trust the member's flag —
    # a member claiming a dangerous tool is "non-destructive" must not dodge the escalation.
    destructive = is_destructive_tool(tool.tool_name, declared=spec.destructive)
    required = tool_tier(phase, destructive=destructive)
    over_cap = _tier_index(required) > _tier_index(member.capped_tier)
    if over_cap or destructive:
        why = (f"tool {tool.tool_name!r} needs {required} which exceeds member cap "
               f"{member.capped_tier}" if over_cap else f"tool {tool.tool_name!r} is destructive")
        esc = EscalationRequest(
            wave_id=member.wave_id, member_id=member.member_id, tool_name=tool.tool_name,
            target=spec.target, requested_tier=required,
            reason=f"{why} → queued for signed operator approval", seq=int(seq),
        )
        return MemberEdgeVerdict(False, "queue", esc.reason, required, escalation=esc, stripped=stripped)
    if gate is None:
        return MemberEdgeVerdict(False, "deny",
                                 "no conjunctive gate wired — a member tool call cannot proceed "
                                 "(fail-closed)", required, stripped=stripped)
    try:
        verdict = gate(tool.tool_name, spec.target, destructive)
    except Exception as exc:  # noqa: BLE001 — any gate error is a DENY, never caught-and-continued
        return MemberEdgeVerdict(False, "deny", f"gate error (fail-closed): {exc}", required,
                                 stripped=stripped)
    raw_outcome = getattr(verdict, "outcome", "deny")
    allowed = getattr(verdict, "allowed", False) is True and raw_outcome == "allow"
    outcome = "allow" if allowed else ("queue" if raw_outcome == "queue" else "deny")
    return MemberEdgeVerdict(allowed, outcome, getattr(verdict, "reason", "") or
                             ("member tool call authorized" if allowed else "member tool call not authorized"),
                             required, stripped=stripped)


@dataclass
class MemberBudget:
    """A deterministic per-member bound: ``credit_remaining`` (tool executions left) + ``deadline_seq``
    (the last injected-sequence tick the member may act on). No wallclock, no RNG."""

    credit_remaining: int
    deadline_seq: int

    def expired(self, seq: int) -> bool:
        """Strict-greater, matching redamon's ``current_iter > max_iter`` router bound."""
        return int(seq) > self.deadline_seq

    def spend(self, n: int = 1) -> None:
        self.credit_remaining = max(0, self.credit_remaining - int(n))


@dataclass
class FireteamMember:
    """A live specialist sub-agent: its immutable spec + the engagement phase it runs in + a mutable
    credit/deadline budget. The cap ``capped_tier`` can never be A3 (enforced at the spec type)."""

    spec: FireteamMemberSpec
    wave_id: str
    phase: Phase = Phase.INFORMATIONAL
    budget: MemberBudget = field(default=None)  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.budget is None:
            self.budget = MemberBudget(credit_remaining=self.spec.credit,
                                       deadline_seq=self.spec.deadline_seq)

    @property
    def member_id(self) -> str:
        return self.spec.member_id

    @property
    def capped_tier(self) -> str:
        return self.spec.capped_tier


@dataclass(frozen=True)
class MemberStepOutcome:
    """The result of advancing a member one step: the (possibly stripped) decision's authorization
    verdict + the terminal status if the step ended the run (budget/deadline)."""

    verdict: MemberEdgeVerdict
    status: MemberStatus
    reason: str


def run_member_step(
    member: FireteamMember,
    decision: Any,
    *,
    gate: Optional[Callable[..., Any]] = None,
    seq: int = 0,
) -> MemberStepOutcome:
    """Advance a member by one decision, bounded and fail-closed. The deterministic budget/deadline is
    checked FIRST (a member past its deadline_seq or out of credit is COMPLETE and touches nothing).
    Otherwise the decision is authorized via :func:`authorize_member_edge`; an allowed target-touching
    call spends one credit. Never raises; ``seq`` is the injected clock (no wallclock)."""
    if member.budget.expired(seq):
        v = MemberEdgeVerdict(False, "deny", "member past its deadline_seq (fail-closed)",
                              member.capped_tier)
        return MemberStepOutcome(v, MemberStatus.TIMEOUT, "deadline reached")
    if member.budget.credit_remaining <= 0:
        v = MemberEdgeVerdict(False, "deny", "member credit exhausted", member.capped_tier)
        return MemberStepOutcome(v, MemberStatus.COMPLETE, "credit exhausted")
    verdict = authorize_member_edge(member, decision, gate=gate, seq=seq)
    if verdict.outcome == "allow" and verdict.tier != "A0":
        # a target-touching (non-inert) authorized call consumes one unit of the member's budget
        member.budget.spend(1)
    if verdict.outcome == "queue":
        return MemberStepOutcome(verdict, MemberStatus.NEEDS_CONFIRMATION, verdict.reason)
    if verdict.outcome == "deny":
        return MemberStepOutcome(verdict, MemberStatus.DENIED, verdict.reason)
    return MemberStepOutcome(verdict, MemberStatus.SUCCESS, verdict.reason)
