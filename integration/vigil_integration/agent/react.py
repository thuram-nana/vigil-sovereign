"""
agent.react — the sovereign ReAct interposition (VIGIL-FUSION F2 keystone).

redamon's ReAct loop lets ``think`` propose an action (use_tool / transition_phase / deploy_fireteam /
…) and an inline ``output_analysis`` that asserts ``exploit_succeeded`` — and then acts on the LLM's
say-so, persisting the assertion as a finding. That is precisely the trust model VIGIL forbids. This
module re-plumbs the same shape through the sovereign core:

  * **parse_decision** — the raw LLM response is parsed FAIL-CLOSED into a typed ``LLMDecision`` and
    downgraded to the safest action on any malformation (a broken ``deploy_fireteam`` never becomes a
    deploy; a total parse failure pauses for a human). The result is a non-authoritative PROPOSAL.
  * **classify_edge / authorize_edge** — EVERY action-bearing edge is routed through the injected
    conjunctive gate (WARDEN tier ∧ CRUCIBLE authority ∧ m-of-n) at the phase's tier (A3 + threshold
    for destructive), and a phase escalation or fireteam deploy additionally requires the signed
    human-approval leg. Inert actions (ask_user/complete/switch_skill) touch no target and pass.
    A structurally-invalid edge (no tool, bad phase transition) is DENIED fail-closed.
  * **intake_result** — the LLM's ``output_analysis`` claims become LEADs, never facts. An
    ``exploit_succeeded`` claim triggers the injected deterministic ORACLE to re-fire over the retained
    raw output; only an oracle confirmation (a signed evidence ref) produces a FACT.

Pure/injected: the gate and oracle are callables passed in, so the whole keystone is testable without
the live kernel/framework. Import-clean (pydantic + .state/.phases + F1 safety; no framework/strix).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from ..safety.llm_intake import parse_proposal
from .phases import can_transition, phase_tier, tool_tier
from .state import ActionType, AgentState, Finding, LLMDecision, OutputAnalysis, Phase

# ---------------------------------------------------------------------------------------------------
# 1. fail-closed decision parsing
# ---------------------------------------------------------------------------------------------------


def _downgrade(obj: Any) -> LLMDecision:
    """Validate the raw dict into an ``LLMDecision`` and downgrade a structurally-incomplete action to
    the safest still-valid one (never up, never a silent no-op that proceeds). Raises on a
    fundamentally invalid object so ``parse_proposal`` falls back to the caller's fail-closed default."""
    decision = LLMDecision.model_validate(obj)
    a = decision.action
    if a == ActionType.USE_TOOL and decision.tool is None:
        return decision.model_copy(update={"action": ActionType.ASK_USER,
                                           "question": "the model asked to use a tool but named none"})
    if a == ActionType.PLAN_TOOLS and not decision.plan:
        if decision.tool is not None:  # a one-tool "plan" is just a use_tool
            return decision.model_copy(update={"action": ActionType.USE_TOOL})
        return decision.model_copy(update={"action": ActionType.ASK_USER,
                                           "question": "the model asked to plan tools but listed none"})
    if a == ActionType.DEPLOY_FIRETEAM and not decision.fireteam:
        # a broken deploy must NEVER become a deploy; fall back to a single tool or a human pause
        if decision.tool is not None:
            return decision.model_copy(update={"action": ActionType.USE_TOOL})
        return decision.model_copy(update={"action": ActionType.ASK_USER,
                                           "question": "the model asked to deploy a fireteam but named no members"})
    if a == ActionType.TRANSITION_PHASE and decision.target_phase is None:
        return decision.model_copy(update={"action": ActionType.ASK_USER,
                                           "question": "the model asked to change phase but named no target"})
    if a == ActionType.SWITCH_SKILL and not decision.skill:
        return decision.model_copy(update={"action": ActionType.ASK_USER,
                                           "question": "the model asked to switch skill but named none"})
    return decision


_FAILCLOSED_DEFAULT = LLMDecision(
    action=ActionType.ASK_USER,
    reasoning="the model response could not be parsed into a valid decision",
    question="I could not parse a valid decision from the model — how should I proceed?",
)


def parse_decision(text: str) -> LLMDecision:
    """Parse a raw LLM response into a fail-closed, non-authoritative ``LLMDecision``. Any total parse
    failure pauses for a human (``ASK_USER``); a malformed action is downgraded to the safest valid
    one. Never raises; never returns an action-bearing edge from unparseable input."""
    return parse_proposal(text, _downgrade, default=_FAILCLOSED_DEFAULT)


# ---------------------------------------------------------------------------------------------------
# 2. sovereign action-edge classification + authorization
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class EdgeSpec:
    """What a decision's action REQUIRES to proceed — the pure policy, before the gate is consulted."""

    action: ActionType
    inert: bool                       # touches no target and needs no gate (ask_user/complete/switch)
    target_touching: bool             # executing it contacts a target → conjunctive gate
    tier: str                         # WARDEN tier required (for target-touching / escalation)
    destructive: bool
    target: str                       # target url/host for a tool call
    requires_signed_approval: bool    # phase escalation / fireteam deploy → signed operator approval
    denied: bool                      # structurally invalid → refuse fail-closed
    reason: str


def _tool_target(tool) -> str:
    """Best-effort target for a tool call, for the gate/egress check. The tool registry re-derives the
    authoritative target server-side in F3; this is the proposal."""
    if tool is None:
        return ""
    for key in ("target", "url", "target_url", "host", "domain"):
        v = tool.tool_args.get(key)
        if isinstance(v, str) and v:
            return v
    return ""


def classify_edge(decision: LLMDecision, phase: Phase) -> EdgeSpec:
    """Pure policy: classify what ``decision`` needs in ``phase``. No gate call, no LLM — deterministic
    and fail-closed (an unknown action, a missing tool, or an illegal phase transition is DENIED)."""
    a = decision.action
    if a in (ActionType.ASK_USER, ActionType.COMPLETE, ActionType.SWITCH_SKILL):
        return EdgeSpec(a, inert=True, target_touching=False, tier="A0", destructive=False,
                        target="", requires_signed_approval=False, denied=False, reason="inert action")
    if a == ActionType.USE_TOOL:
        if decision.tool is None:
            return EdgeSpec(a, False, False, "A3", False, "", False, True, "use_tool without a tool")
        d = bool(decision.tool.destructive) or decision.tool.blast_class in ("destructive", "high-blast")
        return EdgeSpec(a, inert=False, target_touching=True, tier=tool_tier(phase, destructive=d),
                        destructive=d, target=_tool_target(decision.tool),
                        requires_signed_approval=d, denied=False, reason="tool call → conjunctive gate")
    if a == ActionType.PLAN_TOOLS:
        # planning is inert; each tool in the wave is gated individually at execution (F3/F6).
        if not decision.plan:
            return EdgeSpec(a, False, False, "A3", False, "", False, True, "plan_tools with an empty plan")
        return EdgeSpec(a, inert=True, target_touching=False, tier="A0", destructive=False, target="",
                        requires_signed_approval=False, denied=False,
                        reason="plan accepted; each tool is gated when the wave executes")
    if a == ActionType.TRANSITION_PHASE:
        if decision.target_phase is None:
            return EdgeSpec(a, False, False, "A3", False, "", False, True, "transition without a target phase")
        ok, why = can_transition(phase, decision.target_phase)
        if not ok:
            return EdgeSpec(a, False, False, "A3", False, "", False, True, why)
        return EdgeSpec(a, inert=False, target_touching=False, tier=phase_tier(decision.target_phase),
                        destructive=False, target="", requires_signed_approval=True, denied=False, reason=why)
    if a == ActionType.DEPLOY_FIRETEAM:
        return EdgeSpec(a, inert=False, target_touching=False, tier=phase_tier(phase), destructive=False,
                        target="", requires_signed_approval=True, denied=False,
                        reason="fireteam deploy → signed approval + per-member tiers (F6)")
    return EdgeSpec(a, False, False, "A3", False, "", False, True, f"unknown action {a!r}")


@dataclass(frozen=True)
class EdgeVerdict:
    allowed: bool          # may this edge auto-proceed now?
    outcome: str           # "allow" | "queue" | "deny"
    reason: str
    tier: str = "A0"
    requires_signed_approval: bool = False


def authorize_edge(
    decision: LLMDecision,
    state: AgentState,
    *,
    gate: Optional[Callable[..., Any]] = None,
    now: Any = None,
) -> EdgeVerdict:
    """Route ``decision`` through the sovereign core, fail-closed. Inert actions pass. A target-touching
    tool call goes through the injected conjunctive ``gate(tool_name, target, destructive=...)`` — its
    verdict decides. A phase escalation / fireteam deploy QUEUEs for the signed-operator approval leg
    (a bare LLM decision can never escalate). A structurally-invalid edge is DENIED. Never raises."""
    spec = classify_edge(decision, state.phase)
    if spec.denied:
        return EdgeVerdict(False, "deny", f"invalid action (fail-closed): {spec.reason}", spec.tier)
    if spec.inert:
        return EdgeVerdict(True, "allow", spec.reason, spec.tier)
    if spec.requires_signed_approval and not spec.target_touching:
        # phase escalation / fireteam: needs a signed operator approval (the conjunctive gate's human
        # leg); it never auto-runs on the LLM's decision alone.
        return EdgeVerdict(False, "queue", f"requires signed operator approval: {spec.reason}",
                           spec.tier, requires_signed_approval=True)
    # target-touching tool call → the conjunctive gate is the authority.
    if gate is None:
        return EdgeVerdict(False, "deny", "no conjunctive gate wired — a tool call cannot proceed "
                           "(fail-closed)", spec.tier)
    try:
        verdict = gate(decision.tool.tool_name, spec.target, spec.destructive)  # type: ignore[union-attr]
    except Exception as exc:  # noqa: BLE001 — any gate error is a DENY, never caught-and-continued
        return EdgeVerdict(False, "deny", f"gate error (fail-closed): {exc}", spec.tier)
    raw_outcome = getattr(verdict, "outcome", "deny")
    allowed = getattr(verdict, "allowed", False) is True and raw_outcome == "allow"
    # Derive the EdgeVerdict outcome from `allowed` so a malformed gate (allowed=False but
    # outcome=="allow") can never present as "allow" to a downstream consumer keying on outcome.
    outcome = "allow" if allowed else ("queue" if raw_outcome == "queue" else "deny")
    return EdgeVerdict(allowed, outcome, getattr(verdict, "reason", ""), spec.tier,
                       requires_signed_approval=spec.destructive)


# ---------------------------------------------------------------------------------------------------
# 3. oracle interposition — LLM claims become LEADs; the oracle mints FACTs
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class IntakeResult:
    facts: list[Finding]   # oracle-confirmed, each carrying a signed evidence ref
    leads: list[Finding]   # LLM/tool proposals — never facts


def _finding_from_claim(claim: dict, source: str) -> Finding:
    return Finding(
        ref=str(claim.get("ref") or claim.get("check_id") or claim.get("title") or "finding"),
        bug_class=str(claim.get("bug_class") or ""),
        title=str(claim.get("title") or ""),
        severity=str(claim.get("severity") or ""),
        status="lead",
        source=source,
    )


# oracle(raw_output, analysis) -> a signed evidence ref (spine hash / SCITT cert id) if the deterministic
# oracle CONFIRMS the exploit over the retained raw output, else None. In production this wraps
# oracle_adapter.confirm_and_certify; injected here so the keystone is testable without the framework.
OracleFn = Callable[[str, OutputAnalysis], Optional[str]]


def intake_result(
    raw_output: str,
    analysis: Optional[OutputAnalysis],
    *,
    oracle: Optional[OracleFn] = None,
    source: str = "",
) -> IntakeResult:
    """Turn a tool's raw output + the LLM's inline ``analysis`` claims into findings, honestly.

    EVERY proposed finding in ``analysis.findings`` becomes a LEAD. An ``exploit_succeeded`` claim is
    NOT a fact — it triggers the injected deterministic ``oracle`` to re-fire over ``raw_output``; only
    an oracle confirmation (a signed evidence ref) yields a FACT. With no oracle wired, nothing can be
    a fact (fail-closed). This is the load-bearing anti-hallucination seam of the whole fusion."""
    facts: list[Finding] = []
    leads: list[Finding] = []
    if analysis is None:
        return IntakeResult(facts, leads)

    for claim in analysis.findings:
        if isinstance(claim, dict):
            leads.append(_finding_from_claim(claim, source))

    if analysis.exploit_succeeded:
        evidence_ref = None
        if oracle is not None:
            try:
                evidence_ref = oracle(raw_output, analysis)
            except Exception:  # noqa: BLE001 — an oracle error confirms nothing (fail-closed)
                evidence_ref = None
        exploit = Finding(ref=f"exploit:{source or 'claim'}", bug_class="", title="claimed exploit",
                          source=source)
        if evidence_ref and str(evidence_ref).strip():   # a whitespace/garbage ref mints NO fact
            exploit.status = "fact"
            exploit.evidence_ref = str(evidence_ref)
            facts.append(exploit)
        else:
            exploit.status = "lead"
            exploit.title = "claimed exploit (UNCONFIRMED — oracle did not fire)"
            leads.append(exploit)

    return IntakeResult(facts, leads)


def apply_intake(state: AgentState, result: IntakeResult) -> None:
    """Fold an :class:`IntakeResult` into the state's separate fact/lead stores (facts only through the
    oracle-confirmed path, which carries the signed evidence ref)."""
    for f in result.facts:
        state.record_fact(f, evidence_ref=f.evidence_ref)
    for lead in result.leads:
        state.record_lead(lead)
