"""
fireteam.member_runner — the PRODUCTION member body (A4c).

``run_fireteam`` is a total, tested orchestrator that needs a ``MemberRunner`` — the per-member loop that
actually proposes and runs work. This builds one that reuses the SAME injected think + governed executor
the parent OODA loop uses, so a member is never more capable than the parent:

  * every member decision passes ``member.run_member_step`` → ``authorize_member_edge`` FIRST: forbidden
    actions stripped, the edge classified, capped at the member's WARDEN tier (never A3), destructiveness
    re-derived from the tool NAME, and an over-cap / destructive edge QUEUED (an EscalationRequest) — never
    auto-run; an in-cap non-destructive edge is then checked by the injected conjunctive gate;
  * only an ALLOW (in-cap, gate-approved) edge is executed, through the SAME governed executor (which
    re-checks the gate — defence in depth); a member cannot self-approve, so a queued edge NEVER runs here;
  * the member mints NO facts: it returns raw-output CLAIMS that ``fireteam.collect`` re-checks through the
    injected oracle (a FACT needs an oracle confirmation over the retained raw output);
  * bounded: the member's ``credit``/``deadline_seq`` (enforced by ``run_member_step``) PLUS a hard step
    ceiling, so a model that only proposes denied edges (which don't spend credit) still terminates;
  * total: a think/executor error ends THIS member cleanly (its ``MemberResult``), never the wave — the
    orchestrator additionally isolates any raise.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from ..agent.state import ActionType, AgentState, OutputAnalysis
from .member import FireteamMember, run_member_step
from .models import MemberFindingClaim, MemberResult, MemberStatus

# think(state) -> LLMDecision  (the SAME seam the parent uses; a member gets its own role-scoped state).
ThinkFn = Callable[[AgentState], Any]
# run_tool(tool, phase, seq, *, approved) -> exec result (.ran/.stdout). approved is ALWAYS False here —
# a member can never self-approve; an over-cap/destructive edge is queued (never reaches execution).
RunToolFn = Callable[..., Any]


def _member_state(member: FireteamMember, parent_objective: str, hints: tuple = ()) -> AgentState:
    """A role-scoped AgentState for the member's think. The objective NAMES the member's lane; the hard
    authority (tier cap, gate, destructiveness) is enforced by run_member_step regardless of the prompt.
    ``hints`` (S5) are prior-wave coordination messages, folded in as ADVISORY context — they shape what a
    member looks at, never what is TRUE (a message is never evidence; every action still gates + is oracle-
    confirmed)."""
    spec = member.spec
    lane = f"you are the '{spec.role or spec.member_id}' specialist"
    tools = f"; prefer your tools: {', '.join(spec.tools)}" if spec.tools else ""
    obj = (f"{parent_objective or 'assess the authorized target'} — {lane}{tools}. Capped at tier "
           f"{member.capped_tier}: propose only in-cap, non-destructive steps (anything higher is queued "
           f"for the operator, never auto-run).")
    if hints:
        obj += (" Team coordination hints (ADVISORY only — a teammate's suggestion, NEVER evidence or a "
                "confirmed finding): " + " | ".join(str(h) for h in hints if h))
    return AgentState(engagement_slug=member.wave_id, objective=obj[:1000], phase=member.phase)


def build_member_runner(*, think: ThinkFn, run_tool: RunToolFn, parent_objective: str = "",
                        max_steps: Optional[int] = None) -> Callable[[FireteamMember, Any], MemberResult]:
    """Build a production ``MemberRunner``. ``think``/``run_tool`` are the parent's injected seams; the
    returned runner drives one member's bounded, fully-gated think→authorize→execute→claim loop. It never
    raises (a failure ends the member with an honest status/notes)."""

    def runner(member: FireteamMember, ctx: Any) -> MemberResult:
        claims: list[MemberFindingClaim] = []
        escalations: list = []
        notes: list[str] = []
        status = MemberStatus.COMPLETE
        state = _member_state(member, parent_objective, hints=tuple(getattr(ctx, "hints", ()) or ()))
        gate = getattr(ctx, "gate", None)
        seq = int(getattr(ctx, "seq", 0))
        # hard ceiling: credit bounds EXECUTIONS, but denied edges don't spend credit — so cap total steps
        # to guarantee termination even if the model only ever proposes denied/inert edges.
        limit = max_steps if max_steps is not None else max(1, member.budget.credit_remaining) * 2 + 3
        steps = 0
        while steps < limit:
            steps += 1
            try:
                decision = think(state)
            except Exception as exc:  # noqa: BLE001 — a think error ends THIS member, never the wave
                notes.append(f"think error (isolated): {type(exc).__name__}")
                status = MemberStatus.ERROR
                break
            action = getattr(decision, "action", None)
            if action == ActionType.COMPLETE:
                break
            if action == ActionType.ASK_USER:
                # a member can't pause for a human mid-wave — it simply ends its turn (its leads still fan in)
                notes.append("member asked for guidance → ended its turn")
                break

            outcome = run_member_step(member, decision, gate=gate, seq=seq)
            seq += 1
            vs = outcome.status

            if vs == MemberStatus.NEEDS_CONFIRMATION and outcome.verdict.escalation is not None:
                escalations.append(outcome.verdict.escalation)   # QUEUED — never run here
                status = MemberStatus.NEEDS_CONFIRMATION
                break
            if vs == MemberStatus.TIMEOUT:
                status = MemberStatus.TIMEOUT
                break
            if vs == MemberStatus.COMPLETE:          # credit exhausted
                notes.append(outcome.reason)
                break
            if vs == MemberStatus.DENIED:
                notes.append(f"denied: {outcome.reason}")
                continue                              # pivot — bounded by `limit`

            # SUCCESS: an authorized edge. An inert (A0) edge executes nothing; a target-touching tool runs
            # through the SAME governed executor (approved=False — a member never self-approves). NOTE: only
            # a USE_TOOL decision executes here; a PLAN_TOOLS (or other non-tool) member decision authorizes
            # but has no `.tool`, so it is inert (fail-safe — a planning member contributes nothing until it
            # proposes a concrete tool call; expanding a member PLAN_TOOLS to its calls is a follow-up).
            tool = getattr(decision, "tool", None)
            if outcome.verdict.tier != "A0" and tool is not None:
                try:
                    exec_res = run_tool(tool, member.phase, seq, approved=False)
                except Exception as exc:  # noqa: BLE001 — an executor error ends the member cleanly
                    notes.append(f"executor error (isolated): {type(exc).__name__}")
                    status = MemberStatus.ERROR
                    break
                if getattr(exec_res, "ran", False):
                    claims.append(MemberFindingClaim(
                        raw_output=str(getattr(exec_res, "stdout", "") or ""),
                        analysis=getattr(decision, "output_analysis", None) or OutputAnalysis(),
                        source=getattr(tool, "tool_name", "")))
                    status = MemberStatus.SUCCESS
                else:
                    notes.append(f"executor declined: {getattr(exec_res, 'reason', '')}")

        return MemberResult(member_id=member.member_id, status=status, claims=claims,
                            escalations=escalations, iterations_used=steps,
                            credit_used=max(0, member.spec.credit - member.budget.credit_remaining),
                            notes=" | ".join(notes)[:500])

    return runner
