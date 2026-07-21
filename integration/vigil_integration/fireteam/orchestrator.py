"""
fireteam.orchestrator — the governed fan-out/fan-in (VIGIL-FUSION F6, C5).

Ties the pieces together, sovereign-safe:

  * ``run_fireteam`` validates the plan fail-closed (a malformed/oversized/mutex-violating plan is
    REFUSED, never partially spawned), builds each member with a capped tier + a deterministic
    credit/deadline budget, and runs the injected member ``runner`` under a bounded-concurrency
    semaphore. A runner that crashes yields an ERROR member result — one bad member never crashes the
    wave or aborts its siblings.
  * ALL member spine writes go through the single-writer queue, drained once here (``flush``) so the
    append-only chain is never interleaved.
  * every member escalation is registered in the confirmation registry (still PENDING — only a signed
    operator approval can resolve it), and every member finding is rolled up by ``collect`` as a LEAD,
    with FACTs minted solely by the injected oracle.

Deterministic: members keep plan order, each gets ``seq = seq_start + index`` (no wallclock/RNG); the
whole run is reproducible.
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

from ..agent.react import OracleFn
from ..agent.state import Finding, Phase
from .collect import CollectOutcome, collect
from .confirmation import ConfirmationRegistry
from .member import FireteamMember, MemberBudget
from .models import (
    FIRETEAM_MAX_CONCURRENT,
    EscalationRequest,
    FireteamMemberSpec,
    FireteamPlan,
    MemberResult,
    MemberStatus,
    parse_fireteam_plan,
)
from .spine_queue import SingleWriterSpineQueue


@dataclass(frozen=True)
class MemberRunContext:
    """What the injected member ``runner`` is handed. The gate/oracle/spine are the SAME injected
    callables the parent uses; a member never gets a privileged copy."""

    seq: int
    phase: Phase
    gate: Optional[Callable[..., Any]] = None
    oracle: Optional[OracleFn] = None
    spine: Optional[SingleWriterSpineQueue] = None


# runner(member, ctx) -> MemberResult (sync or async). Injected so the whole orchestrator is testable
# without a live LLM/kernel; in production it drives the member ReAct loop of :mod:`fireteam.member`.
MemberRunner = Callable[[FireteamMember, MemberRunContext], "MemberResult | Awaitable[MemberResult]"]


@dataclass(frozen=True)
class FireteamOutcome:
    refused: bool = False
    reason: str = ""
    facts: list[Finding] = field(default_factory=list)
    leads: list[Finding] = field(default_factory=list)
    escalations: list[EscalationRequest] = field(default_factory=list)
    member_results: list[MemberResult] = field(default_factory=list)
    spine_refs: list[str] = field(default_factory=list)


def _build_member(spec: FireteamMemberSpec, wave_id: str, phase: Phase, base_seq: int) -> FireteamMember:
    deadline = spec.deadline_seq if spec.deadline_seq > 0 else base_seq + spec.credit + 1
    return FireteamMember(spec=spec, wave_id=wave_id, phase=phase,
                          budget=MemberBudget(credit_remaining=spec.credit, deadline_seq=deadline))


async def _run_one(runner: MemberRunner, member: FireteamMember, ctx: MemberRunContext,
                   sem: asyncio.Semaphore) -> MemberResult:
    async with sem:
        try:
            result = runner(member, ctx)
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:  # noqa: BLE001 — isolate a member crash; never abort the wave
            return MemberResult(member_id=member.member_id, status=MemberStatus.ERROR,
                                notes=f"member runner error (isolated): {exc}")
        if not isinstance(result, MemberResult):
            return MemberResult(member_id=member.member_id, status=MemberStatus.ERROR,
                                notes="member runner returned a non-MemberResult (fail-closed)")
        return result


async def run_fireteam(
    plan: Any,
    runner: MemberRunner,
    *,
    phase: Phase = Phase.INFORMATIONAL,
    gate: Optional[Callable[..., Any]] = None,
    oracle: Optional[OracleFn] = None,
    spine: Optional[SingleWriterSpineQueue] = None,
    registry: Optional[ConfirmationRegistry] = None,
    max_concurrent: int = FIRETEAM_MAX_CONCURRENT,
    seq_start: int = 0,
) -> FireteamOutcome:
    """Deploy a fireteam wave, sovereign-safe and fail-closed. Returns a :class:`FireteamOutcome`; a
    malformed plan yields ``refused=True`` and spawns NOTHING. Never raises."""
    validated: Optional[FireteamPlan] = parse_fireteam_plan(plan)
    if validated is None:
        return FireteamOutcome(refused=True, reason="malformed/over-cap/mutex-violating plan (fail-closed)")

    members = [_build_member(spec, validated.wave_id, phase, seq_start + i)
               for i, spec in enumerate(validated.members)]
    try:
        conc = int(max_concurrent)
    except (TypeError, ValueError):
        conc = FIRETEAM_MAX_CONCURRENT
    conc = max(1, min(conc, FIRETEAM_MAX_CONCURRENT, len(members)))
    sem = asyncio.Semaphore(conc)

    tasks = []
    for i, member in enumerate(members):
        ctx = MemberRunContext(seq=seq_start + i, phase=phase, gate=gate, oracle=oracle, spine=spine)
        tasks.append(_run_one(runner, member, ctx, sem))
    results: list[MemberResult] = list(await asyncio.gather(*tasks))

    # single-writer drain of any buffered member spine writes (deterministic order; no interleave).
    spine_refs = spine.flush() if spine is not None else []

    # register every escalation as PENDING (signed-approval-only resolution happens elsewhere).
    if registry is not None:
        for r in results:
            for esc in r.escalations:
                registry.register(esc)

    rolled: CollectOutcome = collect(results, oracle=oracle, source_prefix=validated.wave_id)
    return FireteamOutcome(
        refused=False, reason="",
        facts=rolled.facts, leads=rolled.leads, escalations=rolled.escalations,
        member_results=results, spine_refs=spine_refs,
    )
