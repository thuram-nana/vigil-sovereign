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


# The stable per-engagement recipient the fireteam uses as its coordination channel (S5). A member's
# discovery is broadcast here as an agent_message; the NEXT wave's members read it at wave-start as an
# ADVISORY hint. A coordination message is NEVER evidence — no fact-building path reads the agent_message
# kind (blackboard.inbox), so a hint can never be promoted to a fact.
_COORD_RECIPIENT = "fireteam:coord"
_MAX_HINTS = 8               # bound the wave-start hint snapshot (the coord log is append-only + long-lived)


@dataclass(frozen=True)
class MemberRunContext:
    """What the injected member ``runner`` is handed. The gate/oracle/spine are the SAME injected
    callables the parent uses; a member never gets a privileged copy. ``hints`` is a READ-ONLY snapshot of
    prior-wave coordination messages (advisory only — never evidence)."""

    seq: int
    phase: Phase
    gate: Optional[Callable[..., Any]] = None
    oracle: Optional[OracleFn] = None
    spine: Optional[SingleWriterSpineQueue] = None
    hints: tuple = ()


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
    blackboard: Any = None,
    engagement: str = "",
) -> FireteamOutcome:
    """Deploy a fireteam wave, sovereign-safe and fail-closed. Returns a :class:`FireteamOutcome`; a
    malformed plan yields ``refused=True`` and spawns NOTHING. Never raises.

    S5 coordination (optional ``blackboard``): members read a wave-START snapshot of prior-wave coordination
    hints (advisory only, folded into their objective) and, after the wave, each claim-producing member
    broadcasts one directed ``agent_message`` (deterministic member order). A message is NEVER evidence — no
    fact-building path reads it — so this cannot promote anything; ``collect`` still mints facts solely via
    the oracle over member CLAIMS."""
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

    # S5: a READ-ONLY snapshot of prior-wave coordination hints, taken ONCE before any member runs (so intra-
    # wave concurrency can never race a read against a write — determinism preserved). Stable engagement id
    # (the slug), not the per-wave id, so hints span waves. Advisory only.
    eng = engagement or validated.wave_id
    hints: tuple = ()
    if blackboard is not None:
        try:
            rows = blackboard.inbox(engagement=eng, recipient=_COORD_RECIPIENT, since_id=0)
            hints = tuple(str((r.payload or {}).get("body", "")) for r in rows if r.payload)[-_MAX_HINTS:]
        except Exception:  # noqa: BLE001 — coordination is best-effort; a bus error never aborts the wave
            hints = ()

    tasks = []
    for i, member in enumerate(members):
        ctx = MemberRunContext(seq=seq_start + i, phase=phase, gate=gate, oracle=oracle, spine=spine,
                               hints=hints)
        tasks.append(_run_one(runner, member, ctx, sem))
    results: list[MemberResult] = list(await asyncio.gather(*tasks))

    # S5: AFTER the wave, each claim-producing member broadcasts one coordination hint, in DETERMINISTIC
    # member/plan order (never during the concurrent wave). sender == member_id (blackboard anti-spoof). A
    # bus error is swallowed — coordination is advisory and must never fail the wave.
    if blackboard is not None:
        for r in results:
            if not r.claims:
                continue
            srcs = sorted({str(c.source) for c in r.claims if getattr(c, "source", "")})
            try:
                blackboard.post(engagement=eng, kind="agent_message", agent_name=r.member_id,
                                payload={"sender": r.member_id, "recipient": _COORD_RECIPIENT,
                                         "topic": str(phase),
                                         "body": (f"{r.member_id} produced {len(r.claims)} lead(s)"
                                                  + (f" via {', '.join(srcs)}" if srcs else ""))[:2000],
                                         "refs": []})
            except Exception:  # noqa: BLE001
                pass

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
