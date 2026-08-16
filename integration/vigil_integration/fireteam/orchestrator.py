"""
fireteam.orchestrator — the governed fan-out/fan-in (VIGIL-FUSION F6, C5).

Ties the pieces together, sovereign-safe:

  * ``run_fireteam`` validates the plan fail-closed (a malformed/oversized/mutex-violating plan is
    REFUSED, never partially spawned), builds each member with a capped tier + a deterministic
    credit/deadline budget, and runs the injected member ``runner`` under a bounded-concurrency
    semaphore. A runner that crashes yields an ERROR member result — one bad member never crashes the
    wave or aborts its siblings.
  * ALL member spine writes go through the single-writer queue; each member's records are drained the
    instant that member COMPLETES (``flush_member``, never interleaved), with a final ``flush`` for any
    tail (e.g. escalation-registry events). Draining per-member means a crash mid-wave keeps the
    finished members' records instead of losing the whole un-flushed buffer; paired with an optional
    :class:`WaveProgressStore` a resumed wave SKIPS already-completed members (fail-open, at-least-once).
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
from .wave_progress import MemberProgress, WaveProgressStore


# The stable per-engagement recipient the fireteam uses as its coordination channel (S5). A member's
# discovery is broadcast here as an agent_message; the NEXT wave's members read it at wave-start as an
# ADVISORY hint. A coordination message is NEVER evidence — no fact-building path reads the agent_message
# kind (blackboard.inbox), so a hint can never be promoted to a fact.
_COORD_RECIPIENT = "fireteam:coord"
# Keep only the last few coordination hints per wave. NB: blackboard.inbox reads the OLDEST ≤1000
# agent_messages for the engagement (ASC, no cursor), so on a very long-lived log this may serve stale — or
# zero — hints. That is acceptable: coordination is ADVISORY and fail-safe (it can only ever degrade toward
# no coordination, never toward a false fact). A recency cursor is a follow-up.
_MAX_HINTS = 8


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
                   sem: asyncio.Semaphore, *, spine: Optional[SingleWriterSpineQueue] = None,
                   progress: Optional[WaveProgressStore] = None, wave_id: str = "") -> MemberResult:
    async with sem:
        try:
            result: Any = runner(member, ctx)
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:  # noqa: BLE001 — isolate a member crash; never abort the wave
            result = MemberResult(member_id=member.member_id, status=MemberStatus.ERROR,
                                  notes=f"member runner error (isolated): {exc}")
        else:
            if not isinstance(result, MemberResult):
                result = MemberResult(member_id=member.member_id, status=MemberStatus.ERROR,
                                      notes="member runner returned a non-MemberResult (fail-closed)")

        # --- per-member checkpoint: the instant this member COMPLETES, flush ITS buffered spine
        # records (so a crash mid-wave keeps them) and THEN — only if that flush was fully durable —
        # record wave progress. flush-then-record gives at-least-once WITHOUT data loss:
        #   * flush ok + record ok    → skipped on resume, records already durable (never re-written);
        #   * flush ok + record fails → re-run on resume, records written again (acceptable duplication);
        #   * flush DROPPED a record  → NOT checkpointed → re-run on resume so the lost record is
        #     re-written — a member is never skipped-without-durable-records.
        # Every step is fail-open: a checkpoint failure is a recorded no-op that never breaks the wave or
        # changes the member's own result.
        refs: list[str] = []
        flush_ok = True
        if spine is not None:
            try:
                attempted = spine.pending_for(member.member_id)
                refs = spine.flush_member(member.member_id)
                flush_ok = len(refs) == attempted   # every buffered record for this member was written
            except Exception:  # noqa: BLE001 — defence in depth; flush_member is already fail-open
                refs = []
                flush_ok = False
        if progress is not None and flush_ok:
            try:
                progress.record(wave_id, member.member_id, result, refs)
            except Exception:  # noqa: BLE001 — a progress write must never break the wave
                pass
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
    progress: Optional[WaveProgressStore] = None,
) -> FireteamOutcome:
    """Deploy a fireteam wave, sovereign-safe and fail-closed. Returns a :class:`FireteamOutcome`; a
    malformed plan yields ``refused=True`` and spawns NOTHING. Never raises.

    S5 coordination (optional ``blackboard``): members read a wave-START snapshot of prior-wave coordination
    hints (advisory only, folded into their objective) and, after the wave, each claim-producing member
    broadcasts one directed ``agent_message`` (deterministic member order). A message is NEVER evidence — no
    fact-building path reads it — so this cannot promote anything; ``collect`` still mints facts solely via
    the oracle over member CLAIMS.

    Crash-resume checkpoint (optional ``progress``, a :class:`WaveProgressStore` keyed by ``wave_id``): as
    EACH member completes its spine records are flushed immediately (``spine.flush_member``) — not only
    after ``gather`` — so a crash mid-wave keeps the finished members' records instead of losing the whole
    un-flushed buffer; and each completed member is recorded, so a resumed wave (same ``wave_id``) SKIPS the
    already-completed members (restoring their result/refs) instead of re-running them and re-touching the
    target. The checkpoint is fully fail-open: a flush/record failure is a recorded no-op, and because the
    flush precedes the record the semantics are at-least-once — a member whose record was dropped is simply
    re-run on resume (its spine records written again — acceptable), never skipped-without-durable-records.
    A checkpoint records STATE only; a restored member mints nothing — facts are still minted solely by the
    oracle in ``collect``. An ERROR (isolated-crash) member is checkpointed as completed too (retry-on-error
    is a deliberate non-goal of this slice — resume is about not re-doing finished work, not re-doing
    failures)."""
    validated: Optional[FireteamPlan] = parse_fireteam_plan(plan)
    if validated is None:
        return FireteamOutcome(refused=True, reason="malformed/over-cap/mutex-violating plan (fail-closed)")

    wave_id = validated.wave_id

    # RESUME: load the members already completed on a prior run of THIS wave. Fail-open — any load error
    # yields an empty map, so a corrupt/missing checkpoint just re-runs the whole wave (a checkpoint can
    # never cause a member to be wrongly SKIPPED, only — at worst — wrongly re-run).
    done: dict[str, MemberProgress] = {}
    if progress is not None:
        try:
            done = progress.completed(wave_id)
        except Exception:  # noqa: BLE001 — a resume-load failure means "re-run the wave"
            done = {}

    # Build members in PLAN order (each keeps ``seq = seq_start + index``, deterministic). A member already
    # recorded done is not rebuilt into a task — it is SKIPPED and its result restored, never re-run.
    all_members = [_build_member(spec, wave_id, phase, seq_start + i)
                   for i, spec in enumerate(validated.members)]
    to_run = [(i, m) for i, m in enumerate(all_members) if m.member_id not in done]

    try:
        conc = int(max_concurrent)
    except (TypeError, ValueError):
        conc = FIRETEAM_MAX_CONCURRENT
    conc = max(1, min(conc, FIRETEAM_MAX_CONCURRENT, max(1, len(to_run))))
    sem = asyncio.Semaphore(conc)

    # S5: a READ-ONLY snapshot of prior-wave coordination hints, taken ONCE before any member runs (so intra-
    # wave concurrency can never race a read against a write — determinism preserved). Stable engagement id
    # (the slug), not the per-wave id, so hints span waves. Advisory only.
    eng = engagement or wave_id
    hints: tuple = ()
    if blackboard is not None:
        try:
            rows = blackboard.inbox(engagement=eng, recipient=_COORD_RECIPIENT, since_id=0)
            hints = tuple(str((r.payload or {}).get("body", "")) for r in rows if r.payload)[-_MAX_HINTS:]
        except Exception:  # noqa: BLE001 — coordination is best-effort; a bus error never aborts the wave
            hints = ()

    tasks = []
    for i, member in to_run:
        ctx = MemberRunContext(seq=seq_start + i, phase=phase, gate=gate, oracle=oracle, spine=spine,
                               hints=hints)
        tasks.append(_run_one(runner, member, ctx, sem, spine=spine, progress=progress,
                              wave_id=wave_id))
    ran_results: list[MemberResult] = list(await asyncio.gather(*tasks)) if tasks else []
    ran_by_id = {r.member_id: r for r in ran_results}

    # Assemble the wave's results in deterministic PLAN order: a skipped member's RESTORED result, else the
    # member's freshly-run result. member_ids are unique per validated plan, so the by-id lookup is exact.
    results: list[MemberResult] = []
    for m in all_members:
        if m.member_id in done:
            results.append(done[m.member_id].result)
        else:
            results.append(ran_by_id.get(m.member_id) or MemberResult(
                member_id=m.member_id, status=MemberStatus.ERROR, notes="member produced no result"))

    # S5: AFTER the wave, each NEWLY-run claim-producing member broadcasts one coordination hint, in
    # DETERMINISTIC member/plan order (never during the concurrent wave). Skipped (restored) members are NOT
    # re-broadcast — coordination is advisory and re-posting would only add duplicate hints. sender ==
    # member_id (blackboard anti-spoof). A bus error is swallowed — coordination must never fail the wave.
    if blackboard is not None:
        for m in all_members:
            if m.member_id in done:
                continue
            r = ran_by_id.get(m.member_id)
            if r is None or not r.claims:
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

    # register every escalation as PENDING (signed-approval-only resolution happens elsewhere) BEFORE the
    # final flush, so the registry's redacted `confirmation.register` events are in the buffer when we drain
    # — otherwise they strand un-written and the "durable escalation ledger" is a claim the spine never keeps
    # (red-pen E1 MEDIUM). register is append-only/idempotent, so re-registering a restored member's
    # escalation on resume is a safe no-op.
    if registry is not None:
        for r in results:
            for esc in r.escalations:
                registry.register(esc)

    # Per-member records were already flushed as each member completed; this final drain writes anything
    # still buffered (member tail + the confirmation registry's redacted escalation events just submitted)
    # in deterministic order, and returns the FULL this-run ref list in write order.
    this_run_refs = spine.flush() if spine is not None else []
    # A resumed wave's outcome refs = the refs restored for skipped members (flushed on the run that
    # completed them) + everything written this run. The two are disjoint: a skipped member is never
    # re-submitted, so its old refs never reappear in the fresh queue.
    restored_refs: list[str] = []
    for m in all_members:
        if m.member_id in done:
            restored_refs.extend(done[m.member_id].refs)
    spine_refs = restored_refs + list(this_run_refs)

    rolled: CollectOutcome = collect(results, oracle=oracle, source_prefix=wave_id)
    return FireteamOutcome(
        refused=False, reason="",
        facts=rolled.facts, leads=rolled.leads, escalations=rolled.escalations,
        member_results=results, spine_refs=spine_refs,
    )
