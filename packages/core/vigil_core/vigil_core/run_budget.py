"""RUN-SCOPED HARD token budget with a FAIL-CLOSED stop (EC-3).

This is the deliberate fail-CLOSED CONTRAST to :mod:`vigil_core.token_budget`. ``token_budget`` is an
operator-editable, PER-TOOL, PER-UTC-DAY advisory that WARNS + THROTTLES and *never* blocks a call
(fail-OPEN: metering must never break functionality). ``run_budget`` is a single HARD ceiling for ONE
engagement run, token-denominated, that STOPS the run when its cumulative reasoning spend reaches the
ceiling — raising :class:`RunBudgetExceeded` at the one LLM chokepoint BEFORE the overshooting egress.

Why this lives in ``vigil_core``: it is a PURE shared leaf, imported by BOTH isolated planes (the keyless
offense engine enforces it at ``kernel.llm.complete_with_failover``; the sovereign plane may read it) over
the same two-process boundary as ``token_budget``. FATAL-2: this module imports stdlib ONLY (``os`` +
``threading`` + ``contextvars``) — NO ``framework.*``, NO ``sigil.*``, NO offense symbol — like ``token_budget``.
It holds no money number: the engine arms the ceiling from the OWNER-SIGNED
``CreditLaunchLease.units_reserved`` × :data:`vigil_core.ENVELOPE_TOKENS_PER_CREDIT`, so the token ceiling
equals the sovereign reserved envelope BY CONSTRUCTION (one shared constant, never a drift test).

Doctrine:

  * **Run-scoped, process-local, covering the threads one run owns.** The accumulator + ceiling live in a
    :class:`~contextvars.ContextVar`, so concurrent runs each see their OWN budget — one run's spend never
    charges another run's ceiling. One customer run is one process, so per-run == per-process is correct
    (cross-process / pool aggregation is a separate concern — EC-5). The run's OWN child threads ARE covered:
    a ``ContextVar`` is not inherited by a bare ``ThreadPoolExecutor`` worker, so the cost-dominant parallel
    path — the self-consistency sweep (``kernel.consistency.run_consistent`` with ``max_workers>1``) —
    propagates the armed context into its workers via ``copy_context``. Every sample then binds THIS run's
    :class:`_RunBudget` (a lock-guarded accumulator), so the parallel reasoning spend IS charged and the stop
    DOES fire — not just the serial main-thread calls. Concurrent samples check-before / charge-after against
    the one shared slot, so a sweep can overshoot the ceiling by at most its in-flight batch (bounded by
    ``CRUCIBLE_LLM_MAX_WORKERS``) before the next :func:`check_or_raise` stops the run — a HARD ceiling at
    sweep granularity, not a soft target.

  * **DEFAULT-OFF + byte-identical.** Gated by ``VIGIL_RUN_HARD_BUDGET_ENABLED`` (unset ⇒ :func:`arm` is a
    no-op, :func:`current_ceiling` returns ``None``, :func:`charge` accumulates nothing, and
    :func:`check_or_raise` never raises). With the flag off the engine is byte-identical to pre-EC-3 and
    ``make gate`` is unchanged. Only a flag-ON run that is actually armed (a verified lease, or an operator
    ``VIGIL_RUN_TOKEN_CEILING``) ever has a ceiling.

  * **FAIL-CLOSED at the boundary.** The stop fires at ``spent + projected >= ceiling`` (``>=``, not
    ``>``), so reaching the reserved envelope IS the stop — the run can never continue past the ceiling.
"""
from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator, Optional

# The ONE default-off gate (truthy convention shared with the other kernel opt-ins, e.g.
# ``kernel.routing.routing_enabled`` and ``kernel.llm.prompt_cache_disabled``).
_ENABLE_ENV = "VIGIL_RUN_HARD_BUDGET_ENABLED"


class RunBudgetExceeded(Exception):
    """TERMINAL run-budget stop: this run's cumulative reasoning tokens reached its (owner-signed) per-run
    ceiling. A CLEAN stop, not a crash and not a transient — it is raised at the LLM chokepoint BEFORE the
    overshooting egress and propagates out as the run's early-stop signal. It MUST NOT be caught/retried as
    a transient (it is not a :class:`BackendOverloaded`); the engage layer converts it into a PARTIAL
    engagement result that settles consumed-so-far, never a FAILED/full-refund free run."""

    def __init__(self, ceiling: int, spent: int, projected: int = 0) -> None:
        self.ceiling = int(ceiling)
        self.spent = int(spent)
        self.projected = int(projected)
        super().__init__(
            f"run token budget exceeded: spent {self.spent}"
            f"{f' + projected {self.projected}' if self.projected else ''} "
            f">= ceiling {self.ceiling} tokens")


class _RunBudget:
    """The per-run slot held in the ContextVar: a fixed ceiling + a mutable accumulator + a stop latch.

    THREAD-SAFE across the threads ONE run owns. A run's parallel self-consistency sweep
    (``kernel.consistency.run_consistent`` with ``max_workers>1``) propagates THIS object into its pool
    workers via ``copy_context`` — every sample's copied context binds the SAME instance — so parallel
    samples ``charge``/``check_or_raise`` concurrently. ``_lock`` makes the read-modify-write of ``spent``
    and the check-and-latch atomic, so concurrent charges never lose an update and the stop decision is
    consistent. (Distinct runs hold DISTINCT instances via the ContextVar, so they never contend.)"""

    __slots__ = ("ceiling", "spent", "exceeded", "_lock")

    def __init__(self, ceiling: int) -> None:
        self.ceiling = int(ceiling)
        self.spent = 0
        self.exceeded = False
        self._lock = threading.Lock()


# Per-run accumulator+ceiling. Default ``None`` ⇒ UNARMED: every operation is a no-op and the engine is
# byte-identical. A ContextVar (not a module global) so concurrent runs are isolated — see module doctrine.
_BUDGET: ContextVar[Optional[_RunBudget]] = ContextVar("vigil_run_budget", default=None)


def enabled() -> bool:
    """True iff the operator opted into the HARD run budget (``VIGIL_RUN_HARD_BUDGET_ENABLED`` truthy).
    Default OFF. This is the SINGLE arming gate: when off, :func:`arm` refuses to arm, so there is never a
    ceiling and every charge/check is a no-op (byte-identical to pre-EC-3)."""
    return os.environ.get(_ENABLE_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def arm(ceiling_tokens: Optional[int]) -> Optional[int]:
    """Arm THIS run's hard ceiling (in tokens) and zero the accumulator; return the armed ceiling, or
    ``None`` when not armed. DEFAULT-OFF: a pure no-op (returns ``None``, leaves the run UNARMED) when the
    flag is unset — the property ``make gate`` relies on. A ``None`` / non-positive / unparsable ceiling
    also leaves the run unarmed (there is nothing to enforce). Never raises."""
    if not enabled():
        return None
    try:
        c = int(ceiling_tokens)  # ``None`` → TypeError → unarmed
    except (TypeError, ValueError):
        return None
    if c <= 0:
        return None
    _BUDGET.set(_RunBudget(c))
    return c


def charge(tokens: int) -> int:
    """Add ``tokens`` (one call's ACTUAL reasoning spend) to this run's accumulator; return the new
    cumulative spend (``0`` when unarmed). A no-op when unarmed. NEVER raises, and never itself raises
    :class:`RunBudgetExceeded`: the STOP is a separate explicit :func:`check_or_raise` consulted BEFORE the
    next egress, so the call that crosses the ceiling is always allowed to RECORD its spend (the next call
    is the one that is stopped). The caller skips dry-run spend (0 tokens) before calling, mirroring
    ``token_budget.record``."""
    b = _BUDGET.get()
    if b is None:
        return 0
    try:
        n = int(tokens)
    except (TypeError, ValueError):
        n = 0
    # Guard the read-modify-write: a run's parallel self-consistency samples (copy_context-propagated) charge
    # THIS one slot concurrently. CPython's GIL happens to serialize a slot ``+= n`` today, but that is an
    # eval-loop implementation detail, not a language guarantee — and it does NOT hold under free-threaded
    # CPython. The lock makes the money accumulator correct BY CONSTRUCTION, independent of GIL semantics.
    with b._lock:
        if n > 0:
            b.spent += n
        return b.spent


def current_ceiling() -> Optional[int]:
    """This run's armed ceiling in tokens, or ``None`` when UNARMED (flag off / no lease / not armed). The
    engine guards 'is this run metered?' on ``current_ceiling() is not None``."""
    b = _BUDGET.get()
    return b.ceiling if b is not None else None


def spent() -> int:
    """Cumulative reasoning tokens charged to this run (``0`` when unarmed)."""
    b = _BUDGET.get()
    return b.spent if b is not None else 0


def remaining() -> Optional[int]:
    """Tokens left under the ceiling (``ceiling - spent``), or ``None`` when unarmed. May be negative if the
    crossing call overshot before the next :func:`check_or_raise` stopped the run."""
    b = _BUDGET.get()
    return (b.ceiling - b.spent) if b is not None else None


def would_exceed(projected: int = 0) -> bool:
    """True iff the run is armed AND ``spent + projected >= ceiling`` (``>=`` — fail-closed at the
    boundary). False when unarmed. A pure predicate — never raises, never latches."""
    b = _BUDGET.get()
    if b is None:
        return False
    try:
        p = max(0, int(projected))
    except (TypeError, ValueError):
        p = 0
    return (b.spent + p) >= b.ceiling


def check_or_raise(projected: int = 0) -> None:
    """FAIL-CLOSED stop: raise :class:`RunBudgetExceeded` iff the run is armed AND
    ``spent + projected >= ceiling``. A no-op when unarmed (so the default path is byte-identical). The
    kernel calls this with ``projected=0`` immediately BEFORE each egress ('already at/over the ceiling ⇒
    stop'); the ``>=`` makes reaching the reserved envelope itself the stop. Latches :func:`was_exceeded`
    so the run can report a clean budget stop even when an intermediate best-effort phase (whose wrapper
    swallows exceptions) catches the raise."""
    b = _BUDGET.get()
    if b is None:
        return
    try:
        p = max(0, int(projected))
    except (TypeError, ValueError):
        p = 0
    # Take the stop decision + set the latch atomically w.r.t. concurrent charges (parallel samples), then
    # raise OUTSIDE the lock (exception construction/propagation must not hold it).
    with b._lock:
        over = (b.ceiling, b.spent, p) if (b.spent + p) >= b.ceiling else None
        if over is not None:
            b.exceeded = True
    if over is not None:
        raise RunBudgetExceeded(ceiling=over[0], spent=over[1], projected=over[2])


def was_exceeded() -> bool:
    """True iff this run's budget stop has fired (the latch set by :func:`check_or_raise`). Lets the engage
    layer surface a clean ``stopped_reason`` even when a best-effort phase swallowed the raise. False when
    unarmed."""
    b = _BUDGET.get()
    return bool(b.exceeded) if b is not None else False


def reset() -> None:
    """Disarm the run budget for the current context (back to UNARMED). Called at run start/end so a
    ceiling never leaks into the next run that reuses this thread/context. Safe (and byte-identical) when
    already unarmed."""
    _BUDGET.set(None)


@contextmanager
def scope(ceiling_tokens: Optional[int] = None) -> Iterator[Optional[int]]:
    """Run-scoped budget: isolate THIS run's accumulator in a fresh ContextVar slot, optionally :func:`arm`
    it (flag-gated), and ALWAYS disarm on exit — so a reused thread/task never inherits a stale ceiling.
    Yields the armed ceiling (or ``None``). Byte-identical when the flag is off (``arm`` is a no-op ⇒ yields
    ``None``)."""
    token = _BUDGET.set(None)
    try:
        yield arm(ceiling_tokens) if ceiling_tokens is not None else None
    finally:
        _BUDGET.reset(token)
