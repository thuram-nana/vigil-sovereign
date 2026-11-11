"""PROCESS-LOCAL, PER-RUN cost tap that attributes reasoning tokens BY MODEL (EC-2b).

This is the measurement sibling of :mod:`vigil_core.run_budget`. ``run_budget`` enforces a single HARD
per-run token ceiling (fail-CLOSED). This records, for one run, HOW MANY tokens each concrete model spent —
the per-model cost breakdown the A/B no-regression harness (``eval.ab``) reads to report the token/$ delta
between an "A capable" arm (routing off) and a "B cheaper" arm (routing on). It gates NOTHING and decides
NOTHING; it only accumulates.

Why it lives in the kernel (not ``vigil_core``): it is read ONLY by the engine-plane A/B harness and written
ONLY at the engine's one LLM chokepoint (``kernel.llm``), so — unlike ``run_budget``, which BOTH isolated
planes import over the two-process boundary — it needs no shared-leaf home. FATAL-2: this module imports
STDLIB ONLY (``os`` + ``contextvars`` + ``threading``); the sole framework reference is
``from .models import CallTrace`` under ``TYPE_CHECKING`` (a type name, never an import at runtime), so it
pulls in no framework/sigil symbol and cannot form an import cycle with ``kernel.llm`` (which imports it).

Doctrine (mirrors ``run_budget``):

  * **Per-run, process-local, covering the threads one run owns.** The accumulator lives in a
    :class:`~contextvars.ContextVar`, so concurrent runs each see their OWN tap — one run's spend never
    lands in another run's breakdown. The run's OWN child threads ARE covered for free: the cost-dominant
    parallel path, the self-consistency sweep (``kernel.consistency.run_consistent`` with ``max_workers>1``),
    propagates the armed context into its pool workers via ``copy_context`` — a ``copy_context`` copies EVERY
    context var, so this tap rides along with the run budget it already propagates, and a parallel sample's
    tokens are attributed to THIS run's tap, not lost. The read-modify-write of the per-model total is lock-
    guarded so concurrent charges never lose an update (correct under free-threaded CPython too, not only by
    GIL accident).

  * **DEFAULT-OFF + byte-identical.** Gated by ``CRUCIBLE_COST_TAP`` (the truthy convention shared with
    ``kernel.routing.routing_enabled`` and ``vigil_core.run_budget.enabled``). With the flag unset :func:`scope`
    arms NO tap, so :func:`record` accumulates nothing and :func:`totals_by_model` is empty — the engine is
    byte-identical to pre-EC-2b and ``make gate`` is unaffected. Only a flag-ON run that entered a
    :func:`scope` ever accumulates.

  * **Determinism preserved.** :func:`record` skips a DRY-RUN trace (and a ``None`` trace) exactly like
    ``run_budget.charge``/``token_budget.record``, so fixture / ``make gate`` runs — which use the dry-run
    backend — never accumulate, and the scored/gated path carries no wall-clock or RNG.
"""
from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING, Iterator, Optional

if TYPE_CHECKING:  # a type name only — NEVER imported at runtime (FATAL-2: stdlib-only module)
    from .models import CallTrace

# The ONE default-off gate (truthy convention shared with ``routing.routing_enabled`` and
# ``run_budget.enabled``).
_ENABLE_ENV = "CRUCIBLE_COST_TAP"


class _CostTap:
    """The per-run slot held in the ContextVar: a model->tokens accumulator + a lock.

    THREAD-SAFE across the threads ONE run owns. A run's parallel self-consistency sweep propagates THIS
    object into its pool workers via ``copy_context`` — every sample's copied context binds the SAME instance
    — so parallel samples ``record`` concurrently. ``_lock`` makes the per-model read-modify-write atomic, so
    concurrent charges never lose an update. (Distinct runs hold DISTINCT instances via the ContextVar, so
    they never contend and never cross-attribute.)"""

    __slots__ = ("totals", "_lock")

    def __init__(self) -> None:
        self.totals: dict[str, int] = {}
        self._lock = threading.Lock()


# Per-run per-model accumulator. Default ``None`` ⇒ UNARMED: every operation is a no-op and the engine is
# byte-identical. A ContextVar (not a module global) so concurrent runs are isolated — see module doctrine.
_TAP: ContextVar[Optional[_CostTap]] = ContextVar("crucible_cost_tap", default=None)


def enabled() -> bool:
    """True iff the operator opted into the per-run cost tap (``CRUCIBLE_COST_TAP`` truthy). Default OFF.
    This is the SINGLE arming gate: when off, :func:`scope` arms no tap, so every :func:`record` is a no-op
    and the engine is byte-identical to pre-EC-2b. Mirrors the truthy convention used by the other kernel
    opt-ins."""
    return os.environ.get(_ENABLE_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def _arm() -> Optional[_CostTap]:
    """Arm a FRESH tap for the current context and return it, or ``None`` when the flag is off (DEFAULT-OFF:
    a pure no-op that leaves the context UNARMED — the property ``make gate`` relies on). Never raises."""
    if not enabled():
        return None
    tap = _CostTap()
    _TAP.set(tap)
    return tap


def record(trace: "CallTrace | None") -> None:
    """Attribute one call's ACTUAL tokens (``tokens_in + tokens_out``) to this run's tap, keyed by the
    trace's concrete ``model``. A no-op when: the tap is UNARMED (flag off / outside a :func:`scope`), the
    trace is ``None``, or the trace is a DRY-RUN (``is_dryrun`` — so fixture / ``make gate`` runs never
    accumulate and determinism/byte-identity is untouched). A 0-token (e.g. cache-hit) trace records nothing.
    An empty ``model`` keys under ``""`` (unattributed) rather than dropping the spend — the per-model
    breakdown must never UNDER-count a run's real tokens. NEVER raises (recording cost must not break a
    completion)."""
    tap = _TAP.get()
    if tap is None or trace is None or getattr(trace, "is_dryrun", False):
        return
    try:
        model = str(getattr(trace, "model", "") or "")
        tokens = int(getattr(trace, "tokens_in", 0) or 0) + int(getattr(trace, "tokens_out", 0) or 0)
    except (TypeError, ValueError):
        return
    if tokens <= 0:
        return
    with tap._lock:
        tap.totals[model] = tap.totals.get(model, 0) + tokens


def totals_by_model() -> dict[str, int]:
    """A snapshot copy of this run's ``model -> tokens`` breakdown (empty ``{}`` when unarmed). A copy, so a
    caller holding it is not racing the live accumulator."""
    tap = _TAP.get()
    if tap is None:
        return {}
    with tap._lock:
        return dict(tap.totals)


def total_tokens() -> int:
    """The run's total reasoning tokens across every model (``0`` when unarmed) — the convenience sum over
    :func:`totals_by_model`."""
    tap = _TAP.get()
    if tap is None:
        return 0
    with tap._lock:
        return sum(tap.totals.values())


def reset() -> None:
    """Disarm the tap for the current context (back to UNARMED). Called at run start/end so one run's
    breakdown never leaks into the next run that reuses this thread/context. Safe (and byte-identical) when
    already unarmed."""
    _TAP.set(None)


@contextmanager
def scope() -> Iterator[None]:
    """Run-scoped cost tap: isolate THIS run's accumulator in a fresh ContextVar slot, arm it (flag-gated),
    and ALWAYS disarm on exit — so a reused thread/task never inherits a stale breakdown. Read the
    accumulated totals with :func:`totals_by_model` (or :func:`total_tokens`) INSIDE the ``with`` block.
    Byte-identical when the flag is off (``_arm`` is a no-op ⇒ the tap stays unarmed ⇒ every ``record`` is
    inert)."""
    token = _TAP.set(None)
    try:
        _arm()
        yield
    finally:
        _TAP.reset(token)
