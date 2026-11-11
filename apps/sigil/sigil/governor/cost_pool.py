"""EC-5 — the GLOBAL (cross-tenant) cost POOL meter + graduated kill-switch (sovereign plane).

Where EC-4 (``cost_ledger.py``) is the PER-TENANT token-cost envelope ledger, this is the GLOBAL cap on top
of it: a pure READ-ONLY fold over the existing owner-signed cost records, aggregated across ALL tenants
(``CostEnvelopeLedger.global_position`` — Σ committed settled tokens + Σ in-flight reserved envelope), compared
to an OWNER-set pool budget. As the pool depletes it returns a GRADUATED posture:

    NORMAL → THROTTLE → DEGRADE (admit a SMALLER envelope) → REFUSE_NEW (admit 0 new) → HARD_STOP

The launch gate composes this as ONE MORE fail-closed conjunct (``LaunchGate._gated``): REFUSE_NEW / HARD_STOP
refuse a NEW launch (the safe, reversible access-reducing direction — in-flight launches still SETTLE and free
the pool, so the pool AUTO-RELAXES with no owner-signed un-latch, hence no release-replay surface). It folds NO
new signed record, so EC-5 does NOT bump the snapshot schema and does NOT change reserve/settle or the record
model — it only READS the existing v9 cost folds.

THREE load-bearing directions (each a mutation guard):
  * DEFAULT-OFF, BYTE-IDENTICAL: ``budget_tokens`` None/0 ⇒ the pool is UNBOUNDED ⇒ ``posture()`` short-circuits
    to NORMAL and ``admit()`` admits the FULL request **BEFORE any ledger fold** — an unset pool is zero-cost.
  * FAIL-CLOSED SAFE DIRECTION: when the pool IS armed (budget set) and a ledger read/fold RAISES, ``posture()``
    / ``admit()`` return **REFUSE_NEW (never NORMAL)** — an armed pool that cannot measure refuses new draw, the
    access-reducing direction (mirrors ``Governor.decide``'s kill/budget DENY and ``KillSwitch``'s fail-safe).
  * MONOTONE GRADUATION: postures are totally ordered and the admitted envelope is NON-INCREASING in the
    used-fraction — a higher fraction never admits MORE than a lower one; the shrink is a reduction floored at 1.

MONEY ANCHOR: the pool THRESHOLD is an OWNER number (``config.global_pool_tokens`` / band fractions — a
reviewed-code placeholder + env, NEVER a wire value); pool USAGE sums ONLY owner-signed ``verify_signed`` cost
records (a forged / unsigned / negative record is inert — inherited from ``cost_ledger._fold`` + ``_as_tokens``).
The credit→token envelope E is single-sourced in ``vigil_core.ENVELOPE_TOKENS_PER_CREDIT`` (referenced, not
re-defined). FATAL-2: sovereign-plane, ``assert_no_offense`` at import; imports nothing from the engine/offense
plane (only ``cost_ledger`` + ``config`` + the ``vigil_core`` envelope constant).
"""
from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core import ENVELOPE_TOKENS_PER_CREDIT  # noqa: E402,F401  (the credit→token envelope E, re-exported for the gate)

from .. import config  # noqa: E402
from .cost_ledger import CostEnvelopeLedger  # noqa: E402,F401  (the owner-signed cost record source; type ref)


class PoolPosture(enum.Enum):
    """The graduated pool posture, totally ordered NORMAL < THROTTLE < DEGRADE < REFUSE_NEW < HARD_STOP (the
    integer value IS the order, so a monotonicity assertion can compare them directly)."""
    NORMAL = 0
    THROTTLE = 1
    DEGRADE = 2
    REFUSE_NEW = 3
    HARD_STOP = 4


@dataclass(frozen=True)
class PoolBands:
    """The owner-set band fractions (fraction used/budget at which each posture engages) + the DEGRADE shrink
    factor. Monotone by contract; ``from_config`` validates + falls back to safe defaults (fail-safe)."""
    throttle_at: float = 0.75
    degrade_at: float = 0.85
    refuse_at: float = 0.95
    hard_stop_at: float = 1.0
    degrade_factor: float = 0.5

    @classmethod
    def from_config(cls) -> "PoolBands":
        """The owner-ratified band set from ``config.global_pool_bands`` (env-overridable safe placeholders;
        a non-monotone / out-of-range override reverts to the safe defaults there)."""
        b = config.global_pool_bands()
        return cls(throttle_at=b["throttle_at"], degrade_at=b["degrade_at"], refuse_at=b["refuse_at"],
                   hard_stop_at=b["hard_stop_at"], degrade_factor=b["degrade_factor"])


@dataclass(frozen=True)
class PoolPosition:
    """A point-in-time pool reading: the global draw vs the owner budget, the used-fraction, and the posture."""
    used_tokens: int
    pool_tokens: Optional[int]     # None ⇒ UNBOUNDED (default-off)
    fraction: float                # used/budget (0.0 when unbounded — there is no fraction of infinity)
    posture: PoolPosture


class GlobalCostPool:
    """The global cost-pool meter + graduated kill-switch over an EC-4 ``CostEnvelopeLedger``.

    ``budget_tokens`` None/0 ⇒ UNBOUNDED (default-off): every read short-circuits to NORMAL / full admit WITHOUT
    folding the ledger. Armed (budget >= 1): the posture is a pure function of ``global_position().used``
    over the owner budget, fail-closed to REFUSE_NEW on any measurement error."""

    def __init__(self, ledger, *, budget_tokens: Optional[int] = None, bands: Optional[PoolBands] = None):
        self._ledger = ledger
        # Normalize the budget: 0 / negative / non-int ⇒ UNBOUNDED (None), mirroring config.global_pool_tokens.
        b: Optional[int]
        try:
            b = int(budget_tokens) if budget_tokens is not None else None
        except (TypeError, ValueError):
            b = None
        self._budget_tokens = b if (b is not None and b >= 1) else None
        self._bands = bands if bands is not None else PoolBands.from_config()

    # -- arming ---------------------------------------------------------------------------------------
    def is_armed(self) -> bool:
        """True iff the pool has an owner budget (>= 1). Unbounded (default) ⇒ False ⇒ every read is a
        byte-identical no-op that NEVER folds the ledger."""
        return self._budget_tokens is not None

    @property
    def budget_tokens(self) -> Optional[int]:
        return self._budget_tokens

    # -- measurement ----------------------------------------------------------------------------------
    def _used(self) -> int:
        """The global pool draw in tokens — Σ committed settled + Σ in-flight reserved envelope, across ALL
        tenants, in ONE O(spine) pass. Only called when the pool is ARMED (the unbounded path never folds)."""
        pos = self._ledger.global_position()
        return int(pos.used_tokens)

    def _posture_for(self, used: int, budget: int) -> PoolPosture:
        """The band lookup — the single comparison that defines the graduation. The thresholds are ``>=``
        (a used-fraction that REACHES a band engages it): the access-reducing boundary direction."""
        frac = used / budget
        if frac >= self._bands.hard_stop_at:
            return PoolPosture.HARD_STOP
        if frac >= self._bands.refuse_at:
            return PoolPosture.REFUSE_NEW
        if frac >= self._bands.degrade_at:
            return PoolPosture.DEGRADE
        if frac >= self._bands.throttle_at:
            return PoolPosture.THROTTLE
        return PoolPosture.NORMAL

    def posture(self) -> PoolPosture:
        """The current pool posture. UNBOUNDED (default-off) ⇒ NORMAL WITHOUT folding. ARMED ⇒ fold the global
        position and band it; FAIL-CLOSED to REFUSE_NEW (never NORMAL) if the measurement raises."""
        if self._budget_tokens is None:
            return PoolPosture.NORMAL                      # default-off short-circuit — NO fold
        try:
            used = self._used()
        except Exception:  # noqa: BLE001 — an armed pool that cannot MEASURE refuses new draw (fail-closed)
            return PoolPosture.REFUSE_NEW
        return self._posture_for(used, self._budget_tokens)

    def position(self) -> PoolPosition:
        """A full point-in-time reading (for status/observability). UNBOUNDED ⇒ used=0, fraction=0.0, NORMAL,
        WITHOUT folding. ARMED ⇒ the real draw; fail-closed to REFUSE_NEW (used reported -1 as 'unmeasurable')."""
        if self._budget_tokens is None:
            return PoolPosition(used_tokens=0, pool_tokens=None, fraction=0.0, posture=PoolPosture.NORMAL)
        try:
            used = self._used()
        except Exception:  # noqa: BLE001 — fail-closed: report REFUSE_NEW even though the draw is unknown
            return PoolPosition(used_tokens=-1, pool_tokens=self._budget_tokens, fraction=float("inf"),
                                posture=PoolPosture.REFUSE_NEW)
        return PoolPosition(used_tokens=used, pool_tokens=self._budget_tokens,
                            fraction=used / self._budget_tokens, posture=self._posture_for(used, self._budget_tokens))

    # -- admission ------------------------------------------------------------------------------------
    def admit(self, requested_units_tokens: int) -> tuple[int, PoolPosture, str]:
        """Admit a NEW draw of ``requested_units_tokens`` tokens against the pool, returning
        ``(admitted_tokens, posture, reason)`` under the graduation. The admitted envelope is NON-INCREASING in
        the used-fraction, floored at >= 1 when admitted at all, and NEVER exceeds the request.

        UNBOUNDED (default-off): admit the FULL request at NORMAL **BEFORE any ledger fold** (zero-cost). ARMED:
          * NORMAL / THROTTLE → full admit (THROTTLE is a pressure SIGNAL; the hard shrink starts at DEGRADE);
          * DEGRADE           → a SMALLER envelope (``request * degrade_factor``, floored >= 1, never > request);
          * REFUSE_NEW / HARD_STOP → admit 0 (no new draw); an in-flight launch still settles and frees the pool.
        FAIL-CLOSED: an armed pool whose meter raises postures REFUSE_NEW, so ``admit`` admits 0."""
        try:
            req = int(requested_units_tokens)
        except (TypeError, ValueError):
            req = 0
        if req < 0:
            req = 0
        if self._budget_tokens is None:
            # DEFAULT-OFF short-circuit: full admit, NORMAL, NO fold (an unset pool is byte-identical/zero-cost).
            return (req, PoolPosture.NORMAL, "pool unbounded (default-off): full admit")
        p = self.posture()                                 # folds; fail-closed REFUSE_NEW on measurement error
        if p is PoolPosture.HARD_STOP:
            return (0, p, "global cost pool HARD_STOP: no new draw admitted")
        if p is PoolPosture.REFUSE_NEW:
            return (0, p, "global cost pool REFUSE_NEW: refusing new draw while over capacity")
        if p is PoolPosture.DEGRADE:
            if req < 1:
                return (0, p, "global cost pool DEGRADE: nothing to admit")
            admitted = int(req * self._bands.degrade_factor)
            if admitted < 1:
                admitted = 1                               # FLOOR >= 1: a degraded admit is still a real draw
            if admitted > req:
                admitted = req                             # NEVER exceed the request (defensive; factor <= 1)
            return (admitted, p, f"global cost pool DEGRADE: admitting a smaller envelope ({admitted} of {req})")
        # NORMAL or THROTTLE — full admit
        reason = "global cost pool NORMAL" if p is PoolPosture.NORMAL else "global cost pool THROTTLE (full admit, pressure rising)"
        return (req, p, reason)

    # -- gate conjunct --------------------------------------------------------------------------------
    def gate_refusal(self) -> Optional[str]:
        """The launch-gate POOL conjunct: None if a NEW launch may proceed, else the refusal reason. UNBOUNDED
        (default) ⇒ None (byte-identical no-op — NO fold). ARMED + REFUSE_NEW / HARD_STOP ⇒ the reason string.
        FAIL-CLOSED: an armed pool whose meter raises postures REFUSE_NEW, so this refuses. THROTTLE / DEGRADE
        do NOT refuse here (they are softer rungs; the gate admits the launch — the sovereign-pure envelope
        shrink lives in ``admit`` for callers that meter per-draw)."""
        if self._budget_tokens is None:
            return None                                    # default-off: NEVER fold, NEVER refuse
        p = self.posture()
        if p is PoolPosture.REFUSE_NEW or p is PoolPosture.HARD_STOP:
            return (f"global cost pool {p.name}: new launches are refused while the pool is over capacity "
                    f"(in-flight assessments still settle and free the pool)")
        return None
