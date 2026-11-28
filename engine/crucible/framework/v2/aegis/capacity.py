"""aegis.capacity — AS-5a: the gateway CAPACITY admission plane (availability-first load shedding).

The gateway has FINITE serving capacity (a bounded thread pool fronting one upstream). Under load it
must shed EXCESS work rather than queue unboundedly and take the operator's app down with it. This
module is the deterministic admission model the gateway consults per request:

  * PER-CALLER FAIRNESS — each caller (the gateway's stable per-actor key: the client IP) gets its OWN
    independent token-bucket rate budget AND its own in-flight concurrency cap, so one caller's flood is
    shed against ITS budget and can never consume another caller's share. This is the "capacity-planned
    per tenant, not assumed" discipline (ADR-0003) applied at the data plane: a single abusive client
    cannot starve the rest of a tenant's traffic.
  * GLOBAL HEADROOM — a global in-flight cap additionally bounds the gateway's TOTAL concurrent work, so
    the sum of many callers cannot exhaust the finite thread pool.

Doctrine (non-negotiable, enforced here and tested):
  * AVAILABILITY-FIRST, NEVER A BLOCK. A shed is a SOFT, RETRYABLE 503 (``Retry-After``). It is NOT a
    block: it mints no certificate and no attack verdict. A hard block rides ONLY on a fired oracle's
    re-runnable certificate (prove-don't-guess); capacity is an operational signal, never a finding —
    exactly as belief (``response_policy``) is never a block. Shedding load is the fail-safe, not the app
    going down.
  * DETERMINISM. No wall-clock and no RNG: the monotonic clock is INJECTED, and the token bucket is a
    pure function of (stored tokens, last-refill time, now, rate). A fixed request sequence over a fixed
    clock yields the identical admit/shed pattern, so the policy is reproducible in tests and in audit.
  * FAIL-OPEN. Any internal governor error ADMITS (never sheds on the governor's own fault) — the
    capacity layer can only ever REDUCE load it is sure is excess; when unsure, it lets traffic through.
  * BOUNDED MEMORY. Idle callers (full bucket, zero in-flight) are evicted once the caller map exceeds a
    cap, so a spray of one-shot source IPs cannot grow the state without bound.

DEFAULT-OFF: nothing here runs unless a gateway is given a ``CapacityBudget`` AND the strict, fail-closed
``VIGIL_AEGIS_CAPACITY`` flag is set. OFF ⇒ the governor is never consulted and the gateway path is
byte-identical.

FATAL-2: engine leg — imports ONLY the stdlib. No ``vigil_core`` (nothing here needs the shared contracts),
no ``sigil``/``governor``/``strix``, nothing on the scan/engage/benchmark gate path. It adds NO OracleKind
and registers NO vocabulary, so the make-gate byte-identity is structurally untouched.
"""

from __future__ import annotations

import itertools
import math
import os
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

__all__ = [
    "CAPACITY_ENV",
    "Admission",
    "CapacityBudget",
    "CapacityGovernor",
    "capacity_enabled",
]

# The default-OFF switch for the capacity admission plane — strict, fail-closed, read per request (so a
# deployment can be flipped without a restart, exactly like the enforce / gateway-v2 flags). Only an explicit
# affirmative token turns it on; anything else (unset, typo, "0", "false") keeps capacity admission OFF.
CAPACITY_ENV = "VIGIL_AEGIS_CAPACITY"

# Bound the per-caller state map: once it exceeds this, idle callers (full bucket, zero in-flight) are evicted
# on the next admit so a spray of one-shot source IPs cannot grow the map without bound.
_MAX_TRACKED_CALLERS = 8192


def capacity_enabled() -> bool:
    """Is the capacity admission plane armed? Strict, fail-closed, DEFAULT OFF — only an explicit affirmative
    token arms it (mirrors ``gateway._saas_enforce_flag`` / ``broker.broker_enabled``). The governor object is
    still consulted only when a budget was configured AND this returns True."""
    return (os.environ.get(CAPACITY_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class CapacityBudget:
    """The fixed capacity budget a gateway enforces. Per-caller dimensions give FAIRNESS (each caller
    independent); the global dimension bounds the gateway's TOTAL concurrent work.

    * ``rate_per_s``  — sustained admits/second per caller (the token-bucket refill rate). > 0.
    * ``burst``       — the bucket capacity per caller (the largest instantaneous burst a caller may admit).
                        >= 1.
    * ``max_inflight_per_caller`` — max concurrent in-flight requests per caller; 0 ⇒ unlimited.
    * ``max_inflight_global``     — max concurrent in-flight requests across ALL callers; 0 ⇒ unlimited.

    Fail-closed construction: a non-positive rate / burst, or a negative cap, is a configuration error, not a
    silently-ignored field."""

    rate_per_s: float
    burst: int
    max_inflight_per_caller: int = 0
    max_inflight_global: int = 0

    def __post_init__(self) -> None:
        if not (isinstance(self.rate_per_s, (int, float)) and self.rate_per_s > 0):
            raise ValueError("CapacityBudget.rate_per_s must be a positive number")
        if not (isinstance(self.burst, int) and self.burst >= 1):
            raise ValueError("CapacityBudget.burst must be an integer >= 1")
        if not (isinstance(self.max_inflight_per_caller, int) and self.max_inflight_per_caller >= 0):
            raise ValueError("CapacityBudget.max_inflight_per_caller must be an integer >= 0 (0 = unlimited)")
        if not (isinstance(self.max_inflight_global, int) and self.max_inflight_global >= 0):
            raise ValueError("CapacityBudget.max_inflight_global must be an integer >= 0 (0 = unlimited)")


@dataclass(frozen=True)
class Admission:
    """One admission decision. ``admitted`` True ⇒ the request may proceed and a concurrency slot was taken
    (release it with :meth:`CapacityGovernor.release` passing this object). ``admitted`` False ⇒ SHED: the
    gateway returns a soft, retryable 503 after ``retry_after_header`` seconds. NEVER a block — this carries
    no certificate and no verdict. ``acquire_id`` is the opaque handle the governor uses to release exactly
    the slot it granted (so a double-release is a no-op); it is 0 on a shed."""

    admitted: bool
    reason: str
    caller: str = ""
    retry_after_s: float = 0.0
    acquire_id: int = 0

    @property
    def retry_after_header(self) -> int:
        """The integer ``Retry-After`` seconds for the 503 — always >= 1 so a client always backs off."""
        try:
            return max(1, int(math.ceil(self.retry_after_s)))
        except (ValueError, OverflowError):
            return 1


class _Bucket:
    """One caller's mutable state: a token bucket (rate budget) + an in-flight counter (concurrency)."""

    __slots__ = ("tokens", "last", "inflight")

    def __init__(self, tokens: float, last: float) -> None:
        self.tokens = tokens
        self.last = last
        self.inflight = 0


class CapacityGovernor:
    """The per-caller capacity admission governor. Thread-safe (the gateway server is threaded): every read
    and mutation of the shared state is serialised under one lock. Deterministic given an injected monotonic
    clock — the token refill is a pure function of (stored tokens, last-refill, now, rate), no wall-clock and
    no RNG. FAIL-OPEN: any internal error in :meth:`admit` ADMITS.

    The governor NEVER blocks: a refusal is a soft, retryable shed. The gateway maps it to a 503 + Retry-After,
    exactly as it maps a sustained-belief escalation to a soft 429 — both availability-first, neither a block."""

    def __init__(self, budget: CapacityBudget, *, monotonic: Callable[[], float] = time.monotonic,
                 max_tracked: int = _MAX_TRACKED_CALLERS) -> None:
        self._budget = budget
        self._now = monotonic
        self._max_tracked = max(1, int(max_tracked))
        self._lock = threading.Lock()
        self._callers: "dict[str, _Bucket]" = {}
        self._global_inflight = 0
        # acquire ids — a monotonic counter (NOT a wall-clock / rng) so each granted slot has a unique handle
        # and a double-release of the same handle is a safe no-op.
        self._ids = itertools.count(1)
        self._live: "dict[int, str]" = {}   # acquire_id -> caller, for exactly-once release

    # -- internal (hold the lock) ------------------------------------------------------------------------

    def _refill(self, b: _Bucket, now: float) -> None:
        """Refill ``b`` to min(burst, tokens + rate*elapsed). Pure; a non-monotone clock (now < last) adds no
        tokens rather than draining them (clock safety)."""
        elapsed = now - b.last
        if elapsed > 0:
            b.tokens = min(float(self._budget.burst), b.tokens + elapsed * self._budget.rate_per_s)
        b.last = now

    def _evict_if_needed(self, now: float, exclude: str) -> None:
        """Bound the caller map: when it exceeds the cap, drop callers whose rate budget has ALREADY fully
        recovered at ``now`` (effective tokens >= burst) and that hold no in-flight slot. Dropping such a caller
        only forgets history that is already back to the full-budget starting state, so it changes no live
        decision (a returning caller is recreated with a full bucket — identical). The recovery is computed with
        the injected clock (refill is lazy, so a stale stored-token count must not keep an idle caller pinned).
        NEVER evict an in-flight caller (that would lose a concurrency slot), nor ``exclude`` — the caller being
        admitted right now, which starts with a full bucket and would otherwise evict itself. Recovered callers are
        preferred for eviction (forgetting them resets nothing); but BOUNDED MEMORY is non-negotiable, so when the
        recovered set alone cannot bring the map back under the cap — a spray of distinct one-shot source IPs all
        still mid-refill — the least-recently-seen idle callers are force-evicted as a hard-cap fallback (see
        below). The map is therefore bounded by ``max(_max_tracked, concurrent in-flight callers)``, never by the
        attacker-controlled distinct-IP arrival rate."""
        if len(self._callers) <= self._max_tracked:
            return
        full = float(self._budget.burst)
        rate = self._budget.rate_per_s
        drop = [k for k, b in self._callers.items()
                if k != exclude and b.inflight == 0 and (b.tokens + max(0.0, now - b.last) * rate) >= full]
        for k in drop:
            del self._callers[k]
        # Hard cap — BOUNDED MEMORY is non-negotiable. If the recovered-only pass above did not get us back under
        # the cap (distinct one-shot callers all still mid-refill, so none is "fully recovered"), force-evict the
        # LEAST-RECENTLY-SEEN idle callers (smallest ``last`` first) until at the cap. An evicted caller still
        # carrying rate debt is recreated with a full bucket only if it ever returns — a bounded fairness leak for
        # the stalest callers that the availability-first doctrine accepts over unbounded state growth. In-flight
        # callers (and ``exclude``) are never dropped, so the surviving map is bounded by the cap plus the number
        # of concurrently in-flight callers — the latter itself capped by the global in-flight limit.
        if len(self._callers) > self._max_tracked:
            evictable = sorted((b.last, k) for k, b in self._callers.items()
                               if k != exclude and b.inflight == 0)
            for _last, k in evictable:
                if len(self._callers) <= self._max_tracked:
                    break
                del self._callers[k]

    # -- the admission decision --------------------------------------------------------------------------

    def admit(self, caller: str, *, now: Optional[float] = None) -> Admission:
        """Decide whether ``caller`` may proceed RIGHT NOW. Checks, in order (all availability-first — the
        FIRST hit sheds, never a block):

          1. GLOBAL in-flight headroom — the whole gateway is at its concurrent-work cap;
          2. PER-CALLER in-flight cap — this caller already holds its max concurrent requests;
          3. PER-CALLER rate budget — this caller's token bucket is empty (sustained over-rate).

        On admit it CONSUMES one token and takes a per-caller + global concurrency slot, returning an
        :class:`Admission` whose ``acquire_id`` the caller passes back to :meth:`release`. FAIL-OPEN: any
        internal error returns an admit (the capacity layer never sheds on its own fault)."""
        try:
            key = caller or "anon"
            t = self._now() if now is None else float(now)
            with self._lock:
                b = self._callers.get(key)
                if b is None:
                    # a brand-new caller starts with a FULL bucket (no penalty for arriving) at time t.
                    b = _Bucket(tokens=float(self._budget.burst), last=t)
                    self._callers[key] = b
                    self._evict_if_needed(t, exclude=key)
                else:
                    self._refill(b, t)

                g_cap = self._budget.max_inflight_global
                if g_cap and self._global_inflight >= g_cap:
                    return Admission(False, "global capacity saturated", caller=key,
                                     retry_after_s=self._retry_after(b))
                c_cap = self._budget.max_inflight_per_caller
                if c_cap and b.inflight >= c_cap:
                    return Admission(False, "per-caller concurrency saturated", caller=key,
                                     retry_after_s=self._retry_after(b))
                if b.tokens < 1.0:
                    return Admission(False, "per-caller rate budget exhausted", caller=key,
                                     retry_after_s=self._retry_after(b))

                # admit: consume one token, take a per-caller + global concurrency slot, mint a release handle.
                b.tokens -= 1.0
                b.inflight += 1
                self._global_inflight += 1
                aid = next(self._ids)
                self._live[aid] = key
                return Admission(True, "admitted", caller=key, acquire_id=aid)
        except Exception:
            # FAIL-OPEN: a governor fault must never shed real traffic.
            return Admission(True, "admit (fail-open: governor error)", caller=caller or "anon")

    def _retry_after(self, b: _Bucket) -> float:
        """Seconds until the caller's bucket holds one token again (the honest back-off for a rate shed). For a
        concurrency shed the bucket may be full, so this is ~0 ⇒ the header floors it to 1s."""
        deficit = 1.0 - b.tokens
        if deficit <= 0:
            return 0.0
        rate = self._budget.rate_per_s
        return deficit / rate if rate > 0 else 1.0

    def release(self, admission: "Admission | int | None") -> None:
        """Release the concurrency slot a prior admit granted. Takes the :class:`Admission` (or its
        ``acquire_id``). EXACTLY-ONCE and total: an unknown / already-released / shed handle is a safe no-op,
        and the per-caller and global in-flight counters never go below zero. Called from the gateway's
        ``finally`` so a slot is always returned, even on a handler error."""
        try:
            aid = admission.acquire_id if isinstance(admission, Admission) else int(admission or 0)
            if aid <= 0:
                return
            with self._lock:
                key = self._live.pop(aid, None)
                if key is None:
                    return   # already released, or never granted — no-op
                b = self._callers.get(key)
                if b is not None and b.inflight > 0:
                    b.inflight -= 1
                if self._global_inflight > 0:
                    self._global_inflight -= 1
        except Exception:
            # releasing must never raise into the gateway's finally.
            return

    # -- introspection (read-only; for an operator status probe / tests) ---------------------------------

    def snapshot(self) -> "dict[str, int]":
        """A read-only, honest snapshot of the live load: total callers tracked and total global in-flight.
        Carries no per-caller address (metadata only), so it is safe for an operator status surface."""
        with self._lock:
            return {"tracked_callers": len(self._callers), "global_inflight": self._global_inflight}
