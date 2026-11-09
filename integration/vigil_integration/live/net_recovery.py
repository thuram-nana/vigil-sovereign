"""
NET-2 — bounded network recovery (#73 "Item B"): the ONE shared, deterministic backoff primitive for the
places where a TRANSIENT network drop should auto-recover instead of latching dead for the rest of a run.

The house pattern is *degrade / fail-safe, never fail-open*. This module does not change that — it only
lets an already-degraded path try again, a BOUNDED number of times, on a deterministic schedule:

  * **DEFAULT-OFF.** :func:`recovery_enabled` reads ``VIGIL_NET_RECOVERY_ENABLED`` and is false unless it is
    an explicit truthy token. :func:`recovery_from_env` returns ``None`` when off, and every adopter treats
    ``None`` as "today's behavior, byte-identical" (e.g. the OTLP sink's circuit breaker stays latched).
  * **BOUNDED — per LIFETIME, not per outage.** A :class:`BoundedBackoff` grants at most ``max_attempts``
    retries over its WHOLE lifetime, each gated by an exponentially growing delay capped at ``cap``
    seconds. A successful retry re-arms the path but does NOT refill the budget or reset the delay
    growth, so a FLAPPING peer (up for one request, down again) is backed off ever harder and finally
    latched for good — never re-armed indefinitely. Once exhausted it NEVER grants again: a down or
    flapping peer costs a fixed, small number of attempts, never an unbounded hammer on a hot path.
  * **DETERMINISTIC.** No jitter, no RNG; the clock is injectable (``clock=``) so tests drive time exactly.
  * **FAIL-SAFE.** Any clock fault or malformed config resolves toward "do not retry now" (stay degraded),
    never toward "retry immediately / unbounded". A retry GRANT is only ever permission to *attempt* the
    same already-pinned operation — this module never widens a destination, an egress floor, or any
    authority. It authorizes nothing.

Stdlib-only and import-clean on BOTH planes (registered in ``test_two_env_boundary._PROBE``): it must never
import ``framework`` / ``strix`` / ``sigil``.
"""

from __future__ import annotations

import os
import time
from typing import Callable, Mapping, Optional

__all__ = [
    "RECOVERY_ENV",
    "BoundedBackoff",
    "recovery_enabled",
    "recovery_from_env",
]

RECOVERY_ENV = "VIGIL_NET_RECOVERY_ENABLED"
_TRUTHY = frozenset({"1", "true", "yes", "on"})

# Conservative defaults: first retry after 5 s, doubling, capped at 5 min, at most 8 retries per lifetime — a
# peer that stays down is given up on after ~15 min of wall time (5+10+20+40+80+160+300+300 s) and 8 attempts
# total, then the path latches as today.
DEFAULT_BASE_S = 5.0
DEFAULT_CAP_S = 300.0
DEFAULT_MAX_ATTEMPTS = 8


def recovery_enabled(env: Optional[Mapping[str, str]] = None) -> bool:
    """True iff ``VIGIL_NET_RECOVERY_ENABLED`` is an explicit truthy token. Unset / empty / anything else ⇒
    False (default-OFF). Total: a non-mapping ``env`` or a non-string value reads as OFF, never raises."""
    try:
        e = os.environ if env is None else env
        return str(e.get(RECOVERY_ENV, "")).strip().lower() in _TRUTHY
    except Exception:  # noqa: BLE001 — a malformed env reads as OFF (fail-safe), never a crash
        return False


def recovery_from_env(env: Optional[Mapping[str, str]] = None, *,
                      clock: Optional[Callable[[], float]] = None) -> Optional["BoundedBackoff"]:
    """The adopter entry point: a fresh :class:`BoundedBackoff` with the conservative defaults when the flag
    is ON, else ``None`` (the adopter keeps today's behavior, byte-identical)."""
    if not recovery_enabled(env):
        return None
    return BoundedBackoff(clock=clock)


def _positive_float(value: object, default: float) -> float:
    try:
        f = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    if f != f or f <= 0.0 or f == float("inf"):  # NaN / non-positive / inf → the safe default
        return default
    return f


def _positive_int(value: object, default: int) -> int:
    if isinstance(value, bool):
        return default
    try:
        i = int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError, OverflowError):
        return default
    return i if i >= 1 else default


class BoundedBackoff:
    """A deterministic, bounded retry schedule for ONE degraded path.

    Lifecycle: the adopter calls :meth:`trip` when the path degrades (e.g. a circuit breaker latches), asks
    :meth:`ready` before each would-be retry, calls :meth:`begin_attempt` when it actually retries, then
    :meth:`succeeded` (re-armed; the next degradation waits afresh) or :meth:`failed` (next, longer delay).
    The budget is per LIFETIME: after ``max_attempts`` retries — successful or not — :attr:`exhausted` is
    True and :meth:`ready` is permanently False, so the path stays degraded for good.

    Delay before retry ``n`` (1-based) is ``min(cap, base * 2**(n-1))`` measured from the last trip/failure.
    """

    def __init__(self, *, base: float = DEFAULT_BASE_S, cap: float = DEFAULT_CAP_S,
                 max_attempts: int = DEFAULT_MAX_ATTEMPTS,
                 clock: Optional[Callable[[], float]] = None) -> None:
        self.base: float = _positive_float(base, DEFAULT_BASE_S)
        self.cap: float = max(self.base, _positive_float(cap, DEFAULT_CAP_S))
        self.max_attempts: int = _positive_int(max_attempts, DEFAULT_MAX_ATTEMPTS)
        self._clock: Callable[[], float] = clock if callable(clock) else time.monotonic
        self.attempts: int = 0                 # retries begun over this policy's LIFETIME (never refilled)
        self._since: Optional[float] = None    # when the current wait started (None ⇒ not tripped)

    # -- introspection ---------------------------------------------------------------------------------

    @property
    def exhausted(self) -> bool:
        """True once every bounded retry has been spent — no further retry is ever granted."""
        return self.attempts >= self.max_attempts

    @property
    def tripped(self) -> bool:
        return self._since is not None

    def next_delay(self) -> float:
        """The wait before the NEXT retry (``attempts`` + 1). Exponential, capped, overflow-safe."""
        n = self.attempts
        if n >= 64:                           # 2**64 * base is already far past any cap
            return self.cap
        return min(self.cap, self.base * float(2 ** n))

    # -- transitions -----------------------------------------------------------------------------------

    def _now(self) -> Optional[float]:
        try:
            t = float(self._clock())
        except Exception:  # noqa: BLE001 — a broken clock means "cannot prove the wait elapsed"
            return None
        if t != t or t in (float("inf"), float("-inf")):
            return None
        return t

    def trip(self) -> None:
        """The path just degraded: start the wait for the first retry. Idempotent while already tripped
        (does NOT restart the wait — repeated degradations cannot postpone recovery indefinitely)."""
        if self._since is None:
            now = self._now()
            if now is None:
                self._give_up()               # cannot anchor the wait ⇒ stay degraded (today's latch)
                return
            self._since = now

    def ready(self) -> bool:
        """May the adopter attempt ONE retry now? False when not tripped, exhausted, the delay has not yet
        elapsed, or the clock cannot be read (fail-safe: stay degraded)."""
        if self._since is None or self.exhausted:
            return False
        now = self._now()
        if now is None:
            return False
        return (now - self._since) >= self.next_delay()

    def begin_attempt(self) -> None:
        """Consume one bounded retry. Counted at the START so a retry that crashes mid-way still spends its
        budget (the bound holds even if the adopter never reports the outcome)."""
        self.attempts += 1

    def failed(self) -> None:
        """The retry failed: restart the wait (the next delay is longer by construction)."""
        now = self._now()
        if now is None:
            self._give_up()                   # cannot anchor the next wait ⇒ stay degraded (today's latch)
            return
        self._since = now

    def _give_up(self) -> None:
        """Fail-safe collapse: spend the whole budget so :meth:`ready` is permanently False — the adopter
        degrades to exactly its pre-NET-2 behavior (a permanent latch), never to an immediate retry."""
        self.attempts = self.max_attempts
        if self._since is None:
            self._since = 0.0                 # tripped (so `tripped` reports truthfully), but never ready

    def succeeded(self) -> None:
        """The path recovered: it is no longer degraded, so clear the wait anchor (a later :meth:`trip`
        starts the next wait). Deliberately does NOT refill the budget or reset the delay growth — a peer
        that flaps (one success, then down again) would otherwise be re-armed forever (NET-2 red-pen MED).
        The next wait is therefore LONGER than the last, and the lifetime budget keeps draining."""
        self._since = None
