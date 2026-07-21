"""
kb.budget — the non-authoritative budget / rate / spend meter (VIGIL-FUSION F12).

A reimplementation of redamon's ``llm_guard`` metering (MIT: a per-(user,ip) token bucket + a rolling
24h spend cap + a constant-time internal-key check) as a governor that can only DEFER — never gate a
finding's truth and never authorize an action. The sovereign inversions:

  * **Non-authoritative.** A :class:`BudgetVerdict` deliberately carries NO ``allowed``/``authorized``
    field. Its ``defer`` flag is advisory back-pressure ("throttle the next expensive call") in the
    exact spirit of VIGIL's RL/metacog re-rank/defer layer. A finding's truth is the oracle's sole
    job and an action's authorization is the conjunctive gate's — an over-budget signal changes
    neither. Over budget just means: prefer to wait.
  * **Deterministic + spine-safe.** No wallclock and no RNG: the caller injects a monotonic ``now``
    tick (a sequence value), so refill and the rolling window are pure functions of injected time.
    The ledger is append-only.
  * **Fail-closed / total.** A malformed ``now``/``cost``, or a request the meter cannot account for,
    DEFERS (the conservative spend direction) rather than raising or silently spending. The
    constant-time key check inverts redamon's fail-OPEN "no secret configured → allow": here an empty
    expected secret is NOT a match.
  * **Secret-free.** Optional per-charge ``meta`` is scrubbed through the ONE F3 redaction path
    (``tools.redact_tool_args``) before it is retained, so a credential never lands in the ledger.

Import-clean: stdlib (``hmac``/``math``) + the F3 redactor only; no framework/strix/network/wallclock.
"""

from __future__ import annotations

import hmac
import math
from dataclasses import dataclass, field
from typing import Any, Optional

from ..tools import redact_tool_args


def _num(x: Any) -> Optional[float]:
    """Coerce to a finite float, totally. Rejects bool, non-numeric, NaN and ±inf → ``None``."""
    if isinstance(x, bool):
        return None
    if not isinstance(x, (int, float)):
        return None
    try:
        v = float(x)
    except (OverflowError, ValueError, TypeError):
        # e.g. an int too large to convert to float — a malformed magnitude DEFERS, never raises.
        return None
    if math.isnan(v) or math.isinf(v):
        return None
    return v


def _key(k: Any) -> str:
    """A stable string bucket key. A non-string / empty key collapses to a shared ``"_"`` bucket so the
    meter still accounts (conservatively) rather than silently skipping."""
    if isinstance(k, str) and k.strip():
        return k
    return "_"


def constant_time_key_match(provided: Any, expected: Any) -> bool:
    """Constant-time internal-key comparison (redamon's ``_key_ok`` via ``hmac.compare_digest``), with
    the fail-OPEN default INVERTED: a non-string input or an empty configured ``expected`` secret is
    NEVER a match. This is a rate-limit-scoping identity check only — it authorizes nothing."""
    if not isinstance(provided, str) or not isinstance(expected, str) or not expected:
        return False
    return hmac.compare_digest(provided, expected)


@dataclass
class _Bucket:
    tokens: float
    last: float


@dataclass
class TokenBucket:
    """A deterministic token bucket keyed by an arbitrary string. ``now`` is an injected monotonic tick;
    refill = elapsed ticks × ``refill_per_tick``, capped at ``capacity``. Totally fail-closed: a
    malformed ``now`` refuses to advance state and reports "no token" (defer)."""

    capacity: float
    refill_per_tick: float
    _state: dict[str, _Bucket] = field(default_factory=dict)

    def try_consume(self, key: Any, amount: float = 1.0, *, now: Any) -> bool:
        """Attempt to spend ``amount`` tokens for ``key`` at injected ``now``. Returns ``True`` if the
        bucket covered it (tokens decremented), else ``False`` (defer). Never raises."""
        n = _num(now)
        amt = _num(amount)
        if n is None or amt is None or amt < 0:
            return False
        k = _key(key)
        cap = max(0.0, self.capacity)
        b = self._state.get(k)
        if b is None:
            b = _Bucket(tokens=cap, last=n)
            self._state[k] = b
        elapsed = n - b.last
        if elapsed > 0:
            b.tokens = min(cap, b.tokens + elapsed * max(0.0, self.refill_per_tick))
            b.last = n
        elif elapsed < 0:
            # time went backwards (a bad injected tick) — do not credit; just re-anchor conservatively.
            b.last = n
        if b.tokens >= amt:
            b.tokens -= amt
            return True
        return False


@dataclass
class RollingSpendCap:
    """A rolling-window spend cap keyed by an arbitrary string. Append-only: each charge appends a
    ``(now, amount)`` entry; entries older than ``now - window`` are pruned from the live-sum view but
    the accounting is monotone. ``now`` is injected (no wallclock)."""

    cap: float
    window: float
    _log: dict[str, list[tuple[float, float]]] = field(default_factory=dict)

    def _prune_sum(self, key: str, now: float) -> float:
        entries = self._log.get(key, [])
        horizon = now - max(0.0, self.window)
        kept = [(t, a) for (t, a) in entries if t > horizon]
        self._log[key] = kept
        return math.fsum(a for _t, a in kept)

    def current(self, key: Any, *, now: Any) -> Optional[float]:
        n = _num(now)
        if n is None:
            return None
        return self._prune_sum(_key(key), n)

    def would_exceed(self, key: Any, amount: Any, *, now: Any) -> bool:
        """Whether charging ``amount`` now would push the windowed spend over ``cap``. Fail-closed: a
        malformed ``now``/``amount`` returns ``True`` (defer)."""
        n = _num(now)
        amt = _num(amount)
        if n is None or amt is None or amt < 0:
            return True
        return (self._prune_sum(_key(key), n) + amt) > max(0.0, self.cap)

    def record(self, key: Any, amount: Any, *, now: Any) -> bool:
        """Append a spend entry (append-only). Returns ``True`` if recorded, ``False`` if the input was
        malformed and could not be accounted (nothing is appended)."""
        n = _num(now)
        amt = _num(amount)
        if n is None or amt is None or amt < 0:
            return False
        self._log.setdefault(_key(key), []).append((n, amt))
        return True


@dataclass(frozen=True)
class BudgetVerdict:
    """The advisory outcome of a charge. There is intentionally NO ``allowed``/``authorized`` field:
    ``defer`` is back-pressure only. It never denies an action (the gate does) and never marks a
    finding false (the oracle does). ``rate_limited``/``over_budget`` explain WHY a defer was raised."""

    defer: bool
    rate_limited: bool
    over_budget: bool
    spent: float          # windowed spend for this key AFTER this charge
    remaining: float      # max(0, cap - spent)
    reason: str


@dataclass
class BudgetMeter:
    """Combines a rate token bucket and a rolling spend cap into a single non-authoritative governor.

    Construct with a per-window ``daily_cap`` + ``window`` (in injected ticks) and a
    ``rate_capacity`` + ``rate_refill_per_tick``. :meth:`charge` accounts one billed unit of work and
    returns advisory back-pressure — the spend is ALWAYS recorded (append-only accounting), and a
    verdict of ``defer`` only asks the caller to slow down."""

    daily_cap: float = 0.0
    window: float = 86400.0
    rate_capacity: float = 0.0
    rate_refill_per_tick: float = 0.0
    _bucket: TokenBucket = field(init=False)
    _cap: RollingSpendCap = field(init=False)
    _ledger: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._bucket = TokenBucket(self.rate_capacity, self.rate_refill_per_tick)
        self._cap = RollingSpendCap(self.daily_cap, self.window)

    def preview(self, key: Any, cost: Any = 0.0, *, now: Any) -> BudgetVerdict:
        """Check what a ``cost`` charge would do right now WITHOUT recording it — no spend is appended
        and no rate token is consumed (aged out-of-window entries may be pruned, which never changes the
        accounted spend). The verdict is advisory back-pressure, never an authorization."""
        n = _num(now)
        c = _num(cost)
        if n is None or c is None or c < 0:
            return BudgetVerdict(True, False, False, 0.0, 0.0,
                                 "malformed cost/now — deferring (non-authoritative)")
        current = self._cap.current(key, now=n) or 0.0
        over = (current + c) > max(0.0, self.daily_cap)
        spent = current + c
        remaining = max(0.0, max(0.0, self.daily_cap) - spent)
        return BudgetVerdict(over, False, over, spent, remaining,
                             "over budget — prefer to defer" if over else "within budget")

    def charge(self, key: Any, cost: Any = 1.0, *, now: Any, meta: Any = None) -> BudgetVerdict:
        """Account one unit of billed work: consume a rate token, record the spend (append-only), and
        return advisory back-pressure. A malformed ``now``/``cost`` defers WITHOUT mutating state. Any
        provided ``meta`` is scrubbed through the F3 redactor before it is retained (secret-free)."""
        n = _num(now)
        c = _num(cost)
        if n is None or c is None or c < 0:
            return BudgetVerdict(True, False, False, 0.0, 0.0,
                                 "malformed cost/now — deferring without charging (non-authoritative)")
        rate_ok = self._bucket.try_consume(key, 1.0, now=n)
        self._cap.record(key, c, now=n)
        spent = self._cap.current(key, now=n) or c
        over = spent > max(0.0, self.daily_cap)
        remaining = max(0.0, max(0.0, self.daily_cap) - spent)
        self._ledger.append({
            "key": _key(key),
            "cost": c,
            "now": n,
            "meta": redact_tool_args(meta) if isinstance(meta, dict) else {},
        })
        defer = over or (not rate_ok)
        if over and not rate_ok:
            reason = "rate-limited AND over budget — defer (non-authoritative back-pressure)"
        elif over:
            reason = "over budget — defer the next expensive call (does NOT gate truth/authority)"
        elif not rate_ok:
            reason = "rate-limited — too many calls this window; defer (non-authoritative)"
        else:
            reason = "within budget and rate"
        return BudgetVerdict(defer, not rate_ok, over, spent, remaining, reason)

    def ledger(self) -> list[dict[str, Any]]:
        """A copy of the append-only, secret-scrubbed charge ledger (for observability/tests)."""
        return list(self._ledger)
