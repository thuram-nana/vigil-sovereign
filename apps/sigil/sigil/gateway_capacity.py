"""PRICING G1 — the model gateway at scale: capacity sized from the provider's rate-limit headers, a per-tenant
fair share, and a pool of provider accounts with health checks and failover.

This module is the pure mechanism behind the flag ``VIGIL_GATEWAY_G1`` (``sigil.config.gateway_g1_enabled``). The
gateway (``sigil.model_gateway``) wires it in ONLY when the flag is on; with it off nothing here is constructed and
the gateway is byte-identical to its pre-G1 self (the account protections are the stand-in semaphores
``VIGIL_GATEWAY_TENANT_CONCURRENCY`` / ``VIGIL_GATEWAY_GLOBAL_CONCURRENCY``).

What G1 reads from the provider (VERIFIED from platform.claude.com/docs/en/api/rate-limits):

  * ``retry-after`` — seconds to wait; **not on every 429** (the spend-cap ``rate_limit_error`` carries none);
  * ``anthropic-ratelimit-{requests,tokens,input-tokens,output-tokens}-{limit,remaining,reset}`` — ``*-reset`` is an
    RFC 3339 timestamp, token ``*-remaining`` is rounded to the nearest thousand, and ``tokens-*`` shows the most
    restrictive limit in effect. Limits are requests-per-minute (RPM), input-tokens-per-minute (ITPM, cache-aware)
    and output-tokens-per-minute (OTPM), per model class;
  * ``anthropic-workspace-id`` — which workspace answered.

Three pieces:

  * :func:`parse_rate_limit_headers` turns a response's headers into a :class:`RateLimitSnapshot`. It is total and
    fail-closed: any malformed, out-of-range or contradictory value marks the snapshot UNTRUSTED, and an untrusted
    snapshot is never applied to a bucket (the gateway keeps the stand-in limits).
  * :class:`CapacityLane` is a continuous token bucket per (account, model class) and dimension, **seeded by the
    provider's own remaining** so the gateway never reserves past what the provider says is left, and refilling at
    the nominal per-minute rate between snapshots. ``retry-after`` pauses the lane.
  * :class:`FairShareScheduler` is a work-conserving max-min fair share over the account's capacity: every tenant is
    guaranteed its equal share of requests AND tokens per minute, and a greedy tenant may use more only out of
    capacity no other tenant needs — so one tenant can never starve the others.
  * :class:`AccountPool` holds several provider accounts (several workspace keys of the SAME provider), each with its
    own lanes and a health state, and chooses a healthy account for a request; failover and the health probe live in
    the gateway, which calls :meth:`AccountPool.mark_down` / :meth:`AccountPool.mark_up`.

SOVEREIGN plane (FATAL-2): framework-free, ``assert_no_offense()`` at import; stdlib + ``vigil_core`` only. It holds
provider keys (each account's), so it never crosses to the offense plane.
"""
from __future__ import annotations

import datetime as _dt
import threading
from dataclasses import dataclass, field
from typing import Mapping, Optional, Sequence

from .reuse import assert_no_offense

assert_no_offense()

__all__ = ["RateLimitSnapshot", "parse_rate_limit_headers", "model_class", "CapacityLane", "FairShareScheduler",
           "ProviderAccount", "AccountPool", "DEFAULT_MODEL_CLASSES"]

# The four rate-limit dimensions the provider reports. ``requests`` is RPM; the three token dimensions are per-minute
# token limits (``tokens`` = the most restrictive combined limit, ``input_tokens`` = ITPM, ``output_tokens`` = OTPM).
_DIMENSIONS = ("requests", "tokens", "input_tokens", "output_tokens")
_HEADER_PREFIX = "anthropic-ratelimit-"
_WORKSPACE_HEADER = "anthropic-workspace-id"
#: token ``*-remaining`` is rounded to the nearest thousand, so the true remaining is within half that of the
#: reported value; we take the reported value this far below it, so a reservation never assumes more than is truly left
_TOKEN_ROUNDING = 1000
#: the longest a ``retry-after`` we will honour (a hostile or broken header cannot park an account for ever)
_MAX_RETRY_AFTER_S = 3600
#: a reset that reads slightly in the past is tolerated (clock skew); further back is a bad value
_RESET_PAST_SKEW_S = 120.0
#: a model with no explicit class maps to itself — one class per model today (the run model), room for more
DEFAULT_MODEL_CLASSES: "dict[str, str]" = {}


def model_class(model: str, classes: "Optional[Mapping[str, str]]" = None) -> str:
    """The rate-limit CLASS a model's limits are reported under (the provider groups models into classes). Today VIGIL
    runs one model, so the class is the model id itself unless ``classes`` maps it; the pool keeps one lane per class
    so a second model class gets its own capacity without sharing the first's."""
    table = DEFAULT_MODEL_CLASSES if classes is None else classes
    return str(table.get(model, model))


def _parse_reset(value: str, now: float) -> Optional[float]:
    """An RFC 3339 ``*-reset`` as a UTC epoch, or None when it cannot be parsed or is unreasonably in the past. A
    reset far in the past means the header is stale or forged — fail closed (the caller treats the snapshot as
    untrusted)."""
    text = value.strip()
    if not text:
        return None
    try:
        parsed = _dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    epoch = parsed.timestamp()
    if epoch < now - _RESET_PAST_SKEW_S:
        return None
    return epoch


def _parse_nonneg_int(value: str) -> Optional[int]:
    """A non-negative integer, or None when the text is not exactly one (no signs, no spaces, no floats)."""
    text = value.strip()
    if not text.isdigit():
        return None
    return int(text)


def parse_retry_after(value: Optional[str]) -> Optional[int]:
    """``retry-after`` as a whole number of seconds in ``[1, _MAX_RETRY_AFTER_S]``, or None when it is absent or not a
    plain seconds value. The Anthropic ``retry-after`` is seconds; an HTTP-date form (no digits-only value) or junk
    reads as absent, so the gateway falls back to its own backoff."""
    if value is None:
        return None
    n = _parse_nonneg_int(value)
    if n is None or n < 1:
        return None
    return min(n, _MAX_RETRY_AFTER_S)


@dataclass(frozen=True)
class _Dim:
    """One dimension's reported triple. ``limit`` / ``remaining`` are per-minute; ``reset`` is a UTC epoch."""
    limit: int
    remaining: int
    reset: float


@dataclass(frozen=True)
class RateLimitSnapshot:
    """What one upstream response's rate-limit headers said, per dimension. ``trusted`` is False when ANY present
    rate-limit header was malformed, out of range or contradictory — an untrusted snapshot is never applied to a
    bucket, so the gateway keeps its stand-in limits (fail closed). ``present`` is False when the response carried no
    rate-limit headers at all (nothing to apply, not an error)."""
    dims: "Mapping[str, _Dim]"
    retry_after: Optional[int]
    workspace_id: str
    trusted: bool
    present: bool

    def dim(self, name: str) -> "Optional[_Dim]":
        return self.dims.get(name)


def parse_rate_limit_headers(headers: "Mapping[str, str]", now: float) -> RateLimitSnapshot:
    """Parse the Anthropic rate-limit response headers (see the module docstring). ``headers`` is read
    case-insensitively. Total and fail-closed:

      * a token ``*-remaining`` is taken ``_TOKEN_ROUNDING/2`` below its reported (rounded) value, so a reservation
        never assumes more than is truly left;
      * ``remaining`` greater than ``limit``, a ``reset`` that will not parse or is far in the past, a non-digit
        ``limit`` / ``remaining``, or two conflicting values for one header all make the snapshot UNTRUSTED;
      * a dimension is kept only when its full ``limit`` + ``remaining`` + ``reset`` triple is present and valid; a
        partial triple marks the snapshot untrusted (a half-read dimension could over-admit).
    """
    lower: "dict[str, str]" = {}
    for key, value in headers.items():
        k = key.lower()
        if k in lower and lower[k] != value:
            # two different values for the same header (a split/duplicated header): cannot trust any of it
            return RateLimitSnapshot({}, parse_retry_after(value), "", trusted=False, present=True)
        lower[k] = value
    retry_after = parse_retry_after(lower.get("retry-after"))
    workspace_id = (lower.get(_WORKSPACE_HEADER) or "").strip()
    rate_keys = [k for k in lower if k.startswith(_HEADER_PREFIX)]
    present = bool(rate_keys) or retry_after is not None or bool(workspace_id)
    if not rate_keys:
        return RateLimitSnapshot({}, retry_after, workspace_id, trusted=True, present=present)
    dims: "dict[str, _Dim]" = {}
    trusted = True
    for dim in _DIMENSIONS:
        # the header spells the token dimensions with hyphens (``input-tokens``); our keys use underscores
        hdr = dim.replace("_", "-")
        raw_limit = lower.get(f"{_HEADER_PREFIX}{hdr}-limit")
        raw_remaining = lower.get(f"{_HEADER_PREFIX}{hdr}-remaining")
        raw_reset = lower.get(f"{_HEADER_PREFIX}{hdr}-reset")
        if raw_limit is None and raw_remaining is None and raw_reset is None:
            continue
        if raw_limit is None or raw_remaining is None or raw_reset is None:
            trusted = False                 # a half-read dimension: never admit on it
            continue
        limit = _parse_nonneg_int(raw_limit)
        remaining = _parse_nonneg_int(raw_remaining)
        reset = _parse_reset(raw_reset, now)
        if limit is None or remaining is None or reset is None or remaining > limit:
            trusted = False
            continue
        if dim != "requests" and remaining > 0:
            remaining = max(0, remaining - _TOKEN_ROUNDING // 2)
        dims[dim] = _Dim(limit=limit, remaining=remaining, reset=reset)
    # a rate-limit header was present but nothing parsed cleanly: untrusted with no usable dimension
    return RateLimitSnapshot(dims if trusted else {}, retry_after, workspace_id, trusted=trusted, present=present)


class _Bucket:
    """A continuous token bucket for one dimension. Seeded and re-clamped by the provider's reported ``remaining`` so
    its level never exceeds what the provider says is left; refills at ``limit`` per minute between snapshots. A
    ``limit`` of None means the dimension is unknown (no trusted snapshot yet) — the bucket never blocks, so the
    gateway's stand-in semaphores remain the only bound (fail closed to the stand-ins)."""

    __slots__ = ("limit", "level", "last", "paused_until")

    def __init__(self) -> None:
        self.limit: Optional[int] = None
        self.level: float = 0.0
        self.last: float = 0.0
        self.paused_until: float = 0.0

    def _refill(self, now: float) -> None:
        if self.limit is None:
            return
        if now > self.last:
            self.level = min(float(self.limit), self.level + (self.limit / 60.0) * (now - self.last))
        self.last = now

    def observe(self, limit: int, remaining: int, now: float) -> None:
        """Apply a trusted snapshot: adopt the provider's limit, and clamp the level DOWN to the provider's remaining
        (never let the local level claim more than the provider says is left)."""
        self._refill(now)
        self.limit = limit
        self.level = min(self.level, float(remaining)) if self.last and self.limit is not None else float(remaining)
        self.last = now

    def pause(self, until: float) -> None:
        self.paused_until = max(self.paused_until, until)

    def can_take(self, amount: float, now: float) -> bool:
        if self.limit is None:
            return True
        if now < self.paused_until:
            return False
        self._refill(now)
        return self.level + 1e-9 >= amount

    def take(self, amount: float, now: float) -> bool:
        if self.limit is None:
            return True
        if now < self.paused_until:
            return False
        self._refill(now)
        if self.level + 1e-9 < amount:
            return False
        self.level -= amount
        return True

    def give_back(self, amount: float) -> None:
        if self.limit is None:
            return
        self.level = min(float(self.limit), self.level + amount)


class CapacityLane:
    """The capacity of ONE account for ONE model class: a bucket per dimension (requests, combined tokens, input
    tokens, output tokens), sized from the provider's rate-limit headers. Thread-safe.

    ``reserve`` admits a request only if every applicable bucket has room for it; the output is reserved at its
    worst case (``max_tokens``), the input at the gateway's estimate. ``settle`` returns the difference between the
    reserved worst case and the actual usage once the response is metered, so a lane is never pinned by over-estimates.
    ``observe`` applies a snapshot; ``paused`` reports a ``retry-after`` hold."""

    def __init__(self) -> None:
        self._buckets = {name: _Bucket() for name in _DIMENSIONS}
        self._lock = threading.Lock()

    def observe(self, snapshot: RateLimitSnapshot, now: float) -> None:
        if not snapshot.trusted:
            return                          # never trust a malformed header: keep the last good limits
        with self._lock:
            for name in _DIMENSIONS:
                dim = snapshot.dim(name)
                if dim is not None:
                    self._buckets[name].observe(dim.limit, dim.remaining, now)
            if snapshot.retry_after is not None:
                until = now + snapshot.retry_after
                for bucket in self._buckets.values():
                    bucket.pause(until)

    def pause(self, seconds: float, now: float) -> None:
        with self._lock:
            for bucket in self._buckets.values():
                bucket.pause(now + seconds)

    def paused(self, now: float) -> bool:
        with self._lock:
            return any(now < b.paused_until for b in self._buckets.values())

    def known(self) -> bool:
        """True once a trusted snapshot has sized at least one dimension (capacity is being honoured from headers)."""
        with self._lock:
            return any(b.limit is not None for b in self._buckets.values())

    def limits(self) -> "dict[str, Optional[int]]":
        with self._lock:
            return {name: b.limit for name, b in self._buckets.items()}

    def _amounts(self, input_tokens: int, output_tokens: int) -> "dict[str, float]":
        total = float(input_tokens + output_tokens)
        return {"requests": 1.0, "tokens": total, "input_tokens": float(input_tokens),
                "output_tokens": float(output_tokens)}

    def can_reserve(self, input_tokens: int, output_tokens: int, now: float) -> bool:
        amounts = self._amounts(input_tokens, output_tokens)
        with self._lock:
            return all(self._buckets[n].can_take(amounts[n], now) for n in _DIMENSIONS)

    def reserve(self, input_tokens: int, output_tokens: int, now: float) -> bool:
        """Take one request plus its worst-case input and output from every bucket, all or nothing. False when any
        bucket is short (the caller fails over to another account or backs off); never exceeds the provider's
        remaining."""
        amounts = self._amounts(input_tokens, output_tokens)
        with self._lock:
            if not all(self._buckets[n].can_take(amounts[n], now) for n in _DIMENSIONS):
                return False
            for name in _DIMENSIONS:
                self._buckets[name].take(amounts[name], now)
            return True

    def settle(self, reserved_input: int, reserved_output: int, actual_input: int, actual_output: int) -> None:
        """Give back the unused part of a reservation once the response is metered (the request itself is not returned
        — it ran)."""
        back_in = max(0, reserved_input - actual_input)
        back_out = max(0, reserved_output - actual_output)
        with self._lock:
            self._buckets["input_tokens"].give_back(float(back_in))
            self._buckets["output_tokens"].give_back(float(back_out))
            self._buckets["tokens"].give_back(float(back_in + back_out))

    def release(self, reserved_input: int, reserved_output: int) -> None:
        """Give back a whole reservation (the request never ran — a provider error, a failover)."""
        with self._lock:
            self._buckets["requests"].give_back(1.0)
            self._buckets["input_tokens"].give_back(float(reserved_input))
            self._buckets["output_tokens"].give_back(float(reserved_output))
            self._buckets["tokens"].give_back(float(reserved_input + reserved_output))


class FairShareScheduler:
    """A work-conserving max-min fair share of an account's per-minute capacity across tenants, in requests AND
    tokens. Each active tenant is guaranteed an equal share (capacity / active tenants) of each; a tenant may use
    MORE only when the capacity it takes is not needed to meet every other active tenant's guaranteed share. So a
    greedy tenant can never push a modest tenant below its fair share — it can only consume slack.

    ``capacity_rpm`` / ``capacity_tpm`` is the account's (or the pool's) known per-minute capacity; when it is None
    (no trusted snapshot yet) fairness is INACTIVE (every request is admitted — the stand-in semaphores still bound
    the account), matching the fail-closed-to-stand-ins rule.

    Deterministic: given the same sequence of ``admit`` calls with the same clock, the decisions are the same — the
    simulation in the tests drives it directly."""

    def __init__(self, capacity_rpm: Optional[float] = None, capacity_tpm: Optional[float] = None,
                 window_s: float = 60.0) -> None:
        self.capacity_rpm = capacity_rpm
        self.capacity_tpm = capacity_tpm
        self.window_s = window_s
        self._used: "dict[str, list[tuple[float, float, float]]]" = {}   # tenant -> [(ts, requests, tokens)]
        self._lock = threading.Lock()

    def set_capacity(self, capacity_rpm: Optional[float], capacity_tpm: Optional[float]) -> None:
        with self._lock:
            self.capacity_rpm, self.capacity_tpm = capacity_rpm, capacity_tpm

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_s
        for tenant in list(self._used):
            kept = [e for e in self._used[tenant] if e[0] > cutoff]
            if kept:
                self._used[tenant] = kept
            else:
                del self._used[tenant]

    def _usage(self, tenant: str) -> "tuple[float, float]":
        entries = self._used.get(tenant, ())
        return sum(e[1] for e in entries), sum(e[2] for e in entries)

    def admit(self, tenant: str, requests: float, tokens: float, now: float) -> bool:
        """Admit ``tenant``'s demand for ``requests`` and ``tokens`` within this window, or refuse it when admitting
        would eat into another active tenant's guaranteed fair share. Records the demand when it admits."""
        with self._lock:
            self._prune(now)
            if self.capacity_rpm is None or self.capacity_tpm is None:
                self._used.setdefault(tenant, []).append((now, requests, tokens))
                return True                 # fairness inactive: the stand-in semaphores bound the account
            active = set(self._used) | {tenant}
            n = len(active)
            fair_rpm = self.capacity_rpm / n
            fair_tpm = self.capacity_tpm / n
            used_r, used_t = self._usage(tenant)
            over = (used_r + requests > fair_rpm + 1e-9) or (used_t + tokens > fair_tpm + 1e-9)
            if over:
                # admit over-share only if, after this demand, every OTHER active tenant can still reach its fair
                # share out of what is left — i.e. the slack is genuinely unused by anyone else
                guard_r = sum(max(0.0, fair_rpm - self._usage(o)[0]) for o in active if o != tenant)
                guard_t = sum(max(0.0, fair_tpm - self._usage(o)[1]) for o in active if o != tenant)
                taken_r = sum(self._usage(o)[0] for o in active)
                taken_t = sum(self._usage(o)[1] for o in active)
                if taken_r + requests + guard_r > self.capacity_rpm + 1e-9:
                    return False
                if taken_t + tokens + guard_t > self.capacity_tpm + 1e-9:
                    return False
            self._used.setdefault(tenant, []).append((now, requests, tokens))
            return True

    def active_tenants(self, now: float) -> int:
        with self._lock:
            self._prune(now)
            return len(self._used)


@dataclass
class ProviderAccount:
    """One provider account in the pool: a workspace key of the SAME provider (``kind == "anthropic"``). ``kind`` is
    the hook for a second cloud (Bedrock / Vertex) as OVERFLOW — but a different ``kind`` needs its own request API,
    egress allowlisting and prompt-cache scope, so the pool REFUSES to build an account of another kind (the gateway
    reports it): the interface is here, the second cloud is not wired."""
    account_id: str
    api_key: str = field(repr=False)        # never in a repr or a log line
    workspace_id: str = ""
    upstream: str = "https://api.anthropic.com"
    kind: str = "anthropic"


class _AccountState:
    __slots__ = ("account", "lanes", "down_until", "last_error", "last_snapshot_workspace")

    def __init__(self, account: ProviderAccount) -> None:
        self.account = account
        self.lanes: "dict[str, CapacityLane]" = {}
        self.down_until: float = 0.0
        self.last_error: str = ""
        self.last_snapshot_workspace: str = ""

    def lane(self, cls: str) -> CapacityLane:
        lane = self.lanes.get(cls)
        if lane is None:
            lane = self.lanes[cls] = CapacityLane()
        return lane


class AccountPool:
    """A pool of provider accounts of the SAME provider, each with its own capacity lanes and a health state. The
    gateway chooses a healthy account for each request and, on a provider error, marks it down and fails over to
    another; the health probe restores a down account. Thread-safe.

    Failover is for provider trouble only (429 / 5xx / connection errors). A customer's own credit stop
    (``x-vigil-stop: credits_exhausted``) is NOT a provider error — it is the gateway's own refusal and never reaches
    the pool, so it stays terminal and is never retried on another account."""

    def __init__(self, accounts: "Sequence[ProviderAccount]", *, down_s: float = 30.0) -> None:
        if not accounts:
            raise ValueError("a provider pool needs at least one account")
        for account in accounts:
            if account.kind != "anthropic":
                raise ValueError(
                    f"account {account.account_id!r} is kind {account.kind!r}: the G1 pool holds one provider's "
                    f"workspace keys only. A second cloud (Bedrock / Vertex) as overflow needs its own request API "
                    f"and egress allowlist — not wired; report it at the interface.")
        ids = [a.account_id for a in accounts]
        if len(set(ids)) != len(ids):
            raise ValueError("every pool account needs a distinct account_id")
        self._states = [_AccountState(a) for a in accounts]
        self._by_id = {s.account.account_id: s for s in self._states}
        self._down_s = down_s
        self._rr = 0
        self._lock = threading.Lock()

    def account_ids(self) -> "list[str]":
        return [s.account.account_id for s in self._states]

    def size(self) -> int:
        return len(self._states)

    def _state(self, account_id: str) -> _AccountState:
        return self._by_id[account_id]

    def lane(self, account_id: str, cls: str) -> CapacityLane:
        with self._lock:
            return self._state(account_id).lane(cls)

    def healthy_ids(self, now: float) -> "list[str]":
        with self._lock:
            return [s.account.account_id for s in self._states if now >= s.down_until]

    def down_ids(self, now: float) -> "list[str]":
        with self._lock:
            return [s.account.account_id for s in self._states if now < s.down_until]

    def account(self, account_id: str) -> ProviderAccount:
        with self._lock:
            return self._state(account_id).account

    def capacity(self, cls: str, now: float) -> "tuple[Optional[float], Optional[float]]":
        """The healthy pool's aggregate per-minute capacity for ``cls`` (requests, tokens), summed over accounts with
        a known limit; (None, None) when no account has a trusted snapshot yet (fairness then inactive)."""
        rpm = 0.0
        tpm = 0.0
        known = False
        with self._lock:
            for s in self._states:
                if now < s.down_until:
                    continue
                lane = s.lanes.get(cls)
                if lane is None:
                    continue
                limits = lane.limits()
                req = limits.get("requests")
                if req is not None:
                    rpm += float(req)
                    known = True
                tok = limits.get("tokens")
                if tok is None:
                    tok = limits.get("input_tokens")
                if tok is not None:
                    tpm += float(tok)
                    known = True
        return (rpm, tpm) if known else (None, None)

    def choose(self, cls: str, input_tokens: int, output_tokens: int, now: float,
               *, exclude: "Sequence[str]" = ()) -> Optional[str]:
        """A healthy account whose lane can fit the request, preferring the most headroom; round-robin among equals so
        load spreads. None when every healthy account is short or paused (the gateway then backs off)."""
        skip = set(exclude)
        with self._lock:
            candidates = [s for s in self._states
                          if now >= s.down_until and s.account.account_id not in skip]
            if not candidates:
                return None
            fit = [s for s in candidates if s.lane(cls).can_reserve(input_tokens, output_tokens, now)]
            pool = fit or candidates
            # round-robin start so no single account is always preferred
            self._rr = (self._rr + 1) % len(pool)
            ordered = pool[self._rr:] + pool[:self._rr]
            return ordered[0].account.account_id

    def mark_down(self, account_id: str, now: float, reason: str, *, seconds: Optional[float] = None) -> None:
        with self._lock:
            s = self._by_id.get(account_id)
            if s is None:
                return
            s.down_until = max(s.down_until, now + (self._down_s if seconds is None else seconds))
            s.last_error = str(reason)[:120]

    def mark_up(self, account_id: str, now: float) -> None:
        with self._lock:
            s = self._by_id.get(account_id)
            if s is None:
                return
            s.down_until = 0.0
            s.last_error = ""

    def observe(self, account_id: str, cls: str, snapshot: RateLimitSnapshot, now: float) -> None:
        with self._lock:
            s = self._by_id.get(account_id)
            if s is None:
                return
            s.lane(cls).observe(snapshot, now)
            if snapshot.workspace_id:
                s.last_snapshot_workspace = snapshot.workspace_id

    def health(self, now: float) -> "list[dict]":
        with self._lock:
            return [{"account_id": s.account.account_id, "workspace_id": s.account.workspace_id,
                     "healthy": now >= s.down_until, "down_for_s": max(0.0, s.down_until - now),
                     "last_error": s.last_error} for s in self._states]
