"""
authority.fleet — fleet-level concurrency governance (Wave D, slice D3).

The per-engagement :class:`~authority.authorization.EngagementExecutor` bounds
how many actions ONE engagement runs at once (its ``concurrency_limit``). It says
nothing about what happens when the operator runs *N engagements at once against
the same estate* — the fleet case. This module is the layer above the executor
that governs the fleet, with three enforcement bounds that the executor cannot
express because they span engagements:

  * :class:`HostRateLimiter` — a process-global, PER-TARGET-HOST aggregate rate
    cap. N concurrent engagements pointed at one host do NOT multiply the load
    that host sees: the cap is on the host, shared by every engagement.
  * :class:`TenantBudget` — a per-tenant TOTAL action budget spanning all of a
    tenant's concurrent engagements, so one tenant cannot exhaust the deployment.
  * :class:`ProofSerializer` — the **serial-proof-per-target** soundness
    invariant. This is the load-bearing one and the reason D3 exists.

THE SERIAL-PROOF-PER-TARGET INVARIANT
-------------------------------------
Search/crawl SHOULD run concurrently — it is how the fleet covers ground. But a
statistical / timing PROOF re-drive (a time-based-SQLi timing measurement, an
SPRT boolean-inference channel) MUST run SERIALLY against any single target host.

Concurrent timing probes against one host phase-lock: at any instant every worker
is in the same half of its base/treat alternation, so the host serves N cheap
requests during the baseline window and N expensive ones during the treatment
window. Behind any capacity-bounded resource (one DB connection, a worker pool, a
GIL, a lock) that treatment burst QUEUES, and a purely benign, payload-dependent
per-request cost — a longer value taking longer to parse, log, regex-scan or error
on — is amplified ~N-fold by the self-inflicted queueing. The measured shift
crosses the timing oracle's effect floor and a FALSE ``time_based_sqli`` FACT is
minted on an origin that has NO injected delay at all. This is a real hazard this
codebase has hit (see the ``timing-concurrency-phase-lock`` record).

The rule is therefore: **concurrency for SEARCH, serial for PROOF.** A proof
against host H holds H's proof lock for the duration of its measurement; other
proofs against H wait; proofs against a *different* host and any amount of SEARCH
against H run unimpeded. This is a standalone soundness invariant: it protects any
timing/statistical proof arm the moment one exists, and does not depend on that
arm having landed yet.

Nothing here makes a fresh authorization decision — the danger ceiling, scope,
kill-switch and the signed authorization's four bounds are enforced elsewhere.
This module only shapes *how concurrently* already-authorized work may run.
"""

from __future__ import annotations

import enum
import threading
import time
from collections import defaultdict, deque
from contextlib import ExitStack, contextmanager, nullcontext
from typing import Callable, Iterator

from ..common.errors import BudgetExhausted, RateLimitExceeded
from ..common.ethics import extract_hostname

__all__ = [
    "WorkKind",
    "canonical_host",
    "HostRateLimiter",
    "TenantBudget",
    "ProofSerializer",
    "FleetConcurrencyGovernor",
]


class WorkKind(enum.Enum):
    """What kind of work an action is, for the concurrency-vs-serial decision.

    SEARCH runs concurrently (crawl, discovery, cheap probing). PROOF is a
    statistical / timing re-drive whose verdict rests on measured latency or on a
    sequential-probability signal, and MUST be serialized per target host so
    concurrent probes cannot phase-lock and manufacture a false timing/statistical
    FACT. When in doubt, an action is PROOF: serialization is the safe default and
    only ever costs latency, never soundness."""

    SEARCH = "search"
    PROOF = "proof"


def canonical_host(target: str) -> str:
    """The canonical host key a target maps to, so ``https://H/a`` and ``H:443``
    and ``h`` all share one bucket / one proof lock. Reuses the ONE host parser of
    record (:func:`common.ethics.extract_hostname`); falls back to a stripped,
    lower-cased literal when there is no parseable host (so an unparseable target
    still gets a stable, non-empty key rather than colliding into ``""``)."""
    host = extract_hostname(target or "")
    if host:
        return host.lower().strip().rstrip(".")
    return (target or "").strip().lower().rstrip(".")


class HostRateLimiter:
    """Process-global, per-target-host aggregate rate cap, shared across every
    concurrent engagement.

    A sliding window of the last ``window_seconds`` of grants is kept PER canonical
    host. :meth:`try_acquire` grants iff fewer than ``max_per_window`` grants fall
    inside the window for that host, and records the grant. Because the window is
    keyed by host and not by engagement, ten engagements hammering one estate share
    one budget — they cannot multiply the load the host sees.

    Thread-safe. The clock is injectable so tests are deterministic (no sleeps)."""

    def __init__(
        self,
        max_per_window: int,
        window_seconds: float = 1.0,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_per_window < 1:
            raise ValueError("max_per_window must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self._max = int(max_per_window)
        self._window = float(window_seconds)
        self._clock = clock
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, host: str, now: float) -> deque[float]:
        dq = self._hits[host]
        cutoff = now - self._window
        while dq and dq[0] <= cutoff:
            dq.popleft()
        return dq

    def count(self, target: str, *, now: float | None = None) -> int:
        """Grants for ``target``'s host currently inside the window."""
        host = canonical_host(target)
        with self._lock:
            return len(self._prune(host, self._clock() if now is None else now))

    def try_acquire(self, target: str, *, now: float | None = None) -> bool:
        """Grant and record one unit of load against ``target``'s host iff the
        host is under its aggregate cap. Non-blocking; returns whether granted."""
        host = canonical_host(target)
        ts = self._clock() if now is None else now
        with self._lock:
            dq = self._prune(host, ts)
            if len(dq) >= self._max:
                return False
            dq.append(ts)
            return True


class TenantBudget:
    """Per-tenant TOTAL action budget across all of a tenant's engagements.

    A tenant with a live budget of K may run K actions in total, however many
    concurrent engagements it spreads them over; the (K+1)-th is refused until the
    operator raises the cap. Fail-closed: a tenant with no configured budget gets
    ``default`` (0 by default → refused), never unlimited-by-omission.

    :meth:`charge` reserves; :meth:`refund` returns a reservation that a later
    fleet gate refused (so a rate-limited action does not silently consume budget).
    Thread-safe."""

    def __init__(self, budgets: dict[str, int], *, default: int = 0) -> None:
        self._limits: dict[str, int] = {t: int(n) for t, n in budgets.items()}
        self._default = int(default)
        self._spent: dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    def _limit(self, tenant: str) -> int:
        return self._limits.get(tenant, self._default)

    def spent(self, tenant: str) -> int:
        with self._lock:
            return self._spent[tenant]

    def remaining(self, tenant: str) -> int:
        with self._lock:
            return max(0, self._limit(tenant) - self._spent[tenant])

    def charge(self, tenant: str, n: int = 1) -> bool:
        """Reserve ``n`` units for ``tenant`` iff that keeps it within budget.
        Returns whether reserved; never partially charges."""
        if n < 0:
            raise ValueError("charge amount must be >= 0")
        with self._lock:
            if self._spent[tenant] + n > self._limit(tenant):
                return False
            self._spent[tenant] += n
            return True

    def refund(self, tenant: str, n: int = 1) -> None:
        """Return ``n`` previously-charged units (never below zero)."""
        with self._lock:
            self._spent[tenant] = max(0, self._spent[tenant] - n)


class ProofSerializer:
    """The serial-proof-per-target invariant, in code.

    Holds one lock PER canonical target host. A proof against host H acquires H's
    lock for the duration of its measurement, so at most one proof runs against H
    at any instant. Proofs against different hosts run in parallel (different
    locks); SEARCH never touches these locks at all. The lock registry is itself
    guarded so first-touch of a host is race-free.

    ``max_concurrent(host)`` is instrumentation, not a gate: it records the most
    simultaneous holders ever seen for a host, so a test can assert the
    serialization actually held (``== 1``) rather than trusting that it did — a
    counter defeats a silent fallback to concurrent proof."""

    def __init__(self) -> None:
        self._registry_lock = threading.Lock()
        self._host_locks: dict[str, threading.Lock] = {}
        self._holders: dict[str, int] = defaultdict(int)
        self._max_holders: dict[str, int] = defaultdict(int)
        self._counter_lock = threading.Lock()

    def _lock_for(self, host: str) -> threading.Lock:
        with self._registry_lock:
            lk = self._host_locks.get(host)
            if lk is None:
                lk = threading.Lock()
                self._host_locks[host] = lk
            return lk

    def in_proof(self, target: str) -> bool:
        """Whether a proof is currently in flight against ``target``'s host."""
        host = canonical_host(target)
        with self._counter_lock:
            return self._holders[host] > 0

    def max_concurrent(self, target: str) -> int:
        """The most simultaneous proof holders ever observed for ``target``'s
        host. The invariant holds iff this is ``<= 1``."""
        host = canonical_host(target)
        with self._counter_lock:
            return self._max_holders[host]

    @contextmanager
    def proof(self, target: str) -> Iterator[None]:
        """Serialize the enclosed PROOF against ``target``'s host: block until no
        other proof holds this host, then run exclusively, releasing on exit even
        if the body raises."""
        host = canonical_host(target)
        lk = self._lock_for(host)
        lk.acquire()
        try:
            with self._counter_lock:
                self._holders[host] += 1
                if self._holders[host] > self._max_holders[host]:
                    self._max_holders[host] = self._holders[host]
            try:
                yield
            finally:
                with self._counter_lock:
                    self._holders[host] -= 1
        finally:
            lk.release()


class FleetConcurrencyGovernor:
    """The one entry point through which fleet work passes, composing the three
    bounds. This is what makes the primitives *reachable*: an engagement runner
    wraps each action in :meth:`engage` and the fleet bounds are honoured without
    the runner re-implementing any of them.

    :meth:`engage` reserves in an order that leaves no reservation stranded: the
    tenant budget is charged first and REFUNDED if the per-host rate cap then
    refuses, so a rate-limited action consumes no budget. Both refusals raise the
    same typed :class:`~common.errors.EthicsViolation` the rest of the engine uses.
    A PROOF action additionally runs inside the per-host proof lock; a SEARCH
    action does not — that difference is the serial-proof-per-target invariant."""

    def __init__(
        self,
        *,
        host_rate_limiter: HostRateLimiter,
        tenant_budget: TenantBudget,
        proof_serializer: ProofSerializer | None = None,
    ) -> None:
        self.host_rate = host_rate_limiter
        self.budget = tenant_budget
        self.proof_serializer = proof_serializer or ProofSerializer()

    @contextmanager
    def engage(
        self,
        *,
        target: str,
        tenant: str,
        kind: WorkKind,
        cost: int = 1,
        now: float | None = None,
    ) -> Iterator[None]:
        """Admit one already-authorized action into the fleet under all three
        bounds, or refuse it fail-closed. On success the reservations are
        committed for the duration of the ``with`` block; a PROOF holds its host's
        proof lock for that duration."""
        with ExitStack() as rollback:
            # 1. tenant total budget — charged first, refunded if a later gate refuses.
            if not self.budget.charge(tenant, cost):
                raise BudgetExhausted(
                    f"tenant {tenant!r} has no remaining action budget "
                    f"({self.budget.spent(tenant)} spent)"
                )
            rollback.callback(self.budget.refund, tenant, cost)

            # 2. per-target-host aggregate rate cap (shared across engagements).
            if not self.host_rate.try_acquire(target, now=now):
                raise RateLimitExceeded(
                    f"aggregate rate cap reached for host "
                    f"{canonical_host(target)!r} across all engagements"
                )

            # All refusable reservations passed: commit them (cancel the refund).
            rollback.pop_all()

        # 3. serial-proof-per-target — PROOF is exclusive per host; SEARCH is not.
        guard = (
            self.proof_serializer.proof(target)
            if kind is WorkKind.PROOF
            else nullcontext()
        )
        with guard:
            yield
