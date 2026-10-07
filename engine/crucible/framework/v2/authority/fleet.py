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
import os
import threading
import time
from collections import defaultdict, deque
from contextlib import ExitStack, contextmanager, nullcontext
from pathlib import Path
from typing import Callable, Iterator

from ..common.errors import BudgetExhausted, RateLimitExceeded
from ..common.ethics import extract_hostname
from ..xproc_lock import XProcCounter, XProcMutex

__all__ = [
    "WorkKind",
    "canonical_host",
    "HostRateLimiter",
    "TenantBudget",
    "ProofSerializer",
    "FleetConcurrencyGovernor",
    "default_fleet_governor",
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

    Thread-safe. The clock is injectable so tests are deterministic (no sleeps).

    CROSS-PROCESS: with ``xproc_dir`` set the window is kept in a per-host on-disk
    record (:class:`~framework.v2.xproc_lock.XProcCounter`) whose read-modify-write
    is serialized across processes, so N worker PROCESSES share ONE window per host
    rather than each keeping a private in-memory one (which would multiply the real
    load the host sees by the worker count). The default (``xproc_dir=None``) keeps
    the in-memory deque and is byte-identical to before. When cross-process, the
    clock must be comparable across processes, so it defaults to wall-clock
    ``time.time`` (``time.monotonic`` is per-process); the in-memory mode keeps
    ``time.monotonic``. An explicit ``clock`` or ``now`` overrides either."""

    def __init__(
        self,
        max_per_window: int,
        window_seconds: float = 1.0,
        *,
        clock: "Callable[[], float] | None" = None,
        xproc_dir: "str | os.PathLike | None" = None,
    ) -> None:
        if max_per_window < 1:
            raise ValueError("max_per_window must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self._max = int(max_per_window)
        self._window = float(window_seconds)
        self._xproc_dir = Path(xproc_dir) if xproc_dir is not None else None
        if clock is None:
            clock = time.time if self._xproc_dir is not None else time.monotonic
        self._clock = clock
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, host: str, now: float) -> deque[float]:
        dq = self._hits[host]
        cutoff = now - self._window
        while dq and dq[0] <= cutoff:
            dq.popleft()
        return dq

    def _xctr(self, host: str) -> XProcCounter:
        return XProcCounter(self._xproc_dir / "rate", host)  # type: ignore[operator]

    def count(self, target: str, *, now: float | None = None) -> int:
        """Grants for ``target``'s host currently inside the window."""
        host = canonical_host(target)
        ts = self._clock() if now is None else now
        if self._xproc_dir is not None:
            cutoff = ts - self._window
            hits = self._xctr(host).read().get("hits", [])
            return sum(1 for t in hits if isinstance(t, (int, float)) and t > cutoff)
        with self._lock:
            return len(self._prune(host, ts))

    def try_acquire(self, target: str, *, now: float | None = None) -> bool:
        """Grant and record one unit of load against ``target``'s host iff the
        host is under its aggregate cap. Non-blocking; returns whether granted."""
        host = canonical_host(target)
        ts = self._clock() if now is None else now
        if self._xproc_dir is not None:
            cutoff = ts - self._window

            def _fn(doc: dict) -> "tuple[dict, bool]":
                hits = [t for t in doc.get("hits", [])
                        if isinstance(t, (int, float)) and t > cutoff]
                if len(hits) >= self._max:
                    return {"hits": hits}, False
                hits.append(ts)
                return {"hits": hits}, True

            return bool(self._xctr(host).mutate(_fn))
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
    Thread-safe.

    CROSS-PROCESS: with ``xproc_dir`` set the spent counter lives in a per-tenant
    on-disk record whose read-modify-write is serialized across processes, so one
    tenant's budget spans its concurrent engagements running in DIFFERENT worker
    processes (not one budget per process). The limits/default stay process-local
    config; only the running ``spent`` tally is shared. Default (``None``) keeps the
    in-memory tally and is byte-identical to before."""

    def __init__(
        self,
        budgets: dict[str, int],
        *,
        default: int = 0,
        xproc_dir: "str | os.PathLike | None" = None,
    ) -> None:
        self._limits: dict[str, int] = {t: int(n) for t, n in budgets.items()}
        self._default = int(default)
        self._spent: dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
        self._xproc_dir = Path(xproc_dir) if xproc_dir is not None else None

    def _limit(self, tenant: str) -> int:
        return self._limits.get(tenant, self._default)

    def _xctr(self, tenant: str) -> XProcCounter:
        return XProcCounter(self._xproc_dir / "budget", tenant)  # type: ignore[operator]

    def spent(self, tenant: str) -> int:
        if self._xproc_dir is not None:
            return int(self._xctr(tenant).read().get("spent", 0))
        with self._lock:
            return self._spent[tenant]

    def remaining(self, tenant: str) -> int:
        if self._xproc_dir is not None:
            return max(0, self._limit(tenant) - self.spent(tenant))
        with self._lock:
            return max(0, self._limit(tenant) - self._spent[tenant])

    def charge(self, tenant: str, n: int = 1) -> bool:
        """Reserve ``n`` units for ``tenant`` iff that keeps it within budget.
        Returns whether reserved; never partially charges."""
        if n < 0:
            raise ValueError("charge amount must be >= 0")
        if self._xproc_dir is not None:
            limit = self._limit(tenant)

            def _fn(doc: dict) -> "tuple[dict, bool]":
                spent = int(doc.get("spent", 0))
                if spent + n > limit:
                    return {"spent": spent}, False
                return {"spent": spent + n}, True

            return bool(self._xctr(tenant).mutate(_fn))
        with self._lock:
            if self._spent[tenant] + n > self._limit(tenant):
                return False
            self._spent[tenant] += n
            return True

    def refund(self, tenant: str, n: int = 1) -> None:
        """Return ``n`` previously-charged units (never below zero)."""
        if self._xproc_dir is not None:
            def _fn(doc: dict) -> "tuple[dict, None]":
                spent = int(doc.get("spent", 0))
                return {"spent": max(0, spent - n)}, None

            self._xctr(tenant).mutate(_fn)
            return
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
    counter defeats a silent fallback to concurrent proof. (It counts holders in
    THIS process; a cross-process test proves per-host exclusivity by observing
    that a peer process blocks until the holder releases.)

    CROSS-PROCESS: with ``xproc_dir`` set, each proof additionally holds a BLOCKING
    per-host :class:`~framework.v2.xproc_lock.XProcMutex` (an ``flock``) for its
    duration, so a proof running in worker process A makes a proof against the SAME
    host in worker process B WAIT until A releases — the serial-proof-per-target
    invariant now holds across the multi-process fleet, not just within one worker.
    A crashed holder's ``flock`` is released by the kernel, so a dead proof never
    wedges the host. SEARCH never enters here, so it is never serialized. Default
    (``None``) is the in-process-only lock, byte-identical to before."""

    def __init__(self, *, xproc_dir: "str | os.PathLike | None" = None) -> None:
        self._registry_lock = threading.Lock()
        self._host_locks: dict[str, threading.Lock] = {}
        self._holders: dict[str, int] = defaultdict(int)
        self._max_holders: dict[str, int] = defaultdict(int)
        self._counter_lock = threading.Lock()
        self._xproc_dir = Path(xproc_dir) if xproc_dir is not None else None

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
        if the body raises. When ``xproc_dir`` is set the exclusivity spans
        processes (a per-host ``flock``), not just threads in this process."""
        host = canonical_host(target)
        lk = self._lock_for(host)           # in-process: serialize this worker's threads + instrument
        lk.acquire()
        try:
            # cross-process: block until no OTHER process holds this host's proof lock. Acquired UNDER the
            # in-process lock, so only one thread of this worker ever contends for the flock at a time, and
            # the acquire order (in-proc host lock → flock) is consistent for every host ⇒ no deadlock.
            xguard = (
                XProcMutex(self._xproc_dir / "proof", host).hold()
                if self._xproc_dir is not None
                else nullcontext()
            )
            with xguard:
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


#: A default per-tenant budget / per-host rate cap large enough to never REFUSE work. The default fleet
#: governor's only behaviour change versus the pre-wiring (governor-less) fleet path is the serial-proof-
#: per-target soundness invariant; it must not newly refuse engagements the old path admitted, so budget and
#: rate default to effectively unbounded. An operator who wants real caps constructs a governor with real
#: numbers — the cross-process backing is then live for those too.
_UNBOUNDED = 1_000_000_000


def default_fleet_governor(xproc_root: "str | os.PathLike | None" = None) -> "FleetConcurrencyGovernor":
    """The CROSS-PROCESS fleet governor the worker entrypoint wires by default.

    It backs all three bounds with on-disk, cross-process state under ``<root>/fleet_xproc`` so N worker
    PROCESSES share one proof lock / one window / one budget per key. ``xproc_root`` defaults to
    ``crucible_root()``; if that cannot be resolved (a bare context with no initialised root), the governor
    degrades to the in-process-only primitives rather than crashing — still correct for a single-process
    deployment, and the only place the multi-process hazard exists is a multi-process deployment, which has
    a resolvable root.

    The budget/rate caps default to effectively unbounded, so the ONLY behaviour this governor adds over the
    governor-less fleet path is serial-PROOF-per-host (the soundness fix) and concurrent SEARCH. A single-
    engagement (non-fleet) run never constructs this — it stays byte-identical."""
    root: "Path | None"
    if xproc_root is not None:
        root = Path(xproc_root)
    else:
        try:
            from ..common.paths import crucible_root

            root = crucible_root()
        except Exception:
            root = None
    xdir = (root / "fleet_xproc") if root is not None else None
    return FleetConcurrencyGovernor(
        host_rate_limiter=HostRateLimiter(
            max_per_window=_UNBOUNDED, window_seconds=1.0, xproc_dir=xdir
        ),
        tenant_budget=TenantBudget({}, default=_UNBOUNDED, xproc_dir=xdir),
        proof_serializer=ProofSerializer(xproc_dir=xdir),
    )
