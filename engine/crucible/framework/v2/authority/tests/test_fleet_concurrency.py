"""
Wave D / D3 — fleet-level concurrency governance.

Four things are proven here, each the deterministic mechanics behind one D3
deliverable. The load-bearing SOUNDNESS proof (a no-delay origin cannot yield a
timing FACT even under concurrent proof attempts) lives next door in
``test_serial_proof_invariant.py``; this file proves the primitives it rests on.

  1. The concurrency primitive is actually FED: under real concurrent workers the
     ``EngagementExecutor`` bounds in-flight work to ``concurrency_limit`` and the
     ``concurrency_limited`` refusal fires for the overflow — proven by pinning
     ``concurrency_limit`` reservations open and showing the rest are refused.
  2. The per-target-HOST rate limiter caps aggregate load across engagements.
  3. The per-tenant budget spans a tenant's engagements and is refunded when a
     later fleet gate refuses (no stranded reservation).
  4. The ProofSerializer serializes PROOF per host (never > 1 at once) while
     leaving different hosts — and all SEARCH — free to run concurrently.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone

import pytest

from ...common.errors import (
    BudgetExhausted,
    ConcurrencyLimitExceeded,
    RateLimitExceeded,
)
from ..authorization import EngagementAuthorization, EngagementExecutor
from ..fleet import (
    FleetConcurrencyGovernor,
    HostRateLimiter,
    ProofSerializer,
    TenantBudget,
    WorkKind,
    canonical_host,
)

# A window wide enough to stay valid at real wall-clock time — these tests exercise
# the rate/concurrency/proof machinery via ``execute()`` with the default (real)
# clock, not the validity window (which has its own tests).
_FAR_PAST = datetime(2020, 1, 1, tzinfo=timezone.utc)
_FAR_FUTURE = datetime(2099, 1, 1, tzinfo=timezone.utc)


def _authz(**overrides: object) -> EngagementAuthorization:
    base: dict[str, object] = dict(
        authorization_id="auth-1",
        engagement_slug="eng",
        issuer="governance",
        scope=["*.example.com"],
        danger_ceiling="A3",
        not_before=_FAR_PAST,
        not_after=_FAR_FUTURE,
        rate_limit=100_000,
        rate_window_seconds=60.0,
        concurrency_limit=3,
        issued_at=_FAR_PAST,
    )
    base.update(overrides)
    return EngagementAuthorization(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 1. The concurrency primitive is FED — bounded under REAL concurrency.
# ---------------------------------------------------------------------------


def test_concurrency_primitive_is_fed_bounds_in_flight_under_real_threads() -> None:
    """N > limit workers all enter ``execute`` at once and HOLD their reservation
    open; exactly ``concurrency_limit`` are admitted and every other worker is
    refused with ``concurrency_limited``. Holding the reservations open is what
    makes this deterministic rather than ordering-lucky: the overflow cannot slip
    in behind an early releaser because nobody releases until all have attempted."""
    limit = 3
    n_workers = 16
    ex = EngagementExecutor(_authz(concurrency_limit=limit, rate_limit=100_000))

    start = threading.Barrier(n_workers)
    release = threading.Event()
    verdicts: list[str] = [""] * n_workers

    def worker(i: int) -> None:
        start.wait()
        try:
            with ex.execute("http.get"):
                verdicts[i] = "admitted"
                # Hold the in-flight slot until every worker has attempted.
                assert release.wait(timeout=10.0)
        except ConcurrencyLimitExceeded:
            verdicts[i] = "refused"

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_workers)]
    for t in threads:
        t.start()

    # Wait until every worker has recorded a verdict (admitted ones do so BEFORE
    # blocking on `release`; refused ones do so as they raise).
    deadline = threading.Event()
    for _ in range(1000):
        if all(v for v in verdicts):
            break
        deadline.wait(0.01)
    assert all(v for v in verdicts), f"not all workers attempted: {verdicts}"

    admitted = verdicts.count("admitted")
    refused = verdicts.count("refused")
    assert admitted == limit, f"expected exactly {limit} admitted, got {admitted}"
    assert refused == n_workers - limit
    # While the reservations are still held, the executor reports the bound is full.
    assert ex.in_flight == limit

    release.set()
    for t in threads:
        t.join(timeout=10.0)
    # Every reservation is released on exit.
    assert ex.in_flight == 0


def test_in_flight_is_released_even_when_the_body_raises() -> None:
    ex = EngagementExecutor(_authz(concurrency_limit=1))
    with pytest.raises(RuntimeError):
        with ex.execute("http.get"):
            assert ex.in_flight == 1
            raise RuntimeError("boom")
    assert ex.in_flight == 0
    # And the slot is reusable afterwards.
    with ex.execute("http.get"):
        assert ex.in_flight == 1


# ---------------------------------------------------------------------------
# 2. Per-target-HOST aggregate rate limiter.
# ---------------------------------------------------------------------------


def test_host_rate_limiter_caps_aggregate_load_across_engagements() -> None:
    """The cap is on the HOST, not the engagement: distinct 'engagements' (distinct
    URLs that resolve to one host) share one window, so N of them cannot multiply
    the load the host sees."""
    rl = HostRateLimiter(max_per_window=5, window_seconds=1.0)
    urls = [f"https://app.example.com/engagement-{i}/probe" for i in range(10)]
    # Same host across all ten "engagements" — a fixed clock so it is deterministic.
    grants = [rl.try_acquire(u, now=0.0) for u in urls]
    assert grants.count(True) == 5, grants
    assert grants[:5] == [True] * 5 and grants[5:] == [False] * 5
    assert rl.count("app.example.com", now=0.0) == 5

    # A DIFFERENT host has its own independent budget.
    assert rl.try_acquire("https://other.example.com/x", now=0.0) is True

    # Once the window slides past, the host frees up again.
    assert rl.try_acquire("app.example.com", now=1.001) is True


def test_host_rate_limiter_is_exact_under_concurrent_contention() -> None:
    rl = HostRateLimiter(max_per_window=4, window_seconds=1.0)
    n = 32
    start = threading.Barrier(n)
    results: list[bool] = [False] * n

    def worker(i: int) -> None:
        start.wait()
        results[i] = rl.try_acquire("app.example.com", now=0.0)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)
    assert results.count(True) == 4, results


# ---------------------------------------------------------------------------
# 3. Per-tenant budget.
# ---------------------------------------------------------------------------


def test_tenant_budget_enforced_and_refunded() -> None:
    budget = TenantBudget({"acme": 3}, default=0)
    assert [budget.charge("acme") for _ in range(4)] == [True, True, True, False]
    assert budget.spent("acme") == 3
    assert budget.remaining("acme") == 0
    budget.refund("acme")
    assert budget.spent("acme") == 2
    assert budget.charge("acme") is True

    # Fail-closed: an unbudgeted tenant gets the default (0), never unlimited.
    assert budget.charge("stranger") is False


def test_tenant_budget_is_exact_under_concurrent_contention() -> None:
    budget = TenantBudget({"acme": 10}, default=0)
    n = 40
    start = threading.Barrier(n)
    results: list[bool] = [False] * n

    def worker(i: int) -> None:
        start.wait()
        results[i] = budget.charge("acme")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)
    assert results.count(True) == 10
    assert budget.spent("acme") == 10


# ---------------------------------------------------------------------------
# 4. ProofSerializer — serial per host, concurrent across hosts and for search.
# ---------------------------------------------------------------------------


def test_proof_serializer_serializes_same_host() -> None:
    ps = ProofSerializer()
    entered_first = threading.Event()
    release_first = threading.Event()
    second_entered = threading.Event()

    def hold_first() -> None:
        with ps.proof("https://app.example.com/a"):
            entered_first.set()
            assert release_first.wait(timeout=10.0)

    def try_second() -> None:
        with ps.proof("app.example.com"):  # same canonical host
            second_entered.set()

    t1 = threading.Thread(target=hold_first)
    t1.start()
    assert entered_first.wait(timeout=10.0)
    assert ps.in_proof("app.example.com") is True

    t2 = threading.Thread(target=try_second)
    t2.start()
    # The second proof against the SAME host must NOT enter while the first holds.
    assert second_entered.wait(0.25) is False

    release_first.set()
    # Now it proceeds.
    assert second_entered.wait(timeout=10.0) is True
    t1.join(timeout=10.0)
    t2.join(timeout=10.0)
    assert ps.max_concurrent("app.example.com") == 1


def test_proof_serializer_allows_different_hosts_in_parallel() -> None:
    ps = ProofSerializer()
    entered_a = threading.Event()
    release = threading.Event()

    def hold_a() -> None:
        with ps.proof("a.example.com"):
            entered_a.set()
            assert release.wait(timeout=10.0)

    t = threading.Thread(target=hold_a)
    t.start()
    assert entered_a.wait(timeout=10.0)
    # A proof against a DIFFERENT host acquires immediately (would hang if the
    # serializer were global rather than per host).
    got_b = False
    with ps.proof("b.example.com"):
        got_b = True
    assert got_b is True
    release.set()
    t.join(timeout=10.0)


def test_proof_serializer_max_concurrent_is_one_under_contention() -> None:
    ps = ProofSerializer()
    n = 8
    host = "app.example.com"
    start = threading.Barrier(n)
    observed_peak = [0]
    live = [0]
    lk = threading.Lock()

    def worker() -> None:
        start.wait()
        with ps.proof(host):
            with lk:
                live[0] += 1
                observed_peak[0] = max(observed_peak[0], live[0])
            # widen the window so a broken (non-exclusive) impl would overlap here
            threading.Event().wait(0.005)
            with lk:
                live[0] -= 1

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)
    assert observed_peak[0] == 1
    assert ps.max_concurrent(host) == 1


# ---------------------------------------------------------------------------
# The governor — one entry point composing all three, with the invariant.
# ---------------------------------------------------------------------------


def test_governor_serializes_proof_but_not_search_against_one_host() -> None:
    gov = FleetConcurrencyGovernor(
        host_rate_limiter=HostRateLimiter(max_per_window=10_000, window_seconds=1.0),
        tenant_budget=TenantBudget({"acme": 10_000}, default=0),
    )
    host = "https://app.example.com/x"
    n = 6

    # SEARCH: all workers must be able to sit inside their block at once (a barrier
    # of n would DEADLOCK if search were serialized).
    search_barrier = threading.Barrier(n, timeout=10.0)
    search_ok = [True]

    def search_worker() -> None:
        try:
            with gov.engage(target=host, tenant="acme", kind=WorkKind.SEARCH):
                search_barrier.wait()  # only returns if all n are concurrently inside
        except threading.BrokenBarrierError:
            search_ok[0] = False

    threads = [threading.Thread(target=search_worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)
    assert search_ok[0] is True, "SEARCH was serialized — it must run concurrently"
    # SEARCH never touched the proof lock.
    assert gov.proof_serializer.max_concurrent(host) == 0

    # PROOF: never more than one at a time against this host.
    start = threading.Barrier(n)

    def proof_worker() -> None:
        start.wait()
        with gov.engage(target=host, tenant="acme", kind=WorkKind.PROOF):
            threading.Event().wait(0.005)

    pthreads = [threading.Thread(target=proof_worker) for _ in range(n)]
    for t in pthreads:
        t.start()
    for t in pthreads:
        t.join(timeout=10.0)
    assert gov.proof_serializer.max_concurrent(host) == 1


def test_governor_refunds_budget_when_rate_cap_refuses() -> None:
    budget = TenantBudget({"acme": 100}, default=0)
    gov = FleetConcurrencyGovernor(
        host_rate_limiter=HostRateLimiter(max_per_window=1, window_seconds=1.0),
        tenant_budget=budget,
    )
    host = "app.example.com"
    # First action is admitted and consumes 1 unit of budget.
    with gov.engage(target=host, tenant="acme", kind=WorkKind.SEARCH, now=0.0):
        pass
    assert budget.spent("acme") == 1

    # Second action, same window, is rate-refused — and must NOT have consumed budget.
    with pytest.raises(RateLimitExceeded):
        with gov.engage(target=host, tenant="acme", kind=WorkKind.SEARCH, now=0.0):
            pass
    assert budget.spent("acme") == 1, "rate-refused action must not consume budget"


def test_governor_refuses_when_tenant_budget_is_exhausted() -> None:
    gov = FleetConcurrencyGovernor(
        host_rate_limiter=HostRateLimiter(max_per_window=10_000, window_seconds=1.0),
        tenant_budget=TenantBudget({"acme": 1}, default=0),
    )
    host = "app.example.com"
    with gov.engage(target=host, tenant="acme", kind=WorkKind.SEARCH, now=0.0):
        pass
    with pytest.raises(BudgetExhausted):
        with gov.engage(target=host, tenant="acme", kind=WorkKind.SEARCH, now=0.0):
            pass


def test_canonical_host_collapses_url_forms() -> None:
    assert canonical_host("https://App.Example.com/a?b=1") == "app.example.com"
    assert canonical_host("app.example.com.") == "app.example.com"
    assert canonical_host("http://app.example.com:8443/x") == "app.example.com"
