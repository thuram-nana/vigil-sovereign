"""EC-3 — the RUN-SCOPED HARD token budget primitive (vigil_core.run_budget).

The fail-CLOSED contrast to ``token_budget`` (per-tool warn+throttle, never blocks): ONE per-run token
ceiling that STOPS the run when cumulative spend reaches it. This pins the primitive's contract — the
accumulator, the boundary stop, the ContextVar isolation, and the DEFAULT-OFF no-op — all offline, no key.

Mutation-verify targets (each neuter reds a NAMED test here):
  * drop the ``enabled()`` gate in arm() (arm/charge act when the flag is unset) -> test_default_off_is_a_noop
  * flip the stop comparison ``>=`` to ``>`` / make check_or_raise never fire     -> test_stop_fires_at_and_over_the_boundary
  * make charge() itself raise RunBudgetExceeded                                    -> test_charge_records_the_crossing_call_without_raising
  * drop the ContextVar (use a module global) so two runs share one accumulator     -> test_two_concurrent_runs_do_not_share_a_budget
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context

import pytest

from vigil_core import run_budget as rb
from vigil_core import RunBudgetExceeded


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    """Each test starts UNARMED with the flag OFF (the default). A test that exercises an armed budget opts
    in with ``monkeypatch.setenv(rb._ENABLE_ENV, "1")``. The ContextVar persists across tests in the main
    thread, so disarm before and after."""
    monkeypatch.delenv(rb._ENABLE_ENV, raising=False)
    rb.reset()
    yield
    rb.reset()


def _on(monkeypatch):
    monkeypatch.setenv(rb._ENABLE_ENV, "1")


# --------------------------------------------------------------------------- default-OFF (byte-identical)
def test_default_off_is_a_noop(monkeypatch):
    # Flag UNSET: arm must refuse to arm, so there is never a ceiling and every op is inert.
    assert rb.enabled() is False
    assert rb.arm(100) is None
    assert rb.current_ceiling() is None
    assert rb.charge(999) == 0            # accumulates nothing
    assert rb.spent() == 0
    assert rb.would_exceed(10**9) is False
    rb.check_or_raise()                   # never raises when unarmed
    rb.check_or_raise(10**9)
    assert rb.was_exceeded() is False


def test_scope_is_a_noop_when_off(monkeypatch):
    with rb.scope(500) as ceiling:
        assert ceiling is None            # arm refused (flag off)
        assert rb.current_ceiling() is None
        rb.check_or_raise(10**9)          # inert


# --------------------------------------------------------------------------- armed primitive
def test_arm_and_charge_accumulate(monkeypatch):
    _on(monkeypatch)
    assert rb.arm(1000) == 1000
    assert rb.current_ceiling() == 1000
    assert rb.charge(100) == 100
    assert rb.charge(250) == 350
    assert rb.spent() == 350
    assert rb.remaining() == 650
    assert rb.would_exceed() is False


def test_arm_rejects_non_positive_and_none(monkeypatch):
    _on(monkeypatch)
    assert rb.arm(0) is None
    assert rb.current_ceiling() is None
    assert rb.arm(-5) is None
    assert rb.arm(None) is None
    assert rb.current_ceiling() is None


def test_stop_fires_at_and_over_the_boundary(monkeypatch):
    _on(monkeypatch)
    rb.arm(100)
    rb.charge(99)
    assert rb.would_exceed() is False
    rb.check_or_raise()                   # 99 < 100: still runnable
    rb.charge(1)                          # now exactly at the ceiling
    assert rb.spent() == 100
    assert rb.would_exceed() is True      # >= boundary is a stop (never spend PAST the reserved envelope)
    with pytest.raises(RunBudgetExceeded) as ei:
        rb.check_or_raise()
    assert ei.value.ceiling == 100 and ei.value.spent == 100
    assert rb.was_exceeded() is True      # latched for the engage layer


def test_stop_fires_when_over(monkeypatch):
    _on(monkeypatch)
    rb.arm(100)
    rb.charge(150)                        # a single big call overshot
    with pytest.raises(RunBudgetExceeded):
        rb.check_or_raise()


def test_check_projected_stops_before_the_overshoot(monkeypatch):
    _on(monkeypatch)
    rb.arm(100)
    rb.charge(60)
    assert rb.would_exceed(40) is True    # 60 + 40 >= 100
    assert rb.would_exceed(39) is False   # 60 + 39 < 100
    with pytest.raises(RunBudgetExceeded):
        rb.check_or_raise(40)


def test_charge_records_the_crossing_call_without_raising(monkeypatch):
    # charge() must NEVER raise — the crossing call is always allowed to RECORD its spend; the next
    # check_or_raise is what stops the run. (A charge that raised would turn recording into the stop and
    # lose the clean "charge-after, check-before" discipline.)
    _on(monkeypatch)
    rb.arm(10)
    assert rb.charge(1000) == 1000        # no raise
    assert rb.spent() == 1000
    with pytest.raises(RunBudgetExceeded):
        rb.check_or_raise()


def test_reset_disarms(monkeypatch):
    _on(monkeypatch)
    rb.arm(100)
    rb.charge(50)
    rb.reset()
    assert rb.current_ceiling() is None
    assert rb.spent() == 0
    assert rb.was_exceeded() is False
    rb.check_or_raise(10**9)              # inert after reset


def test_scope_arms_then_disarms(monkeypatch):
    _on(monkeypatch)
    with rb.scope(500) as ceiling:
        assert ceiling == 500
        assert rb.current_ceiling() == 500
        rb.charge(500)
        with pytest.raises(RunBudgetExceeded):
            rb.check_or_raise()
    assert rb.current_ceiling() is None   # ALWAYS disarmed on exit (no leak to the next run)


# --------------------------------------------------------------------------- ContextVar isolation
def test_two_concurrent_runs_do_not_share_a_budget(monkeypatch):
    """Two threads, each its OWN run: each arms its own ceiling and charges independently; one run's spend
    never charges the other's accumulator (the ContextVar-per-run property). A Barrier forces them to
    overlap so a shared module global would cross-contaminate and red this test."""
    _on(monkeypatch)
    barrier = threading.Barrier(2)
    out: dict[str, dict] = {}

    def run(name: str, ceiling: int, charges: list[int]) -> None:
        rb.arm(ceiling)
        barrier.wait()                    # both armed before either charges → interleave
        for c in charges:
            rb.charge(c)
        out[name] = {"ceiling": rb.current_ceiling(), "spent": rb.spent()}

    ta = threading.Thread(target=run, args=("a", 100, [10, 10, 10]))
    tb = threading.Thread(target=run, args=("b", 5000, [1000, 1000]))
    ta.start(); tb.start(); ta.join(); tb.join()

    assert out["a"] == {"ceiling": 100, "spent": 30}
    assert out["b"] == {"ceiling": 5000, "spent": 2000}


def test_bare_child_thread_does_not_inherit_the_parent_budget(monkeypatch):
    """A BARE child thread starts in a FRESH context — it does NOT inherit the parent's armed budget. This
    is the isolation guarantee (distinct runs never cross), and the exact reason the run's parallel
    self-consistency sweep must EXPLICITLY propagate the armed context into its pool workers via
    ``copy_context`` (proven in ``test_copy_context_propagates_budget_to_a_pool_worker``) — a bare
    ``ThreadPoolExecutor`` worker would otherwise escape the cap. The run's own thread stays armed
    throughout."""
    _on(monkeypatch)
    rb.arm(100)
    seen: dict[str, object] = {}

    def child() -> None:
        seen["ceiling"] = rb.current_ceiling()
        rb.charge(10**9)                  # charges the child's (empty) context, not the parent's
        seen["child_spent"] = rb.spent()

    t = threading.Thread(target=child)
    t.start(); t.join()

    assert seen["ceiling"] is None        # child did not inherit the parent's ceiling
    assert seen["child_spent"] == 0       # child's charge hit an unarmed context
    assert rb.current_ceiling() == 100    # parent still armed
    assert rb.spent() == 0                # parent untouched by the child's charge


def test_copy_context_propagates_budget_to_a_pool_worker(monkeypatch):
    """The mechanism behind the self-consistency fix: when the armed context is propagated with
    ``copy_context`` (exactly as ``kernel.consistency.run_consistent`` does for its pool workers), a worker
    thread binds the SAME _RunBudget — so its charge lands on the RUN's accumulator and a later
    ``check_or_raise`` sees the run's full spend. The bare-thread case above escapes; the copy_context worker
    does not. This is what moves the cost-dominant parallel reasoning path back under the hard cap."""
    _on(monkeypatch)
    rb.arm(1000)
    seen: dict[str, object] = {}

    def worker() -> None:
        seen["ceiling"] = rb.current_ceiling()   # the propagated ceiling is visible
        rb.charge(400)                            # charges the SHARED run slot
        seen["worker_spent"] = rb.spent()

    ctx = copy_context()                          # snapshot the armed (parent) context on THIS thread
    t = threading.Thread(target=lambda: ctx.run(worker))
    t.start(); t.join()

    assert seen["ceiling"] == 1000                # the worker inherited the armed ceiling
    assert seen["worker_spent"] == 400
    assert rb.spent() == 400                      # the charge landed on the PARENT run's accumulator
    with pytest.raises(RunBudgetExceeded):        # and the stop is now visible on the parent (400+600 >= 1000)
        rb.check_or_raise(projected=600)


def test_concurrent_copy_context_workers_charge_the_one_shared_slot(monkeypatch):
    """copy_context binds the SAME _RunBudget into every pool worker (exactly as the self-consistency sweep
    does), so many workers charging CONCURRENTLY all aggregate onto the ONE run accumulator — the total is
    EXACT, none escapes to a fresh (unarmed) context. This is the propagation-at-scale contract behind the
    hard cap. (``charge`` LOCKS the read-modify-write, so the count is correct BY CONSTRUCTION. ``spent += n``
    is a non-atomic RMW in principle; CPython's current eval loop happens not to preempt a slot ``+= n`` mid-op,
    so the total is already exact here under the GIL — but that is an implementation detail, not atomicity, and
    it does NOT hold under free-threaded CPython, so the lock is the real guard, not an optional optimisation.)"""
    _on(monkeypatch)
    rb.arm(10**9)                                  # high ceiling: this pins aggregation, not the stop
    n_threads, per_thread = 8, 5000                # 40000 single-token charges across 8 copy_context workers
    barrier = threading.Barrier(n_threads)

    def hammer() -> None:
        barrier.wait()                             # release all workers together → real concurrency
        for _ in range(per_thread):
            rb.charge(1)

    ctxs = [copy_context() for _ in range(n_threads)]   # all bind the SAME armed _RunBudget
    with ThreadPoolExecutor(max_workers=n_threads) as ex:
        list(ex.map(lambda c: c.run(hammer), ctxs))
    assert rb.spent() == n_threads * per_thread    # exactly 40000 — every concurrent charge aggregated
