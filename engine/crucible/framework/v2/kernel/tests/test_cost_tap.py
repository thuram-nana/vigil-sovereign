"""EC-2b — the PER-RUN, PER-MODEL cost tap primitive (kernel.cost_tap).

The measurement sibling of the EC-3 hard budget: it records HOW MANY tokens each concrete model spent in one
run, which the A/B harness reads for its token/$ delta. It gates nothing. This pins its contract — accumulate
by model, the ContextVar per-run isolation (incl. the parallel-sweep copy_context propagation), dry-run
skipping, and the DEFAULT-OFF no-op — all offline, no key.

Mutation-verify targets (each neuter reds a NAMED test here):
  * make _arm() arm even when the flag is unset (drop the enabled() gate)      -> test_default_off_records_nothing
  * drop the is_dryrun guard in record() (accumulate dry-run spend)            -> test_dryrun_trace_is_skipped
  * key record() on something other than trace.model (e.g. backend)            -> test_record_accumulates_by_model
  * use a module global instead of the ContextVar (two runs share one tap)     -> test_two_scopes_do_not_share_a_tap
  * drop the lock / mis-propagate context so parallel samples are lost         -> test_parallel_samples_are_attributed
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from types import SimpleNamespace

import pytest

from framework.v2.kernel import cost_tap as ct


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    """Each test starts UNARMED with the flag OFF (the default). A test that exercises an armed tap opts in
    with the flag. The ContextVar persists across tests in the main thread, so disarm before and after."""
    monkeypatch.delenv(ct._ENABLE_ENV, raising=False)
    ct.reset()
    yield
    ct.reset()


def _on(monkeypatch):
    monkeypatch.setenv(ct._ENABLE_ENV, "1")


def _trace(model: str, tokens_in: int = 0, tokens_out: int = 0, *, dryrun: bool = False):
    """A minimal trace double — record() reads only model / tokens_in / tokens_out / is_dryrun by getattr."""
    return SimpleNamespace(model=model, tokens_in=tokens_in, tokens_out=tokens_out, is_dryrun=dryrun)


# --------------------------------------------------------------------------- default-OFF (byte-identical)
def test_default_off_records_nothing(monkeypatch):
    # Flag UNSET: scope arms NO tap, so record is inert and the breakdown is empty — the make-gate property.
    assert ct.enabled() is False
    with ct.scope():
        ct.record(_trace("claude-opus-4-8", 100, 50))
        ct.record(_trace("claude-haiku-4-5", 10, 5))
        assert ct.totals_by_model() == {}
        assert ct.total_tokens() == 0


def test_record_outside_a_scope_is_a_noop(monkeypatch):
    # Even with the flag ON, no scope entered ⇒ no armed tap ⇒ record no-ops (nothing to accumulate into).
    _on(monkeypatch)
    ct.record(_trace("claude-opus-4-8", 100, 50))
    assert ct.totals_by_model() == {}


# --------------------------------------------------------------------------- armed primitive
def test_record_accumulates_by_model(monkeypatch):
    _on(monkeypatch)
    with ct.scope():
        ct.record(_trace("claude-opus-4-8", 100, 50))   # 150
        ct.record(_trace("claude-opus-4-8", 10, 0))      # +10 -> 160
        ct.record(_trace("claude-haiku-4-5", 4, 1))      # 5
        assert ct.totals_by_model() == {"claude-opus-4-8": 160, "claude-haiku-4-5": 5}
        assert ct.total_tokens() == 165


def test_dryrun_trace_is_skipped(monkeypatch):
    # A dry-run trace spends 0 real tokens — it MUST NOT accumulate (so fixture / make gate never move the tap).
    _on(monkeypatch)
    with ct.scope():
        ct.record(_trace("claude-opus-4-8", 100, 50, dryrun=True))
        ct.record(_trace("claude-opus-4-8", 7, 3))        # the one real call
        assert ct.totals_by_model() == {"claude-opus-4-8": 10}


def test_none_and_zero_and_empty_model(monkeypatch):
    _on(monkeypatch)
    with ct.scope():
        ct.record(None)                                   # safe no-op
        ct.record(_trace("claude-opus-4-8", 0, 0))        # 0 tokens -> nothing
        ct.record(_trace("", 3, 2))                       # empty model -> keyed under "" (never dropped)
        assert ct.totals_by_model() == {"": 5}


def test_scope_restores_prior_state(monkeypatch):
    _on(monkeypatch)
    with ct.scope():
        ct.record(_trace("m", 5, 0))
        assert ct.total_tokens() == 5
    # After the scope the tap is disarmed again — a reused thread never inherits a stale breakdown.
    assert ct.totals_by_model() == {}


def test_two_scopes_do_not_share_a_tap(monkeypatch):
    _on(monkeypatch)
    with ct.scope():
        ct.record(_trace("m", 100, 0))
        assert ct.total_tokens() == 100
    with ct.scope():
        # A FRESH tap: the prior run's 100 must not carry over (ContextVar per-run isolation, not a global).
        assert ct.totals_by_model() == {}
        ct.record(_trace("m", 7, 0))
        assert ct.total_tokens() == 7


# --------------------------------------------------------------------------- parallel-sweep propagation
def test_parallel_samples_are_attributed(monkeypatch):
    # The cost-dominant path is the parallel self-consistency sweep: workers get the armed context via
    # copy_context (which copies EVERY context var, so this tap rides along with the run budget). Each worker's
    # record() must land in THIS run's tap, and the lock must keep concurrent charges from losing updates.
    _on(monkeypatch)
    with ct.scope():
        ctx = copy_context()

        def _charge(_i: int) -> None:
            ctx.run(ct.record, _trace("m", 1, 0))

        with ThreadPoolExecutor(max_workers=8) as ex:
            list(ex.map(_charge, range(200)))
        assert ct.totals_by_model() == {"m": 200}
