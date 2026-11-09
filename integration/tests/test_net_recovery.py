"""
NET-2 (#73 "Item B") — bounded network recovery: ``live.net_recovery.BoundedBackoff`` and its first
adopter, the OTLP sink's circuit-breaker latch.

The through-line: a TRANSIENT collector drop must be able to auto-recover, but only

  * when the operator opted in (``VIGIL_NET_RECOVERY_ENABLED`` — DEFAULT-OFF; off ⇒ the latch is permanent,
    byte-identical to before NET-2),
  * a BOUNDED number of times (a collector that stays down costs a fixed number of probe exports, never an
    unbounded hammer on the engine's hot path, no matter how long the run or how many records it emits),
  * on a DETERMINISTIC schedule (injectable clock, no jitter), failing SAFE (a broken clock ⇒ no retry),
  * and never past the loopback egress pin (recovery re-tries the same pinned destination; a non-loopback
    endpoint is still refused before the latch is even consulted).

Runs WITHOUT opentelemetry (the CI hash lock does not ship it): the sink's span conversion is replaced by a
stub so the latch/recovery state machine is exercised directly.
"""

from __future__ import annotations

import inspect
import logging

import pytest

from vigil_integration.live import net_recovery
from vigil_integration.live.net_recovery import (
    RECOVERY_ENV,
    BoundedBackoff,
    recovery_enabled,
    recovery_from_env,
)
from vigil_integration.live.otel_export import OTLPSink
from vigil_integration.observability import new_span

LOOPBACK = "http://127.0.0.1:4318"


class Clock:
    """A hand-driven monotonic clock."""

    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


class Collector:
    """A fake OTLP exporter whose up/down state the test flips. Counts every network attempt."""

    def __init__(self, up: bool = False) -> None:
        self.up = up
        self.attempts = 0

    def export(self, spans):
        self.attempts += 1
        if not self.up:
            raise ConnectionError("collector down")
        return None


def _sink(collector, *, recovery=None, endpoint=LOOPBACK, max_failures=3):
    sink = OTLPSink(endpoint, exporter=collector, max_consecutive_failures=max_failures, recovery=recovery)
    sink._to_readable_span = lambda record: ("readable", record)   # no opentelemetry needed
    return sink


def _rec(i: int = 0):
    return new_span("op", spine_hash="h", seq=i)


def _latch(sink, n: int = 3) -> None:
    for i in range(n):
        sink(_rec(i))
    assert sink._disabled is True


# --- the flag: DEFAULT-OFF, explicit truthy only, total ---------------------------------------------

def test_flag_is_off_by_default_and_on_only_for_explicit_truthy_tokens():
    assert recovery_enabled({}) is False
    for off in ("", "0", "false", "no", "off", "maybe", " ", "2"):
        assert recovery_enabled({RECOVERY_ENV: off}) is False, off
    for on in ("1", "true", "TRUE", " yes ", "on"):
        assert recovery_enabled({RECOVERY_ENV: on}) is True, on


def test_flag_is_total_on_a_malformed_env():
    assert recovery_enabled(object()) is False          # type: ignore[arg-type]
    assert recovery_enabled({RECOVERY_ENV: None}) is False  # type: ignore[dict-item]


def test_recovery_from_env_returns_none_when_off_and_a_policy_when_on():
    assert recovery_from_env({}) is None
    pol = recovery_from_env({RECOVERY_ENV: "1"})
    assert isinstance(pol, BoundedBackoff) and pol.attempts == 0 and not pol.tripped


# --- BoundedBackoff: deterministic, bounded, fail-safe ----------------------------------------------

def test_not_ready_until_tripped_and_the_first_delay_elapses():
    clk = Clock()
    b = BoundedBackoff(base=5, cap=60, max_attempts=3, clock=clk)
    assert b.ready() is False                    # never degraded ⇒ nothing to recover
    b.trip()
    assert b.ready() is False
    clk.advance(4.999)
    assert b.ready() is False
    clk.advance(0.001)
    assert b.ready() is True


def test_delay_doubles_and_is_capped():
    clk = Clock()
    b = BoundedBackoff(base=5, cap=30, max_attempts=10, clock=clk)
    delays = []
    for _ in range(6):
        delays.append(b.next_delay())
        b.begin_attempt()
    assert delays == [5, 10, 20, 30, 30, 30]


def test_budget_is_bounded_forever_once_exhausted():
    clk = Clock()
    b = BoundedBackoff(base=1, cap=4, max_attempts=3, clock=clk)
    b.trip()
    granted = 0
    for _ in range(200):                          # a long outage: keep asking, keep failing
        clk.advance(10_000)
        if b.ready():
            granted += 1
            b.begin_attempt()
            b.failed()
    assert granted == 3 and b.exhausted
    clk.advance(10 ** 9)
    assert b.ready() is False


def test_success_fully_resets_the_schedule():
    clk = Clock()
    b = BoundedBackoff(base=2, cap=8, max_attempts=2, clock=clk)
    b.trip()
    clk.advance(2)
    b.begin_attempt()
    b.succeeded()
    assert b.attempts == 0 and not b.tripped and b.ready() is False
    b.trip()                                      # a later outage gets a fresh, equally bounded schedule
    clk.advance(2)
    assert b.ready() is True


def test_repeated_trips_do_not_postpone_recovery():
    clk = Clock()
    b = BoundedBackoff(base=5, cap=60, max_attempts=3, clock=clk)
    b.trip()
    clk.advance(4)
    b.trip()                                      # idempotent while tripped — does not restart the wait
    clk.advance(1)
    assert b.ready() is True


def test_a_broken_clock_fails_safe_to_no_retry():
    def boom() -> float:
        raise RuntimeError("clock gone")

    b = BoundedBackoff(base=1, cap=1, max_attempts=5, clock=boom)
    b.trip()
    assert b.ready() is False and b.exhausted     # cannot anchor the wait ⇒ degrade to the permanent latch

    clk = Clock()
    b2 = BoundedBackoff(base=1, cap=1, max_attempts=5, clock=clk)
    b2.trip()
    clk.advance(1)
    assert b2.ready() is True
    b2.begin_attempt()
    b2._clock = boom
    b2.failed()                                   # cannot anchor the NEXT wait ⇒ give up, never retry now
    assert b2.exhausted and b2.ready() is False
    b2._clock = lambda: float("nan")
    assert b2.ready() is False


@pytest.mark.parametrize("bad", [float("inf"), float("-inf"), float("nan")])
def test_a_non_finite_clock_reading_never_grants_a_retry(bad):
    clk = Clock()
    b = BoundedBackoff(base=5, cap=60, max_attempts=3, clock=clk)
    b.trip()                                      # anchored on a sane reading
    b._clock = lambda: bad                        # the clock then jumps to a non-finite value
    assert b.ready() is False                     # +inf would otherwise read as "the wait has elapsed"
    b2 = BoundedBackoff(base=5, cap=60, max_attempts=3, clock=lambda: bad)
    b2.trip()                                     # cannot anchor on a non-finite reading ⇒ give up
    assert b2.ready() is False and b2.exhausted


@pytest.mark.parametrize("base,cap,attempts", [
    (0, 0, 0), (-1, -1, -1), (float("nan"), float("inf"), True), ("x", None, "y"), (None, 1e-9, 0.5),
])
def test_malformed_config_resolves_to_safe_bounded_values(base, cap, attempts):
    b = BoundedBackoff(base=base, cap=cap, max_attempts=attempts, clock=Clock())
    assert b.base > 0 and b.cap >= b.base and b.cap != float("inf")
    assert isinstance(b.max_attempts, int) and 1 <= b.max_attempts <= net_recovery.DEFAULT_MAX_ATTEMPTS


# --- OTLPSink adoption: OFF ⇒ byte-identical permanent latch ----------------------------------------

def test_flag_off_the_latch_is_permanent_exactly_as_before(monkeypatch):
    monkeypatch.delenv(RECOVERY_ENV, raising=False)
    col = Collector(up=False)
    sink = OTLPSink(LOOPBACK, exporter=col, max_consecutive_failures=3)    # env-resolved policy
    sink._to_readable_span = lambda record: ("readable", record)
    assert sink._recovery is None
    _latch(sink)
    col.up = True                                 # the collector comes back...
    for i in range(50):
        sink(_rec(100 + i))
    assert col.attempts == 3                      # ...but with the flag off the sink never probes again
    assert sink.skipped == 50 and sink.exported == 0 and sink.recovered == 0


def test_flag_on_via_env_resolves_a_bounded_policy(monkeypatch):
    monkeypatch.setenv(RECOVERY_ENV, "1")
    sink = OTLPSink(LOOPBACK, exporter=Collector())
    assert isinstance(sink._recovery, BoundedBackoff)


def test_explicit_none_disables_recovery_even_with_the_flag_on(monkeypatch):
    monkeypatch.setenv(RECOVERY_ENV, "1")
    assert OTLPSink(LOOPBACK, exporter=Collector(), recovery=None)._recovery is None


def test_a_policy_resolution_fault_degrades_to_no_recovery(monkeypatch):
    import vigil_integration.live.otel_export as oe

    def boom():
        raise RuntimeError("policy broken")

    monkeypatch.setattr(oe, "recovery_from_env", boom)
    assert OTLPSink(LOOPBACK, exporter=Collector())._recovery is None


# --- OTLPSink adoption: ON ⇒ a transient drop auto-recovers ----------------------------------------

def test_a_transient_drop_recovers_after_the_backoff(caplog):
    clk = Clock()
    col = Collector(up=False)
    sink = _sink(col, recovery=BoundedBackoff(base=5, cap=60, max_attempts=4, clock=clk))
    _latch(sink)
    col.up = True
    sink(_rec(10))                                # before the delay: still latched, no network touch
    assert col.attempts == 3 and sink.skipped == 1
    clk.advance(5)
    with caplog.at_level(logging.WARNING, logger="vigil_integration.live.otel_export"):
        sink(_rec(11))                            # the half-open probe — succeeds
    assert col.attempts == 4 and sink.recovered == 1 and sink._disabled is False
    assert any("reachable again" in r.getMessage() for r in caplog.records)
    for i in range(5):                            # re-armed: every record flows again, no clock needed
        sink(_rec(20 + i))
    assert sink.exported == 6 and col.attempts == 9
    assert sink._recovery.attempts == 0 and not sink._recovery.tripped


def test_a_failed_probe_stays_latched_and_waits_longer():
    clk = Clock()
    col = Collector(up=False)
    sink = _sink(col, recovery=BoundedBackoff(base=5, cap=60, max_attempts=4, clock=clk))
    _latch(sink)
    clk.advance(5)
    sink(_rec(10))                                # probe 1 — fails
    assert col.attempts == 4 and sink._disabled is True
    clk.advance(9.9)
    sink(_rec(11))                                # 2nd delay is 10 s — not yet
    assert col.attempts == 4
    clk.advance(0.1)
    col.up = True
    sink(_rec(12))                                # probe 2 — succeeds
    assert col.attempts == 5 and sink.recovered == 1 and sink._disabled is False


def test_a_persistently_down_collector_costs_a_bounded_number_of_exports(caplog):
    clk = Clock()
    col = Collector(up=False)
    sink = _sink(col, recovery=BoundedBackoff(base=1, cap=2, max_attempts=3, clock=clk))
    _latch(sink)
    caplog.clear()                                # drop the (expected, once) original latch warning
    with caplog.at_level(logging.WARNING, logger="vigil_integration.live.otel_export"):
        for i in range(500):                      # a long run: many records, lots of wall time
            clk.advance(100)
            sink(_rec(1000 + i))
    assert col.attempts == 3 + 3                  # the 3 that latched it + exactly max_attempts probes
    assert sink._disabled is True and sink._recovery.exhausted
    gave_up = [r for r in caplog.records if "recovery probes" in r.getMessage()]
    assert len(gave_up) == 1                      # logged once at exhaustion — never a flood
    relatched = [r for r in caplog.records if "consecutive export failures" in r.getMessage()]
    assert relatched == []                        # a failed probe never re-runs the latch path
    assert sink._consecutive_failures == 3


def test_recovery_never_widens_the_loopback_egress_pin():
    clk = Clock()
    col = Collector(up=True)
    sink = _sink(col, endpoint="http://169.254.169.254:4318",
                 recovery=BoundedBackoff(base=1, cap=1, max_attempts=5, clock=clk))
    sink._disabled = True                         # even forced into the latched state...
    sink._recovery.trip()
    for i in range(10):
        clk.advance(10)
        sink(_rec(i))
    assert col.attempts == 0 and sink.refused == 10 and sink.recovered == 0


def test_a_record_that_cannot_be_converted_does_not_spend_the_budget():
    clk = Clock()
    col = Collector(up=False)
    sink = _sink(col, recovery=BoundedBackoff(base=1, cap=1, max_attempts=2, clock=clk))
    _latch(sink)
    clk.advance(5)
    for garbage in (None, 123, "x"):
        sink(garbage)                             # malformed ⇒ skipped before any probe
    sink._to_readable_span = lambda record: None  # otel absent / unconvertible ⇒ skipped before any probe
    sink(_rec(50))
    assert sink._recovery.attempts == 0 and col.attempts == 3


def test_the_recovery_clock_never_reaches_span_identity():
    # The structural determinism guard (test_live_otel_export) keeps wallclock/RNG out of the exporter
    # source. NET-2's clock lives in net_recovery and may only decide WHEN a probe happens — it must never
    # be consulted by the identity-bearing conversion.
    src = inspect.getsource(OTLPSink._to_readable_span)
    assert "_recovery" not in src and "net_recovery" not in src and "_clock" not in src
