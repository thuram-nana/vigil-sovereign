"""
Wave D / D3 — THE serial-proof-per-target soundness invariant.

This is the load-bearing test of the slice. It proves, against the REAL
``verify.oracles.timing_oracle`` (its real 250 ms effect floor and one-sided
Mann-Whitney at alpha <= 0.01 — nothing weakened for the test), that:

  * CONCURRENT proof re-drives against ONE no-delay host MANUFACTURE a false
    ``time_based_sqli`` FACT — the counterfactual, so the pass below is not
    vacuous; and
  * routing the SAME proof workload through the per-host ``ProofSerializer`` mints
    ZERO timing FACTs, while still genuinely MEASURING the origin (an
    exercised-and-clean negative, not an empty one).

The mechanism (see the ``timing-concurrency-phase-lock`` record). The origin has
NO injected delay anywhere. Its only per-request cost is benign and
payload-CORRELATED — a longer value costs more to handle (parse / log / regex /
error path) — behind a single capacity-bounded resource (one DB connection / one
worker / a GIL / a lock). Run N proofs concurrently and they phase-lock: at any
instant every worker is in the same half of its baseline/treatment alternation, so
the treatment burst QUEUES behind the one resource and the tiny payload asymmetry
is amplified ~N-fold — across the 250 ms floor. Serialize proof per host and each
measurement hits an idle resource, so only the raw (un-amplified, sub-floor)
asymmetry remains and nothing fires.

Honesty notes:
  * Real threads, a real capacity-1 lock, real ``time.sleep`` service, real
    measured latencies, the real oracle. Nothing simulates the signature.
  * The barrier in the concurrent arm deterministically pins the worst-case phase
    alignment that arises stochastically among free-running concurrent workers; it
    does not create the effect, the queue does (a payload-INDEPENDENT origin does
    not fire even saturated — asserted).
  * The queue is modelled explicitly (peak depth asserted > 1) because queueing,
    not mere concurrency, is the amplifier.
"""

from __future__ import annotations

import threading
import time

from ...verify.oracles import timing_oracle
from ..fleet import ProofSerializer

_HOST = "https://shop.example.com/search"

# Benign, payload-correlated per-request service cost. NO injected delay.
_BASE_S = 0.002          # per request
_PER_CHAR_S = 0.002      # per character of the submitted value
_BASELINE_VALUE = "x"            # short baseline value  -> ~4 ms service
_TREATMENT_VALUE = "x" * 29      # long treatment value  -> ~60 ms service (56 ms asymmetry)

_N_WORKERS = 10          # concurrent proof attempts (a small fleet on one estate)
_SAMPLES = 5             # samples per arm per proof (== oracle min_samples)


class _CapacityOneOrigin:
    """One target behind a single capacity-bounded resource. Service time depends
    ONLY on the value's length; there is no ``sleep`` tied to any injected payload.
    Records the peak queue depth so a test can prove the queue (the amplifier)
    actually formed. ``payload_independent=True`` makes every request cost the same
    regardless of value — the control that shows the queue, not the concurrency, is
    what manufactures the shift."""

    def __init__(self, *, payload_independent: bool = False) -> None:
        self._resource = threading.Lock()  # capacity 1
        self._payload_independent = payload_independent
        self._depth = 0
        self.peak_depth = 0
        self._m = threading.Lock()

    def _service_s(self, value: str) -> float:
        n = 15 if self._payload_independent else len(value)
        return _BASE_S + _PER_CHAR_S * n

    def fetch_latency_ms(self, value: str) -> float:
        cost = self._service_s(value)
        t0 = time.perf_counter()
        with self._m:
            self._depth += 1
            if self._depth > self.peak_depth:
                self.peak_depth = self._depth
        with self._resource:      # queue behind the one resource
            time.sleep(cost)
        with self._m:
            self._depth -= 1
        return (time.perf_counter() - t0) * 1000.0


def _measure_one_proof(origin: _CapacityOneOrigin, barrier: threading.Barrier | None):
    """Collect one proof attempt's baseline/treatment latency samples via the
    classic within-point alternation. When a barrier is supplied every worker
    crosses each half-cycle together (the phase-lock)."""
    base_samples: list[float] = []
    treat_samples: list[float] = []
    for _ in range(_SAMPLES):
        if barrier is not None:
            barrier.wait()
        base_samples.append(origin.fetch_latency_ms(_BASELINE_VALUE))
        if barrier is not None:
            barrier.wait()
        treat_samples.append(origin.fetch_latency_ms(_TREATMENT_VALUE))
    return base_samples, treat_samples


def _run(*, serialize: bool, payload_independent: bool = False):
    """Run ``_N_WORKERS`` proof attempts against one origin. ``serialize`` routes
    each through the per-host ProofSerializer (no barrier — one runs at a time);
    otherwise they run concurrently, phase-locked by a shared barrier."""
    origin = _CapacityOneOrigin(payload_independent=payload_independent)
    ps = ProofSerializer()
    barrier = None if serialize else threading.Barrier(_N_WORKERS)
    per_worker = [None] * _N_WORKERS
    pooled_base: list[float] = []
    pooled_treat: list[float] = []
    pool_lock = threading.Lock()

    def worker(i: int) -> None:
        if serialize:
            with ps.proof(_HOST):
                base, treat = _measure_one_proof(origin, None)
        else:
            base, treat = _measure_one_proof(origin, barrier)
        sig = timing_oracle(base, treat)
        per_worker[i] = sig.fired
        with pool_lock:
            pooled_base.extend(base)
            pooled_treat.extend(treat)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(_N_WORKERS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30.0)

    fired = sum(1 for f in per_worker if f)
    pooled = timing_oracle(pooled_base, pooled_treat)
    return {
        "fired_workers": fired,
        "pooled_fired": pooled.fired,
        "pooled_shift_ms": pooled.observed.get("median_shift_ms"),
        "origin_peak_depth": origin.peak_depth,
        "proof_max_concurrent": ps.max_concurrent(_HOST),
        "n_base": len(pooled_base),
        "n_treat": len(pooled_treat),
    }


def test_concurrent_proof_manufactures_a_false_timing_fact() -> None:
    """COUNTERFACTUAL (proves the invariant test below is not vacuous): with proof
    NOT serialized, the phase-locked queue on a no-delay origin drives the shift
    across the real oracle's floor and mints false ``time_based_sqli`` FACTs."""
    r = _run(serialize=False)
    # The queue — the amplifier — actually formed.
    assert r["origin_peak_depth"] > 1, r
    # At least one concurrent proof attempt fired a FALSE timing FACT.
    assert r["fired_workers"] >= 1, r
    # And the pooled fleet evidence fires deterministically (median shift >> floor).
    assert r["pooled_fired"] is True, r
    assert r["pooled_shift_ms"] is not None and r["pooled_shift_ms"] >= 250.0, r


def test_serial_proof_per_target_mints_no_timing_fact() -> None:
    """THE INVARIANT: the SAME proof workload, serialized per host, mints ZERO
    timing FACTs on the no-delay origin — even though every worker still ran a real
    measurement (exercised-and-clean, not empty)."""
    r = _run(serialize=True)

    # Serialization actually held: never more than one proof against the host.
    assert r["proof_max_concurrent"] == 1, r
    # No queue formed, so the payload asymmetry was never amplified.
    assert r["origin_peak_depth"] == 1, r

    # ZERO false FACTs — per worker and on the pooled fleet evidence.
    assert r["fired_workers"] == 0, r
    assert r["pooled_fired"] is False, r

    # It is clean because it was MEASURED and un-amplified, not because it was
    # empty: full sample counts, and the raw asymmetry is present but below the floor.
    assert r["n_base"] == _N_WORKERS * _SAMPLES
    assert r["n_treat"] == _N_WORKERS * _SAMPLES
    assert r["pooled_shift_ms"] is not None
    assert 0.0 < r["pooled_shift_ms"] < 250.0, r


def test_payload_independent_origin_is_safe_even_concurrent() -> None:
    """Control: with the payload-correlated cost removed (every request the same
    size), the same concurrent phase-lock manufactures NO fact — confirming the
    queue amplifies a real per-request asymmetry rather than inventing one."""
    r = _run(serialize=False, payload_independent=True)
    assert r["origin_peak_depth"] > 1, r  # the queue still formed
    assert r["fired_workers"] == 0, r
    assert r["pooled_fired"] is False, r
