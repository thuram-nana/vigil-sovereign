"""
Wave 4 — the statistical timing oracle.

A real hypothesis test for time-based blind, not a fixed latency threshold:
Mann-Whitney U (rank-sum) + a Hodges-Lehmann effect-size floor + an optional
dose-response check. It fires on a genuine injected delay under jitter, refuses a
statistically-significant-but-tiny drift, refuses overlapping distributions, and
Holm-Bonferroni suppresses spurious fires across many probed params.
"""

from __future__ import annotations

import random

from framework.v2.verify.oracles import holm_correction, timing_oracle


def _samples(rng: random.Random, mean: float, sd: float, n: int) -> list[float]:
    return [max(0.0, rng.gauss(mean, sd)) for _ in range(n)]


def test_real_injected_delay_fires_under_jitter() -> None:
    rng = random.Random(0)
    base = _samples(rng, 100.0, 25.0, 20)
    treat = _samples(rng, 100.0 + 2000.0, 25.0, 20)  # SLEEP(2) under network jitter
    sig = timing_oracle(base, treat, injected_ms=2000.0, alpha=0.01)
    assert sig.fired and sig.confidence >= 0.7
    assert sig.observed["median_shift_ms"] > 1500.0


def test_overlapping_distributions_do_not_fire() -> None:
    rng = random.Random(1)
    base = _samples(rng, 100.0, 25.0, 20)
    treat = _samples(rng, 100.0, 25.0, 20)  # no conditional delay
    sig = timing_oracle(base, treat, injected_ms=2000.0, alpha=0.01)
    assert not sig.fired


def test_tiny_significant_shift_fails_effect_floor() -> None:
    # a real but tiny 30ms offset can be statistically significant with enough
    # samples, yet is far below a SLEEP(2) effect — the floor must refuse it
    rng = random.Random(2)
    base = _samples(rng, 100.0, 5.0, 30)
    treat = _samples(rng, 130.0, 5.0, 30)
    sig = timing_oracle(base, treat, injected_ms=2000.0, alpha=0.01)
    assert not sig.fired
    assert "floor" in sig.evidence


def test_dose_response_confirms_scaling_delay() -> None:
    rng = random.Random(3)
    base = _samples(rng, 100.0, 25.0, 20)
    low = _samples(rng, 100.0 + 1000.0, 25.0, 20)   # SLEEP(1)
    high = _samples(rng, 100.0 + 2000.0, 25.0, 20)  # SLEEP(2) ~= 2x the shift
    dose = {"low_ms": 1000.0, "low_samples": low, "high_ms": 2000.0, "high_samples": high}
    sig = timing_oracle(base, low, injected_ms=1000.0, alpha=0.01, dose=dose)
    assert sig.fired and sig.observed["dose_ok"] is True


def test_dose_response_rejects_constant_offset() -> None:
    # both "delays" produce the SAME shift regardless of the injected amount —
    # a constant offset (e.g. a slow proxy), not a real dose-dependent sleep
    rng = random.Random(4)
    base = _samples(rng, 100.0, 20.0, 20)
    low = _samples(rng, 100.0 + 800.0, 20.0, 20)
    high = _samples(rng, 100.0 + 800.0, 20.0, 20)   # NOT ~2x
    dose = {"low_ms": 1000.0, "low_samples": low, "high_ms": 2000.0, "high_samples": high}
    sig = timing_oracle(base, low, injected_ms=1000.0, alpha=0.01, dose=dose)
    assert not sig.fired


def test_jitter_only_almost_never_fires_over_many_trials() -> None:
    rng = random.Random(1234)
    fires = 0
    trials = 400
    for _ in range(trials):
        base = _samples(rng, 120.0, 40.0, 20)
        treat = _samples(rng, 120.0, 40.0, 20)  # no conditional delay, pure jitter
        if timing_oracle(base, treat, injected_ms=2000.0, alpha=0.01).fired:
            fires += 1
    # with alpha=0.01 AND a 1000ms effect floor on pure-jitter data, fires are
    # effectively impossible — the floor dominates
    assert fires == 0, f"{fires}/{trials} false fires on jitter-only data"


def test_holm_suppresses_spurious_across_many_params() -> None:
    # 20 params: one genuinely tiny p, the rest ~uniform. Holm rejects only the
    # one that survives the family-wise correction.
    p_values = [0.0001] + [0.2 + 0.03 * i for i in range(19)]
    rejected = holm_correction(p_values, alpha=0.01)
    assert rejected[0] is True
    assert sum(rejected) == 1


def test_insufficient_samples_never_fires() -> None:
    sig = timing_oracle([100.0, 2000.0], [2100.0, 2200.0], injected_ms=2000.0)
    assert not sig.fired and "insufficient" in sig.evidence
