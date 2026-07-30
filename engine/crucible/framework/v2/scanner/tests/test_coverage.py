"""
Coverage-guided discovery tests — deterministic, seeded, and exercising the
*invariants* (coverage rises only on NEW behavior; the bandit re-ranks but never
drops a family; a candidate with no fired oracle yields no FACT; seeded runs
replay), not fixtures shaped to pass.

All randomness flows through an injected ``random.Random`` and all coverage math
is pure set arithmetic, so every assertion is a fixed, replayable outcome.
"""

from __future__ import annotations

import random

import pytest

from framework.v2.intruder import generators as _generators
from framework.v2.scanner.coverage import (
    PAYLOAD_FAMILIES,
    AttemptOutcome,
    CoverageGuidedScheduler,
    CoverageState,
    buckets_of,
    coverage_gain,
    produces_fact,
    signal_bucket,
)
from framework.v2.scanner.learning import ContextualBandit
from framework.v2.verify.models import OracleKind, OracleSignal
from framework.v2.verify.verifier import HIGH_CONFIDENCE


# --- signal factories ---------------------------------------------------------


def _diff(*diverging: str, fired: bool | None = None) -> OracleSignal:
    """A differential verdict whose named dimensions diverged."""
    dims = [
        {"dim": d, "differs": d in diverging, "weight": 0.9 if d in diverging else 0.0}
        for d in ("status", "structural", "latency", "marker")
    ]
    did_fire = bool(diverging) if fired is None else fired
    return OracleSignal(
        kind=OracleKind.DIFFERENTIAL_RESPONSE,
        fired=did_fire,
        confidence=0.9 if did_fire else 0.0,
        observed={"dimensions": dims, "expect": "differ"},
    )


def _error(engine: str | None) -> OracleSignal:
    if engine is None:
        return OracleSignal(
            kind=OracleKind.ERROR_SIGNATURE, fired=False, confidence=0.0, observed={}
        )
    return OracleSignal(
        kind=OracleKind.ERROR_SIGNATURE,
        fired=True,
        confidence=0.9,
        observed={"engine": engine, "match": f"{engine} boom"},
    )


def _reflect(context: str | None) -> OracleSignal:
    fired = context in ("html_tag", "script", "js_attribute")
    observed = {"marker": "cRuc1ble"}
    if context is not None:
        observed["context"] = context
    return OracleSignal(
        kind=OracleKind.REFLECTION_CONTEXT,
        fired=fired,
        confidence=0.95 if fired else 0.0,
        observed=observed,
    )


# --- the payload-family vocabulary -------------------------------------------


def test_payload_families_track_the_generators_module() -> None:
    # Every arm is a real public generator; nothing invented, nothing private.
    public = {
        name
        for name in dir(_generators)
        if callable(getattr(_generators, name))
        and getattr(getattr(_generators, name), "__module__", "") == _generators.__name__
        and not name.startswith("_")
    }
    assert set(PAYLOAD_FAMILIES) == public
    assert PAYLOAD_FAMILIES == tuple(sorted(PAYLOAD_FAMILIES))  # canonical order
    for staple in ("simple_list", "numbers", "brute_force", "bit_flipper"):
        assert staple in PAYLOAD_FAMILIES


# --- the coverage metric ------------------------------------------------------


def test_signal_bucket_is_deterministic_and_behavior_specific() -> None:
    # Same behavior -> same token, regardless of object identity.
    assert signal_bucket(_diff("status")) == signal_bucket(_diff("status"))
    # Different diverging dimensions -> different behavior buckets.
    assert signal_bucket(_diff("status")) != signal_bucket(_diff("latency"))
    # A dimension SET, order-independent, collapses to one token.
    assert signal_bucket(_diff("status", "latency")) == signal_bucket(_diff("latency", "status"))
    # Distinct datastores are distinct behavior; the non-firing case is its own bucket.
    assert signal_bucket(_error("mysql")) != signal_bucket(_error("postgres"))
    assert signal_bucket(_error(None)) == "error_signature:engine=none"
    # Reflection contexts, including the encoded-inert non-firing one.
    assert signal_bucket(_reflect("html_tag")) == "reflection_context:ctx=html_tag"
    assert signal_bucket(_reflect("inert")) == "reflection_context:ctx=inert"
    assert signal_bucket(_reflect(None)) == "reflection_context:ctx=absent"
    # js_attribute detail is collapsed to a bounded prefix.
    assert signal_bucket(_reflect("js_attribute:onerror")) == "reflection_context:ctx=js_attribute"


def test_signal_bucket_falls_back_to_fired_bit_for_other_kinds() -> None:
    fire = OracleSignal(kind=OracleKind.TIMING, fired=True, confidence=0.8)
    miss = OracleSignal(kind=OracleKind.TIMING, fired=False, confidence=0.0)
    assert signal_bucket(fire) == "timing:fired=1"
    assert signal_bucket(miss) == "timing:fired=0"
    assert signal_bucket(fire) != signal_bucket(miss)


def test_buckets_of_is_order_independent() -> None:
    a = buckets_of([_diff("status"), _error("mysql")])
    b = buckets_of([_error("mysql"), _diff("status")])
    assert a == b
    assert len(a) == 2


def test_coverage_rises_only_on_new_buckets() -> None:
    state = CoverageState()
    assert state.score() == 0
    # First sighting of a behavior: coverage rises by exactly the new-bucket count.
    assert state.observe([_diff("status")]) == 1
    assert state.score() == 1
    # Re-seeing the SAME behavior gains nothing; the metric does not rise.
    assert state.observe([_diff("status")]) == 0
    assert state.score() == 1
    # A genuinely new behavior rises it again.
    assert state.observe([_error("mysql")]) == 1
    assert state.score() == 2
    # A batch mixing one new + one seen bucket gains exactly one.
    assert state.observe([_error("mysql"), _reflect("html_tag")]) == 1
    assert state.score() == 3


def test_coverage_metric_is_deterministic_across_states() -> None:
    signals = [_diff("status", "latency"), _error("postgres"), _reflect("script")]
    s1, s2 = CoverageState(), CoverageState()
    assert s1.observe(signals) == s2.observe(list(reversed(signals)))  # order-free
    assert s1.buckets() == s2.buckets()
    assert s1.sorted_buckets() == s2.sorted_buckets()


def test_gain_of_and_coverage_gain_are_pure() -> None:
    state = CoverageState()
    state.observe([_diff("status")])
    # gain_of predicts the marginal gain WITHOUT mutating.
    assert state.gain_of([_diff("status")]) == 0
    assert state.gain_of([_error("mysql")]) == 1
    assert state.score() == 1  # unchanged by the look-ahead
    # the free function agrees with the stateful method
    assert coverage_gain(state.buckets(), [_error("mysql")]) == 1
    assert coverage_gain(state.buckets(), [_diff("status")]) == 0


# --- the oracle-authority (FACT) gate ----------------------------------------


def test_no_fired_oracle_yields_no_fact() -> None:
    # No signal fired at all.
    assert produces_fact([_diff(fired=False), _error(None), _reflect("inert")]) is False
    # A signal that FIRED but sits BELOW the high-confidence threshold is not a FACT.
    weak = OracleSignal(
        kind=OracleKind.DIFFERENTIAL_RESPONSE,
        fired=True,
        confidence=HIGH_CONFIDENCE - 0.01,
        observed={"dimensions": [{"dim": "latency", "differs": True}], "expect": "differ"},
    )
    assert produces_fact([weak]) is False
    # A real oracle firing at/above threshold IS a FACT.
    assert produces_fact([_error("mysql")]) is True


def test_record_attempt_separates_coverage_from_fact() -> None:
    sched = CoverageGuidedScheduler.over_families()
    ctx = "archetype=api"
    # Novel behavior, but NOTHING fired -> coverage gain > 0, produced_fact False.
    novel_but_unconfirmed = [_diff(fired=False), _reflect("inert")]
    out = sched.record_attempt(ctx, "simple_list", novel_but_unconfirmed)
    assert isinstance(out, AttemptOutcome)
    assert out.coverage_gain == 2
    assert out.produced_fact is False
    assert set(out.new_buckets) == {
        "differential_response:diverge=none",
        "reflection_context:ctx=inert",
    }
    # A fired oracle -> produced_fact True (coverage authority never promotes; the
    # oracle does).
    out2 = sched.record_attempt(ctx, "numbers", [_error("mysql")])
    assert out2.produced_fact is True
    assert out2.coverage_gain == 1


# --- the coverage-guided bandit: re-ranks, never gates out --------------------


def test_rank_re_ranks_but_drops_no_family() -> None:
    sched = CoverageGuidedScheduler.over_families()
    ctx = "archetype=web"
    fams = ["hot", "cold", "untouched"]

    # "hot" keeps surfacing NEW behavior -> rewarded.
    sched.record_attempt(ctx, "hot", [_diff("status")])
    sched.record_attempt(ctx, "hot", [_error("mysql")])
    sched.record_attempt(ctx, "hot", [_reflect("html_tag")])
    # "cold" only re-treads behavior already covered by "hot" -> gain 0, not rewarded.
    sched.record_attempt(ctx, "cold", [_diff("status")])
    sched.record_attempt(ctx, "cold", [_error("mysql")])

    ranked = sched.rank_families(ctx, fams)
    # Re-rank, never gate: the returned set is exactly the candidate set.
    assert set(ranked) == set(fams)
    assert len(ranked) == len(fams)
    # The coverage-productive family floats to the front; the stale one sinks but
    # is NOT dropped (it is tried last, honoring coverage doctrine).
    assert ranked[0] == "hot"
    assert ranked[-1] == "cold"
    assert "untouched" in ranked  # a never-tried family remains eligible
    assert sched.expected_coverage_gain(ctx, "hot") > sched.expected_coverage_gain(ctx, "cold")


def test_rank_over_default_families_returns_all() -> None:
    sched = CoverageGuidedScheduler.over_families()
    ranked = sched.rank_families("ctx")
    assert set(ranked) == set(PAYLOAD_FAMILIES)
    assert len(ranked) == len(PAYLOAD_FAMILIES)


def test_select_stays_eligible_for_every_family() -> None:
    # Even a family with a poor coverage record can still be selected (explore),
    # so no surface is ever gated out of the stochastic path either.
    sched = CoverageGuidedScheduler.over_families(families=["a", "b", "c"])
    rng = random.Random(7)
    seen = {sched.select_family("ctx", rng=rng) for _ in range(200)}
    assert seen == {"a", "b", "c"}


# --- determinism / reproducibility -------------------------------------------


def test_seeded_selection_is_reproducible() -> None:
    fams = ["a", "b", "c", "d"]
    seq1 = _run_seeded(fams, seed=2024)
    seq2 = _run_seeded(fams, seed=2024)
    assert seq1 == seq2, "same seed + same posteriors must replay identically"
    # A different seed is free to diverge (sanity that the rng actually drives it).
    seq3 = _run_seeded(fams, seed=99)
    assert seq3 != seq1 or len(set(seq1)) == 1


def _run_seeded(fams: list[str], *, seed: int) -> list[str]:
    sched = CoverageGuidedScheduler.over_families(families=fams)
    ctx = "ctx"
    rng = random.Random(seed)
    picks: list[str] = []
    for i in range(12):
        pick = sched.select_family(ctx, rng=rng)
        picks.append(pick)
        # deterministic, seeded feedback loop: alternate new/stale behavior
        sig = _diff("status") if i % 2 == 0 else _diff("latency")
        sched.record_attempt(ctx, pick, [sig])
    return picks


def test_empty_family_set_is_refused() -> None:
    with pytest.raises(ValueError):
        CoverageGuidedScheduler(ContextualBandit(), families=[])
    sched = CoverageGuidedScheduler.over_families()
    with pytest.raises(ValueError):
        sched.rank_families("ctx", [])
