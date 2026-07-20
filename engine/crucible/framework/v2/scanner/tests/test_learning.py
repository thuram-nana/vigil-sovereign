"""
Contextual-bandit tests — statistical, seeded, and exercising the *behaviour*
(exploration that provably concentrates on the winning arm), not a fixture
shaped to pass. All randomness flows through an injected ``random.Random``, so
every assertion is a fixed, replayable outcome, not a flaky threshold.
"""

from __future__ import annotations

import random

import pytest

from framework.v2.scanner.learning import (
    BetaPosterior,
    ContextualBandit,
    LearningError,
    arm_key,
    context_key,
)


# --- key helpers --------------------------------------------------------------


def test_arm_key_joins_and_round_trips() -> None:
    assert arm_key("boolean_sqli", "quote_break") == "boolean_sqli::quote_break"
    assert arm_key("xss") == "xss"
    with pytest.raises(LearningError):
        arm_key("  ")


def test_context_key_is_order_independent_and_buckets_floats() -> None:
    a = context_key({"archetype": "api", "reflects": True, "depth": 0.03})
    b = context_key({"depth": 0.04, "reflects": True, "archetype": "api"})
    assert a == b, "context key must not depend on feature ordering or sub-bucket noise"
    # different bucket -> different context
    assert context_key({"depth": 0.9}) != context_key({"depth": 0.1})
    assert context_key({}) == "_"


# --- core learning: concentration on the winning arm --------------------------


def _train(bandit: ContextualBandit, ctx: str, arm: str, hits: int, misses: int) -> None:
    for _ in range(hits):
        bandit.update(ctx, arm, True)
    for _ in range(misses):
        bandit.update(ctx, arm, False)


def test_thompson_concentrates_on_the_winning_arm() -> None:
    bandit = ContextualBandit()
    ctx = "api-json"
    arms = ["sqli", "xss", "idor"]

    # Ground truth: sqli lands often here, xss rarely, idor sometimes.
    _train(bandit, ctx, "sqli", hits=80, misses=20)   # ~0.79
    _train(bandit, ctx, "xss", hits=3, misses=97)     # ~0.04
    _train(bandit, ctx, "idor", hits=30, misses=70)   # ~0.30

    # rank() is the greedy exploit order: the true winner is first.
    assert bandit.rank(ctx, arms) == ["sqli", "idor", "xss"]
    assert bandit.expected_value(ctx, "sqli") > bandit.expected_value(ctx, "idor")

    # select() (stochastic) still lands on sqli far above 1/3 chance.
    rng = random.Random(20260705)
    picks = [bandit.select(ctx, arms, rng=rng) for _ in range(400)]
    sqli_rate = picks.count("sqli") / len(picks)
    assert sqli_rate > 0.85, f"winner picked only {sqli_rate:.2%} of the time"
    # With ~100 observations per arm the posteriors are tight, so the sampler
    # has correctly *stopped* wasting draws on the clearly-worse arms: the dead
    # arm (xss, ~0.04) is never picked, and it never loses to the runner-up.
    assert picks.count("xss") == 0
    assert picks.count("sqli") > picks.count("idor")


def test_contexts_learn_independently() -> None:
    bandit = ContextualBandit()
    arms = ["sqli", "ssrf"]

    # On the API context sqli wins; on the gateway context ssrf wins.
    _train(bandit, "api", "sqli", hits=60, misses=10)
    _train(bandit, "api", "ssrf", hits=2, misses=68)
    _train(bandit, "gateway", "ssrf", hits=60, misses=10)
    _train(bandit, "gateway", "sqli", hits=2, misses=68)

    assert bandit.rank("api", arms)[0] == "sqli"
    assert bandit.rank("gateway", arms)[0] == "ssrf"

    # Evidence for one context must not leak into the other's posterior.
    fresh = ContextualBandit()
    _train(fresh, "api", "sqli", hits=60, misses=10)
    assert fresh.expected_value("gateway", "sqli") == pytest.approx(0.5)
    assert bandit.expected_value("gateway", "sqli") != pytest.approx(
        bandit.expected_value("api", "sqli")
    )

    rng = random.Random(7)
    api_picks = [bandit.select("api", arms, rng=rng) for _ in range(200)]
    gw_picks = [bandit.select("gateway", arms, rng=rng) for _ in range(200)]
    assert api_picks.count("sqli") > api_picks.count("ssrf")
    assert gw_picks.count("ssrf") > gw_picks.count("sqli")


# --- cold start explores ------------------------------------------------------


def test_cold_start_explores_not_a_fixed_arm() -> None:
    bandit = ContextualBandit()
    arms = ["a", "b", "c", "d"]
    rng = random.Random(1234)
    picks = [bandit.select("virgin", arms, rng=rng) for _ in range(200)]
    # With all posteriors at the uniform prior, no arm may dominate — every arm
    # gets explored, and the argmax is genuinely stochastic.
    distinct = set(picks)
    assert distinct == set(arms), f"cold start failed to explore all arms: {distinct}"
    for arm in arms:
        assert picks.count(arm) > 10, f"arm {arm} starved at cold start"


def test_cold_start_is_deterministic_given_the_rng() -> None:
    bandit = ContextualBandit()
    arms = ["a", "b", "c"]
    seq1 = [bandit.select("x", arms, rng=random.Random(99)) for _ in range(50)]
    seq2 = [bandit.select("x", arms, rng=random.Random(99)) for _ in range(50)]
    assert seq1 == seq2, "same rng seed must reproduce the same selection sequence"
    # And selection is independent of the order arms are passed in.
    a = bandit.select("x", ["a", "b", "c"], rng=random.Random(5))
    b = bandit.select("x", ["c", "b", "a"], rng=random.Random(5))
    assert a == b


# --- persistence: JSON round-trip preserves posteriors ------------------------


def test_json_round_trip_preserves_posteriors_and_behaviour() -> None:
    bandit = ContextualBandit(prior_alpha=1.0, prior_beta=2.0)
    _train(bandit, "api", "sqli", hits=40, misses=8)
    _train(bandit, "api", "xss", hits=1, misses=30)
    _train(bandit, "gateway", "ssrf", hits=12, misses=3)

    restored = ContextualBandit.from_json(bandit.to_json())

    # Exact posterior identity across every materialised cell.
    assert restored.to_dict() == bandit.to_dict()
    for ctx in bandit.contexts():
        for arm in bandit.arms(ctx):
            assert restored.expected_value(ctx, arm) == bandit.expected_value(ctx, arm)
            assert restored.observations(ctx, arm) == bandit.observations(ctx, arm)

    # ...and identical decisions under a shared rng seed.
    arms = ["sqli", "xss"]
    orig = [bandit.select("api", arms, rng=random.Random(2026)) for _ in range(100)]
    back = [restored.select("api", arms, rng=random.Random(2026)) for _ in range(100)]
    assert orig == back

    # The non-default prior survives, so cold arms behave identically too.
    assert restored.expected_value("new-ctx", "unseen") == pytest.approx(1.0 / 3.0)


def test_from_dict_rejects_bad_shapes() -> None:
    with pytest.raises(LearningError):
        ContextualBandit.from_dict({"schema_version": 999, "prior": [1, 1], "posteriors": {}})
    with pytest.raises(LearningError):
        ContextualBandit.from_dict(
            {"schema_version": 1, "prior": [1, 1],
             "posteriors": {"c": {"a": [0.0, 1.0]}}}  # alpha must be > 0
        )
    with pytest.raises(LearningError):
        ContextualBandit.from_dict(
            {"schema_version": 1, "prior": [1, 1], "posteriors": {"c": {"a": [1.0]}}}
        )


def test_save_load_round_trip(tmp_path) -> None:
    bandit = ContextualBandit()
    _train(bandit, "api", "sqli", hits=5, misses=1)
    path = tmp_path / "nested" / "bandit.json"
    bandit.save(path)
    assert ContextualBandit.load(path).to_dict() == bandit.to_dict()
    with pytest.raises(LearningError):
        ContextualBandit.load(tmp_path / "does-not-exist.json")


# --- warm-start seeding -------------------------------------------------------


def test_seed_prior_biases_and_then_gets_overridden_by_evidence() -> None:
    bandit = ContextualBandit()
    # Pretend memory.priors said arm "sqli" landed 9/10 on this archetype.
    bandit.seed_prior("api", "sqli", successes=9, failures=1)
    assert bandit.expected_value("api", "sqli") == pytest.approx(10.0 / 12.0)
    assert bandit.observations("api", "sqli") == pytest.approx(10.0)
    with pytest.raises(LearningError):
        bandit.seed_prior("api", "sqli", successes=-1, failures=0)


def test_seed_from_ledger_learns_per_arm_successes() -> None:
    # Structural stand-ins for calibration.Prediction / Outcome — the bandit
    # takes the ledger by shape (pairs() of objects with a .target), so this
    # test needs no calibration import and cannot perturb it.
    class _Pred:
        def __init__(self, fid: str, cls: str) -> None:
            self.finding_id = fid
            self.bug_class = cls

    class _Outcome:
        def __init__(self, target: float | None) -> None:
            self.target = target

    class _Ledger:
        def __init__(self, rows: list[tuple[_Pred, _Outcome]]) -> None:
            self._rows = rows

        def pairs(self) -> list[tuple[_Pred, _Outcome]]:
            return self._rows

    rows = (
        [(_Pred(f"h{i}", "sqli"), _Outcome(1.0)) for i in range(7)]
        + [(_Pred(f"m{i}", "sqli"), _Outcome(0.0)) for i in range(3)]
        + [(_Pred("x1", "xss"), _Outcome(0.0))]
        + [(_Pred("d1", "sqli"), _Outcome(None))]  # DISPUTED -> skipped
    )
    ledger = _Ledger(rows)
    bandit = ContextualBandit()

    n = bandit.seed_from_ledger(
        ledger, classify=lambda pred, out: ("api", pred.bug_class)
    )
    assert n == 11, "disputed pair must be skipped, all others folded in"
    # 7 hits / 3 misses -> Beta(8, 4) -> mean 8/12.
    assert bandit.expected_value("api", "sqli") == pytest.approx(8.0 / 12.0)
    assert bandit.expected_value("api", "xss") == pytest.approx(1.0 / 3.0)
    # A classifier that returns None drops the pair entirely.
    b2 = ContextualBandit()
    assert b2.seed_from_ledger(ledger, classify=lambda p, o: None) == 0


def test_seed_from_priors_uses_successes_and_attempts() -> None:
    class _Prior:
        def __init__(self, cls: str, successes: int, attempts: int) -> None:
            self.bug_class = cls
            self.successes = successes
            self.attempts = attempts

    priors = [_Prior("sqli", 9, 12), _Prior("xss", 0, 5)]
    bandit = ContextualBandit()
    n = bandit.seed_from_priors(priors, key=lambda p: ("api", p.bug_class))
    assert n == 2
    # sqli: alpha 1+9, beta 1+3 -> 10/14 ; xss: alpha 1, beta 1+5 -> 1/7
    assert bandit.expected_value("api", "sqli") == pytest.approx(10.0 / 14.0)
    assert bandit.expected_value("api", "xss") == pytest.approx(1.0 / 7.0)
    assert bandit.rank("api", ["sqli", "xss"]) == ["sqli", "xss"]


# --- guardrails ---------------------------------------------------------------


def test_empty_arm_set_and_bad_prior_are_refused() -> None:
    bandit = ContextualBandit()
    with pytest.raises(LearningError):
        bandit.select("c", [], rng=random.Random(0))
    with pytest.raises(LearningError):
        bandit.rank("c", [])
    with pytest.raises(LearningError):
        ContextualBandit(prior_alpha=0.0)


def test_posterior_sample_is_in_unit_interval() -> None:
    p = BetaPosterior(alpha=3.0, beta=5.0)
    rng = random.Random(0)
    for _ in range(100):
        s = p.sample(rng)
        assert 0.0 <= s <= 1.0
    assert p.mean == pytest.approx(3.0 / 8.0)
