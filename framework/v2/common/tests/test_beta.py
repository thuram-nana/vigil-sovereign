"""
common.beta tests — prove the shared Beta-posterior helpers reproduce, BYTE FOR
BYTE, the arithmetic the two learners used to open-code.

The whole point of extracting these is that nothing observable changes:

  * ``beta_mean(alpha, beta)`` must equal the old
    ``scanner.learning.BetaPosterior.mean`` expression ``alpha / (alpha + beta)``.
  * ``beta_mean_from_counts(s, a)`` must equal the old
    ``memory.priors.{Prior,SmoothedPrior}.mean`` expression ``(s + 1) / (a + 2)``.

Equality is asserted with ``==`` (exact float identity), never ``approx`` — a
last-bit drift would mean the refactor changed a rank key or a serialized mean,
which is exactly what must not happen on the gate-critical path.
"""

from __future__ import annotations

import pytest

from framework.v2.common.beta import beta_mean, beta_mean_from_counts
from framework.v2.memory.priors import Prior, SmoothedPrior
from framework.v2.scanner.learning import BetaPosterior


# --- canonical (alpha, beta) form: the bandit's rank key ----------------------


@pytest.mark.parametrize(
    "alpha, beta",
    [
        (1.0, 1.0),      # uniform prior
        (3.0, 5.0),      # the value asserted in test_learning.py
        (8.0, 4.0),      # 7 hits / 3 misses
        (81.0, 21.0),    # ~0.79
        (0.5, 0.5),      # Jeffreys-ish
        (100.0, 1.0),
        (1.0, 100.0),
    ],
)
def test_beta_mean_is_the_open_coded_expression(alpha: float, beta: float) -> None:
    # Byte-for-byte the arithmetic BetaPosterior.mean used to inline.
    assert beta_mean(alpha, beta) == alpha / (alpha + beta)


@pytest.mark.parametrize(
    "alpha, beta",
    [(1.0, 1.0), (3.0, 5.0), (8.0, 4.0), (81.0, 21.0), (0.5, 0.5)],
)
def test_beta_posterior_mean_matches_helper(alpha: float, beta: float) -> None:
    # The live class must delegate to the helper with no numeric change.
    assert BetaPosterior(alpha=alpha, beta=beta).mean == beta_mean(alpha, beta)


# --- count (successes, attempts) form: the memory.priors Laplace mean ---------


@pytest.mark.parametrize(
    "successes, attempts",
    [
        (0, 0),          # cold: prior mean 0.5
        (1, 2),
        (4, 10),         # 0.4166..
        (6, 10),         # value asserted in test_priors_transfer.py
        (0, 5),
        (5, 5),
        (2.5, 7.5),      # fractional effective counts (transfer)
        (0.14285714285714285, 0.8571428571428571),
    ],
)
def test_beta_mean_from_counts_is_the_open_coded_expression(
    successes: float, attempts: float
) -> None:
    # Byte-for-byte the arithmetic Prior.mean / SmoothedPrior.mean used to inline.
    assert beta_mean_from_counts(successes, attempts) == (successes + 1) / (attempts + 2)


@pytest.mark.parametrize("successes, attempts", [(0, 0), (4, 10), (6, 10), (0, 5)])
def test_prior_mean_matches_helper(successes: int, attempts: int) -> None:
    p = Prior(
        archetype="api", bug_class="sqli", surface_pattern="",
        successes=successes, attempts=attempts, last_updated="2026-01-01T00:00:00+00:00",
    )
    assert p.mean == beta_mean_from_counts(successes, attempts)


@pytest.mark.parametrize("successes, attempts", [(0.0, 0.0), (2.5, 7.5), (6.0, 10.0)])
def test_smoothed_prior_mean_matches_helper(successes: float, attempts: float) -> None:
    sm = SmoothedPrior(
        archetype="api", bug_class="sqli", surface_pattern="",
        successes=successes, attempts=attempts,
        is_transferred=False, sources=[], sim_weight=0.0,
    )
    assert sm.mean == beta_mean_from_counts(successes, attempts)


# --- why the two forms are kept distinct (float add is not associative) -------


def test_count_form_denominator_is_not_reassociated() -> None:
    """``beta_mean_from_counts`` keeps its own ``attempts + 2`` denominator on
    purpose: routing the count form through ``beta_mean(s + 1, (a - s) + 1)``
    would reassociate the addition and, for fractional counts, drift the last
    bit. This concrete pair (1/7, 6/7) exhibits that drift, so the two helpers
    are genuinely not interchangeable and must both exist."""
    s, a = 1.0 / 7.0, 6.0 / 7.0
    direct = beta_mean_from_counts(s, a)
    reassociated = beta_mean(s + 1, (a - s) + 1)
    assert direct == (s + 1) / (a + 2)          # matches the historical call site
    assert direct != reassociated               # ...and differs from the reassociated form
