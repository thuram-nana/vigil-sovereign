"""
common.beta — the Beta-posterior mean, defined once for both learners.

Two components estimate a hit/success rate as the mean of a Beta posterior under
a uniform ``Beta(1, 1)`` prior — the Laplace-smoothed rate — and until now each
open-coded the arithmetic:

  * ``scanner.learning.BetaPosterior`` stores the *canonical* posterior
    parameters ``(alpha, beta)`` directly (``alpha`` = hits + 1, ``beta`` =
    misses + 1) and reads its mean as ``alpha / (alpha + beta)``.
  * ``memory.priors.Prior`` / ``SmoothedPrior`` store raw *counts*
    ``(successes, attempts)`` and apply the same ``Beta(1, 1)`` prior at read
    time as ``(successes + 1) / (attempts + 2)``.

These are the *same* estimator under two parameterizations. This module holds
both forms so neither learner open-codes the math, and so the one relationship
between them lives in exactly one documented place.

Byte-identical by construction: each function reproduces the exact arithmetic
expression of the call site it replaces — no reassociation, no reordering. In
particular ``beta_mean_from_counts`` is written as ``(successes + 1) /
(attempts + 2)`` and NOT routed through ``beta_mean(successes + 1, attempts + 1)``
because floating-point addition is not associative: for the fractional effective
counts that ``memory.priors.SmoothedPrior`` carries, computing the denominator as
``(successes + 1) + ((attempts - successes) + 1)`` could differ in the last bit
from ``attempts + 2``. The count form must therefore keep its own denominator.

Pure and deterministic: no imports beyond the future annotation, no wallclock, no
rng. Not on any gate/oracle decision path itself — it only centralises arithmetic
those components already performed identically.
"""

from __future__ import annotations


def beta_mean(alpha: float, beta: float) -> float:
    """Mean of a ``Beta(alpha, beta)`` distribution: ``alpha / (alpha + beta)``.

    ``alpha`` and ``beta`` are the *canonical* posterior parameters (already
    including the prior). This is the rank key for ``scanner.learning``'s
    per-``(context, arm)`` posteriors."""
    return alpha / (alpha + beta)


def beta_mean_from_counts(successes: float, attempts: float) -> float:
    """Posterior mean of a success rate under a uniform ``Beta(1, 1)`` prior,
    given raw counts: ``(successes + 1) / (attempts + 2)`` — the Laplace-smoothed
    rate.

    Conceptually ``beta_mean(successes + 1, (attempts - successes) + 1)``, but
    written directly so the denominator is computed as ``attempts + 2`` exactly.
    Reassociating through :func:`beta_mean` would change the last bit for
    fractional counts (float addition is not associative), so the two forms are
    kept distinct on purpose. ``successes`` and ``attempts`` may be ints (exact)
    or fractional effective counts (e.g. transferred priors)."""
    return (successes + 1) / (attempts + 2)
