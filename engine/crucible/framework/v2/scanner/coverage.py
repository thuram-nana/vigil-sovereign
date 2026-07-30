"""
scanner.coverage — a coverage-guided, ORACLE-GATED discovery signal.

What this is
------------
A *response-behavior coverage* metric plus a scheduler that uses it to re-rank
which payload family (:mod:`framework.v2.intruder.generators`) to spend the next
attempt on. The metric scores how much NEW target behavior a candidate surfaced,
read straight off the deterministic verification layer's verdicts
(:class:`framework.v2.verify.models.OracleSignal`). The scheduler drives the
existing :class:`framework.v2.scanner.learning.ContextualBandit` — the same
Thompson-sampling bandit the campaign already uses for check ordering — with a
*coverage reward*, so the bandit learns which families surface unexplored
behavior on a target that looks like this one.

It is an OPT-IN selection strategy. Nothing here runs by default; a caller
(scanner or planner) constructs a :class:`CoverageGuidedScheduler` explicitly.
Default scan/engage behavior is unchanged.

What this is NOT — the hard line
--------------------------------
This is **not an evasion engine**. It explores the *target's* response behavior;
it does **not** hide from a defender, rotate identity, or shape traffic to evade
detection. Correlatable traffic and a stable User-Agent are preserved exactly as
the engine's OPSEC doctrine requires — the operator must still be able to grep
their logs and find every request this scheduler prioritized. "Coverage" here
means *coverage of the target's observable behavior surface* (distinct
differential / error / reflection / crash signal buckets), never coverage of a
defender's blind spots. The re-ranking only reorders effort over the target's own
responses; it changes *what to try next*, never *how to look like someone else*.

Invariants (enforced, not just documented)
-------------------------------------------
* **Oracle authority.** The scheduler NEVER promotes a candidate to a FACT.
  A finding is a FACT only when a real oracle FIRED at or above the verifier's
  high-confidence threshold (:data:`framework.v2.verify.verifier.HIGH_CONFIDENCE`).
  ``AttemptOutcome.produced_fact`` reports that gate and nothing else; coverage
  gain is a *ranking* signal that can reorder effort but can never confirm a bug.
* **Re-rank / defer, never gate out.** :meth:`CoverageGuidedScheduler.rank_families`
  returns EVERY candidate family, reordered — a low-coverage family is tried
  last, never dropped. This is asserted at runtime. Coverage doctrine (try every
  surface that exists) is preserved.
* **Deterministic, seeded PRNG.** All coverage math is pure set arithmetic — no
  clock, no randomness. The bandit's only stochastic method, :meth:`select`,
  draws from an injected ``random.Random``; there is no module-global rng and no
  wallclock anywhere. Given the same posteriors and the same rng, every decision
  is replayable.

How coverage is computed
------------------------
:func:`signal_bucket` maps one ``OracleSignal`` to a canonical, bounded token
that names the *kind of target behavior* it observed — derived only from the
signal's ``kind`` and a curated subset of its ``observed`` payload:

  * ``differential_response`` -> which dimensions diverged (``diverge=status,latency``)
  * ``error_signature``       -> which datastore/parser errored (``engine=mysql``)
  * ``reflection_context``    -> the reflection context (``ctx=html_tag`` / ``inert`` / ...)
  * ``sanitizer_signal``      -> the crash class (``crash=asan-heap-overflow``)
  * any other kind            -> a coarse ``<kind>:fired=<0|1>`` bit

The token vocabulary is bounded by construction, so coverage SATURATES: once a
family stops surfacing new behavior its coverage reward decays and the bandit
deprioritizes it — the mechanism that makes "expected coverage gain" a real,
diminishing signal rather than an unbounded chase. A non-firing oracle still
carries behavior (the payload produced no anomaly, or a reflection was encoded
inert) and is counted; that is coverage of the response surface, and it is kept
strictly separate from the FACT gate above.
"""

from __future__ import annotations

import inspect
from collections.abc import Iterable
from random import Random

from pydantic import BaseModel, ConfigDict, Field

from ..intruder import generators as _generators
from ..verify.models import OracleKind, OracleSignal
from ..verify.verifier import HIGH_CONFIDENCE
from .learning import Arm, Context, ContextualBandit


# ---------------------------------------------------------------------------
# Payload families — the arms, taken from intruder.generators
# ---------------------------------------------------------------------------


def _discover_payload_families() -> tuple[str, ...]:
    """The public payload-generator function names defined in
    :mod:`framework.v2.intruder.generators`, sorted. Derived by introspection so
    this list can never silently drift from the generator vocabulary it names."""
    names = [
        name
        for name, obj in inspect.getmembers(_generators, inspect.isfunction)
        if obj.__module__ == _generators.__name__ and not name.startswith("_")
    ]
    return tuple(sorted(names))


PAYLOAD_FAMILIES: tuple[str, ...] = _discover_payload_families()
"""Canonical payload-family arm ids (e.g. ``bit_flipper``, ``numbers``,
``simple_list``), one per public generator in :mod:`intruder.generators`."""


# ---------------------------------------------------------------------------
# The coverage metric — a pure function over OracleSignals
# ---------------------------------------------------------------------------


def _diverging_dimensions(observed: object) -> list[str]:
    """The names of the dimensions that DIFFERED in a differential verdict,
    sorted. Defensive against a malformed ``observed`` (returns ``[]``)."""
    if not isinstance(observed, dict):
        return []
    dims = observed.get("dimensions")
    if not isinstance(dims, list):
        return []
    out: list[str] = []
    for d in dims:
        if isinstance(d, dict) and d.get("differs") and isinstance(d.get("dim"), str):
            out.append(d["dim"])
    return sorted(set(out))


def _reflection_context(observed: object) -> str:
    """The normalized reflection context (``html_tag`` / ``script`` /
    ``js_attribute`` / ``inert`` / ``absent``). The specific tag / attribute
    detail is deliberately dropped so the bucket vocabulary stays bounded."""
    if not isinstance(observed, dict):
        return "absent"
    ctx = observed.get("context")
    if not isinstance(ctx, str) or not ctx:
        return "absent"
    # collapse ``js_attribute:onerror`` and friends to their family prefix
    return ctx.split(":", 1)[0]


def signal_bucket(signal: OracleSignal) -> str:
    """Map one ``OracleSignal`` to a canonical, bounded *response-behavior*
    bucket token — the unit of coverage.

    Pure and deterministic: the result depends only on ``signal.kind`` and a
    curated subset of ``signal.observed``. Two attempts that provoked the *same
    kind* of target behavior collapse to the same token; a genuinely new behavior
    (a new diverging dimension, a new datastore error, a new reflection context,
    a new crash class) yields a new token. Every signal maps to exactly one
    token, so the function is total.

    This reads the target's OWN observed responses — never anything about a
    defender."""
    kind = signal.kind
    observed = signal.observed

    if kind == OracleKind.DIFFERENTIAL_RESPONSE:
        diverge = _diverging_dimensions(observed)
        return "differential_response:diverge=" + (",".join(diverge) if diverge else "none")

    if kind == OracleKind.ERROR_SIGNATURE:
        engine = observed.get("engine") if isinstance(observed, dict) else None
        return f"error_signature:engine={engine if isinstance(engine, str) and engine else 'none'}"

    if kind == OracleKind.REFLECTION_CONTEXT:
        return f"reflection_context:ctx={_reflection_context(observed)}"

    if kind == OracleKind.SANITIZER_SIGNAL:
        best = observed.get("best") if isinstance(observed, dict) else None
        return f"sanitizer_signal:crash={best if isinstance(best, str) and best else 'none'}"

    # Every other oracle kind: the behavioral bit is simply whether it fired.
    return f"{kind.value}:fired={'1' if signal.fired else '0'}"


def buckets_of(signals: Iterable[OracleSignal]) -> frozenset[str]:
    """The set of distinct response-behavior buckets a batch of signals covers."""
    return frozenset(signal_bucket(s) for s in signals)


def produces_fact(
    signals: Iterable[OracleSignal], *, threshold: float = HIGH_CONFIDENCE
) -> bool:
    """The ORACLE-AUTHORITY gate, standalone: True iff at least one oracle FIRED
    at or above ``threshold``. This — and only this — is what makes a candidate a
    FACT. Coverage gain has no vote here: a candidate with no fired oracle yields
    no FACT, however novel its behavior."""
    return any(s.fired and s.confidence >= threshold for s in signals)


class CoverageState:
    """The accumulating set of response-behavior buckets seen so far.

    Pure set arithmetic — deterministic, order-independent, no clock, no rng.
    :meth:`observe` folds a batch in and returns its *marginal* coverage gain
    (the count of buckets that were genuinely new); :meth:`gain_of` computes the
    same marginal gain WITHOUT mutating, so a scheduler can look before it
    leaps."""

    def __init__(self, initial: Iterable[str] = ()) -> None:
        self._buckets: set[str] = {str(b) for b in initial}

    def score(self) -> int:
        """Total distinct behavior buckets covered — the coverage metric. Rises
        only when a genuinely new bucket is observed; re-seeing known behavior
        leaves it unchanged."""
        return len(self._buckets)

    def buckets(self) -> frozenset[str]:
        """An immutable snapshot of the covered buckets."""
        return frozenset(self._buckets)

    def sorted_buckets(self) -> list[str]:
        """The covered buckets, sorted — a stable, human-readable projection."""
        return sorted(self._buckets)

    def gain_of(self, signals: Iterable[OracleSignal]) -> int:
        """How many NEW buckets ``signals`` would add — pure, no mutation."""
        return len(buckets_of(signals) - self._buckets)

    def observe(self, signals: Iterable[OracleSignal]) -> int:
        """Fold a batch of signals in; return the marginal coverage gain (the
        number of buckets that were new). Idempotent on already-seen behavior:
        observing the same signals twice gains nothing the second time."""
        new = buckets_of(signals) - self._buckets
        self._buckets |= new
        return len(new)


def coverage_gain(seen: Iterable[str], signals: Iterable[OracleSignal]) -> int:
    """Pure, stateless marginal coverage: how many buckets in ``signals`` are not
    already in ``seen``. The free-function form of :meth:`CoverageState.gain_of`."""
    seen_set = {str(b) for b in seen}
    return len(buckets_of(signals) - seen_set)


# ---------------------------------------------------------------------------
# The coverage-guided scheduler
# ---------------------------------------------------------------------------


class AttemptOutcome(BaseModel):
    """The record of one recorded attempt: its coverage contribution and,
    strictly separately, whether a real oracle confirmed a FACT."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    family: str = Field(description="The payload family (bandit arm) attempted.")
    context: str = Field(description="The target-class context the attempt ran in.")
    coverage_gain: int = Field(
        ge=0, description="Count of NEW behavior buckets this attempt surfaced."
    )
    new_buckets: tuple[str, ...] = Field(
        default=(), description="The specific new buckets, sorted."
    )
    produced_fact: bool = Field(
        description="True iff a real oracle FIRED at/above the FACT threshold. "
        "This — not coverage — is the sole authority for a confirmed finding."
    )


class CoverageGuidedScheduler:
    """An opt-in selection strategy that re-ranks payload families by *expected
    coverage gain*, driving a reused :class:`ContextualBandit`.

    The link between coverage and the bandit is the reward: each recorded attempt
    feeds the bandit a Bernoulli reward of "did this family surface any NEW
    target behavior?" (``coverage_gain > 0``). The bandit therefore learns, per
    target-class context, which families are still coverage-productive; its
    posterior mean for a ``(context, family)`` arm *is* the estimated probability
    that the family will surface new behavior — i.e. its expected coverage gain.
    :meth:`rank_families` (greedy) and :meth:`select_family` (Thompson) then order
    effort by that estimate.

    Guarantees, restated at the seam:

    * **Never gates a surface out.** :meth:`rank_families` returns every family,
      reordered — verified with a runtime assertion. Effort is deferred, never
      dropped.
    * **Never promotes without an oracle.** Coverage steers *effort only*.
      :meth:`record_attempt` reports ``produced_fact`` from the oracle gate
      alone; coverage novelty can reorder attempts but can never confirm a bug.
    * **Not evasion.** It reasons only over the target's observed responses (see
      the module docstring). Traffic stays correlatable; identity stays stable.
    * **Deterministic.** No wallclock, no global rng. :meth:`select_family` takes
      an injected ``random.Random``; everything else is pure.
    """

    def __init__(
        self,
        bandit: ContextualBandit,
        coverage: CoverageState | None = None,
        *,
        families: Iterable[str] = PAYLOAD_FAMILIES,
        fact_threshold: float = HIGH_CONFIDENCE,
    ) -> None:
        self.bandit = bandit
        self.coverage = coverage if coverage is not None else CoverageState()
        self._families: tuple[str, ...] = tuple(dict.fromkeys(str(f) for f in families))
        if not self._families:
            raise ValueError("scheduler needs at least one payload family")
        self._fact_threshold = float(fact_threshold)
        # Per-family record of the buckets it has ever surfaced (across contexts),
        # for introspection / reporting only — it feeds no decision.
        self._family_buckets: dict[str, set[str]] = {}

    @classmethod
    def over_families(
        cls,
        bandit: ContextualBandit | None = None,
        *,
        families: Iterable[str] = PAYLOAD_FAMILIES,
        coverage: CoverageState | None = None,
        fact_threshold: float = HIGH_CONFIDENCE,
    ) -> "CoverageGuidedScheduler":
        """Convenience constructor: reuse a caller's bandit, or start a fresh
        uniform-prior one. The scanner/planner opts in by calling this and then
        driving :meth:`select_family` / :meth:`rank_families` / :meth:`record_attempt`."""
        return cls(
            bandit if bandit is not None else ContextualBandit(),
            coverage,
            families=families,
            fact_threshold=fact_threshold,
        )

    # -- decision ----------------------------------------------------------

    def families(self) -> tuple[str, ...]:
        """The candidate payload families this scheduler ranks over."""
        return self._families

    def rank_families(
        self, context: Context, families: Iterable[str] | None = None
    ) -> list[Arm]:
        """Every candidate family, reordered best-first by expected coverage gain
        (the bandit posterior mean). Deterministic — no sampling, ties break by
        family id. NEVER drops a family: the returned set equals the candidate
        set, asserted here, so coverage doctrine holds."""
        fams = self._resolve(families)
        ranked = self.bandit.rank(context, fams)
        assert set(ranked) == {str(f) for f in fams}, (
            "coverage invariant violated: rank_families must re-rank, never gate a "
            "family out"
        )
        return ranked

    def select_family(
        self, context: Context, families: Iterable[str] | None = None, *, rng: Random
    ) -> Arm:
        """Thompson-sample one family to try next — explore/exploit over expected
        coverage gain, using the injected ``rng``. Every candidate remains
        eligible on every call (a cold or low-coverage family still samples and
        can win), so nothing is gated out."""
        fams = self._resolve(families)
        return self.bandit.select(context, fams, rng=rng)

    def expected_coverage_gain(self, context: Context, family: str) -> float:
        """The estimated probability that ``family`` surfaces new behavior on
        this context — the bandit's posterior-mean coverage reward. This is the
        rank key; it is a ranking estimate only and confirms nothing."""
        return self.bandit.expected_value(context, str(family))

    # -- learning ----------------------------------------------------------

    def record_attempt(
        self, context: Context, family: str, signals: Iterable[OracleSignal]
    ) -> AttemptOutcome:
        """Fold one attempt's oracle verdicts in: update the coverage state,
        reward the bandit by whether NEW behavior was surfaced, and report — from
        the oracle gate ALONE — whether a FACT was confirmed.

        Coverage and confirmation are computed independently: ``coverage_gain``
        can be positive while ``produced_fact`` is False (novel but unconfirmed
        behavior), and vice versa. The bandit reward is coverage novelty, never
        the FACT — so effort is steered toward unexplored behavior without any
        finding being promoted by the ranking layer."""
        fam = str(family)
        sigs = list(signals)
        new_buckets = tuple(sorted(buckets_of(sigs) - self.coverage.buckets()))
        gain = self.coverage.observe(sigs)
        # The bandit learns coverage-productivity: reward iff new behavior appeared.
        self.bandit.update(context, fam, reward=gain > 0)
        self._family_buckets.setdefault(fam, set()).update(buckets_of(sigs))
        produced_fact = produces_fact(sigs, threshold=self._fact_threshold)
        return AttemptOutcome(
            family=fam,
            context=str(context),
            coverage_gain=gain,
            new_buckets=new_buckets,
            produced_fact=produced_fact,
        )

    # -- introspection -----------------------------------------------------

    def family_buckets(self, family: str) -> list[str]:
        """The buckets ``family`` has surfaced so far, sorted — reporting only."""
        return sorted(self._family_buckets.get(str(family), set()))

    def _resolve(self, families: Iterable[str] | None) -> tuple[str, ...]:
        if families is None:
            return self._families
        fams = tuple(dict.fromkeys(str(f) for f in families))
        if not fams:
            raise ValueError("rank/select requires a non-empty family set")
        return fams
