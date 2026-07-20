"""
scanner.learning — a self-learning contextual bandit for check ordering.

The scanner has a finite request budget per target and a large menu of checks
and payload families. ``targeting.py`` already prunes by parameter-name
intuition; this module adds the orthogonal, *learned* signal: which arm
(a check / bug-class / ``(bug_class, payload_family)`` id) is most likely to
land an oracle-confirmed hit **on targets that look like this one**, given
everything the framework has confirmed before. Try those first; the scan gets
sharper every engagement instead of re-running the same fixed order forever.

The algorithm is Thompson sampling over per-``(context, arm)`` Beta posteriors:

  * Each ``(context, arm)`` keeps a ``Beta(alpha, beta)`` posterior with a
    ``Beta(1, 1)`` (uniform) prior. ``alpha`` is a running count of
    oracle-confirmed hits + 1; ``beta`` is misses + 1. The posterior mean
    ``alpha / (alpha + beta)`` is the Laplace-smoothed hit rate — the same
    estimator ``memory.priors`` uses, here made per-context and decision-driving.

  * ``select`` draws one sample from every candidate arm's posterior and returns
    the arm with the largest draw. This is exploration/exploitation with no
    tuned epsilon: an arm we know little about has a wide posterior and *will*
    occasionally sample high (explore); an arm with many confirmed hits has a
    tight posterior near its true rate and wins most draws (exploit). As
    evidence accumulates the sampler provably concentrates on the best arm.

  * ``update`` folds one oracle outcome back in — ``+1`` to ``alpha`` on a
    confirmed hit, ``+1`` to ``beta`` otherwise.

Determinism: every draw comes from an injected ``random.Random`` — no module
global, no wallclock. Given the same posteriors and the same rng, ``select`` is
replayable. Contexts are independent: learning on one target archetype never
moves another's posteriors.

Warm-start: posteriors serialise to plain, sorted JSON (``to_dict`` /
``from_dict``) so priors carry across engagements, and can be *seeded* from a
``calibration.OutcomeLedger`` (confirmed/false-positive outcomes) or from
``memory.priors`` counts. Seeding needs a caller-supplied classifier because the
ledger records a finding_id and an outcome label, not an arm identity — this
module never invents which arm a past finding belonged to; the caller, who knows
its own arm space, supplies that mapping.

Limits, stated honestly:

  * Rewards are treated as i.i.d. Bernoulli per ``(context, arm)``. Real hit
    rates drift (a target gets patched mid-engagement); there is no discount
    factor, so very stale evidence is weighted equally with fresh evidence.
    Callers that care can decay ``alpha``/``beta`` between engagements.
  * Contexts are hard-bucketed strings. Two similar-but-not-identical
    fingerprints do not share evidence; there is no smoothing across contexts.
    This is deliberate — it keeps the model auditable and cold-start honest —
    but it means very high-cardinality contexts learn slowly.
  * The bandit orders effort; it never *gates*. An arm with a low posterior is
    tried last, not dropped. Coverage doctrine is the engine's job, not this
    module's.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from random import Random
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..common import paths
from ..common.beta import beta_mean
from ..common.errors import CrucibleError

SCHEMA_VERSION = 1

# An arm id and a context key are both opaque hashable strings. Helpers below
# build canonical ones, but any non-empty string the caller trusts works.
Arm = str
Context = str


class LearningError(CrucibleError):
    """Recoverable bandit error — empty arm set, unknown persisted shape, or a
    non-positive posterior parameter. The bandit orders effort; it makes no
    trust decision, so this is a plain CrucibleError, never an EthicsViolation."""


def arm_key(*parts: object) -> Arm:
    """Canonical arm id from one or more parts, e.g.
    ``arm_key("boolean_sqli", "quote_break")`` -> ``"boolean_sqli::quote_break"``.

    Parts are stringified and joined with ``::``; a single part round-trips to
    itself. Empty/whitespace-only ids are refused so a blank arm can never
    silently collide with another."""
    key = "::".join(str(p) for p in parts)
    if not key.strip():
        raise LearningError("arm id must be a non-empty string")
    return key


def context_key(features: Mapping[str, object]) -> Context:
    """Canonical context key from a bucketed-feature mapping.

    Keys are sorted so ordering never matters; values are stringified, with
    floats rounded to one decimal so near-identical fingerprints bucket
    together instead of exploding cardinality. The result is a stable
    ``k=v|k2=v2`` string — the hashable target-class the posteriors key on.

    This is a convenience for turning an ``intake.fingerprint`` feature dict
    into a context; callers with their own archetype id can pass that directly
    to ``select``/``update`` and skip this."""
    if not features:
        return "_"
    parts: list[str] = []
    for k in sorted(features):
        v = features[k]
        if isinstance(v, bool):
            token = "1" if v else "0"
        elif isinstance(v, float):
            token = f"{round(v, 1):.1f}"
        else:
            token = str(v)
        parts.append(f"{k}={token}")
    return "|".join(parts)


class BetaPosterior(BaseModel):
    """One ``(context, arm)`` posterior: ``Beta(alpha, beta)`` over the arm's
    hit rate, ``Beta(1, 1)`` prior. ``alpha - 1`` confirmed hits observed,
    ``beta - 1`` misses."""

    model_config = ConfigDict(extra="forbid")

    alpha: float = Field(default=1.0, gt=0.0, description="Hits + prior; > 0.")
    beta: float = Field(default=1.0, gt=0.0, description="Misses + prior; > 0.")

    @property
    def mean(self) -> float:
        """Posterior mean hit rate ``alpha / (alpha + beta)`` — the rank key.
        Computed by the shared :func:`common.beta.beta_mean` (identical
        arithmetic), so this canonical form and ``memory.priors``' count form
        stay one documented estimator."""
        return beta_mean(self.alpha, self.beta)

    @property
    def observations(self) -> float:
        """Evidence folded in so far: ``(alpha - 1) + (beta - 1)`` against the
        default ``Beta(1, 1)`` prior. Fractional if seeded from smoothed counts."""
        return (self.alpha - 1.0) + (self.beta - 1.0)

    def sample(self, rng: Random) -> float:
        """One Thompson draw from this posterior, using the injected rng."""
        return rng.betavariate(self.alpha, self.beta)


class ContextualBandit:
    """Thompson-sampling contextual bandit over per-``(context, arm)`` Beta
    posteriors. Deterministic given an injected rng; contexts learn
    independently; posteriors persist to JSON for cross-engagement warm-start.

    The prior is ``Beta(prior_alpha, prior_beta)``, ``Beta(1, 1)`` by default.
    A heavier prior (e.g. ``Beta(1, 3)``) makes cold arms pessimistic, useful
    when an unproven check is expensive to run."""

    def __init__(self, *, prior_alpha: float = 1.0, prior_beta: float = 1.0) -> None:
        if prior_alpha <= 0.0 or prior_beta <= 0.0:
            raise LearningError(
                f"prior must be positive, got Beta({prior_alpha}, {prior_beta})"
            )
        self._prior_alpha = float(prior_alpha)
        self._prior_beta = float(prior_beta)
        # context -> arm -> posterior. Only touched arms are materialised; an
        # untouched arm behaves as a fresh prior wherever it is queried.
        self._posteriors: dict[Context, dict[Arm, BetaPosterior]] = {}

    # -- internal ----------------------------------------------------------

    def _posterior(self, context: Context, arm: Arm, *, create: bool) -> BetaPosterior:
        arms = self._posteriors.get(context)
        if arms is not None and arm in arms:
            return arms[arm]
        fresh = BetaPosterior(alpha=self._prior_alpha, beta=self._prior_beta)
        if create:
            self._posteriors.setdefault(context, {})[arm] = fresh
        return fresh

    @staticmethod
    def _candidates(arms: Iterable[Arm]) -> list[Arm]:
        # Dedupe and sort so a run depends only on the *set* of arms and the
        # rng, never on the order the caller happened to pass them in.
        uniq = {str(a) for a in arms}
        if not uniq:
            raise LearningError("select/rank requires a non-empty arm set")
        for a in uniq:
            if not a.strip():
                raise LearningError("arm id must be a non-empty string")
        return sorted(uniq)

    # -- decision ----------------------------------------------------------

    def select(self, context: Context, arms: Iterable[Arm], *, rng: Random) -> Arm:
        """Thompson-sample one draw per candidate arm and return the arm with
        the largest draw — the arm to try first on this context.

        The draw sequence is taken over the arms in canonical (sorted) order,
        so the choice is fully determined by the posteriors and ``rng``. Ties
        (possible only when two draws are bit-identical) break by arm id."""
        candidates = self._candidates(arms)
        best_arm = candidates[0]
        best_sample = self._posterior(context, best_arm, create=False).sample(rng)
        for arm in candidates[1:]:
            s = self._posterior(context, arm, create=False).sample(rng)
            if s > best_sample:
                best_sample, best_arm = s, arm
        return best_arm

    def rank(self, context: Context, arms: Iterable[Arm]) -> list[Arm]:
        """Candidate arms ordered by posterior mean, best first. Deterministic:
        no sampling — ties break by arm id. This is the greedy exploit order,
        the counterpart to ``select``'s stochastic explore-and-exploit."""
        candidates = self._candidates(arms)
        return sorted(
            candidates,
            key=lambda a: (-self._posterior(context, a, create=False).mean, a),
        )

    def expected_value(self, context: Context, arm: Arm) -> float:
        """Posterior-mean hit rate for ``(context, arm)`` — the prior mean for
        an arm with no evidence yet."""
        return self._posterior(context, str(arm), create=False).mean

    def observations(self, context: Context, arm: Arm) -> float:
        """How much evidence backs ``(context, arm)`` (hits + misses folded in)."""
        return self._posterior(context, str(arm), create=False).observations

    # -- learning ----------------------------------------------------------

    def update(self, context: Context, arm: Arm, reward: bool) -> None:
        """Fold one oracle outcome into ``(context, arm)``: ``+1`` to ``alpha``
        on a confirmed hit, ``+1`` to ``beta`` on a miss. Materialises the
        posterior on first touch."""
        p = self._posterior(context, str(arm), create=True)
        if reward:
            p.alpha += 1.0
        else:
            p.beta += 1.0

    def seed_prior(
        self, context: Context, arm: Arm, *, successes: float, failures: float
    ) -> None:
        """Warm-start ``(context, arm)`` from aggregate counts (e.g.
        ``memory.priors`` successes/attempts): add ``successes`` to ``alpha``
        and ``failures`` to ``beta`` on top of the current posterior. Counts
        may be fractional. Negative counts are refused."""
        if successes < 0.0 or failures < 0.0:
            raise LearningError(
                f"seed counts must be >= 0, got ({successes}, {failures})"
            )
        p = self._posterior(context, str(arm), create=True)
        p.alpha += float(successes)
        p.beta += float(failures)

    def seed_from_ledger(
        self,
        ledger: object,
        classify: Callable[[object, object], tuple[Context, Arm] | None],
    ) -> int:
        """Warm-start from a ``calibration.OutcomeLedger``. For each resolved
        ``(prediction, outcome)`` pair, ``classify(prediction, outcome)`` returns
        the ``(context, arm)`` that finding belonged to (or ``None`` to skip —
        the classifier owns the arm space, this module never guesses it).
        DISPUTED outcomes (``target is None``) are skipped. The outcome's binary
        exploitability target drives the update: ``1.0`` -> hit, ``0.0`` -> miss.

        Returns the number of pairs folded in. Takes ``ledger`` structurally
        (anything exposing ``pairs()`` of objects with a ``target``) so this
        module imports nothing from calibration and cannot perturb it."""
        pairs = getattr(ledger, "pairs", None)
        if not callable(pairs):
            raise LearningError("ledger must expose a pairs() method")
        n = 0
        for prediction, outcome in pairs():
            target = getattr(outcome, "target", None)
            if target is None:
                continue
            key = classify(prediction, outcome)
            if key is None:
                continue
            context, arm = key
            self.update(context, str(arm), bool(target >= 0.5))
            n += 1
        return n

    def seed_from_priors(
        self,
        priors: Iterable[object],
        key: Callable[[object], tuple[Context, Arm] | None],
    ) -> int:
        """Warm-start from ``memory.priors.Prior`` rows (or any objects with
        ``successes`` and ``attempts``). ``key(prior)`` maps each row to a
        ``(context, arm)`` or ``None`` to skip. ``successes`` add to ``alpha``,
        ``attempts - successes`` to ``beta``. Returns the number seeded."""
        n = 0
        for prior in priors:
            k = key(prior)
            if k is None:
                continue
            successes = float(getattr(prior, "successes", 0))
            attempts = float(getattr(prior, "attempts", 0))
            failures = max(0.0, attempts - successes)
            context, arm = k
            self.seed_prior(context, str(arm), successes=successes, failures=failures)
            n += 1
        return n

    # -- introspection -----------------------------------------------------

    def contexts(self) -> list[Context]:
        """Every context with materialised evidence, sorted."""
        return sorted(self._posteriors)

    def arms(self, context: Context) -> list[Arm]:
        """Every arm with materialised evidence under ``context``, sorted."""
        return sorted(self._posteriors.get(context, {}))

    # -- persistence -------------------------------------------------------

    def to_dict(self) -> dict[str, object]:
        """Serialise to a plain, deterministic dict (contexts and arms sorted).
        Only materialised posteriors are written; the prior is recorded so a
        reload reproduces cold-arm behaviour exactly."""
        posteriors: dict[str, dict[str, list[float]]] = {}
        for context in sorted(self._posteriors):
            arms = self._posteriors[context]
            posteriors[context] = {
                arm: [arms[arm].alpha, arms[arm].beta] for arm in sorted(arms)
            }
        return {
            "schema_version": SCHEMA_VERSION,
            "prior": [self._prior_alpha, self._prior_beta],
            "posteriors": posteriors,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        """Deterministic JSON string. ``indent=None`` gives a compact line."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "ContextualBandit":
        """Rebuild from a ``to_dict`` document, re-validating the prior and
        every posterior (both parameters must be > 0)."""
        if not isinstance(data, dict):
            raise LearningError("bandit document must be a JSON object")
        version = data.get("schema_version")
        if version != SCHEMA_VERSION:
            raise LearningError(
                f"unsupported bandit schema_version {version!r} (expected {SCHEMA_VERSION})"
            )
        prior = data.get("prior", [1.0, 1.0])
        if not (isinstance(prior, (list, tuple)) and len(prior) == 2):
            raise LearningError("bandit 'prior' must be a [alpha, beta] pair")
        try:
            bandit = cls(prior_alpha=float(prior[0]), prior_beta=float(prior[1]))
        except (TypeError, ValueError) as e:
            raise LearningError(f"bandit prior is not numeric: {e}") from e

        raw = data.get("posteriors", {})
        if not isinstance(raw, dict):
            raise LearningError("bandit 'posteriors' must be an object")
        for context, arms in raw.items():
            if not isinstance(arms, dict):
                raise LearningError(f"posteriors for context {context!r} must be an object")
            for arm, params in arms.items():
                if not (isinstance(params, (list, tuple)) and len(params) == 2):
                    raise LearningError(
                        f"posterior for ({context!r}, {arm!r}) must be [alpha, beta]"
                    )
                try:
                    post = BetaPosterior(alpha=float(params[0]), beta=float(params[1]))
                except (ValidationError, TypeError, ValueError) as e:
                    raise LearningError(
                        f"posterior for ({context!r}, {arm!r}) is invalid: {e}"
                    ) from e
                bandit._posteriors.setdefault(str(context), {})[str(arm)] = post
        return bandit

    @classmethod
    def from_json(cls, text: str) -> "ContextualBandit":
        """Rebuild from a JSON string produced by ``to_json``."""
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise LearningError(f"bandit document is not valid JSON: {e}") from e
        return cls.from_dict(data)

    def save(self, path: Path | str, *, indent: int | None = 2) -> None:
        """Write the bandit to ``path`` (parent dirs created)."""
        p = Path(path)
        paths.secure_write(p, self.to_json(indent=indent))   # X2: owner-only (learned target signal)

    @classmethod
    def load(cls, path: Path | str) -> "ContextualBandit":
        """Read a bandit from ``path``. Missing file -> LearningError."""
        p = Path(path)
        if not p.is_file():
            raise LearningError(f"no bandit file at {p}")
        try:
            text = p.read_text(encoding="utf-8")
        except OSError as e:
            raise LearningError(f"cannot read bandit at {p}: {e}") from e
        return cls.from_json(text)
