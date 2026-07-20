"""
scanner.adaptive — evolving payloads and a WAF-adaptive bypass loop.

Two engines that "find a way" when a canned verification probe fails to reach
its oracle:

  * GENETIC PAYLOAD SYNTHESIS (:func:`evolve`) — a small string-genome GA.
    A population of payloads is scored by an operator-supplied fitness, parents
    are chosen by tournament, spliced (crossover) and perturbed (mutation via
    the transform library below plus char-level edits); elitism guarantees the
    best-so-far never regresses. It converges toward high fitness. It is *not*
    a global optimizer — it hill-climbs the fitness the caller defines, so a
    deceptive/flat fitness will strand it on a plateau. That is by design: the
    fitness is where domain knowledge (oracle proximity, marker reflection,
    differential delta) is injected.

  * WAF-ADAPTIVE BYPASS LOOP (:func:`waf_adapt`) — an ordered ladder of real
    evasion transforms (case variation, inline SQL comments, url/double-url/
    fullwidth encoding, whitespace and null tricks, keyword splitting). It
    climbs the ladder cumulatively, applying the next transform whenever the
    current form is still blocked, and stops at the first form the WAF lets
    through — preferring a form that *also* fires the oracle. This is a
    verification aid: it distinguishes "the bug isn't there" from "the bug is
    there but a filter ate the canonical probe", which changes the finding's
    disposition. It is a fixed ladder, not an adversarial encoder-generator; a
    WAF that normalizes all of these rungs will be reported as ``exhausted``.

Determinism: every stochastic decision in :func:`evolve` is drawn from the
injected ``random.Random``; :func:`waf_adapt` is fully deterministic. No wall
clock is read in any logic here.

Boundary: these engines evolve *verification probes* against operator-owned /
loopback targets to prove reachability past a filter. Fitness and attempt
closures are supplied by the caller (the audit engine / oracle layer), which is
where scope, charter, kill-switch and rate limits are enforced — this module
sends nothing itself and holds no network code.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field

# --------------------------------------------------------------------------- #
# Transform library — deterministic, stdlib-only payload rewrites.
#
# Each transform is a pure str->str rewrite. They are the alphabet both engines
# draw from: the GA uses them as macro-mutations, the WAF loop as ladder rungs.
# None of them read a clock or randomness — a `Transform` is reproducible.
# --------------------------------------------------------------------------- #

_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
)


def _url_encode_all(s: str) -> str:
    """Percent-encode *every* byte of ``s``'s UTF-8 (even unreserved chars).

    Unlike a URL-component encoder this leaves nothing literal, which is what a
    naive substring WAF signature (e.g. ``<script``) fails to normalize."""
    return "".join(f"%{b:02X}" for b in s.encode("utf-8"))


def _url_encode_special(s: str) -> str:
    """Percent-encode only the non-unreserved chars (RFC-3986 component form).

    This is the encoding a target actually decodes back to the raw payload, so
    it is the realistic 'does the app url-decode?' probe."""
    out: list[str] = []
    for b in s.encode("utf-8"):
        c = chr(b)
        out.append(c if c in _UNRESERVED else f"%{b:02X}")
    return "".join(out)


def _double_url_encode(s: str) -> str:
    """Encode, then encode the percent signs again (``<`` -> ``%253C``).

    Defeats a filter that url-decodes once before matching but hands the twice-
    encoded value to a sink that decodes a second time."""
    return _url_encode_all(_url_encode_special(s))


def _alt_case(s: str) -> str:
    """Alternate the case of alphabetic chars (deterministic by position).

    Bypasses case-sensitive keyword signatures while staying semantically
    identical for case-insensitive parsers (SQL keywords, HTML tag names)."""
    out: list[str] = []
    i = 0
    for ch in s:
        if ch.isalpha():
            out.append(ch.upper() if i % 2 == 0 else ch.lower())
            i += 1
        else:
            out.append(ch)
    return "".join(out)


def _to_upper(s: str) -> str:
    return s.upper()


def _to_lower(s: str) -> str:
    return s.lower()


def _fullwidth(s: str) -> str:
    """Map ASCII printables to their Unicode fullwidth forms (U+FF01..U+FF5E).

    A real evasion: some stacks normalize fullwidth to ASCII only *after* the
    WAF has matched on the raw (non-matching) fullwidth bytes."""
    out: list[str] = []
    for ch in s:
        o = ord(ch)
        if 0x21 <= o <= 0x7E:
            out.append(chr(o - 0x21 + 0xFF01))
        elif ch == " ":
            out.append("　")  # ideographic space
        else:
            out.append(ch)
    return "".join(out)


def _sql_comment_space(s: str) -> str:
    """Replace spaces with empty inline SQL comments (``/**/``)."""
    return s.replace(" ", "/**/")


def _sql_inline_split(s: str) -> str:
    """Split each alphabetic run of length >= 2 with an inline SQL comment.

    ``SELECT`` -> ``S/**/ELECT`` — breaks a contiguous-keyword signature while
    the SQL tokenizer still reads one keyword. Only touches the first boundary
    of each run so the result stays short and readable."""
    out: list[str] = []
    run = 0
    for ch in s:
        if ch.isalpha():
            run += 1
            if run == 2:
                out.append("/**/")
            out.append(ch)
        else:
            run = 0
            out.append(ch)
    return "".join(out)


def _tab_space(s: str) -> str:
    return s.replace(" ", "\t")


def _newline_space(s: str) -> str:
    return s.replace(" ", "\n")


def _null_suffix(s: str) -> str:
    """Append a raw NUL — truncates C-string filters that a later sink ignores."""
    return s + "\x00"


def _null_url_suffix(s: str) -> str:
    return s + "%00"


@dataclass(frozen=True)
class Transform:
    """A named, deterministic payload rewrite (a rung / a macro-mutation)."""

    name: str
    fn: Callable[[str], str]

    def apply(self, s: str) -> str:
        return self.fn(s)


# The transforms the GA may pick as macro-mutations.
MUTATION_TRANSFORMS: tuple[Transform, ...] = (
    Transform("url_encode", _url_encode_special),
    Transform("url_encode_all", _url_encode_all),
    Transform("double_url_encode", _double_url_encode),
    Transform("alt_case", _alt_case),
    Transform("upper", _to_upper),
    Transform("lower", _to_lower),
    Transform("fullwidth", _fullwidth),
    Transform("sql_comment_space", _sql_comment_space),
    Transform("sql_inline_split", _sql_inline_split),
    Transform("tab_space", _tab_space),
    Transform("newline_space", _newline_space),
    Transform("null_url_suffix", _null_url_suffix),
)

# The WAF evasion ladder, ordered cheapest/most-transparent first. A rung early
# in the ladder changes the payload the least; later rungs are heavier and more
# likely to also perturb semantics, so we prefer to stop early.
WAF_LADDER: tuple[Transform, ...] = (
    Transform("alt_case", _alt_case),
    Transform("sql_inline_split", _sql_inline_split),
    Transform("sql_comment_space", _sql_comment_space),
    Transform("tab_space", _tab_space),
    Transform("url_encode", _url_encode_special),
    Transform("url_encode_all", _url_encode_all),
    Transform("double_url_encode", _double_url_encode),
    Transform("fullwidth", _fullwidth),
    Transform("null_url_suffix", _null_url_suffix),
)


# --------------------------------------------------------------------------- #
# (1) Genetic payload synthesis
# --------------------------------------------------------------------------- #

Fitness = Callable[[str], float]


class EvolveResult(BaseModel):
    """Outcome of a GA run. ``best`` is the highest-fitness payload found."""

    model_config = ConfigDict(extra="forbid")

    best: str = Field(description="Highest-fitness payload discovered.")
    fitness: float = Field(description="Fitness of ``best``.")
    seed_best_fitness: float = Field(
        description="Best fitness among the initial seeds — the bar to beat."
    )
    generations_run: int = Field(ge=0, description="Generations actually evaluated.")
    history: list[float] = Field(
        default_factory=list,
        description="Best-so-far fitness after each generation (monotonic non-decreasing).",
    )
    evaluations: int = Field(
        ge=0, description="Total distinct fitness evaluations performed."
    )

    @property
    def improved(self) -> bool:
        """True iff evolution beat the best seed."""
        return self.fitness > self.seed_best_fitness


def _crossover(a: str, b: str, rng: random.Random) -> str:
    """Splice a prefix of ``a`` with a suffix of ``b`` at independent cut points.

    Single-point crossover on each parent (the cuts need not align), so the
    child length varies — this is what lets the GA *assemble* a payload longer
    than either parent from complementary building blocks."""
    if not a:
        return b
    if not b:
        return a
    ca = rng.randint(0, len(a))
    cb = rng.randint(0, len(b))
    return a[:ca] + b[cb:]


_MUT_CHARS = "<>\"'();=/*- \t{}[]&|%$#!aeiourtnsl01"


def _mutate(s: str, rng: random.Random) -> str:
    """Apply one random mutation: a macro-transform or a char-level edit.

    Char edits (insert/delete/substitute a byte from a small alphabet of chars
    that matter to injection grammars) give fine-grained hill-climbing; the
    macro-transforms give the big encoding jumps a WAF-evasion search needs."""
    kind = rng.random()
    if kind < 0.45 and s:
        # macro-mutation: reuse a transform from the library
        return rng.choice(MUTATION_TRANSFORMS).apply(s)
    if kind < 0.65:
        # insert a char
        pos = rng.randint(0, len(s))
        return s[:pos] + rng.choice(_MUT_CHARS) + s[pos:]
    if kind < 0.80 and s:
        # delete a char
        pos = rng.randrange(len(s))
        return s[:pos] + s[pos + 1 :]
    if s:
        # substitute a char
        pos = rng.randrange(len(s))
        return s[:pos] + rng.choice(_MUT_CHARS) + s[pos + 1 :]
    # empty string fallback: seed a char
    return rng.choice(_MUT_CHARS)


def _tournament(
    scored: list[tuple[float, str]], k: int, rng: random.Random
) -> str:
    """Pick the fittest of ``k`` uniformly-random contestants (tournament sel.)."""
    best_f = float("-inf")
    best_p = scored[0][1]
    for _ in range(k):
        f, p = scored[rng.randrange(len(scored))]
        if f > best_f:
            best_f, best_p = f, p
    return best_p


def evolve(
    seeds: list[str],
    fitness: Fitness,
    *,
    generations: int = 40,
    population: int = 40,
    rng: random.Random,
    elitism: int = 2,
    tournament_k: int = 3,
    crossover_rate: float = 0.7,
    mutation_rate: float = 0.6,
    max_len: int = 512,
) -> EvolveResult:
    """Evolve a payload maximizing ``fitness`` from ``seeds``.

    A tournament GA with single-point crossover, transform/char mutation and
    elitism. Elitism makes the best-so-far monotonic non-decreasing, so the
    returned ``best`` is guaranteed to be at least as fit as the best seed.
    Fully deterministic given ``rng``.

    Args:
        seeds: initial payloads; the population is seeded from these (padded by
            mutation if fewer than ``population``, truncated if more).
        fitness: higher is better; called once per distinct genome per gen. Must
            be a pure function of the payload for determinism to hold.
        generations / population: search budget. Cost ~= generations*population
            fitness calls (memoized within the run).
        elitism: number of top genomes copied verbatim into the next gen.
        tournament_k: contestants per parent selection; higher = greedier.
        crossover_rate / mutation_rate: per-child probabilities.
        max_len: children longer than this are truncated (keeps runaway growth
            and fitness cost bounded).

    Returns:
        :class:`EvolveResult` — ``.best`` is the payload; ``.improved`` says
        whether it beat the seeds.

    Limits: this optimizes exactly the supplied fitness. It cannot find a
    payload the fitness does not reward, and a flat/deceptive fitness yields no
    progress (``history`` stays constant). It is a local search, not a proof of
    optimality.
    """
    if generations < 0:
        raise ValueError("generations must be >= 0")
    if population < 1:
        raise ValueError("population must be >= 1")
    if elitism < 0 or elitism > population:
        raise ValueError("elitism must be in [0, population]")

    cache: dict[str, float] = {}

    def score(p: str) -> float:
        v = cache.get(p)
        if v is None:
            v = fitness(p)
            cache[p] = v
        return v

    # --- seed the population ------------------------------------------------
    base_seeds = [s for s in seeds if s is not None]
    if not base_seeds:
        base_seeds = [""]
    seed_best = max(score(s) for s in base_seeds)

    pop: list[str] = list(base_seeds[:population])
    while len(pop) < population:
        # pad by mutating a random seed so the initial gene pool is diverse
        pop.append(_mutate(base_seeds[rng.randrange(len(base_seeds))], rng))

    best_p = max(base_seeds, key=score)
    best_f = score(best_p)
    history: list[float] = []

    # --- generational loop --------------------------------------------------
    for _ in range(generations):
        scored = sorted(((score(p), p) for p in pop), key=lambda t: t[0], reverse=True)
        if scored[0][0] > best_f:
            best_f, best_p = scored[0]

        nxt: list[str] = [p for _, p in scored[:elitism]]
        while len(nxt) < population:
            p1 = _tournament(scored, tournament_k, rng)
            if rng.random() < crossover_rate:
                p2 = _tournament(scored, tournament_k, rng)
                child = _crossover(p1, p2, rng)
            else:
                child = p1
            if rng.random() < mutation_rate:
                child = _mutate(child, rng)
            if len(child) > max_len:
                child = child[:max_len]
            nxt.append(child)
        pop = nxt
        history.append(best_f)

    # final sweep (covers the last generation's fresh children)
    for p in pop:
        f = score(p)
        if f > best_f:
            best_f, best_p = f, p

    return EvolveResult(
        best=best_p,
        fitness=best_f,
        seed_best_fitness=seed_best,
        generations_run=generations,
        history=history,
        evaluations=len(cache),
    )


# --------------------------------------------------------------------------- #
# (2) WAF-adaptive bypass loop
# --------------------------------------------------------------------------- #


class ProbeOutcome(BaseModel):
    """What the ``attempt`` closure reports for one candidate payload.

    Deliberately distinct from ``calibration.models.Outcome`` (which resolves a
    *finding's* disposition): this is the per-request WAF signal the loop
    steers on. ``blocked`` = the filter rejected it (403/challenge/scrubbed);
    ``succeeded`` = the oracle fired (the probe reached and proved the sink)."""

    model_config = ConfigDict(extra="forbid")

    blocked: bool = Field(description="True iff the WAF/filter rejected this form.")
    succeeded: bool = Field(
        default=False, description="True iff the verification oracle fired for this form."
    )


Attempt = Callable[[str], ProbeOutcome]


class AdaptResult(BaseModel):
    """Result of a WAF-adaptive bypass search."""

    model_config = ConfigDict(extra="forbid")

    bypassed: bool = Field(description="True iff a non-blocked form was found.")
    succeeded: bool = Field(
        default=False,
        description="True iff the returned form both bypassed and fired the oracle.",
    )
    exhausted: bool = Field(
        default=False,
        description="True iff the whole ladder was tried and everything was blocked.",
    )
    payload: str | None = Field(
        default=None, description="The working transformed payload, or None if exhausted."
    )
    chain: list[str] = Field(
        default_factory=list,
        description="Ordered transform names applied (cumulatively) to get the working form.",
    )
    attempts: int = Field(ge=0, description="Number of `attempt` calls made.")


def waf_adapt(
    payload: str,
    attempt: Attempt,
    *,
    ladder: tuple[Transform, ...] = WAF_LADDER,
) -> AdaptResult:
    """Climb an evasion ladder until a form gets past the WAF.

    Starts with the raw ``payload``; if ``attempt`` reports it blocked, applies
    the next ladder transform *cumulatively* (on top of the current form) and
    re-tests, stopping at the first form that is not blocked. It keeps climbing
    past a merely-unblocked form to prefer one that *also* fires the oracle
    (``succeeded``), but never discards the first working form — if nothing
    later both bypasses and succeeds, that earliest bypass is returned.

    Returns an :class:`AdaptResult`; ``exhausted`` (and ``payload is None``)
    when every rung is blocked.

    Limits: a fixed, ordered ladder — not an adaptive encoder-generator. A WAF
    that normalizes all these rungs is reported cleanly as exhausted rather than
    escalated against; escalation into novel evasions is out of scope here by
    design (verification aid, not a weapon).
    """
    attempts = 0
    first_bypass: tuple[str, list[str]] | None = None

    # rung 0: the raw payload (empty chain)
    o = attempt(payload)
    attempts += 1
    if not o.blocked:
        if o.succeeded:
            return AdaptResult(
                bypassed=True, succeeded=True, payload=payload, chain=[], attempts=attempts
            )
        first_bypass = (payload, [])

    current = payload
    chain: list[str] = []
    for rung in ladder:
        current = rung.apply(current)
        chain = chain + [rung.name]
        o = attempt(current)
        attempts += 1
        if not o.blocked:
            if o.succeeded:
                return AdaptResult(
                    bypassed=True,
                    succeeded=True,
                    payload=current,
                    chain=list(chain),
                    attempts=attempts,
                )
            if first_bypass is None:
                first_bypass = (current, list(chain))
            # else: keep climbing, still hoping for a form that also succeeds

    if first_bypass is not None:
        form, used = first_bypass
        return AdaptResult(
            bypassed=True, succeeded=False, payload=form, chain=used, attempts=attempts
        )

    return AdaptResult(
        bypassed=False, succeeded=False, exhausted=True, payload=None, chain=[], attempts=attempts
    )
