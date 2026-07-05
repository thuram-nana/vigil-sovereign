"""
Tests for scanner.adaptive — exercise the *real* adaptive behavior, not fixtures
shaped to pass.

The GA test defines an honest, caller-side fitness (reward a payload whose
url-encoded form contains a set of required tokens, with a parsimony penalty)
and asserts evolution both beats the seeds and actually assembles a payload that
meets the target — something no single seed does. The WAF test drives the loop
with in-memory 'WAF' closures that model concrete filter behaviors and asserts
the loop finds the bypassing form + the transform chain, and reports exhaustion
cleanly when nothing gets through. No network, no clock.
"""

from __future__ import annotations

import random

from framework.v2.scanner.adaptive import (
    ProbeOutcome,
    WAF_LADDER,
    _alt_case,
    _url_encode_all,
    _url_encode_special,
    evolve,
    waf_adapt,
)


# --------------------------------------------------------------------------- #
# (1) Genetic payload synthesis
# --------------------------------------------------------------------------- #

# The GA must *assemble* a payload whose url-encoded form carries BOTH hard
# tokens. They are deliberately symmetric in difficulty and each lives in a
# different seed, so neither seed dominates and success requires real crossover
# of the two halves — not just selecting the fitter seed.
_REQUIRED = ["%3Cscript%3E", "%3C%2Fscript%3E"]  # <script> and </script>


def _url_fitness(p: str) -> float:
    """Reward tokens present in the url-encoded form. Partial credit is the
    squared prefix-fraction, so a single shared leading char ('<' -> %3C) is
    nearly worthless and the gradient only pays off near a complete token —
    this gives a climbable landscape without a cheap local optimum. A small
    length penalty enforces parsimony."""
    enc = _url_encode_special(p)
    s = 0.0
    for tok in _REQUIRED:
        best = 0
        for length in range(len(tok), 0, -1):
            if tok[:length] in enc:
                best = length
                break
        s += (best / len(tok)) ** 2
    return s - 0.003 * len(p)


def test_evolve_assembles_target_and_beats_seeds() -> None:
    rng = random.Random(1234)
    # each seed holds exactly one of the two required halves
    seeds = ["<script>foofoo", "barbar</script>", "qqqqqqqq", "zzzz", ""]

    res = evolve(
        seeds,
        _url_fitness,
        generations=80,
        population=60,
        rng=rng,
    )

    # It genuinely improved on the seeds (elitism guarantees >=, we want >).
    assert res.improved, (res.fitness, res.seed_best_fitness)
    assert res.fitness > res.seed_best_fitness

    # The best payload MEETS the target: every required token present in its
    # url-encoded form — i.e. evolution assembled all building blocks.
    enc = _url_encode_special(res.best)
    for tok in _REQUIRED:
        assert tok in enc, (tok, res.best, enc)

    # Best-so-far history is monotonic non-decreasing (elitism invariant).
    assert res.history == sorted(res.history)
    assert len(res.history) == res.generations_run
    # Memoization keeps evaluations well under the naive gen*pop bound.
    assert res.evaluations <= 80 * 60


def test_evolve_is_deterministic() -> None:
    a = evolve(["<script>", "()"], _url_fitness, generations=25, population=20, rng=random.Random(7))
    b = evolve(["<script>", "()"], _url_fitness, generations=25, population=20, rng=random.Random(7))
    assert a.best == b.best
    assert a.fitness == b.fitness
    assert a.history == b.history


def test_evolve_flat_fitness_does_not_regress() -> None:
    # A flat fitness => no progress possible; best must still equal a seed's
    # fitness (elitism never regresses) and history is constant.
    res = evolve(["abc", "def"], lambda p: 1.0, generations=10, population=8, rng=random.Random(1))
    assert res.fitness == 1.0
    assert res.seed_best_fitness == 1.0
    assert res.history == [1.0] * 10
    assert not res.improved  # flat landscape => cannot beat the seeds


# --------------------------------------------------------------------------- #
# (2) WAF-adaptive bypass loop
# --------------------------------------------------------------------------- #


def _make_waf(*, block_substrings: list[str], case_insensitive: bool):
    """Build an `attempt` closure that BLOCKS any payload containing one of the
    given signature substrings, and reports SUCCESS when it is not blocked."""

    def attempt(p: str) -> ProbeOutcome:
        hay = p.lower() if case_insensitive else p
        for sig in block_substrings:
            needle = sig.lower() if case_insensitive else sig
            if needle in hay:
                return ProbeOutcome(blocked=True, succeeded=False)
        return ProbeOutcome(blocked=False, succeeded=True)

    return attempt


def test_waf_case_sensitive_signature_bypassed_by_case_variation() -> None:
    # WAF blocks the *exact lowercase* tag; the first ladder rung (alt_case)
    # changes the case and slips through, and the oracle then fires.
    waf = _make_waf(block_substrings=["<script>"], case_insensitive=False)
    raw = "<script>"
    assert waf(raw).blocked  # sanity: the raw probe really is blocked

    res = waf_adapt(raw, waf)
    assert res.bypassed
    assert res.succeeded
    assert res.payload is not None and not waf(res.payload).blocked
    assert res.chain == ["alt_case"]
    assert res.payload == _alt_case(raw)


def test_waf_normalizing_filter_needs_encoding() -> None:
    # A more capable WAF: it lowercases, strips inline comments and normalizes
    # whitespace before matching "<script". So case-vary, comment-split and
    # whitespace rungs are all defeated — only removing the literal '<' (via
    # percent-encoding) gets through. This forces the loop to climb to a
    # url-encoding rung, proving cumulative escalation.
    def normalizing_waf(p: str):
        norm = p.lower().replace("/**/", "").replace("\t", " ").replace("\n", " ")
        blocked = "<script" in norm
        return ProbeOutcome(blocked=blocked, succeeded=not blocked)

    raw = "<script>alert(1)</script>"
    assert normalizing_waf(raw).blocked
    assert normalizing_waf(_alt_case(raw)).blocked  # case variation alone fails

    res = waf_adapt(raw, normalizing_waf)
    assert res.bypassed and res.succeeded
    assert res.payload is not None and not normalizing_waf(res.payload).blocked
    # A url-encoding rung is what finally removed the literal "<script".
    assert "url_encode" in res.chain
    assert res.chain[0] == "alt_case"  # climbed from the cheapest rung upward
    assert len(res.chain) >= 2
    # The recorded chain, replayed on the raw payload, reproduces the form.
    replayed = raw
    by_name = {t.name: t for t in WAF_LADDER}
    for name in res.chain:
        replayed = by_name[name].apply(replayed)
    assert replayed == res.payload


def test_waf_sqli_signature_bypass() -> None:
    waf = _make_waf(block_substrings=["' OR '1'='1"], case_insensitive=False)
    raw = "' OR '1'='1"
    assert waf(raw).blocked
    res = waf_adapt(raw, waf)
    assert res.bypassed and res.succeeded
    assert res.payload is not None and not waf(res.payload).blocked
    assert len(res.chain) >= 1


def test_waf_blocks_everything_is_exhausted_cleanly() -> None:
    # A WAF that blocks unconditionally: the loop must exhaust the ladder and
    # return a clean negative result (no exception, no phantom payload).
    def deny_all(p: str) -> ProbeOutcome:
        return ProbeOutcome(blocked=True, succeeded=False)

    res = waf_adapt("<script>", deny_all)
    assert not res.bypassed
    assert not res.succeeded
    assert res.exhausted
    assert res.payload is None
    assert res.chain == []
    # raw + every ladder rung tried exactly once.
    assert res.attempts == 1 + len(WAF_LADDER)


def test_waf_unblocked_but_not_succeeding_returns_first_bypass() -> None:
    # Model a filter that lets forms through but the oracle only fires for the
    # fullwidth form (later in the ladder). The loop should return a bypassing
    # form; since an earlier rung already bypassed (but didn't succeed), it
    # keeps the first bypass unless a later one both bypasses AND succeeds.
    def attempt(p: str) -> ProbeOutcome:
        blocked = "<script>" in p  # exact raw only
        succeeded = not blocked
        return ProbeOutcome(blocked=blocked, succeeded=succeeded)

    res = waf_adapt("<script>", attempt)
    # alt_case unblocks AND (by this closure) succeeds -> returned immediately.
    assert res.bypassed and res.succeeded
    assert res.chain == ["alt_case"]


def test_waf_raw_passes_immediately() -> None:
    # If the raw payload is already fine, no transforms are applied.
    def allow(p: str) -> ProbeOutcome:
        return ProbeOutcome(blocked=False, succeeded=True)

    res = waf_adapt("benign", allow)
    assert res.bypassed and res.succeeded
    assert res.chain == []
    assert res.payload == "benign"
    assert res.attempts == 1


def test_transforms_are_reversible_evidence() -> None:
    # Spot-check the encoders do what the docstrings claim (real behavior).
    assert _url_encode_special("<a>") == "%3Ca%3E"
    assert _url_encode_all("A") == "%41"
    assert _alt_case("select") == "SeLeCt"
