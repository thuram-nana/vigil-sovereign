"""
Wave 5 — the SPRT boolean-inference oracle, whose per-round signal is a TRUTH-VALUE
ATTRIBUTION test.

A boolean_sqli FACT means the response is a deterministic FUNCTION of the injected
boolean's TRUTH VALUE: every one of K_T distinct always-TRUE clauses lands on the same
response, every one of K_F distinct always-FALSE clauses lands on the same response, and
the two clusters are disjoint. These tests confirm a clean 2-cluster split on a real
channel, refuse a deterministic non-vuln, refuse a page that changes every request, refuse
a COARSE (low-cardinality) input-independent page, refuse a SKEWED one whose determinism
pre-gate is FORCED to pass, and refuse an old single-clause context (fail-closed on shape).
"""

from __future__ import annotations

import random

from framework.v2.verify.oracles import _boolean_discriminator, boolean_inference_oracle

_MANY = {"status": 200, "body": "id=1\nid=2\nid=3\nid=4\nid=5 (all rows)"}
_NONE = {"status": 200, "body": "no results"}


def _round(trues, falses) -> dict:
    """A TRUTH-VALUE ATTRIBUTION round on a DETERMINISTIC page: each clause's byte-identical
    repeat returns the same response, so the repeats are copies of the clause responses."""
    return {"trues": list(trues), "falses": list(falses),
            "true_repeats": [dict(r) for r in trues], "false_repeats": [dict(r) for r in falses]}


def _clean(true=_MANY, false=_NONE, k: int = 6) -> dict:
    """A round from a page that IS a function of the truth value: every true clause -> one
    page, every false clause -> another."""
    return _round([dict(true) for _ in range(k)], [dict(false) for _ in range(k)])


def _baseline(resp, n: int = 16) -> list:
    # the determinism PRE-FILTER: n responses to ONE IDENTICAL false-clause request (all
    # identical on a deterministic page). A confirm additionally requires this to have passed.
    return [dict(resp) for _ in range(n)]


def test_clean_two_cluster_split_confirms_in_few_rounds() -> None:
    # every always-TRUE clause returns the whole table, every always-FALSE clause returns
    # "no results" — the response IS a function of the truth value.
    rounds = [_clean() for _ in range(24)]
    sig = boolean_inference_oracle(rounds, false_baseline_samples=_baseline(_NONE))
    assert sig.fired and sig.confidence >= 0.7
    assert sig.observed["rounds_used"] <= 6  # SPRT stops early on a clear signal


def test_confirm_requires_the_baseline_determinism_pregate() -> None:
    # FAIL-CLOSED: even a perfect 2-cluster split does NOT mint a FACT without the up-front
    # identical-request baseline. (A cheap pre-filter on top of the attribution test, not the
    # thing that makes the oracle sound — see the skewed test below, where it is forced to pass.)
    rounds = [_clean() for _ in range(24)]
    sig = boolean_inference_oracle(rounds)  # no false_baseline_samples
    assert not sig.fired
    assert sig.observed["decision"] == "inconclusive"


def test_insufficient_baseline_samples_cannot_confirm() -> None:
    rounds = [_clean() for _ in range(24)]
    sig = boolean_inference_oracle(rounds, false_baseline_samples=_baseline(_NONE, n=3))
    assert not sig.fired


def test_one_clause_per_truth_value_cannot_confirm_fail_closed() -> None:
    # A SINGLE clause per truth value is ONE DRAW — it cannot attribute a response to a truth
    # VALUE, so the round is never a positive signal no matter how cleanly it separates.
    rounds = [_round([dict(_MANY)], [dict(_NONE)]) for _ in range(24)]
    sig = boolean_inference_oracle(rounds, false_baseline_samples=_baseline(_NONE))
    assert not sig.fired
    assert sig.observed["decision"] == "refute"


def test_old_single_clause_context_cannot_confirm_fail_closed() -> None:
    # An OLD retained context ({"true", "false_a", "false_b", "false_a_repeat"}) carries no
    # truth-value arms, so it can only ever REFUTE — old evidence can never mint.
    rounds = [{"true": dict(_MANY), "false_a": dict(_NONE), "false_b": dict(_NONE),
               "false_a_repeat": dict(_NONE)} for _ in range(24)]
    sig = boolean_inference_oracle(rounds, false_baseline_samples=_baseline(_NONE))
    assert not sig.fired
    assert sig.observed["decision"] == "refute"


def test_within_truth_disagreement_refuses() -> None:
    # The true clauses do NOT all land on the same response (one of them returns the false page):
    # there is no single TRUE cluster, so the response is not a function of the truth value.
    rounds = [_round([dict(_MANY)] * 5 + [dict(_NONE)],
                     [dict(_NONE) for _ in range(6)]) for _ in range(24)]
    sig = boolean_inference_oracle(rounds, false_baseline_samples=_baseline(_NONE))
    assert not sig.fired
    assert sig.observed["decision"] == "refute"


def test_coarse_input_independent_page_is_refused() -> None:
    # A page whose body is one of only K=2 distinct variants chosen independently of the input:
    # its identical-request baseline is not all-identical -> proven non-deterministic -> REFUSE.
    v0 = {"status": 200, "body": "no results variant A" + "A" * 50}
    v1 = {"status": 200, "body": "no results variant B" + "B" * 50}
    coarse_baseline = [v0, v1, v0, v0, v1, v0, v1, v1, v0, v1, v0, v0, v1, v0, v1, v1]
    sig = boolean_inference_oracle([_clean(v1, v0) for _ in range(24)],
                                   false_baseline_samples=coarse_baseline)
    assert not sig.fired
    assert sig.observed.get("nondeterministic") is True


def test_skewed_input_independent_page_refuses_with_the_pregate_forced_to_pass() -> None:
    # THE red-pen BLOCK regression at the ORACLE level, with the determinism pre-gate DEFEATED
    # by construction: a SKEWED (dominant variant p=0.9) K=2 input-independent page, handed an
    # all-identical 16-sample baseline so the pre-gate PASSES. Every response — clause and
    # repeat — is an independent draw. A clean 2-cluster split by truth value then requires all
    # 12 true-side draws to be one variant and all 12 false-side draws the other (<= 2*2**-24),
    # so the oracle must refuse every seed. This is what a determinism gate alone could not do.
    variants = [{"status": 200, "body": "no results variant A" + "A" * 60},
                {"status": 200, "body": "no results variant B" + "B" * 60}]
    forced_baseline = [dict(variants[0]) for _ in range(16)]
    for seed in range(400):
        rng = random.Random(seed)

        def draw(_rng=rng):
            return dict(_rng.choices(variants, weights=[0.9, 0.1], k=1)[0])

        rounds = [{"trues": [draw() for _ in range(6)], "true_repeats": [draw() for _ in range(6)],
                   "falses": [draw() for _ in range(6)], "false_repeats": [draw() for _ in range(6)]}
                  for _ in range(24)]
        sig = boolean_inference_oracle(rounds, false_baseline_samples=forced_baseline)
        assert not sig.fired, f"skewed input-independent page minted a FALSE FACT at seed {seed}"


def test_deterministic_non_vuln_is_refuted() -> None:
    # the clause is treated as literal data: true and false give the same response
    sig = boolean_inference_oracle([_clean(_NONE, _NONE) for _ in range(24)],
                                   false_baseline_samples=_baseline(_NONE))
    assert not sig.fired
    assert sig.observed["decision"] == "refute"


def test_dynamic_page_hard_refutes_on_a_differing_repeat() -> None:
    # every response differs (a per-request nonce), so a byte-identical clause repeat comes back
    # different -> the page is PROVEN non-deterministic -> hard refute, never a FACT.
    def _nonce(tag: str) -> dict:
        # a long per-request token dominates the body, so ANY two responses diverge lexically
        return {"status": 200, "body": "session " + (tag * 40) + " — no results"}

    rounds = [{"trues": [_nonce(f"a{i}{j}") for j in range(3)],
               "true_repeats": [_nonce(f"b{i}{j}") for j in range(3)],
               "falses": [_nonce(f"c{i}{j}") for j in range(3)],
               "false_repeats": [_nonce(f"d{i}{j}") for j in range(3)]}
              for i in range(24)]
    sig = boolean_inference_oracle(rounds)
    assert not sig.fired
    assert sig.observed.get("nondeterministic") is True


def test_flaky_endpoint_does_not_confirm() -> None:
    # the clusters separate only half the time, by chance; the SPRT must not confirm
    rounds = [_clean() if i % 2 == 0 else _clean(_NONE, _NONE) for i in range(24)]
    sig = boolean_inference_oracle(rounds, false_baseline_samples=_baseline(_NONE))
    assert not sig.fired


def test_request_count_is_bounded() -> None:
    sig = boolean_inference_oracle([_clean(_NONE, _NONE) for _ in range(100)])
    # SPRT decides well before consuming all rounds
    assert sig.observed["rounds_used"] <= 24


def test_the_deterministic_arbitrary_map_residual_is_real_and_is_disclosed() -> None:
    """THE HONEST LIMIT, PINNED — not merely asserted in prose.

    A page that is a DETERMINISTIC but ARBITRARY function of the URL (a CDN caching per exact URL
    over an origin that picked a variant at fill time) can hand back a perfect 2-cluster split
    with NO boolean channel: the repeats are cache hits, so determinism holds, and every later
    round returns the same bytes. The oracle DOES confirm here. Repetition cannot help against a
    map that is constant in the request, so for THIS case more distinct clauses is the lever
    (``<= 2 * 2**-(K_T+K_F)`` that the split is chance) and the drivers additionally BOUND the
    number of independent attempts per URL and state the resulting figure.

    This test exists so the code and the disclosure cannot drift apart: if someone later claims
    this residual is closed, this test fails and forces the claim to be re-earned or the
    docstring corrected."""
    v_a = {"status": 200, "body": "variant A" + "A" * 60}
    v_b = {"status": 200, "body": "variant B" + "B" * 60}
    # the cache froze variant A on every true-clause URL and variant B on every false-clause URL
    sig = boolean_inference_oracle([_clean(v_a, v_b) for _ in range(24)],
                                   false_baseline_samples=_baseline(v_b))
    assert sig.fired, "the disclosed deterministic-arbitrary-map residual is no longer reachable"
    doc = boolean_inference_oracle.__doc__ or ""
    assert "DETERMINISTIC but ARBITRARY function of the request" in doc
    # ...and the disclosure must NOT be dressed up as unobservable-in-principle. An earlier revision
    # claimed "no observation of the response can separate" and "RAISING K_T/K_F is the only lever";
    # both were measurably FALSE (a truth-correlated LEXICAL filter mints at rate 1.0 and is beaten by
    # clause-SHAPE diversity, not by K). Keep those words out.
    for overclaim in ("IRREDUCIBLE RESIDUAL", "no observation of the response can separate",
                      "is the only lever"):
        assert overclaim not in doc, f"the oracle docstring re-states a refuted absolute: {overclaim!r}"


def test_the_request_filter_failure_mode_is_disclosed_without_absolutes() -> None:
    """The OTHER documented failure mode must stay documented — and must stay documented HONESTLY.

    An earlier revision of this test asserted the docstring contained "CLAUSE-SHAPE DIVERSITY" and
    "``K`` is NOT a lever here", i.e. it PINNED the very absolute that measurement went on to refute
    (a complete constant folder partitions a shape-varied but purely-foldable set perfectly). That
    is the same anti-pattern as the deleted "IRREDUCIBLE" / "only lever" claims, so this test now
    checks only that the mode is NAMED and that a RESIDUAL is named with it — never that any
    particular mitigation is sufficient. The live behavioural regressions
    (``scanner/tests/test_boolean_inference_check.py``: CRS-942130, the complete constant folder,
    and the leave-one-shape-out sweep) are what actually hold the mechanism."""
    doc = boolean_inference_oracle.__doc__ or ""
    assert "TRUTH-CORRELATED REQUEST FILTER" in doc, "the failure mode is no longer named"
    assert "RESIDUAL (a2), NAMED NOT CLOSED" in doc, "the residual is no longer named with it"
    # and no phrasing that asserts a mitigation is complete
    for absolute in ("no single surface rule", "cannot be partitioned", "is the only lever",
                     "no clause set can be partitioned"):
        assert absolute not in doc, f"the docstring re-states an unmeasurable absolute: {absolute!r}"


def test_latency_alone_can_never_mint_a_boolean_fact() -> None:
    """RED-PEN BLOCK-2 — ``differential_response_oracle``'s DEFAULT dimension set includes ``latency``
    (differing at +1000ms), so a caller passing no discriminator let a boolean_sqli FACT rest on TIMING
    over BYTE-IDENTICAL bodies. And because the probe order is all-TRUE then all-FALSE, any step
    slowdown crossing that boundary (a tarpit, a pool or rate-limit transition) lands exactly on the
    truth partition. The oracle now PINS the dimensions, so this must refute — including when the
    retained context explicitly asks for latency (an untrusted report cannot widen the channel back)."""
    same = "the very same page, byte for byte, for every single clause we sent"
    fast = {"status": 200, "body": same, "latency_ms": 20.0}
    slow = {"status": 200, "body": same, "latency_ms": 9000.0}   # a 9s step across the truth boundary
    rounds = [_round([dict(slow) for _ in range(6)], [dict(fast) for _ in range(6)]) for _ in range(24)]
    for disc in (None, {"dimensions": ["status", "length", "lexical", "latency"]}, {"dimensions": ["latency"]},
                 "latency"):
        sig = boolean_inference_oracle(rounds, discriminator=disc,
                                       false_baseline_samples=_baseline(fast))
        assert not sig.fired, f"a latency-only split minted a boolean FACT with discriminator={disc!r}"
        assert sig.observed["decision"] == "refute"


def test_the_sprt_parameters_are_not_context_supplied() -> None:
    """RED-PEN item 6 — a context could pass ``sprt_p0``; ``sprt_p0=1e-9`` converts the two-net-signal
    confirm boundary into a ONE-signal boundary, so a single coincidentally-separating round out of 24
    mints at confidence 0.95. The verifier no longer forwards them."""
    import inspect
    import re as _re

    from framework.v2.verify.verifier import OracleVerifier
    # strip comments so the explanatory note about the removal does not satisfy its own test
    src = "\n".join(_re.sub(r"#.*$", "", ln) for ln in inspect.getsource(OracleVerifier).splitlines())
    assert "sprt_" not in src, "the verifier forwards context-supplied SPRT parameters again"

    one_signal = [_clean()] + [_clean(_NONE, _NONE) for _ in range(23)]
    ctx = {"bug_class": "boolean_sqli", "probe_rounds": one_signal,
           "false_baseline_samples": _baseline(_NONE), "sprt_p0": 1e-9, "sprt_p1": 0.999999}
    res = OracleVerifier().confirm(ctx)
    assert not res.confirmed, "a context-supplied sprt_p0 still lowered the confirm bar"
    # control: the SAME evidence with the honest parameters is a refute, so the assertion is not vacuous
    assert not OracleVerifier().confirm(
        {k: v for k, v in ctx.items() if not k.startswith("sprt_")}).confirmed


def test_a_context_supplied_discriminator_cannot_tune_the_boolean_channel() -> None:
    """Companion to the SPRT-parameter pin: the oracle forces the comparison DIMENSIONS, but a
    context-supplied THRESHOLD still tunes sensitivity, and a threshold fitted to the retained bytes
    can manufacture "within-cluster same, across-cluster differ" out of noise. The verifier therefore
    re-executes the boolean channel under protocol defaults."""
    import inspect

    from framework.v2.verify.verifier import OracleVerifier
    src = inspect.getsource(OracleVerifier._run_oracle if hasattr(OracleVerifier, "_run_oracle")
                            else OracleVerifier)
    i = src.index("BOOLEAN_INFERENCE")
    assert 'discriminator=ctx' not in src[i:i + 1200], \
        "the verifier forwards a context-supplied discriminator to the boolean oracle again"

    # a near-miss page: the two clusters differ by well under the honest lexical threshold
    base = "catalogue listing " + "item " * 200
    t = {"status": 200, "body": base + "A"}
    f = {"status": 200, "body": base + "B"}
    rounds = [_round([dict(t) for _ in range(6)], [dict(f) for _ in range(6)]) for _ in range(24)]
    ctx = {"bug_class": "boolean_sqli", "probe_rounds": rounds,
           "false_baseline_samples": _baseline(f),
           # fitted by the producer to call a 1-byte difference a "divergence"
           "discriminator": {"dimensions": ["lexical"], "lexical_threshold": 0.0}}
    assert not OracleVerifier().confirm(ctx).confirmed, \
        "a context-supplied threshold tuned a sub-threshold difference into a boolean FACT"
    # ...and the pin is at the ORACLE too, so it holds even when the oracle is called DIRECTLY with a
    # fitted threshold (the verifier is the only path that drops the discriminator wholesale).
    sig = boolean_inference_oracle(rounds, false_baseline_samples=_baseline(f),
                                   discriminator={"dimensions": ["lexical"], "lexical_threshold": 0.0})
    assert not sig.fired, "a fitted threshold passed straight to the oracle still tuned the channel"
    assert _boolean_discriminator({"lexical_threshold": 0.0, "length_threshold": 0.0}) == {
        "dimensions": ["status", "length", "lexical"], "expect": "differ"}


def test_forced_pregate_over_generated_rounds_never_mints() -> None:
    """RED-PEN BLOCK-3 — the CORRECTED "pre-gate forced to pass" control, through the REAL mint path.

    The earlier harness drove ``BooleanInferenceCheck.probe`` against an input-independent page and
    then overwrote ``false_baseline_samples``. But ``probe`` SHORT-CIRCUITS on the first baseline
    divergence and returns ZERO rounds, so the forced cells handed the oracle an EMPTY round list and
    measured nothing — the tell was that the forced and honest artefacts had byte-identical request
    counts. Here the rounds are GENERATED directly from the input-independent model (exactly the
    responses the check would have collected had the pre-gate passed), the all-identical baseline is
    attached, and the assertions below FAIL if the evidence is vacuous."""
    from framework.v2.verify.adapter import FindingContext
    from framework.v2.verify.confirmation import confirm_finding
    from framework.v2.verify.verifier import OracleVerifier

    variants = [{"status": 200, "body": "no results variant " + c * 61} for c in "AB"]
    forced = [dict(variants[0]) for _ in range(16)]
    facts = 0
    for seed in range(200):
        rng = random.Random(0xF0 + seed)

        def draw(_rng=rng):
            return dict(_rng.choices(variants, weights=[0.9, 0.1], k=1)[0])

        tr = [[draw() for _ in range(6)] for _ in range(24)]
        trr = [[draw() for _ in range(6)] for _ in range(24)]
        fr = [[draw() for _ in range(6)] for _ in range(24)]
        frr = [[draw() for _ in range(6)] for _ in range(24)]
        ctx = FindingContext.from_boolean_probes(
            true_rounds=tr, false_rounds=fr, true_repeat_rounds=trr, false_repeat_rounds=frr,
            bug_class="boolean_sqli", false_baseline_samples=forced).to_verifier_context()
        # NON-VACUITY: the rounds must actually exist and the pre-gate must actually be satisfiable.
        assert len(ctx["probe_rounds"]) == 24 and len(ctx["false_baseline_samples"]) == 16
        assert len(ctx["probe_rounds"][0]["trues"]) == 6
        if confirm_finding(finding={"bug_class": "boolean_sqli"}, context=ctx,
                           verifier=OracleVerifier()) is not None:
            facts += 1
    assert facts == 0, f"{facts}/200 FALSE FACTs with the determinism pre-gate forced to pass"
