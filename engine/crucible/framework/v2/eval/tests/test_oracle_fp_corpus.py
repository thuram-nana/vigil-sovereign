"""Per-oracle near-zero-false-positive corpus.

``test_gate_corpus_controls`` pins the boolean-SQLi SPRT's false-positive floor with live HTTP controls.
This sibling generalises that discipline to the OTHER precise bug-class oracles that a crafted-but-benign
surface could fool, as a pure, deterministic, in-process corpus (no HTTP server): for each oracle a set of
BENIGN NEGATIVES a sound detector MUST NOT fire on, and POSITIVE CONTROLS it MUST fire on. The gate is
asymmetric — a benign negative that fires is a false positive and fails the build — and the positives keep
the file from passing by a detector that simply never fires.

The benign families are the exact confusions each oracle exists to resolve:

  * EVALUATION (SSTI)       — a REFLECTING-not-evaluating page (the raw payload echoes, but the arithmetic
                              result does not; or the result is page boilerplate present in the control).
  * ERROR_SIGNATURE (errsig)— a STATIC ERROR BANNER (a generic "error" word with no engine-specific
                              signature; or an engine banner present in BOTH observed and control, so it is
                              not attributable to the payload).
  * ACHIEVED_STATE (idor)   — an IDOR BOILERPLATE body (a shared CMS footer matched by a differential-free
                              single positive leaf) and a LIVENESS-ONLY response (``body_available`` true /
                              ``probe_count`` > 0 alone), neither of which adjudicates a cross-identity leak.
  * DIFFERENTIAL            — two IDENTICAL responses (no channel), which must not be read as a divergence.

fp == 0 over the whole benign set is asserted collectively (``test_no_oracle_fires_on_any_benign_input``),
and every positive control is asserted to fire (``test_every_positive_control_fires``).
"""
from __future__ import annotations

from collections import namedtuple

import pytest

from framework.v2.verify.oracles import (
    differential_response_oracle,
    error_signature_oracle,
    evaluation_oracle,
    predicate_oracle,
)

# A corpus entry: a callable returning an OracleSignal, plus a human label. ``run()`` yields ``.fired``.
Entry = namedtuple("Entry", "oracle label run")

# A distinctive arithmetic marker for SSTI (a large product that cannot coincidentally appear).
_RAW_EXPR = "{{31337*31337}}"
_EVAL_RESULT = "981538969"

# A real engine-specific SQL error signature vs a generic, non-attributable banner.
_SQL_ERR = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL"
_STATIC_BANNER = "<div class='error'>Something went wrong. Please try again later.</div>"

# The sound idor differential and its benign boilerplate confusions.
_IDOR_PRED = {"all": [
    {"min_len": [{"var": "discriminator"}, 6]},
    {"contains": [{"var": "victim_body"}, {"var": "discriminator"}]},
    {"contains": [{"var": "attacker_body"}, {"var": "discriminator"}]},
    {"not": {"contains": [{"var": "attacker_own_body"}, {"var": "discriminator"}]}}]}
_IDOR_OBS = {"discriminator": "acct-7FA91C33", "victim_body": "owner acct-7FA91C33",
             "attacker_body": "leaked acct-7FA91C33", "attacker_own_body": "your own profile"}

# A differential-free boilerplate predicate (a single positive leaf against a captured value) — the shape the
# grammar refuses because a shared CMS footer matches it for every user.
_BOILERPLATE_PRED = {"all": [{"contains": [{"var": "attacker_body"}, {"var": "discriminator"}]}]}
_BOILERPLATE_OBS = {"attacker_body": "<footer>Powered by Acme CMS</footer>", "discriminator": "Acme CMS"}


# ---------------------------------------------------------------------------
# BENIGN NEGATIVES — a precise detector MUST NOT fire on any of these.
# ---------------------------------------------------------------------------
_BENIGN = [
    # EVALUATION — reflecting, not evaluating: the raw payload echoes but its product does not.
    Entry("evaluation", "ssti_reflected_not_evaluated",
          lambda: evaluation_oracle(_RAW_EXPR, _EVAL_RESULT,
                                    observed_body=f"<p>you searched for {_RAW_EXPR}</p>")),
    # EVALUATION — the raw text survives verbatim alongside the result (still reflection).
    Entry("evaluation", "ssti_raw_survives_with_result",
          lambda: evaluation_oracle(_RAW_EXPR, _EVAL_RESULT,
                                    observed_body=f"<p>{_RAW_EXPR} = {_EVAL_RESULT}</p>")),
    # EVALUATION — the "result" is page boilerplate present in the benign control, so not attributable.
    Entry("evaluation", "ssti_result_is_page_boilerplate",
          lambda: evaluation_oracle(_RAW_EXPR, _EVAL_RESULT,
                                    observed_body=f"<footer>build {_EVAL_RESULT}</footer>",
                                    control_body=f"<footer>build {_EVAL_RESULT}</footer>")),
    # ERROR_SIGNATURE — a static banner with a generic "error" word, no engine-specific signature.
    Entry("error_signature", "errsig_static_generic_banner",
          lambda: error_signature_oracle(_STATIC_BANNER)),
    # ERROR_SIGNATURE — an engine banner present WITHOUT the payload (same in observed and control).
    Entry("error_signature", "errsig_banner_also_in_control",
          lambda: error_signature_oracle(f"<pre>{_SQL_ERR}</pre>", control_body=f"<pre>{_SQL_ERR}</pre>")),
    # ACHIEVED_STATE (idor) — a differential-free boilerplate match (shared CMS footer).
    Entry("predicate", "idor_boilerplate_single_leaf",
          lambda: predicate_oracle(_BOILERPLATE_OBS, _BOILERPLATE_PRED)),
    # ACHIEVED_STATE — a LIVENESS-ONLY response (body_available true alone).
    Entry("predicate", "liveness_only_body_available",
          lambda: predicate_oracle({"body_available": True}, {"eq": [{"var": "body_available"}, True]})),
    # ACHIEVED_STATE — a LIVENESS-ONLY response (probe_count > 0 alone).
    Entry("predicate", "liveness_only_probe_count",
          lambda: predicate_oracle({"probe_count": 4}, {"gt": [{"var": "probe_count"}, 0]})),
    # ACHIEVED_STATE (idor) — the full differential where the attacker's OWN body ALSO carries the
    # discriminator (so the leak is not cross-identity): the negated clause fails => does not fire.
    Entry("predicate", "idor_full_pred_no_cross_identity_leak",
          lambda: predicate_oracle({**_IDOR_OBS, "attacker_own_body": "your own acct-7FA91C33"}, _IDOR_PRED)),
    # DIFFERENTIAL — two identical responses: no channel, must not read a divergence.
    Entry("differential", "differential_identical_responses",
          lambda: differential_response_oracle(
              {"status": 200, "body": "same static body"}, {"status": 200, "body": "same static body"},
              {"dimensions": ["status", "length", "lexical"]})),
]

# ---------------------------------------------------------------------------
# POSITIVE CONTROLS — a precise detector MUST fire on each of these (so the file cannot pass vacuously).
# ---------------------------------------------------------------------------
_POSITIVE = [
    Entry("evaluation", "ssti_evaluated_result_present",
          lambda: evaluation_oracle(_RAW_EXPR, _EVAL_RESULT,
                                    observed_body=f"<p>answer: {_EVAL_RESULT}</p>",
                                    control_body="<p>answer: </p>")),
    Entry("error_signature", "errsig_real_engine_error_absent_from_control",
          lambda: error_signature_oracle(f"<pre>{_SQL_ERR}</pre>", control_body="200 OK normal page")),
    Entry("predicate", "idor_real_cross_identity_leak",
          lambda: predicate_oracle(_IDOR_OBS, _IDOR_PRED)),
    Entry("differential", "differential_material_divergence",
          lambda: differential_response_oracle(
              {"status": 200, "body": "welcome user, your balance is 42 and your token is abcdef123456"},
              {"status": 500, "body": "internal error stack trace " + "x" * 400},
              {"dimensions": ["status", "length", "lexical"]})),
]


def test_no_oracle_fires_on_any_benign_input():
    """fp == 0 over the whole benign corpus — a false positive here fails the build."""
    fired = [e.label for e in _BENIGN if e.run().fired]
    assert fired == [], f"FALSE POSITIVE(S) on benign input: {fired}"


@pytest.mark.parametrize("entry", _BENIGN, ids=[e.label for e in _BENIGN])
def test_each_benign_negative_does_not_fire(entry):
    """Per-case form of the fp==0 assertion, so a regression names the exact benign surface that broke."""
    sig = entry.run()
    assert sig.fired is False, f"{entry.oracle}: false positive on {entry.label!r}: {sig.evidence}"


@pytest.mark.parametrize("entry", _POSITIVE, ids=[e.label for e in _POSITIVE])
def test_every_positive_control_fires(entry):
    """Each positive control MUST fire — otherwise every benign assertion above is satisfied by a detector
    that never fires (the inert-corpus failure mode ``test_gate_corpus_controls`` warns about)."""
    sig = entry.run()
    assert sig.fired is True, f"{entry.oracle}: positive control {entry.label!r} failed to fire: {sig.evidence}"


def test_corpus_covers_every_targeted_oracle_both_ways():
    """Coverage guard: every targeted oracle appears in BOTH the benign and the positive set, so neither the
    fp floor nor the liveness check can silently lose an oracle."""
    targeted = {"evaluation", "error_signature", "predicate", "differential"}
    benign_oracles = {e.oracle for e in _BENIGN}
    positive_oracles = {e.oracle for e in _POSITIVE}
    assert targeted <= benign_oracles, f"benign set missing: {targeted - benign_oracles}"
    assert targeted <= positive_oracles, f"positive set missing: {targeted - positive_oracles}"
