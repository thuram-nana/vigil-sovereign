"""
Wave 6 — the program-level CORPUS-WIDE zero-false-positive gate.

This is the assertion that makes "the wider deep/full engagement roster ships on by
default" SAFE: run the WHOLE benchmark corpus (every planted bug AND every benign twin
/ negative control) under the deep AND full profiles, and prove

  * ZERO false positives anywhere in the corpus — no benign twin / negative control is
    ever flagged (the near-zero-FP thesis), AND
  * the planted bugs still confirm — enabling the wider roster costs no coverage.

Two layers, so the gate is provably not a no-op AND provably portable:

  (A) Fast, browserless UNIT tests over ``zero_fp_gate`` and the XSS-corroboration
      de-dup — these prove the gate FAILS on a planted FP or a coverage drop, is
      fail-closed on an empty run, and that the de-dup can NEVER launder a benign FP.
  (B) An end-to-end run of the real deep/full roster over the benchmark app. On a host
      WITH a browser the DOM-XSS pass corroborates the reflected XSS at the same sink
      (one bug, two oracles — de-duped to a single TP); on a browserless host those
      surfaces emit no finding (recorded INCONCLUSIVE elsewhere, never CLEAN). Both
      hold 11tp/0fp/0fn, so the gate passes everywhere.

FAIL-BEFORE / PASS-AFTER: introduce a real FP under the deep roster (e.g. flag a safe
endpoint) and (A) + (B) go red; drop the XSS-corroboration de-dup and (B) sees the
DOM/reflected double as an FP and goes red on a browser host.
"""

from __future__ import annotations

import pytest

from ..benchmark_run import (
    _collapse_xss_corroboration,
    _xss_family_key,
)
from ..gate import zero_fp_gate
from ..validation import (
    MeasuredBoard,
    NormalizedFinding,
    RunMetrics,
    Scoreboard,
)

# The benchmark app's SAFE endpoints (the negative controls) — nothing may ever be
# reported on any of these under ANY profile. Kept in lock-step with benchmark_app's
# safe routes and write_report's preamble.
_SAFE_ENDPOINTS = ("/profile", "/api/health", "/download", "/greeting", "/support")


def _board(tp: int, fp: int, fn: int, *, tool: str = "crucible", app: str = "benchmark-app") -> MeasuredBoard:
    return MeasuredBoard(
        scoreboard=Scoreboard(tool=tool, target=app, true_positives=tp,
                              false_positives=fp, false_negatives=fn),
        metrics=RunMetrics(tool=tool, target=app, elapsed_s=0.1, findings_reported=tp + fp),
    )


# ---------------------------------------------------------------------------
# (A) the gate is asymmetric, fail-closed, and provably not a no-op
# ---------------------------------------------------------------------------


def test_gate_passes_on_a_clean_zero_fp_full_coverage_run():
    verdict = zero_fp_gate({"benchmark-app": [_board(11, 0, 0)]})
    assert verdict.passed
    assert not verdict.regressions


def test_gate_fails_on_any_false_positive():
    verdict = zero_fp_gate({"benchmark-app": [_board(11, 1, 0)]})
    assert not verdict.passed
    assert any("FALSE POSITIVE" in r for r in verdict.regressions)


def test_gate_fails_on_a_coverage_regression():
    # a drop in planted-bug coverage under the wider roster is a hard failure too
    verdict = zero_fp_gate({"benchmark-app": [_board(10, 0, 1)]})
    assert not verdict.passed
    assert any("REGRESSED planted-bug coverage" in r for r in verdict.regressions)


def test_gate_is_fail_closed_on_an_empty_run():
    # a gate that evaluated nothing tested nothing — it must not pass
    verdict = zero_fp_gate({})
    assert not verdict.passed


def test_gate_honours_an_explicit_true_positive_floor():
    # with an explicit floor, more TP than the floor is fine (asymmetric: never a failure)
    assert zero_fp_gate({"benchmark-app": [_board(11, 0, 0)]},
                        min_true_positives={"benchmark-app": 11}).passed
    # below the floor fails
    assert not zero_fp_gate({"benchmark-app": [_board(10, 0, 0)]},
                            min_true_positives={"benchmark-app": 11}).passed


# ---------------------------------------------------------------------------
# (A) the XSS-corroboration de-dup is SOUND — it can never launder a benign FP
# ---------------------------------------------------------------------------


def _nf(bug_class: str, location: str) -> NormalizedFinding:
    return NormalizedFinding(tool="crucible", bug_class=bug_class, location=location, confirmed=True)


def test_xss_family_key_collapses_only_the_xss_subclasses():
    assert _xss_family_key("dom_xss") == "xss"
    assert _xss_family_key("stored_xss") == "xss"
    assert _xss_family_key("XSS") == "xss"
    # a non-XSS class is untouched
    assert _xss_family_key("boolean_sqli") != "xss"
    assert _xss_family_key("open_redirect") != "xss"


def test_dedup_merges_a_dom_xss_corroboration_of_the_same_sink():
    # the reflected-XSS static check + the browser DOM-execution pass confirm ONE bug
    out = _collapse_xss_corroboration([_nf("xss", "/search?q"), _nf("dom_xss", "/search?q")])
    assert len(out) == 1
    assert out[0].bug_class == "xss"  # first occurrence (the family label) is kept


def test_dedup_NEVER_launders_a_benign_endpoint_false_positive():
    # a DOM-XSS on a DIFFERENT location (a benign twin) is a DISTINCT finding: it must
    # survive the de-dup so the zero-FP gate still catches it. This is the soundness
    # property that stops the de-dup from being a laundering mechanism.
    out = _collapse_xss_corroboration([_nf("xss", "/search?q"), _nf("dom_xss", "/profile?name")])
    assert len(out) == 2


def test_dedup_preserves_distinct_non_xss_findings():
    findings = [_nf("boolean_sqli", "/users?name"), _nf("error_based_sqli", "/product?id")]
    assert len(_collapse_xss_corroboration(findings)) == 2


# ---------------------------------------------------------------------------
# (B) end-to-end: the real deep/full roster is zero-FP over the whole corpus
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def deep_and_full_runs() -> dict[str, tuple[list[MeasuredBoard], list[NormalizedFinding]]]:
    """Run the whole benchmark corpus under the deep AND full profiles ONCE each,
    capturing BOTH the scored board and the raw produced findings from the SAME scan
    (so the negative-control check adds no extra scan). On a host with Chromium this
    exercises the browser DOM/stored-XSS passes; on a browserless host those surfaces
    emit no finding (INCONCLUSIVE elsewhere, never CLEAN). Either way the corpus stays
    zero-FP with full planted-bug coverage."""
    from ..benchmark_app import benchmark_corpus, serve
    from ..benchmark_run import BenchmarkCrucibleAdapter
    from ..validation import score

    out: dict[str, tuple[list[MeasuredBoard], list[NormalizedFinding]]] = {}
    for profile in ("deep", "full"):
        with serve() as base_url:
            corpus = benchmark_corpus(base_url)
            produced = BenchmarkCrucibleAdapter(profile=profile).run(corpus)
            sb = score(produced, corpus.expected, tool="crucible", target=corpus.name)
        board = MeasuredBoard(
            scoreboard=sb,
            metrics=RunMetrics(tool="crucible", target=corpus.name, elapsed_s=0.0,
                               findings_reported=len(produced)),
        )
        out[profile] = ([board], produced)
    return out


@pytest.mark.parametrize("profile", ["deep", "full"])
def test_corpus_is_zero_fp_with_full_coverage_under_the_profile(deep_and_full_runs, profile):
    boards, _ = deep_and_full_runs[profile]
    sb = boards[0].scoreboard
    assert sb.tool == "crucible"
    # the corpus-wide zero-FP invariant: no benign twin / negative control flagged
    assert sb.false_positives == 0, f"{profile}: NEW false positive under the wider roster"
    # the planted bugs still confirm (no coverage regression vs. surface = 11)
    assert sb.true_positives == 11
    assert sb.false_negatives == 0
    assert sb.precision == 1.0


def test_the_zero_fp_gate_passes_under_deep_and_full(deep_and_full_runs):
    for profile, (boards, _) in deep_and_full_runs.items():
        verdict = zero_fp_gate({"benchmark-app": boards})
        assert verdict.passed, f"{profile}: {verdict.regressions}"


def test_no_finding_ever_lands_on_a_negative_control(deep_and_full_runs):
    """Defense in depth over the strict scoreboard: independently confirm that under the
    deep/full roster CRUCIBLE reports NOTHING on any of the benchmark app's safe
    endpoints — a finding there would be an unambiguous benign-control false positive."""
    for profile, (_, produced) in deep_and_full_runs.items():
        for f in produced:
            assert not any(safe in f.location for safe in _SAFE_ENDPOINTS), (
                f"{profile}: finding on a negative control: {f.bug_class} @ {f.location}")


# ---------------------------------------------------------------------------
# surface stays byte-identical: the profile is pure roster EXPANSION
# ---------------------------------------------------------------------------


def test_surface_profile_is_the_default_roster():
    """``profile='surface'`` flips no extra pass and applies no de-dup — the default
    ``make gate`` roster, unchanged. (The 11tp/0fp/0fn number is pinned by the default
    benchmark test + the committed baseline; here we assert the surface adapter takes
    the untouched path.)"""
    from ..benchmark_run import _PROFILE_ROSTER, BenchmarkCrucibleAdapter

    assert _PROFILE_ROSTER["surface"] == {}
    a = BenchmarkCrucibleAdapter()  # default
    assert a._profile == "surface"


def test_unknown_profile_is_rejected():
    from ..benchmark_run import BenchmarkCrucibleAdapter
    from ..validation import HarnessError

    with pytest.raises(HarnessError):
        BenchmarkCrucibleAdapter(profile="turbo")
