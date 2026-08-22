"""Unit + negative-control tests for the W11-1 loopback-engagement asserter (issue #482).

Pure-function tests: the predicates in ``check.py`` take parsed JSON, so every negative control here
perturbs an in-memory fixture and proves the checker REPORTS the divergence rather than waving it
through. Stdlib only (no engine deps) — runs anywhere the new CI job installs pytest.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check


def _built(confirmed: int = 5, full: bool = True) -> dict:
    return {
        "target": "http://127.0.0.1:18080/",
        "summary": {"confirmed": confirmed},
        "coverage": {"full_coverage": full, "built_in_run": 11, "library_run": 137},
    }


def _reverify(classes=("error_based_sqli", "boolean_sqli", "xss", "auth_bypass", "nosqli")) -> dict:
    return {
        "target": "http://127.0.0.1:18080/",
        "active_findings": [
            {"bug_class": c, "confirmed_by": "oracle", "confidence": 0.9,
             "insertion_point": "query_value:0", "oracle_context": {"bug_class": c, "marker": "x"}}
            for c in classes
        ],
    }


# ---- positive control ----------------------------------------------------------------------------
def test_positive_valid_passes():
    assert check.positive_reasons(_built(), _reverify(), floor=3, required=check.PLANTED_CLASSES) == []


def test_positive_bites_on_low_count():
    b = _built(confirmed=2)
    rv = _reverify(("error_based_sqli", "boolean_sqli"))
    reasons = check.positive_reasons(b, rv, floor=3, required=check.PLANTED_CLASSES)
    assert any("floor" in r for r in reasons), reasons


def test_positive_bites_on_missing_planted_class():
    # xss removed -> a planted weakness went unconfirmed; count still >= floor so ONLY the class check fires
    rv = _reverify(("error_based_sqli", "boolean_sqli", "auth_bypass"))
    b = _built(confirmed=3)
    reasons = check.positive_reasons(b, rv, floor=3, required=check.PLANTED_CLASSES)
    assert any("planted classes not confirmed" in r and "xss" in r for r in reasons), reasons


def test_positive_bites_on_partial_coverage():
    reasons = check.positive_reasons(_built(full=False), _reverify(), floor=3, required=check.PLANTED_CLASSES)
    assert any("full_coverage" in r for r in reasons), reasons


def test_positive_bites_on_uncertificated_finding():
    rv = _reverify()
    rv["active_findings"][0]["oracle_context"] = {}   # a fact with no re-verifiable certificate
    reasons = check.positive_reasons(_built(), rv, floor=3, required=check.PLANTED_CLASSES)
    assert any("oracle_context" in r for r in reasons), reasons


def test_positive_bites_on_count_disagreement():
    # built says 5 confirmed but the re-verifiable doc has only 3 -> the two artifacts disagree
    reasons = check.positive_reasons(_built(confirmed=5),
                                     _reverify(("error_based_sqli", "boolean_sqli", "xss")),
                                     floor=3, required=check.PLANTED_CLASSES)
    assert any("re-verifiable report has" in r for r in reasons), reasons


# ---- negative control ----------------------------------------------------------------------------
def test_negative_clean_and_conclusive_passes():
    assert check.negative_reasons(_built(confirmed=0, full=True)) == []


def test_negative_bites_when_patched_target_still_confirms():
    reasons = check.negative_reasons(_built(confirmed=1, full=True))
    assert any("still produced" in r for r in reasons), reasons


def test_negative_bites_on_silence_without_full_coverage():
    # zero findings but the full corpus never ran -> silence, NOT a sound negative
    reasons = check.negative_reasons(_built(confirmed=0, full=False))
    assert any("not a sound negative" in r for r in reasons), reasons


# ---- tamper control ------------------------------------------------------------------------------
def test_tamper_relabels_first_finding():
    doc = _reverify()
    tampered, note = check.tamper_document(doc)
    assert tampered["active_findings"][0]["bug_class"] == check._TAMPER_CLASS
    assert doc["active_findings"][0]["bug_class"] != check._TAMPER_CLASS  # original untouched (deep copy)
    assert "->" in note


def test_tamper_refuses_empty_input():
    with pytest.raises(ValueError):
        check.tamper_document({"active_findings": []})


# ---- helpers -------------------------------------------------------------------------------------
def test_coverage_line_states_full_or_partial():
    assert "full corpus" in check.coverage_line(_built(full=True))
    assert "PARTIAL" in check.coverage_line(_built(full=False))


def test_cli_round_trip(tmp_path):
    """The CLI wiring works end to end over files (positive/negative/tamper), exit codes correct."""
    bv = tmp_path / "b.json"; bv.write_text(json.dumps(_built()))
    rv = tmp_path / "r.json"; rv.write_text(json.dumps(_reverify()))
    assert check.main(["positive", "--built", str(bv), "--reverify", str(rv), "--floor", "3"]) == 0
    bn = tmp_path / "bn.json"; bn.write_text(json.dumps(_built(confirmed=0)))
    assert check.main(["negative", "--built", str(bn)]) == 0
    out = tmp_path / "t.json"
    assert check.main(["tamper", "--in", str(rv), "--out", str(out)]) == 0
    assert json.loads(out.read_text())["active_findings"][0]["bug_class"] == check._TAMPER_CLASS
