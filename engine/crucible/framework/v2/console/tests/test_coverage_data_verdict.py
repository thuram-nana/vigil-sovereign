"""api.coverage_data must surface the BOUNDED coverage verdict.

`build_report` computes `coverage_verdict` (scanner/report.py:303 -> ScanReport.coverage_bounds()) — what an
absence of findings actually PROVES (verdict_by_class rolled up; clean_is_corpus_wide; the inconclusive
classes). `coverage_data` previously dropped it, so a console/CI consumer could not tell a default
(library-off) CLEAN from a corpus-wide negative. These tests pin that it is now passed through when the saved
report carries it, and is None (not a KeyError, no fabricated verdict) for a fallback doc that has none.
"""

from __future__ import annotations

from framework.v2.console import api


def test_coverage_data_passes_coverage_verdict_through(monkeypatch):
    verdict = {
        "clean_is_corpus_wide": False,
        "classes_inconclusive": ["nosqli", "ldap_injection", "xpath_injection"],
        "classes_exercised": ["boolean_sqli"],
    }
    doc = {
        "run_id": "r1", "target": "http://t/",
        "fingerprint": ["nginx"], "discovered_endpoints": ["/a"],
        "summary": {"findings": 0}, "coverage_verdict": verdict,
        "findings": [{"kind": "passive", "check_id": "hdr"}],
    }
    monkeypatch.setattr(api, "run_report", lambda run_id: doc)
    out = api.coverage_data("r1")
    assert "coverage_verdict" in out, "coverage_data dropped coverage_verdict"
    assert out["coverage_verdict"] == verdict
    # unchanged: the rest of the surface view is still present and correct.
    assert out["coverage_verdict"]["clean_is_corpus_wide"] is False
    assert "nosqli" in out["coverage_verdict"]["classes_inconclusive"]
    assert out["passive"] == [{"kind": "passive", "check_id": "hdr"}]


def test_coverage_data_verdict_is_none_when_source_doc_lacks_it(monkeypatch):
    # A fallback doc (progress/spine recovery) carries no rendered report → no coverage_verdict. The field
    # must be present as None (an honest "unknown"), never a KeyError and never a fabricated verdict.
    doc = {"run_id": "r2", "target": "http://t/", "summary": {"findings": 1}, "findings": []}
    monkeypatch.setattr(api, "run_report", lambda run_id: doc)
    out = api.coverage_data("r2")
    assert "coverage_verdict" in out and out["coverage_verdict"] is None


def test_coverage_data_pending_is_unchanged(monkeypatch):
    monkeypatch.setattr(api, "run_report", lambda run_id: {"pending": True})
    out = api.coverage_data("r3")
    assert out == {"run_id": "r3", "pending": True}
