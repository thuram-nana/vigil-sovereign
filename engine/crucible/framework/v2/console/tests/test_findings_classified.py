"""Every finding the Findings/Fixes screens render is CLASSIFIED — bug class + its CWE id(s) + OWASP
Top-10 category — not merely named. The server stamps the taxonomy from ``report.standards`` (the same
frozen table the Compliance screen uses) onto each finding at the ONE serving chokepoint (``run_report``,
both its report.json and progress-stream branches, plus the Fixes list).

HONEST SCOPE guard: the stamp is DATA about the weakness class (a confirmed XSS *is* CWE-79 by
definition), NOT a compliance-coverage assertion — so it is additive, never overwrites a caller's own
value, and is a no-op for an unmapped class. These tests pin exactly that.
"""
from __future__ import annotations

import json

from framework.v2.console import actions, api
from framework.v2.report import standards


def _write(tmp_path, run_id, name, text):
    d = tmp_path / "runs" / run_id
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(text, encoding="utf-8")


# ---- the pure classifier -------------------------------------------------

def test_classify_stamps_cwe_and_owasp_for_real_classes():
    for bc, cwe, owasp in [
        ("xss", "CWE-79", "A03:2021"),
        ("boolean_sqli", "CWE-89", "A03:2021"),
        ("error_based_sqli", "CWE-89", "A03:2021"),
        ("ssrf", None, None),          # owasp checked below via the table, not hard-pinned here
        ("path_traversal", None, None),
    ]:
        f = api._classify_finding({"bug_class": bc})
        controls = standards.controls_for(bc)
        assert controls is not None, bc
        assert f["cwe"] == list(controls["cwe"]), bc
        if cwe is not None:
            assert cwe in f["cwe"], bc
        assert f.get("owasp") == controls["owasp"], bc


def test_classify_is_additive_never_overwrites():
    f = api._classify_finding({"bug_class": "xss", "cwe": ["CWE-CUSTOM"]})
    assert f["cwe"] == ["CWE-CUSTOM"]          # a caller's own value is preserved


def test_classify_is_a_noop_for_unmapped_or_empty():
    assert "cwe" not in api._classify_finding({"bug_class": "not_a_real_class_zzz"})
    assert "cwe" not in api._classify_finding({"bug_class": ""})
    assert api._classify_finding({}) == {}
    # a non-dict is returned unchanged (total)
    assert api._classify_finding(None) is None


# ---- the serving chokepoint (run_report) ---------------------------------

def test_run_report_classifies_report_json_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    doc = {"findings": [{"bug_class": "xss", "title": "reflected", "grounding": "fact"},
                        {"bug_class": "boolean_sqli", "title": "blind", "grounding": "fact"}]}
    _write(tmp_path, "r1", "report.json", json.dumps(doc))
    out = api.run_report("r1")
    by_class = {f["bug_class"]: f for f in out["findings"]}
    assert by_class["xss"]["cwe"] == ["CWE-79"]
    assert by_class["xss"]["owasp"] == "A03:2021"
    assert "CWE-89" in by_class["boolean_sqli"]["cwe"]


def test_run_report_classifies_progress_stream_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    events = [
        {"kind": "finding", "payload": {"bug_class": "xss", "title": "reflected",
                                        "verified_by_oracle": True, "target": "http://127.0.0.1:19010/"}},
    ]
    _write(tmp_path, "r2", "progress.jsonl", "\n".join(json.dumps(e) for e in events) + "\n")
    _write(tmp_path, "r2", "meta.json", json.dumps({"status": "done", "target": "http://127.0.0.1:19010/"}))
    out = api.run_report("r2")
    assert out["findings"], "progress-stream findings should surface"
    assert out["findings"][0]["cwe"] == ["CWE-79"]
    assert out["findings"][0]["owasp"] == "A03:2021"


# ---- the blackboard (spine) fallback for whole-app SUITE runs -------------

class _FakeRow:
    def __init__(self, payload): self.payload = payload


class _FakeBB:
    """A stand-in for the blackboard: returns canned finding rows, records that close() ran."""
    def __init__(self, rows): self._rows = rows; self.closed = False
    def read(self, *, engagement, kinds=None, limit=1000): return list(self._rows)
    def close(self): self.closed = True


def test_run_report_recovers_spine_findings_for_a_suite_run(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    # a suite run: meta carries a slug, but the run dir has NO report.json and NO progress.jsonl
    _write(tmp_path, "r3", "meta.json", json.dumps({"status": "done", "mode": "suite",
                                                     "slug": "wholeapp-xyz"}))
    rows = [
        _FakeRow({"bug_class": "xss", "title": "xss confirmed", "verified_by_oracle": True,
                  "surface": "http://127.0.0.1:19010/records/search?q=t", "oracle_kind": "reflection_context",
                  "oracle_context": {"bug_class": "xss"}, "severity": "High"}),
        _FakeRow({"bug_class": "ssrf", "title": "ssrf confirmed", "verified_by_oracle": True,
                  "surface": "http://127.0.0.1:19010/documents/fetch?url=t", "oracle_kind": "oob_callback",
                  "oracle_context": {"bug_class": "ssrf"}, "severity": "High"}),
        _FakeRow({"bug_class": "missing-content-security-policy", "title": "Missing CSP",
                  "verified_by_oracle": False, "surface": "http://127.0.0.1:19010/", "severity": "Medium"}),
    ]
    monkeypatch.setattr("framework.v2.agents.blackboard.open_blackboard", lambda: _FakeBB(rows))
    out = api.run_report("r3")
    assert out.get("source") == "spine"
    assert out["summary"] == {"findings": 3, "facts": 2, "leads": 1}
    by_class = {f["bug_class"]: f for f in out["findings"]}
    assert by_class["xss"]["cwe"] == ["CWE-79"] and by_class["xss"]["verified_by_oracle"] is True
    assert by_class["ssrf"]["cwe"] == ["CWE-918"] and by_class["ssrf"]["owasp"] == "A10:2021"
    # the passive lead surfaces as a LEAD (never promoted) and its unmapped class carries no CWE
    assert by_class["missing-content-security-policy"]["grounding"] == "lead"
    assert "cwe" not in by_class["missing-content-security-policy"]


def test_spine_fallback_never_shadows_a_progress_stream(tmp_path, monkeypatch):
    """If the run dir already streamed findings, the spine is NOT consulted (no double source)."""
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    _write(tmp_path, "r4", "meta.json", json.dumps({"status": "done", "slug": "wholeapp-abc"}))
    _write(tmp_path, "r4", "progress.jsonl",
           json.dumps({"kind": "finding", "payload": {"bug_class": "xss", "title": "from-progress",
                                                       "verified_by_oracle": True}}) + "\n")
    def _boom(): raise AssertionError("blackboard must not be opened when progress has findings")
    monkeypatch.setattr("framework.v2.agents.blackboard.open_blackboard", _boom)
    out = api.run_report("r4")
    assert out.get("source") == "progress-stream"
    assert out["findings"][0]["title"] == "from-progress"
