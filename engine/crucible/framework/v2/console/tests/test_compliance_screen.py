"""C3-UI — the console `compliance_data` provider (surfaces report.standards over a run's findings).

Honesty under test: a LEAD (a finding whose retained oracle_context does NOT re-fire) is graded advisory and
asserts NO control coverage — only an oracle-PROVEN fact carries controls. The mapping logic itself is
covered by framework/v2/report's own suite; this checks the console wrapper + the honesty passthrough.
"""

from __future__ import annotations

import json

from framework.v2.console import actions, api


def test_compliance_data_is_safe_on_a_missing_run():
    d = api.compliance_data("no-such-run-xyz")
    assert d["run_id"] == "no-such-run-xyz" and d["findings"] == [] and d.get("pending") is True
    assert isinstance(d["standards"], dict) and d["standards"]        # standard versions surfaced
    assert "advisory" in d["doctrine"].lower()


def test_compliance_data_never_asserts_coverage_for_a_lead(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path / ".console")
    run = "20260101-000000-001"
    rd = actions.run_dir(run)
    rd.mkdir(parents=True, exist_ok=True)
    # an inert oracle_context (no probe rounds) grades a LEAD → advisory NOTE only, no control coverage.
    (rd / "reverifiable.json").write_text(json.dumps({"active_findings": [
        {"bug_class": "sqli", "oracle_context": {"bug_class": "sqli", "note": "inert — no probe rounds"}}]}),
        encoding="utf-8")
    d = api.compliance_data(run)
    assert d["findings"], "the finding should be surfaced"
    f = d["findings"][0]
    assert f["status"] != "proven" and f["coverage_asserted"] is False   # a lead
    assert f["controls"] is None                                          # NO control coverage for a lead
