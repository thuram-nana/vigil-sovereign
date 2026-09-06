"""A chat-launched (integration) `vigil engage` is spawned capture_report=False, so it writes no report.json
and /api/report used to stay pending forever — the Findings screen was empty for it. run_report now falls
back to the run's progress.jsonl finding stream, so its oracle-confirmed FACTs appear on the Findings screen.
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip("framework")

from framework.v2.console import api


def test_findings_recovered_from_progress_stream(tmp_path):
    prog = tmp_path / "progress.jsonl"
    rows = [
        {"kind": "decision", "payload": {"choice": "use_tool"}},                       # ignored
        {"kind": "finding", "payload": {"title": "claimed exploit", "surface": "httpx",
                                        "bug_class": "error_based_sqli", "target": "127.0.0.1:19010",
                                        "verified_by_oracle": True, "status": "fact"}},
        {"kind": "finding", "payload": {"title": "claimed exploit", "surface": "httpx",
                                        "bug_class": "error_based_sqli", "target": "127.0.0.1:19010",
                                        "verified_by_oracle": True, "status": "fact"}},   # duplicate → deduped
        {"kind": "finding", "payload": {"title": "maybe xss", "surface": "httpx",
                                        "verified_by_oracle": False}},                   # a LEAD
    ]
    prog.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

    fs = api._findings_from_progress(tmp_path)
    assert len(fs) == 2, "the duplicate FACT is deduped; the FACT + the LEAD remain"
    fact = next(f for f in fs if f["title"] == "claimed exploit")
    assert fact["verified_by_oracle"] is True and fact["grounding"] == "fact"
    assert fact["bug_class"] == "error_based_sqli"
    lead = next(f for f in fs if f["title"] == "maybe xss")
    assert lead["verified_by_oracle"] is False and lead["grounding"] == "lead"


def test_run_report_falls_back_to_progress_when_no_report_json(tmp_path, monkeypatch):
    from framework.v2.console import actions
    rid = "20260101-000000-001"
    rd = tmp_path / rid
    rd.mkdir(parents=True)
    (rd / "meta.json").write_text(json.dumps({"status": "done", "engine": "integration",
                                              "target": "http://127.0.0.1:19010/"}), encoding="utf-8")
    (rd / "progress.jsonl").write_text(json.dumps(
        {"kind": "finding", "payload": {"title": "claimed exploit", "verified_by_oracle": True}}), encoding="utf-8")
    monkeypatch.setattr(actions, "run_dir", lambda r: (tmp_path / r))

    doc = api.run_report(rid)
    assert not doc.get("pending"), "a finished integration run must NOT be pending — recover its findings"
    assert doc["summary"]["facts"] == 1
    assert doc["source"] == "progress-stream"
    assert doc["findings"][0]["verified_by_oracle"] is True


def test_finding_row_shows_the_oracle_class_endpoint_and_oracle_not_the_tool(tmp_path):
    """The Findings row for a chat-launched FACT must show the CONFIRMED class (open_redirect), the
    endpoint as the location, and 'oracle' as the confirmer — never the tool (httpx)."""
    prog = tmp_path / "progress.jsonl"
    rows = [
        {"kind": "finding", "payload": {
            "title": "open_redirect — oracle-confirmed exploit", "surface": "httpx",
            "bug_class": "open_redirect", "target": "http://127.0.0.1:19010/auth/continue?next=x",
            "ref": "exploit:open_redirect", "verified_by_oracle": True, "status": "fact"}},
    ]
    prog.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    findings = api._findings_from_progress(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f["bug_class"] == "open_redirect"       # NOT "httpx"
    assert f["confirmed_by"] == "oracle"           # NOT "httpx"
    assert f["location"] == "http://127.0.0.1:19010/auth/continue?next=x"
    assert f["grounding"] == "fact"


def test_finding_bug_class_never_falls_back_to_the_tool_surface(tmp_path):
    """Even if a finding event somehow lacks bug_class, the row must NOT display the tool surface as the
    bug class (the old bug)."""
    prog = tmp_path / "progress.jsonl"
    rows = [{"kind": "finding", "payload": {"title": "x", "surface": "httpx", "verified_by_oracle": True}}]
    prog.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    f = api._findings_from_progress(tmp_path)[0]
    assert f["bug_class"] != "httpx"
