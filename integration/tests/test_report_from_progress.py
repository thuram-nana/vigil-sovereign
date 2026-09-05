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
