"""
The opt-in live-progress sink (scanner.progress) — the ONE engine touch for the UI.

Pins the two guarantees that make it safe: the default is a literal no-op (the
campaign holds `None` and makes no calls), and the JSONL sink is fire-and-forget
(a write error never raises into a scan).
"""

from __future__ import annotations

import json

from framework.v2.scanner.campaign import WebScanCampaign
from framework.v2.scanner.progress import JsonlSink, ProgressSink


def _send(_req):
    return {"status": 200, "body": "ok"}


def test_default_progress_is_none_no_op() -> None:
    # the campaign default: no sink -> no calls on the hot path
    camp = WebScanCampaign(_send)
    assert camp._progress is None


def test_jsonl_sink_writes_phase_finding_done(tmp_path) -> None:
    p = tmp_path / "progress.jsonl"
    sink = JsonlSink(p)
    assert isinstance(sink, ProgressSink)  # satisfies the protocol
    sink.phase("crawl", target="http://t/")
    sink.finding("xss", "reflection_context", "q", "http://t/s?q=1", 0.97)
    sink.done(findings=1, requests_sent=42, elapsed_s=1.5)
    events = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    kinds = [e["event"] for e in events]
    assert kinds == ["scan.phase", "scan.finding", "scan.done"]
    assert [e["seq"] for e in events] == [1, 2, 3]  # monotonic, clock-free ordering
    f = events[1]
    assert f["bug_class"] == "xss" and f["confirmed_by"] == "reflection_context" and f["confidence"] == 0.97


def test_jsonl_sink_swallows_write_errors(tmp_path) -> None:
    # a sink pointed at an unwritable path must never raise into the scan
    bad = tmp_path / "nonexist-dir-removed"
    sink = JsonlSink(bad / "sub" / "p.jsonl")
    # make the parent a file so the append can't create/open the target
    (tmp_path / "blocker").write_text("x", encoding="utf-8")
    sink_bad = JsonlSink(tmp_path / "blocker" / "p.jsonl")
    sink_bad.phase("crawl")  # must not raise
    sink_bad.finding("x", "y", "z", "u", 0.5)
    sink_bad.done(0, 0, 0.0)
