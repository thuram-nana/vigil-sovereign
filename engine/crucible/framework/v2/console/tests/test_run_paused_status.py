"""Wave 7 — a run that exited resumably (awaiting a signature / anti-spin / ask_user) is recorded as
PAUSED, not "done". _run_outcome reads the engine's terminal run_summary from progress.jsonl."""
from __future__ import annotations

import json

from framework.v2.console import actions


def _write_progress(tmp_path, run_id, events):
    d = tmp_path / "runs" / run_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "progress.jsonl").write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")


def test_run_outcome_reads_the_paused_summary(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    _write_progress(tmp_path, "r1", [
        {"kind": "decision", "payload": {"choice": "use_tool"}},
        {"kind": "run_summary", "payload": {"paused": "awaiting_approval", "done": False, "fact_count": 0}},
    ])
    out = actions._run_outcome("r1")
    assert out.get("paused") == "awaiting_approval" and out.get("done") is False


def test_run_outcome_empty_for_a_finished_run(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    _write_progress(tmp_path, "r2", [
        {"kind": "run_summary", "payload": {"paused": "", "done": True, "fact_count": 2}},
    ])
    out = actions._run_outcome("r2")
    assert out.get("paused") == "" and out.get("done") is True


def test_run_outcome_none_when_no_summary(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    _write_progress(tmp_path, "r3", [{"kind": "decision", "payload": {"choice": "complete"}}])
    assert actions._run_outcome("r3") == {}
