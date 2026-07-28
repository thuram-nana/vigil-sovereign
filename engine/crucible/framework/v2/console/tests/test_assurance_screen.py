"""C2 — the console drift_data provider (continuous proof / drift between two runs).

The drift LOGIC (re-fire confirmed certs, set-diff) is covered by verify/drift's own suite; this checks the
console wrapper: honest pending on a missing run, and the "<curr>:<prev>" argument parsing.
"""

from __future__ import annotations

from framework.v2.console import actions, api


def test_drift_data_is_safe_on_a_missing_run(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path / ".console")
    d = api.drift_data("no-such-run")
    assert d["pending"] is True and d["regressions"] == [] and d["fixed"] == []
    assert d["has_drift"] is False and "drift" in d["doctrine"].lower()


def test_drift_data_parses_curr_and_prev(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path / ".console")
    d = api.drift_data("runA:runB")
    assert d["curr"] == "runA" and d["prev"] == "runB"
