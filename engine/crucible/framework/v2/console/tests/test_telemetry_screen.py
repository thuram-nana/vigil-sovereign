"""G2 — the console read provider for the live assurance/metrics snapshot (api.telemetry).

Read-only: the console SERVES the `vigil up --with-telemetry` collector's snapshot file (a pure one-way
projection of the signed spine). An absent file yields an honest `running: false` marker, never a traceback.
"""

from __future__ import annotations

import json

from framework.v2.console import api


def test_telemetry_not_running_is_honest(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path))          # no live-ui/telemetry.json under it
    r = api.telemetry()
    assert r["ok"] is True and r["running"] is False
    assert "with-telemetry" in r["note"] and r["engagements"] == []


def test_telemetry_serves_the_collector_snapshot(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path))
    d = tmp_path / "live-ui"
    d.mkdir()
    (d / "telemetry.json").write_text(json.dumps({
        "schema": 1, "generated_at": 42,
        "engagements": [{"slug": "loopback", "facts": 2, "leads": 3, "refusals": 1}],
        "totals": {"facts": 2, "leads": 3, "refusals": 1}}), encoding="utf-8")
    r = api.telemetry()
    assert r["ok"] is True and r["running"] is True
    assert r["totals"]["facts"] == 2 and r["engagements"][0]["slug"] == "loopback"


def test_telemetry_bad_file_is_fail_soft(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path))
    d = tmp_path / "live-ui"
    d.mkdir()
    (d / "telemetry.json").write_text("not json at all", encoding="utf-8")
    r = api.telemetry()
    assert r["ok"] is True and r["running"] is False           # unparseable → honest not-running, no crash
