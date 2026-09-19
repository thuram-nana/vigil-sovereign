"""B10 — operator-settable rate / User-Agent controls.

The scanner ALREADY identifies itself (the correlatable OBSIDIAN UA) and throttles per the charter posture.
These tests lock the operator CONTROLS layered on top: a correlatable UA tag, and a rate FLOOR that can only
TIGHTEN (slow the run), never loosen it below what the posture mandates; plus the console helper that threads
them to the engage child and surfaces a read-only traffic profile.
"""

from __future__ import annotations

import pytest


def _exec(monkeypatch, *, op_id=None, min_interval=None):
    monkeypatch.delenv("VIGIL_OPERATOR_ID", raising=False)
    monkeypatch.delenv("VIGIL_MIN_REQUEST_INTERVAL_S", raising=False)
    if op_id is not None:
        monkeypatch.setenv("VIGIL_OPERATOR_ID", op_id)
    if min_interval is not None:
        monkeypatch.setenv("VIGIL_MIN_REQUEST_INTERVAL_S", min_interval)
    from framework.v2.agents.http_executor import HttpExecutor
    return HttpExecutor(engagement_slug="<test>", base_url="http://127.0.0.1/", posture="TEST")


# ---- executor: UA tag + tighten-only rate floor --------------------------------------------------
def test_operator_id_env_tags_the_correlatable_user_agent(monkeypatch):
    from framework.v2.agents.http_executor import user_agent_for
    ex = _exec(monkeypatch, op_id="gov-run-42")
    assert ex.operator_identifier == "gov-run-42"
    ua = user_agent_for("TEST", ex.operator_identifier)
    assert ua.startswith("OBSIDIAN/1.0 (authorized owner-test") and "gov-run-42" in ua


def test_min_interval_env_tightens_the_rate_floor(monkeypatch):
    import framework.v2.agents.http_executor as H
    ex = _exec(monkeypatch, min_interval="2.0")
    assert ex._operator_min_interval == 2.0
    slept: list[float] = []
    monkeypatch.setattr(H.time, "sleep", lambda s: slept.append(s))
    monkeypatch.setattr(H.time, "time", lambda: 1000.0)
    ex._last_request_at = 999.9                       # ~0.1s since the last request
    ex._sleep_for_rate_limit()
    # TEST floor 0.2, operator floor 2.0 -> effective 2.0; elapsed 0.1 -> wait ~1.9 (jitter 0 on TEST)
    assert slept and abs(slept[0] - 1.9) < 0.05, slept


def test_operator_min_below_posture_floor_cannot_loosen(monkeypatch):
    import framework.v2.agents.http_executor as H
    ex = _exec(monkeypatch, min_interval="0.05")      # BELOW the TEST posture floor 0.2
    slept: list[float] = []
    monkeypatch.setattr(H.time, "sleep", lambda s: slept.append(s))
    monkeypatch.setattr(H.time, "time", lambda: 1000.0)
    ex._last_request_at = 1000.0                      # ~0 elapsed
    ex._sleep_for_rate_limit()
    # effective floor = max(0.2, 0.05) = 0.2 — the posture floor is kept; the operator can't speed it up
    assert slept and abs(slept[0] - 0.2) < 0.02, slept


def test_min_interval_env_clamped_and_fail_safe(monkeypatch):
    from framework.v2.agents.http_executor import _env_min_request_interval
    monkeypatch.setenv("VIGIL_MIN_REQUEST_INTERVAL_S", "not-a-number")
    assert _env_min_request_interval() == 0.0
    monkeypatch.setenv("VIGIL_MIN_REQUEST_INTERVAL_S", "-5")
    assert _env_min_request_interval() == 0.0
    monkeypatch.setenv("VIGIL_MIN_REQUEST_INTERVAL_S", "99999")
    assert _env_min_request_interval() == 3600.0
    monkeypatch.delenv("VIGIL_MIN_REQUEST_INTERVAL_S", raising=False)
    assert _env_min_request_interval() == 0.0


# ---- console helper: env threading + read-only profile + header-injection safety -----------------
def test_console_helper_threads_env_and_profile():
    from framework.v2.console.actions import _operator_traffic_controls
    r = _operator_traffic_controls({"operator_id": "gov-run-1", "min_request_interval_s": 1.5}, "someslug")
    assert r["env"]["VIGIL_OPERATOR_ID"] == "gov-run-1"
    assert r["env"]["VIGIL_MIN_REQUEST_INTERVAL_S"] == "1.5"
    assert r["profile"]["get_only"] is True
    assert r["profile"]["operator_min_request_interval_s"] == 1.5
    assert r["profile"]["effective_min_request_interval_s"] >= 1.5   # tightened at/above posture floor


def test_console_helper_sanitises_operator_id_against_header_injection():
    from framework.v2.console.actions import _operator_traffic_controls
    r = _operator_traffic_controls({"operator_id": "x\r\nInjected-Header: 1"}, "s")
    tag = r["env"].get("VIGIL_OPERATOR_ID", "")
    assert "\r" not in tag and "\n" not in tag and tag == "xInjected-Header: 1"


def test_console_helper_ignores_invalid_interval():
    from framework.v2.console.actions import _operator_traffic_controls
    r = _operator_traffic_controls({"min_request_interval_s": "nope"}, "s")
    assert "VIGIL_MIN_REQUEST_INTERVAL_S" not in r["env"]
    assert r["profile"]["operator_min_request_interval_s"] == 0.0
