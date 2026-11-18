"""L1 (live Max) — the ONE per-engagement rate limit + connection cap the gated executor holds (pricing design §6).

An engagement builds exactly ONE ``HttpExecutor`` and every gated request rides it, so the per-engagement floor and cap
pinned here bound the WHOLE run — a single global throttle, never one per tool or per agent. A Max run
(``vigil_core.run_tier.engage_controls_for("max")``: 10 requests/second ⇒ a 0.1 s floor, 8 connections) can therefore
never hammer a live target, however many agents call the executor.

The framework conftest zeroes the posture rate profiles for speed, so in the unmarked tests below the per-engagement
floor is the only non-zero floor — exactly the value under test. The one test that compares it with the GENUINE posture
floor opts out with ``real_rate_floor`` (it reads ``_rate_floor()`` only — no wall-clock wait).

Mutation-verify targets (each neuter reds a NAMED test here):
  * drop the per-engagement floor from ``_rate_floor``     -> test_one_per_engagement_rate_limit_spaces_every_caller_of_the_one_executor
  * ``_sleep_for_rate_limit`` bypasses ``_rate_floor``      -> test_one_per_engagement_rate_limit_spaces_every_caller_of_the_one_executor
  * the per-engagement floor overrides (loosens) the posture -> test_the_per_engagement_floor_only_tightens_the_posture
  * drop the clamp on the per-engagement floor             -> test_the_per_engagement_floor_is_clamped_fail_safe
  * ``_client_limits`` returns no cap / ``_client`` drops it -> test_one_connection_cap_bounds_the_one_client
"""
from __future__ import annotations

import threading

import pytest

from vigil_core import run_tier


def _executor(posture: str = "TEST", **kw):
    from framework.v2.agents.http_executor import HttpExecutor
    return HttpExecutor(engagement_slug="<test>", base_url="http://127.0.0.1/", posture=posture, **kw)


def test_one_per_engagement_rate_limit_spaces_every_caller_of_the_one_executor(monkeypatch):
    # Eight "agents" call the ONE executor at the same frozen instant, held to the Max floor (0.1 s = 10 requests per
    # second). They share ONE anchor, so their reserved start instants are spaced by the floor ACROSS all of them: the
    # first goes at once and the k-th waits k floors — eight requests over 0.7 s, 10 per second for the engagement in
    # total, never 10 per second per caller.
    import framework.v2.agents.http_executor as H
    monkeypatch.delenv("VIGIL_MIN_REQUEST_INTERVAL_S", raising=False)
    floor = run_tier.engage_controls_for("max").min_request_interval_s
    ex = _executor(per_engagement_rate_floor_s=floor)
    slept: list[float] = []
    guard = threading.Lock()

    def _sleep(s: float) -> None:
        with guard:
            slept.append(s)

    monkeypatch.setattr(H.time, "sleep", _sleep)
    monkeypatch.setattr(H.time, "time", lambda: 1000.0)
    agents = [threading.Thread(target=ex._sleep_for_rate_limit) for _ in range(8)]
    for a in agents:
        a.start()
    for a in agents:
        a.join()
    assert sorted(round(s, 6) for s in slept) == [round(k * floor, 6) for k in range(1, 8)]


@pytest.mark.real_rate_floor
def test_the_per_engagement_floor_only_tightens_the_posture(monkeypatch):
    # GENUINE posture floors. The per-engagement floor can only make a run slower: below the posture it changes nothing
    # (the Max 0.1 s on a TEST charter stays at the TEST floor); above the posture it binds.
    from framework.v2.agents.http_executor import _RATE_PROFILES
    monkeypatch.delenv("VIGIL_MIN_REQUEST_INTERVAL_S", raising=False)
    test_floor, audit_floor = _RATE_PROFILES["TEST"][0], _RATE_PROFILES["AUDIT"][0]
    assert test_floor > 0.1 and audit_floor > 0.5                       # the real profiles are in force here
    assert _executor(per_engagement_rate_floor_s=0.1)._rate_floor() == test_floor        # never loosens
    assert _executor(per_engagement_rate_floor_s=0.5)._rate_floor() == 0.5               # tightens
    assert _executor("AUDIT", per_engagement_rate_floor_s=0.5)._rate_floor() == audit_floor


def test_a_default_executor_holds_no_engagement_floor_or_cap(monkeypatch):
    # Byte-identical: an executor built without the L1 controls (every non-Max run) has no per-engagement floor — its
    # floor is exactly the posture/operator max it always was — and builds its client without a limits override.
    import framework.v2.agents.http_executor as H
    monkeypatch.delenv("VIGIL_MIN_REQUEST_INTERVAL_S", raising=False)
    ex = _executor()
    assert ex._per_engagement_rate_floor == 0.0 and ex._client_limits() is None
    assert ex._rate_floor() == max(H._RATE_PROFILES["TEST"][0], ex._operator_min_interval)
    seen: dict = {}
    monkeypatch.setattr(H.httpx, "Client", lambda **kw: seen.update(kw) or object())
    ex._client()
    assert "limits" not in seen and seen["follow_redirects"] is False


@pytest.mark.parametrize("raw,expect", [("x", 0.0), (-1, 0.0), (None, 0.0), (99999, 3600.0), (0.1, 0.1)])
def test_the_per_engagement_floor_is_clamped_fail_safe(raw, expect):
    # Junk / negative ⇒ no engagement floor (the posture still binds); a huge value is capped at 1 h per request.
    assert _executor(per_engagement_rate_floor_s=raw)._per_engagement_rate_floor == pytest.approx(expect)


def test_one_connection_cap_bounds_the_one_client(monkeypatch):
    # The Max cap (8) bounds BOTH the total and the keep-alive connections of the ONE shared client, so the whole
    # engagement opens at most that many sockets to the target at once.
    import framework.v2.agents.http_executor as H
    cap = run_tier.engage_controls_for("max").connection_cap
    seen: dict = {}
    monkeypatch.setattr(H.httpx, "Client", lambda **kw: seen.update(kw) or object())
    _executor(per_engagement_connection_cap=cap)._client()
    limits = seen["limits"]
    assert limits.max_connections == cap == 8 and limits.max_keepalive_connections == cap


@pytest.mark.parametrize("bad", [0, -1, True, "8", 2.5, None])
def test_a_malformed_connection_cap_adds_no_limits_override(bad):
    # The executor never builds a pool from a junk cap; a governed (Max) run with a junk cap is refused earlier, in
    # run_engagement's preflight (engage._check_engage_controls), so it never reaches here.
    assert _executor(per_engagement_connection_cap=bad)._client_limits() is None
