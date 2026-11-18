"""L1 (live Max) — governed tools only, and ONE rate limit per engagement, inside ``run_engagement`` (pricing design §6).

A Max run is held to VIGIL's governed tools: everything it sends must ride the ONE gated executor (scope / WARDEN /
rate-limited). Two kinds of pass would escape that executor — the ungoverned raw-socket arsenal (it speaks bytes on the
wire directly) and the directly-navigating browser passes (a second, un-throttled egress path) — so with
``governed_tools_only`` both are forced OFF, and the executor is built with the engagement's one rate floor and
connection cap. A governed run that does not carry well-formed controls is refused before the lease arm and before any
traffic. Every non-Max run (``governed_tools_only`` False, inert floor / cap) is byte-identical.

The run tests drive the REAL ``run_engagement`` with the executor, the campaign, preflight and the lease arm replaced by
recorders (a non-customer slug), rooted in a temporary CRUCIBLE_ROOT so nothing is written into the source tree.

Mutation-verify targets (each neuter reds a NAMED test here):
  * ``_governed_tool_overlay`` stops narrowing / leaks one pass      -> test_governed_tools_only_forces_every_executor_bypassing_pass_off
  * ``_governed_tool_overlay`` narrows a non-governed run            -> test_without_governed_tools_only_the_roster_is_unchanged
  * ``run_engagement`` hands the campaign a raw knob, not the overlay -> test_a_max_run_rides_only_the_one_gated_executor
  * the executor is built without the floor / cap                   -> test_a_max_run_rides_only_the_one_gated_executor
  * ``_check_engage_controls`` accepts a missing / malformed control -> test_a_governed_run_without_well_formed_controls_is_refused
  * the controls check moves after preflight / the lease arm         -> test_a_malformed_max_run_is_refused_before_preflight_and_the_lease_arm
"""
from __future__ import annotations

import itertools

import pytest

from framework.v2 import engage as engage_mod
from framework.v2.engage import EngagementRefused
from vigil_core import run_tier

SLUG, SEED = "l1-max-governed", "https://apme.example/"
_MAX = run_tier.engage_controls_for("max")


def _rig(monkeypatch, tmp_path) -> dict:
    """Root the run in a temporary CRUCIBLE_ROOT and replace preflight, the lease arm, the executor, the campaign and
    the profile-manifest writer with recorders. Returns the record."""
    from framework.v2.common import paths
    from framework.v2.scanner.campaign import ScanReport
    (tmp_path / paths._SENTINEL).write_text("sentinel\n")             # the engine's root marker
    monkeypatch.setenv("CRUCIBLE_ROOT", str(tmp_path))
    paths.crucible_root.cache_clear()
    rec: dict = {"calls": [], "executor": [], "campaign": [], "profile": []}

    class _Executor:
        def __init__(self, **kw):
            rec["executor"].append(kw)

        def gated_fetch(self, request):
            return {"status": 0, "body": "", "headers": [], "latency_ms": 0.0}

        def close(self):
            pass

    class _Campaign:
        def __init__(self, send, **kw):
            rec["campaign"].append(kw)

        def run(self, seed):
            return ScanReport(target=seed, pages_crawled=1)

    monkeypatch.setattr(engage_mod, "preflight", lambda slug, seed_url: rec["calls"].append("preflight"))
    monkeypatch.setattr(engage_mod, "_engage_launch_lease_precondition",
                        lambda *a, **k: rec["calls"].append("lease_arm"))
    monkeypatch.setattr(engage_mod, "HttpExecutor", _Executor)
    monkeypatch.setattr(engage_mod, "WebScanCampaign", _Campaign)
    monkeypatch.setattr(engage_mod, "browser_surfaces_if_unusable", lambda **kw: [])   # never probe a real browser
    monkeypatch.setattr(engage_mod, "_record_engagement_profile",
                        lambda rd, profile, flags, deferred: rec["profile"].append(dict(flags)))
    return rec


@pytest.mark.parametrize("arsenal,browser_xss,spa", list(itertools.product([False, True], repeat=3)))
def test_governed_tools_only_forces_every_executor_bypassing_pass_off(arsenal, browser_xss, spa):
    assert engage_mod._governed_tool_overlay(arsenal, browser_xss, spa, governed_tools_only=True) == (
        False, False, False)


@pytest.mark.parametrize("arsenal,browser_xss,spa", list(itertools.product([False, True], repeat=3)))
def test_without_governed_tools_only_the_roster_is_unchanged(arsenal, browser_xss, spa):
    assert engage_mod._governed_tool_overlay(arsenal, browser_xss, spa, governed_tools_only=False) == (
        arsenal, browser_xss, spa)


def test_a_max_run_rides_only_the_one_gated_executor(monkeypatch, tmp_path):
    # Every executor-bypassing pass is ASKED for; the governed run gets none of them: the campaign runs with the arsenal
    # (and its authorizer) and both directly-navigating browser passes OFF, the manifest records what actually ran, and
    # the ONE executor — the run's only egress — carries the engagement's single rate floor and connection cap.
    rec = _rig(monkeypatch, tmp_path)
    engage_mod.run_engagement(
        SLUG, SEED, enable_chaining=False, enable_arsenal=True, enable_browser_xss=True, enable_spa_crawl=True,
        governed_tools_only=True, per_engagement_rate_floor_s=_MAX.min_request_interval_s,
        per_engagement_connection_cap=_MAX.connection_cap)
    assert rec["calls"] == ["preflight", "lease_arm"]                 # a well-formed Max run is not refused
    assert len(rec["executor"]) == 1                                  # ONE executor for the whole engagement
    ex = rec["executor"][0]
    assert ex["per_engagement_rate_floor_s"] == pytest.approx(0.1) and ex["per_engagement_connection_cap"] == 8
    (camp,) = rec["campaign"]
    assert camp["enable_arsenal"] is False and camp["arsenal_authz"] is None
    assert camp["enable_browser_xss"] is False and camp["enable_spa_crawl"] is False
    assert camp["browser_allowed_hosts"] is None                      # no browser was armed at all
    (flags,) = rec["profile"]
    assert (flags["enable_arsenal"], flags["enable_browser_xss"], flags["enable_spa_crawl"]) == (False, False, False)


def test_a_run_without_the_max_controls_is_unchanged(monkeypatch, tmp_path):
    # Byte-identical: a non-governed run asking for the same passes keeps every one of them and builds its executor with
    # the inert floor / cap (no engagement-wide throttle beyond the posture).
    rec = _rig(monkeypatch, tmp_path)
    engage_mod.run_engagement(SLUG, SEED, enable_chaining=False, enable_arsenal=True, enable_browser_xss=True,
                              enable_spa_crawl=True)
    assert rec["calls"] == ["preflight", "lease_arm"]
    ex = rec["executor"][0]
    assert ex["per_engagement_rate_floor_s"] == 0.0 and ex["per_engagement_connection_cap"] == 0
    (camp,) = rec["campaign"]
    assert camp["enable_arsenal"] is True and callable(camp["arsenal_authz"])
    assert camp["enable_browser_xss"] is True and camp["enable_spa_crawl"] is True
    (flags,) = rec["profile"]
    assert (flags["enable_arsenal"], flags["enable_browser_xss"], flags["enable_spa_crawl"]) == (True, True, True)


@pytest.mark.parametrize("floor,cap", [
    (0.0, 8), (-0.1, 8), (float("inf"), 8), (float("nan"), 8), (True, 8), ("0.1", 8), (None, 8),
    (0.1, 0), (0.1, -8), (0.1, True), (0.1, 8.0), (0.1, "8"), (0.1, None),
])
def test_a_governed_run_without_well_formed_controls_is_refused(floor, cap):
    with pytest.raises(EngagementRefused, match="governed"):
        engage_mod._check_engage_controls(True, floor, cap)


def test_well_formed_or_non_governed_controls_pass_the_check():
    engage_mod._check_engage_controls(True, _MAX.min_request_interval_s, _MAX.connection_cap)   # the Max controls
    engage_mod._check_engage_controls(True, 2, 1)                                              # any positive pair
    for floor, cap in ((0.0, 0), ("junk", None), (float("nan"), -1)):
        engage_mod._check_engage_controls(False, floor, cap)          # a non-governed run is never checked (inert)


def test_a_malformed_max_run_is_refused_before_preflight_and_the_lease_arm(monkeypatch, tmp_path):
    # A governed run whose rate limit is missing (floor 0.0) never reaches preflight's lease arm (no single-use floor is
    # burned), never builds an executor and never runs a campaign.
    rec = _rig(monkeypatch, tmp_path)
    with pytest.raises(EngagementRefused, match="governed"):
        engage_mod.run_engagement(SLUG, SEED, enable_chaining=False, governed_tools_only=True,
                                  per_engagement_rate_floor_s=0.0, per_engagement_connection_cap=8)
    assert rec["calls"] == [] and rec["executor"] == [] and rec["campaign"] == []
