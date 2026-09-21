"""
Slice 0.2 — the engagement PROFILE flag-expansion + the runtime browser gate.

``engage --profile {surface,deep,full}`` is a PURE convenience: it flips EXISTING ``enable_*`` opt-in flags
ON, adds NO oracle, relaxes NO gate, and fabricates NO finding. When a browser pass is enabled but the
headless browser is not USABLE at runtime (installed != usable), the browser-dependent surfaces are recorded
INCONCLUSIVE (never CLEAN, never a silent skip) via the SAME framework-owned ``_inconclusive.json`` mechanism
the fusion pass uses.

Proven here:
  (a) ``--profile surface`` leaves the enabled-flag set IDENTICAL to today's default (no behaviour drift),
      both as a pure mapping and through the real ``main`` → ``run_engagement`` wiring.
  (b) ``--profile deep`` flips EXACTLY {domxss, browser_xss, sso, graphql_dos} (and ``full`` additionally
      access_control), touches nothing else, and the resolved profile + roster are recorded in the manifest.
  (c) a deep/full run whose ``browser_usable()`` (the real capability probe) returns False records the
      browser surfaces as INCONCLUSIVE — present + coverage-incomplete, NOT clean and NOT silently absent —
      and MERGES with (never clobbers) any fusion surfaces already on disk.

FAIL-BEFORE / PASS-AFTER: revert ``resolve_profile`` and (a)/(b) break; revert the browser gate persist and
(c) breaks (the artifact is never produced, so a browserless run would read CLEAN).
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from framework.v2 import engage as engage_mod
from framework.v2 import inconclusive_manifest as im
from framework.v2 import profile_manifest
from framework.v2.engage import (
    EngagementRefused,
    browser_surfaces_if_unusable,
    persist_browser_inconclusive,
    persist_seed_unreachable_inconclusive,
    resolve_profile,
    seed_unreachable_surface,
)


# The roster dests the CLI exposes (store_true, default False). enable_oob has no CLI flag (default ON).
_ROSTER_DESTS = ("domxss", "browser_xss", "spa", "sso", "graphql_dos", "access_control",
                 "arsenal", "recon", "library")


def _roster_args() -> argparse.Namespace:
    """A namespace mirroring the CLI roster flags, all at their store_true default (False)."""
    return argparse.Namespace(**{d: False for d in _ROSTER_DESTS})


# ---------------------------------------------------------------------------
# (a) surface = today's default roster (no drift), as a pure mapping
# ---------------------------------------------------------------------------


def test_surface_flips_nothing_and_defers_nothing() -> None:
    args = _roster_args()
    enabled, deferred = resolve_profile("surface", args)
    assert enabled == []
    assert deferred == []
    # every roster flag is untouched → identical to today's default
    assert all(getattr(args, d) is False for d in _ROSTER_DESTS)


# ---------------------------------------------------------------------------
# (b) deep / full flip EXACTLY the intended existing flags, nothing else
# ---------------------------------------------------------------------------


def test_deep_flips_exactly_the_intended_flags() -> None:
    args = _roster_args()
    enabled, deferred = resolve_profile("deep", args)
    assert set(enabled) == {"domxss", "browser_xss", "sso", "graphql_dos"}
    # the intended flags are ON …
    assert args.domxss and args.browser_xss and args.sso and args.graphql_dos
    # … and NOTHING else moved (no access_control / arsenal / recon / library / spa)
    assert not any(getattr(args, d) for d in ("access_control", "arsenal", "recon", "library", "spa"))
    # plan-named packs with no flag yet are reported deferred, never invented
    assert deferred == ["time_based_sqli", "nosqli", "ldap", "xpath"]


def test_full_is_deep_plus_access_control() -> None:
    args = _roster_args()
    enabled, deferred = resolve_profile("full", args)
    assert set(enabled) == {"domxss", "browser_xss", "sso", "graphql_dos", "access_control"}
    assert args.access_control is True
    assert not any(getattr(args, d) for d in ("arsenal", "recon", "library", "spa"))
    assert deferred == ["time_based_sqli", "nosqli", "ldap", "xpath", "bizlogic", "race"]


def test_profile_only_adds_never_removes_an_explicit_flag() -> None:
    # an explicit --arsenal survives 'surface' (which flips nothing); the profile only ever ADDS.
    args = _roster_args()
    args.arsenal = True
    resolve_profile("surface", args)
    assert args.arsenal is True


def test_deferred_packs_helper_matches_the_table() -> None:
    assert engage_mod._profile_deferred_packs("surface") == []
    assert engage_mod._profile_deferred_packs("deep") == ["time_based_sqli", "nosqli", "ldap", "xpath"]


# ---------------------------------------------------------------------------
# (b) the resolved profile + roster are RECORDED in the run-dir manifest
# ---------------------------------------------------------------------------


def test_profile_manifest_records_resolved_roster(tmp_path: Path) -> None:
    rd = tmp_path / "run"
    # exactly what run_engagement records after resolve_profile('deep', …) flips the flags
    engage_mod._record_engagement_profile(str(rd), "deep", {
        "enable_domxss": True, "enable_browser_xss": True, "enable_sso": True,
        "enable_graphql_dos": True, "enable_access_control": False, "enable_arsenal": False,
        "enable_oob": True, "use_library": False,
    }, engage_mod._profile_deferred_packs("deep"))
    pm = profile_manifest.read_profile_manifest(str(rd))
    assert pm["present"] is True
    assert pm["profile"] == "deep"
    # the exact resolved roster is recorded (enabled_flags = the True flags, sorted)
    assert pm["enabled_flags"] == [
        "enable_browser_xss", "enable_domxss", "enable_graphql_dos", "enable_oob", "enable_sso"]
    assert pm["flags"]["enable_access_control"] is False
    assert pm["deferred_packs"] == ["ldap", "nosqli", "time_based_sqli", "xpath"]


def test_profile_manifest_is_deterministic(tmp_path: Path) -> None:
    rd = tmp_path / "run"
    flags = {"enable_browser_xss": True, "enable_domxss": True, "enable_oob": True}
    assert profile_manifest.write_profile_manifest(str(rd), "deep", flags, ["ldap"]) is True
    first = (rd / profile_manifest.PROFILE_ARTIFACT).read_bytes()
    # a differently-ordered dict + deferred list produces byte-identical output
    profile_manifest.write_profile_manifest(
        str(rd), "deep", dict(reversed(list(flags.items()))), ["ldap"])
    assert (rd / profile_manifest.PROFILE_ARTIFACT).read_bytes() == first


def test_profile_manifest_noop_without_run_dir() -> None:
    assert profile_manifest.write_profile_manifest(None, "deep", {"enable_domxss": True}) is False
    assert profile_manifest.read_profile_manifest(None)["present"] is False


# ---------------------------------------------------------------------------
# (c) browserless browser pass → INCONCLUSIVE (never CLEAN, never silently absent)
# ---------------------------------------------------------------------------


def test_browser_gate_returns_surfaces_when_unusable() -> None:
    s = browser_surfaces_if_unusable(
        enable_browser_xss=True, enable_spa_crawl=True, usable_check=lambda: False)
    assert s == [("browser_xss", "headless_browser_unusable"),
                 ("spa_crawl", "headless_browser_unusable")]


def test_browser_gate_is_silent_when_usable_or_disabled() -> None:
    # browser usable → the passes run and adjudicate per the oracle; nothing recorded
    assert browser_surfaces_if_unusable(
        enable_browser_xss=True, enable_spa_crawl=False, usable_check=lambda: True) == []
    # no browser pass enabled → nothing to gate (byte-identical default path)
    assert browser_surfaces_if_unusable(
        enable_browser_xss=False, enable_spa_crawl=False, usable_check=lambda: False) == []


def test_browser_gate_default_check_uses_the_real_probe(monkeypatch) -> None:
    # with no explicit usable_check, the gate consults the real _headless_browser_usable probe.
    monkeypatch.setattr(engage_mod, "_headless_browser_usable", lambda: False)
    s = browser_surfaces_if_unusable(enable_browser_xss=True, enable_spa_crawl=False)
    assert s == [("browser_xss", "headless_browser_unusable")]


def test_headless_probe_gates_on_browser_usable(monkeypatch) -> None:
    """The slice's exact wording: when scanner.browser.browser_usable() returns False, the runtime probe
    is False (so the browser surfaces become INCONCLUSIVE) — cdp is not even consulted."""
    from framework.v2.scanner import browser as browser_mod
    monkeypatch.setattr(browser_mod, "browser_usable", lambda *a, **k: False)
    assert engage_mod._headless_browser_usable() is False


def test_browserless_run_records_inconclusive_not_clean(tmp_path: Path) -> None:
    """The core invariant: a deep/full run whose browser is NOT usable records the browser surface as
    INCONCLUSIVE — present + coverage-incomplete — NOT clean and NOT silently absent."""
    rd = tmp_path / "run"
    surfaces = browser_surfaces_if_unusable(
        enable_browser_xss=True, enable_spa_crawl=False, usable_check=lambda: False)
    assert persist_browser_inconclusive(surfaces, run_dir=str(rd)) is True
    doc = im.read_manifest(str(rd))
    assert doc["coverage_incomplete"] is True                 # NOT clean
    assert doc["present"] is True                             # NOT silently absent
    assert ("browser_xss", "headless_browser_unusable") in [
        (s["sensor"], s["missing_prerequisite"]) for s in doc["surfaces"]]


def test_persist_is_noop_when_usable(tmp_path: Path) -> None:
    rd = tmp_path / "run"
    # usable browser → empty surface list → no artifact (a browser-capable run is byte-identical)
    surfaces = browser_surfaces_if_unusable(
        enable_browser_xss=True, enable_spa_crawl=False, usable_check=lambda: True)
    assert persist_browser_inconclusive(surfaces, run_dir=str(rd)) is False
    assert not (rd / im.INCONCLUSIVE_ARTIFACT).exists()


def test_browser_persist_merges_and_never_clobbers_fusion(tmp_path: Path) -> None:
    """The browser gate persists LAST; it must PRESERVE fusion surfaces already on disk (a clobber would
    silently drop the fusion coverage gap), keeping each existing surface's count."""
    rd = tmp_path / "run"
    im.write_manifest(str(rd), [("cloud_live", "no aws creds"), ("cloud_live", "no aws creds")])
    surfaces = browser_surfaces_if_unusable(
        enable_browser_xss=True, enable_spa_crawl=False, usable_check=lambda: False)
    assert persist_browser_inconclusive(surfaces, run_dir=str(rd)) is True
    got = {(s["sensor"], s["missing_prerequisite"]): s["count"] for s in im.read_manifest(str(rd))["surfaces"]}
    assert got == {("cloud_live", "no aws creds"): 2, ("browser_xss", "headless_browser_unusable"): 1}


# ---------------------------------------------------------------------------
# (a)/(b) end-to-end through the REAL `main` → `run_engagement` wiring
# ---------------------------------------------------------------------------


@pytest.fixture
def captured_run(monkeypatch):
    """Stub run_engagement to CAPTURE its kwargs then refuse (so main returns 2 without a real scan)."""
    captured: dict = {}

    def _stub(*a, **k):
        captured["args"] = a
        captured.update(k)
        raise EngagementRefused("stub — captured the roster, no traffic")

    monkeypatch.setattr(engage_mod, "run_engagement", _stub)
    return captured


def test_main_surface_default_matches_no_profile(captured_run) -> None:
    assert engage_mod.main(["slug", "http://127.0.0.1/"]) == 2
    base = {k: captured_run.get(k) for k in (
        "enable_domxss", "enable_browser_xss", "enable_sso", "enable_graphql_dos",
        "enable_access_control", "enable_arsenal", "enable_recon", "use_library")}
    # today's default roster: every opt-in pack OFF
    assert base == {k: False for k in base}
    assert captured_run.get("profile") == "surface"


def test_main_deep_flips_exactly_the_intended_enable_kwargs(captured_run) -> None:
    assert engage_mod.main(["slug", "http://127.0.0.1/", "--profile", "deep"]) == 2
    assert captured_run["profile"] == "deep"
    assert captured_run["enable_domxss"] is True
    assert captured_run["enable_browser_xss"] is True
    assert captured_run["enable_sso"] is True
    assert captured_run["enable_graphql_dos"] is True
    # nothing outside the deep set moved
    assert captured_run["enable_access_control"] is False
    assert captured_run["enable_arsenal"] is False
    assert captured_run["enable_recon"] is False
    assert captured_run["use_library"] is False


def test_main_full_adds_access_control(captured_run) -> None:
    assert engage_mod.main(["slug", "http://127.0.0.1/", "--profile", "full"]) == 2
    assert captured_run["profile"] == "full"
    assert captured_run["enable_access_control"] is True
    assert captured_run["enable_browser_xss"] is True


# ---------------------------------------------------------------------------
# #799 — a dead/wrong-port seed is recorded INCONCLUSIVE (never a clean 1-page run)
# ---------------------------------------------------------------------------


def test_seed_unreachable_surface_names_the_port() -> None:
    sensor, note = seed_unreachable_surface("http://127.0.0.1:19010/")
    assert sensor == "seed_reachability"
    assert "127.0.0.1:19010" in note and "unreachable" in note.lower()
    # a default-port https seed still names the resolved port
    _, note2 = seed_unreachable_surface("https://example.test/app")
    assert "example.test:443" in note2


def test_persist_seed_unreachable_records_inconclusive_not_clean(tmp_path: Path) -> None:
    rd = tmp_path / "run"
    assert persist_seed_unreachable_inconclusive("http://127.0.0.1:19010/", run_dir=str(rd)) is True
    doc = im.read_manifest(str(rd))
    assert doc["coverage_incomplete"] is True and doc["present"] is True
    assert "seed_reachability" in [s["sensor"] for s in doc["surfaces"]]


def test_persist_seed_unreachable_noop_without_run_dir() -> None:
    assert persist_seed_unreachable_inconclusive("http://127.0.0.1:19010/", run_dir=None) is False


def test_persist_seed_unreachable_merges_never_clobbers(tmp_path: Path) -> None:
    """The seed-unreachable surface must PRESERVE any fusion/browser surface already on disk."""
    rd = tmp_path / "run"
    im.write_manifest(str(rd), [("cloud_live", "no aws creds")])
    assert persist_seed_unreachable_inconclusive("http://127.0.0.1:19010/", run_dir=str(rd)) is True
    sensors = [s["sensor"] for s in im.read_manifest(str(rd))["surfaces"]]
    assert "cloud_live" in sensors and "seed_reachability" in sensors
