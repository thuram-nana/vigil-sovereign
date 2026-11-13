"""EC-7 — the RUN-TIER derivation leaf (vigil_core.run_tier).

The PURE shared leaf behind the tiered Quick/Deep launch products: a launch's run tier is DERIVED from its
already-signed ``units_reserved`` by a fixed units band (no new signed field, no snapshot bump), and the tier
maps to the engine's engagement-profile vocabulary + the EC-2a model-routing lever as a plain cross-module
contract. This pins the leaf's contract — the band, the fail-SAFE directions, the tier→profile/routing maps,
the owner-tunable boundary, and the default-OFF flag — all offline, stdlib-only, no key, no framework.

Mutation-verify targets (each neuter reds a NAMED test here):
  * flip the band compare ``u <= quick_max_units()`` to ``<``        -> test_band_boundary_is_inclusive
  * flip the except fallback ``return "quick"`` to ``"deep"``        -> test_nonpositive_and_malformed_units_are_quick
  * change the ``engage_profile_for`` default off "surface"          -> test_unknown_tier_profile_is_surface
  * change the ``routing_enabled_for`` default off False             -> test_unknown_tier_routing_is_off_fail_toward_capable
  * drop the ``v >= 1`` fallback in quick_max_units                  -> test_quick_max_units_bad_env_falls_back
  * widen/narrow the tiered_products flag affirmative set            -> test_tiered_products_enabled_affirmative_set
"""
from __future__ import annotations

import pytest

from vigil_core import run_tier as rt


def test_run_tiers_vocabulary_is_fixed():
    assert rt.RUN_TIERS == ("quick", "deep")


# ---- the units band -----------------------------------------------------------------------------------

def test_band_boundary_is_inclusive():
    # units <= quick_max_units ⇒ quick; strictly above ⇒ deep. The boundary itself (10) is quick.
    assert rt.quick_max_units() == 10
    assert rt.run_tier_for_units(10) == "quick"      # AT the boundary ⇒ quick (inclusive)
    assert rt.run_tier_for_units(11) == "deep"       # one above ⇒ deep
    assert rt.run_tier_for_units(9) == "quick"
    assert rt.run_tier_for_units(10_000) == "deep"


def test_nonpositive_and_malformed_units_are_quick():
    # fail-SAFE: a bad / non-positive units resolves to the SMALLER-impact, cheaper "quick" — a malformed
    # launch never silently escalates to the fuller/capable/large-budget "deep".
    for bad in (0, -1, -999, None, "x", 1.9, object()):
        assert rt.run_tier_for_units(bad) == "quick", bad
    assert rt.run_tier_for_units(1) == "quick"       # the smallest positive is still quick


def test_quick_max_units_env_override(monkeypatch):
    monkeypatch.setenv("VIGIL_QUICK_MAX_UNITS", "5")
    assert rt.quick_max_units() == 5
    assert rt.run_tier_for_units(5) == "quick"
    assert rt.run_tier_for_units(6) == "deep"


def test_quick_max_units_bad_env_falls_back(monkeypatch):
    # a bad / non-positive override falls back to the placeholder — never a 0/negative band that would make
    # EVERY run classify "deep" (the most-expensive tier). Fail-safe toward the cheaper default.
    for bad in ("", "nope", "0", "-3", "2.5"):
        monkeypatch.setenv("VIGIL_QUICK_MAX_UNITS", bad)
        assert rt.quick_max_units() == 10, bad


# ---- tier → engagement profile (the engine's surface|deep|full vocabulary) -----------------------------

def test_tier_to_engage_profile():
    assert rt.engage_profile_for("quick") == "surface"   # quick = the low-impact default roster
    assert rt.engage_profile_for("deep") == "full"       # deep = the full roster


def test_unknown_tier_profile_is_surface():
    # fail-SAFE: an unknown tier ⇒ the SMALLEST-impact roster, never silently the fullest scan on the target.
    for bad in ("", "quickk", "DEEP", None, "full"):
        assert rt.engage_profile_for(bad) == "surface", bad


def test_profile_for_units_composes_band_and_map():
    assert rt.profile_for_units(3) == "surface"      # 3 ⇒ quick ⇒ surface
    assert rt.profile_for_units(20) == "full"        # 20 ⇒ deep ⇒ full
    assert rt.profile_for_units(0) == "surface"      # fail-safe ⇒ quick ⇒ surface


# ---- tier → EC-2a model-routing lever ------------------------------------------------------------------

def test_tier_to_routing_lever():
    assert rt.routing_enabled_for("quick") is True   # quick ⇒ routing ON (the cheaper per-binding tiers)
    assert rt.routing_enabled_for("deep") is False   # deep ⇒ routing OFF (every binding on its capable model)


def test_unknown_tier_routing_is_off_fail_toward_capable():
    # fail-SAFE: an unknown tier ⇒ routing OFF ⇒ capable models — the engine's own fail-toward-capable
    # doctrine; a typo never silently downgrades model quality.
    for bad in ("", "quickk", "DEEP", None):
        assert rt.routing_enabled_for(bad) is False, bad


# ---- the default-OFF EC-7 flag (shared by BOTH planes) -------------------------------------------------

def test_tiered_products_enabled_default_off(monkeypatch):
    monkeypatch.delenv("VIGIL_TIERED_PRODUCTS", raising=False)
    assert rt.tiered_products_enabled() is False


def test_tiered_products_enabled_affirmative_set():
    for on in ("1", "true", "TRUE", "yes", "on", "enabled", " on "):
        assert rt.tiered_products_enabled({"VIGIL_TIERED_PRODUCTS": on}) is True, on
    for off in ("", "0", "no", "off", "disabled", "2", "y"):
        assert rt.tiered_products_enabled({"VIGIL_TIERED_PRODUCTS": off}) is False, off


def test_tiered_products_enabled_reads_process_env_by_default(monkeypatch):
    monkeypatch.setenv("VIGIL_TIERED_PRODUCTS", "yes")
    assert rt.tiered_products_enabled() is True


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


def test_each_tier_pins_its_effort_and_an_unknown_tier_never_escalates():
    """PRICING M1c: Quick = high, Deep = xhigh (design §2.2); an unknown tier gets the quick tier's effort."""
    assert rt.effort_for("quick") == "high" and rt.effort_for("deep") == "xhigh"
    assert rt.effort_for("bogus") == "high" and rt.effort_for("") == "high"
    assert set(rt.RUN_TIERS) <= set(rt._EFFORT)
