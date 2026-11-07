"""EC-7 — the ENGINE-side conformance pin for the cross-module run-tier contract.

``vigil_core.run_tier`` (the PURE sovereign leaf) emits plain strings — an engagement-profile NAME and the
model-routing lever — that the keyless engage worker feeds straight into ``run_engagement``. Those strings are
a STABLE cross-module contract: the leaf names a profile, the engine resolves it. This test lives on the ENGINE
side (it imports BOTH ``vigil_core.run_tier`` and ``framework.v2.engage``) so the contract can never silently
drift — if someone renames an ``ENGAGEMENT_PROFILES`` member, removes an ``enable_*`` kwarg, or diverges the
worker-path roster from the CLI ``--profile`` roster, a NAMED assertion here reds.

Mutation-verify targets:
  * run_tier.engage_profile_for emits a name NOT in ENGAGEMENT_PROFILES  -> test_every_run_tier_profile_is_a_real_engage_profile
  * engage.profile_kwargs returns a key that is not a run_engagement arg -> test_every_profile_kwargs_key_is_a_real_run_engagement_kwarg
  * engage.profile_kwargs diverges from the CLI resolve_profile roster   -> test_profile_kwargs_matches_the_cli_resolve_profile_roster
"""
from __future__ import annotations

import argparse
import inspect

from framework.v2 import engage
from vigil_core import run_tier as rt


def test_every_run_tier_profile_is_a_real_engage_profile():
    # The CONTRACT the run_tier leaf promises: every tier resolves to a profile the engine actually knows.
    for tier in rt.RUN_TIERS:
        name = rt.engage_profile_for(tier)
        assert name in engage.ENGAGEMENT_PROFILES, (tier, name)
    # and the fail-safe unknown-tier default is itself a real profile (the smallest-impact one).
    assert rt.engage_profile_for("nonsense") in engage.ENGAGEMENT_PROFILES


def test_every_profile_kwargs_key_is_a_real_run_engagement_kwarg():
    # profile_kwargs must only ever emit kwargs run_engagement actually accepts — else the keyless worker
    # that splats them would crash. Introspect the real signature.
    params = set(inspect.signature(engage.run_engagement).parameters)
    assert "profile" in params                       # the roster NAME is a real kwarg too (manifest record)
    for name in engage.ENGAGEMENT_PROFILES:
        for key, val in engage.profile_kwargs(name).items():
            assert key in params, (name, key)
            assert val is True                       # a profile only ever turns a flag ON (never off)


def test_surface_profile_is_byte_identical_empty():
    # "surface" (what the base "quick" tier resolves to) flips NOTHING ⇒ byte-identical to the default roster.
    assert engage.profile_kwargs("surface") == {}
    assert engage.profile_kwargs("") == {}           # the default/unknown name also flips nothing


def test_deep_and_full_rosters_are_additive_supersets():
    deep = engage.profile_kwargs("deep")
    full = engage.profile_kwargs("full")
    assert deep, "the deep roster must turn on at least one pass"
    # full ⊇ deep (full = deep + the operator-spec-gated packs whose flags exist) — additive, never removes.
    assert set(deep).issubset(set(full))
    assert "enable_access_control" in full and "enable_access_control" not in deep


def test_profile_kwargs_matches_the_cli_resolve_profile_roster():
    # The anti-DRIFT pin: profile_kwargs (worker path) and resolve_profile (CLI --profile path) MUST turn on
    # the SAME enable_* roster for every profile, since both read _PROFILE_FLAGS + _PROFILE_FLAG_KWARG. Build
    # a Namespace carrying every enable_* dest run_engagement knows (defaulted False); resolve_profile mutates
    # it, and the dests it set True must map 1:1 to profile_kwargs' keys.
    enable_params = [p for p in inspect.signature(engage.run_engagement).parameters if p.startswith("enable_")]
    dest_for_kwarg = {v: k for k, v in engage._PROFILE_FLAG_KWARG.items()}   # enable_* -> argparse dest
    for name in engage.ENGAGEMENT_PROFILES:
        ns = argparse.Namespace(**{p: False for p in enable_params})
        # map the enable_* params onto their profile dests so resolve_profile can flip them
        for kwarg, dest in dest_for_kwarg.items():
            if kwarg in enable_params:
                setattr(ns, dest, getattr(ns, kwarg))
        enabled_dests, _deferred = engage.resolve_profile(name, ns)
        cli_roster = {engage._PROFILE_FLAG_KWARG[d]: True for d in enabled_dests if d in engage._PROFILE_FLAG_KWARG}
        assert engage.profile_kwargs(name) == cli_roster, name
