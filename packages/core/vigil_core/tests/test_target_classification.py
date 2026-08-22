"""W13-4 (#497) — target classification + a registered-asset store where UNKNOWN is NEVER AUTHORIZED.

These are the PURE-core proofs (stdlib only, no framework / integration): they run in the required
``vigil_core — shared integrity substrate`` CI job (``pytest packages/core/vigil_core/tests -q``).

FAILS WITHOUT THE FIX: this whole module imports ``vigil_core.target_classification``; on a tree without
W13-4 that import ERRORs and every test here fails at collection — the failure is observed on a tree
without the module, not assumed.

Each assertion pins one acceptance line of #497:
  * every target resolves to a class; UNKNOWN is asserted to be never authorized (directly + structurally);
  * a registered in-scope asset is allowed and its classification is recorded;
  * NEGATIVE CONTROLS: an unregistered/out-of-scope target is refused; a target explicitly classified
    OUT_OF_SCOPE is refused even when the scope predicate would say yes (the store is not a no-op);
  * deployment modes are enumerated and each has a test.
"""

from __future__ import annotations

import pytest

from vigil_core.target_classification import (
    AUTHORIZED_CLASSES,
    ClassificationResult,
    DeploymentMode,
    RegisteredAsset,
    RegisteredAssetStore,
    TargetClass,
    classify_target,
    is_authorized,
    normalize_target,
)


# ---------------------------------------------------------------------------------------------------------
# UNKNOWN is never authorized — asserted directly and structurally
# ---------------------------------------------------------------------------------------------------------
def test_unknown_is_never_authorized_directly():
    assert is_authorized(TargetClass.UNKNOWN) is False
    assert TargetClass.UNKNOWN not in AUTHORIZED_CLASSES


def test_no_non_authorized_class_is_authorized():
    # STRUCTURAL: exactly the four owned/authorized classes authorize; every other class — including the
    # risky PUBLIC_INTERNET / CRITICAL_INFRASTRUCTURE and the forbidden OUT_OF_SCOPE — is refused.
    authorized = {c for c in TargetClass if is_authorized(c)}
    assert authorized == {
        TargetClass.LOOPBACK,
        TargetClass.PRIVATE_NETWORK,
        TargetClass.OWN_INFRA,
        TargetClass.AUTHORIZED_THIRD_PARTY,
    }
    for refused in (
        TargetClass.PUBLIC_INTERNET,
        TargetClass.CRITICAL_INFRASTRUCTURE,
        TargetClass.OUT_OF_SCOPE,
        TargetClass.UNKNOWN,
    ):
        assert is_authorized(refused) is False


def test_every_target_resolves_to_a_class():
    # Empty / unparseable / registered / in-scope / neither — every one yields a ClassificationResult.
    store = RegisteredAssetStore([RegisteredAsset("host.test", TargetClass.OWN_INFRA)])
    scope = {"lab.test"}
    in_scope = lambda h: h in scope  # noqa: E731
    for target in ("", "   ", "host.test", "lab.test", "stranger.test", "not a url"):
        res = classify_target(target, store=store, in_scope=in_scope)
        assert isinstance(res, ClassificationResult)
        assert isinstance(res.target_class, TargetClass)
        assert res.authorized is is_authorized(res.target_class)


# ---------------------------------------------------------------------------------------------------------
# UNKNOWN-deny: an unclassified target is refused, never defaulted to authorized
# ---------------------------------------------------------------------------------------------------------
def test_unregistered_and_out_of_scope_target_is_unknown_and_refused():
    store = RegisteredAssetStore()
    res = classify_target("stranger.test", store=store, in_scope=lambda h: False)
    assert res.target_class is TargetClass.UNKNOWN
    assert res.authorized is False


def test_empty_target_is_unknown_and_refused():
    res = classify_target("", store=RegisteredAssetStore(), in_scope=lambda h: True)
    assert res.target_class is TargetClass.UNKNOWN
    assert res.authorized is False


def test_no_store_and_no_scope_is_unknown():
    # With nothing to resolve against, a target cannot be defaulted to authorized.
    res = classify_target("anything.test")
    assert res.target_class is TargetClass.UNKNOWN
    assert res.authorized is False


def test_scope_predicate_that_raises_fails_closed_to_unknown():
    def boom(_h):
        raise RuntimeError("scope source unavailable")

    res = classify_target("x.test", in_scope=boom)
    assert res.target_class is TargetClass.UNKNOWN
    assert res.authorized is False


# ---------------------------------------------------------------------------------------------------------
# A registered in-scope asset is allowed; the classification is recorded
# ---------------------------------------------------------------------------------------------------------
def test_registered_asset_is_classified_and_allowed():
    store = RegisteredAssetStore()
    store.register("https://lab.example/path", TargetClass.OWN_INFRA, note="ci lab box")
    res = classify_target("lab.example", store=store, in_scope=lambda h: False)
    assert res.target_class is TargetClass.OWN_INFRA
    assert res.authorized is True
    assert res.normalized == "lab.example"
    assert "registered asset" in res.reason and "ci lab box" in res.reason


def test_in_scope_target_is_classified_own_infra_via_the_charter_scope():
    # No store entry — resolution falls back to the charter scope (the source of truth) and derives a class.
    res = classify_target("app.owned.test", in_scope=lambda h: h == "app.owned.test")
    assert res.target_class is TargetClass.OWN_INFRA
    assert res.authorized is True
    assert "in charter scope" in res.reason


def test_in_scope_loopback_and_private_are_network_classified():
    res_lo = classify_target("127.0.0.1", in_scope=lambda h: True)
    assert res_lo.target_class is TargetClass.LOOPBACK and res_lo.authorized is True
    res_localhost = classify_target("localhost", in_scope=lambda h: True)
    assert res_localhost.target_class is TargetClass.LOOPBACK
    res_priv = classify_target("10.0.0.5", in_scope=lambda h: True)
    assert res_priv.target_class is TargetClass.PRIVATE_NETWORK and res_priv.authorized is True


# ---------------------------------------------------------------------------------------------------------
# NEGATIVE CONTROL — a classified out-of-scope target is refused (the store can DENY, not only allow)
# ---------------------------------------------------------------------------------------------------------
def test_registered_out_of_scope_target_is_refused_even_when_scope_says_yes():
    # The store is NOT a rubber stamp: registering a target OUT_OF_SCOPE refuses it, and that decision wins
    # over a permissive scope predicate — proving the registration is consulted and can deny.
    store = RegisteredAssetStore()
    store.register("forbidden.test", TargetClass.OUT_OF_SCOPE, note="explicitly forbidden")
    res = classify_target("forbidden.test", store=store, in_scope=lambda h: True)
    assert res.target_class is TargetClass.OUT_OF_SCOPE
    assert res.authorized is False


def test_registered_critical_infrastructure_is_not_auto_authorized():
    store = RegisteredAssetStore([RegisteredAsset("scada.test", TargetClass.CRITICAL_INFRASTRUCTURE)])
    res = classify_target("scada.test", store=store, in_scope=lambda h: True)
    assert res.target_class is TargetClass.CRITICAL_INFRASTRUCTURE
    assert res.authorized is False


# ---------------------------------------------------------------------------------------------------------
# normalization + store keying
# ---------------------------------------------------------------------------------------------------------
def test_normalize_target_canonicalizes_host_port_and_ipv6():
    assert normalize_target("https://Example.COM:8443/x?y=1") == "example.com"
    assert normalize_target("192.168.1.1:8080") == "192.168.1.1"
    assert normalize_target("fe80:0:0:0:0:0:0:1") == "fe80::1"
    assert normalize_target("[fe80::1]:80") == "fe80::1"
    assert normalize_target("") == ""
    assert normalize_target(None) == ""
    assert normalize_target(1234) == ""


def test_store_lookup_matches_regardless_of_target_form():
    store = RegisteredAssetStore()
    store.register("host.test", TargetClass.OWN_INFRA)
    assert store.lookup("https://Host.test:9000/path") is not None
    assert "host.test" in store
    assert store.lookup("other.test") is None
    assert "other.test" not in store
    assert len(store) == 1


def test_store_refuses_unparseable_registration():
    store = RegisteredAssetStore()
    with pytest.raises(ValueError):
        store.register("", TargetClass.OWN_INFRA)


def test_ipv6_variants_collapse_to_one_asset():
    store = RegisteredAssetStore()
    store.register("fe80:0:0:0:0:0:0:1", TargetClass.PRIVATE_NETWORK)
    assert store.lookup("[fe80::1]:443") is not None
    assert len(store) == 1


# ---------------------------------------------------------------------------------------------------------
# deployment modes — enumerated, each has a test
# ---------------------------------------------------------------------------------------------------------
def test_deployment_modes_are_enumerated():
    assert {m.value for m in DeploymentMode} == {
        "local_offline", "local_lab", "staging", "production", "reviewer",
    }
    assert len(set(DeploymentMode)) == 5


def test_deployment_mode_local_offline():
    assert DeploymentMode.LOCAL_OFFLINE.value == "local_offline"


def test_deployment_mode_local_lab():
    assert DeploymentMode.LOCAL_LAB.value == "local_lab"


def test_deployment_mode_staging():
    assert DeploymentMode.STAGING.value == "staging"


def test_deployment_mode_production():
    assert DeploymentMode.PRODUCTION.value == "production"


def test_deployment_mode_reviewer():
    assert DeploymentMode.REVIEWER.value == "reviewer"
