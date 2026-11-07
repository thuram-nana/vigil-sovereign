"""Slice D — the owner-controlled price->entitlement catalog (the money anchor).

Load-bearing invariants:
  * the catalog is the ONLY thing that decides how much a payment grants (billing doctrine); entitlements()
    yields a valid {price_id: Entitlement} the signer consumes, and a verified webhook for a catalog price mints
    exactly the catalog's credits/plan — NEVER an on-the-wire amount;
  * the catalog is VALIDATED fail-closed (a malformed entry raises at import / in _validate), so a bad catalog
    cannot ship;
  * the public projection carries no sovereign internals beyond the display/price fields; expected_amounts()
    exposes the per-price fiat for the later checkout cross-check.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor import catalog as cat
from sigil.governor.billing import (EVENT_SUBSCRIPTION_ACTIVE, EVENT_TOPUP, BillingSigner, Entitlement,
                                     FlutterwaveBillingProvider)
from sigil.governor.catalog import CatalogEntry
from sigil.governor.metering import CreditMeter, PlanCreditLedger
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
_iss = itertools.count(1)


def test_catalog_validates_and_projects():
    ents = cat.entitlements()
    assert ents and all(isinstance(e, Entitlement) for e in ents.values())
    # every entitlement is well-formed for its kind
    for pid, e in ents.items():
        if e.kind == EVENT_TOPUP:
            assert e.credits > 0 and not e.plan_id
        else:
            assert e.plan_id and e.period_s > 0 and not e.credits
            assert e.allotment > 0 or cat.monitoring_plan(e.plan_id) is not None
    plans = cat.plans()
    assert {p["price_id"] for p in plans} == set(ents)
    assert all({"price_id", "kind", "name", "amount_minor", "currency"} <= set(p) for p in plans)
    exp = cat.expected_amounts()
    assert set(exp) == set(ents) and all(a >= 0 and len(c) == 3 for a, c in exp.values())


def test_public_projection_hides_no_secret_and_matches_kind():
    for p in cat.plans():
        assert "cred_hash" not in p and "salt" not in p
        if p["kind"] == EVENT_TOPUP:
            assert "credits" in p and "plan_id" not in p
        else:
            assert "plan_id" in p and "allotment" in p and "period_days" in p


def test_malformed_catalog_is_rejected_fail_closed():
    bad = [
        CatalogEntry("", EVENT_TOPUP, "x", 100, "USD", credits=10),                 # empty price_id
        CatalogEntry("dup", EVENT_TOPUP, "x", 100, "USD", credits=10),
        CatalogEntry("dup", EVENT_TOPUP, "y", 100, "USD", credits=10),              # duplicate id (as a pair)
        CatalogEntry("t", "nonsense_kind", "x", 100, "USD", credits=10),            # unknown kind
        CatalogEntry("t", EVENT_TOPUP, "x", -1, "USD", credits=10),                 # negative amount
        CatalogEntry("t", EVENT_TOPUP, "x", 100, "US", credits=10),                 # bad currency
        CatalogEntry("t", EVENT_TOPUP, "x", 100, "USD", credits=0),                 # topup w/o credits
        CatalogEntry("t", EVENT_TOPUP, "x", 100, "USD", credits=10, plan_id="p"),   # topup w/ plan
        CatalogEntry("s", EVENT_SUBSCRIPTION_ACTIVE, "x", 100, "USD"),              # sub w/o plan/allotment/period
        CatalogEntry("s", EVENT_SUBSCRIPTION_ACTIVE, "x", 100, "USD", plan_id="p", allotment=1, period_s=1,
                     credits=5),                                                    # sub w/ credits
        CatalogEntry("s", EVENT_SUBSCRIPTION_ACTIVE, "x", 100, "USD", plan_id="Pro", allotment=1,
                     period_s=1),                                                   # plan_id not a lowercase slug (mint-path parity, D/C2)
        CatalogEntry("s", EVENT_SUBSCRIPTION_ACTIVE, "x", 100, "USD", plan_id="p", allotment=1,
                     period_s=float("inf")),                                        # non-finite period (inf) — fail-closed (D/A1)
        CatalogEntry("s", EVENT_SUBSCRIPTION_ACTIVE, "x", 100, "USD", plan_id="p", allotment=1,
                     period_s=float("nan")),                                        # non-finite period (NaN) — fail-closed (D/A1)
        CatalogEntry("t", EVENT_TOPUP, "x", 100, "usd", credits=10),                # currency not uppercase (case, D/C2)
    ]
    # the duplicate case needs a pair; the rest each raise on their own
    assert cat._validate.__call__  # present
    with pytest.raises(ValueError):
        cat._validate((bad[1], bad[2]))                                            # duplicate
    for e in (bad[0], bad[3], bad[4], bad[5], bad[6], bad[7], bad[8], bad[9],
              bad[10], bad[11], bad[12], bad[13]):
        with pytest.raises(ValueError):
            cat._validate((e,))


def test_catalog_drives_a_real_mint_end_to_end():
    # the UNLOCK: entitlements() wired into the signer makes a verified Flutterwave top-up actually mint the
    # catalog's credits (not any on-the-wire amount).
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    w = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    subs = SubscriptionRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    plan = PlanCreditLedger(s, owner_key=OWNER, trusted_pubkey=OP)
    meter = CreditMeter(w, plan, subs)
    verified = {"42": {"id": 42, "status": "successful", "tx_ref": "vigil:acme:n1", "created_at": 100.0,
                       "amount": 999999, "meta": {"price_id": "vigil_topup_1k"}}}   # wire amount is a lie
    signer = BillingSigner(FlutterwaveBillingProvider("flw-hash", lambda t: verified.get(str(t))),
                           wallet=w, subscriptions=subs, plan=plan, catalog=cat.entitlements())
    import json
    body = json.dumps({"event": "charge.completed", "data": {"id": 42}}).encode()
    assert signer.ingest(body, "flw-hash", now=100.0) is not None
    assert w.available("acme") == 1000, "mint must be the CATALOG's 1000 credits, never the wire's 999999"
    assert meter.available("acme", now=100.0) == 1000


def test_catalog_drives_a_subscription_mint():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    w = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    subs = SubscriptionRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    plan = PlanCreditLedger(s, owner_key=OWNER, trusted_pubkey=OP)
    meter = CreditMeter(w, plan, subs)
    verified = {"7": {"id": 7, "status": "successful", "tx_ref": "vigil:acme:n1", "created_at": 100.0,
                      "payment_plan": "vigil_pro_monthly"}}
    signer = BillingSigner(FlutterwaveBillingProvider("flw-hash", lambda t: verified.get(str(t))),
                           wallet=w, subscriptions=subs, plan=plan, catalog=cat.entitlements())
    import json
    body = json.dumps({"event": "charge.completed", "data": {"id": 7}}).encode()
    assert signer.ingest(body, "flw-hash", now=100.0) is not None
    assert subs.subscription("acme").plan_id == "pro"
    assert meter.available("acme", now=200.0) == 6000        # the Pro monthly allotment from the catalog


# ==================================================================================================
# EC-7 — tiered Quick/Deep LAUNCH PRODUCTS (default-OFF; byte-identical catalog surface when off).
# ==================================================================================================

def test_launch_products_default_off_is_byte_identical(monkeypatch):
    monkeypatch.delenv("VIGIL_TIERED_PRODUCTS", raising=False)
    assert cat.launch_products() == ()                       # nothing offered
    assert cat.launch_product("vigil_launch_quick") is None
    # the EC-7 flag must not perturb the payment/pricing surface at all
    plans_off = cat.plans()
    amts_off = cat.expected_amounts()
    ents_off = cat.entitlements()
    monkeypatch.setenv("VIGIL_TIERED_PRODUCTS", "1")
    assert cat.plans() == plans_off
    assert cat.expected_amounts() == amts_off
    assert cat.entitlements() == ents_off                    # launch products are NOT payment offerings


def test_launch_products_offered_when_flag_on(monkeypatch):
    monkeypatch.setenv("VIGIL_TIERED_PRODUCTS", "1")
    prods = cat.launch_products()
    assert {p.product_id for p in prods} == {"vigil_launch_quick", "vigil_launch_deep"}
    quick = cat.launch_product("vigil_launch_quick")
    deep = cat.launch_product("vigil_launch_deep")
    assert quick.run_tier == "quick" and quick.public()["profile"] == "surface"
    assert deep.run_tier == "deep" and deep.public()["profile"] == "full"
    assert cat.launch_product("nope") is None                # unknown ⇒ None (catalog decides, never a client field)
    assert deep.units > quick.units                          # deep reserves more credits than quick


def test_launch_product_declared_tier_matches_the_units_band():
    # the load-bearing EC-7 consistency: each product's DECLARED tier equals the band-derived tier for its
    # units — so the catalog definition and the runtime (run_tier) derivation can never diverge.
    from vigil_core import run_tier
    for p in cat._LAUNCH_PRODUCTS:
        assert run_tier.run_tier_for_units(p.units) == p.run_tier, p.product_id


def test_launch_products_validate_fail_closed():
    LP = cat.LaunchProduct
    # a well-formed set validates
    cat._validate_launch_products((LP("a", "A", "quick", units=3), LP("b", "B", "deep", units=20)))
    # duplicate / empty product_id
    with pytest.raises(ValueError):
        cat._validate_launch_products((LP("a", "A", "quick", 3), LP("a", "A2", "deep", 20)))
    with pytest.raises(ValueError):
        cat._validate_launch_products((LP("", "A", "quick", 3),))
    # unknown run_tier
    with pytest.raises(ValueError):
        cat._validate_launch_products((LP("a", "A", "medium", 3),))
    # units must be a positive int (bool is rejected — a classic int-subclass footgun)
    for bad in (0, -1, True):
        with pytest.raises(ValueError):
            cat._validate_launch_products((LP("a", "A", "quick", bad),))
    # BAND MISMATCH: units 20 fall in the "deep" band but the product declares "quick" ⇒ fail-closed
    with pytest.raises(ValueError):
        cat._validate_launch_products((LP("a", "A", "quick", units=20),))
    with pytest.raises(ValueError):
        cat._validate_launch_products((LP("a", "A", "deep", units=3),))
