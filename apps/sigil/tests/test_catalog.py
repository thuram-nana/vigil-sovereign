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
            assert e.plan_id and e.allotment > 0 and e.period_s > 0 and not e.credits
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
