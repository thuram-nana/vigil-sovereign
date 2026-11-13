"""EC-6 — the operator billing<->cost MARGIN reconciliation (ui/margin.py) + its owner-tier read route.

Load-bearing invariants a false-green would break (each has a mutation-verify guard, see the MUTATION-VERIFY
notes on the asserts):
  * MARGIN FORMULA: margin = billed_revenue - cost, cost = committed_tokens * rate // 1_000_000 (integer floor);
  * NOT-CONFIGURED FAIL-CLOSED: an unset (None) cost rate => cost/margin are None (never a fabricated 0), while
    committed tokens + billed revenue are still shown;
  * DOUBLE-COUNT GUARD: the 'payment' kind (a postpaid receipt — money IN) is the COLLECTED axis, never revenue;
  * IN-FLIGHT held OUT of committed cost / margin;
  * READ-ONLY: the projection appends nothing (store.next_seq unchanged);
  * OPERATOR-ONLY: the /api/billing/margin read is owner-tier (manage_billing) — no per-org member can read it —
    and behind VIGIL_MARGIN_DASHBOARD_ENABLED (default OFF => 404).

Cost records are seeded DIRECTLY here (reserve/settle) so the tests do not depend on EC-5's launch-gate wiring.
"""
from __future__ import annotations

import contextlib
import json
import math
import os
import tempfile
import threading
import time
import urllib.error
import urllib.request
from fractions import Fraction

from sigil.governor import catalog
from sigil.governor.authn import signed_payload
from sigil.governor.cost_ledger import COST_SETTLE_SIGNAL, CostEnvelopeLedger
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.invoices import InvoiceRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui import margin
from sigil.ui.server import build_server

TOKEN = "owner-shared-token-xyz789"
RATE = 300          # micro-minor per token: cost_minor = committed_tokens * 300 // 1_000_000 (clean integers)
TEST_M = Fraction(1, 7)   # a test-only target margin (not a pricing number): cost 1200 -> target 1200 / (6/7) = 1400


@contextlib.contextmanager
def _env(**kv):
    """Set/clear env vars for the block, restoring the prior values (so a test never leaks a rate/flag)."""
    old = {k: os.environ.get(k) for k in kv}
    try:
        for k, v in kv.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _store():
    path = tempfile.mktemp(suffix=".jsonl")
    SpineStore(path).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    return SpineStore(path)


def _seed_acme(store, owner):
    """One org 'acme' with billed revenue (subscription+topup+postpaid) + a postpaid PAYMENT receipt, SETTLED
    cost (4,000,000 tok committed) and an in-flight RESERVE (1,000,000 tok, unsettled). All owner-signed."""
    orgs = OrgRegistry(store, owner_key=owner)
    inv = InvoiceRegistry(store, owner_key=owner)
    cost = CostEnvelopeLedger(store, owner_key=owner)
    it = iter(range(1, 100_000))
    orgs.create_org("acme", "Acme Corp", owner="owner", issued_at=float(next(it)))
    inv.record("acme", invoice_id="a_sub", kind="subscription", price_id="pro", amount_minor=9900,
               currency="USD", credits=6000, period_start=0.0, period_end=1000.0, issued_at=100.0)
    inv.record("acme", invoice_id="a_top", kind="topup", price_id="t", amount_minor=1000, currency="USD",
               credits=1000, issued_at=200.0)
    inv.record("acme", invoice_id="a_pp", kind="postpaid", price_id="postpaid_arrears", amount_minor=500,
               currency="USD", credits=500, period_start=0.0, period_end=1000.0, issued_at=300.0)
    # a PAYMENT receipt against the postpaid invoice — money IN (collected), NEVER revenue (double-count guard).
    inv.record("acme", invoice_id="pay:a_pp", kind="payment", price_id="postpaid_payment", amount_minor=500,
               currency="USD", credits=500, issued_at=400.0)
    cost.settle("acme", 4_000_000, entry_id="settle-cost:runA:n1", issued_at=150.0)      # committed
    cost.reserve("acme", 1_000_000, entry_id="reserve-cost:runB:n2", issued_at=500.0)    # in-flight (no settle)


# ---- the owner-input catalog accessors (additive, default-UNSET) -------------------------------------
def test_catalog_cost_rate_accessors_default_none_and_env_override():
    with _env(VIGIL_COST_RATE_MICRO_MINOR_PER_TOKEN=None):
        assert catalog.cost_rate_micro_minor_per_token() is None     # PLACEHOLDER default: not configured
    with _env(VIGIL_COST_RATE_MICRO_MINOR_PER_TOKEN="300"):
        assert catalog.cost_rate_micro_minor_per_token() == 300
    with _env(VIGIL_COST_RATE_MICRO_MINOR_PER_TOKEN="-5"):
        assert catalog.cost_rate_micro_minor_per_token() is None     # negative/junk -> None (fail-closed)
    with _env(VIGIL_COST_RATE_MICRO_MINOR_PER_TOKEN="junk"):
        assert catalog.cost_rate_micro_minor_per_token() is None
    # ONE pricing number: the catalog no longer carries a target multiplier (the target line comes from the
    # target margin, vigil_core.model_metering.target_margin).
    assert not hasattr(catalog, "margin_multiplier_k")
    # ADDITIVE: the new accessors do not perturb the existing pricing surface (byte-identical when unset).
    assert isinstance(catalog.plans(), list) and catalog.postpaid_per_credit_minor() == 1


# ---- per-tenant margin math when the cost rate IS configured -----------------------------------------
def test_margin_math_per_tenant_configured():
    store = _store()
    owner = ensure_owner_keypair()
    _seed_acme(store, owner)
    ov = margin.margin_overview(store, cost_rate=RATE, target_margin=TEST_M)
    assert ov["rate_configured"] is True and ov["cost_status"] == "configured"
    assert ov["target_margin_set"] is True and ov["target_margin_issue"] is None
    assert ov["target_margin_basis"].startswith("metered AI cost only")
    t = next(x for x in ov["tenants"] if x["org_id"] == "acme")
    assert t["name"] == "Acme Corp"
    # revenue basis = {subscription, topup, postpaid}, PAYMENT excluded (collected axis).
    assert t["revenue_by_kind"] == {"subscription": 9900, "topup": 1000, "postpaid": 500}
    assert t["billed_revenue_minor"] == 11400
    assert t["collected_minor"] == 500                       # the payment receipt — collected, not revenue
    # IN-FLIGHT held OUT: committed is the SETTLED 4,000,000 only (not 5,000,000).  MUTATION-VERIFY (in-flight).
    assert t["committed_tokens"] == 4_000_000 and t["in_flight_tokens"] == 1_000_000
    # cost = committed_tokens * rate // 1_000_000 = 4_000_000 * 300 // 1_000_000 = 1200 (NOT 1500 from +in-flight).
    assert t["cost_minor"] == 1200
    # margin = billed - cost = 11400 - 1200 = 10200.  MUTATION-VERIFY (the margin formula).
    assert t["margin_minor"] == 10200
    assert t["margin_pct"] == round(10200 / 11400 * 100, 2)
    # display target = cost / (1 - m) = 1200 / (6/7) = 1400; never the actual margin.  MUTATION-VERIFY.
    assert t["target_revenue_minor"] == 1400
    assert t["currency"] == "USD"
    # totals reconcile.
    assert ov["totals"] == {"tenant_count": 1, "committed_tokens": 4_000_000, "in_flight_tokens": 1_000_000,
                            "billed_revenue_minor": 11400, "collected_minor": 500, "cost_minor": 1200,
                            "margin_minor": 10200, "margin_pct": round(10200 / 11400 * 100, 2)}


def test_margin_per_period_splits_two_periods():
    store = _store()
    owner = ensure_owner_keypair()
    orgs = OrgRegistry(store, owner_key=owner)
    inv = InvoiceRegistry(store, owner_key=owner)
    cost = CostEnvelopeLedger(store, owner_key=owner)
    it = iter(range(1, 100_000))
    orgs.create_org("acme", "Acme Corp", owner="owner", issued_at=float(next(it)))
    inv.record("acme", invoice_id="s1", kind="subscription", price_id="pro", amount_minor=10000,
               currency="USD", credits=6000, period_start=0.0, period_end=1000.0, issued_at=100.0)
    inv.record("acme", invoice_id="s2", kind="subscription", price_id="pro", amount_minor=20000,
               currency="USD", credits=6000, period_start=1000.0, period_end=2000.0, issued_at=1100.0)
    cost.settle("acme", 1_000_000, entry_id="settle-cost:a:1", issued_at=500.0)    # period 1 (issued_at in [0,1000))
    cost.settle("acme", 3_000_000, entry_id="settle-cost:b:2", issued_at=1500.0)   # period 2 (in [1000,2000))
    ov = margin.margin_overview(store, cost_rate=RATE)
    t = next(x for x in ov["tenants"] if x["org_id"] == "acme")
    periods = {p["period_start"]: p for p in t["periods"]}
    assert set(periods) == {0.0, 1000.0}
    p1, p2 = periods[0.0], periods[1000.0]
    assert (p1["billed_revenue_minor"], p1["committed_tokens"], p1["cost_minor"], p1["margin_minor"]) == \
        (10000, 1_000_000, 300, 9700)
    assert (p2["billed_revenue_minor"], p2["committed_tokens"], p2["cost_minor"], p2["margin_minor"]) == \
        (20000, 3_000_000, 900, 19100)
    # the periods reconcile to the lifetime per-tenant total (settled cost attributed by settle issued_at).
    assert t["committed_tokens"] == 4_000_000 and t["cost_minor"] == 1200
    assert sum(p["committed_tokens"] for p in t["periods"]) == t["committed_tokens"]


def test_payment_kind_excluded_from_revenue_double_count_guard():
    # A postpaid invoice + its payment receipt: billed counts the postpaid ONCE; collected counts the payment;
    # margin uses billed. Including 'payment' in revenue would double it to 10000.  MUTATION-VERIFY (double-count).
    store = _store()
    owner = ensure_owner_keypair()
    orgs = OrgRegistry(store, owner_key=owner)
    inv = InvoiceRegistry(store, owner_key=owner)
    it = iter(range(1, 100_000))
    orgs.create_org("zz", "ZZ Inc", owner="owner", issued_at=float(next(it)))
    inv.record("zz", invoice_id="pp", kind="postpaid", price_id="postpaid_arrears", amount_minor=5000,
               currency="USD", credits=5000, period_start=0.0, period_end=100.0, issued_at=10.0)
    inv.record("zz", invoice_id="pay:pp", kind="payment", price_id="postpaid_payment", amount_minor=5000,
               currency="USD", credits=5000, issued_at=20.0)
    ov = margin.margin_overview(store, cost_rate=RATE)
    t = next(x for x in ov["tenants"] if x["org_id"] == "zz")
    assert t["billed_revenue_minor"] == 5000 and t["revenue_by_kind"]["postpaid"] == 5000
    assert t["collected_minor"] == 5000
    assert ov["totals"]["billed_revenue_minor"] == 5000 and ov["totals"]["collected_minor"] == 5000


# ---- the NOT-CONFIGURED fail-closed path (never a fabricated margin) ---------------------------------
def test_not_configured_shows_tokens_and_revenue_but_no_fabricated_margin():
    store = _store()
    owner = ensure_owner_keypair()
    _seed_acme(store, owner)
    ov = margin.margin_overview(store, cost_rate=None)       # rate UNSET
    assert ov["rate_configured"] is False and ov["cost_status"] == "not configured"
    assert ov["cost_rate_micro_minor_per_token"] is None
    t = next(x for x in ov["tenants"] if x["org_id"] == "acme")
    # cost/margin are None (NOT 0, NOT fabricated).  MUTATION-VERIFY (the not-configured guard).
    assert t["cost_minor"] is None and t["margin_minor"] is None and t["margin_pct"] is None
    assert t["target_revenue_minor"] is None and t["cost_status"] == "not configured"
    # ...yet committed tokens + billed revenue ARE still shown (what IS reconcilable).
    assert t["committed_tokens"] == 4_000_000 and t["billed_revenue_minor"] == 11400
    assert t["collected_minor"] == 500 and t["in_flight_tokens"] == 1_000_000
    # per-period rows carry None cost/margin too (never a fabricated 0), with revenue still bucketed.
    assert all(p["cost_minor"] is None and p["margin_minor"] is None for p in t["periods"])
    assert sum(p["billed_revenue_minor"] for p in t["periods"]) == 11400
    assert ov["totals"]["cost_minor"] is None and ov["totals"]["margin_minor"] is None


def test_margin_overview_defaults_to_unconfigured_catalog():
    # With no cost rate set in the owner catalog (the shipped default), the projection reads NOT CONFIGURED
    # straight from catalog.cost_rate_micro_minor_per_token() — the money-anchor default, no fabricated number.
    store = _store()
    owner = ensure_owner_keypair()
    _seed_acme(store, owner)
    with _env(VIGIL_COST_RATE_MICRO_MINOR_PER_TOKEN=None, VIGIL_BILLING_TARGET_MARGIN=None):
        ov = margin.margin_overview(store)                   # read the catalog (no override)
    assert ov["rate_configured"] is False
    assert all(t["cost_minor"] is None for t in ov["tenants"])
    assert ov["target_margin_set"] is False and "VIGIL_BILLING_TARGET_MARGIN is not set" in ov["target_margin_issue"]
    assert all(t["target_revenue_minor"] is None for t in ov["tenants"])


# ---- the ONE pricing number: the target line comes from the target margin ---------------------------
def test_target_revenue_is_cost_over_one_minus_margin_rounded_up():
    # 1003 / (2/3) = 1504.5 -> 1505: rounded UP (the charge's direction), not to even and not down.
    assert margin._target_revenue(1003, Fraction(1, 3)) == 1505
    assert margin._target_revenue(1200, TEST_M) == 1400                  # exact: no rounding
    # a small fractional part still rounds up (half-up rounding would give the lower value here)
    exact = Fraction(1201) / (1 - TEST_M)
    assert exact - int(exact) < Fraction(1, 2) and margin._target_revenue(1201, TEST_M) == int(exact) + 1
    assert margin._target_revenue(0, TEST_M) == 0


def test_target_line_reads_the_deploy_margin_and_never_carries_its_value():
    store = _store()
    owner = ensure_owner_keypair()
    _seed_acme(store, owner)
    decoy = "0." + "1" * 6                                     # a test value, assembled at run time
    with _env(VIGIL_BILLING_TARGET_MARGIN=decoy, VIGIL_BILLING_MARKUP_K=None, VIGIL_MARGIN_MULTIPLIER_K=None):
        ov = margin.margin_overview(store, cost_rate=RATE)
    t = next(x for x in ov["tenants"] if x["org_id"] == "acme")
    assert ov["target_margin_set"] is True and ov["target_margin_issue"] is None
    assert t["target_revenue_minor"] == math.ceil(Fraction(1200) / (1 - Fraction(decoy)))
    body = json.dumps(ov)                                       # a Fraction in the payload would not serialise
    assert decoy not in body and "1" * 6 not in body
    m = Fraction(decoy)                                         # nor any other form of it: percent, markup
    for form in (str(float(m * 100)), str(float(1 / (1 - m))), str(1 / (1 - m)), str(m)):
        assert form not in body, form
    # the payload's shape is pinned: a new margin-derived field cannot appear unnoticed
    assert set(ov) == {"rate_configured", "cost_status", "cost_rate_micro_minor_per_token", "target_margin_set",
                       "target_margin_basis", "target_margin_issue", "cost_basis", "currency", "tenants", "totals"}
    assert "estimate" in ov["cost_basis"] and "not metered AI cost" in ov["cost_basis"]


def test_a_retired_pricing_setting_removes_the_target_line_with_the_billing_refusal():
    store = _store()
    owner = ensure_owner_keypair()
    _seed_acme(store, owner)
    decoy = "0." + "1" * 6
    for name in ("VIGIL_BILLING_MARKUP_K", "VIGIL_MARGIN_MULTIPLIER_K"):
        others = {n: None for n in ("VIGIL_BILLING_MARKUP_K", "VIGIL_MARGIN_MULTIPLIER_K") if n != name}
        with _env(VIGIL_BILLING_TARGET_MARGIN=decoy, **{name: "2"}, **others):
            ov = margin.margin_overview(store, cost_rate=RATE)
        assert ov["target_margin_set"] is False
        assert ov["target_margin_issue"] == (f"{name} is set: remove it; the only pricing input is "
                                             f"VIGIL_BILLING_TARGET_MARGIN")
        assert all(t["target_revenue_minor"] is None for t in ov["tenants"])
        # the ACTUAL margin is unaffected: the target line is display-only.
        assert next(x for x in ov["tenants"] if x["org_id"] == "acme")["margin_minor"] == 10200


# ---- READ-ONLY: a projection mints/appends nothing (no money-state mutation) -------------------------
def test_margin_projection_is_read_only_no_spine_mutation():
    store = _store()
    owner = ensure_owner_keypair()
    _seed_acme(store, owner)
    before = store.next_seq
    margin.margin_overview(store, cost_rate=RATE, target_margin=TEST_M)
    margin.margin_overview(store, cost_rate=None)
    margin.margin_overview(store)
    assert store.next_seq == before                          # the spine head is unchanged — a pure read


# ---- _settle_events hardening: the per-period attribution fold rejects forged + replayed settles ----
def test_settle_events_rejects_forged_and_replayed_per_period_settles():
    """_settle_events is a 2nd hand-rolled fold of cost_settle (the per-PERIOD attribution stream): it MUST
    verify each record under the owner pubkey and dedup on (org, entry_id), exactly as the ledger's own fold.
    A forged (wrong-key) settle and a verbatim replay must both be INERT in the per-period view, else a hostile
    spine append could inflate a period's attributed cost."""
    store = _store()
    owner = ensure_owner_keypair()
    orgs = OrgRegistry(store, owner_key=owner)
    inv = InvoiceRegistry(store, owner_key=owner)
    cost = CostEnvelopeLedger(store, owner_key=owner)
    it = iter(range(1, 100_000))
    orgs.create_org("acme", "Acme Corp", owner="owner", issued_at=float(next(it)))
    inv.record("acme", invoice_id="s1", kind="subscription", price_id="pro", amount_minor=10000,
               currency="USD", credits=6000, period_start=0.0, period_end=1000.0, issued_at=100.0)
    cost.settle("acme", 1_000_000, entry_id="settle-cost:valid:1", issued_at=500.0)    # the ONE valid settle
    # REPLAY the valid settle verbatim (same (org, entry_id) -> deduped by _settle_events AND the ledger fold).
    captured = next(r.payload for r in store.iter_records()
                    if isinstance(r.payload, dict) and r.payload.get("signal") == COST_SETTLE_SIGNAL
                    and r.payload.get("entry_id") == "settle-cost:valid:1")
    store.append(kind="event", source="governor", actor="WARDEN", payload=dict(captured))
    # a FORGED (attacker-signed) settle in the SAME window -> must fail verify_signed, never attributed.
    forged = {"signal": COST_SETTLE_SIGNAL, "org_id": "acme", "entry_id": "settle-cost:forged:9",
              "tokens": 9_000_000, "engagement_id": "", "issued_at": 600.0}
    store.append(kind="event", source="governor", actor="WARDEN",
                 payload={**signed_payload(forged, generate_keypair())})
    ov = margin.margin_overview(store, cost_rate=RATE)
    t = next(x for x in ov["tenants"] if x["org_id"] == "acme")
    # headline committed = the ONE valid settle only (the ledger fold drops forged + dedups replay).
    assert t["committed_tokens"] == 1_000_000
    p1 = next(p for p in t["periods"] if p["period_start"] == 0.0)
    # per-period attribution counts the valid settle ONCE — not 10_000_000 (if forged counted) nor 2_000_000
    # (if replay double-counted).  MUTATION-VERIFY: drop _settle_events' verify_signed -> 10_000_000; drop its
    # (org, entry_id) dedup -> 2_000_000.
    assert p1["committed_tokens"] == 1_000_000
    assert p1["cost_minor"] == 1_000_000 * RATE // 1_000_000     # == 300
    # periods still reconcile EXACTLY to the durable lifetime total (forged/replay never inflate it).
    assert sum(p["committed_tokens"] for p in t["periods"]) == t["committed_tokens"] == 1_000_000


# ---- MIXED-CURRENCY fail-closed: never fabricate a cross-currency margin ------------------------------
def test_mixed_currency_withholds_margin_fail_closed():
    """A margin is revenue - cost; when a tenant bills in MORE THAN ONE currency the subtraction is a
    cross-currency fabrication. The view WITHHOLDS margin/pct/target (None) and labels currency 'mixed', while
    still showing committed tokens + the raw billed sum + the single-currency cost. Unreachable under the
    USD-only catalog today — a defence-in-depth guard.  MUTATION-VERIFY (the mixed-currency guard)."""
    store = _store()
    owner = ensure_owner_keypair()
    orgs = OrgRegistry(store, owner_key=owner)
    inv = InvoiceRegistry(store, owner_key=owner)
    cost = CostEnvelopeLedger(store, owner_key=owner)
    it = iter(range(1, 100_000))
    orgs.create_org("mix", "Mixed Co", owner="owner", issued_at=float(next(it)))
    inv.record("mix", invoice_id="m_usd", kind="subscription", price_id="pro", amount_minor=10000,
               currency="USD", credits=6000, period_start=0.0, period_end=1000.0, issued_at=100.0)
    inv.record("mix", invoice_id="m_eur", kind="topup", price_id="t", amount_minor=5000,
               currency="EUR", credits=5000, issued_at=200.0)
    cost.settle("mix", 2_000_000, entry_id="settle-cost:mix:1", issued_at=300.0)
    ov = margin.margin_overview(store, cost_rate=RATE, target_margin=TEST_M)
    t = next(x for x in ov["tenants"] if x["org_id"] == "mix")
    assert t["currency"] == "mixed"
    # MARGIN WITHHELD — never a fabricated cross-currency margin (including the target-margin display target).
    assert t["margin_minor"] is None and t["margin_pct"] is None and t["target_revenue_minor"] is None
    # ...but committed tokens + the raw billed sum + the single-currency cost ARE still shown.
    assert t["committed_tokens"] == 2_000_000
    assert t["billed_revenue_minor"] == 15000                    # 10000 USD + 5000 EUR raw sum (labelled 'mixed')
    assert t["cost_minor"] == 2_000_000 * RATE // 1_000_000      # == 600 (a real single-currency cost figure)
    # per-period rows withhold margin too (margin_ok=False) while keeping the per-period cost.
    assert all(p["margin_minor"] is None for p in t["periods"])
    assert any(p["cost_minor"] is not None for p in t["periods"])
    # totals: billed spans >1 currency -> grand margin withheld; cost + tokens still shown.
    assert ov["currency"] == "mixed"
    assert ov["totals"]["margin_minor"] is None and ov["totals"]["margin_pct"] is None
    assert ov["totals"]["cost_minor"] == 600 and ov["totals"]["committed_tokens"] == 2_000_000


# ---- per-period cost is DISPLAY-APPROXIMATE (independent floor); only TOKENS reconcile exactly --------
def test_per_period_cost_is_display_approximate_but_tokens_reconcile_exactly():
    """Each per-period cost is floored INDEPENDENTLY, so the per-period cost columns can sum to a few minor
    units BELOW the single-floored per-tenant headline (books foot on TOKENS, not cents). Pins the documented
    display-approximate behaviour: TOKENS reconcile EXACTLY; the per-period cost columns are display-only."""
    store = _store()
    owner = ensure_owner_keypair()
    orgs = OrgRegistry(store, owner_key=owner)
    inv = InvoiceRegistry(store, owner_key=owner)
    cost = CostEnvelopeLedger(store, owner_key=owner)
    it = iter(range(1, 100_000))
    orgs.create_org("fl", "Floor Co", owner="owner", issued_at=float(next(it)))
    inv.record("fl", invoice_id="f1", kind="subscription", price_id="pro", amount_minor=10000,
               currency="USD", credits=6000, period_start=0.0, period_end=1000.0, issued_at=100.0)
    inv.record("fl", invoice_id="f2", kind="subscription", price_id="pro", amount_minor=10000,
               currency="USD", credits=6000, period_start=1000.0, period_end=2000.0, issued_at=1100.0)
    # tokens chosen so independent per-period flooring loses a minor unit vs the single headline floor:
    # headline 6667*300//1e6 = 2; period1 3334*300//1e6 = 1; period2 3333*300//1e6 = 0; 1 < 2.
    cost.settle("fl", 3334, entry_id="settle-cost:fl:1", issued_at=500.0)     # period 1
    cost.settle("fl", 3333, entry_id="settle-cost:fl:2", issued_at=1500.0)    # period 2
    ov = margin.margin_overview(store, cost_rate=RATE)
    t = next(x for x in ov["tenants"] if x["org_id"] == "fl")
    # TOKENS reconcile EXACTLY (the authoritative axis).
    assert t["committed_tokens"] == 6667
    assert sum(p["committed_tokens"] for p in t["periods"]) == 6667
    assert t["cost_minor"] == 6667 * RATE // 1_000_000               # == 2 (the single-floored headline)
    # the per-period cost columns are each independently floored and here sum BELOW the headline — documented
    # display-approximate behaviour (tokens still foot exactly; the headline is the authoritative cost).
    per_period_cost = sum(p["cost_minor"] for p in t["periods"])
    assert per_period_cost == 1 and per_period_cost < t["cost_minor"]


# ============ the owner-tier HTTP read route (/api/billing/margin) ====================================
def _serve(spine_path):
    srv = build_server(token=TOKEN, port=0, spine_path=spine_path)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, port


def _get(port, path, *, token=TOKEN):
    h = {"X-SIGIL-Token": token} if token is not None else {}
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _bearer(port, username, role):
    h = {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}",
         "Host": f"127.0.0.1:{port}", "X-SIGIL-Token": TOKEN}
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/action",
                                 data=json.dumps({"action": "create_account", "username": username,
                                                  "role": role}).encode(), headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read().decode())["bearer_token"]


def _seed_server_path():
    path = tempfile.mktemp(suffix=".jsonl")
    SpineStore(path).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    owner = ensure_owner_keypair()
    store = SpineStore(path)
    orgs = OrgRegistry(store, owner_key=owner)
    cost = CostEnvelopeLedger(store, owner_key=owner)
    it = iter(range(1, 100_000))
    orgs.create_org("acme", "Acme Corp", owner="owner", issued_at=float(next(it)))
    orgs.grant_membership("acme", "alice", "operator", issued_at=float(next(it)))   # per-org operator@acme
    cost.settle("acme", 4_000_000, entry_id="settle-cost:r:n1", issued_at=150.0)
    return path


def test_margin_route_owner_only_when_enabled():
    with _env(VIGIL_MARGIN_DASHBOARD_ENABLED="1"):
        srv, port = _serve(_seed_server_path())
        try:
            # the owner (legacy owner token -> owner role, which carries manage_billing) reads it.
            code, body = _get(port, "/api/billing/margin")
            assert code == 200, (code, body)
            assert body["totals"]["tenant_count"] == 1
            assert any(t["org_id"] == "acme" and t["committed_tokens"] == 4_000_000 for t in body["tenants"])
            # a GLOBAL operator / analyst / viewer bearer does NOT carry manage_billing (owner-only) -> 403.
            # MUTATION-VERIFY (the operator-gate): weakening it to view_billing/read would 200 the operator here.
            for role in ("operator", "analyst", "viewer"):
                tok = _bearer(port, f"u_{role}", role)
                assert _get(port, "/api/billing/margin", token=tok)[0] == 403, role
            # a per-org operator MEMBER (global viewer, operator@acme) still 403 — membership never grants
            # manage_billing, so a tenant can never read the operator's cross-tenant margin.
            alice = _bearer(port, "alice", "viewer")
            assert _get(port, "/api/billing/margin", token=alice)[0] == 403
            # an unauthenticated caller -> 401.
            assert _get(port, "/api/billing/margin", token=None)[0] == 401
        finally:
            srv.shutdown()


def test_margin_route_absent_when_flag_off():
    with _env(VIGIL_MARGIN_DASHBOARD_ENABLED=None):           # the shipped default: OFF
        srv, port = _serve(_seed_server_path())
        try:
            # even the owner gets 404 — the surface is opt-in (the console is byte-identical to a build w/o EC-6).
            assert _get(port, "/api/billing/margin")[0] == 404
        finally:
            srv.shutdown()
