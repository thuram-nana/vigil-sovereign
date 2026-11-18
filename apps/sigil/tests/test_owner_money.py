"""O1 — the OWNER money view (ui/owner_money.py) + its owner-tier read route + the `sigil owner-money` CLI verb.

Load-bearing invariants a false-green would break (each has a MUTATION-VERIFY guard, see the notes on the asserts):
  * MONEY MATH: rate_card_revenue_nano = charge_mc x 10_000 (one milli-credit is 10,000 nano-USD); gross margin =
    revenue - cost (an integer nano-USD subtraction that may be negative);
  * COST + AT-RISK from the meters: confirmed = sum of cost_nano; at-risk = sum of a cut-off response's held_nano +
    an orphan's reserved (VIGIL's cost, never billed) — the G1 loss split;
  * PER PERIOD: each UTC day's columns are bucketed by the meter line's own ts and sum back to the org headline;
  * SETTLED CROSS-CHECK from the signed spine: settled_revenue_mc == the wallet's exact metered consumption;
  * TENANT ISOLATION: one tenant's meters / wallet never appear for another;
  * FAIL-CLOSED: a corrupt meter is skipped and COUNTED (meter_errors), never fabricated / a crash; an unset target
    margin withholds the target line (with its reason), never a fabricated number; the margin VALUE is never in the
    payload, a commit or a fixture (a money-hygiene-style test);
  * OWNER-ONLY: /api/billing/owner-money is owner-tier (manage_billing) — no per-org member can read it — and behind
    VIGIL_OWNER_MONEY_VIEW (default OFF => 404); the CLI verb refuses when the flag is off.

The meters are seeded through the REAL gateway meter path (reserve -> commit; a dead open auto-orphaned by a fresh
gateway) so every usage line carries the authentic org_id, cost_nano and rate-card charge_mc.
"""
from __future__ import annotations

import contextlib
import importlib.util
import itertools
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from fractions import Fraction
from pathlib import Path

import pytest

from sigil import config
from sigil import model_gateway as gw
from sigil.governor import launch_settlement as ls
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.spine.store import SpineStore
from sigil.ui import owner_money as om
from sigil.ui.server import build_server
from vigil_core import model_metering as mm
from vigil_core.model_grant import ModelGrant
from vigil_core.rate_card import DEFAULT_RATE_CARD

TOKEN = "owner-shared-token-abc123"
# a test-only target line (NOT a pricing decision): with cost c the target revenue is c / (1 - 1/7) = c * 7 / 6.
TEST_M = Fraction(1, 7)
# two instants two UTC days apart (fixed, so the per-period day strings are deterministic).
DAY1 = 1_700_000_000.0
DAY2 = DAY1 + 2 * 86_400.0
_iss = itertools.count(1)


@contextlib.contextmanager
def _env(**kv):
    """Set/clear env vars for the block, restoring the prior values (so a test never leaks a flag)."""
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


def _utc_day(ts: float) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


def _grant(org: str, slug: str, nonce: str) -> ModelGrant:
    return ModelGrant(grant_id="a" * 32, org_id=org, engagement_slug=slug, nonce=nonce,
                      model=mm.DEFAULT_RUN_MODEL, effort="high", cap_nano_usd=10 ** 14, not_after=DAY2 + 86_400,
                      issued_at=DAY1 - 60)


def _card_charge(usage: mm.Usage) -> int:
    return DEFAULT_RATE_CARD.charge(usage)[0]


def _seed_meter(meter_dir: Path, org: str, slug: str, nonce: str, usages) -> None:
    """Write one launch's meter as the gateway does: for each (usage, cost_nano, held_nano, ts) a reserve + commit,
    so the usage line carries org_id, cost_nano, held_nano and the published rate-card charge_mc."""
    g = _grant(org, slug, nonce)
    m = gw.GrantMeter(meter_dir, gateway=True, rate_card=DEFAULT_RATE_CARD)
    try:
        for usage, cost, held, ts in usages:
            rid, _reserved, reason = m.reserve(g, 50_000_000, 25_000, now=ts)
            assert reason == "", reason
            m.commit(g, rid, usage, cost, request_id="r", now=ts, held_nano=held)
    finally:
        m.shutdown()


def _seed_orphan(meter_dir: Path, org: str, slug: str, nonce: str, ts: float) -> int:
    """Leave one launch with a dangling open (a dead gateway's leftover), then start a fresh gateway so it records
    the open as an orphan (pure unconfirmed spend). Returns the reserved amount the orphan carries."""
    g = _grant(org, slug, nonce)
    a = gw.GrantMeter(meter_dir, gateway=True, rate_card=DEFAULT_RATE_CARD)
    _rid, reserved, reason = a.reserve(g, 50_000_000, 25_000, now=ts)
    assert reason == "", reason
    a.shutdown()                                   # give up the lock without committing — a dead open
    b = gw.GrantMeter(meter_dir, gateway=True, rate_card=DEFAULT_RATE_CARD)   # __init__ orphans the dead open
    b.shutdown()
    return reserved


def _seed_superseded(meter_dir: Path, org: str, slug: str, nonce: str, usage: mm.Usage, cost: int,
                     ts: float) -> int:
    """A request orphaned and THEN recorded: its gateway stops (gives up the lock) with the request in flight, a fresh
    gateway records the open as an orphan, then the stopped gateway's in-flight request lands. The meter's own replay
    counts it once, as what it really was. Returns the orphan's reservation."""
    g = _grant(org, slug, nonce)
    a = gw.GrantMeter(meter_dir, gateway=True, rate_card=DEFAULT_RATE_CARD)
    rid, reserved, reason = a.reserve(g, 50_000_000, 25_000, now=ts)
    assert reason == "", reason
    a.shutdown()
    b = gw.GrantMeter(meter_dir, gateway=True, rate_card=DEFAULT_RATE_CARD)   # orphans the in-flight open
    b.shutdown()
    a.commit(g, rid, usage, cost, request_id="late", now=ts)                   # ... which then lands
    return reserved


def _seed_settle(store, owner, org: str, slug: str, consumed_mc: int) -> None:
    """Seed the org's wallet exact metered consumption (usage_mc) via a real owner-signed v3 settle decision: the
    whole-credit debit is the floor of the usage (the decision must reconcile exactly) and the reservation holds it."""
    consumed = consumed_mc // 1000
    reserved = consumed + 8
    dec = ls.SettlementDecision.prepaid(reserved, consumed, 0, reserved - consumed, 0.0, "settle").with_exact(
        consumed_mc, 0)
    ls.record_launch_settled(store, owner, org_id=org, slug=slug, nonce="n", decision=dec,
                             issued_at=float(next(_iss)))


# ============ the projection ==========================================================================
def test_revenue_cost_margin_at_risk_per_org_and_total(tmp_path):
    """Two tenants, confirmed spend + a cut-off (held) part + an orphan: revenue (charge_mc), confirmed cost
    (cost_nano), at-risk (held + orphan reserved) and the gross margin are each folded correctly, per org + total."""
    store = _store()
    owner = ensure_owner_keypair()
    orgs = OrgRegistry(store, owner_key=owner)
    orgs.create_org("acme", "Acme Corp", owner="owner", issued_at=float(next(_iss)))
    orgs.create_org("globex", "Globex", owner="owner", issued_at=float(next(_iss)))
    meter_dir = tmp_path / "model_meter"
    u1 = mm.Usage(output_tokens=8_640)
    assert _card_charge(u1) == 54_000              # the published card's charge for this usage (54 credits)
    # acme: one confirmed response (cost 216,000,000 nano) with a 1,000,000-nano cut-off (held) part.
    _seed_meter(meter_dir, "acme", "acme_run", "n1", [(u1, 216_000_000, 1_000_000, DAY1)])
    orphan = _seed_orphan(meter_dir, "acme", "acme_run2", "n2", DAY1)
    assert orphan > 0                              # a real orphan reservation (keeps the at-risk check non-vacuous)
    # globex: two confirmed responses, no at-risk.
    _seed_meter(meter_dir, "globex", "gx_run", "n3", [(u1, 216_000_000, 0, DAY1), (u1, 100_000_000, 0, DAY1)])

    ov = om.money_overview(store, meter_dir=meter_dir, target_margin=None)
    by = {o["org_id"]: o for o in ov["orgs"]}

    acme = by["acme"]
    assert acme["name"] == "Acme Corp"
    assert acme["rate_card_revenue_mc"] == 54_000                     # one response's charge
    # MUTATION-VERIFY (nano-per-mc): a wrong factor reds this — revenue_nano = charge_mc * 10,000.
    assert acme["rate_card_revenue_nano"] == 54_000 * 10_000 == 540_000_000
    assert acme["provider_cost_nano"] == 216_000_000
    # MUTATION-VERIFY (margin sign): margin = revenue - cost.
    assert acme["gross_margin_nano"] == 540_000_000 - 216_000_000 == 324_000_000
    # MUTATION-VERIFY (at-risk = held + orphan reserved): dropping either term reds this.
    assert acme["at_risk_nano"] == 1_000_000 + orphan

    gx = by["globex"]
    assert gx["rate_card_revenue_mc"] == 2 * 54_000
    assert gx["provider_cost_nano"] == 316_000_000 and gx["at_risk_nano"] == 0

    tot = ov["totals"]
    assert tot["tenant_count"] == 2
    assert tot["rate_card_revenue_mc"] == 54_000 + 2 * 54_000
    assert tot["provider_cost_nano"] == 216_000_000 + 316_000_000
    assert tot["at_risk_nano"] == 1_000_000 + orphan
    assert tot["gross_margin_nano"] == (54_000 * 3) * 10_000 - (216_000_000 + 316_000_000)


def test_per_period_breakdown_by_utc_day(tmp_path):
    """A launch running on two different UTC days splits into two period rows, each bucketed by the meter line's own
    ts, that sum back to the org headline."""
    store = _store()
    owner = ensure_owner_keypair()
    OrgRegistry(store, owner_key=owner).create_org("acme", "Acme Corp", owner="o", issued_at=float(next(_iss)))
    meter_dir = tmp_path / "model_meter"
    u1 = mm.Usage(output_tokens=8_640)
    _seed_meter(meter_dir, "acme", "acme_run", "n1",
                [(u1, 216_000_000, 0, DAY1), (u1, 100_000_000, 0, DAY2)])

    ov = om.money_overview(store, meter_dir=meter_dir, target_margin=None)
    acme = next(o for o in ov["orgs"] if o["org_id"] == "acme")
    periods = {p["day"]: p for p in acme["periods"]}
    assert set(periods) == {_utc_day(DAY1), _utc_day(DAY2)}
    # MUTATION-VERIFY (per-period): bucketing both days into one would red one of these.
    assert periods[_utc_day(DAY1)]["provider_cost_nano"] == 216_000_000
    assert periods[_utc_day(DAY2)]["provider_cost_nano"] == 100_000_000
    assert sum(p["rate_card_revenue_mc"] for p in acme["periods"]) == acme["rate_card_revenue_mc"] == 2 * 54_000
    assert sum(p["provider_cost_nano"] for p in acme["periods"]) == acme["provider_cost_nano"]


def test_tenant_isolation(tmp_path):
    """Each launch is attributed to its own org: two tenants with different spend each see exactly their own — never
    the other's, never a sum, never swapped."""
    store = _store()
    owner = ensure_owner_keypair()
    orgs = OrgRegistry(store, owner_key=owner)
    orgs.create_org("acme", "Acme", owner="o", issued_at=float(next(_iss)))
    orgs.create_org("globex", "Globex", owner="o", issued_at=float(next(_iss)))
    meter_dir = tmp_path / "model_meter"
    u1 = mm.Usage(output_tokens=8_640)
    u2 = mm.Usage(output_tokens=1_000)
    _seed_meter(meter_dir, "acme", "acme_run", "n1", [(u1, 216_000_000, 0, DAY1)])
    _seed_meter(meter_dir, "globex", "gx_run", "n2", [(u2, 25_000_000, 3_000, DAY1)])
    ov = om.money_overview(store, meter_dir=meter_dir, target_margin=None)

    def cols(org):
        o = next(x for x in ov["orgs"] if x["org_id"] == org)
        return o["provider_cost_nano"], o["rate_card_revenue_mc"], o["at_risk_nano"]

    # MUTATION-VERIFY (isolation): attributing a launch to the wrong org, or folding orgs together, reds these.
    assert cols("acme") == (216_000_000, _card_charge(u1), 0)
    assert cols("globex") == (25_000_000, _card_charge(u2), 3_000)


def test_settled_revenue_cross_check_from_signed_spine(tmp_path, monkeypatch):
    """settled_revenue_mc is the wallet's exact metered consumption (the signed-spine authoritative figure), with the
    verified fold cache off and on. The org here has settled usage but no wallet grant / debit (a run funded from plan
    credits alone): it must still be listed — and ``balances`` (the per-tenant billing view) stays unchanged."""
    from sigil.governor.wallet import WalletRegistry
    for cache in ("", "1"):
        if cache:
            monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", cache)
        else:
            monkeypatch.delenv("VIGIL_FOLD_CACHE_ENABLED", raising=False)
        store = _store()
        owner = ensure_owner_keypair()
        OrgRegistry(store, owner_key=owner).create_org("acme", "Acme", owner="o", issued_at=float(next(_iss)))
        _seed_settle(store, owner, "acme", "acme_run", 2_502)
        ov = om.money_overview(store, meter_dir=tmp_path / "model_meter", target_margin=None)
        acme = next(o for o in ov["orgs"] if o["org_id"] == "acme")
        # MUTATION-VERIFY (spine source / usage-only org): reading anything but the wallet usage_mc — or listing only
        # grant / debit orgs — reds this.
        assert acme["settled_revenue_mc"] == 2_502, cache
        assert ov["totals"]["settled_revenue_mc"] == 2_502, cache
        # additive: the per-tenant billing view still lists only grant / debit activity (byte-identical).
        assert [b.org_id for b in WalletRegistry(store).balances()] == [], cache
        assert [(b.org_id, b.usage_mc) for b in WalletRegistry(store).positions()] == [("acme", 2_502)], cache


def test_target_line_from_margin_and_omitted_when_unset(tmp_path):
    """With a target margin the display target revenue is cost / (1 - m); with none it is withheld (with a reason).
    The margin VALUE is never in the payload."""
    store = _store()
    owner = ensure_owner_keypair()
    OrgRegistry(store, owner_key=owner).create_org("acme", "Acme", owner="o", issued_at=float(next(_iss)))
    meter_dir = tmp_path / "model_meter"
    u1 = mm.Usage(output_tokens=8_640)
    _seed_meter(meter_dir, "acme", "acme_run", "n1", [(u1, 216_000_000, 0, DAY1)])

    ov = om.money_overview(store, meter_dir=meter_dir, target_margin=TEST_M)
    acme = next(o for o in ov["orgs"] if o["org_id"] == "acme")
    assert ov["target_margin_set"] is True and ov["target_margin_issue"] is None
    # MUTATION-VERIFY (target line): cost / (1 - m) = 216,000,000 * 7 / 6 = 252,000,000; (1 + m) would red this.
    assert acme["target_revenue_nano"] == 252_000_000
    assert ov["totals"]["target_revenue_nano"] == 252_000_000

    off = om.money_overview(store, meter_dir=meter_dir, target_margin=None)
    assert off["target_margin_set"] is False and off["target_margin_issue"]
    assert off["orgs"][0]["target_revenue_nano"] is None
    # the margin value itself never appears anywhere in the payload (money hygiene): no target_margin field, and
    # the fraction's decimal/ratio text is absent from the whole serialized view.
    for payload in (ov, off):
        blob = json.dumps(payload)
        assert "target_margin" not in {k for o in payload["orgs"] for k in o}  # no per-org margin field
        assert "0.142" not in blob and "1/7" not in blob and "1, 7" not in blob


def test_a_launch_sums_to_the_meters_own_verified_totals(tmp_path):
    """Implementation-independent: for EVERY launch meter, its per-day rows sum exactly to the meter's own verified
    totals (``GrantMeter.verify`` — what the settle signs): confirmed cost, unconfirmed spend, rate-card charge and
    responses — including a request orphaned and then recorded, which is counted once, as what it really was."""
    store = _store()
    owner = ensure_owner_keypair()
    OrgRegistry(store, owner_key=owner).create_org("acme", "Acme", owner="o", issued_at=float(next(_iss)))
    meter_dir = tmp_path / "model_meter"
    u1 = mm.Usage(output_tokens=8_640)
    _seed_meter(meter_dir, "acme", "acme_run", "n1", [(u1, 216_000_000, 1_000_000, DAY1), (u1, 5, 0, DAY2)])
    plain = _seed_orphan(meter_dir, "acme", "acme_orphan", "n2", DAY1)
    late = _seed_superseded(meter_dir, "acme", "acme_late", "n3", u1, 100_000_000, DAY1)
    assert plain > 0 and late > 0

    reader = gw.GrantMeter(meter_dir)
    mids = reader.meter_ids()
    assert len(mids) == 3
    for mid in mids:
        rows, t = reader.spend_by_day(mid), reader.verify(mid)
        # MUTATION-VERIFY (supersede): counting the late request's orphan as well reds the unconfirmed column.
        assert (sum(r.cost_nano for r in rows), sum(r.at_risk_nano for r in rows), sum(r.charge_mc for r in rows),
                sum(r.responses for r in rows)) == (t.cost_nano, t.unconfirmed_nano, t.charged_mc, t.requests), mid
        # the late request's superseded orphan leaves its day at nothing: that day is not listed
        assert all(r.responses or r.at_risk_nano for r in rows), mid
    acme = om.money_overview(store, meter_dir=meter_dir, target_margin=None)["orgs"][0]
    assert acme["at_risk_nano"] == 1_000_000 + plain               # the late request's orphan is not at risk
    assert acme["provider_cost_nano"] == 216_000_000 + 5 + 100_000_000


def test_reads_beside_the_live_gateway_and_writes_no_meter(tmp_path):
    """A pure read: the view runs while the live gateway holds its directory lock (it never takes the gateway role)
    and writes no meter line — a request in flight (an open the live gateway owns) is neither orphaned nor counted."""
    store = _store()
    owner = ensure_owner_keypair()
    OrgRegistry(store, owner_key=owner).create_org("acme", "Acme", owner="o", issued_at=float(next(_iss)))
    meter_dir = tmp_path / "model_meter"
    g = _grant("acme", "acme_run", "n1")
    live = gw.GrantMeter(meter_dir, gateway=True, rate_card=DEFAULT_RATE_CARD)
    try:
        rid, _reserved, reason = live.reserve(g, 50_000_000, 25_000, now=DAY1)
        assert reason == "", reason
        live.commit(g, rid, mm.Usage(output_tokens=8_640), 216_000_000, request_id="r", now=DAY1)
        _rid2, _reserved2, reason2 = live.reserve(g, 50_000_000, 25_000, now=DAY1)    # still in flight
        assert reason2 == "", reason2
        before = {p.name: p.read_bytes() for p in meter_dir.iterdir()}
        ov = om.money_overview(store, meter_dir=meter_dir, target_margin=None)
        after = {p.name: p.read_bytes() for p in meter_dir.iterdir()}
    finally:
        live.shutdown()
    # MUTATION-VERIFY (pure read): taking the gateway role would fail on the live lock (or orphan the open).
    assert after == before
    acme = next(o for o in ov["orgs"] if o["org_id"] == "acme")
    assert acme["provider_cost_nano"] == 216_000_000 and acme["at_risk_nano"] == 0


def test_fail_closed_on_corrupt_meter(tmp_path):
    """A hash-broken / unreadable meter is skipped and counted (meter_errors), never fabricated or a crash; the
    sound meters still fold; a file that is not a meter at all is ignored."""
    store = _store()
    owner = ensure_owner_keypair()
    OrgRegistry(store, owner_key=owner).create_org("acme", "Acme", owner="o", issued_at=float(next(_iss)))
    meter_dir = tmp_path / "model_meter"
    u1 = mm.Usage(output_tokens=8_640)
    _seed_meter(meter_dir, "acme", "acme_run", "n1", [(u1, 216_000_000, 0, DAY1)])
    # a second file with a valid 32-hex name but a broken hash chain.
    bad = meter_dir / ("b" * 32 + ".jsonl")
    bad.write_text('{"kind":"usage","ts":1.0,"org_id":"acme","cost_nano":9,"n":1,"prev":"","h":"deadbeef"}\n')
    # and a file that is not a meter (its name is not a meter id): ignored, not an error.
    (meter_dir / "notes.jsonl").write_text("{}\n")

    ov = om.money_overview(store, meter_dir=meter_dir, target_margin=None)
    # MUTATION-VERIFY (fail-closed + meter-id filter): swallowing the error, or reading a non-meter file as a
    # meter, changes this count.
    assert ov["meter_errors"] == 1
    acme = next(o for o in ov["orgs"] if o["org_id"] == "acme")
    assert acme["provider_cost_nano"] == 216_000_000               # the corrupt file contributed nothing


def test_admin_api_reconciliation_scaffold(tmp_path):
    """The provider's own Usage & Cost figure is a scaffolded OWNER-PROVIDED interface — unconfigured by default,
    surfaced (never derived) when supplied."""
    store = _store()
    ensure_owner_keypair()
    unset = om.money_overview(store, meter_dir=tmp_path / "model_meter", target_margin=None)
    rec = unset["admin_api_reconciliation"]
    assert rec["configured"] is False and rec["provider_cost_nano"] is None and "owner-provided" in rec["source"]
    got = om.money_overview(store, meter_dir=tmp_path / "model_meter", target_margin=None,
                            admin_api_cost_nano=500_000_000)
    assert got["admin_api_reconciliation"]["configured"] is True
    assert got["admin_api_reconciliation"]["provider_cost_nano"] == 500_000_000


def test_read_only_no_mint(tmp_path):
    """A pure read: the spine head does not move."""
    store = _store()
    owner = ensure_owner_keypair()
    OrgRegistry(store, owner_key=owner).create_org("acme", "Acme", owner="o", issued_at=float(next(_iss)))
    meter_dir = tmp_path / "model_meter"
    _seed_meter(meter_dir, "acme", "acme_run", "n1", [(mm.Usage(output_tokens=8_640), 216_000_000, 0, DAY1)])
    before = store.next_seq
    om.money_overview(store, meter_dir=meter_dir, target_margin=TEST_M)
    assert store.next_seq == before


# ============ W5 arrears: the purchase-side owed, BESIDE the provider-side at-risk =====================
def _seed_reversal(store, owner, org: str, *, granted: int, spent: int, disputed: int, topup: int = 0) -> int:
    """One org's disputed purchase on the REAL W5 ledger: a grant, a spend, then a dispute OPEN that removes
    ``disputed`` credits (the already-spent part booked as OWED / arrears); an optional top-up then repays what it
    can. Records are owner-signed under the persisted identity, so ``money_overview``'s own read verifies them.
    Returns the org's arrears (owed credits) after the steps."""
    from sigil.governor.billing_reversal import BillingReversalLedger, REASON_DISPUTE
    from sigil.governor.wallet import WalletRegistry
    w = WalletRegistry(store, owner_key=owner)
    ledger = BillingReversalLedger(store, wallet=w, owner_key=owner)
    ref = f"cs_{org}_1"
    w.grant(org, granted, "topup", entry_id=ref, issued_at=float(next(_iss)))
    if spent:
        w.debit(org, spent, entry_id=f"spend_{org}", issued_at=float(next(_iss)))
    ledger.reconcile(org, ref, cap=granted, reason=REASON_DISPUTE, now=float(next(_iss)), disputed=disputed)
    if topup:
        top = f"cs_{org}_2"
        w.grant(org, topup, "topup", entry_id=top, issued_at=float(next(_iss)))
        ledger.repay(org, top, now=float(next(_iss)))
    return ledger.owed(org)


def test_arrears_owed_from_a_disputed_then_partially_repaid_purchase(tmp_path):
    """An org whose purchase was disputed (the already-spent part booked as OWED) and then only partially repaid
    shows the correct arrears — in credits and, at the published credit unit, in nano-USD — per org and in total."""
    store = _store()
    owner = ensure_owner_keypair()
    OrgRegistry(store, owner_key=owner).create_org("acme", "Acme", owner="o", issued_at=float(next(_iss)))
    # grant 1000, spend 900 (spendable 100); a full dispute removes 1000 => 100 from the wallet, 900 OWED; a 500
    # top-up repays 500 => 400 still owed.
    assert _seed_reversal(store, owner, "acme", granted=1000, spent=900, disputed=1000, topup=500) == 400
    ov = om.money_overview(store, meter_dir=tmp_path / "model_meter", target_margin=None)
    acme = next(o for o in ov["orgs"] if o["org_id"] == "acme")
    # MUTATION-VERIFY (wrong ledger / not read): reading nothing from the reversal ledger reds the owed credits;
    # MUTATION-VERIFY (repayments not netted): counting booked arrears without subtracting the repay reds it (900).
    assert acme["arrears_credits"] == 400
    assert acme["arrears_nano"] == 400 * mm.CREDIT_NANO_USD == 4_000_000_000
    assert acme["arrears_usd"] == om._usd(4_000_000_000)
    assert ov["totals"]["arrears_credits"] == 400 and ov["totals"]["arrears_nano"] == 4_000_000_000


def test_arrears_is_distinct_from_the_provider_side_at_risk(tmp_path):
    """The customer-side arrears and the provider-side at-risk are two DIFFERENT losses, each in its own field — a
    both-nonzero org carries both, correct and not conflated into one number."""
    store = _store()
    owner = ensure_owner_keypair()
    OrgRegistry(store, owner_key=owner).create_org("acme", "Acme", owner="o", issued_at=float(next(_iss)))
    meter_dir = tmp_path / "model_meter"
    # provider-side at-risk: a cut-off (held) part of a confirmed response.
    _seed_meter(meter_dir, "acme", "acme_run", "n1", [(mm.Usage(output_tokens=8_640), 216_000_000, 1_000_000, DAY1)])
    # customer-side arrears: a disputed-then-partially-repaid purchase (400 owed).
    assert _seed_reversal(store, owner, "acme", granted=1000, spent=900, disputed=1000, topup=500) == 400
    ov = om.money_overview(store, meter_dir=meter_dir, target_margin=None)
    acme = next(o for o in ov["orgs"] if o["org_id"] == "acme")
    # MUTATION-VERIFY (conflated): folding arrears into the at-risk field (or vice-versa) reds one of these.
    assert acme["at_risk_nano"] == 1_000_000                        # provider-side, from the meter — unchanged
    assert acme["arrears_credits"] == 400 and acme["arrears_nano"] == 400 * mm.CREDIT_NANO_USD
    assert acme["arrears_nano"] != acme["at_risk_nano"]             # two different losses, never one number


def test_total_arrears_sums_the_orgs(tmp_path):
    """Total arrears is the sum of the per-org arrears across tenants."""
    store = _store()
    owner = ensure_owner_keypair()
    orgs = OrgRegistry(store, owner_key=owner)
    orgs.create_org("acme", "Acme", owner="o", issued_at=float(next(_iss)))
    orgs.create_org("globex", "Globex", owner="o", issued_at=float(next(_iss)))
    assert _seed_reversal(store, owner, "acme", granted=1000, spent=900, disputed=1000, topup=500) == 400
    assert _seed_reversal(store, owner, "globex", granted=500, spent=500, disputed=500) == 500
    ov = om.money_overview(store, meter_dir=tmp_path / "model_meter", target_margin=None)
    by = {o["org_id"]: o["arrears_credits"] for o in ov["orgs"]}
    assert by == {"acme": 400, "globex": 500}
    # MUTATION-VERIFY (total): the grand total is exactly the sum of the orgs' own arrears.
    assert ov["totals"]["arrears_credits"] == 400 + 500 == 900
    assert ov["totals"]["arrears_nano"] == 900 * mm.CREDIT_NANO_USD


def test_arrears_tenant_isolation(tmp_path):
    """Each org's arrears is its OWN: an org that owes nothing shows 0 even while another tenant owes — never the
    other's, never a sum."""
    store = _store()
    owner = ensure_owner_keypair()
    orgs = OrgRegistry(store, owner_key=owner)
    orgs.create_org("acme", "Acme", owner="o", issued_at=float(next(_iss)))
    orgs.create_org("globex", "Globex", owner="o", issued_at=float(next(_iss)))
    meter_dir = tmp_path / "model_meter"
    # acme owes 400; globex has metered activity but no reversal, so it owes nothing.
    assert _seed_reversal(store, owner, "acme", granted=1000, spent=900, disputed=1000, topup=500) == 400
    _seed_meter(meter_dir, "globex", "gx_run", "n9", [(mm.Usage(output_tokens=8_640), 216_000_000, 0, DAY1)])
    ov = om.money_overview(store, meter_dir=meter_dir, target_margin=None)
    by = {o["org_id"]: o["arrears_credits"] for o in ov["orgs"]}
    # MUTATION-VERIFY (cross-org leak): attributing one tenant's arrears (or the total) to another reds globex's 0.
    assert by["acme"] == 400 and by["globex"] == 0


def test_zero_arrears_when_no_reversal_exists(tmp_path):
    """With no reversal on the spine (the W5 reversals feature off => no records) every org's arrears — and the
    total — is 0, so the column is inert and nothing changes."""
    store = _store()
    owner = ensure_owner_keypair()
    OrgRegistry(store, owner_key=owner).create_org("acme", "Acme", owner="o", issued_at=float(next(_iss)))
    meter_dir = tmp_path / "model_meter"
    _seed_meter(meter_dir, "acme", "acme_run", "n1", [(mm.Usage(output_tokens=8_640), 216_000_000, 0, DAY1)])
    ov = om.money_overview(store, meter_dir=meter_dir, target_margin=None)
    acme = next(o for o in ov["orgs"] if o["org_id"] == "acme")
    assert acme["arrears_credits"] == 0 and acme["arrears_nano"] == 0 and acme["arrears_usd"] == om._usd(0)
    assert ov["totals"]["arrears_credits"] == 0 and ov["totals"]["arrears_nano"] == 0


def test_arrears_read_is_pure_the_spine_head_does_not_move(tmp_path):
    """Folding the arrears mints nothing: with a reversal on the spine, ``money_overview`` does not append a record."""
    store = _store()
    owner = ensure_owner_keypair()
    OrgRegistry(store, owner_key=owner).create_org("acme", "Acme", owner="o", issued_at=float(next(_iss)))
    _seed_reversal(store, owner, "acme", granted=1000, spent=900, disputed=1000, topup=500)
    before = store.next_seq
    om.money_overview(store, meter_dir=tmp_path / "model_meter", target_margin=None)
    assert store.next_seq == before


# ============ the owner-tier HTTP route (/api/billing/owner-money) ====================================
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


def _seed_server_path(meter_dir):
    path = tempfile.mktemp(suffix=".jsonl")
    SpineStore(path).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    owner = ensure_owner_keypair()
    store = SpineStore(path)
    orgs = OrgRegistry(store, owner_key=owner)
    orgs.create_org("acme", "Acme Corp", owner="owner", issued_at=float(next(_iss)))
    orgs.grant_membership("acme", "alice", "operator", issued_at=float(next(_iss)))  # per-org operator@acme
    _seed_meter(meter_dir, "acme", "acme_run", "n1", [(mm.Usage(output_tokens=8_640), 216_000_000, 0, DAY1)])
    return path


def test_owner_money_route_owner_only_when_enabled(tmp_path, monkeypatch):
    meter_dir = tmp_path / "model_meter"
    monkeypatch.setattr(config, "MODEL_METER_DIR", meter_dir)
    with _env(VIGIL_OWNER_MONEY_VIEW="1"):
        srv, port = _serve(_seed_server_path(meter_dir))
        try:
            code, body = _get(port, "/api/billing/owner-money")
            assert code == 200, (code, body)
            assert body["totals"]["tenant_count"] == 1
            assert any(o["org_id"] == "acme" and o["rate_card_revenue_mc"] == 54_000 for o in body["orgs"])
            # the arrears column is carried over the route too (0 here: no reversal) — beside the at-risk figure.
            assert body["totals"]["arrears_credits"] == 0
            assert all("arrears_credits" in o and "at_risk_nano" in o for o in body["orgs"])
            # MUTATION-VERIFY (owner-gate): weakening manage_billing to view_billing/read would 200 the operator.
            for role in ("operator", "analyst", "viewer"):
                tok = _bearer(port, f"u_{role}", role)
                assert _get(port, "/api/billing/owner-money", token=tok)[0] == 403, role
            # a per-org operator MEMBER (global viewer, operator@acme) still 403 — membership never grants it.
            alice = _bearer(port, "alice", "viewer")
            assert _get(port, "/api/billing/owner-money", token=alice)[0] == 403
            assert _get(port, "/api/billing/owner-money", token=None)[0] == 401
        finally:
            srv.shutdown()


def test_owner_money_route_absent_when_flag_off(tmp_path, monkeypatch):
    meter_dir = tmp_path / "model_meter"
    monkeypatch.setattr(config, "MODEL_METER_DIR", meter_dir)
    with _env(VIGIL_OWNER_MONEY_VIEW=None):          # the shipped default: OFF
        srv, port = _serve(_seed_server_path(meter_dir))
        try:
            # MUTATION-VERIFY (byte-identical off): even the owner gets the 404 a route that never existed gets —
            # same status, same body — so the server surface is exactly a build without O1.
            off = _get(port, "/api/billing/owner-money")
            assert off[0] == 404
            assert off == _get(port, "/api/billing/no-such-route-o1")
        finally:
            srv.shutdown()


# ============ the CLI verb ============================================================================
def test_cli_surface_is_byte_identical_when_flag_off(capsys):
    """With the flag off the `sigil` CLI is exactly a build without O1: `owner-money` is an unknown verb (refused
    word-for-word as a verb that never existed) and `--help` does not list it. With the flag on it is listed."""
    from sigil import cli
    with _env(VIGIL_OWNER_MONEY_VIEW=None):
        with pytest.raises(SystemExit) as off:
            cli.main(["owner-money"])
        err_off = capsys.readouterr().err
        with pytest.raises(SystemExit) as unknown:
            cli.main(["no-such-verb-o1"])
        err_unknown = capsys.readouterr().err
        with pytest.raises(SystemExit):
            cli.main(["--help"])
        help_off = capsys.readouterr().out
    # MUTATION-VERIFY (byte-identical off): registering the verb unconditionally reds these.
    assert off.value.code == unknown.value.code == 2
    assert err_off.replace("owner-money", "V") == err_unknown.replace("no-such-verb-o1", "V")
    assert "owner-money" not in help_off
    with _env(VIGIL_OWNER_MONEY_VIEW="1"):
        with pytest.raises(SystemExit):
            cli.main(["--help"])
        assert "owner-money" in capsys.readouterr().out


def test_cli_owner_money_refuses_when_flag_off(capsys):
    """The handler re-checks the flag (a second, independent refusal behind the conditional registration)."""
    from sigil import cli
    with _env(VIGIL_OWNER_MONEY_VIEW=None):
        with pytest.raises(SystemExit) as e:
            cli.cmd_owner_money(type("A", (), {"json": False})())
    # MUTATION-VERIFY (handler flag check): dropping it runs the view instead of exiting 2.
    assert e.value.code == 2
    assert "VIGIL_OWNER_MONEY_VIEW" in capsys.readouterr().err


def test_cli_owner_money_prints_totals_when_on(tmp_path, monkeypatch, capsys):
    meter_dir = tmp_path / "model_meter"
    monkeypatch.setattr(config, "MODEL_METER_DIR", meter_dir)
    path = tempfile.mktemp(suffix=".jsonl")
    SpineStore(path).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    monkeypatch.setattr("sigil.cli.SpineStore", lambda *a, **k: SpineStore(path))   # the CLI's default store
    owner = ensure_owner_keypair()
    store = SpineStore(path)
    OrgRegistry(store, owner_key=owner).create_org("acme", "Acme Corp", owner="o", issued_at=float(next(_iss)))
    _seed_meter(meter_dir, "acme", "acme_run", "n1", [(mm.Usage(output_tokens=8_640), 216_000_000, 0, DAY1)])
    from sigil import cli
    with _env(VIGIL_OWNER_MONEY_VIEW="1"):
        cli.cmd_owner_money(type("A", (), {"json": False})())
    out = capsys.readouterr().out
    assert "owner money view" in out and "Acme Corp" in out and "TOTAL" in out
    # the purchase-side arrears is surfaced beside the provider-side at-risk (two labelled losses).
    assert "at risk" in out and "owed" in out


# ============ money hygiene: the deploy's margin is read, never leaked; no value in the slice's files ===
def test_target_line_reads_the_deploy_margin_and_never_leaks_it(tmp_path, monkeypatch):
    """Without an override the view reads the deploy's target margin through ``model_metering.target_margin``: unset
    => no target line and the reason names the setting; set (stood in for here by patching the reader, so no value
    ever sits in this test's environment) => the target line is drawn and the serialized view still carries no
    trace of the value."""
    store = _store()
    owner = ensure_owner_keypair()
    OrgRegistry(store, owner_key=owner).create_org("acme", "Acme", owner="o", issued_at=float(next(_iss)))
    meter_dir = tmp_path / "model_meter"
    _seed_meter(meter_dir, "acme", "acme_run", "n1", [(mm.Usage(output_tokens=8_640), 216_000_000, 0, DAY1)])
    for k in (mm.MARGIN_ENV, *mm.OBSOLETE_PRICING_ENVS):
        monkeypatch.delenv(k, raising=False)
    unset = om.money_overview(store, meter_dir=meter_dir)
    assert unset["target_margin_set"] is False and mm.MARGIN_ENV in unset["target_margin_issue"]
    assert unset["totals"]["target_revenue_nano"] is None
    monkeypatch.setattr(mm, "target_margin", lambda env=None: TEST_M)
    got = om.money_overview(store, meter_dir=meter_dir)
    assert got["target_margin_set"] is True and got["totals"]["target_revenue_nano"] == 252_000_000
    blob = json.dumps(got)
    assert "0.142" not in blob and "1/7" not in blob and "1, 7" not in blob


#: every file this slice adds or edits — the scan below covers each of them.
_O1_FILES = ("apps/sigil/sigil/ui/owner_money.py", "apps/sigil/tests/test_owner_money.py",
             "apps/sigil/sigil/model_gateway.py", "apps/sigil/sigil/governor/wallet.py",
             "apps/sigil/sigil/config.py", "apps/sigil/sigil/ui/server.py", "apps/sigil/sigil/cli.py")
_REPO = Path(__file__).resolve().parents[3]


def _load_money_hygiene(monkeypatch):
    spec = importlib.util.spec_from_file_location("money_hygiene",
                                                  _REPO / "tools" / "governance" / "money_hygiene.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "money_hygiene", mod)    # a dataclass resolves its module while defined
    spec.loader.exec_module(mod)
    return mod


def test_no_margin_value_in_the_slice_files(monkeypatch):
    """A money-hygiene-style guard: no file this slice adds or edits carries a markup / margin VALUE (the public-repo
    rule). Runs the real scanner (tools/governance/money_hygiene.py) over each one's source."""
    mh = _load_money_hygiene(monkeypatch)
    for rel in _O1_FILES:
        hits = mh.scan_text((_REPO / rel).read_text(encoding="utf-8"), rel)
        assert hits == [], [h.render() for h in hits]
