"""W2c-2 (j) — the statement's EXACT balance-after, remaining, available-to-start; and the overview's exact balance.

Each metered charge carries ``balance_after_mc`` (the org's EXACT remaining credit right after it, reconstructed in
timestamp order over the org's purchases, trial grant, plan tranches + their expiry, and charges). Two top-level
numbers: ``remaining_mc`` (bought - consumed, exact) and ``available_to_start_mc`` (remaining - the allowances running
scans still hold). Behind ``VIGIL_METERED_BILLING``; the flag OFF ⇒ the statement and overview are byte-identical.

Drives the REAL reserve -> metered publish -> gateway meter -> settle path with the published default rate card.

Mutation-verify targets (each neuter reds a NAMED test here):
  * flip the balance-after sort order (reverse the events)      -> test_balance_after_reflects_a_purchase_between_two_charges
  * drop a grant from the timeline (skip purchase_events)       -> test_balance_after_reflects_a_purchase_between_two_charges
  * count a failed (unavailable) meter in pricing/remaining     -> test_a_failed_meter_is_excluded_from_pricing_and_the_balance
  * let available_to_start exceed remaining (held over 0)       -> test_remaining_vs_available_to_start_with_a_running_scan
  * show the exact balance on the overview with the flag off    -> test_the_overview_exact_balance_only_appears_when_metered
  * purchase_events counts a refund return                      -> test_purchase_events_excludes_settlement_refunds
  * never expire a live plan tranche / always expire one        -> test_a_plan_tranche_expiring_between_charges_enters_and_expires
"""
from __future__ import annotations

import itertools
import json
import tempfile

import pytest

from sigil import config
from sigil import model_gateway as gw
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui import billing as ui_billing
from sigil.ui.target_authorization import add_customer_target
from sigil.ui.launch_gate import LaunchGate
from vigil_core import model_metering as mm
from vigil_core.model_grant import ModelGrant, meter_id

_iss = itertools.count(1)
NOW = 2000.0
U2502 = mm.Usage(output_tokens=400, cache_read_tokens=16)   # 2,500 + 2 = 2502 mc (each line rounded on its own)
U499 = mm.Usage(output_tokens=79, input_tokens=4)           # 494 + 5 = 499 mc
U1 = mm.Usage(cache_read_tokens=8)                          # 1 mc
U500 = mm.Usage(output_tokens=80)                           # exactly 500 mc
U5000 = mm.Usage(output_tokens=800)                         # exactly 5,000 mc
U10000 = mm.Usage(output_tokens=1600)                       # exactly 10,000 mc


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    for k in ("VIGIL_METERED_BILLING", mm.MARGIN_ENV, mm.CANCEL_ENV, "VIGIL_SETTLE_SPINE_RECORD", "VIGIL_RATE_CARD",
              "VIGIL_FOLD_CACHE_ENABLED", *mm.OBSOLETE_PRICING_ENVS):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    monkeypatch.setenv(mm.MARGIN_ENV, "0.5")
    monkeypatch.setenv(mm.CANCEL_ENV, "metered")


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _org(store, org, host, *, credits):
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(org, org, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(org, "u", "operator", issued_at=float(next(_iss)))
    if credits:
        WalletRegistry(store).grant(org, credits, "trial", entry_id=f"trial:{org}", issued_at=NOW - 1000)
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
    assert add_customer_target(host, org_id=org, store=store, now=NOW)["ok"]
    return LaunchGate(store)


def _topup(store, org, credits, *, at):
    WalletRegistry(store).grant(org, credits, "topup", entry_id=f"topup:{org}:{at}", issued_at=at)


def _launch(g, org, host, *, units=10):
    r = g.reserve_launch(requester="u", org_id=org, host=host, units=units, now=NOW)
    assert r["ok"], r
    assert g.publish_lease(signed_lease=r["lease"], expect_org_id=org)["ok"]
    return r


def _use(r, org, usage, *, at):
    m = gw.GrantMeter(config.MODEL_METER_DIR)
    grant = ModelGrant(grant_id="0" * 32, org_id=org, engagement_slug=r["slug"], nonce=r["nonce"],
                       model="claude-opus-4-8", effort="high", cap_nano_usd=10 ** 13, not_after=at + 86_400,
                       issued_at=at - 60)
    rid, _res, why = m.reserve(grant, 10 ** 6, 25_000, now=at)
    assert why == "", why
    m.commit(grant, rid, usage, 1, request_id=f"r{at}", now=at)


def _settle(g, r, *, at=NOW + 10_000):
    gw.GrantMeter(config.MODEL_METER_DIR).close(meter_id(r["slug"], r["nonce"]), now=at)
    mc = g.metered_use_mc(r["slug"], r["nonce"])
    out = g.settle_launch(signed_lease=r["lease"], consumed_units=0, consumed_mc=mc, now=at,
                          basis="completion:completed")
    assert out["ok"], out
    return out


def _usage(store, org, *, now):
    return ui_billing.billing_usage(store, org, trusted_pubkey=ensure_owner_keypair().public_key_b64,
                                    meter_dir=config.MODEL_METER_DIR, now=now)


def _overview(store, org):
    return ui_billing.billing_overview(store, org, now=NOW + 20_000)


def _bal(store, org):
    return WalletRegistry(store).balance(org)


# --------------------------------------------------------------------------------- I4: latest == remaining == overview

def test_i4_latest_balance_after_equals_remaining_and_the_overview():
    s = _store()
    g = _org(s, "org_a", "apme.cm", credits=100)
    for usage, at in ((U2502, NOW), (U499, NOW + 1), (U1, NOW + 2)):
        r = _launch(g, "org_a", "apme.cm")
        _use(r, "org_a", usage, at=at)
        _settle(g, r)
    out = _usage(s, "org_a", now=NOW + 30_000)
    # newest-first: U1@NOW+2 (96998), U499@NOW+1 (96999), U2502@NOW (97498)
    assert [c["balance_after_mc"] for c in out["charges"]] == [96_998, 96_999, 97_498]
    assert out["remaining_mc"] == 96_998 and out["available_to_start_mc"] == 96_998 and out["held_mc"] == 0
    bal = _bal(s, "org_a")
    assert bal.exact_available_mc == 96_998                                  # the wallet's authoritative exact
    ov = _overview(s, "org_a")
    assert ov["exact_available_mc"] == 96_998 and ov["exact_available"] == 96
    # I4, stated as one chain: latest line == remaining == available (settled) == wallet exact == overview exact
    assert out["charges"][0]["balance_after_mc"] == out["remaining_mc"] == bal.exact_available_mc == ov["exact_available_mc"]


# --------------------------------------------------------------------------------- interleaved grants and charges

def test_balance_after_reflects_a_purchase_between_two_charges():
    s = _store()
    g = _org(s, "org_a", "apme.cm", credits=50)
    ra = _launch(g, "org_a", "apme.cm")
    _use(ra, "org_a", U10000, at=NOW)                 # 10 credits consumed, before the top-up
    _settle(g, ra)
    _topup(s, "org_a", 20, at=NOW + 5)                # a 20-credit purchase BETWEEN the two charges
    rb = _launch(g, "org_a", "apme.cm")
    _use(rb, "org_a", U5000, at=NOW + 10)             # 5 credits consumed, after the top-up
    _settle(g, rb)
    out = _usage(s, "org_a", now=NOW + 30_000)
    after = {c["ts"]: c["balance_after_mc"] for c in out["charges"]}
    assert after[NOW] == 40_000                        # 50 - 10 (the top-up has not landed yet)
    assert after[NOW + 10] == 55_000                   # 40 + 20 (top-up) - 5 = 55: the purchase lifted the balance
    assert out["remaining_mc"] == 55_000 == _bal(s, "org_a").exact_available_mc


# --------------------------------------------------------------------------------- a plan tranche entering + expiring

def test_a_plan_tranche_expiring_between_charges_enters_and_expires():
    s = _store()
    g = _org(s, "org_a", "apme.cm", credits=50)
    # a 20-credit plan tranche granted before the charges, expiring BETWEEN them (period_end = NOW+50). No active
    # subscription, so the wallet (not the plan) funds the launches — the tranche is never debited, it only enters
    # and expires, so its effect on the balance-after is purely the non-rollover enter/expire.
    PlanCreditLedger(s).grant("org_a", 20, period_end=NOW + 50, entry_id="plan:org_a:1", issued_at=NOW - 50)
    ra = _launch(g, "org_a", "apme.cm")
    _use(ra, "org_a", U5000, at=NOW)                   # before the tranche expires
    _settle(g, ra)
    rb = _launch(g, "org_a", "apme.cm")
    _use(rb, "org_a", U5000, at=NOW + 100)             # after the tranche has expired
    _settle(g, rb)
    out = _usage(s, "org_a", now=NOW + 30_000)         # now is past period_end -> the tranche HAS expired
    after = {c["ts"]: c["balance_after_mc"] for c in out["charges"]}
    assert after[NOW] == 65_000                         # 50 trial + 20 plan - 5 used = 65 (plan live here)
    assert after[NOW + 100] == 40_000                   # the 20 plan credits expired (-20) before this charge
    assert out["remaining_mc"] == 40_000 == _bal(s, "org_a").exact_available_mc
    # a read BEFORE the tranche expires keeps its 20 credits live in the remaining
    early = _usage(s, "org_a", now=NOW + 10)
    assert early["remaining_mc"] == 60_000             # 50 + 20 - 10 used; the future expiry is NOT applied


# --------------------------------------------------------------------------------- tenant isolation

def test_two_orgs_never_mix_in_the_balance():
    s = _store()
    ga = _org(s, "org_a", "apme.cm", credits=100)
    gb = _org(s, "org_b", "bpme.cm", credits=40)
    ra = _launch(ga, "org_a", "apme.cm")
    _use(ra, "org_a", U2502, at=NOW)
    _settle(ga, ra)
    rb = _launch(gb, "org_b", "bpme.cm")
    _use(rb, "org_b", U500, at=NOW)
    _settle(gb, rb)
    a = _usage(s, "org_a", now=NOW + 30_000)
    b = _usage(s, "org_b", now=NOW + 30_000)
    assert a["remaining_mc"] == 97_498 and b["remaining_mc"] == 39_500      # 100-2.502 ; 40-0.5
    assert a["remaining_mc"] == _bal(s, "org_a").exact_available_mc
    assert b["remaining_mc"] == _bal(s, "org_b").exact_available_mc
    assert [c["scan"] for c in a["charges"]] == [ra["slug"]]                # no org_b line in org_a's statement
    assert WalletRegistry(s).purchase_events("org_a") == [(NOW - 1000, 100)]
    assert WalletRegistry(s).purchase_events("org_b") == [(NOW - 1000, 40)]


# --------------------------------------------------------------------------------- a failed meter is excluded

def test_a_failed_meter_is_excluded_from_pricing_and_the_balance():
    s = _store()
    g = _org(s, "org_a", "apme.cm", credits=100)
    ra = _launch(g, "org_a", "apme.cm")
    _use(ra, "org_a", U2502, at=NOW)
    _settle(g, ra)
    rb = _launch(g, "org_a", "apme.cm")                # a RUNNING launch whose meter we then corrupt
    _use(rb, "org_a", U500, at=NOW + 5)
    p = config.MODEL_METER_DIR / f"{meter_id(rb['slug'], rb['nonce'])}.jsonl"
    lines = p.read_text().splitlines()
    rec = json.loads(lines[-1]); rec["usage"]["output_tokens"] = 1          # tamper a recorded response
    p.write_text("\n".join(lines[:-1] + [json.dumps(rec)]) + "\n")
    out = _usage(s, "org_a", now=NOW + 30_000)
    statuses = {sc["launch"]: sc["status"] for sc in out["scans"]}          # ra/rb share a slug; key by nonce
    assert statuses[rb["nonce"]] == "unavailable" and statuses[ra["nonce"]] == "ok"
    assert [c["launch"] for c in out["charges"]] == [ra["nonce"]]           # the broken meter is NEVER priced
    assert out["remaining_mc"] == 97_498                                    # 100 - 2.502 only; the broken scan is not consumed
    # its reservation is still a real debit, so available_to_start stays == the wallet's authoritative exact
    assert out["available_to_start_mc"] == _bal(s, "org_a").exact_available_mc


# --------------------------------------------------------------------------------- remaining vs available-to-start

def test_remaining_vs_available_to_start_with_a_running_scan():
    s = _store()
    g = _org(s, "org_a", "apme.cm", credits=100)
    r = _launch(g, "org_a", "apme.cm", units=10)       # holds a 10-credit allowance
    _use(r, "org_a", U2502, at=NOW)                    # consumed 2.502, NOT settled -> still running
    out = _usage(s, "org_a", now=NOW + 100)
    assert out["remaining_mc"] == 97_498               # 100 - 2.502 consumed (bought - consumed)
    assert out["held_mc"] == 7_498                     # 10,000 reserved - 2,502 consumed still held by the running scan
    assert out["available_to_start_mc"] == 90_000      # remaining - held: what you can START new work with
    assert out["available_to_start_mc"] < out["remaining_mc"]
    assert out["available_to_start_mc"] == _bal(s, "org_a").exact_available_mc    # == the wallet's authoritative exact
    # the latest balance-after is the REMAINING (not the available-to-start) while a scan runs
    assert out["charges"][0]["balance_after_mc"] == out["remaining_mc"]


# --------------------------------------------------------------------------------- the overview exact + the flag gate

def test_the_overview_exact_balance_only_appears_when_metered(monkeypatch):
    s = _store()
    g = _org(s, "org_a", "apme.cm", credits=100)
    r = _launch(g, "org_a", "apme.cm")
    _use(r, "org_a", U2502, at=NOW)
    _settle(g, r)
    ov_on = ui_billing.billing_overview(s, "org_a", now=NOW + 20_000)
    assert ov_on["exact_available_mc"] == 97_498 and ov_on["exact_available"] == 97
    monkeypatch.delenv("VIGIL_METERED_BILLING", raising=False)
    ov_off = ui_billing.billing_overview(s, "org_a", now=NOW + 20_000)
    assert "exact_available_mc" not in ov_off and "exact_available" not in ov_off
    # every pre-existing field is unchanged (byte-identical but for the two added keys)
    assert {k: ov_off[k] for k in ov_off} == {k: ov_on[k] for k in ov_on if k not in ("exact_available", "exact_available_mc")}


def test_the_statement_is_byte_identical_with_the_flag_off(monkeypatch):
    s = _store()
    g = _org(s, "org_a", "apme.cm", credits=100)
    r = _launch(g, "org_a", "apme.cm")
    _use(r, "org_a", U2502, at=NOW)
    _settle(g, r)
    on = _usage(s, "org_a", now=NOW + 30_000)
    assert "remaining_mc" in on and all("balance_after_mc" in c for c in on["charges"])
    monkeypatch.delenv("VIGIL_METERED_BILLING", raising=False)
    off = _usage(s, "org_a", now=NOW + 30_000)
    assert set(off) == {"org_id", "currency", "scans", "charges", "count", "credits", "amount_mc"}
    assert all("balance_after_mc" not in c for c in off["charges"])
    # the OLD fields are identical whether or not the flag is on
    assert {k: on[k] for k in off if k != "charges"} == {k: off[k] for k in off if k != "charges"}
    assert [{k: v for k, v in c.items() if k != "balance_after_mc"} for c in on["charges"]] == off["charges"]


# --------------------------------------------------------------------------------- purchase_events excludes refunds

def test_purchase_events_excludes_settlement_refunds():
    s = _store()
    g = _org(s, "org_a", "apme.cm", credits=50)        # a trial grant
    _topup(s, "org_a", 20, at=NOW + 5)                 # a top-up purchase
    r = _launch(g, "org_a", "apme.cm", units=10)
    _use(r, "org_a", U500, at=NOW)
    _settle(g, r)                                      # this settle GRANTS a `refund` back to the wallet
    # a refund return exists on the spine...
    from sigil.governor.wallet import GRANT_KINDS
    assert "refund" in GRANT_KINDS
    kinds = []
    for rec in s.iter_records():
        p = rec.payload
        if isinstance(p, dict) and p.get("signal") == "governor.credit_grant":
            kinds.append(p.get("kind"))
    assert "refund" in kinds                            # ...a settlement refund really landed
    # ...but purchase_events reports ONLY the trial + top-up (never the refund): bought = 70 credits
    assert WalletRegistry(s).purchase_events("org_a") == [(NOW - 1000, 50), (NOW + 5, 20)]
    out = _usage(s, "org_a", now=NOW + 30_000)
    assert out["remaining_mc"] == 69_500 == _bal(s, "org_a").exact_available_mc   # 70 bought - 0.5 used
