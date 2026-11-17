"""W2c-1 — a metered run settles EXACTLY, to the milli-credit (HANDOFF §11.5 f + g, §15.2).

A metered settle keeps ``floor((r + used) / 1000)`` whole credits of the launch's reservation and carries the rest as
the org's sub-credit REMAINDER ``r``. The owner-signed ``governor.launch_settled`` v3 decision is the only place the
remainder moves; the wallet fold derives ``r`` from the lifetime sum of the v3 ``consumed_mc`` (prune-durable through
the snapshot's ``wallet_usage_mc``). Reserves and allowance extensions draw from the EXACT balance (whole credits less
``r``), so the exact balance never goes below zero (I2); the statement and the settle price usage identically (I4).
Drives the REAL reserve -> metered publish -> gateway meter -> settle path, with the published default rate card.

Mutation-verify targets (each neuter reds a NAMED test here):
  * round the debit up (prepaid / postpaid builder)        -> test_the_remainder_is_exact_across_three_settles /
                                                              test_a_postpaid_metered_launch_settles_exactly
  * decide on r = 0 (drop the remainder)                   -> test_the_remainder_is_exact_across_three_settles
  * the wallet fold ignores v3 decisions                   -> test_the_remainder_is_exact_across_three_settles
  * the fold counts a replayed v3 twice                    -> test_a_replayed_decision_counts_once
  * the fold counts a forged v3                            -> test_a_forged_exact_decision_moves_no_remainder
  * validate() without the reconciliation identity         -> test_an_exact_decision_that_does_not_reconcile_is_refused
  * no clamp of consumed_mc to the allowance               -> test_a_settle_never_keeps_more_than_the_allowance
  * the reserve ignores r                                  -> test_a_reserve_draws_from_the_exact_balance
  * no in-lock start check after sizing                    -> test_the_start_check_uses_the_exact_balance
  * the extension ignores r                                -> test_an_extension_draws_from_the_exact_balance
  * record the exact decision only with the settle flag    -> test_the_exact_decision_is_recorded_with_the_settle_record_off
  * re-decide a recorded settle on the current r           -> test_a_crash_after_the_decision_finishes_it_exactly_once
  * price a recorded charge again / pre-W2a lines with the default card
                                                           -> test_a_recorded_charge_is_never_repriced
  * exact settle allowed on a flat launch                  -> test_an_exact_settle_of_a_flat_launch_is_refused
  * the snapshot drops the usage total                     -> test_the_snapshot_carries_the_usage_total
"""
from __future__ import annotations

import itertools
import json
import os
import tempfile

import pytest

from sigil import config
from sigil import model_gateway as gw
from sigil.governor import launch_settlement as ls
from sigil.governor import wallet as wallet_mod
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.authn import signed_payload
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.postpaid import PostpaidArrearsLedger, PostpaidRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.snapshot import build
from sigil.spine.store import SpineStore
from sigil.ui import billing as ui_billing
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_core import generate_keypair
from vigil_core import model_metering as mm
from vigil_core.model_grant import ModelGrant
from vigil_core.rate_card import DEFAULT_RATE_CARD, MC_PER_CREDIT, RATE_CARD_ENV

_iss = itertools.count(1)
ORG, HOST, NOW = "org_a", "apme.cm", 2000.0
TEST_MARGIN = "0.5"                              # a test fixture (markup 2), not a pricing decision

# Usages priced at the published default card (output 6.25 mc / token, input 1.25, cache read 0.125), each line rounded
# up on its own (the statement's rule): 400 output + 16 cache-read = 2,500 + 2; 79 output + 4 input = 494 + 5; 8 cache
# read = 1.
U2502 = mm.Usage(output_tokens=400, cache_read_tokens=16)
U499 = mm.Usage(output_tokens=79, input_tokens=4)
U1 = mm.Usage(cache_read_tokens=8)
U500 = mm.Usage(output_tokens=80)                 # 80 x 6.25 = exactly 500


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    for k in ("VIGIL_METERED_BILLING", mm.MARGIN_ENV, mm.CANCEL_ENV, "VIGIL_MODEL_PRICES", "VIGIL_SETTLE_SPINE_RECORD",
              "VIGIL_MODEL_GATEWAY_ENABLED", "VIGIL_RUN_MODEL", "VIGIL_FOLD_CACHE_ENABLED", RATE_CARD_ENV,
              *mm.OBSOLETE_PRICING_ENVS):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    monkeypatch.setenv(mm.MARGIN_ENV, TEST_MARGIN)
    monkeypatch.setenv(mm.CANCEL_ENV, "metered")


def test_the_fixture_usages_cost_what_they_say():
    assert [DEFAULT_RATE_CARD.charge(u)[0] for u in (U2502, U499, U1, U500)] == [2502, 499, 1, 500]


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _org(store, *, credits, postpaid=None):
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(ORG, ORG, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(ORG, "u", "operator", issued_at=float(next(_iss)))
    if credits:
        WalletRegistry(store).grant(ORG, credits, "trial", entry_id=f"trial:{ORG}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(ORG, HOST, issued_at=float(next(_iss)))
    reg.verify_and_record(ORG, HOST, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
    assert add_customer_target(HOST, org_id=ORG, store=store, now=NOW)["ok"]
    if postpaid is not None:
        PostpaidRegistry(store).set_account(ORG, postpaid, 30, issued_at=float(next(_iss)))
    return LaunchGate(store)


def _launch(g, *, units=10, depth=None):
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=units, now=NOW, depth=depth)
    assert r["ok"], r
    assert g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    return r


def _use(r, usage, *, card=None):
    """One confirmed response on the launch's meter (``card``: the gateway priced it, W2a; None: a pre-W2a line)."""
    m = gw.GrantMeter(config.MODEL_METER_DIR, rate_card=card)
    grant = ModelGrant(grant_id="0" * 32, org_id=ORG, engagement_slug=r["slug"], nonce=r["nonce"],
                       model="claude-opus-4-8", effort="high", cap_nano_usd=10 ** 13, not_after=NOW + 86_400,
                       issued_at=NOW - 60)
    rid, _res, why = m.reserve(grant, 10 ** 6, 25_000, now=NOW)
    assert why == "", why
    m.commit(grant, rid, usage, 1, request_id="r", now=NOW)


def _settle(g, r, *, used=None):
    """Settle launch ``r`` exactly: its meter closed, its use read as the drain reads it (``metered_use_mc``)."""
    gw.GrantMeter(config.MODEL_METER_DIR).close(_mid(r), now=NOW)
    mc = g.metered_use_mc(r["slug"], r["nonce"]) if used is None else used
    return g.settle_launch(signed_lease=r["lease"], consumed_units=0, consumed_mc=mc, now=NOW,
                           basis="completion:completed")


def _mid(r):
    from vigil_core.model_grant import meter_id
    return meter_id(r["slug"], r["nonce"])


def _decisions(store):
    return [r.payload for r in store.iter_records()
            if isinstance(r.payload, dict) and r.payload.get("signal") == ls.LAUNCH_SETTLED_SIGNAL]


def _bal(store):
    return WalletRegistry(store).balance(ORG)


# --------------------------------------------------------------------------------------------- the remainder

@pytest.mark.parametrize("cache", ["off", "on"])
def test_the_remainder_is_exact_across_three_settles(monkeypatch, cache):
    if cache == "on":
        monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    s = _store()
    g = _org(s, credits=100)
    for usage in (U2502, U499, U1):
        r = _launch(g)
        _use(r, usage)
        out = _settle(g, r)
        assert out["ok"] and out["action"] == "launch_settled", out
    rows = [(d["consumed_mc"], d["consumed"], d["remainder_before"], d["remainder_after"], d["v"])
            for d in _decisions(s)]
    assert rows == [(2502, 2, 0, 502, 3), (499, 1, 502, 1, 3), (1, 0, 1, 2, 3)]
    b = _bal(s)
    assert (b.available, b.remainder_mc, b.exact_available_mc, b.spendable) == (97, 2, 96_998, 96)
    assert WalletRegistry(s).remainder_mc(ORG) == 2


def test_a_settle_never_keeps_more_than_the_allowance():
    s = _store()
    g = _org(s, credits=100)
    r = _launch(g, units=2)                                       # holds 2 credits
    _use(r, U2502)
    out = _settle(g, r, used=5_000)
    assert out["ok"] and out["consumed_mc"] == 2_000 and out["net_spend"] == 2 and out["remainder_mc"] == 0
    (d,) = _decisions(s)
    assert (d["consumed_mc"], d["consumed"], d["remainder_after"]) == (2_000, 2, 0)
    assert _bal(s).available == 98


def test_the_statement_and_the_settle_price_the_same_usage(monkeypatch):
    """I4: the settle's consumed_mc is the statement's amount for the launch (each line rounded on its own)."""
    s = _store()
    g = _org(s, credits=100)
    r = _launch(g)
    _use(r, mm.Usage(output_tokens=1))                            # 6.25 -> 7 mc per line, twice = 14 (aggregate: 13)
    _use(r, mm.Usage(output_tokens=1))
    assert g.metered_use_mc(r["slug"], r["nonce"]) == 14
    usage = ui_billing.billing_usage(s, ORG, trusted_pubkey=ensure_owner_keypair().public_key_b64,
                                     meter_dir=config.MODEL_METER_DIR)
    assert usage["amount_mc"] == 14


def test_a_recorded_charge_is_never_repriced(monkeypatch):
    """A response the gateway priced (W2a) keeps its recorded charge; one recorded before W2a is priced with the card
    in force — the owner's override, not the published default."""
    s = _store()
    g = _org(s, credits=100)
    r = _launch(g)
    _use(r, U500, card=DEFAULT_RATE_CARD)                         # recorded: 500 mc
    _use(r, U500)                                                 # pre-W2a: priced at settle
    doubled = {"ai": {"input_tokens": "2500", "output_tokens": "12500", "cache_read_tokens": "250",
                      "cache_write_5m_tokens": "3126", "cache_write_1h_tokens": "5000", "web_searches": "5"},
               "worker_minute": "2"}
    monkeypatch.setenv(RATE_CARD_ENV, json.dumps(doubled))
    assert g.metered_use_mc(r["slug"], r["nonce"]) == 500 + 1_000


# --------------------------------------------------------------------------------------------- the exact balance

def _carry_500(g, s):
    """Leave the org with a remainder of 500 mc (a 1-credit launch that used 500 mc keeps nothing)."""
    r = _launch(g, units=1)
    _use(r, U500)
    out = _settle(g, r)
    assert out["ok"] and out["net_spend"] == 0 and _bal(s).remainder_mc == 500


def test_a_reserve_draws_from_the_exact_balance():
    s = _store()
    g = _org(s, credits=30)
    _carry_500(g, s)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=100, now=NOW, depth="quick")
    assert r["ok"] and r["units_reserved"] == 29, r                # 30 credits less 0.5 used: 29 whole credits
    assert _bal(s).exact_available_mc >= 0                         # I2


def test_the_start_check_uses_the_exact_balance():
    s = _store()
    need = -(-gw.min_request_mc(DEFAULT_RATE_CARD) // MC_PER_CREDIT)   # 8 whole credits hold one useful request
    g = _org(s, credits=need)
    _carry_500(g, s)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=100, now=NOW, depth="quick")
    assert r["ok"] is False and "insufficient credits to start" in r["error"]   # 7.5 credits cannot hold 7.965
    assert _bal(s).available == need


def test_a_draw_that_lands_before_the_settle_lock_is_seen_by_the_sizing(monkeypatch):
    """The pre-checks run before the reserve takes the cross-process settle lock; a draw that lands in between (another
    process's flat reserve, simulated here) leaves less than one useful request — the in-lock start check refuses."""
    s = _store()
    need = -(-gw.min_request_mc(DEFAULT_RATE_CARD) // MC_PER_CREDIT)
    g = _org(s, credits=need)                                      # exactly enough at the pre-checks
    real = g._settle_lock_into

    def draw_first(held):
        WalletRegistry(s).debit(ORG, 1, entry_id="elsewhere:1", issued_at=float(next(_iss)))
        return real(held)

    monkeypatch.setattr(g, "_settle_lock_into", draw_first)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=100, now=NOW, depth="quick")
    assert r["ok"] is False and "insufficient credits to start" in r["error"] and "lease" not in r
    assert _bal(s).available == need - 1                           # nothing reserved


def test_an_extension_draws_from_the_exact_balance():
    s = _store()
    g = _org(s, credits=30)
    _carry_500(g, s)
    r = _launch(g, units=10)                                       # wallet 20, r = 500: 19 whole credits
    e = g.extend_reservation(org_id=ORG, slug=r["slug"], nonce=r["nonce"], credits=20, now=NOW)
    assert e["ok"] is False and e.get("insufficient")
    e = g.extend_reservation(org_id=ORG, slug=r["slug"], nonce=r["nonce"], credits=19, now=NOW)
    assert e["ok"], e
    assert _bal(s).exact_available_mc == 500                       # 1 credit left, 0.5 of it already used


# --------------------------------------------------------------------------------------------- the record

def test_the_exact_decision_is_recorded_with_the_settle_record_off():
    s = _store()
    g = _org(s, credits=100)
    r = _launch(g)
    _use(r, U2502)
    assert not config.settle_spine_record_enabled()
    assert _settle(g, r)["ok"]
    (d,) = _decisions(s)
    assert d["v"] == ls.EXACT_RECORD_VERSION


def test_an_exact_settle_of_a_flat_launch_is_refused(monkeypatch):
    s = _store()
    monkeypatch.delenv("VIGIL_METERED_BILLING")                    # published flat
    g = _org(s, credits=100)
    r = _launch(g)
    out = g.settle_launch(signed_lease=r["lease"], consumed_units=0, consumed_mc=500, now=NOW)
    assert out["ok"] is False and "metered" in out["error"]
    assert _decisions(s) == [] and _bal(s).available == 90         # nothing moved
    assert g.settle_launch(signed_lease=r["lease"], consumed_units=10, now=NOW)["ok"]
    assert _decisions(s) == []                                     # a flat settle records nothing new (I7)


def test_an_exact_settle_takes_consumed_mc_alone():
    s = _store()
    g = _org(s, credits=100)
    r = _launch(g)
    for bad in (-1, True, 1.5, "7"):
        assert g.settle_launch(signed_lease=r["lease"], consumed_units=0, consumed_mc=bad, now=NOW)["ok"] is False
    assert g.settle_launch(signed_lease=r["lease"], consumed_units=1, consumed_mc=5, now=NOW)["ok"] is False
    assert _decisions(s) == []


def test_an_exact_decision_that_does_not_reconcile_is_refused():
    good = ls.SettlementDecision.prepaid(10, 2, 0, 8, 0.0, "settle").with_exact(2_502, 0)
    assert good.validate() is None and good.remainder_after == 502
    rounded_up = ls.SettlementDecision.prepaid(10, 3, 0, 7, 0.0, "settle").with_exact(2_502, 0)
    assert "reconcile" in rounded_up.validate()
    dropped = ls.SettlementDecision.prepaid(10, 2, 0, 8, 0.0, "settle").with_exact(2_502, 600)
    assert dropped.validate() is not None                          # 600 + 2,502 is not 2,000 + its remainder
    with pytest.raises(ValueError):
        ls.record_launch_settled(_store(), ensure_owner_keypair(), org_id=ORG, slug="cust_x", nonce="n",
                                 decision=rounded_up, issued_at=NOW)


# --------------------------------------------------------------------------------------------- crash and replay

def test_a_crash_after_the_decision_finishes_it_exactly_once(monkeypatch):
    s = _store()
    g = _org(s, credits=100)
    r = _launch(g)
    _use(r, U2502)
    real = WalletRegistry.grant
    calls = {"n": 0}

    def flaky(self, org_id, credits, *a, entry_id=None, **kw):
        if str(entry_id or "").startswith("settle-wallet:") and calls["n"] == 0:
            calls["n"] += 1
            raise OSError("disk went away")
        return real(self, org_id, credits, *a, entry_id=entry_id, **kw)

    monkeypatch.setattr(WalletRegistry, "grant", flaky)
    out = _settle(g, r)
    assert out["ok"] is False and out.get("retry"), out
    (d,) = _decisions(s)                                           # decided (and the remainder moved) once
    assert (d["consumed_mc"], d["consumed"], d["remainder_after"]) == (2502, 2, 502)
    again = _settle(g, r, used=12_345)                             # a re-drive with another number changes nothing
    assert again["ok"] and again["action"] == "launch_already_settled" and again.get("rolled_forward"), again
    assert (again["net_spend"], again.get("consumed_mc"), again.get("remainder_mc")) == (2, 2502, 502)   # recorded
    assert len(_decisions(s)) == 1 and _bal(s).remainder_mc == 502 and _bal(s).available == 98


def test_a_crash_before_the_decision_decides_afresh(monkeypatch):
    s = _store()
    g = _org(s, credits=100)
    r = _launch(g)
    _use(r, U2502)
    real = ls.record_launch_settled
    calls = {"n": 0}

    def flaky(*a, **kw):
        if calls["n"] == 0:
            calls["n"] += 1
            raise OSError("disk went away")
        return real(*a, **kw)

    monkeypatch.setattr(ls, "record_launch_settled", flaky)
    out = _settle(g, r)
    assert out["ok"] is False and out.get("retry") and _decisions(s) == [] and _bal(s).remainder_mc == 0
    out = _settle(g, r)
    assert out["ok"] and out["action"] == "launch_settled" and _bal(s).remainder_mc == 502


def _replay(store, payload):
    store.append(kind="event", source="governor", actor="WARDEN", payload=dict(payload))


@pytest.mark.parametrize("cache", ["off", "on"])
def test_a_replayed_decision_counts_once(monkeypatch, cache):
    if cache == "on":
        monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    s = _store()
    g = _org(s, credits=100)
    r = _launch(g)
    _use(r, U2502)
    assert _settle(g, r)["ok"]
    (d,) = _decisions(s)
    _replay(s, d)                                                  # a captured record appended again
    assert _bal(s).usage_mc == 2502 and _bal(s).remainder_mc == 502


@pytest.mark.parametrize("cache", ["off", "on"])
def test_a_forged_exact_decision_moves_no_remainder(monkeypatch, cache):
    if cache == "on":
        monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    s = _store()
    _org(s, credits=100)
    forged = ls.SettlementDecision.prepaid(10, 0, 0, 10, 0.0, "settle").with_exact(999, 0)
    core = {"signal": ls.LAUNCH_SETTLED_SIGNAL, "v": 3, "org_id": ORG, "slug": "cust_f", "nonce": "n1",
            "mode": "prepaid", "reserved": 10, "consumed": 0, "refund_plan": 0, "refund_wallet": 10,
            "refund_postpaid": 0, "plan_period_end": 0.0, "basis": "settle", "issued_at": NOW,
            "consumed_mc": forged.consumed_mc, "remainder_before": 0, "remainder_after": 999}
    _replay(s, signed_payload(core, generate_keypair()))           # signed, but not by the owner
    assert _bal(s).usage_mc == 0 and _bal(s).remainder_mc == 0


def test_the_snapshot_carries_the_usage_total():
    s = _store()
    g = _org(s, credits=100)
    for usage in (U2502, U499):
        r = _launch(g)
        _use(r, usage)
        assert _settle(g, r)["ok"]
    pub = ensure_owner_keypair().public_key_b64
    snap = build(list(s.iter_records()), trusted_pubkey=pub, base_seq=0, snapshot_seq=-1)
    assert snap.schema_version == 12 and snap.wallet_usage_map() == {ORG: 3001}
    (d, _d2) = _decisions(s)
    _replay(s, d)                                                  # replayed: still counted once in a fresh build
    assert build(list(s.iter_records()), trusted_pubkey=pub, base_seq=0,
                 snapshot_seq=-1).wallet_usage_map() == {ORG: 3001}


def _v2_core(**over):
    core = {"signal": ls.LAUNCH_SETTLED_SIGNAL, "v": 2, "org_id": ORG, "slug": "cust_v", "nonce": "n1",
            "mode": "prepaid", "reserved": 10, "consumed": 2, "refund_plan": 0, "refund_wallet": 8,
            "refund_postpaid": 0, "plan_period_end": 0.0, "basis": "settle", "issued_at": NOW}
    core.update(over)
    return core


def test_an_unknown_version_record_still_settles_its_lease():
    """Any owner-signed decision settles its lease (fail-closed), whatever version it claims; one this build cannot
    read is settled-but-malformed (never rolled forward, moves no remainder)."""
    s = _store()
    _org(s, credits=100)
    owner = ensure_owner_keypair()
    _replay(s, signed_payload(_v2_core(v=4), owner))
    ev = ls.scan_settlement(s, owner.public_key_b64, org_id=ORG, slug="cust_v", nonce="n1")
    assert ev.settled and ev.malformed and ev.decision is None
    assert _bal(s).usage_mc == 0


def test_a_decision_is_read_only_from_its_signed_core():
    """A record claiming v3 whose exact fields are OUTSIDE the owner's signature (signed over the v2 core) settles its
    lease but is malformed: its unsigned exact fields are never read, and it moves no remainder."""
    s = _store()
    _org(s, credits=100)
    owner = ensure_owner_keypair()
    p = signed_payload(_v2_core(v=3), owner)                       # the v2 fields only, under the owner key
    p.update(consumed_mc=2_502, remainder_before=0, remainder_after=502)   # added after signing
    _replay(s, p)
    ev = ls.scan_settlement(s, owner.public_key_b64, org_id=ORG, slug="cust_v", nonce="n1")
    assert ev.settled and ev.malformed and ev.decision is None
    assert _bal(s).usage_mc == 0


# --------------------------------------------------------------------------------------------- postpaid

def test_a_postpaid_metered_launch_settles_exactly():
    s = _store()
    g = _org(s, credits=0, postpaid=40)
    r = _launch(g, units=20)
    _use(r, U2502)
    out = _settle(g, r)
    assert out["ok"] and out["net_spend"] == 2 and out["remainder_mc"] == 502, out
    assert PostpaidArrearsLedger(s).accrued(ORG) == 2
    nxt = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=100, now=NOW, depth="quick")
    assert nxt["ok"] and nxt["units_reserved"] == 37, nxt          # 38 credits of headroom less 0.502 used


# --------------------------------------------------------------------------------------------- pins

def test_the_restated_constants_match_their_definitions():
    from sigil.ui import launch_gate as lg
    assert wallet_mod._SETTLED_SIGNAL == ls.LAUNCH_SETTLED_SIGNAL
    assert wallet_mod._EXACT_SETTLED_VERSION == ls.EXACT_RECORD_VERSION == 3
    assert wallet_mod.MC_PER_CREDIT == ls.MC_PER_CREDIT == lg.MC_PER_CREDIT == MC_PER_CREDIT == 1000
    assert os.environ.get("VIGIL_FOLD_CACHE_ENABLED") is None      # the fixture leaves the cache off by default
