"""PR-J2 — the customer security assistant's ACCOUNTING (``sigil.ui.assistant_wallet`` + ``sigil.governor.assistant_turns``):
the per-org rate limit and daily turn budget, the owner-signed audit record of every turn, the WALLET DRAW and its
statement line.

With ``VIGIL_CUSTOMER_ASSISTANT_WALLET`` on, every assistant turn is admitted before its one model request: the org's
turns in the last hour / day are counted from the owner-signed turn ledger (over a limit ⇒ rate limited, nothing sent)
and the turn's audit record (who asked, for which org, under which grant) is written first. With metered billing on the
turn is also billed to the org's own credits exactly as a metered launch is: BEFORE its one model request, that
request's worst case is HELD (an owner-signed reserve keyed by the turn's grant nonce — refused, with nothing held, when
the exact balance cannot cover it); the gateway admits the request only within that hold; afterwards the turn settles
EXACTLY (its closed meter's confirmed charge kept to the milli-credit, the rest returned) and the statement lists the
charge as "Security assistant". Everything is driven through the REAL ledgers, the REAL meter and — for the end-to-end
cases — the REAL model gateway with a FAKE model behind it (never a provider).

The red-pen attacks are named ``test_attack_*``: replay / double-spend a grant nonce, race turns past the balance and
past the rate limit, negative / zero / overflowing / non-integer amounts, a cross-org draw (a grant naming another
org's hold), forged / foreign / tampered turn records, malformed records, and the PR-J repro (a zero-credit flat org
asking turn after turn).

Mutation-verify targets (each neuter reds a NAMED test here):
  * reserve skips the availability-delta check (a replayed nonce)   -> test_attack_a_replayed_nonce_holds_nothing_twice
  * reserve decides outside the locks / without the re-check        -> test_attack_racing_turns_never_hold_more_than_the_org_has
  * reserve ignores the remainder (whole credits, not exact)        -> test_reserve_sizes_from_the_exact_balance
  * reserve rounds the hold DOWN                                    -> test_reserve_holds_the_worst_case_in_whole_credits
  * reserve skips the billing-hold conjunct                         -> test_a_billing_hold_refuses_the_turn
  * the allowance trusts the grant's slug (no org re-derivation)    -> test_attack_a_grant_naming_another_orgs_hold_gets_no_allowance
  * the allowance answers a settled turn                            -> test_a_settled_turns_grant_gets_no_allowance
  * settle without closing the meter first                          -> test_settle_closes_the_meter_so_the_grant_is_dead
  * settle without the clamp to the hold                            -> test_settle_never_keeps_more_than_the_hold
  * settle writes the seam (seam marker / tombstone)                -> test_settle_writes_nothing_on_the_seam
  * _settle_once without the always-record leg for seam=False       -> test_a_seamless_settle_always_records_its_decision
  * plain_request_worst_mc drifts from the gateway's _admit         -> test_plain_request_worst_mc_is_exactly_what_the_gateway_reserves
  * the provisioner sends before the hold                           -> test_e2e_insufficient_credits_sends_no_request
  * the provisioner skips the settle on a failed call               -> test_e2e_a_failed_call_is_refunded_in_full
  * the flag-off metered refusal changes                            -> test_flag_off_metered_on_is_refused_exactly_as_before
  * the statement lists a turn as a scan / never labels it          -> test_statement_lists_the_turn_as_a_security_assistant_line
  * the gateway keeps a settled turn's memory                       -> test_e2e_the_gateway_forgets_a_settled_turn
  * the ledger never refuses (no rate limit / budget)               -> test_the_hourly_rate_limit_and_the_daily_budget_windows,
                                                                       test_attack_a_zero_credit_flat_org_cannot_spend_unbounded
  * the ledger counts an unverified / non-governor record           -> test_attack_a_forged_foreign_or_tampered_turn_record_is_inert
  * the ledger counts a re-recorded nonce twice                     -> test_a_re_recorded_nonce_counts_once
  * the admission decides outside the critical section              -> test_attack_racing_turns_never_pass_the_rate_limit
  * a turn is admitted without its audit record                     -> test_a_metered_reserve_writes_the_audit_record_before_the_hold
  * the accounted turn's grounding call drifts from PR-J's           -> test_the_accounted_turn_grounds_exactly_like_the_unaccounted_one
  * the accounted dial skips its closer on a failure                -> test_the_accounted_dial_closes_the_turn_when_the_gateway_fails
  * a grant that cannot be minted strands the hold                  -> test_a_grant_that_cannot_be_minted_returns_the_hold_at_once
  * a rate-limited turn is answered as a plain denial               -> test_e2e_the_org_rate_limit_refuses_a_turn_with_nothing_held_or_sent
  * the edge gives up on an accounted turn at PR-J's 10 s           -> test_the_edge_outwaits_an_accounted_turn_and_keeps_its_drain_deadline
  * a credit-drawing turn skips the spend permission                -> test_a_member_who_may_read_but_not_spend_draws_nothing
"""
from __future__ import annotations

import itertools
import json
import tempfile
import threading
import time
from pathlib import Path

import pytest

from sigil import config
from sigil import model_gateway as gw
from sigil.governor import assistant_turns as at
from sigil.governor import launch_settlement as ls
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.postpaid import PostpaidArrearsLedger, PostpaidRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui import assistant_wallet as aw
from sigil.ui import billing as ui_billing
from sigil.ui.launch_gate import LaunchAllowance, LaunchGate
from sigil.ui.provision import ProvisionDenied, ProvisionRateLimited, Provisioner
from sigil.ui.target_authorization import _customer_slug
from vigil_core import model_metering as mm
from vigil_core.model_grant import ModelGrant, encode_token, meter_id, new_grant_id
from vigil_core.rate_card import DEFAULT_RATE_CARD, MC_PER_CREDIT, RATE_CARD_ENV

_iss = itertools.count(1)
ORG, OTHER = "org_a", "org_b"
NOW = 2_000_000.0
U2502 = mm.Usage(output_tokens=400, cache_read_tokens=16)      # 2,500 + 2 = 2,502 mc at the default card
U500 = mm.Usage(output_tokens=80)                              # exactly 500 mc
U_HUGE = mm.Usage(output_tokens=10_000_000)                    # far past any hold


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "seam"))
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    for k in ("VIGIL_METERED_BILLING", "VIGIL_CUSTOMER_ASSISTANT", "VIGIL_CUSTOMER_ASSISTANT_WALLET",
              "VIGIL_SETTLE_SPINE_RECORD", "VIGIL_FOLD_CACHE_ENABLED", "VIGIL_BILLING_REVERSALS", RATE_CARD_ENV,
              "VIGIL_MODEL_PRICES", "VIGIL_ASSISTANT_MODEL", "VIGIL_ASSISTANT_MAX_TOKENS", "VIGIL_ASSISTANT_CAP_NANO_USD",
              "VIGIL_ASSISTANT_TURNS_PER_HOUR", "VIGIL_ASSISTANT_TURNS_PER_DAY", *mm.OBSOLETE_PRICING_ENVS):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    monkeypatch.setenv("VIGIL_CUSTOMER_ASSISTANT", "1")
    monkeypatch.setenv("VIGIL_CUSTOMER_ASSISTANT_WALLET", "1")


def _store() -> SpineStore:
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    s.append(kind="message", source="x", actor="user", payload={"text": "hi"})
    return s


def _org(store, org=ORG, *, credits=100, member=("alice", "operator")):
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(org, org, owner="owner", issued_at=float(next(_iss)))
    if member:
        orgs.grant_membership(org, member[0], member[1], issued_at=float(next(_iss)))
    if credits:
        WalletRegistry(store).grant(org, credits, "trial", entry_id=f"trial:{org}", issued_at=NOW - 10_000)
    return LaunchGate(store)


def _turns(store) -> aw.AssistantTurns:
    return aw.AssistantTurns(LaunchGate(store))


def _exact(store, org=ORG) -> int:
    return WalletRegistry(store).balance(org).exact_available_mc


def _grant(org=ORG, *, slug=None, nonce=None, life=aw.TURN_LIFE_S, at=NOW) -> ModelGrant:
    return ModelGrant(grant_id=new_grant_id(), org_id=org, engagement_slug=slug or aw.assistant_slug(org),
                      nonce=nonce or new_grant_id(), model="claude-opus-4-8", effort="high",
                      cap_nano_usd=500_000_000, not_after=at + life, issued_at=at)


def _use(org, nonce, usage, *, at=NOW + 1):
    """One confirmed response on the turn's meter, priced by the published card — what the gateway writes."""
    m = gw.GrantMeter(config.MODEL_METER_DIR, rate_card=DEFAULT_RATE_CARD)
    g = _grant(org, nonce=nonce, life=86_400, at=at - 60)
    rid, _res, why = m.reserve(g, 10 ** 6, 25_000, now=at)
    assert why == "", why
    m.commit(g, rid, usage, 1, request_id="r", now=at)


CAP = 500_000_000
ROOMY = {"per_hour": 10_000, "per_day": 10_000}                 # money tests: never at the rate limit


def _rv(turns, *, org_id=ORG, nonce, need_mc, now, requester="alice", cap_nano_usd=CAP, **limits):
    """``AssistantTurns.reserve`` as the turn opener calls it (the session requester and the grant's cap)."""
    return turns.reserve(org_id=org_id, nonce=nonce, need_mc=need_mc, now=now, requester=requester,
                         cap_nano_usd=cap_nano_usd, **(limits or ROOMY))


def _reserve(store, org=ORG, *, need_mc=12_345, nonce=None, now=NOW, **limits):
    nonce = nonce or new_grant_id()
    r = _rv(_turns(store), org_id=org, nonce=nonce, need_mc=need_mc, now=now, **limits)
    return r, nonce


def _settled_records(store, org=ORG):
    return [r.payload for r in store.iter_records()
            if isinstance(r.payload, dict) and r.payload.get("signal") == ls.LAUNCH_SETTLED_SIGNAL
            and r.payload.get("org_id") == org]


# ================================================================================================ the turn's slug ==

def test_the_assistant_slug_is_per_org_one_way_and_never_a_launch_slug():
    a, b = aw.assistant_slug(ORG), aw.assistant_slug(OTHER)
    assert a == aw.assistant_slug(ORG) and a != b                        # deterministic, per org
    assert aw.is_assistant_slug(a) and ":" not in a and ORG not in a     # the ledger separator never; names no org
    launch = _customer_slug(ORG, "acme.example")
    assert not aw.is_assistant_slug(launch) and launch != a              # a launch slug is never a turn's
    for bad in (None, "", "asst_", "asst_" + "g" * 24, "asst_" + "a" * 23, "ASST_" + "a" * 24, "cust_" + "a" * 24,
                "assistant:cust_" + "a" * 24):
        assert not aw.is_assistant_slug(bad), bad


def test_the_turn_life_is_the_life_of_the_minted_grant():
    """``TURN_LIFE_S`` (which decides when a turn is stale) is exactly the life the provisioner gives a turn's grant,
    and the metered mint binds the HOLD's slug and nonce (so the gateway checks the request against that hold)."""
    from vigil_core.model_grant import decode_token
    owner = ensure_owner_keypair()

    class _P:
        _mint_assistant_grant = Provisioner._mint_assistant_grant

    nonce = new_grant_id()
    tok = _P()._mint_assistant_grant(ORG, owner, now=NOW, slug=aw.assistant_slug(ORG), nonce=nonce)
    g, why = decode_token(tok, owner.public_key_b64)
    assert g is not None, why
    assert g.not_after - g.issued_at == aw.TURN_LIFE_S
    assert (g.org_id, g.engagement_slug, g.nonce) == (ORG, aw.assistant_slug(ORG), nonce)
    legacy, _ = decode_token(_P()._mint_assistant_grant(ORG, owner, now=NOW), owner.public_key_b64)
    assert legacy.engagement_slug.startswith("assistant:")              # metered billing off: exactly as before


# ======================================================================================================= reserve ==

def test_reserve_holds_the_worst_case_in_whole_credits():
    store = _store()
    _org(store, credits=100)
    before = _exact(store)
    r, nonce = _reserve(store, need_mc=12_001)
    assert r["ok"], r
    assert r["units_reserved"] == 13 and r["allowance_mc"] == 13_000     # rounded UP, never below the worst case
    assert r["slug"] == aw.assistant_slug(ORG) and r["nonce"] == nonce
    assert _exact(store) == before - 13_000
    assert gw.GrantMeter(config.MODEL_METER_DIR).was_metered(meter_id(r["slug"], nonce))


def test_reserve_refuses_when_the_credits_cannot_cover_it_and_holds_nothing():
    store = _store()
    _org(store, credits=5)
    r, _ = _reserve(store, need_mc=5_001)                                  # 6 credits needed, 5 held
    assert not r["ok"] and "insufficient credits" in r["error"]
    assert _exact(store) == 5_000
    r, _ = _reserve(store, need_mc=5_000)                                  # exactly the balance: fits
    assert r["ok"] and _exact(store) == 0


def test_reserve_sizes_from_the_exact_balance():
    """The hold draws from the EXACT balance: whole credits LESS the org's sub-credit remainder (a turn that used
    500 mc leaves 6 credits with a 500 mc remainder — 5.5 credits exactly, so only 5 whole credits may be held)."""
    store = _store()
    _org(store, credits=6)
    turns = _turns(store)
    r, nonce = _reserve(store, need_mc=1_000)
    _use(ORG, nonce, U500)
    s = turns.settle(org_id=ORG, nonce=nonce, now=NOW + 5)
    assert s["ok"] and s["consumed_mc"] == 500 and s["remainder_mc"] == 500, s
    assert WalletRegistry(store).balance(ORG).available == 6 and _exact(store) == 5_500
    r, _ = _reserve(store, need_mc=5_001)                                  # 6 whole credits: past the exact 5.5
    assert not r["ok"] and "insufficient" in r["error"]
    r, _ = _reserve(store, need_mc=5_000)
    assert r["ok"] and _exact(store) == 500


def test_attack_a_replayed_nonce_holds_nothing_twice():
    """Idempotent per grant nonce: replaying a turn's reserve (the same nonce) is refused and moves nothing."""
    store = _store()
    _org(store, credits=50)
    r, nonce = _reserve(store, need_mc=4_000)
    assert r["ok"]
    after_first = _exact(store)
    again = _rv(_turns(store), nonce=nonce, need_mc=4_000, now=NOW + 1)
    assert not again["ok"] and "nonce was already used" in again["error"]
    assert _exact(store) == after_first == 46_000
    # a replay with a different size is the same nonce: still refused, still nothing moved
    again = _rv(_turns(store), nonce=nonce, need_mc=9_000, now=NOW + 2)
    assert not again["ok"] and _exact(store) == 46_000


@pytest.mark.parametrize("need", [0, -1, -10 ** 9, True, False, 1.5, "100", None, aw.MAX_TURN_MC + 1, 10 ** 30])
def test_attack_bad_amounts_are_refused_before_anything_is_held(need):
    store = _store()
    _org(store, credits=50)
    r = _rv(_turns(store), nonce=new_grant_id(), need_mc=need, now=NOW)
    assert not r["ok"] and "need_mc" in r["error"]
    assert _exact(store) == 50_000


@pytest.mark.parametrize("nonce", ["", "x:y", "g" * 32, "a" * 31, "A" * 32, None, 123])
def test_attack_a_malformed_nonce_or_org_is_refused(nonce):
    store = _store()
    _org(store, credits=50)
    r = _rv(_turns(store), nonce=nonce, need_mc=1_000, now=NOW)
    assert not r["ok"] and _exact(store) == 50_000
    r = _rv(_turns(store), org_id="../org_a", nonce=new_grant_id(), need_mc=1_000, now=NOW)
    assert not r["ok"] and _exact(store) == 50_000


def test_attack_racing_turns_never_hold_more_than_the_org_has():
    """Eight turns race for 3 credits each against 10: exactly three hold, the rest are refused, the exact balance
    never goes below zero — the size is decided inside the spine lock and the cross-process settle lock."""
    store = _store()
    _org(store, credits=10)
    results: list = []
    barrier = threading.Barrier(8)

    def go():
        barrier.wait()
        results.append(_rv(_turns(SpineStore(store.path)), nonce=new_grant_id(), need_mc=3_000, now=NOW))

    threads = [threading.Thread(target=go) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    ok = [r for r in results if r.get("ok")]
    assert len(results) == 8 and len(ok) == 3, results
    assert all("insufficient" in r["error"] or r.get("retry") for r in results if not r.get("ok"))
    assert _exact(store) == 1_000


def test_a_billing_hold_refuses_the_turn(monkeypatch):
    store = _store()
    gate = _org(store, credits=50)
    monkeypatch.setattr(LaunchGate, "_billing_hold_refusal", lambda self, oid: "billing is on hold: 7 credits owed")
    r = _rv(aw.AssistantTurns(gate), nonce=new_grant_id(), need_mc=1_000, now=NOW)
    assert not r["ok"] and "billing is on hold" in r["error"]
    assert _exact(store) == 50_000


def test_a_postpaid_org_draws_its_credit_line_and_settles_exactly():
    store = _store()
    _org(store, credits=0)
    PostpaidRegistry(store).set_account(ORG, 20, 30, issued_at=float(next(_iss)))
    arrears = PostpaidArrearsLedger(store)
    r, nonce = _reserve(store, need_mc=7_500)
    assert r["ok"] and arrears.accrued(ORG) == 8                          # drawn from the line, never the wallet
    _use(ORG, nonce, U2502)
    s = _turns(store).settle(org_id=ORG, nonce=nonce, now=NOW + 5)
    assert s["ok"] and s["consumed_mc"] == 2_502 and s["remainder_mc"] == 502, s
    assert arrears.accrued(ORG) == 2                                       # floor(2502/1000): the rest reversed
    r, _ = _reserve(store, need_mc=19_000)                                 # 19 > 20 - 2 - (the remainder)
    assert not r["ok"] and "credit line" in r["error"]


# ===================================================================================================== allowance ==

def test_the_allowance_is_the_turns_own_hold():
    store = _store()
    gate = _org(store, credits=50)
    r, nonce = _reserve(store, need_mc=4_200)
    allowance = LaunchAllowance(gate)
    g = _grant(ORG, nonce=nonce)
    assert allowance.allowance_mc(g) == 5_000
    assert allowance.available_credits(g) == 0                             # never extended
    assert allowance.extend(g, 10) == {"ok": False, "insufficient": True,
                                       "error": "an assistant turn's hold is never extended"}
    assert allowance.note_credit_pause(g, NOW) is True                     # nothing to park
    assert _exact(store) == 45_000                                         # none of it moved anything


def test_attack_a_grant_naming_another_orgs_hold_gets_no_allowance():
    """A cross-org draw: org B's hold can never back a grant for org A — not with B's slug (it is not A's own), not
    with A's slug and B's nonce (no such hold of A), and an unknown nonce backs nothing."""
    store = _store()
    gate = _org(store, ORG, credits=50)
    _org(store, OTHER, credits=50, member=None)
    rb, nonce_b = _reserve(store, OTHER, need_mc=4_000)
    assert rb["ok"]
    allowance = LaunchAllowance(gate)
    assert allowance.allowance_mc(_grant(OTHER, nonce=nonce_b)) == 4_000          # B's own grant: its hold
    assert allowance.allowance_mc(_grant(ORG, slug=aw.assistant_slug(OTHER), nonce=nonce_b)) is None
    assert allowance.allowance_mc(_grant(ORG, nonce=nonce_b)) is None
    assert allowance.allowance_mc(_grant(ORG)) is None                            # no hold at all
    assert allowance.allowance_mc(_grant(ORG, nonce="n-1")) is None               # not a turn nonce
    assert _exact(store, ORG) == 50_000 and _exact(store, OTHER) == 46_000


def test_a_settled_turns_grant_gets_no_allowance():
    store = _store()
    gate = _org(store, credits=50)
    r, nonce = _reserve(store, need_mc=4_000)
    assert _turns(store).settle(org_id=ORG, nonce=nonce, now=NOW + 5)["ok"]
    assert LaunchAllowance(gate).allowance_mc(_grant(ORG, nonce=nonce)) is None


def test_flag_off_an_assistant_grant_takes_the_launch_path(monkeypatch):
    """Byte-identical when off: LaunchAllowance answers an ``asst_`` grant exactly as it did before PR-J2 — no lease
    on the seam, so no allowance (the gateway refuses it) — and its sizing hint is the launch path's (the wallet)."""
    store = _store()
    gate = _org(store, credits=50)
    r, nonce = _reserve(store, need_mc=4_000)
    monkeypatch.delenv("VIGIL_CUSTOMER_ASSISTANT_WALLET")
    allowance = LaunchAllowance(gate)
    g = _grant(ORG, nonce=nonce)
    assert allowance.allowance_mc(g) is None
    assert allowance.available_credits(g) == WalletRegistry(store).balance(ORG).spendable == 46


# ======================================================================================================== settle ==

def test_settle_keeps_the_exact_metered_charge_and_returns_the_rest():
    store = _store()
    _org(store, credits=50)
    before = _exact(store)
    r, nonce = _reserve(store, need_mc=12_345)
    _use(ORG, nonce, U2502)
    s = _turns(store).settle(org_id=ORG, nonce=nonce, now=NOW + 5)
    assert s["ok"] and s["action"] == "launch_settled", s
    assert s["consumed_mc"] == 2_502 and s["remainder_mc"] == 502 and s["refunded"] == 11 and s["net_spend"] == 2
    assert _exact(store) == before - 2_502                                # EXACTLY the metered charge, to the mc
    rec = _settled_records(store)
    assert len(rec) == 1 and rec[0]["v"] == ls.EXACT_RECORD_VERSION and rec[0]["basis"] == aw.SETTLE_BASIS
    assert rec[0]["slug"] == aw.assistant_slug(ORG) and rec[0]["nonce"] == nonce


def test_attack_a_settle_is_exactly_once():
    store = _store()
    _org(store, credits=50)
    r, nonce = _reserve(store, need_mc=12_345)
    _use(ORG, nonce, U2502)
    assert _turns(store).settle(org_id=ORG, nonce=nonce, now=NOW + 5)["ok"]
    after = _exact(store)
    for k in range(3):
        again = _turns(store).settle(org_id=ORG, nonce=nonce, now=NOW + 10 + k)
        assert again["ok"] and again["action"] == "launch_already_settled" and again["refunded"] == 0, again
    assert _exact(store) == after and len(_settled_records(store)) == 1


def test_settle_never_keeps_more_than_the_hold():
    """A response billed past the gateway's worst case is VIGIL's cost: the customer is charged at most the hold."""
    store = _store()
    _org(store, credits=50)
    before = _exact(store)
    r, nonce = _reserve(store, need_mc=3_000)
    _use(ORG, nonce, U_HUGE)
    s = _turns(store).settle(org_id=ORG, nonce=nonce, now=NOW + 5)
    assert s["ok"] and s["consumed_mc"] == 3_000 and s["refunded"] == 0, s
    assert _exact(store) == before - 3_000


def test_a_turn_that_never_reached_the_gateway_is_refunded_in_full():
    store = _store()
    _org(store, credits=50)
    r, nonce = _reserve(store, need_mc=8_000)
    s = _turns(store).settle(org_id=ORG, nonce=nonce, now=NOW + 5)
    assert s["ok"] and s["consumed_mc"] == 0 and s["refunded"] == 8, s
    assert _exact(store) == 50_000


def test_settle_closes_the_meter_so_the_grant_is_dead():
    store = _store()
    _org(store, credits=50)
    r, nonce = _reserve(store, need_mc=8_000)
    mid = meter_id(aw.assistant_slug(ORG), nonce)
    assert not gw.GrantMeter(config.MODEL_METER_DIR).is_closed(mid)
    assert _turns(store).settle(org_id=ORG, nonce=nonce, now=NOW + 5)["ok"]
    assert gw.GrantMeter(config.MODEL_METER_DIR).is_closed(mid)
    # a request on the dead grant is refused by the meter itself
    m = gw.GrantMeter(config.MODEL_METER_DIR, rate_card=DEFAULT_RATE_CARD)
    assert m.reserve(_grant(ORG, nonce=nonce), 10 ** 6, 25_000, now=NOW + 6)[2] == "closed"


def test_settle_writes_nothing_on_the_seam(tmp_path):
    store = _store()
    _org(store, credits=50)
    r, nonce = _reserve(store, need_mc=8_000)
    _use(ORG, nonce, U500)
    assert _turns(store).settle(org_id=ORG, nonce=nonce, now=NOW + 5)["ok"]
    seam = tmp_path / "seam"
    written = [p for p in seam.rglob("*") if p.is_file()] if seam.exists() else []
    assert written == [], written                                          # no marker, no tombstone, no grant file


def test_a_seamless_settle_always_records_its_decision(monkeypatch):
    """Without the seam marker the spine record is the turn's ONLY settlement evidence: a seam=False settle records
    its decision whatever ``VIGIL_SETTLE_SPINE_RECORD`` says, even a non-exact one — so a full-consumption settle
    (nothing refunded, no money entry) can never be settled twice."""
    store = _store()
    gate = _org(store, credits=50)
    r, nonce = _reserve(store, need_mc=3_000)
    slug = aw.assistant_slug(ORG)
    gw.GrantMeter(config.MODEL_METER_DIR).close(meter_id(slug, nonce), now=NOW + 1)
    out = gate._settle_reservation(ORG, slug, nonce, 3, 3, NOW + 2, None, aw.SETTLE_BASIS, seam=False)
    assert out["ok"] and out["refunded"] == 0, out
    assert len(_settled_records(store)) == 1
    again = gate._settle_reservation(ORG, slug, nonce, 3, 0, NOW + 3, None, aw.SETTLE_BASIS, seam=False)
    assert again["action"] == "launch_already_settled" and again["refunded"] == 0
    assert _exact(store) == 47_000


def test_inconsistent_hold_records_refuse_the_settle():
    store = _store()
    _org(store, credits=50)
    assert not _turns(store).settle(org_id=ORG, nonce=new_grant_id(), now=NOW)["ok"]   # no hold at all


# ========================================================================================= turns a crash left behind ==

def test_a_stale_turn_is_settled_by_the_next_and_a_live_one_is_not():
    store = _store()
    _org(store, credits=50)
    turns = _turns(store)
    r, nonce = _reserve(store, need_mc=8_000)
    _use(ORG, nonce, U2502)
    assert turns.stale(now=NOW + 10, org_id=ORG) == []                     # its grant may still be admitted
    late = NOW + aw.TURN_LIFE_S + aw.STALE_GRACE_S + 1
    rows = turns.stale(now=late, org_id=ORG)
    assert [(x["nonce"], x["why"]) for x in rows] == [(nonce, "unsettled")]
    out = turns.settle_stale(org_id=ORG, now=late)
    assert len(out) == 1 and out[0]["result"]["ok"] and out[0]["result"]["consumed_mc"] == 2_502
    assert turns.stale(now=late, org_id=ORG) == [] and _exact(store) == 50_000 - 2_502


def test_an_interrupted_settle_is_finished_from_its_record(monkeypatch):
    """A crash after the settle's decision is recorded but before its refund landed: the turn is listed
    ``settle_interrupted`` and the next settle FINISHES the recorded decision — the refund lands exactly once."""
    store = _store()
    _org(store, credits=50)
    r, nonce = _reserve(store, need_mc=8_000)
    _use(ORG, nonce, U2502)
    real = WalletRegistry.grant

    def boom(self, org_id, credits, kind, **kw):
        if kind == "refund":
            raise OSError("disk gone")
        return real(self, org_id, credits, kind, **kw)

    monkeypatch.setattr(WalletRegistry, "grant", boom)
    s = _turns(store).settle(org_id=ORG, nonce=nonce, now=NOW + 5)
    assert not s["ok"] and s.get("retry"), s
    monkeypatch.setattr(WalletRegistry, "grant", real)
    rows = _turns(store).stale(now=NOW + 6, org_id=ORG)
    assert [x["why"] for x in rows] == ["settle_interrupted"] and rows[0]["pending_wallet"] == 6
    out = _turns(store).settle(org_id=ORG, nonce=nonce, now=NOW + 7)
    assert out["ok"] and out["action"] == "launch_already_settled" and out.get("rolled_forward"), out
    assert _exact(store) == 50_000 - 2_502
    again = _turns(store).settle(org_id=ORG, nonce=nonce, now=NOW + 8)
    assert again["ok"] and not again.get("rolled_forward") and _exact(store) == 50_000 - 2_502


# =========================================================================== the gateway reserves exactly the hold ==

class _Allowance:
    """A fixed allowance source (what the gateway asks of ``LaunchAllowance``), never extended."""

    def __init__(self, mc):
        self.mc = mc

    def allowance_mc(self, grant):
        return self.mc

    def available_credits(self, grant):
        return 0

    def extend(self, grant, credits):
        return {"ok": False, "insufficient": True}

    def note_credit_pause(self, grant, now):
        return True


def _no_proxy(monkeypatch):
    for v in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")


def _start(upstream, allowance, *, owner=None, required=True):
    from test_model_gateway import NO_PROXY, PROVIDER_KEY
    owner = owner or ensure_owner_keypair()
    cfg = gw.GatewayConfig(api_key=PROVIDER_KEY, owner_pubkey=owner.public_key_b64, meter_dir=config.MODEL_METER_DIR,
                           upstream=f"http://127.0.0.1:{upstream.server_address[1]}", opener=NO_PROXY,
                           rate_card=DEFAULT_RATE_CARD, allowance=allowance, allowance_required=required)
    server, _t = gw.start(cfg)
    server.url = f"http://127.0.0.1:{server.server_address[1]}"
    return server


def _stop(*servers):
    for s in servers:
        s.shutdown()
        s.server_close()


def _post(server, raw: bytes, token: str):
    import urllib.error
    import urllib.request
    from test_model_gateway import NO_PROXY
    req = urllib.request.Request(server.url + "/v1/messages", data=raw, method="POST",
                                 headers={"content-type": "application/json", "x-api-key": token,
                                          "anthropic-version": "2023-06-01"})
    try:
        with NO_PROXY.open(req, timeout=20) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def test_plain_request_worst_mc_is_exactly_what_the_gateway_reserves(monkeypatch):
    """The parity the per-turn hold rests on: an allowance of exactly ``plain_request_worst_mc`` for the bytes sent
    admits the request with its ``max_tokens`` intact (the open line's ``reserved_mc`` IS that amount), and one
    milli-credit less is refused with the terminal credit stop — so the hold is never short and never padded."""
    from test_model_gateway import OPUS, _serve, _Upstream
    from vigil_core.model_grant import STOP_CREDITS_EXHAUSTED, STOP_HEADER
    _no_proxy(monkeypatch)
    owner = ensure_owner_keypair()
    body = {"model": OPUS, "max_tokens": 1024, "messages": [{"role": "user", "content": "é" * 900 + "x" * 3000}]}
    raw = json.dumps(body).encode("utf-8")
    worst = gw.plain_request_worst_mc(DEFAULT_RATE_CARD, len(raw), 1024)
    up = _serve(_Upstream)
    for allowance, admitted in ((worst, True), (worst - 1, False)):
        server = _start(up, _Allowance(allowance), owner=owner)
        try:
            g = _grant("org_x", nonce=new_grant_id(), life=3_600, at=time.time() - 60)
            g = g.model_copy(update={"model": OPUS})
            status, headers, out = _post(server, raw, encode_token(g, owner.private_key_b64))
            if admitted:
                assert status == 200, out
                sent = [x for x in up.seen if x["path"].startswith("/v1/messages")][-1]
                assert sent["body"]["max_tokens"] == 1024                       # intact: never lowered
                lines = [json.loads(x) for x in (config.MODEL_METER_DIR / f"{g.meter_id}.jsonl").read_text()
                         .splitlines()]
                assert [ln["reserved_mc"] for ln in lines if ln["kind"] == "open"] == [worst]
            else:
                assert status == 403 and headers.get(STOP_HEADER) == STOP_CREDITS_EXHAUSTED, (status, out)
        finally:
            _stop(server)
    _stop(up)


def test_plain_request_worst_mc_refuses_impossible_sizes():
    for raw_len, mt in ((-1, 1024), (10, gw.MIN_USEFUL_OUTPUT_TOKENS - 1), (True, 1024), (10, 1.0), ("9", 1024)):
        with pytest.raises(ValueError):
            gw.plain_request_worst_mc(DEFAULT_RATE_CARD, raw_len, mt)
    with pytest.raises(ValueError):                                       # a hostile size: the card's own bound
        gw.plain_request_worst_mc(DEFAULT_RATE_CARD, 10 ** 16, 1024)
    assert aw.turn_need_mc(0, 1024) == gw.plain_request_worst_mc(DEFAULT_RATE_CARD, 0, 1024) > 0


# ============================================================================ the provisioner, end to end, metered ==

from http.server import BaseHTTPRequestHandler  # noqa: E402


class _Model(BaseHTTPRequestHandler):
    """A FAKE model behind the real gateway: answers every message with a fixed text and a small, honest usage."""
    protocol_version = "HTTP/1.1"
    USAGE = {"input_tokens": 800, "output_tokens": 120}            # 800 x 1.25 + 120 x 6.25 = 1,750 mc
    CHARGE_MC = 1_750

    def log_message(self, *a):
        return

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("content-length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        self.server.seen.append({"path": self.path, "body": body})
        doc = {"id": "msg_1", "type": "message", "role": "assistant", "model": body.get("model"),
               "stop_reason": "end_turn", "content": [{"type": "text", "text": "Fix the SQL injection first."}],
               "usage": self.USAGE}
        raw = json.dumps(doc).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def _seed_findings(store, org=ORG, host="acme.example"):
    """A proven host and two oracle-confirmed findings for ``org`` (what the assistant grounds on)."""
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    from test_ui_assistant import _finding
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=10.0, ttl_seconds=1e12)
    slug = _customer_slug(org, host)
    _finding(store, slug, "F1")
    _finding(store, slug, "F2", bug_class="sqli")


class _P:
    """A Provisioner double with ONLY what the assistant touches (``store`` / ``orgs``) and the REAL methods bound."""

    def __init__(self, store):
        self.store = store
        self.orgs = OrgRegistry(store, owner_key=ensure_owner_keypair())

    customer_assistant_ask = Provisioner.customer_assistant_ask
    _assistant_ask_accounted = Provisioner._assistant_ask_accounted
    _mint_assistant_grant = Provisioner._mint_assistant_grant
    _audit = Provisioner._audit


@pytest.fixture()
def metered(monkeypatch):
    """The cockpit's wiring in miniature: the REAL gateway, started with the REAL allowance source over the spine
    (``LaunchAllowance(LaunchGate(store))``, metered billing ON so an allowance is REQUIRED), a fake model behind it,
    the provisioner dialling it at ``config.model_gateway_url()``."""
    from test_model_gateway import OPUS, _serve
    _no_proxy(monkeypatch)
    monkeypatch.setenv("VIGIL_ASSISTANT_MODEL", OPUS)
    store = _store()
    _org(store, credits=100)
    _seed_findings(store)
    up = _serve(_Model)
    server = _start(up, LaunchAllowance(LaunchGate(store)))
    monkeypatch.setenv("VIGIL_MODEL_GATEWAY_PORT", str(server.server_address[1]))
    yield store, up, server
    _stop(server, up)


def _sent(up):
    return [x for x in up.seen if x["path"].startswith("/v1/messages")]


def _turn_holds(store, org=ORG):
    from sigil.governor.launch_reservations import scan_reservations
    ix = scan_reservations(store, ensure_owner_keypair().public_key_b64, org_id=org, slug=aw.assistant_slug(org))
    return ix


def test_e2e_a_metered_turn_is_billed_exactly_its_metered_charge(metered):
    store, up, server = metered
    before = _exact(store)
    out = _P(store).customer_assistant_ask("alice", ORG, "what should I fix first?", ip="1.2.3.4")
    assert out["kind"] == "assistant_advice" and out["answer"] == "Fix the SQL injection first."
    assert set(out["grounded_in"]) == {"F1", "F2"}
    assert not any(k in out for k in ("credits", "amount_mc", "cost", "model"))   # no cost, no model in the reply
    assert len(_sent(up)) == 1
    assert _exact(store) == before - _Model.CHARGE_MC                      # EXACTLY the metered charge, to the mc
    ix = _turn_holds(store)
    (res,) = ix.reservations.values()
    assert res.key in ix.settled                                           # the turn settled itself
    assert gw.GrantMeter(config.MODEL_METER_DIR).is_closed(meter_id(res.slug, res.nonce))
    rec = _settled_records(store)
    assert len(rec) == 1 and rec[0]["consumed_mc"] == _Model.CHARGE_MC and rec[0]["basis"] == "assistant"


def test_e2e_a_replayed_turn_grant_is_refused_after_the_settle(metered):
    """Double-spend a turn's grant: once the turn settled, a request on its (slug, nonce) — even freshly owner-signed
    — is refused by the gateway (the meter is closed and the hold is settled), and nothing more is charged."""
    store, up, server = metered
    _P(store).customer_assistant_ask("alice", ORG, "what should I fix first?", ip="1.2.3.4")
    (res,) = _turn_holds(store).reservations.values()
    after = _exact(store)
    owner = ensure_owner_keypair()
    from test_model_gateway import OPUS
    g = _grant(ORG, nonce=res.nonce, life=aw.TURN_LIFE_S, at=time.time() - 5).model_copy(update={"model": OPUS})
    raw = json.dumps({"model": OPUS, "max_tokens": 1024, "messages": [{"role": "user", "content": "again"}]}).encode()
    status, _h, _b = _post(server, raw, encode_token(g, owner.private_key_b64))
    assert status in (403, 529) and len(_sent(up)) == 1                   # refused: the provider saw one request
    assert _exact(store) == after


def test_e2e_insufficient_credits_sends_no_request(metered):
    store, up, server = metered
    gate = LaunchGate(store)
    # leave the org 1 credit: far below any turn's worst case
    WalletRegistry(store).debit(ORG, 99, entry_id="drain", issued_at=NOW)
    with pytest.raises(ProvisionDenied) as e:
        _P(store).customer_assistant_ask("alice", ORG, "what should I fix first?", ip="1.2.3.4")
    assert "insufficient credits" in str(e.value)
    assert _sent(up) == []                                                 # NO model request was made
    assert _exact(store) == 1_000 and not _turn_holds(store).reservations  # nothing held
    assert gate.wallet.balance(ORG).available == 1


def test_e2e_a_failed_call_is_refunded_in_full(metered, monkeypatch):
    """The gateway cannot be reached: the turn fails closed (no answer), and its hold is settled with nothing
    charged — never a charge the meter cannot prove."""
    from sigil.ui.assistant import AssistantError
    store, up, server = metered
    monkeypatch.setenv("VIGIL_MODEL_GATEWAY_PORT", "1")                   # nothing listens there
    with pytest.raises(AssistantError):
        _P(store).customer_assistant_ask("alice", ORG, "what should I fix first?", ip="1.2.3.4")
    ix = _turn_holds(store)
    (res,) = ix.reservations.values()
    assert res.key in ix.settled and _exact(store) == 100_000              # held, then returned in full
    assert _sent(up) == []


def test_e2e_a_non_member_draws_nothing(metered):
    """Cross-org / IDOR: a requester who is not a member of the org is refused before anything is held — the org is
    the hop-bound session's, and the wallet drawn is always that org's."""
    store, up, server = metered
    _org(store, OTHER, credits=100, member=("mallory", "operator"))
    with pytest.raises(ProvisionDenied):
        _P(store).customer_assistant_ask("mallory", ORG, "what should I fix first?", ip="1.2.3.4")
    assert _exact(store, ORG) == 100_000 and _exact(store, OTHER) == 100_000 and _sent(up) == []
    # mallory's own org pays for mallory's own turn — never ORG's wallet
    _P(store).customer_assistant_ask("mallory", OTHER, "what should I fix first?", ip="1.2.3.4")
    assert _exact(store, ORG) == 100_000 and _exact(store, OTHER) == 100_000 - _Model.CHARGE_MC


def test_e2e_the_gateway_forgets_a_settled_turn(metered, monkeypatch):
    """One meter per turn must not grow the cockpit's gateway memory: after the turn's settle the gateway running in
    this process drops the closed meter's state, its allowance cache and its lock — and a replay is still refused."""
    store, up, server = metered
    monkeypatch.setitem(gw._RUNNING, "test", server)
    _P(store).customer_assistant_ask("alice", ORG, "what should I fix first?", ip="1.2.3.4")
    (res,) = _turn_holds(store).reservations.values()
    mid = meter_id(res.slug, res.nonce)
    g = server.gateway
    assert mid not in g.meter._states and mid not in g._allowances and mid not in g._extend_locks
    assert g.forget_meter(mid) is False                                    # already gone: nothing to drop
    owner = ensure_owner_keypair()
    from test_model_gateway import OPUS
    tok = encode_token(_grant(ORG, nonce=res.nonce, at=time.time() - 5).model_copy(update={"model": OPUS}),
                       owner.private_key_b64)
    raw = json.dumps({"model": OPUS, "max_tokens": 1024, "messages": [{"role": "user", "content": "x"}]}).encode()
    assert _post(server, raw, tok)[0] == 403 and len(_sent(up)) == 1


def test_forget_keeps_an_open_meter():
    m = gw.GrantMeter(config.MODEL_METER_DIR, rate_card=DEFAULT_RATE_CARD)
    g = _grant(ORG, life=86_400, at=NOW - 60)
    rid, _r, why = m.reserve(g, 10 ** 6, 25_000, now=NOW)
    assert why == ""
    assert m.forget(g.meter_id) is False                                   # a request in flight: kept
    m.commit(g, rid, U500, 1, request_id="r", now=NOW)
    assert m.forget(g.meter_id) is False                                   # settled but not closed: kept
    gw.GrantMeter(config.MODEL_METER_DIR).close(g.meter_id, now=NOW + 1)
    assert m.forget(g.meter_id) is True and g.meter_id not in m._states    # closed elsewhere: dropped
    assert m.reserve(g, 10 ** 6, 25_000, now=NOW + 2)[2] == "closed"       # re-read from disk: still refused


def test_flag_off_metered_on_is_refused_exactly_as_before(metered, monkeypatch):
    store, up, server = metered
    monkeypatch.delenv("VIGIL_CUSTOMER_ASSISTANT_WALLET")
    with pytest.raises(ProvisionDenied) as e:
        _P(store).customer_assistant_ask("alice", ORG, "what should I fix first?", ip="1.2.3.4")
    assert str(e.value) == "the assistant is not yet available while metered billing is enabled"
    assert _sent(up) == [] and _exact(store) == 100_000 and not _turn_holds(store).reservations


def test_e2e_a_stale_turn_is_settled_before_the_next_is_sized(metered):
    """A crash left a turn held (its usage metered, never settled): the org's next turn settles it first — the
    customer pays exactly the two metered charges, and nothing stays held."""
    store, up, server = metered
    r, nonce = _reserve(store, need_mc=20_000, now=time.time() - aw.TURN_LIFE_S - aw.STALE_GRACE_S - 5)
    assert r["ok"]
    _use(ORG, nonce, U2502, at=time.time() - aw.TURN_LIFE_S - aw.STALE_GRACE_S)
    _P(store).customer_assistant_ask("alice", ORG, "what should I fix first?", ip="1.2.3.4")
    ix = _turn_holds(store)
    assert len(ix.reservations) == 2 and all(k in ix.settled for k in ix.reservations)
    assert _exact(store) == 100_000 - 2_502 - _Model.CHARGE_MC


# ================================================================================================= the statement ==

def _usage(store, org=ORG, *, now=NOW + 50_000):
    return ui_billing.billing_usage(store, org, trusted_pubkey=ensure_owner_keypair().public_key_b64,
                                    meter_dir=config.MODEL_METER_DIR, now=now)


def test_statement_lists_the_turn_as_a_security_assistant_line():
    store = _store()
    _org(store, credits=50)
    r, nonce = _reserve(store, need_mc=8_000)
    _use(ORG, nonce, U2502)
    assert _turns(store).settle(org_id=ORG, nonce=nonce, now=NOW + 5)["ok"]
    WalletRegistry(store).grant(ORG, 10, "topup", entry_id="topup-1", issued_at=NOW + 10)
    u = _usage(store)
    assert u["scans"] == []                                                # a turn is never a scan
    (charge,) = u["charges"]
    assert charge["operation"] == aw.STATEMENT_OPERATION == "Security assistant" and charge["source"] == "assistant"
    assert charge["amount_mc"] == 2_502 and charge["credits"] == "2.502"
    assert sum(ln["amount_mc"] for ln in charge["lines"]) == 2_502         # the lines add up to the charge
    assert u["assistant"] == {"turns": 1, "requests": 1, "credits": "2.502", "amount_mc": 2_502, "running": 0,
                              "held_mc": 0}
    assert u["credits"] == "2.502" and u["count"] == 1
    # I4: the balance-after timeline reconciles to the wallet's exact balance, the turn's charge included
    assert charge["balance_after_mc"] == 50_000 - 2_502
    assert u["remaining_mc"] == u["available_to_start_mc"] == _exact(store) == 60_000 - 2_502


def test_statement_holds_a_running_turn():
    store = _store()
    _org(store, credits=50)
    r, nonce = _reserve(store, need_mc=8_000)
    _use(ORG, nonce, U500)
    u = _usage(store)
    assert u["assistant"]["running"] == 1 and u["assistant"]["held_mc"] == 8_000 - 500
    assert u["held_mc"] == 7_500 and u["available_to_start_mc"] == u["remaining_mc"] - 7_500
    assert u["scans"] == []


def test_statement_never_shows_another_orgs_turn():
    store = _store()
    _org(store, ORG, credits=50)
    _org(store, OTHER, credits=50, member=None)
    r, nonce = _reserve(store, OTHER, need_mc=8_000)
    _use(OTHER, nonce, U2502)
    assert _turns(store).settle(org_id=OTHER, nonce=nonce, now=NOW + 5)["ok"]
    u = _usage(store, ORG)
    assert u["charges"] == [] and u["assistant"]["turns"] == 0 and u["amount_mc"] == 0


def test_statement_flag_off_is_the_pre_pr_projection(monkeypatch):
    """Byte-identical when off: no ``assistant`` block, no ``source`` key, the pre-PR operation name — a turn's
    reservation projects exactly as the pre-PR statement projected any reservation."""
    store = _store()
    _org(store, credits=50)
    r, nonce = _reserve(store, need_mc=8_000)
    _use(ORG, nonce, U2502)
    assert _turns(store).settle(org_id=ORG, nonce=nonce, now=NOW + 5)["ok"]
    monkeypatch.delenv("VIGIL_CUSTOMER_ASSISTANT_WALLET")
    u = _usage(store)
    assert "assistant" not in u
    (charge,) = u["charges"]
    assert "source" not in charge and charge["operation"] == "AI analysis"
    assert [s["scan"] for s in u["scans"]] == [aw.assistant_slug(ORG)]


# ===================================================================================================== the sweep ==

def test_the_reservation_sweep_lists_and_settles_a_stale_turn(monkeypatch):
    from sigil import ops_sweeps
    store = _store()
    gate = _org(store, credits=50)
    r, nonce = _reserve(store, need_mc=8_000)
    _use(ORG, nonce, U2502)
    late = NOW + aw.TURN_LIFE_S + aw.STALE_GRACE_S + 1
    assert ops_sweeps.sweep_assistant_turns(gate, now=NOW + 1)["items"] == []          # still within its life
    (row,) = ops_sweeps.sweep_assistant_turns(gate, now=late)["items"]
    assert row["status"] == "assistant_unsettled" and row["nonce"] == nonce and row["units_reserved"] == 8
    assert _exact(store) == 42_000                                                   # a report moves nothing
    (row,) = ops_sweeps.sweep_assistant_turns(gate, now=late, apply=True)["items"]
    assert row["status"] == "assistant_settled" and row["consumed_mc"] == 2_502 and row["refunded"] == 6
    assert ops_sweeps.sweep_assistant_turns(gate, now=late, apply=True)["items"] == []
    assert _exact(store) == 50_000 - 2_502
    # off: no assistant leg at all
    monkeypatch.delenv("VIGIL_CUSTOMER_ASSISTANT_WALLET")
    r2, _n2 = _reserve(store, need_mc=1_000)
    assert ops_sweeps.sweep_assistant_turns(gate, now=late + 10_000, apply=True) == {"applied": True, "items": []}


def test_the_superseded_sweep_never_touches_a_turn():
    """A turn is not a launch: the E7 superseded-reservation sweep skips every assistant turn (they are later
    reservations of one slug with no lease on the seam — exactly what it would otherwise release in full)."""
    from sigil import ops_sweeps
    store = _store()
    gate = _org(store, credits=50)
    for _ in range(2):
        _reserve(store, need_mc=1_000)
    week = NOW + 9 * 86_400
    out = ops_sweeps.sweep_superseded_reservations(gate, now=week, ttl_s=0, apply=False)
    assert out["items"] == []
    assert _exact(store) == 48_000


# ========================================================================================== the customer app (SPA) ==

def test_the_usage_card_shows_what_the_assistant_used_only_when_present():
    from test_customer_billing_dashboard import _node, _render_fns
    base = {"credits": "4.252", "amount_mc": 4252, "held_mc": 0, "available_to_start_mc": 1000}
    out = _node(_render_fns(), "out.on = billingUsageCard(" + json.dumps(
        {**base, "assistant": {"turns": 2, "requests": 2, "credits": "2.502", "amount_mc": 2502}})
        + ").textContent; out.off = billingUsageCard(" + json.dumps(base) + ").textContent;")
    assert "Security assistant2.502" in out["on"] and "Credits used4.252" in out["on"]
    assert "Security assistant" not in out["off"] and "Credits used4.252" in out["off"]


# ============================================================== the turn ledger: audit record + rate limit + budget ==

def _ledger(store) -> at.AssistantTurnLedger:
    return at.AssistantTurnLedger(store, owner_key=ensure_owner_keypair())


def _turn(led, org=ORG, *, now=NOW, nonce=None, requester="alice", mode="flat", cap=CAP, hold=0):
    return led.record(org, nonce=nonce or new_grant_id(), requester=requester, mode=mode, cap_nano_usd=cap,
                      hold_mc=hold, now=now)


def _provision_audits(store, org=ORG):
    return [r.payload for r in store.iter_records()
            if isinstance(r.payload, dict) and r.payload.get("signal") == "provision.audit"
            and r.payload.get("action") == "assistant_ask" and r.payload.get("org_id") == org]


def test_the_turn_ledger_writes_an_owner_signed_audit_record_of_who_asked():
    store = _store()
    _org(store)
    led = _ledger(store)
    nonce = new_grant_id()
    seq = _turn(led, nonce=nonce, mode="metered", hold=13_000)
    (rec,) = [r for r in store.iter_records() if r.seq == seq]
    assert (rec.kind, rec.source) == ("event", "governor")
    p = rec.payload
    assert {k: p[k] for k in ("signal", "v", "org_id", "nonce", "requester", "mode", "cap_nano_usd", "hold_mc",
                              "issued_at")} == {
        "signal": at.SIGNAL, "v": at.RECORD_VERSION, "org_id": ORG, "nonce": nonce, "requester": "alice",
        "mode": "metered", "cap_nano_usd": CAP, "hold_mc": 13_000, "issued_at": NOW}
    assert p["sig"] and p["pubkey"] == ensure_owner_keypair().public_key_b64
    (t,) = led.turns(ORG)
    assert (t.nonce, t.requester, t.mode, t.cap_nano_usd, t.hold_mc, t.issued_at) == (
        nonce, "alice", "metered", CAP, 13_000, NOW)


@pytest.mark.parametrize("bad", [
    {"org_id": "../org_a"}, {"nonce": "n-1"}, {"nonce": "A" * 32}, {"requester": ""}, {"requester": "a b"},
    {"requester": "x" * 65}, {"mode": "free"}, {"cap_nano_usd": -1}, {"cap_nano_usd": True},
    {"cap_nano_usd": at.MAX_CAP_NANO_USD + 1}, {"hold_mc": -5}, {"hold_mc": 1.5}, {"mode": "flat", "hold_mc": 1},
    {"now": float("nan")}, {"now": float("inf")}, {"now": -1.0}, {"now": True}])
def test_attack_a_malformed_turn_record_is_refused_and_nothing_is_written(bad):
    store = _store()
    _org(store)
    led = _ledger(store)
    args = {"org_id": ORG, "nonce": new_grant_id(), "requester": "alice", "mode": "metered", "cap_nano_usd": CAP,
            "hold_mc": 1_000, "now": NOW, **bad}
    before = sum(1 for _ in store.iter_records())
    with pytest.raises(ValueError):
        led.record(args.pop("org_id"), **args)
    assert sum(1 for _ in store.iter_records()) == before


def test_attack_a_forged_foreign_or_tampered_turn_record_is_inert():
    """Only owner-signed, governor-written records count: one signed by another key, one the owner signed but that a
    non-governor path appended, and one whose signed core was edited neither fill a slot nor show in the audit trail."""
    from sigil.governor.authn import signed_payload
    from sigil.reuse import generate_keypair
    store = _store()
    _org(store)
    led = _ledger(store)

    def core():
        return {"signal": at.SIGNAL, "v": 1, "org_id": ORG, "nonce": new_grant_id(), "requester": "mallory",
                "mode": "flat", "cap_nano_usd": 1, "hold_mc": 0, "issued_at": NOW}

    store.append(kind="event", source="governor", actor="WARDEN", payload=signed_payload(core(), generate_keypair()))
    store.append(kind="event", source="provision", actor="WARDEN",
                 payload=signed_payload(core(), ensure_owner_keypair()))
    store.append(kind="event", source="governor", actor="WARDEN",
                 payload={**signed_payload(core(), ensure_owner_keypair()), "requester": "eve"})
    assert led.turns(ORG) == []
    assert led.refusal(ORG, now=NOW, per_hour=1, per_day=1) is None


def test_a_re_recorded_nonce_counts_once():
    store = _store()
    _org(store)
    led = _ledger(store)
    nonce = new_grant_id()
    _turn(led, nonce=nonce)
    _turn(led, nonce=nonce, now=NOW + 1)
    assert len(led.turns(ORG)) == 1
    assert led.refusal(ORG, now=NOW + 2, per_hour=2, per_day=2) is None


def test_the_hourly_rate_limit_and_the_daily_budget_windows():
    store = _store()
    _org(store)
    led = _ledger(store)
    for k in range(3):                                               # NOW, NOW+100, NOW+200
        _turn(led, now=NOW + 100 * k)
    r = led.refusal(ORG, now=NOW + 300, per_hour=3, per_day=50)
    assert (r.window, r.used, r.limit) == ("hour", 3, 3)
    assert r.retry_after == pytest.approx(3600 - 300)                # the oldest leaves the hour then
    assert "3 questions per hour" in r.message
    assert led.refusal(ORG, now=NOW + 300, per_hour=4, per_day=50) is None
    r = led.refusal(ORG, now=NOW + 300, per_hour=2, per_day=50)      # 3 in a window of 2: the 2nd oldest frees it
    assert r.retry_after == pytest.approx(100 + 3600 - 300)
    assert led.refusal(ORG, now=NOW + 3600, per_hour=3, per_day=50) is None          # NOW has left the hour
    r = led.refusal(ORG, now=NOW + 7200, per_hour=10, per_day=3)
    assert (r.window, r.used) == ("day", 3) and r.retry_after == pytest.approx(86400 - 7200)
    assert led.refusal(ORG, now=NOW + 86400, per_hour=10, per_day=3) is None         # NOW has left the day
    r = led.refusal(ORG, now=NOW + 300, per_hour=3, per_day=3)       # both full: the longer wait wins
    assert r.window == "day"
    assert led.refusal(ORG, now=NOW - 10_000, per_hour=3, per_day=50).window == "hour"   # a clock step back frees nothing
    for bad in ((0, 1), (1, 0), (-1, 5), (True, 5), (1.5, 5)):
        with pytest.raises(ValueError):
            led.refusal(ORG, now=NOW, per_hour=bad[0], per_day=bad[1])


def test_the_limits_are_per_org():
    store = _store()
    _org(store, ORG)
    _org(store, OTHER, member=None)
    led = _ledger(store)
    for _ in range(2):
        _turn(led, OTHER)
    assert led.refusal(OTHER, now=NOW + 1, per_hour=2, per_day=9).window == "hour"
    assert led.refusal(ORG, now=NOW + 1, per_hour=2, per_day=9) is None and led.turns(ORG) == []


def test_the_turn_limits_config_is_bounded_and_never_unlimited(monkeypatch):
    assert (config.assistant_turns_per_hour(), config.assistant_turns_per_day()) == (20, 100)
    for raw in ("0", "-3", "junk", "1e9", "100001"):
        monkeypatch.setenv("VIGIL_ASSISTANT_TURNS_PER_HOUR", raw)
        monkeypatch.setenv("VIGIL_ASSISTANT_TURNS_PER_DAY", raw)
        assert (config.assistant_turns_per_hour(), config.assistant_turns_per_day()) == (20, 100)
    monkeypatch.setenv("VIGIL_ASSISTANT_TURNS_PER_HOUR", "7")
    monkeypatch.setenv("VIGIL_ASSISTANT_TURNS_PER_DAY", "70")
    assert (config.assistant_turns_per_hour(), config.assistant_turns_per_day()) == (7, 70)


# ============================================================================ the admission, in both billing modes ==

def test_a_metered_reserve_writes_the_audit_record_before_the_hold():
    store = _store()
    _org(store, credits=50)
    r, nonce = _reserve(store, need_mc=12_001)
    assert r["ok"]
    (t,) = _ledger(store).turns(ORG)
    assert (t.nonce, t.requester, t.mode, t.hold_mc, t.cap_nano_usd) == (nonce, "alice", "metered", 13_000, CAP)
    (res,) = _turn_holds(store).reservations.values()
    assert t.seq < res.seq                                            # the record precedes the hold


def test_a_metered_turn_at_the_rate_limit_holds_nothing():
    store = _store()
    _org(store, credits=50)
    for _ in range(2):
        assert _reserve(store, need_mc=1_000, per_hour=2, per_day=50)[0]["ok"]
    r, _n = _reserve(store, need_mc=1_000, per_hour=2, per_day=50)
    assert not r["ok"] and r["rate_limited"] and r["window"] == "hour" and r["retry_after"] > 0
    assert _exact(store) == 48_000 and len(_ledger(store).turns(ORG)) == 2      # nothing held, nothing recorded
    assert len(_turn_holds(store).reservations) == 2


def test_insufficient_credits_write_no_audit_record():
    store = _store()
    _org(store, credits=2)
    r, _n = _reserve(store, need_mc=5_000)
    assert not r["ok"] and "insufficient" in r["error"]
    assert _ledger(store).turns(ORG) == []                           # a refused turn is not a turn


def test_admit_flat_audits_and_draws_nothing():
    store = _store()
    _org(store, credits=50)
    turns = _turns(store)
    nonce = new_grant_id()
    r = turns.admit_flat(org_id=ORG, nonce=nonce, requester="alice", cap_nano_usd=CAP, now=NOW, **ROOMY)
    assert r == {"ok": True, "action": "assistant_turn_admitted", "org_id": ORG, "nonce": nonce}
    (t,) = _ledger(store).turns(ORG)
    assert (t.nonce, t.mode, t.hold_mc) == (nonce, "flat", 0)
    assert _exact(store) == 50_000 and not _turn_holds(store).reservations
    for bad in ({"org_id": "../x"}, {"nonce": "n-1"}, {"requester": "a b"}, {"cap_nano_usd": -1}, {"now": "soon"}):
        args = {"org_id": ORG, "nonce": new_grant_id(), "requester": "alice", "cap_nano_usd": CAP, "now": NOW,
                **ROOMY, **bad}
        assert not turns.admit_flat(**args)["ok"]
    assert len(_ledger(store).turns(ORG)) == 1


@pytest.mark.parametrize("metered", [False, True], ids=["flat", "metered"])
def test_attack_racing_turns_never_pass_the_rate_limit(metered):
    """Eight turns race an hourly limit of 3, in each billing mode: exactly three are admitted — the count and the
    audit record are one critical section (the spine lock + the cross-process settle lock)."""
    store = _store()
    _org(store, credits=100)
    results: list = []
    barrier = threading.Barrier(8)

    def go():
        turns = _turns(SpineStore(store.path))
        barrier.wait()
        if metered:
            results.append(_rv(turns, nonce=new_grant_id(), need_mc=1_000, now=NOW, per_hour=3, per_day=50))
        else:
            results.append(turns.admit_flat(org_id=ORG, nonce=new_grant_id(), requester="alice", cap_nano_usd=CAP,
                                            now=NOW, per_hour=3, per_day=50))

    threads = [threading.Thread(target=go) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    ok = [r for r in results if r.get("ok")]
    assert len(results) == 8 and len(ok) == 3, results
    assert all(r.get("rate_limited") for r in results if not r.get("ok")), results
    assert len(_ledger(store).turns(ORG)) == 3
    assert _exact(store) == (97_000 if metered else 100_000)


def test_a_grant_that_cannot_be_minted_returns_the_hold_at_once():
    store = _store()
    _org(store, credits=50)

    def mint(**kw):
        raise RuntimeError("the vault is locked")

    open_turn = aw.turn_opener(LaunchGate(store), org_id=ORG, requester="alice", mint=mint, metered=True)
    with pytest.raises(RuntimeError):
        open_turn(b"x" * 100, 1024)
    ix = _turn_holds(store)
    (res,) = ix.reservations.values()
    assert res.key in ix.settled and _exact(store) == 50_000


def test_the_turn_opener_refuses_an_unpriceable_request_before_anything_is_held():
    store = _store()
    _org(store, credits=50)
    open_turn = aw.turn_opener(LaunchGate(store), org_id=ORG, requester="alice",
                               mint=lambda **kw: pytest.fail("never minted"), metered=True)
    with pytest.raises(aw.TurnRefused):
        open_turn(b"x" * 100, gw.MIN_USEFUL_OUTPUT_TOKENS - 1)
    assert _exact(store) == 50_000 and _ledger(store).turns(ORG) == [] and not _turn_holds(store).reservations


# ===================================================================== the accounted dial (assistant.py, PR-J2) ==

class _Resp:
    def __init__(self, doc):
        self._raw = json.dumps(doc).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._raw


class _Opener:
    def __init__(self, doc=None, exc=None):
        self.sent: list = []
        self.doc, self.exc = doc or {"content": [{"type": "text", "text": "ok"}]}, exc

    def open(self, req, timeout):
        self.sent.append(req)
        if self.exc is not None:
            raise self.exc
        return _Resp(self.doc)


def test_the_accounted_dial_sends_nothing_when_the_turn_is_refused():
    from sigil.ui import assistant as asst
    opener = _Opener()

    def refuse(raw, mt):
        raise aw.TurnRefused("no")

    call = asst.accounted_gateway_model_call(gateway_url="http://127.0.0.1:9", open_turn=refuse, opener=opener)
    with pytest.raises(aw.TurnRefused):
        call({"model": "m", "max_tokens": 10, "messages": []})
    assert opener.sent == []


def test_the_accounted_dial_sends_exactly_the_bytes_it_admitted_and_closes_the_turn():
    from sigil.ui import assistant as asst
    seen: dict = {}
    closed: list = []

    def admit(raw, mt):
        seen.update(raw=raw, mt=mt)
        return "tok", lambda: closed.append(1)

    opener = _Opener()
    call = asst.accounted_gateway_model_call(gateway_url="http://127.0.0.1:9", open_turn=admit,
                                             min_output_tokens=1024, opener=opener)
    out = call({"model": "m", "max_tokens": 100, "messages": []})
    assert out["content"][0]["text"] == "ok" and closed == [1]
    (req,) = opener.sent
    assert req.data == seen["raw"] and req.get_header("X-api-key") == "tok"
    assert seen["mt"] == 1024 and json.loads(seen["raw"])["max_tokens"] == 1024     # raised to the least admitted
    call2 = asst.accounted_gateway_model_call(gateway_url="http://127.0.0.1:9", open_turn=admit, opener=opener)
    call2({"model": "m", "max_tokens": 100, "messages": []})
    assert seen["mt"] == 100                                          # no floor: the request's own bound


def test_the_accounted_dial_closes_the_turn_when_the_gateway_fails():
    import urllib.error
    from sigil.ui import assistant as asst
    closed: list = []
    opener = _Opener(exc=urllib.error.URLError("down"))
    call = asst.accounted_gateway_model_call(gateway_url="http://127.0.0.1:9",
                                             open_turn=lambda raw, mt: ("tok", lambda: closed.append(1)),
                                             opener=opener)
    with pytest.raises(asst.AssistantError):
        call({"model": "m", "max_tokens": 10, "messages": []})
    assert closed == [1] and len(opener.sent) == 1


def test_the_accounted_dial_is_loopback_only_and_needs_an_output_bound():
    from sigil.ui import assistant as asst
    for url in ("https://api.anthropic.com", "http://10.0.0.1:8742"):
        with pytest.raises(asst.AssistantError):
            asst.accounted_gateway_model_call(gateway_url=url, open_turn=lambda raw, mt: ("t", None))
    with pytest.raises(asst.AssistantError):
        asst.accounted_gateway_model_call(gateway_url="http://127.0.0.1:9", open_turn=lambda r, m: ("t", None),
                                          min_output_tokens=-1)
    call = asst.accounted_gateway_model_call(gateway_url="http://127.0.0.1:9",
                                             open_turn=lambda raw, mt: pytest.fail("never admitted"))
    for bad in ({"max_tokens": "9"}, {"max_tokens": True}, {"max_tokens": 0}, {}):
        with pytest.raises(asst.AssistantError):
            call({"model": "m", "messages": [], **bad})


# ======================================================================= the provisioner, end to end, accounted ==

def test_e2e_a_metered_turn_carries_its_audit_record(metered):
    store, up, server = metered
    _P(store).customer_assistant_ask("alice", ORG, "what should I fix first?", ip="1.2.3.4")
    (t,) = _ledger(store).turns(ORG)
    (res,) = _turn_holds(store).reservations.values()
    (settled,) = _settled_records(store)
    assert (t.requester, t.mode, t.nonce) == ("alice", "metered", res.nonce) and settled["nonce"] == t.nonce
    assert t.hold_mc == MC_PER_CREDIT * res.reserved and t.cap_nano_usd == config.assistant_cap_nano_usd()


def test_e2e_the_org_rate_limit_refuses_a_turn_with_nothing_held_or_sent(metered, monkeypatch):
    store, up, server = metered
    monkeypatch.setenv("VIGIL_ASSISTANT_TURNS_PER_HOUR", "2")
    for _ in range(2):
        _P(store).customer_assistant_ask("alice", ORG, "what should I fix first?", ip="1.2.3.4")
    before = _exact(store)
    with pytest.raises(ProvisionRateLimited) as e:
        _P(store).customer_assistant_ask("alice", ORG, "what should I fix first?", ip="1.2.3.4")
    assert 0 < e.value.retry_after <= 3600
    assert len(_sent(up)) == 2 and _exact(store) == before and len(_turn_holds(store).reservations) == 2
    assert [t.requester for t in _ledger(store).turns(ORG)] == ["alice", "alice"]
    (refusal,) = _provision_audits(store)
    assert (refusal["requester"], refusal["outcome"], refusal["reason"]) == ("alice", "refused", "rate_limited")
    # another org is never limited by this one's turns
    _org(store, OTHER, credits=100, member=("bob", "operator"))
    _P(store).customer_assistant_ask("bob", OTHER, "what should I fix first?", ip="1.2.3.4")
    assert len(_sent(up)) == 3


@pytest.fixture()
def flat(monkeypatch):
    """A FLAT-billed deployment (metered billing off) with the assistant wallet flag on: the REAL gateway (no allowance
    required), a fake model behind it, the provisioner dialling it."""
    from test_model_gateway import OPUS, _serve
    _no_proxy(monkeypatch)
    monkeypatch.delenv("VIGIL_METERED_BILLING")
    monkeypatch.setenv("VIGIL_ASSISTANT_MODEL", OPUS)
    store = _store()
    _org(store, credits=100)
    _seed_findings(store)
    up = _serve(_Model)
    server = _start(up, None, required=False)
    monkeypatch.setenv("VIGIL_MODEL_GATEWAY_PORT", str(server.server_address[1]))
    yield store, up, server
    _stop(server, up)


def test_e2e_a_flat_turn_is_audited_metered_and_draws_nothing(flat):
    store, up, server = flat
    out = _P(store).customer_assistant_ask("alice", ORG, "what should I fix first?", ip="1.2.3.4")
    assert out["kind"] == "assistant_advice" and out["answer"] == "Fix the SQL injection first."
    assert _exact(store) == 100_000 and not _turn_holds(store).reservations      # flat: nothing drawn
    (t,) = _ledger(store).turns(ORG)
    assert (t.requester, t.mode, t.hold_mc, t.cap_nano_usd) == ("alice", "flat", 0, config.assistant_cap_nano_usd())
    # the request the gateway metered ran on exactly the audited grant (the org's assistant meter, the record's nonce)
    slug = "assistant:" + _customer_slug(ORG, "__assistant__")
    assert gw.GrantMeter(config.MODEL_METER_DIR).totals(meter_id(slug, t.nonce)).requests == 1
    (sent,) = _sent(up)
    assert sent["body"]["max_tokens"] == config.assistant_max_tokens()


def test_attack_a_zero_credit_flat_org_cannot_spend_unbounded(flat, monkeypatch):
    """The PR-J red-pen repro: an org with NO credits on a flat deployment asked turn after turn, each a paid provider
    request. With the assistant accounted, its daily turn budget bounds it — and so what it can cost VIGIL in a day is
    at most the budget times the grant's cap."""
    store, up, server = flat
    WalletRegistry(store).debit(ORG, 100, entry_id="drain", issued_at=NOW)
    monkeypatch.setenv("VIGIL_ASSISTANT_TURNS_PER_DAY", "3")
    for _ in range(3):
        _P(store).customer_assistant_ask("alice", ORG, "what should I fix first?", ip="1.2.3.4")
    for _ in range(2):
        with pytest.raises(ProvisionRateLimited):
            _P(store).customer_assistant_ask("alice", ORG, "what should I fix first?", ip="1.2.3.4")
    assert len(_sent(up)) == 3                                        # the provider saw exactly the budget
    turns = _ledger(store).turns(ORG)
    assert len(turns) == 3 and sum(t.cap_nano_usd for t in turns) == 3 * config.assistant_cap_nano_usd()
    assert [a["reason"] for a in _provision_audits(store)] == ["rate_limited", "rate_limited"]


def test_flag_off_flat_is_pr_j_exactly(flat, monkeypatch):
    """Byte-identical when off: a flat turn writes no turn record and is never rate limited (PR-J's path)."""
    store, up, server = flat
    monkeypatch.delenv("VIGIL_CUSTOMER_ASSISTANT_WALLET")
    monkeypatch.setenv("VIGIL_ASSISTANT_TURNS_PER_HOUR", "1")
    for _ in range(3):
        _P(store).customer_assistant_ask("alice", ORG, "what should I fix first?", ip="1.2.3.4")
    assert len(_sent(up)) == 3 and _ledger(store).turns(ORG) == [] and _provision_audits(store) == []
    assert not any(isinstance(r.payload, dict) and r.payload.get("signal") == at.SIGNAL for r in store.iter_records())


def test_the_accounted_turn_grounds_exactly_like_the_unaccounted_one(monkeypatch):
    """PARITY PIN: an accounted turn differs from PR-J's ONLY in its model dial — the SAME ``assistant.answer`` call
    (same store, org, question, model, output bound, finding limit and any other grounding argument). A grounding
    argument added to one path and not the other reds this test."""
    from sigil.ui import assistant as asst
    store = _store()
    _org(store, credits=100)
    seen: list = []

    def fake_answer(store_, org_id, question, **kw):
        seen.append((store_ is store, org_id, question,
                     {k: v for k, v in kw.items() if k not in ("model_call", "now")}))
        return asst.AssistantReply(answer="ok")

    monkeypatch.setattr(asst, "answer", fake_answer)
    monkeypatch.delenv("VIGIL_CUSTOMER_ASSISTANT_WALLET")
    monkeypatch.delenv("VIGIL_METERED_BILLING")
    _P(store).customer_assistant_ask("alice", ORG, "what should I fix first?", ip="")      # PR-J: unaccounted
    monkeypatch.setenv("VIGIL_CUSTOMER_ASSISTANT_WALLET", "1")
    _P(store).customer_assistant_ask("alice", ORG, "what should I fix first?", ip="")      # accounted, flat
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    _P(store).customer_assistant_ask("alice", ORG, "what should I fix first?", ip="")      # accounted, metered
    assert len(seen) == 3 and seen[0] == seen[1] == seen[2], seen


def test_a_postpaid_orgs_assistant_use_is_billed_on_its_arrears_invoice():
    """The invoice line: a postpaid org's settled assistant turn is billable consumption on its arrears invoice — held
    out while in flight, then billed at its settled whole credits."""
    from sigil.governor.invoices import InvoiceRegistry
    from sigil.governor.postpaid import invoice_postpaid_arrears
    store = _store()
    _org(store, credits=0)
    postpaid = PostpaidRegistry(store)
    postpaid.set_account(ORG, 20, 30, issued_at=float(next(_iss)))
    arrears, invoices = PostpaidArrearsLedger(store), InvoiceRegistry(store)
    r, nonce = _reserve(store, need_mc=7_500)
    assert r["ok"] and arrears.in_flight_reserved(ORG) == 8
    assert invoice_postpaid_arrears(postpaid, arrears, invoices, ORG, period_end=NOW, issued_at=NOW) is None
    _use(ORG, nonce, U2502)
    assert _turns(store).settle(org_id=ORG, nonce=nonce, now=NOW + 5)["ok"]
    assert arrears.in_flight_reserved(ORG) == 0
    assert invoice_postpaid_arrears(postpaid, arrears, invoices, ORG, period_end=NOW, issued_at=NOW + 6) is not None
    (line,) = [i for i in invoices.invoices(ORG) if i.kind == "postpaid"]
    assert line.credits == 2                                          # floor(2,502 / 1,000); the 502 mc carried


# ============================================================================ the customer edge waits for the turn ==

def test_the_edge_outwaits_an_accounted_turn_and_keeps_its_drain_deadline(monkeypatch):
    """A turn billed to the org must never be reported failed by the edge while the cockpit completes it: with the
    assistant accounted the edge waits longer than the cockpit's gateway dial plus its admission and settle; the drain
    deadline (pinned against the units' TimeoutStopSec) still covers that wait. Off: PR-J's hop, unchanged."""
    from sigil.ui import custui
    monkeypatch.delenv("VIGIL_CUSTOMER_ASSISTANT_WALLET")
    assert custui._hop_timeout("assistant_ask") == custui._HOP_TIMEOUT_S
    monkeypatch.setenv("VIGIL_CUSTOMER_ASSISTANT_WALLET", "1")
    assert custui._hop_timeout("assistant_ask") == custui._ASSISTANT_ACCOUNTED_HOP_S
    assert custui._ASSISTANT_ACCOUNTED_HOP_S >= aw.TURN_DIAL_TIMEOUT_S + 15.0          # + admission and settle
    assert custui.drain_deadline_s() > custui._ASSISTANT_ACCOUNTED_HOP_S
    assert custui.drain_deadline_s() == max(custui._SLOW_HOP_TIMEOUTS_S.values()) + custui._DRAIN_MARGIN_S
    assert custui._hop_timeout("login") == custui._HOP_TIMEOUT_S                        # nothing else moves


def test_the_accounted_dial_gives_up_within_its_own_timeout(metered, monkeypatch):
    """The cockpit's dial for an accounted turn uses ``TURN_DIAL_TIMEOUT_S``, not PR-J's longer default."""
    from sigil.ui import assistant as asst
    store, up, server = metered
    seen: list = []
    real = asst.accounted_gateway_model_call

    def spy(**kw):
        seen.append(kw.get("timeout"))
        return real(**kw)

    monkeypatch.setattr(asst, "accounted_gateway_model_call", spy)
    _P(store).customer_assistant_ask("alice", ORG, "what should I fix first?", ip="1.2.3.4")
    assert seen == [aw.TURN_DIAL_TIMEOUT_S]


def test_every_role_that_may_ask_may_also_spend():
    """No money escalation: every role that carries the assistant's permission (view_assessments) also carries the one
    that spends credits on a launch (run_engagement) — so billing a turn to the org never lets a member spend more
    than they already could."""
    from vigil_core.rbac import PERMISSIONS
    askers = [r for r, perms in PERMISSIONS.items() if "view_assessments" in perms]
    assert askers and all("run_engagement" in PERMISSIONS[r] for r in askers)


def test_a_member_who_may_read_but_not_spend_draws_nothing(metered, monkeypatch):
    """Defence in depth: should a read-only role ever gain the assistant, a turn billed to the org's credits still
    needs run_engagement — refused before anything is recorded, held or sent."""
    store, up, server = metered
    real = OrgRegistry.admit_customer

    def no_spend(self, *, username, org_id, permission):
        return permission != "run_engagement" and real(self, username=username, org_id=org_id, permission=permission)

    monkeypatch.setattr(OrgRegistry, "admit_customer", no_spend)
    with pytest.raises(ProvisionDenied) as e:
        _P(store).customer_assistant_ask("alice", ORG, "what should I fix first?", ip="1.2.3.4")
    assert "run_engagement" in str(e.value)
    assert _sent(up) == [] and _exact(store) == 100_000 and _ledger(store).turns(ORG) == []
