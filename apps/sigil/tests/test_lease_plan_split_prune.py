"""The plan/wallet split of a prepaid launch settle across a REAL hard prune (``prune.commit_prune``).

A prepaid reserve debits the tenant's current plan tranche first, then the wallet; a settle refunds each bucket its
own share. With ``VIGIL_LEASE_PLAN_SPLIT=1`` the owner-signed lease records the split it was minted with
(``plan_reserved`` / ``plan_period_end``), so the settle restores the plan share to the SAME tranche from the lease
— even when a hard prune has taken the reserve's plan debit record out of the live spine window. A lease minted
without the split settles from the live record; when that record is gone while the plan ledger's prune-durable
seen-set still holds it (``PlanCreditLedger.has_debit_entry``), a FRESH settle refuses (``plan_debit_pruned``) and
moves nothing, so the plan share is never refunded into the wallet.

Pinned here (each guard has a named test that a mutant turns red):
  * the lease split is used across a prune (sweep refund / metered completion)  -> test_split_lease_settles_...
  * the legacy prune check (has_debit_entry)                                    -> test_legacy_lease_after_a_prune_...
  * the check runs on a FRESH settle only                                      -> test_a_legacy_lease_settled_before_...
  * the lease split vs a disagreeing live record                               -> test_a_lease_split_that_disagrees_...
  * _spend reports only the plan debit it appended / the flag gates stamping   -> test_reserve_stamps_...
  * the settle drain quarantines a held settle                                 -> test_the_settle_drain_quarantines_...

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:integration:packages/core/vigil_core \
     python -m pytest apps/sigil/tests/test_lease_plan_split_prune.py
"""
from __future__ import annotations

import itertools
import json
import os
import tempfile
from pathlib import Path

import pytest

import sigil.config as cfg
import sigil.spine.checkpoint as _cp
import sigil.spine.floor as _fl
import sigil.spine.snapshot as _snap
import sigil.spine.tail as _tail
from sigil import ops_sweeps
from sigil.governor import identity
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.metering import PlanCreditLedger, refill_active_subscription
from sigil.governor.orgs import OrgRegistry
from sigil.governor.postpaid import PostpaidRegistry
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine import fold_cache, prune
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import PLAN_DEBIT_PRUNED, LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_core import SignedCreditLaunchLease

_iss = itertools.count(1)
ORG, HOST, NOW = "org_a", "apme.cm", 2000.0
PERIOD_END = 1e12
LATE = NOW + 3600.0 + 100.0                    # past a 1h lease's not_after + the sweep ttl (50)


@pytest.fixture(params=[("", ""), ("1", ""), ("", "1")], ids=["cache_off", "cache_on", "settle_record_on"])
def world(request, tmp_path, monkeypatch):
    """One spine with its own owner key, signed head, floor and prune archive (a prune needs all of them)."""
    keys = tmp_path / "keys"
    monkeypatch.setattr(cfg, "KEYS_DIR", keys, raising=False)
    monkeypatch.setattr(_cp, "KEYS_DIR", keys)
    for mod in (_cp, identity):
        monkeypatch.setattr(mod, "_PRIV", keys / "owner.priv")
        monkeypatch.setattr(mod, "_PUB", keys / "owner.pub")
    monkeypatch.setattr(identity, "_GENESIS_PUB", keys / "owner.genesis.pub")
    head = tmp_path / "head.json"
    for mod in (cfg, _cp, _snap, _tail):
        monkeypatch.setattr(mod, "HEAD_PATH", head, raising=False)
    monkeypatch.setattr(_fl, "FLOOR_PATH", tmp_path / "floor.json")
    monkeypatch.setenv("SIGIL_SPINE_ARCHIVE_DIR", str(tmp_path / "archive"))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "seam"))
    monkeypatch.setattr(cfg, "MODEL_METER_DIR", tmp_path / "model_meter")
    for k in ("VIGIL_LEASE_PLAN_SPLIT", "VIGIL_SETTLE_SPINE_RECORD", "VIGIL_METERED_BILLING",
              "VIGIL_ONE_LAUNCH_PER_HOST", "VIGIL_COST_LEDGER_WRITE"):
        monkeypatch.delenv(k, raising=False)
    cache, record = request.param
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", cache)
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", record)
    fold_cache.clear_all()
    path = tmp_path / "spine.jsonl"
    SpineStore(path).migrate()
    identity.ensure_owner_keypair()
    yield path
    fold_cache.clear_all()


def _store(path) -> SpineStore:
    return SpineStore(path)                    # a FRESH handle: nothing in memory survives a prune


def _seat(store, *, wallet=20, plan=5, postpaid=None):
    orgs = OrgRegistry(store)
    orgs.create_org(ORG, ORG, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(ORG, "u", "operator", issued_at=float(next(_iss)))
    WalletRegistry(store).grant(ORG, wallet, "trial", entry_id=f"trial:{ORG}", issued_at=float(next(_iss)))
    if plan:
        subs = SubscriptionRegistry(store)
        subs.subscribe(ORG, "pro", plan, period_start=0.0, period_end=PERIOD_END, issued_at=float(next(_iss)))
        refill_active_subscription(subs, PlanCreditLedger(store), ORG, issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(ORG, HOST, issued_at=float(next(_iss)))
    reg.verify_and_record(ORG, HOST, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
    assert add_customer_target(HOST, org_id=ORG, store=store, now=NOW)["ok"]
    if postpaid is not None:
        PostpaidRegistry(store).set_account(ORG, postpaid[0], postpaid[1], issued_at=float(next(_iss)))


def _reserve(store, units=10, *, publish=True):
    g = LaunchGate(store)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=units, now=NOW, duration_hours=1)
    assert r["ok"], r
    if publish:
        assert g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    return r


def _buckets(store):
    """(plan credits left in the reserved tranche, wallet credits)."""
    return PlanCreditLedger(store).available(ORG, NOW), WalletRegistry(store).available(ORG)


def _entries(store, prefix):
    return sum(1 for x in store.iter_records() if str((x.payload or {}).get("entry_id", "")).startswith(prefix))


def _hard_prune_past_the_reserve(path) -> int:
    """Seal every record so far (the reserve's debits included) below K, add a live window, sign the head and run
    the REAL cutover. Returns K."""
    s = _store(path)
    s.rotate()
    k = s.next_seq
    for i in range(2):
        s.append(kind="event", source="t", actor="u", payload={"signal": "noise", "live": i})
    s.rotate()
    for i in range(3):
        s.append(kind="event", source="t", actor="u", payload={"signal": "noise", "tail": i})
    _cp.checkpoint(s)
    rep = prune.commit_prune(s, k, confirm=True)
    assert rep["base_seq"] == k
    fold_cache.clear_all()
    return k


def _assert_debit_pruned(path, r):
    """The fixture has teeth: the reserve's plan debit left the live window, yet the ledger still knows it."""
    s = _store(path)
    eid = f"reserve-plan:{r['slug']}:{r['nonce']}"
    assert all((x.payload or {}).get("entry_id") != eid for x in s.iter_records())
    assert PlanCreditLedger(s).debited_entry(ORG, eid) is None, "the live read must miss the pruned debit"
    assert PlanCreditLedger(s).has_debit_entry(ORG, eid) is True, "the seen-set must survive the prune"


def _spool():
    spool = tempfile.mkdtemp()
    for sub in ("incoming", "working", "rejected"):
        os.makedirs(os.path.join(spool, sub))
    return spool


def _sweep(store, *, apply=True):
    return ops_sweeps.sweep_abandoned_reservations(LaunchGate(store), now=LATE, ttl_s=50, apply=apply,
                                                   completion_spool=_spool())["items"]


def _doc(r):
    return SignedCreditLaunchLease.model_validate(r["lease"]).document


# =====================================================================================================================
# the lease records the split it was minted with
# =====================================================================================================================
def test_reserve_stamps_the_plan_split_only_with_the_flag(world, monkeypatch):
    s = _store(world)
    _seat(s)
    off = _reserve(s, units=3, publish=False)
    assert set(off["lease"]["document"]) & {"plan_reserved", "plan_period_end", "run_tier", "continue_of"} == set()
    assert _doc(off).plan_reserved is None
    monkeypatch.setenv("VIGIL_LEASE_PLAN_SPLIT", "1")
    on = _reserve(s, units=4, publish=False)                          # the tranche has 2 left: plan 2 + wallet 2
    assert (_doc(on).plan_reserved, _doc(on).plan_period_end) == (2, PERIOD_END)
    wallet_only = _reserve(s, units=5, publish=False)                 # the tranche is empty now
    assert (_doc(wallet_only).plan_reserved, _doc(wallet_only).plan_period_end) == (0, None)
    assert "plan_period_end" not in wallet_only["lease"]["document"]


def test_reserve_stamps_no_split_for_a_postpaid_launch(world, monkeypatch):
    monkeypatch.setenv("VIGIL_LEASE_PLAN_SPLIT", "1")
    s = _store(world)
    _seat(s, postpaid=(1000, 30))
    r = _reserve(s, publish=False)
    assert "plan_reserved" not in r["lease"]["document"]


# =====================================================================================================================
# a lease minted with the split settles correctly across a real hard prune
# =====================================================================================================================
def test_split_lease_settles_both_buckets_after_a_hard_prune(world, monkeypatch):
    monkeypatch.setenv("VIGIL_LEASE_PLAN_SPLIT", "1")
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r = _reserve(s, units=10)                                          # plan 5 + wallet 5
    assert _buckets(s) == (0, 15)
    _hard_prune_past_the_reserve(world)
    _assert_debit_pruned(world, r)
    rows = _sweep(_store(world))
    assert [(x["status"], x.get("refunded")) for x in rows] == [("refunded", 10)], rows
    s2 = _store(world)
    assert _buckets(s2) == (5, 20), "the plan share goes back to its own tranche, the wallet share to the wallet"
    assert _entries(s2, "settle-plan:") == 1 and _entries(s2, "settle-wallet:") == 1
    assert [x["status"] for x in _sweep(_store(world))] == []           # settled and retired: nothing left to do


def test_split_lease_metered_completion_after_a_hard_prune_eats_the_plan_share_first(world, monkeypatch):
    monkeypatch.setenv("VIGIL_LEASE_PLAN_SPLIT", "1")
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r = _reserve(s, units=10)
    _hard_prune_past_the_reserve(world)
    _assert_debit_pruned(world, r)
    out = LaunchGate(_store(world)).settle_launch(signed_lease=r["lease"], consumed_units=3, now=NOW + 60,
                                                  basis="completion:completed")
    assert out["ok"] and (out["refunded_plan"], out["refunded_wallet"], out["net_spend"]) == (2, 5, 3), out
    assert _buckets(_store(world)) == (2, 20)


# =====================================================================================================================
# a lease minted WITHOUT the split: the pruned record holds the settle (never a wallet refund of the plan share)
# =====================================================================================================================
def test_legacy_lease_after_a_prune_of_its_plan_debit_is_held_and_moves_nothing(world):
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r = _reserve(s, units=10)                                          # flag off: a lease without the split
    _hard_prune_past_the_reserve(world)
    _assert_debit_pruned(world, r)
    rows = _sweep(_store(world))
    assert [x["status"] for x in rows] == [PLAN_DEBIT_PRUNED], rows
    s2 = _store(world)
    assert _buckets(s2) == (0, 15), "nothing refunded: the plan share must never land in the wallet"
    assert _entries(s2, "settle-") == 0
    again = LaunchGate(s2).settle_launch(signed_lease=r["lease"], consumed_units=0, now=LATE, basis="cancel")
    assert again["ok"] is False and again["refused"] == PLAN_DEBIT_PRUNED, again
    assert _buckets(_store(world)) == (0, 15)


def test_legacy_wallet_only_lease_after_a_prune_still_refunds_the_wallet(world):
    s = _store(world)
    _seat(s, wallet=20, plan=0)                                        # no plan: a wallet-only reservation
    _reserve(s, units=10)
    _hard_prune_past_the_reserve(world)
    rows = _sweep(_store(world))
    assert [(x["status"], x.get("refunded")) for x in rows] == [("refunded", 10)], rows
    assert WalletRegistry(_store(world)).available(ORG) == 20


def test_a_legacy_lease_settled_before_the_prune_is_already_settled_not_held(world):
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r = _reserve(s, units=10)
    first = LaunchGate(s).settle_launch(signed_lease=r["lease"], consumed_units=10, now=NOW + 60,
                                        basis="completion:completed")
    assert first["ok"] and first["action"] == "launch_settled", first
    _hard_prune_past_the_reserve(world)
    _assert_debit_pruned(world, r)
    again = LaunchGate(_store(world)).settle_launch(signed_lease=r["lease"], consumed_units=0, now=LATE,
                                                    basis="cancel")
    assert again["ok"] and again["action"] == "launch_already_settled" and again["refunded"] == 0, again
    assert _buckets(_store(world)) == (0, 15)


def test_the_settle_drain_quarantines_a_held_settle(world):
    """A completion whose settle is held can never be settled by a retry: it is quarantined (the drain alarms),
    and the sweep then treats the run as finished and never refunds it."""
    from sigil.governor.identity import delegate_offense_governance
    from sigil.inbound.completion_spool import CompletionSpoolWatcher
    from vigil_core import AuthorizerKey, generate_keypair
    from vigil_integration.jobs.completion_signal import emit_completion_signal
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r = _reserve(s, units=10)
    _hard_prune_past_the_reserve(world)
    owner = identity.ensure_owner_keypair()
    gov = generate_keypair()
    deleg = delegate_offense_governance(
        owner, authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=gov.public_key_b64)],
        threshold=1, scope=r["slug"], not_after=9_000_000_000)
    spool = _spool()
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="completed",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    w = CompletionSpoolWatcher(_store(world), spool_dir=spool, owner_pubkey=owner.public_key_b64, delegation=deleg,
                               scope=r["slug"], base_dir=os.environ["VIGIL_BASE_DIR"], now_fn=lambda: NOW + 60)
    out = w.drain()
    assert (out["settled"], out["rejected"]) == (0, 1), out
    reasons = [p.read_text() for p in Path(spool, "rejected").glob("*.reason")]
    assert reasons and PLAN_DEBIT_PRUNED in reasons[0], reasons
    assert _buckets(_store(world)) == (0, 15)
    rows = ops_sweeps.sweep_abandoned_reservations(LaunchGate(_store(world)), now=LATE, ttl_s=50, apply=True,
                                                   completion_spool=spool)["items"]
    assert [x["status"] for x in rows] == ["completion_pending"], rows


# =====================================================================================================================
# the lease split is checked against the live record while it is still readable
# =====================================================================================================================
@pytest.mark.parametrize("live", [(4, PERIOD_END), (5, PERIOD_END - 1.0)], ids=["credits", "period"])
def test_a_lease_split_that_disagrees_with_the_live_record_refuses_and_moves_nothing(world, monkeypatch, live):
    from sigil.governor import metering
    monkeypatch.setenv("VIGIL_LEASE_PLAN_SPLIT", "1")
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r = _reserve(s, units=10)
    monkeypatch.setattr(metering.PlanCreditLedger, "debited_entry", lambda *a, **k: live)
    out = LaunchGate(s).settle_launch(signed_lease=r["lease"], consumed_units=0, now=NOW + 60, basis="cancel")
    assert out["ok"] is False and "refund invariant violated" in out["error"], out
    assert _buckets(s) == (0, 15) and _entries(s, "settle-") == 0


def test_a_wallet_only_split_lease_refuses_when_a_plan_debit_appears(world, monkeypatch):
    from sigil.governor import metering
    monkeypatch.setenv("VIGIL_LEASE_PLAN_SPLIT", "1")
    s = _store(world)
    _seat(s, wallet=20, plan=0)
    r = _reserve(s, units=10)
    assert _doc(r).plan_reserved == 0
    monkeypatch.setattr(metering.PlanCreditLedger, "debited_entry", lambda *a, **k: (3, PERIOD_END))
    out = LaunchGate(s).settle_launch(signed_lease=r["lease"], consumed_units=0, now=NOW + 60, basis="cancel")
    assert out["ok"] is False and "refund invariant violated" in out["error"], out
    assert WalletRegistry(s).available(ORG) == 10


def test_a_split_lease_settles_like_before_while_the_record_is_live(world, monkeypatch):
    monkeypatch.setenv("VIGIL_LEASE_PLAN_SPLIT", "1")
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r = _reserve(s, units=10)
    out = LaunchGate(s).settle_launch(signed_lease=r["lease"], consumed_units=7, now=NOW + 60,
                                      basis="completion:completed")
    assert out["ok"] and (out["refunded_plan"], out["refunded_wallet"]) == (0, 3), out
    assert _buckets(s) == (0, 18)


def test_a_tampered_split_does_not_verify(world, monkeypatch):
    monkeypatch.setenv("VIGIL_LEASE_PLAN_SPLIT", "1")
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r = _reserve(s, units=10)
    forged = json.loads(json.dumps(r["lease"]))
    forged["document"]["plan_reserved"] = 0                           # claim it all came from the wallet
    del forged["document"]["plan_period_end"]
    out = LaunchGate(s).settle_launch(signed_lease=forged, consumed_units=0, now=NOW + 60, basis="cancel")
    assert out["ok"] is False and "does not verify" in out["error"], out
    stripped = json.loads(json.dumps(r["lease"]))
    for k in ("plan_reserved", "plan_period_end"):
        del stripped["document"][k]                                    # pass it off as a lease without the split
    out = LaunchGate(s).settle_launch(signed_lease=stripped, consumed_units=0, now=NOW + 60, basis="cancel")
    assert out["ok"] is False and "does not verify" in out["error"], out
    assert _buckets(s) == (0, 15)
