"""The plan/wallet split of a prepaid launch settle across a REAL hard prune (``prune.commit_prune``).

A prepaid reserve debits the tenant's current plan tranche first, then the wallet; a settle refunds each bucket its
own share. With ``VIGIL_LEASE_PLAN_SPLIT=1`` the owner-signed lease records the split it was minted with
(``plan_reserved`` / ``plan_period_end``), so the settle restores the plan share to the SAME tranche from the lease
— even when a hard prune has taken the reserve's plan debit record out of the live spine window. A lease minted
without the split settles from the live record; when that record is gone while the plan ledger's prune-durable
seen-set still holds it (``PlanCreditLedger.has_debit_entry``), a FRESH settle refuses (``plan_debit_pruned``) and
moves nothing, so the plan share is never refunded into the wallet. A superseded reservation (E7, released from its
live reserve records, with no lease) is held the same way, so it is never released short.

Pinned here (each guard has a named test that a mutant turns red):
  * the lease split is used across a prune (sweep refund / metered completion)  -> test_split_lease_settles_...
  * the legacy prune check (has_debit_entry)                                    -> test_legacy_lease_after_a_prune_...
  * the check runs on a FRESH settle only                                      -> test_a_legacy_lease_settled_before_...
  * the lease split vs a disagreeing live record                               -> test_a_lease_split_that_disagrees_...
  * _spend reports only the plan debit it appended / the flag gates stamping   -> test_reserve_stamps_...
  * the settle drain quarantines a held settle                                 -> test_the_settle_drain_quarantines_...
  * the caller's own precondition is evaluated before the hold               -> test_a_held_settle_reports_the_...
  * E7: a pruned plan debit holds the release / a pruned wallet debit refuses -> test_a_superseded_reservation_...
  * every held settle names the launch in the held-settle alarm (`vigil doctor` HARD), the customer's cancel
    included (its own refusal + a critical audit), until the launch settles      -> test_a_customer_cancel_of_a_held_...,
    test_a_held_launch_leaves_the_alarm_..., test_the_reservations_sweep_drops_..., test_vigil_doctor_reports_...

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
from sigil.governor.settle_hold import held_alarm_path, read_held
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
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))       # the held-settle alarm lives under it
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


def _held():
    """The launches the held-settle alarm (`vigil doctor`) names, as (slug, nonce)."""
    return sorted((h["slug"], h["nonce"]) for h in (read_held() or []))


def _owner_settles(path, r, *, plan, wallet):
    """The owner returns a held reservation's credits under the launch's own settle entry ids (what a settle writes)."""
    s = _store(path)
    if plan:
        PlanCreditLedger(s).grant(ORG, plan, period_end=PERIOD_END, entry_id=f"settle-plan:{r['slug']}:{r['nonce']}",
                                  issued_at=LATE)
    if wallet:
        WalletRegistry(s).grant(ORG, wallet, "refund", source_ref=r["slug"],
                                entry_id=f"settle-wallet:{r['slug']}:{r['nonce']}", issued_at=LATE)


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
    assert _held() == []
    rows = _sweep(_store(world))
    assert [x["status"] for x in rows] == [PLAN_DEBIT_PRUNED], rows
    assert _held() == [(r["slug"], r["nonce"])], "a held settle names the launch in the alarm doctor reports"
    s2 = _store(world)
    assert _buckets(s2) == (0, 15), "nothing refunded: the plan share must never land in the wallet"
    assert _entries(s2, "settle-") == 0
    again = LaunchGate(s2).settle_launch(signed_lease=r["lease"], consumed_units=0, now=LATE, basis="cancel")
    assert again["ok"] is False and again["refused"] == PLAN_DEBIT_PRUNED, again
    assert _buckets(_store(world)) == (0, 15)


def test_a_held_settle_reports_the_callers_own_refusal_first(world):
    """The caller's precondition is evaluated before the pruned-record check: a settle its caller refuses (e.g. a
    completion that landed meanwhile, or a pricing guard the drain re-prices next pass) reports THAT reason, not a
    hold, and moves nothing."""
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r = _reserve(s, units=10)
    _hard_prune_past_the_reserve(world)
    _assert_debit_pruned(world, r)
    out = LaunchGate(_store(world)).settle_launch(signed_lease=r["lease"], consumed_units=0, now=LATE,
                                                  basis="sweep:refund", refuse_if=lambda: "completion_pending")
    assert out["ok"] is False and out["refused"] == "completion_pending", out
    assert _buckets(_store(world)) == (0, 15)
    assert _held() == [], "a refusal that is not a hold raises no held-settle alarm"


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
    assert _held() == [(r["slug"], r["nonce"])]
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


# =====================================================================================================================
# E7 — a superseded reservation (no lease: its amount is its live reserve records) is never released short
# =====================================================================================================================
SUPERSEDED_AT = NOW + 400 * 3600.0              # past the longest lease window: the release grace is over


def _reserve_across_a_segment_boundary(store, monkeypatch, *, wallet_first=False) -> "tuple[dict, int]":
    """Reserve plan 5 + wallet 5 with a segment boundary between its two debit records (the plan debit first, as
    ``_spend`` appends them; ``wallet_first`` swaps them). Returns the reservation and the first seq after the
    boundary."""
    g = LaunchGate(store)
    mark = {}

    def _spend(self, oid, units, slug, nonce, now_ts):
        sub = self.meter.subscriptions.active_subscription(oid, now_ts)
        steps = [lambda: self.meter.plan.debit(oid, 5, period_end=sub.period_end, engagement_id=slug,
                                               entry_id=f"reserve-plan:{slug}:{nonce}", issued_at=now_ts),
                 lambda: self.wallet.debit(oid, units - 5, engagement_id=slug,
                                           entry_id=f"reserve-wallet:{slug}:{nonce}", issued_at=now_ts)]
        first, second = reversed(steps) if wallet_first else steps
        first()
        self.store.rotate()                    # the segment boundary between the two debit records
        mark["k"] = self.store.next_seq
        second()
        return (5, float(sub.period_end))
    with monkeypatch.context() as m:
        m.setattr(LaunchGate, "_spend", _spend)
        r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=10, now=NOW, duration_hours=1)
    assert r["ok"], r
    assert _buckets(store) == (0, 15)
    return r, mark["k"]


def _supersede_and_prune_at(path, k) -> None:
    """A later launch of the same target supersedes the reservation on the seam; then a REAL hard prune at ``k``."""
    g = LaunchGate(_store(path))
    later = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=1, now=NOW + 1, duration_hours=1)
    assert later["ok"], later
    assert g.publish_lease(signed_lease=later["lease"], expect_org_id=ORG)["ok"]
    s = _store(path)
    s.rotate()
    for i in range(3):
        s.append(kind="event", source="t", actor="u", payload={"signal": "noise", "tail": i})
    _cp.checkpoint(s)
    assert prune.commit_prune(s, k, confirm=True)["base_seq"] == k
    fold_cache.clear_all()


def _release(path, r):
    return LaunchGate(_store(path)).release_superseded_reservation(org_id=ORG, slug=r["slug"], nonce=r["nonce"],
                                                                   now=SUPERSEDED_AT, grace_s=0.0)


def test_a_superseded_reservation_whose_plan_debit_a_prune_removed_is_held_not_released_short(world, monkeypatch):
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r, k = _reserve_across_a_segment_boundary(s, monkeypatch)
    _supersede_and_prune_at(world, k)
    _assert_debit_pruned(world, r)
    before = _buckets(_store(world))
    out = _release(world, r)
    assert out["ok"] is False and out["refused"] == PLAN_DEBIT_PRUNED, out
    assert _held() == [(r["slug"], r["nonce"])]
    s2 = _store(world)
    assert _buckets(s2) == before, "nothing moves: the wallet share alone is never released as the whole"
    assert _entries(s2, f"settle-wallet:{r['slug']}:{r['nonce']}") == 0
    assert _entries(s2, f"settle-plan:{r['slug']}:{r['nonce']}") == 0


def test_a_superseded_reservation_whose_wallet_debit_a_prune_removed_is_refused(world, monkeypatch):
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r, k = _reserve_across_a_segment_boundary(s, monkeypatch, wallet_first=True)
    _supersede_and_prune_at(world, k)
    eid = f"reserve-wallet:{r['slug']}:{r['nonce']}"
    s1 = _store(world)
    assert all((x.payload or {}).get("entry_id") != eid for x in s1.iter_records())
    assert WalletRegistry(s1).has_debit_entry(ORG, eid) is True, "the seen-set must survive the prune"
    before = _buckets(s1)
    out = _release(world, r)
    assert out["ok"] is False and "inconsistent" in out["error"], out
    s2 = _store(world)
    assert _buckets(s2) == before and _entries(s2, "settle-") == 0


def test_a_superseded_reservation_with_its_records_live_is_still_released_in_full(world, monkeypatch):
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r, _k = _reserve_across_a_segment_boundary(s, monkeypatch)
    g = LaunchGate(_store(world))
    later = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=1, now=NOW + 1, duration_hours=1)
    assert later["ok"] and g.publish_lease(signed_lease=later["lease"], expect_org_id=ORG)["ok"]
    out = _release(world, r)
    assert out["ok"] and (out["refunded_plan"], out["refunded_wallet"]) == (5, 5), out


# =====================================================================================================================
# a held settle alarms on every path, the customer's cancel included, until the launch settles
# =====================================================================================================================
def _audits(store, outcome):
    return [x.payload for x in store.iter_records()
            if (x.payload or {}).get("signal") == "provision.audit" and x.payload.get("outcome") == outcome]


def test_a_customer_cancel_of_a_held_launch_says_it_is_held_alarms_and_moves_nothing(world):
    from sigil.ui.provision import LAUNCH_REFUND_HELD_DETAIL, ProvisionDenied, build_provisioner
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r = _reserve(s, units=10, publish=False)                           # reserved, never started
    _hard_prune_past_the_reserve(world)
    _assert_debit_pruned(world, r)
    with pytest.raises(ProvisionDenied) as ei:
        build_provisioner(_store(world)).launch_cancel("u", ORG, r["lease"], now=NOW + 60)
    assert str(ei.value) == LAUNCH_REFUND_HELD_DETAIL, "never told it was started: it was not"
    s2 = _store(world)
    held = _audits(s2, "refund_held")
    assert len(held) == 1 and held[0]["reason"] == PLAN_DEBIT_PRUNED and held[0]["target"] == r["slug"], held
    assert _audits(s2, "refused_started") == []
    assert _held() == [(r["slug"], r["nonce"])]
    assert _buckets(s2) == (0, 15) and _entries(s2, "settle-") == 0


def test_a_held_cancel_leaves_a_marker_so_the_reservation_can_never_be_started(world):
    # the customer was told the reservation is cancelled (its credits held for the operator): a later start — from
    # the customer, or a re-publish after the held-settle alarm file was lost (a restore leaves it out) — is refused
    from sigil.governor.launch_settlement import LAUNCH_CANCEL_HELD_SIGNAL, scan_settlement
    from sigil.ui.launch_gate import CANCEL_HELD_START_DETAIL
    from sigil.ui.provision import ProvisionDenied, build_provisioner
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r = _reserve(s, units=10, publish=False)
    _hard_prune_past_the_reserve(world)
    with pytest.raises(ProvisionDenied):
        build_provisioner(_store(world)).launch_cancel("u", ORG, r["lease"], now=NOW + 60)
    s2 = _store(world)
    marks = [x.payload for x in s2.iter_records() if (x.payload or {}).get("signal") == LAUNCH_CANCEL_HELD_SIGNAL]
    assert marks == [{"signal": LAUNCH_CANCEL_HELD_SIGNAL, "org_id": ORG, "slug": r["slug"], "nonce": r["nonce"]}]
    g = LaunchGate(s2)
    assert scan_settlement(s2, g.owner_key.public_key_b64, org_id=ORG, slug=r["slug"], nonce=r["nonce"]).cancel_held
    out = g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)
    assert out == {"ok": False, "error": CANCEL_HELD_START_DETAIL}, out
    from sigil.governor import settle_hold
    settle_hold.held_alarm_path().unlink()                          # the alarm file gone: the marker still holds
    assert LaunchGate(_store(world)).publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"] is False
    assert _buckets(_store(world)) == (0, 15)                       # nothing moved


def test_a_held_cancel_whose_marker_cannot_be_written_is_not_reported_cancelled(world, monkeypatch):
    from sigil.governor.launch_settlement import LAUNCH_CANCEL_HELD_SIGNAL
    from sigil.ui.provision import LAUNCH_REFUND_HELD_DETAIL, ProvisionDenied, build_provisioner
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r = _reserve(s, units=10, publish=False)
    _hard_prune_past_the_reserve(world)
    p = build_provisioner(_store(world))
    real = p.store.append

    def _append(**kw):
        if (kw.get("payload") or {}).get("signal") == LAUNCH_CANCEL_HELD_SIGNAL:
            raise OSError("disk full")
        return real(**kw)
    monkeypatch.setattr(p.store, "append", _append)
    with pytest.raises(ProvisionDenied) as ei:
        p.launch_cancel("u", ORG, r["lease"], now=NOW + 60)
    assert str(ei.value) != LAUNCH_REFUND_HELD_DETAIL and "retry" in str(ei.value)
    assert _audits(_store(world), "refund_held") == []


def test_a_customer_cancel_of_a_started_launch_is_still_refused_as_started(world):
    from sigil.ui.provision import ProvisionDenied, build_provisioner
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r = _reserve(s, units=10)                                          # published: started
    _hard_prune_past_the_reserve(world)
    with pytest.raises(ProvisionDenied) as ei:
        build_provisioner(_store(world)).launch_cancel("u", ORG, r["lease"], now=NOW + 60)
    assert "has been started" in str(ei.value)
    assert _held() == [] and _audits(_store(world), "refund_held") == []


def test_a_held_launch_leaves_the_alarm_once_it_is_settled(world):
    """The owner settles the held launch (its settle entries); the launch's next settle finds it already settled and
    drops it from the alarm — a re-cancel here — and nothing moves twice."""
    from sigil.ui.provision import ProvisionDenied, build_provisioner
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r = _reserve(s, units=10, publish=False)
    _hard_prune_past_the_reserve(world)
    with pytest.raises(ProvisionDenied):
        build_provisioner(_store(world)).launch_cancel("u", ORG, r["lease"], now=NOW + 60)
    assert _held() == [(r["slug"], r["nonce"])]
    _owner_settles(world, r, plan=5, wallet=5)
    assert _buckets(_store(world)) == (5, 20)
    out = build_provisioner(_store(world)).launch_cancel("u", ORG, r["lease"], now=NOW + 120)
    assert out.get("already_settled") is True and out["refunded"] == 0, out
    assert _held() == [] and not held_alarm_path().exists()
    assert _buckets(_store(world)) == (5, 20)


def test_the_reservations_sweep_drops_a_held_launch_the_spine_shows_settled(world):
    """A held launch nothing re-settles (an unpublished reservation) leaves the alarm at the next
    `ops-sweep reservations --apply` once the spine shows it settled — and only then."""
    from sigil.ui.provision import ProvisionDenied, build_provisioner
    s = _store(world)
    _seat(s, wallet=30, plan=8)
    r = _reserve(s, units=4, publish=False)                            # plan 4
    other = _reserve(_store(world), units=3, publish=False)            # plan 3
    _hard_prune_past_the_reserve(world)
    for lease in (r, other):
        with pytest.raises(ProvisionDenied):
            build_provisioner(_store(world)).launch_cancel("u", ORG, lease["lease"], now=NOW + 60)
    assert _held() == sorted([(r["slug"], r["nonce"]), (other["slug"], other["nonce"])])
    _sweep(_store(world))
    assert len(_held()) == 2, "nothing is settled yet: the alarm stays"
    _owner_settles(world, r, plan=4, wallet=0)
    _sweep(_store(world), apply=False)
    assert len(_held()) == 2, "a report-only sweep writes nothing"
    _sweep(_store(world))
    assert _held() == [(other["slug"], other["nonce"])]


def test_vigil_doctor_reports_a_held_settle_as_a_hard_issue_by_slug(world, monkeypatch):
    from vigil_integration import doctor as _doc
    repo = Path(_doc.__file__).resolve().parents[2]
    monkeypatch.setenv("VIGIL_SETTLE_SPOOL", str(Path(os.environ["SIGIL_HOME"]) / "no-spool"))
    clean = _doc.collect(repo)
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r = _reserve(s, units=10)
    _hard_prune_past_the_reserve(world)
    _sweep(_store(world))
    report = _doc.collect(repo)
    new = [i for i in report["issues"] if i not in clean["issues"]]
    assert len(new) == 1 and "held for the owner" in new[0] and r["slug"] in new[0], new
    assert r["nonce"] not in new[0], "doctor names slugs only"
    assert report["launch_settlements"]["held"] == [r["slug"]]
    assert held_alarm_path().name == "launch-settle-held.json" and str(held_alarm_path()).startswith(
        os.environ["SIGIL_HOME"])


def test_a_finish_only_pass_over_a_held_launch_keeps_it_in_the_alarm(world):
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r = _reserve(s, units=10)
    _hard_prune_past_the_reserve(world)
    _sweep(_store(world))
    out = LaunchGate(_store(world)).settle_launch(signed_lease=r["lease"], consumed_units=0, now=LATE,
                                                  basis="sweep:refund", finish_only=True)
    assert out["ok"] and out["action"] == "launch_not_settled", out
    assert _held() == [(r["slug"], r["nonce"])], "only a settled launch leaves the alarm"


def test_the_reservations_sweep_drops_a_held_launch_its_seam_marker_shows_settled(world):
    from vigil_integration.live.credit_lease_broker import record_lease_settlement
    from sigil.ui.provision import ProvisionDenied, build_provisioner
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r = _reserve(s, units=10, publish=False)
    _hard_prune_past_the_reserve(world)
    with pytest.raises(ProvisionDenied):
        build_provisioner(_store(world)).launch_cancel("u", ORG, r["lease"], now=NOW + 60)
    record_lease_settlement(os.environ["VIGIL_BASE_DIR"], r["slug"], r["nonce"])   # what a settle reads as settled
    _sweep(_store(world))
    assert _held() == []


def test_a_held_cancels_audit_write_is_never_dropped(world, monkeypatch):
    """The audit of a held cancel is critical: when it cannot be written the cancel fails loudly (the caller sees the
    write error), never with the audit silently missing."""
    from sigil.ui.provision import build_provisioner
    s = _store(world)
    _seat(s, wallet=20, plan=5)
    r = _reserve(s, units=10, publish=False)
    _hard_prune_past_the_reserve(world)
    prov = build_provisioner(_store(world))
    real_append = prov.store.append

    def append(*a, **k):
        if (k.get("payload") or {}).get("outcome") == "refund_held":
            raise OSError("disk full")
        return real_append(*a, **k)
    monkeypatch.setattr(prov.store, "append", append)
    with pytest.raises(OSError):                       # not swallowed into the ProvisionDenied it would have raised
        prov.launch_cancel("u", ORG, r["lease"], now=NOW + 60)
    assert _buckets(_store(world)) == (0, 15)
