"""E3bc on main — the review findings folded into the exactly-once settle, each pinned (in-process halves; the
cross-process races live in ``test_settle_cross_process_race.py``, the flag-off parity in
``test_settle_flag_off_golden.py``).

  * findings 0 / 6 — a roll-forward moves the RECORDED split only (never a prune-sensitive re-derivation, never the
    caller's consumption), so a re-cancel after a pruned reserve debit cannot launder plan credits into the wallet;
    the v2 record is owner-signed over the split, validated on write and on scan; a disagreeing, malformed or legacy
    record moves nothing; a landed-but-pruned entry is confirmed against the seen-sets and never re-issued;
  * finding 5 — a roll-forward that moved money says so (``rolled_forward``, the moved amounts) on every caller;
  * finding 7 — the spool lock orders the drain's reverse moves with the sweep's in-lock completion re-check;
  * finding 11 — with the flag on, the sweep finishes its own interrupted settle (and never makes a fresh one there);
  * finding 12 — refuse_if runs before the settle's meter close and before the record, flag OFF and ON;
  * the pause-marker cross-process lock and the pause / settle linearization; the M1c / D3 / D4 merge; the lock order.

Mutation-verify targets (each neuter turns a NAMED test red):
  * record before refuse_if / meter close before refuse_if  -> test_a_refused_settle_writes_no_decision_...
  * record before the meter close                           -> test_a_meter_retry_writes_no_decision
  * the roll-forward re-derives the split (debited_entry)   -> test_roll_forward_after_the_reserve_plan_debit_...
  * the mover ignores landed / the seen-set                 -> test_a_pruned_landed_entry_is_not_reissued_...
  * the sweep keeps its marker skip with the flag on        -> test_flag_on_sweep_finishes_its_own_interrupted_refund
  * finish_only allowed to make a fresh decision            -> test_finish_only_never_makes_a_fresh_decision
  * the sweep's globs / the reclaim without the spool lock  -> test_the_completion_recheck_sees_a_completion_reclaimed_...
  * the deferred return without the spool lock             -> test_the_deferred_return_waits_for_the_completion_recheck
  * pause without the settle lock                          -> test_a_pause_during_a_stuck_settle_lock_still_records_...
  * _pause_state reads the late record first               -> test_a_late_resume_between_the_sweeps_pause_reads_...
  * resume clears before it records the late record        -> test_resume_records_the_late_record_before_it_clears
  * the cost settle skipped on a roll-forward               -> test_roll_forward_resettles_the_cost_ledger_once_...
  * NTF-3 on a sweep-basis roll-forward                     -> test_a_drain_roll_forward_of_a_completion_emits_ntf3_...
  * the tombstone before the money                          -> test_flag_on_sweep_finishes_its_own_interrupted_refund
  * publish without its in-lock re-scan                     -> test_publish_lease_in_lock_rescan_refuses_...
  * a relaunch replaces a lease whose recorded settle has unlanded money
                                                            -> test_flag_on_a_relaunch_waits_for_an_interrupted_...
  * that check refusing a settle whose money all landed     -> test_flag_on_a_relaunch_after_a_settle_whose_money_...
  * the earlier lease's unlocked scan continued for another nonce
                                                            -> test_flag_on_a_relaunch_rescans_in_full_when_...
  * pause refusing on an unusable settle lock / a spine read error
                                                            -> test_an_unusable_settle_lock_still_records_the_halt,
                                                               test_flag_on_a_spine_scan_failure_still_records_...
  * pause skipping the marker check without the settle lock -> test_an_unusable_settle_lock_still_refuses_to_pause_...
  * the sweep's in-lock pause_unknown check removed         -> test_the_sweeps_in_lock_pause_unknown_branch_...
  * the drain's in-lock past-expiry guard passing a None    -> test_a_failed_completion_whose_past_expiry_record_...
  * the postpaid mover ignores the seen-set                 -> test_a_pruned_landed_postpaid_settle_is_not_reissued_...

Run: PYTHONPATH=apps/sigil:integration:packages/core/vigil_core python -m pytest apps/sigil/tests/test_settle_fold_main.py
"""
from __future__ import annotations

import contextlib
import fcntl
import itertools
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from sigil import config
from sigil import ops_sweeps
from sigil.governor import launch_settlement as ls
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.authn import signed_payload
from sigil.governor.identity import delegate_offense_governance, ensure_owner_keypair
from sigil.governor.launch_settlement import (
    LAUNCH_SETTLED_SIGNAL, SettlementDecision, record_launch_settled, scan_settlement, settle_lock_path,
)
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.orgs import OrgRegistry
from sigil.governor.postpaid import PostpaidArrearsLedger, PostpaidRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.inbound.completion_spool import CompletionSpoolWatcher
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_core import AuthorizerKey, generate_keypair
from vigil_core import model_metering as mm
from vigil_core.model_grant import ModelGrant, meter_id
from vigil_integration.jobs.completion_signal import emit_completion_signal
from vigil_integration.live.credit_lease_broker import is_lease_settled, read_credit_lease, settlements_root

_iss = itertools.count(1)
ORG, HOST, NOW = "org_a", "apme.cm", 2000.0
LATE = NOW + 3600.0 + 100.0                    # past a 1h lease's not_after + the sweep ttl (50)
MLATE = NOW + 8 * 3600 + 2 * 86400             # past a default (8h) lease window + a 1-day ttl (metered helpers)
USAGE = mm.Usage(output_tokens=10_650)
USAGE_COST = 266_250_000                       # 54 credits with the test markup below
_TEST_MARKUP_INPUT = "0.5"                     # the meter tests' fixture input (see test_metered_billing)


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    for k in ("VIGIL_METERED_BILLING", mm.MARGIN_ENV, mm.CANCEL_ENV, "VIGIL_RUN_FLOOR_CREDITS", "VIGIL_MODEL_PRICES",
              "VIGIL_MODEL_GATEWAY_ENABLED", "VIGIL_RUN_MODEL", "VIGIL_SETTLE_SPINE_RECORD", "VIGIL_SETTLE_LOCK_WAIT_S",
              "VIGIL_COST_LEDGER_WRITE", *mm.OBSOLETE_PRICING_ENVS):
        monkeypatch.delenv(k, raising=False)


@pytest.fixture(params=["", "1"], ids=["flag_off", "flag_on"])
def flag(request, monkeypatch):
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", request.param)
    return bool(request.param)


@pytest.fixture
def record_on(monkeypatch):
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")


def _metered(monkeypatch):
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    monkeypatch.setenv(mm.MARGIN_ENV, _TEST_MARKUP_INPUT)
    monkeypatch.setenv(mm.CANCEL_ENV, "metered")


def _base() -> str:
    return os.environ["VIGIL_BASE_DIR"]


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _seat(store, *, credits=100, postpaid=None, plan=None):
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(ORG, ORG, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(ORG, "u", "operator", issued_at=float(next(_iss)))
    if credits:
        WalletRegistry(store).grant(ORG, credits, "trial", entry_id=f"trial:{ORG}", issued_at=float(next(_iss)))
    if plan is not None:
        from sigil.governor.metering import refill_active_subscription
        from sigil.governor.subscription import SubscriptionRegistry
        subs = SubscriptionRegistry(store)
        subs.subscribe(ORG, "pro", plan, period_start=0.0, period_end=1e12, issued_at=float(next(_iss)))
        refill_active_subscription(subs, PlanCreditLedger(store), ORG, issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(ORG, HOST, issued_at=float(next(_iss)))
    reg.verify_and_record(ORG, HOST, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
    assert add_customer_target(HOST, org_id=ORG, store=store, now=NOW)["ok"]
    if postpaid is not None:
        PostpaidRegistry(store).set_account(ORG, postpaid[0], postpaid[1], issued_at=float(next(_iss)))


def _reserve(store, units=30, nonce=None, publish=False, hours=1):
    g = LaunchGate(store)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=units, now=NOW, duration_hours=hours, nonce=nonce)
    assert r["ok"], r
    if publish:
        assert g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    return r


def _settle(store, r, consumed, now=NOW + 60, **kw):
    return LaunchGate(store).settle_launch(signed_lease=r["lease"], consumed_units=consumed, now=now, **kw)


def _avail(store):
    return WalletRegistry(store).available(ORG)


def _plan(store):
    return PlanCreditLedger(store).available(ORG, NOW)


def _signals(store, since=-1):
    return [(x.payload or {}).get("signal") for x in store.iter_records(since_seq=since)]


def _entries(store, prefix):
    return sum(1 for x in store.iter_records() if str((x.payload or {}).get("entry_id", "")).startswith(prefix))


def _decisions(store):
    return [x for x in store.iter_records() if (x.payload or {}).get("signal") == LAUNCH_SETTLED_SIGNAL]


def _lose_marker(r):
    (settlements_root(_base()) / f"{r['slug']}.json").unlink()


def _lose_seam():
    shutil.rmtree(_base())
    os.makedirs(_base())


def _kill(monkeypatch, cls, name, exc=None):
    """Make ``cls.name`` raise (a process killed there by default); returns a restorer."""
    real = getattr(cls, name)

    def _boom(*a, **k):
        raise exc if exc is not None else SystemExit(f"killed in {name}")

    monkeypatch.setattr(cls, name, _boom)
    return lambda: monkeypatch.setattr(cls, name, real)


def _spool():
    spool = tempfile.mkdtemp()
    for sub in ("incoming", "working", "rejected"):
        os.makedirs(os.path.join(spool, sub))
    return spool


def _sweep(gate, spool, *, apply=True, now=LATE, ttl=50):
    return ops_sweeps.sweep_abandoned_reservations(gate, now=now, ttl_s=ttl, apply=apply,
                                                   completion_spool=spool)["items"]


class _Gov:
    """A governance key + its owner-signed delegation for one lease's slug, and a completion drain over a spool."""

    def __init__(self, store, r, spool=None, now=NOW + 60):
        self.store, self.r, self.now = store, r, now
        self.owner = ensure_owner_keypair()
        self.key = generate_keypair()
        self.deleg = delegate_offense_governance(
            self.owner, authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=self.key.public_key_b64)],
            threshold=1, scope=r["slug"], not_after=9_000_000_000)
        self.spool = spool or _spool()

    def emit(self, outcome):
        return emit_completion_signal(engagement_slug=self.r["slug"], nonce=self.r["nonce"], outcome=outcome,
                                      signers=[("gov", self.key.private_key_b64)], spool_dir=self.spool)

    def watcher(self):
        return CompletionSpoolWatcher(self.store, spool_dir=self.spool, owner_pubkey=self.owner.public_key_b64,
                                      delegation=self.deleg, scope=self.r["slug"], base_dir=_base(),
                                      now_fn=lambda: self.now)


def _grant(r, gid="0"):
    return ModelGrant(grant_id=gid * 32, org_id=ORG, engagement_slug=r["slug"], nonce=r["nonce"],
                      model="test-run-model", effort="high", cap_nano_usd=10 ** 12, not_after=NOW + 86_400,
                      issued_at=NOW - 60)


def _spend(r, *, meter=None):
    from sigil import model_gateway as gw
    m = meter or gw.GrantMeter(config.MODEL_METER_DIR)
    g = _grant(r)
    rid, _reserved, reason = m.reserve(g, 10 ** 6, 25_000, now=NOW)
    assert reason == "", reason
    m.commit(g, rid, USAGE, USAGE_COST, request_id="r", now=NOW)


def _meter_closed(r) -> bool:
    from sigil import model_gateway as gw
    return gw.GrantMeter(config.MODEL_METER_DIR).reserve(_grant(r, "9"), 10 ** 6, 25_000, now=NOW)[2] == "closed"


def _v2_core(r, **over):
    core = {"signal": LAUNCH_SETTLED_SIGNAL, "v": 2, "org_id": ORG, "slug": r["slug"], "nonce": r["nonce"],
            "mode": "prepaid", "reserved": 30, "consumed": 0, "refund_plan": 0, "refund_wallet": 30,
            "refund_postpaid": 0, "plan_period_end": 0.0, "basis": "cancel", "issued_at": NOW}
    core.update(over)
    return core


def _append_signed(store, core, key):
    store.append(kind="event", source="governor", actor="WARDEN",
                 payload={**signed_payload(core, key), "by": "owner", "requested_by": "owner", "tier": "A0",
                          "decision": "auto", "reason": "test"})


# =====================================================================================================================
# findings 0 / 6 — a roll-forward moves the RECORDED split only
# =====================================================================================================================
def test_roll_forward_after_the_reserve_plan_debit_is_pruned_uses_the_recorded_split(record_on, monkeypatch):
    from sigil.governor import metering
    s = _store()
    _seat(s, credits=20, plan=5)
    r = _reserve(s, units=10)                                         # plan 5 + wallet 5
    assert (_plan(s), _avail(s)) == (0, 15)
    restore = _kill(monkeypatch, WalletRegistry, "grant")            # killed after the plan refund landed
    with pytest.raises(SystemExit):
        _settle(s, r, 0, basis="cancel")
    restore()
    assert (_plan(s), _avail(s)) == (5, 15)
    monkeypatch.setattr(metering.PlanCreditLedger, "debited_entry", lambda *a, **k: None)   # the debit was pruned
    again = _settle(s, r, 0, now=NOW + 90, basis="cancel")           # the customer's re-cancel
    assert again["action"] == "launch_already_settled" and again["rolled_forward"] is True, again
    assert (again["refunded"], again["refunded_plan"], again["refunded_wallet"]) == (5, 0, 5)
    assert (_plan(s), _avail(s)) == (5, 20)                          # nothing laundered plan -> wallet
    assert _entries(s, "settle-wallet:") == 1 and _entries(s, "settle-plan:") == 1


def test_roll_forward_with_nothing_landed_after_the_debit_is_pruned_restores_both_buckets(record_on, monkeypatch):
    from sigil.governor import metering
    s = _store()
    _seat(s, credits=20, plan=5)
    r = _reserve(s, units=10)
    restore = _kill(monkeypatch, metering.PlanCreditLedger, "grant")  # killed before any refund landed
    with pytest.raises(SystemExit):
        _settle(s, r, 0, basis="cancel")
    restore()
    assert (_plan(s), _avail(s)) == (0, 15)
    monkeypatch.setattr(metering.PlanCreditLedger, "debited_entry", lambda *a, **k: None)
    again = _settle(s, r, 0, now=NOW + 90)
    assert (again["refunded_plan"], again["refunded_wallet"], again["rolled_forward"]) == (5, 5, True), again
    assert (_plan(s), _avail(s)) == (5, 20)                          # plan 5 into the RECORDED tranche, wallet 5


def test_a_completed_runs_recorded_zero_refund_is_never_reopened_by_a_recancel_after_prune(record_on, monkeypatch):
    from sigil.governor import metering
    s = _store()
    _seat(s, credits=20, plan=5)
    r = _reserve(s, units=10)
    assert _settle(s, r, 10, basis="completion:completed")["action"] == "launch_settled"
    monkeypatch.setattr(metering.PlanCreditLedger, "debited_entry", lambda *a, **k: None)
    _lose_marker(r)
    again = _settle(s, r, 0, now=NOW + 90, basis="cancel")
    assert again["action"] == "launch_already_settled" and again["refunded"] == 0, again
    assert "rolled_forward" not in again and again["net_spend"] == 10
    assert (_plan(s), _avail(s)) == (0, 15)


def test_the_decision_record_is_owner_signed_over_the_split():
    s = _store()
    _seat(s)
    r = _reserve(s)
    kp = ensure_owner_keypair()
    tampered = signed_payload(_v2_core(r, consumed=30, refund_wallet=0), kp)
    tampered["refund_wallet"] = 30                                   # the split altered after signing
    s.append(kind="event", source="governor", actor="WARDEN", payload=tampered)
    unsigned = {k: v for k, v in signed_payload(_v2_core(r, consumed=30, refund_wallet=0), kp).items() if k != "sig"}
    s.append(kind="event", source="governor", actor="WARDEN", payload=unsigned)
    _append_signed(s, _v2_core(r, consumed=30, refund_wallet=0), generate_keypair())   # a foreign key
    ev = scan_settlement(s, kp.public_key_b64, org_id=ORG, slug=r["slug"], nonce=r["nonce"])
    assert not ev.settled and ev.decision is None and not ev.malformed
    first = _v2_core(r, consumed=30, refund_wallet=0, basis="completion:completed")
    _append_signed(s, first, kp)
    _append_signed(s, _v2_core(r), kp)                               # a later competing decision
    ev = scan_settlement(s, kp.public_key_b64, org_id=ORG, slug=r["slug"], nonce=r["nonce"])
    assert ev.decision == SettlementDecision.prepaid(30, 30, 0, 0, 0.0, "completion:completed")   # the first wins
    out = _settle(s, r, 0)
    assert out["action"] == "launch_already_settled" and out["refunded"] == 0 and _avail(s) == 70, out


@pytest.mark.parametrize("over", [{"reserved": 31, "refund_wallet": 31}, {"mode": "postpaid", "refund_wallet": 0,
                                                                         "refund_postpaid": 30}])
def test_a_recorded_decision_that_disagrees_with_the_lease_refuses_the_roll_forward(over):
    s = _store()
    _seat(s)
    r = _reserve(s)
    _append_signed(s, _v2_core(r, **over), ensure_owner_keypair())
    out = _settle(s, r, 0)
    assert out["ok"] is False and "disagrees with the lease" in out["error"], out
    assert _avail(s) == 70 and _entries(s, "settle-") == 0


@pytest.mark.parametrize("core", [
    {"refund_wallet": 29},                                           # owner-signed but the split does not sum
    {"v": 3},                                                        # an unknown version
    "v1",                                                            # the E3bc draft record (consumed only)
], ids=["bad_split", "unknown_version", "legacy_v1"])
def test_a_malformed_or_legacy_owner_signed_record_is_settled_but_never_rolled_forward(core):
    s = _store()
    _seat(s)
    r = _reserve(s)
    kp = ensure_owner_keypair()
    if core == "v1":
        _append_signed(s, {"signal": LAUNCH_SETTLED_SIGNAL, "org_id": ORG, "slug": r["slug"], "nonce": r["nonce"],
                           "consumed": 0, "issued_at": NOW}, kp)
    else:
        _append_signed(s, _v2_core(r, **core), kp)
    ev = scan_settlement(s, kp.public_key_b64, org_id=ORG, slug=r["slug"], nonce=r["nonce"])
    assert ev.settled and ev.malformed and ev.decision is None
    out = _settle(s, r, 0)
    assert out["ok"] is False and "unusable" in out["error"], out    # blocks a fresh settle, moves nothing
    assert _avail(s) == 70 and _entries(s, "settle-") == 0


@pytest.mark.parametrize("decision", [
    SettlementDecision.prepaid(30, 0, 0, 29, 0.0, "cancel"),          # the split does not sum
    SettlementDecision.prepaid(30, 0, -1, 31, 0.0, "cancel"),         # a negative amount
    SettlementDecision("prepaid", 30, 0, 0, True, 0, 0.0, "cancel"),  # a bool amount
    SettlementDecision.prepaid(30, 31, 0, 0, 0.0, "cancel"),          # consumed > reserved
    SettlementDecision("postpaid", 30, 0, 0, 30, 0, 0.0, "cancel"),   # a postpaid wallet refund
    SettlementDecision.prepaid(30, 0, 5, 25, 0.0, "cancel"),          # a plan refund with no tranche
    SettlementDecision.prepaid(30, 0, 5, 25, float("nan"), "cancel"),  # a NaN period_end
    SettlementDecision.prepaid(30, 0, 0, 30, 0.0, "whatever"),        # an unknown basis
], ids=["sum", "negative", "bool", "over", "postpaid_wallet", "no_tranche", "nan", "basis"])
def test_record_launch_settled_rejects_an_inconsistent_split(decision):
    s = _store()
    kp = ensure_owner_keypair()
    with pytest.raises(ValueError):
        record_launch_settled(s, kp, org_id=ORG, slug="cust_x", nonce="n1", decision=decision, issued_at=NOW)
    assert s.next_seq == 0


def test_a_pruned_landed_entry_is_not_reissued_by_a_roll_forward(record_on, monkeypatch):
    s = _store()
    _seat(s)
    r = _reserve(s)
    assert _settle(s, r, 0, basis="cancel")["refunded_wallet"] == 30 and _avail(s) == 100
    _lose_marker(r)
    real = ls.scan_settlement

    def _live_miss(*a, **k):                                         # the refund grant fell out of the live window
        ev = real(*a, **k)
        ev.landed.discard("wallet")
        return ev

    monkeypatch.setattr(ls, "scan_settlement", _live_miss)
    tip = s.next_seq - 1
    again = _settle(s, r, 0, now=NOW + 90)
    assert again["action"] == "launch_already_settled" and "rolled_forward" not in again, again
    assert _signals(s, tip) == [] and _avail(s) == 100               # the seen-set confirmed it: nothing re-issued


def test_a_pruned_landed_postpaid_settle_is_not_reissued_by_a_roll_forward(record_on, monkeypatch):
    s = _store()
    _seat(s, credits=0, postpaid=(500, 30))
    r = _reserve(s, units=30)
    assert _settle(s, r, 10, basis="completion:completed")["refunded"] == 20
    _lose_marker(r)
    real = ls.scan_settlement

    def _live_miss(*a, **k):                                         # the settle-postpaid entry left the live window
        ev = real(*a, **k)
        ev.landed.discard("postpaid")
        return ev

    monkeypatch.setattr(ls, "scan_settlement", _live_miss)
    tip = s.next_seq - 1
    again = _settle(s, r, 0, now=NOW + 90, basis="cancel")
    assert again["action"] == "launch_already_settled" and "rolled_forward" not in again, again
    assert again["refunded"] == 0 and _signals(s, tip) == []          # the seen-set confirmed it: nothing re-issued
    assert PostpaidArrearsLedger(s).accrued(ORG) == 10


def test_forged_settle_entries_are_ignored_as_evidence(flag):
    s = _store()
    _seat(s, credits=100)
    r = _reserve(s)
    tail = f"{r['slug']}:{r['nonce']}"
    foreign = generate_keypair()
    WalletRegistry(s, owner_key=foreign).grant(ORG, 1, "refund", entry_id=f"settle-wallet:{tail}", issued_at=NOW)
    PlanCreditLedger(s, owner_key=foreign).grant(ORG, 1, period_end=1e12, entry_id=f"settle-plan:{tail}",
                                                 issued_at=NOW)
    PostpaidArrearsLedger(s, owner_key=foreign).settle(ORG, 0, entry_id=f"settle-postpaid:{tail}", issued_at=NOW)
    _append_signed(s, _v2_core(r, consumed=30, refund_wallet=0), foreign)
    ev = scan_settlement(s, ensure_owner_keypair().public_key_b64, org_id=ORG, slug=r["slug"], nonce=r["nonce"])
    assert not ev.settled
    out = _settle(s, r, 0)
    assert out["action"] == "launch_settled" and out["refunded_wallet"] == 30 and _avail(s) == 100, out


# =====================================================================================================================
# finding 5 — a roll-forward that moved money says so, on every caller
# =====================================================================================================================
def test_a_sweep_roll_forward_reports_settle_completed_with_its_amounts(record_on, monkeypatch):
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    spool = _spool()
    restore = _kill(monkeypatch, WalletRegistry, "grant")
    with pytest.raises(SystemExit):
        _sweep(LaunchGate(s), spool)
    restore()
    _lose_marker(r)                                                  # the main settle path, not the finish path
    rows = _sweep(LaunchGate(s), spool)
    assert [(x["status"], x["refunded"], x["refunded_wallet"], x["net_spend"]) for x in rows] == [
        ("settle_completed", 30, 30, 0)], rows
    assert _avail(s) == 100


def test_a_cancel_roll_forward_returns_the_moved_refund(record_on, monkeypatch):
    from sigil.ui.provision import build_provisioner
    s = _store()
    _seat(s)
    r = _reserve(s)
    restore = _kill(monkeypatch, WalletRegistry, "grant")
    with pytest.raises(SystemExit):
        build_provisioner(s).launch_cancel("u", ORG, r["lease"], now=NOW + 60)
    restore()
    assert _avail(s) == 70
    out = build_provisioner(s).launch_cancel("u", ORG, r["lease"], now=NOW + 90)
    assert out == {"slug": r["slug"], "refunded": 30} and _avail(s) == 100
    audits = [x.payload for x in s.iter_records() if (x.payload or {}).get("signal") == "provision.audit"]
    assert audits[-1]["outcome"] == "rolled_forward"
    lost = build_provisioner(s).launch_cancel("u", ORG, r["lease"], now=NOW + 99)   # a losing cancel: honest
    assert lost == {"slug": r["slug"], "refunded": 0, "already_settled": True} and _avail(s) == 100


def test_a_plain_re_settle_carries_no_rolled_forward_key(flag):
    s = _store()
    _seat(s)
    r = _reserve(s)
    first = _settle(s, r, 0)
    again = _settle(s, r, 0)
    keys = {"ok", "action", "org_id", "slug", "refunded", "refunded_plan", "refunded_wallet", "net_spend"}
    assert set(first) == keys and set(again) == keys, (first, again)
    assert again["action"] == "launch_already_settled" and again["refunded"] == 0


def test_a_drain_roll_forward_of_a_completion_emits_ntf3_once_and_a_sweep_basis_roll_forward_does_not(record_on,
                                                                                                    monkeypatch):
    s = _store()
    _seat(s, credits=200)
    r = _reserve(s, publish=True)
    gov = _Gov(s, r)
    gov.emit("failed")
    restore = _kill(monkeypatch, WalletRegistry, "grant")
    with pytest.raises(SystemExit):
        gov.watcher().drain()
    restore()
    out = gov.watcher().drain()                                      # the re-drive finishes it (reclaimed)
    assert out["settled"] == 1 and _avail(s) == 200
    outcomes = [x.payload for x in s.iter_records() if x.kind == "assessment_outcome"]
    assert [o["outcome"] for o in outcomes] == ["failed"]
    assert gov.watcher().drain()["settled"] == 0                     # nothing left: no second record
    # a roll-forward of a SWEEP decision, driven by a later completion, emits nothing
    r2 = _reserve(s, publish=True)
    restore = _kill(monkeypatch, WalletRegistry, "grant")
    with pytest.raises(SystemExit):
        _settle(s, r2, 0, basis="sweep:refund")
    restore()
    gov2 = _Gov(s, r2)
    gov2.emit("completed")
    res = gov2.watcher().drain()
    assert res["settled"] == 1 and _avail(s) == 200                  # the RECORDED refund, not a charge
    assert [x.payload["outcome"] for x in s.iter_records() if x.kind == "assessment_outcome"] == ["failed"]


# =====================================================================================================================
# finding 7 — the spool lock orders the drain's reverse moves with the sweep's in-lock completion re-check
# =====================================================================================================================
def test_the_completion_recheck_sees_a_completion_reclaimed_between_its_globs(monkeypatch):
    """A completion stranded in working/ (a crashed claim) is moved back to incoming/ by the drain's reclaim exactly
    while the sweep's in-lock re-check is between its incoming/ and working/ globs: the reclaim waits on the spool
    lock, so the re-check still sees the completion and refuses the refund."""
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    gov = _Gov(s, r)
    w = gov.watcher()                                                # creates the spool dirs + its lock
    gate = LaunchGate(s)
    real_settle = gate.settle_launch
    real_glob = Path.glob
    seen = {"armed": False, "alive": None}
    reclaim = threading.Thread(target=w._reclaim_working)

    def _strand_then_settle(**kw):                                   # after the sweep's up-front snapshot
        f = gov.emit("completed")
        os.replace(f, Path(gov.spool) / "working" / f.name)
        seen["armed"] = True
        return real_settle(**kw)

    def _glob(self, pattern):
        if seen["armed"] and self == Path(gov.spool) / "working":
            seen["armed"] = False
            reclaim.start()                                          # the drain's reclaim, between the two globs
            reclaim.join(0.5)
            seen["alive"] = reclaim.is_alive()
        return real_glob(self, pattern)

    monkeypatch.setattr(gate, "settle_launch", _strand_then_settle)
    monkeypatch.setattr(Path, "glob", _glob)
    rows = _sweep(gate, gov.spool)
    reclaim.join(10)
    assert seen["alive"] is True                                     # it waited for the sweep's shared hold
    assert [x["status"] for x in rows] == ["completion_pending"] and _avail(s) == 70, rows
    assert not is_lease_settled(_base(), r["slug"], r["nonce"])
    assert len(list((Path(gov.spool) / "incoming").glob("*.json"))) == 1   # ...and then reclaimed it


def test_the_deferred_return_waits_for_the_completion_recheck(monkeypatch):
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    gov = _Gov(s, r)
    w = gov.watcher()
    gov.emit("completed")
    monkeypatch.setattr(CompletionSpoolWatcher, "_SPOOL_LOCK_WAIT_S", 0.2)
    real_close = LaunchGate._close_model_meter
    monkeypatch.setattr(LaunchGate, "_close_model_meter",
                        lambda self, slug, nonce, now_ts: {"ok": False, "retry": True, "error": "busy"})
    fd = os.open(str(Path(gov.spool) / ".spool.lock"), os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)                               # the sweep's in-lock re-check holds it
        out = w.drain()
        assert out.get("deferred") == 1 and out["rejected"] == 0, out
        assert len(list(w.working.glob("*.json"))) == 1 and not list(w.incoming.glob("*.json"))   # not moved back
    finally:
        os.close(fd)
    monkeypatch.setattr(LaunchGate, "_close_model_meter", real_close)
    out = gov.watcher().drain()                                      # reclaimed, then settled
    assert out["settled"] == 1 and _avail(s) == 70


@pytest.mark.parametrize("kind", ["dir", "fifo", "symlink"])
def test_an_unlockable_spool_is_completion_unknown(kind):
    s = _store()
    _seat(s)
    _reserve(s, publish=True)
    spool = _spool()
    p = Path(spool) / ".spool.lock"
    if kind == "dir":
        p.mkdir()
    elif kind == "fifo":
        os.mkfifo(p)
    else:
        (Path(spool) / "elsewhere").write_text("", encoding="utf-8")
        p.symlink_to(Path(spool) / "elsewhere")
    t0 = time.monotonic()
    rows = _sweep(LaunchGate(s), spool)
    assert time.monotonic() - t0 < 4.0                               # no hang on the lock
    assert [x["status"] for x in rows] == ["completion_unknown"] and _avail(s) == 70, rows


def test_a_mispointed_spool_creates_no_lock_file():
    s = _store()
    _seat(s)
    _reserve(s, publish=True)
    spool = tempfile.mkdtemp()                                       # none of the drain's subdirs
    rows = _sweep(LaunchGate(s), spool)
    assert [x["status"] for x in rows] == ["completion_unknown"] and _avail(s) == 70
    assert os.listdir(spool) == []


def test_the_drain_creates_the_spool_lock():
    s = _store()
    _seat(s)
    r = _reserve(s)
    w = _Gov(s, r, spool=tempfile.mkdtemp()).watcher()
    p = w.spool / ".spool.lock"
    assert p.is_file() and not p.is_symlink() and (p.stat().st_mode & 0o777) == 0o600


def test_a_reclaim_that_cannot_lock_leaves_files_in_working_and_the_sweep_reads_them_as_pending():
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    gov = _Gov(s, r)
    w = gov.watcher()
    f = gov.emit("completed")
    os.replace(f, w.working / f.name)
    (w.spool / ".spool.lock").unlink()
    (w.spool / ".spool.lock").mkdir()                                # the lock is unusable
    w._reclaim_working()
    assert [p.name for p in w.working.glob("*.json")] == [f.name]   # left in working/, not lost
    rows = _sweep(LaunchGate(s), gov.spool)
    assert [x["status"] for x in rows] == ["completion_pending"] and _avail(s) == 70


# =====================================================================================================================
# finding 11 — with the flag on, the sweep finishes its own interrupted settle
# =====================================================================================================================
def test_flag_on_sweep_finishes_its_own_interrupted_refund(record_on, monkeypatch):
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    spool = _spool()
    restore = _kill(monkeypatch, WalletRegistry, "grant")
    with pytest.raises(SystemExit):
        _sweep(LaunchGate(s), spool)                                 # dies after the decision + marker
    restore()
    assert _avail(s) == 70 and is_lease_settled(_base(), r["slug"], r["nonce"])
    assert read_credit_lease(_base(), r["slug"]) is not None         # the tombstone is last: still listed
    rows = _sweep(LaunchGate(s), spool)
    assert [(x["status"], x["refunded"], x["refunded_wallet"]) for x in rows] == [("settle_completed", 30, 30)]
    assert _avail(s) == 100
    tip = s.next_seq - 1
    assert _sweep(LaunchGate(s), spool) == [] and _signals(s, tip) == []
    assert read_credit_lease(_base(), r["slug"]) is None


def test_flag_on_sweep_finishes_an_interrupted_postpaid_settle(record_on, monkeypatch):
    s = _store()
    _seat(s, credits=0, postpaid=(500, 30))
    r = _reserve(s, units=100, nonce="pp1", publish=True)
    spool = _spool()
    restore = _kill(monkeypatch, PostpaidArrearsLedger, "settle")
    with pytest.raises(SystemExit):
        _sweep(LaunchGate(s), spool)
    restore()
    assert PostpaidArrearsLedger(s).accrued(ORG) == 100
    rows = _sweep(LaunchGate(s), spool)
    assert [(x["status"], x["refunded"]) for x in rows] == [("settle_completed", 100)]
    assert PostpaidArrearsLedger(s).accrued(ORG) == 0
    assert _sweep(LaunchGate(s), spool) == [] and PostpaidArrearsLedger(s).accrued(ORG) == 0


def test_flag_on_finish_path_ignores_ttl_and_pending_completions(record_on, monkeypatch):
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    restore = _kill(monkeypatch, WalletRegistry, "grant")
    with pytest.raises(SystemExit):
        _settle(s, r, 0, basis="cancel")
    restore()
    gov = _Gov(s, r)
    gov.emit("completed")                                            # a completion is pending
    rows = _sweep(LaunchGate(s), gov.spool, now=NOW + 60)            # and the lease is still inside its window
    assert [(x["status"], x["refunded_wallet"]) for x in rows] == [("settle_completed", 30)] and _avail(s) == 100


def test_flag_on_finish_path_with_a_broken_meter_still_rolls_forward(record_on, monkeypatch):
    _metered(monkeypatch)
    s = _store()
    _seat(s, credits=1_000)
    r = _reserve(s, units=900, publish=True, hours=8)
    _spend(r)
    spool = _spool()
    restore = _kill(monkeypatch, WalletRegistry, "grant")
    with pytest.raises(SystemExit):
        _sweep(LaunchGate(s), spool, now=MLATE, ttl=86400)           # an unpaused metered launch: a full refund
    restore()
    p = config.MODEL_METER_DIR / f"{meter_id(r['slug'], r['nonce'])}.jsonl"
    p.write_text("\n".join(p.read_text().splitlines()[1:]) + "\n")   # the meter's hash chain is now broken
    rows = _sweep(LaunchGate(s), spool, now=MLATE, ttl=86400)
    assert [(x["status"], x["refunded"]) for x in rows] == [("settle_completed", 900)] and _avail(s) == 1_000


def test_flag_off_sweep_still_skips_a_marker_present_lease(monkeypatch):
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    spool = _spool()
    restore = _kill(monkeypatch, WalletRegistry, "grant")
    with pytest.raises(SystemExit):
        _sweep(LaunchGate(s), spool)
    restore()
    tip = s.next_seq - 1
    assert _sweep(LaunchGate(s), spool) == [] and _signals(s, tip) == [] and _avail(s) == 70   # main: stranded
    assert read_credit_lease(_base(), r["slug"]) is not None


def test_finish_only_never_makes_a_fresh_decision(record_on, monkeypatch):
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    tip = s.next_seq - 1
    out = _settle(s, r, 0, finish_only=True)
    assert out["action"] == "launch_not_settled" and out["refunded"] == 0, out
    assert _signals(s, tip) == [] and not is_lease_settled(_base(), r["slug"], r["nonce"]) and _avail(s) == 70
    # via the sweep: a flag-off COMPLETED settle left only its marker; the marker vanishes between the listing and
    # the settle — the finish path must not turn that charged run into a fresh full refund
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "")
    assert _settle(s, r, 30)["action"] == "launch_settled" and _avail(s) == 70
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")
    from vigil_integration.live.credit_lease_broker import write_credit_lease
    from vigil_core import SignedCreditLaunchLease, TrustRoot
    signed = SignedCreditLaunchLease.model_validate(r["lease"])
    write_credit_lease(_base(), r["slug"], signed, TrustRoot.model_validate(r["trust_root"]))   # a stale bundle
    gate = LaunchGate(s)
    real = gate.settle_launch

    def _marker_vanishes(**kw):
        _lose_marker(r)
        return real(**kw)

    monkeypatch.setattr(gate, "settle_launch", _marker_vanishes)
    tip = s.next_seq - 1
    assert _sweep(gate, _spool()) == [] and _avail(s) == 70 and _signals(s, tip) == []


def test_report_only_sweep_shows_an_interrupted_settle(record_on, monkeypatch):
    s = _store()
    _seat(s)
    _reserve(s, publish=True)
    spool = _spool()
    restore = _kill(monkeypatch, WalletRegistry, "grant")
    with pytest.raises(SystemExit):
        _sweep(LaunchGate(s), spool)
    restore()
    tip = s.next_seq - 1
    rows = _sweep(LaunchGate(s), spool, apply=False)
    assert [(x["status"], x["pending_wallet"], x["pending_plan"], x["consumed"], x["basis"]) for x in rows] == [
        ("settle_interrupted", 30, 0, 0, "sweep:refund")], rows
    assert _signals(s, tip) == [] and _avail(s) == 70


def test_a_mover_oserror_after_the_decision_returns_retry_and_the_drain_defers_not_quarantines(record_on,
                                                                                                monkeypatch):
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    gov = _Gov(s, r)
    gov.emit("failed")
    restore = _kill(monkeypatch, WalletRegistry, "grant", exc=OSError("disk full"))
    out = gov.watcher().drain()
    restore()
    assert (out["settled"], out["rejected"], out.get("deferred")) == (0, 0, 1), out
    assert len(_decisions(s)) == 1 and _avail(s) == 70
    out = gov.watcher().drain()
    assert out["settled"] == 1 and _avail(s) == 100 and len(_decisions(s)) == 1


# =====================================================================================================================
# finding 12 — refuse_if runs before the settle's meter close and before the record (flag OFF and ON)
# =====================================================================================================================
def _spy_meter_close(monkeypatch):
    calls = []
    real = LaunchGate._close_model_meter

    def _spy(self, slug, nonce, now_ts):
        calls.append((slug, nonce))
        return real(self, slug, nonce, now_ts)

    monkeypatch.setattr(LaunchGate, "_close_model_meter", _spy)
    return calls


# How settle_launch handles each refusal reason a caller's precondition can give (a stub precondition). The callers'
# real in-lock producers are pinned separately (test_the_sweeps_in_lock_*, test_a_pause_landing_after_*,
# test_a_failed_completion_whose_past_expiry_record_*, test_a_refused_cancel_of_a_started_*).
@pytest.mark.parametrize("why", ["completion_pending", "completion_unknown", "pause_changed", "pause_unknown",
                                 "started", "raises"])
def test_a_refused_settle_writes_no_decision_and_a_later_charge_is_fresh(flag, why, monkeypatch):
    s = _store()
    _seat(s)
    r = _reserve(s)
    calls = _spy_meter_close(monkeypatch)

    def _pre():
        if why == "raises":
            raise OSError("cannot tell")
        return why

    tip = s.next_seq - 1
    out = _settle(s, r, 0, refuse_if=_pre)
    assert out["ok"] is False and out["refused"] and _avail(s) == 70, out
    assert _signals(s, tip) == [] and not _decisions(s) and calls == []
    assert not is_lease_settled(_base(), r["slug"], r["nonce"])
    later = _settle(s, r, 30, now=NOW + 90)                          # the completion's charge is FRESH
    assert later["action"] == "launch_settled" and later["refunded"] == 0 and _avail(s) == 70, later


def test_a_meter_retry_writes_no_decision(flag, monkeypatch):
    from sigil import model_gateway as gw
    _metered(monkeypatch)
    s = _store()
    _seat(s, credits=1_000)
    r = _reserve(s, units=900, publish=True, hours=8)
    live = gw.GrantMeter(config.MODEL_METER_DIR, gateway=True)
    try:
        _spend(r, meter=live)
        grant = _grant(r, "2")
        rid, _res, reason = live.reserve(grant, 10 ** 6, 25_000, now=NOW)   # a request still in flight
        assert reason == ""
        busy = _settle(s, r, 0)
        assert busy["ok"] is False and busy.get("retry") is True, busy
        assert not _decisions(s) and not is_lease_settled(_base(), r["slug"], r["nonce"]) and _avail(s) == 100
        assert _meter_closed(r)                                      # admission stopped (MeterBusy closes first)
        gov = _Gov(s, r, now=NOW)
        gov.emit("completed")
        assert gov.watcher().drain().get("deferred") == 1 and _avail(s) == 100
        live.commit(grant, rid, USAGE, USAGE_COST, request_id="r2", now=NOW)
        out = gov.watcher().drain()
        assert out["settled"] == 1 and _avail(s) == 1_000 - 107      # charged FRESH: both responses
    finally:
        live.shutdown()


_HOLD = r"""
import fcntl, os, sys, time
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
open(sys.argv[2], "w").close()
time.sleep(60)
"""


def test_settle_lock_busy_or_unopenable_is_retryable_and_writes_nothing(flag, monkeypatch):
    monkeypatch.setenv("VIGIL_SETTLE_LOCK_WAIT_S", "0.3")
    s = _store()
    _seat(s)
    r = _reserve(s)
    ready = Path(tempfile.mkdtemp()) / "ready"
    h = subprocess.Popen([sys.executable, "-c", _HOLD, str(settle_lock_path(s)), str(ready)])
    try:
        deadline = time.monotonic() + 30
        while not ready.exists():
            assert time.monotonic() < deadline and h.poll() is None
            time.sleep(0.01)
        tip = s.next_seq - 1
        t0 = time.monotonic()
        out = _settle(s, r, 0)
        assert time.monotonic() - t0 < 3.0
        assert out["ok"] is False and out.get("retry") is True and "settle lock" in out["error"], out
        assert _signals(s, tip) == [] and _avail(s) == 70 and not is_lease_settled(_base(), r["slug"], r["nonce"])
        pub = LaunchGate(s).publish_lease(signed_lease=r["lease"], expect_org_id=ORG)
        assert pub["ok"] is False and pub.get("retry") is True and read_credit_lease(_base(), r["slug"]) is None
    finally:
        h.kill()
        h.wait()
    os.unlink(settle_lock_path(s))
    os.mkfifo(settle_lock_path(s))                                   # an unusable lock file: never a hang
    t0 = time.monotonic()
    out = _settle(s, r, 0)
    assert time.monotonic() - t0 < 3.0 and out["ok"] is False and out.get("retry") is True and _avail(s) == 70


def test_a_record_append_failure_returns_retry_and_moves_nothing(record_on, monkeypatch):
    s = _store()
    _seat(s)
    r = _reserve(s)

    def _boom(*a, **k):
        raise OSError("spine full")

    real = ls.record_launch_settled
    monkeypatch.setattr(ls, "record_launch_settled", _boom)
    out = _settle(s, r, 0)
    assert out["ok"] is False and out.get("retry") is True and _avail(s) == 70, out
    assert not is_lease_settled(_base(), r["slug"], r["nonce"])
    monkeypatch.setattr(ls, "record_launch_settled", real)
    assert _settle(s, r, 0)["action"] == "launch_settled" and _avail(s) == 100


def test_the_sweeps_in_lock_completion_unknown_branch_refuses(monkeypatch):
    s = _store()
    _seat(s)
    _reserve(s, publish=True)
    spool = _spool()
    gate = LaunchGate(s)
    real = gate.settle_launch

    def _garbage_lands(**kw):
        (Path(spool) / "incoming" / "x.json").write_text("{not json", encoding="utf-8")
        return real(**kw)

    monkeypatch.setattr(gate, "settle_launch", _garbage_lands)
    rows = _sweep(gate, spool)
    assert [x["status"] for x in rows] == ["completion_unknown"] and _avail(s) == 70


def test_publish_lease_in_lock_rescan_refuses_a_decision_landing_after_its_unlocked_scan(record_on, monkeypatch):
    s = _store()
    _seat(s)
    r = _reserve(s)
    real = ls.scan_settlement
    calls = {"n": 0}

    def _scan(*a, **k):
        ev = real(*a, **k)
        calls["n"] += 1
        if calls["n"] == 1:                                          # another process settles it right then
            record_launch_settled(s, ensure_owner_keypair(), org_id=ORG, slug=r["slug"], nonce=r["nonce"],
                                  decision=SettlementDecision.prepaid(30, 0, 0, 30, 0.0, "cancel"), issued_at=NOW)
        return ev

    monkeypatch.setattr(ls, "scan_settlement", _scan)
    out = LaunchGate(s).publish_lease(signed_lease=r["lease"], expect_org_id=ORG)
    assert out["ok"] is False and "settled" in out["error"], out
    assert read_credit_lease(_base(), r["slug"]) is None


# =====================================================================================================================
# the pause-marker lock and the pause / settle linearization
# =====================================================================================================================
def test_a_pause_during_a_stuck_settle_lock_still_records_the_halt(monkeypatch):
    from vigil_integration.live.credit_lease_pause import is_lease_paused
    monkeypatch.setenv("VIGIL_SETTLE_LOCK_WAIT_S", "0.3")
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    free = LaunchGate(s).pause_launch(signed_lease=r["lease"], expect_org_id=ORG)
    assert free["ok"] and "linearized" not in free                   # the lock was free: linearized
    r2 = _reserve(s, publish=False)
    fd = os.open(str(settle_lock_path(s)), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)                               # a settle holding it for longer than the wait
        t0 = time.monotonic()
        out = LaunchGate(s).pause_launch(signed_lease=r2["lease"], expect_org_id=ORG)
        assert time.monotonic() - t0 < 3.0
    finally:
        os.close(fd)
    assert out["ok"] is True and out["linearized"] is False, out     # the halt wins (OD-1)
    assert is_lease_paused(_base(), r2["slug"], r2["nonce"])


@pytest.mark.parametrize("fault", ["not_a_file", "permission", "no_path"])
def test_an_unusable_settle_lock_still_records_the_halt(flag, fault, monkeypatch):
    from vigil_integration.live.credit_lease_pause import is_lease_paused
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    if fault == "not_a_file":                                        # e.g. a damaged spine directory
        p = settle_lock_path(s)
        p.unlink(missing_ok=True)
        p.mkdir()
    else:
        exc = PermissionError(13, "Permission denied") if fault == "permission" else ValueError("no path")

        def _unusable(*a, **k):
            raise exc

        monkeypatch.setattr(ls, "settle_lock", _unusable)
    out = LaunchGate(s).pause_launch(signed_lease=r["lease"], expect_org_id=ORG)
    assert out["ok"] is True and out["linearized"] is False, out     # the halt wins (OD-1)
    assert is_lease_paused(_base(), r["slug"], r["nonce"])


def test_an_unusable_settle_lock_still_refuses_to_pause_a_settled_lease(flag):
    from vigil_integration.live.credit_lease_pause import is_lease_paused
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    assert _settle(s, r, 30)["action"] == "launch_settled"
    p = settle_lock_path(s)
    p.unlink(missing_ok=True)
    p.mkdir()
    out = LaunchGate(s).pause_launch(signed_lease=r["lease"], expect_org_id=ORG)
    assert out["ok"] is False and "settled" in out["error"], out
    assert not is_lease_paused(_base(), r["slug"], r["nonce"])


@pytest.mark.parametrize("which", ["unlocked", "in_lock"])
def test_flag_on_a_spine_scan_failure_still_records_the_halt(record_on, which, monkeypatch):
    from sigil.spine.store import SpineError
    from vigil_integration.live.credit_lease_pause import is_lease_paused
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    real = ls.scan_settlement
    calls = {"n": 0}

    def _scan(*a, **k):
        calls["n"] += 1
        if calls["n"] == (1 if which == "unlocked" else 2):
            raise SpineError("a referenced segment is missing")
        return real(*a, **k)

    monkeypatch.setattr(ls, "scan_settlement", _scan)
    out = LaunchGate(s).pause_launch(signed_lease=r["lease"], expect_org_id=ORG)
    assert out["ok"] is True and out["linearized"] is False, out     # decided on the seam marker alone
    assert is_lease_paused(_base(), r["slug"], r["nonce"])
    assert calls["n"] == (1 if which == "unlocked" else 2)


def test_resume_never_takes_the_settle_lock(monkeypatch):
    from vigil_integration.live.credit_lease_pause import is_lease_paused, record_lease_pause
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    record_lease_pause(_base(), r["slug"], r["nonce"])

    def _no(*a, **k):
        raise RuntimeError("resume must never take the settle lock")

    monkeypatch.setattr(ls, "settle_lock", _no)
    assert LaunchGate(s).resume_launch(signed_lease=r["lease"], expect_org_id=ORG, now=NOW + 10)["ok"]
    assert not is_lease_paused(_base(), r["slug"], r["nonce"])
    record_lease_pause(_base(), r["slug"], r["nonce"])
    late = LaunchGate(s).resume_launch(signed_lease=r["lease"], expect_org_id=ORG, now=LATE)
    assert late["ok"] and late["expired"] and not is_lease_paused(_base(), r["slug"], r["nonce"])


def test_a_pause_landing_after_the_sweeps_pause_read_is_honoured(monkeypatch):
    _metered(monkeypatch)
    s = _store()
    _seat(s, credits=1_000)
    r = _reserve(s, units=900, publish=True, hours=8)
    _spend(r)
    spool = _spool()
    gate = LaunchGate(s)
    real = gate.settle_launch

    def _pause_lands(**kw):
        assert gate.pause_launch(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
        return real(**kw)

    monkeypatch.setattr(gate, "settle_launch", _pause_lands)
    rows = _sweep(gate, spool, now=MLATE, ttl=86400)
    assert [x["status"] for x in rows] == ["pause_changed"] and _avail(s) == 100, rows
    assert not _meter_closed(r) and not is_lease_settled(_base(), r["slug"], r["nonce"])
    rows = _sweep(LaunchGate(s), spool, now=MLATE, ttl=86400)       # the next pass applies D4
    assert [(x["status"], x["charged"]) for x in rows] == [("charged_paused", 54)] and _avail(s) == 1_000 - 54


def test_the_sweeps_in_lock_pause_unknown_branch_refuses_a_metered_refund(flag, monkeypatch):
    from vigil_integration.live.credit_lease_pause import pause_path
    _metered(monkeypatch)
    s = _store()
    _seat(s, credits=1_000)
    r = _reserve(s, units=900, publish=True, hours=8)
    _spend(r)
    gate = LaunchGate(s)
    real = gate.settle_launch

    def _marker_turns_unreadable(**kw):                              # after the sweep priced it "not paused"
        p = pause_path(_base(), r["slug"])
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("{not json", encoding="utf-8")
        return real(**kw)

    monkeypatch.setattr(gate, "settle_launch", _marker_turns_unreadable)
    tip = s.next_seq - 1
    rows = _sweep(gate, _spool(), now=MLATE, ttl=86400)
    assert [x["status"] for x in rows] == ["pause_unknown"] and _avail(s) == 100, rows
    assert _signals(s, tip) == [] and not _meter_closed(r)            # nothing refunded, recorded or closed
    assert not is_lease_settled(_base(), r["slug"], r["nonce"])


def test_a_late_resume_between_the_sweeps_pause_reads_never_reads_as_unpaused(monkeypatch):
    import vigil_integration.live.credit_lease_pause as P
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    P.record_lease_pause(_base(), r["slug"], r["nonce"])
    real_pause, real_late = P.lease_pause_state, P.paused_past_expiry
    state = {"resumed": False}

    def _late_resume():
        if not state["resumed"]:
            state["resumed"] = True
            P.record_paused_past_expiry(_base(), r["slug"], r["nonce"])   # resume's order: the late record first,
            P.clear_lease_pause(_base(), r["slug"], r["nonce"])           # then the clear

    def _pause(*a):
        v = real_pause(*a)
        _late_resume()                                               # the resume lands right after this read
        return v

    def _late(*a):
        v = real_late(*a)
        _late_resume()
        return v

    monkeypatch.setattr(P, "lease_pause_state", _pause)
    monkeypatch.setattr(P, "paused_past_expiry", _late)
    assert ops_sweeps._pause_state(_base(), r["slug"], r["nonce"]) is True


def test_resume_records_the_late_record_before_it_clears(monkeypatch):
    import vigil_integration.live.credit_lease_pause as P
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    P.record_lease_pause(_base(), r["slug"], r["nonce"])
    seen = []
    real = P.record_paused_past_expiry

    def _observe(*a, **k):
        seen.append(ops_sweeps._pause_state(_base(), r["slug"], r["nonce"]))   # a settle-side read right now
        return real(*a, **k)

    real_clear = P.clear_lease_pause

    def _observe_clear(*a, **k):
        seen.append(ops_sweeps._pause_state(_base(), r["slug"], r["nonce"]))
        return real_clear(*a, **k)

    monkeypatch.setattr(P, "record_paused_past_expiry", _observe)
    monkeypatch.setattr(P, "clear_lease_pause", _observe_clear)
    assert LaunchGate(s).resume_launch(signed_lease=r["lease"], expect_org_id=ORG, now=LATE)["expired"]
    assert seen == [True, True]                                      # never "never paused" between the two writes
    assert ops_sweeps._pause_state(_base(), r["slug"], r["nonce"]) is True


def test_an_unusable_pause_marker_lock_refuses_pause_and_resume_and_clears_nothing():
    from vigil_integration.live.credit_lease_pause import is_lease_paused, pauses_root, record_lease_pause
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    record_lease_pause(_base(), r["slug"], r["nonce"])
    (pauses_root(_base()) / f"{r['slug']}.json.lock").unlink()
    (pauses_root(_base()) / f"{r['slug']}.json.lock").mkdir()
    out = LaunchGate(s).resume_launch(signed_lease=r["lease"], expect_org_id=ORG, now=NOW + 10)
    assert out["ok"] is False and "fail-closed" in out["error"], out
    assert is_lease_paused(_base(), r["slug"], r["nonce"])           # nothing cleared
    r2 = _reserve(s)
    out = LaunchGate(s).pause_launch(signed_lease=r2["lease"], expect_org_id=ORG)
    assert out["ok"] is False and "fail-closed" in out["error"], out


def test_a_lease_settled_on_the_spine_with_the_seam_lost_cannot_be_paused(flag):
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    assert _settle(s, r, 30)["action"] == "launch_settled"          # a completed run: no refund on the spine
    _lose_seam()
    out = LaunchGate(s).pause_launch(signed_lease=r["lease"], expect_org_id=ORG)
    if flag:
        assert out["ok"] is False and "settled" in out["error"], out
    else:
        assert out["ok"] is True                                     # flag off: main (only the seam marker counts)


# =====================================================================================================================
# the main merge: M1c meter close, D3, D4, cost settle, one launch per host
# =====================================================================================================================
def test_a_refused_cancel_of_a_started_metered_launch_leaves_its_meter_open(flag, monkeypatch):
    from sigil.ui import launch_gate as lg
    from sigil.ui.provision import ProvisionDenied, build_provisioner
    from vigil_integration.live.model_grant_broker import read_model_grant
    _metered(monkeypatch)
    s = _store()
    _seat(s, credits=1_000)
    r = _reserve(s, units=900, hours=8)
    real = lg.LaunchGate.settle_launch

    def _start_lands_then_settle(self, **kw):                        # after the cancel's eager pre-check
        assert LaunchGate(s).publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
        return real(self, **kw)

    monkeypatch.setattr(lg.LaunchGate, "settle_launch", _start_lands_then_settle)
    with pytest.raises(ProvisionDenied, match="has been started"):
        build_provisioner(s).launch_cancel("u", ORG, r["lease"], now=NOW + 60)
    assert not _meter_closed(r) and read_model_grant(_base(), r["slug"]) is not None
    assert _avail(s) == 100 and not is_lease_settled(_base(), r["slug"], r["nonce"])


def test_a_sweep_refusal_of_an_unpaused_metered_launch_leaves_its_meter_open(monkeypatch):
    _metered(monkeypatch)
    s = _store()
    _seat(s, credits=1_000)
    r = _reserve(s, units=900, publish=True, hours=8)
    _spend(r)
    gov = _Gov(s, r)
    gate = LaunchGate(s)
    real = gate.settle_launch

    def _completion_lands(**kw):
        gov.emit("completed")
        return real(**kw)

    monkeypatch.setattr(gate, "settle_launch", _completion_lands)
    rows = _sweep(gate, gov.spool, now=MLATE, ttl=86400)
    assert [x["status"] for x in rows] == ["completion_pending"] and not _meter_closed(r) and _avail(s) == 100


def test_a_sweep_refusal_of_a_paused_metered_launch_leaves_it_unsettled_and_the_next_pass_charges(monkeypatch):
    from vigil_integration.live.credit_lease_pause import record_lease_pause
    _metered(monkeypatch)
    s = _store()
    _seat(s, credits=1_000)
    r = _reserve(s, units=900, publish=True, hours=8)
    _spend(r)
    record_lease_pause(_base(), r["slug"], r["nonce"])
    spool = _spool()
    gate = LaunchGate(s)
    real = gate.settle_launch
    bad = Path(spool) / "incoming" / "x.json"

    def _garbage_lands(**kw):
        bad.write_text("{not json", encoding="utf-8")
        return real(**kw)

    monkeypatch.setattr(gate, "settle_launch", _garbage_lands)
    rows = _sweep(gate, spool, now=MLATE, ttl=86400)
    assert [x["status"] for x in rows] == ["completion_unknown"] and _avail(s) == 100
    assert _meter_closed(r) and not is_lease_settled(_base(), r["slug"], r["nonce"])   # priced, then refused
    bad.unlink()
    rows = _sweep(LaunchGate(s), spool, now=MLATE, ttl=86400)
    assert [(x["status"], x["charged"]) for x in rows] == [("charged_paused", 54)] and _avail(s) == 1_000 - 54


def test_a_failed_completion_whose_past_expiry_record_flips_in_lock_is_deferred_then_charged_under_d4(monkeypatch):
    from vigil_integration.live.credit_lease_pause import record_lease_pause
    _metered(monkeypatch)
    s = _store()
    _seat(s, credits=1_000)
    r = _reserve(s, units=900, publish=True, hours=8)
    _spend(r)
    record_lease_pause(_base(), r["slug"], r["nonce"])
    gov = _Gov(s, r, now=MLATE)
    gov.emit("failed")
    w = gov.watcher()
    real = w._gate.settle_launch

    def _late_resume_lands(**kw):                                    # after the drain priced the FAILED run as free
        assert w._gate.resume_launch(signed_lease=r["lease"], expect_org_id=ORG, now=MLATE)["expired"]
        return real(**kw)

    monkeypatch.setattr(w._gate, "settle_launch", _late_resume_lands)
    out = w.drain()
    assert out.get("deferred") == 1 and out["settled"] == 0 and _avail(s) == 100, out
    out = gov.watcher().drain()                                      # re-priced: paused past expiry -> D4
    assert out["settled"] == 1 and _avail(s) == 1_000 - 54, out


def test_a_failed_completion_whose_past_expiry_record_turns_unreadable_in_lock_is_deferred(flag, monkeypatch):
    import vigil_integration.live.credit_lease_pause as P
    _metered(monkeypatch)
    s = _store()
    _seat(s, credits=1_000)
    r = _reserve(s, units=900, publish=True, hours=8)
    _spend(r)
    gov = _Gov(s, r, now=MLATE)
    gov.emit("failed")
    w = gov.watcher()
    real = w._gate.settle_launch
    late = P._past_expiry_path(_base(), r["slug"])

    def _record_turns_unreadable(**kw):                              # after the drain priced the FAILED run as free
        late.parent.mkdir(parents=True, exist_ok=True)
        late.write_text("{not json", encoding="utf-8")
        return real(**kw)

    monkeypatch.setattr(w._gate, "settle_launch", _record_turns_unreadable)
    tip = s.next_seq - 1
    out = w.drain()
    assert out.get("deferred") == 1 and out["settled"] == 0 and out["rejected"] == 0, out
    assert _avail(s) == 100 and _signals(s, tip) == []               # nothing refunded or recorded on a guess
    assert not is_lease_settled(_base(), r["slug"], r["nonce"])
    late.unlink()                                                    # readable again (no late record): decided afresh
    out = gov.watcher().drain()
    assert out["settled"] == 1 and _avail(s) == 1_000, out


def test_flag_on_a_d3_metered_cancel_charge_survives_seam_loss(record_on, monkeypatch):
    from sigil.ui.provision import build_provisioner
    _metered(monkeypatch)
    s = _store()
    _seat(s, credits=1_000)
    r = _reserve(s, units=900, publish=True, hours=8)
    _spend(r)
    gov = _Gov(s, r, now=NOW)
    gov.emit("canceled")
    assert gov.watcher().drain()["settled"] == 1 and _avail(s) == 1_000 - 54
    (d,) = _decisions(s)
    assert (d.payload["consumed"], d.payload["basis"], d.payload["refund_wallet"]) == (54, "completion:canceled", 846)
    _lose_seam()
    out = build_provisioner(s).launch_cancel("u", ORG, r["lease"], now=NOW + 120)
    assert out["refunded"] == 0 and out.get("already_settled") is True and _avail(s) == 1_000 - 54


def test_flag_on_a_d4_paused_charge_survives_seam_loss(record_on, monkeypatch):
    from sigil.ui.provision import build_provisioner
    from vigil_integration.live.credit_lease_pause import record_lease_pause
    _metered(monkeypatch)
    s = _store()
    _seat(s, credits=1_000)
    r = _reserve(s, units=900, publish=True, hours=8)
    _spend(r)
    record_lease_pause(_base(), r["slug"], r["nonce"])
    rows = _sweep(LaunchGate(s), _spool(), now=MLATE, ttl=86400)
    assert [x["status"] for x in rows] == ["charged_paused"] and _avail(s) == 1_000 - 54
    assert _decisions(s)[0].payload["basis"] == "sweep:paused"
    _lose_seam()
    out = build_provisioner(s).launch_cancel("u", ORG, r["lease"], now=MLATE + 1)
    assert out["refunded"] == 0 and _avail(s) == 1_000 - 54


def test_flag_on_a_failed_paused_past_expiry_charge_is_recorded(record_on, monkeypatch):
    from vigil_integration.live.credit_lease_pause import record_lease_pause
    _metered(monkeypatch)
    s = _store()
    _seat(s, credits=1_000)
    r = _reserve(s, units=900, publish=True, hours=8)
    _spend(r)
    record_lease_pause(_base(), r["slug"], r["nonce"])
    assert LaunchGate(s).resume_launch(signed_lease=r["lease"], expect_org_id=ORG, now=MLATE)["expired"]
    gov = _Gov(s, r, now=MLATE)
    gov.emit("failed")
    assert gov.watcher().drain()["settled"] == 1 and _avail(s) == 1_000 - 54
    (d,) = _decisions(s)
    assert (d.payload["consumed"], d.payload["basis"]) == (54, "completion:failed")
    again = _settle(s, r, 0, now=MLATE + 5, basis="cancel")          # a later cancel: the recorded charge stands
    assert again["action"] == "launch_already_settled" and again["refunded"] == 0 and again["net_spend"] == 54


def test_roll_forward_resettles_the_cost_ledger_once_when_cost_writes_are_on(record_on, monkeypatch):
    from sigil.governor.cost_ledger import COST_SETTLE_SIGNAL, CostEnvelopeLedger
    monkeypatch.setenv("VIGIL_COST_LEDGER_WRITE", "1")
    s = _store()
    _seat(s)
    r = _reserve(s)
    restore = _kill(monkeypatch, CostEnvelopeLedger, "settle")      # killed after the money, before the cost settle
    with pytest.raises(SystemExit):
        _settle(s, r, 0)
    restore()
    assert _avail(s) == 100 and _signals(s).count(COST_SETTLE_SIGNAL) == 0
    again = _settle(s, r, 0, now=NOW + 90)
    assert again["action"] == "launch_already_settled" and _signals(s).count(COST_SETTLE_SIGNAL) == 1
    _settle(s, r, 0, now=NOW + 99)
    assert _signals(s).count(COST_SETTLE_SIGNAL) == 1 and _avail(s) == 100


def test_earlier_launch_spine_settled_with_lost_marker_does_not_block_a_new_metered_launch(flag, monkeypatch):
    _metered(monkeypatch)
    s = _store()
    _seat(s, credits=1_000)
    r1 = _reserve(s, units=100, publish=True, hours=8)
    stale = tempfile.mkdtemp()
    shutil.rmtree(stale)
    shutil.copytree(_base(), stale)                                  # a backup taken while r1 ran
    assert _settle(s, r1, 30)["action"] == "launch_settled"         # a completed run: no refund on the spine
    shutil.rmtree(_base())
    shutil.copytree(stale, _base())                                  # ...restored: r1's bundle back, its marker lost
    r2 = _reserve(s, units=100, hours=8)
    out = LaunchGate(s).publish_lease(signed_lease=r2["lease"], expect_org_id=ORG)
    if flag:
        assert out["ok"] is True, out                                # the spine says r1 settled
        assert is_lease_settled(_base(), r1["slug"], r1["nonce"])    # and its lost marker is re-asserted
    else:
        assert out["ok"] is False and "earlier launch" in out["error"], out   # main: the marker alone decides


# =====================================================================================================================
# the seam holds one lease per org+host: a relaunch never replaces a lease whose recorded settle is unfinished
# =====================================================================================================================
def _relaunch(s, units, nonce):
    r = LaunchGate(s).reserve_launch(requester="u", org_id=ORG, host=HOST, units=units, now=NOW + 120,
                                     duration_hours=8, nonce=nonce)
    assert r["ok"], r
    return r, LaunchGate(s).publish_lease(signed_lease=r["lease"], expect_org_id=ORG)


@pytest.mark.parametrize("mode", ["flat", "metered"])
def test_flag_on_a_relaunch_waits_for_an_interrupted_drain_settle_and_its_refund_lands(record_on, mode, monkeypatch):
    if mode == "metered":
        _metered(monkeypatch)
    s = _store()
    _seat(s, credits=1_000)
    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    gov = _Gov(s, rA)
    gov.emit("failed")                                               # VIGIL's failure: the whole 300 is owed back
    restore = _kill(monkeypatch, WalletRegistry, "grant", exc=OSError("disk full"))
    assert gov.watcher().drain().get("deferred") == 1               # interrupted after its decision + marker
    restore()
    assert _avail(s) == 700 and LaunchGate(s).interrupted_settlement(rA["lease"])["pending_wallet"] == 300
    rB, out = _relaunch(s, 100, "B" * 16)                            # the customer relaunches on the same host
    assert out["ok"] is False and out.get("retry") is True, out
    assert read_credit_lease(_base(), rA["slug"]).signed_lease.document.nonce == rA["nonce"]   # A's lease stays
    out = gov.watcher().drain()                                      # the drain finishes A from its record
    assert (out["settled"], out["rejected"]) == (1, 0) and _avail(s) == 1_000 - 100, out
    assert LaunchGate(s).interrupted_settlement(rA["lease"]) is None and len(_decisions(s)) == 1
    assert LaunchGate(s).publish_lease(signed_lease=rB["lease"], expect_org_id=ORG)["ok"]
    assert gov.watcher().drain()["settled"] == 0 and _avail(s) == 1_000 - 100   # never refunded twice


@pytest.mark.parametrize("mode", ["flat", "metered"])
@pytest.mark.parametrize("dies", ["before_the_money", "before_the_marker"])
def test_flag_on_a_relaunch_waits_for_an_interrupted_sweep_settle_and_its_refund_lands(record_on, mode, dies,
                                                                                       monkeypatch):
    import vigil_integration.live.credit_lease_broker as B
    if mode == "metered":
        _metered(monkeypatch)
    now, ttl = (MLATE, 86400) if mode == "metered" else (NOW + 8 * 3600 + 100, 50)
    s = _store()
    _seat(s, credits=1_000)
    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    spool = _spool()
    restore = (_kill(monkeypatch, WalletRegistry, "grant") if dies == "before_the_money"
               else _kill(monkeypatch, B, "record_lease_settlement"))
    with pytest.raises(SystemExit):
        _sweep(LaunchGate(s), spool, now=now, ttl=ttl)               # dies after the decision record
    restore()
    assert _avail(s) == 700 and len(_decisions(s)) == 1
    assert is_lease_settled(_base(), rA["slug"], rA["nonce"]) is (dies == "before_the_money")
    rB, out = _relaunch(s, 100, "B" * 16)
    assert out["ok"] is False and out.get("retry") is True, out
    assert read_credit_lease(_base(), rA["slug"]).signed_lease.document.nonce == rA["nonce"]
    rows = _sweep(LaunchGate(s), spool, now=now, ttl=ttl)            # the next pass finishes A from its record
    assert [(x["nonce"], x["status"], x["refunded"]) for x in rows] == [(rA["nonce"], "settle_completed", 300)], rows
    assert _avail(s) == 1_000 - 100 and LaunchGate(s).interrupted_settlement(rA["lease"]) is None
    assert LaunchGate(s).publish_lease(signed_lease=rB["lease"], expect_org_id=ORG)["ok"]
    assert len(_decisions(s)) == 1 and _avail(s) == 1_000 - 100


def test_flag_on_a_relaunch_rescans_in_full_when_the_seams_lease_changed_before_its_locks(record_on, monkeypatch):
    import types
    import vigil_integration.live.credit_lease_broker as B
    s = _store()
    _seat(s, credits=1_000)
    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    gov = _Gov(s, rA)
    gov.emit("failed")
    restore = _kill(monkeypatch, WalletRegistry, "grant", exc=OSError("disk full"))
    assert gov.watcher().drain().get("deferred") == 1
    restore()
    rB = LaunchGate(s).reserve_launch(requester="u", org_id=ORG, host=HOST, units=100, now=NOW + 120,
                                      duration_hours=8, nonce="B" * 16)
    real, calls = B.read_credit_lease, {"n": 0}

    def _read(base, slug):
        calls["n"] += 1
        if calls["n"] == 1:                                          # publish's unlocked read saw another lease
            return types.SimpleNamespace(signed_lease=types.SimpleNamespace(
                document=types.SimpleNamespace(nonce="X" * 16)))
        return real(base, slug)

    monkeypatch.setattr(B, "read_credit_lease", _read)
    out = LaunchGate(s).publish_lease(signed_lease=rB["lease"], expect_org_id=ORG)
    assert out["ok"] is False and out.get("retry") is True, out      # A's evidence was read in full under the locks
    assert real(_base(), rA["slug"]).signed_lease.document.nonce == rA["nonce"] and calls["n"] >= 2


@pytest.mark.parametrize("mode", ["flat", "metered"])
def test_flag_on_a_relaunch_after_a_settle_whose_money_landed_is_not_held_back(record_on, mode, monkeypatch):
    import vigil_integration.live.credit_lease_broker as B
    if mode == "metered":
        _metered(monkeypatch)
    s = _store()
    _seat(s, credits=1_000)
    rA = _reserve(s, units=300, publish=True, hours=8, nonce="A" * 16)
    restore = _kill(monkeypatch, B, "tombstone_credit_lease")        # dies after the money, before the tombstone
    with pytest.raises(SystemExit):
        _settle(s, rA, 0, basis="completion:failed")
    restore()
    assert _avail(s) == 1_000 and read_credit_lease(_base(), rA["slug"]) is not None
    _, out = _relaunch(s, 100, "B" * 16)
    assert out["ok"] is True, out                                    # nothing of A's is left to land
    assert read_credit_lease(_base(), rA["slug"]).signed_lease.document.nonce == "B" * 16


# =====================================================================================================================
# the lock order
# =====================================================================================================================
class _LockRecorder:
    """Records every acquisition of the settle path's locks per thread and checks the global rank on each one."""

    def __init__(self):
        self.local = threading.local()
        self.violations: list = []
        self.taken: list = []

    def held(self) -> list:
        if not hasattr(self.local, "stack"):
            self.local.stack = []
        return self.local.stack

    def acquire(self, name: str) -> None:
        held = self.held()
        leaves = [h for h in held if h.startswith("leaf")]
        if name == "publish" and ({"spine", "settle"} & set(held)):
            self.violations.append(f"publish lock under {held}")
        if name == "settle" and ("spine" not in held or "settle" in held or leaves):
            self.violations.append(f"settle lock under {held}")
        if name == "spine" and leaves:
            self.violations.append(f"spine lock under {held}")
        if name.startswith("leaf") and leaves:
            self.violations.append(f"{name} nested in {leaves}")
        self.taken.append((name, tuple(held)))
        held.append(name)

    def release(self, name: str) -> None:
        held = self.held()
        held.remove(name)

    def wrap(self, name, factory):
        rec = self

        @contextlib.contextmanager
        def cm(*a, **k):
            inner = factory(*a, **k)
            rec.acquire(name)
            try:
                with inner as v:
                    yield v
            finally:
                rec.release(name)
        return cm


def test_lock_acquisition_order_respects_the_global_rank(record_on, monkeypatch):
    import vigil_integration.live.credit_lease_broker as B
    import vigil_integration.live.credit_lease_pause as P
    import vigil_integration.live.seam_lock as SL
    from sigil import model_gateway as gw
    from sigil.ui import launch_gate as lg
    from sigil.ui.provision import build_provisioner
    rec = _LockRecorder()
    real_spine = lg.spine_lock

    class _Spine:
        def __init__(self, inner):
            self.inner = inner

        def __enter__(self):
            rec.acquire("spine")
            return self.inner.__enter__()

        def __exit__(self, *exc):
            try:
                return self.inner.__exit__(*exc)
            finally:
                rec.release("spine")

    monkeypatch.setattr(lg, "spine_lock", lambda path: _Spine(real_spine(path)))
    monkeypatch.setattr(ls, "settle_lock", rec.wrap("settle", ls.settle_lock))
    monkeypatch.setattr(LaunchGate, "_publish_lock", staticmethod(rec.wrap("publish", LaunchGate._publish_lock)))
    marker = rec.wrap("leaf:marker", B._marker_lock)
    monkeypatch.setattr(B, "_marker_lock", marker)
    monkeypatch.setattr(P, "_marker_lock", marker)
    real_locked = SL.locked_file
    monkeypatch.setattr(SL, "locked_file", lambda *a, **k: rec.wrap(
        "leaf:spool_sh" if k.get("shared") else "leaf:spool_ex", real_locked)(*a, **k))
    monkeypatch.setattr(gw.GrantMeter, "_locked", rec.wrap("leaf:meter", gw.GrantMeter._locked))

    s = _store()
    _seat(s, credits=10_000)
    flat = _reserve(s, units=30, publish=True)                       # a flat publish
    assert _settle(s, flat, 30)["ok"]
    build_provisioner(s).launch_cancel("u", ORG, _reserve(s, units=30)["lease"], now=NOW + 60)   # a cancel
    _metered(monkeypatch)
    m1 = _reserve(s, units=900, publish=True, hours=8)               # a metered publish
    _spend(m1)
    gov = _Gov(s, m1, now=NOW)
    gov.emit("completed")
    assert gov.watcher().drain()["settled"] == 1                     # a metered completion drain
    m2 = _reserve(s, units=900, publish=True, hours=8)
    assert LaunchGate(s).pause_launch(signed_lease=m2["lease"], expect_org_id=ORG)["ok"]
    rec.taken.clear()
    assert LaunchGate(s).resume_launch(signed_lease=m2["lease"], expect_org_id=ORG, now=NOW + 10)["ok"]
    assert "settle" not in [t[0] for t in rec.taken]                 # resume never takes the settle lock
    spool = _spool()
    restore = _kill(monkeypatch, WalletRegistry, "grant")
    with pytest.raises(SystemExit):
        _sweep(LaunchGate(s), spool, now=MLATE, ttl=86400)           # a sweep apply, interrupted
    restore()
    assert [x["status"] for x in _sweep(LaunchGate(s), spool, now=MLATE, ttl=86400)] == ["settle_completed"]
    assert rec.violations == [], rec.violations
    names = {t[0] for t in rec.taken}
    assert {"spine", "settle", "leaf:marker", "leaf:spool_sh"} <= names, names


def test_settle_pause_resume_sweep_and_drain_never_take_the_publish_lock(monkeypatch):
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    r2 = _reserve(s)

    def _no(*a, **k):
        raise AssertionError("only a metered publish takes the publish lock")

    monkeypatch.setattr(LaunchGate, "_publish_lock", staticmethod(_no))
    g = LaunchGate(s)
    assert g.pause_launch(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    assert g.resume_launch(signed_lease=r["lease"], expect_org_id=ORG, now=NOW + 10)["ok"]
    assert [x["status"] for x in _sweep(g, _spool())] == ["refunded"]
    assert _settle(s, r, 0)["action"] == "launch_already_settled"
    assert g.publish_lease(signed_lease=r2["lease"], expect_org_id=ORG)["ok"]    # a FLAT publish
    gov = _Gov(s, r2)
    gov.emit("completed")
    assert gov.watcher().drain()["settled"] == 1


def test_a_flat_publish_creates_nothing_under_the_meter_dir():
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    assert _settle(s, r, 30)["ok"]
    assert not config.MODEL_METER_DIR.exists()
