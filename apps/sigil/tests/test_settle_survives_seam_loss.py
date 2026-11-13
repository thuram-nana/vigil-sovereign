"""E3b/E3c — launch settle is exactly-once per (slug, nonce), whatever happens to the seam directory.

The seam settlement marker (``<VIGIL_BASE_DIR>/credit-lease-settlements/``) lives in the cross-plane seam, which
is not on the spine and is not captured by the sovereign backup. It was the ONLY record that a COMPLETED run
(refund 0, so no refund grant) had been settled: lose it, or restore the seam out of step with the spine, and
``launch_cancel`` / ``ops-sweep reservations --apply`` fully refunded the charged run. The spine is now the
authority: a lease is settled when the spine carries owner-signed evidence of it (a ``governor.launch_settled``
decision record — written first by every settle while ``VIGIL_SETTLE_SPINE_RECORD`` is on — or a settle refund /
postpaid settle entry) or the marker says so; a later settle of a recorded decision finishes it at the RECORDED
consumption (crash recovery, never a second payment). The in-process halves of E3c live here too: the sweep
re-checks the completion spool inside the settle's critical section, a caller precondition that raises refuses,
the settle lock fails closed, and ``launch_cancel`` re-checks "started" inside the critical section.

Run: PYTHONPATH=apps/sigil:integration:packages/core/vigil_core python -m pytest \
     apps/sigil/tests/test_settle_survives_seam_loss.py
"""
from __future__ import annotations

import itertools
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from sigil import ops_sweeps
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.launch_settlement import (
    LAUNCH_SETTLED_SIGNAL, SettlementDecision, record_launch_settled, scan_settlement, settle_lock_path,
)
from sigil.governor.orgs import OrgRegistry
from sigil.governor.postpaid import POSTPAID_CREDIT_SIGNAL, PostpaidArrearsLedger, PostpaidRegistry
from sigil.governor.wallet import CREDIT_GRANT_SIGNAL, WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_core import generate_keypair
from vigil_integration.live.credit_lease_broker import (
    is_lease_settled, read_credit_lease, settlements_root,
)

_iss = itertools.count(1)
ORG, HOST, NOW = "org_a", "apme.cm", 2000.0
LATE = NOW + 3600.0 + 100.0                    # past a 1h lease's not_after + the sweep ttl (50)


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.delenv("VIGIL_SETTLE_SPINE_RECORD", raising=False)


@pytest.fixture
def record_on(monkeypatch):
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")


def _base() -> str:
    return os.environ["VIGIL_BASE_DIR"]


def _seat(store, *, credits=100, postpaid=None, plan=None):
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(ORG, ORG, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(ORG, "u", "operator", issued_at=float(next(_iss)))
    if credits:
        WalletRegistry(store).grant(ORG, credits, "trial", entry_id=f"trial:{ORG}", issued_at=float(next(_iss)))
    if plan is not None:
        from sigil.governor.metering import PlanCreditLedger, refill_active_subscription
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


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _avail(store):
    return WalletRegistry(store).available(ORG)


def _reserve(store, units=30, nonce=None, publish=False):
    g = LaunchGate(store)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=units, now=NOW, duration_hours=1, nonce=nonce)
    assert r["ok"], r
    if publish:
        assert g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    return r


def _signals(store, since=-1):
    return [(x.payload or {}).get("signal") for x in store.iter_records(since_seq=since)]


def _lose_seam():
    shutil.rmtree(_base())
    os.makedirs(_base())


def _settle(store, r, consumed, now=NOW + 60, **kw):
    return LaunchGate(store).settle_launch(signed_lease=r["lease"], consumed_units=consumed, now=now, **kw)


# ---- flag OFF: the spine records a settle writes are unchanged ---------------------------------------------------
def test_flag_off_a_settle_appends_exactly_the_records_it_always_did():
    s = _store()
    _seat(s)
    cancel, done = _reserve(s, nonce="n1"), _reserve(s, nonce="n2")
    tip = s.next_seq - 1
    assert _settle(s, cancel, 0)["refunded_wallet"] == 30
    assert _signals(s, tip) == [CREDIT_GRANT_SIGNAL]                 # a cancel: exactly its refund grant
    tip = s.next_seq - 1
    out = _settle(s, done, 30)                                       # (another lease's refund is not ITS evidence)
    assert out == {"ok": True, "action": "launch_settled", "org_id": ORG, "slug": done["slug"], "refunded": 0,
                   "refunded_plan": 0, "refunded_wallet": 0, "net_spend": 30}
    assert _signals(s, tip) == []                                    # a completed settle: nothing on the spine
    assert LAUNCH_SETTLED_SIGNAL not in _signals(s)
    marker = settlements_root(_base()) / f"{done['slug']}.json"
    ino = marker.stat().st_ino
    assert _settle(s, done, 0)["action"] == "launch_already_settled"
    assert marker.stat().st_ino == ino                               # an already-settled re-settle rewrites nothing


# ---- flag ON: every settle records its decision; a lost / stale seam cannot re-open the refund -----------------
def test_flag_on_a_completed_settle_records_one_owner_signed_decision(record_on):
    s = _store()
    _seat(s)
    r = _reserve(s)
    assert _settle(s, r, 30)["action"] == "launch_settled"
    assert _settle(s, r, 0)["action"] == "launch_already_settled"
    recs = [x for x in s.iter_records() if (x.payload or {}).get("signal") == LAUNCH_SETTLED_SIGNAL]
    assert len(recs) == 1 and recs[0].payload["consumed"] == 30 and recs[0].payload["nonce"] == r["nonce"]
    ev = scan_settlement(s, ensure_owner_keypair().public_key_b64, org_id=ORG, slug=r["slug"], nonce=r["nonce"])
    assert ev.record_seq == recs[0].seq and ev.consumed == 30


def test_flag_on_seam_lost_launch_cancel_does_not_refund_a_completed_run(record_on):
    from sigil.ui.provision import build_provisioner
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    assert _settle(s, r, 30)["refunded"] == 0 and _avail(s) == 70
    _lose_seam()
    out = build_provisioner(s).launch_cancel("u", ORG, r["lease"], now=NOW + 120)
    assert out["refunded"] == 0 and _avail(s) == 70                  # still charged: no free run
    assert is_lease_settled(_base(), r["slug"], r["nonce"])          # the seam revocation was re-asserted
    assert _signals(s).count(LAUNCH_SETTLED_SIGNAL) == 1             # and no second decision was recorded


def test_flag_on_stale_seam_restore_sweep_does_not_refund_a_completed_run(record_on):
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    snap = tempfile.mkdtemp()
    shutil.rmtree(snap)
    shutil.copytree(_base(), snap)                                   # backup taken while the run was in flight
    assert _settle(s, r, 30)["ok"]
    shutil.rmtree(_base())
    shutil.copytree(snap, _base())                                   # ...restored after the charge
    spool = tempfile.mkdtemp()
    (Path(spool) / "incoming").mkdir()
    out = ops_sweeps.sweep_abandoned_reservations(LaunchGate(s), now=LATE, ttl_s=50, apply=True,
                                                  completion_spool=spool)
    assert [i["status"] for i in out["items"]] == ["already_settled"] and _avail(s) == 70
    assert is_lease_settled(_base(), r["slug"], r["nonce"])          # marker re-asserted
    assert read_credit_lease(_base(), r["slug"]) is None             # the resurrected bundle is tombstoned again


# ---- flag-independent spine evidence: a settle that moved money is already on the spine ------------------------
def test_refunded_lease_resettled_after_seam_loss_reports_already_settled_and_writes_no_grant():
    s = _store()
    _seat(s)
    r = _reserve(s)
    assert _settle(s, r, 0)["refunded"] == 30 and _avail(s) == 100
    _lose_seam()
    tip = s.next_seq - 1
    again = _settle(s, r, 0, now=NOW + 120)
    assert again["action"] == "launch_already_settled" and again["refunded"] == 0, again
    assert _signals(s, tip) == [] and _avail(s) == 100               # no second (deduped) grant record


@pytest.mark.parametrize("flag", ["", "1"])
def test_postpaid_settle_after_seam_loss_does_not_reverse_a_consumed_draw(flag, monkeypatch):
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", flag)
    s = _store()
    _seat(s, credits=0, postpaid=(500, 30))
    r = _reserve(s, units=100, nonce="pp1")
    assert _settle(s, r, 100)["ok"] and PostpaidArrearsLedger(s).accrued(ORG) == 100
    _lose_seam()
    tip = s.next_seq - 1
    again = _settle(s, r, 0, now=NOW + 120)                          # a cancel after the marker was lost
    assert again["action"] == "launch_already_settled", again
    assert PostpaidArrearsLedger(s).accrued(ORG) == 100              # the consumed draw was NOT reversed
    assert POSTPAID_CREDIT_SIGNAL not in _signals(s, tip)            # and no second settle credit was written


def test_a_settled_lease_cannot_be_republished_after_the_seam_is_lost():
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    assert _settle(s, r, 0)["ok"]                                    # refund > 0: on the spine with the flag off
    _lose_seam()
    again = LaunchGate(s).publish_lease(signed_lease=r["lease"], expect_org_id=ORG)
    assert again["ok"] is False and "settled" in again["error"]
    assert read_credit_lease(_base(), r["slug"]) is None             # not resurrected as a runnable capability


def test_a_settlement_record_not_signed_by_the_owner_is_ignored(record_on):
    s = _store()
    _seat(s)
    r = _reserve(s)
    record_launch_settled(s, generate_keypair(), org_id=ORG, slug=r["slug"], nonce=r["nonce"],
                          decision=SettlementDecision.prepaid(30, 30, 0, 0, 0.0, "settle"), issued_at=NOW)
    st = _settle(s, r, 0)                                            # a legitimate pre-start cancel
    assert st["action"] == "launch_settled" and st["refunded"] == 30 and _avail(s) == 100


def test_the_spine_lookup_is_bound_to_org_slug_and_nonce():
    s = _store()
    kp = ensure_owner_keypair()
    five, zero = (SettlementDecision.prepaid(30, 5, 0, 25, 0.0, "settle"),
                  SettlementDecision.prepaid(30, 0, 0, 30, 0.0, "cancel"))
    record_launch_settled(s, kp, org_id="org_b", slug="cust_x", nonce="n1", decision=five, issued_at=NOW)
    seq = record_launch_settled(s, kp, org_id=ORG, slug="cust_x", nonce="n1", decision=five, issued_at=NOW)
    record_launch_settled(s, kp, org_id=ORG, slug="cust_x", nonce="n1", decision=zero, issued_at=NOW)
    pub = kp.public_key_b64
    ev = scan_settlement(s, pub, org_id=ORG, slug="cust_x", nonce="n1")
    assert (ev.record_seq, ev.consumed, ev.through) == (seq, 5, s.next_seq - 1)     # the FIRST decision wins
    assert not scan_settlement(s, pub, org_id=ORG, slug="cust_x", nonce="n2").settled
    assert not scan_settlement(s, pub, org_id=ORG, slug="cust_y", nonce="n1").settled


# ---- crash recovery: a recorded decision is finished by the next settle, at the RECORDED consumption -----------
def test_a_crash_before_the_postpaid_settle_credit_is_finished_exactly_once(record_on, monkeypatch):
    from sigil.governor import postpaid as pp
    s = _store()
    _seat(s, credits=0, postpaid=(500, 30))
    r = _reserve(s, units=100, nonce="pp2")
    real = pp.PostpaidArrearsLedger.settle
    monkeypatch.setattr(pp.PostpaidArrearsLedger, "settle",
                        lambda *a, **k: (_ for _ in ()).throw(SystemExit("killed before the settle credit")))
    with pytest.raises(SystemExit):
        _settle(s, r, 40)                                            # consumed 40 of 100
    monkeypatch.setattr(pp.PostpaidArrearsLedger, "settle", real)
    assert PostpaidArrearsLedger(s).accrued(ORG) == 100
    again = _settle(s, r, 0, now=NOW + 90)                           # a cancel: the RECORDED 40 decides
    assert again["action"] == "launch_already_settled" and again["refunded"] == 60, again
    assert PostpaidArrearsLedger(s).accrued(ORG) == 40
    tip = s.next_seq - 1
    assert _settle(s, r, 0, now=NOW + 99)["refunded"] == 0 and _signals(s, tip) == []


def test_a_crash_before_the_refund_grant_is_finished_exactly_once_by_a_retry(record_on, monkeypatch):
    from sigil.governor import wallet as wallet_mod
    from sigil.governor.cost_ledger import COST_SETTLE_SIGNAL
    monkeypatch.setenv("VIGIL_COST_LEDGER_WRITE", "1")                # the advisory cost settle is finished too
    s = _store()
    _seat(s)
    r = _reserve(s)
    real = wallet_mod.WalletRegistry.grant

    def _killed(self, *a, **k):
        raise SystemExit("process killed before the refund grant")

    monkeypatch.setattr(wallet_mod.WalletRegistry, "grant", _killed)
    with pytest.raises(SystemExit):
        _settle(s, r, 0)
    monkeypatch.setattr(wallet_mod.WalletRegistry, "grant", real)
    assert _avail(s) == 70 and is_lease_settled(_base(), r["slug"], r["nonce"])
    again = _settle(s, r, 30, now=NOW + 90)              # e.g. a late 'completed' — the RECORDED cancel decides
    assert again["action"] == "launch_already_settled" and again["refunded_wallet"] == 30, again
    assert _avail(s) == 100 and _signals(s).count(COST_SETTLE_SIGNAL) == 1
    tip = s.next_seq - 1
    assert _settle(s, r, 0, now=NOW + 99)["refunded"] == 0 and _signals(s, tip) == []   # never paid twice


def test_a_crash_before_the_plan_refund_is_finished_into_the_same_tranche(record_on, monkeypatch):
    from sigil.governor import metering
    s = _store()
    _seat(s, credits=20, plan=5)
    r = _reserve(s, units=10)                                        # plan 5 + wallet 5
    real = metering.PlanCreditLedger.grant

    def _killed(self, *a, **k):
        raise SystemExit("process killed before the plan refund")

    monkeypatch.setattr(metering.PlanCreditLedger, "grant", _killed)
    with pytest.raises(SystemExit):
        _settle(s, r, 0)
    monkeypatch.setattr(metering.PlanCreditLedger, "grant", real)
    again = _settle(s, r, 0, now=NOW + 90)
    assert (again["refunded_plan"], again["refunded_wallet"]) == (5, 5), again
    tip = s.next_seq - 1
    third = _settle(s, r, 0, now=NOW + 99)
    assert third["refunded"] == 0 and _signals(s, tip) == []
    assert metering.PlanCreditLedger(s).available(ORG, NOW) == 5 and _avail(s) == 20


def test_a_recorded_completion_is_never_turned_into_a_refund_by_a_later_cancel(record_on, monkeypatch):
    import vigil_integration.live.credit_lease_broker as clb
    s = _store()
    _seat(s)
    r = _reserve(s)
    real = clb.record_lease_settlement
    monkeypatch.setattr(clb, "record_lease_settlement", lambda *a, **k: (_ for _ in ()).throw(OSError("seam")))
    assert _settle(s, r, 30)["ok"] is False                          # decision recorded, seam write failed
    monkeypatch.setattr(clb, "record_lease_settlement", real)
    st = _settle(s, r, 0, now=NOW + 90)                              # the customer's cancel
    assert st["action"] == "launch_already_settled" and st["refunded"] == 0 and st["net_spend"] == 30, st
    assert _avail(s) == 70 and is_lease_settled(_base(), r["slug"], r["nonce"])


def test_a_seam_revocation_failure_with_the_flag_off_records_nothing_so_a_retry_settles(monkeypatch):
    import vigil_integration.live.credit_lease_broker as clb
    s = _store()
    _seat(s)
    r = _reserve(s)
    real = clb.record_lease_settlement
    monkeypatch.setattr(clb, "record_lease_settlement", lambda *a, **k: (_ for _ in ()).throw(OSError("seam")))
    tip = s.next_seq - 1
    assert _settle(s, r, 0)["ok"] is False and _avail(s) == 70 and _signals(s, tip) == []
    monkeypatch.setattr(clb, "record_lease_settlement", real)
    assert _settle(s, r, 0)["action"] == "launch_settled" and _avail(s) == 100


def test_the_settle_drain_redrive_finishes_a_settle_a_crash_interrupted(record_on, monkeypatch):
    """A failed run's settle dies after the decision + marker, before the refund: the drain's crash recovery
    (working/ is reclaimed) re-drives it — the published bundle is tombstoned only after the money moved."""
    from sigil.governor import wallet as wallet_mod
    from sigil.inbound.completion_spool import CompletionSpoolWatcher
    from sigil.ui.launch_governance import provision_launch_governance
    from vigil_core.delegation import DelegationCert
    from vigil_integration.jobs.completion_signal import emit_completion_signal
    from vigil_integration.live.governance_identity import (
        DEFAULT_GOVERNANCE_KEY_FILE, GOVERNANCE_KEY_ID, load_or_create_governance_keypair,
    )
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    deleg = DelegationCert.model_validate_json(Path(provision_launch_governance(
        slug=r["slug"], not_after=9_000_000_000, base_dir=_base())).read_text(encoding="utf-8"))
    gov = load_or_create_governance_keypair(path=os.path.join(_base(), DEFAULT_GOVERNANCE_KEY_FILE))
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="failed",
                           signers=[(GOVERNANCE_KEY_ID, gov.private_key_b64)], spool_dir=spool)

    def _watcher():
        return CompletionSpoolWatcher(s, spool_dir=spool, owner_pubkey=ensure_owner_keypair().public_key_b64,
                                      delegation=deleg, scope=r["slug"], base_dir=_base(), now_fn=lambda: NOW + 60)

    real = wallet_mod.WalletRegistry.grant
    monkeypatch.setattr(wallet_mod.WalletRegistry, "grant",
                        lambda *a, **k: (_ for _ in ()).throw(SystemExit("killed")))
    with pytest.raises(SystemExit):
        _watcher().drain()
    monkeypatch.setattr(wallet_mod.WalletRegistry, "grant", real)
    assert _avail(s) == 70
    assert _watcher().drain()["settled"] == 1 and _avail(s) == 100   # re-driven from working/, refunded once
    assert read_credit_lease(_base(), r["slug"]) is None


def test_a_competing_decision_landing_after_the_unlocked_scan_is_honoured(record_on, monkeypatch):
    """Another process records its decision between this settle's unlocked full scan and its lock (and dies
    before writing the marker): the re-scan inside the critical section must see it."""
    import sigil.governor.launch_settlement as ls
    s = _store()
    _seat(s)
    r = _reserve(s)
    real = ls.scan_settlement
    calls = {"n": 0}

    def _scan(*a, **k):
        ev = real(*a, **k)
        calls["n"] += 1
        if calls["n"] == 1:                                          # just after the unlocked scan
            real_kp = ensure_owner_keypair()
            ls.record_launch_settled(s, real_kp, org_id=ORG, slug=r["slug"], nonce=r["nonce"],
                                     decision=SettlementDecision.prepaid(30, 30, 0, 0, 0.0, "completion:completed"),
                                     issued_at=NOW)
        return ev

    monkeypatch.setattr(ls, "scan_settlement", _scan)
    st = _settle(s, r, 0)
    assert st["action"] == "launch_already_settled" and st["refunded"] == 0, st
    assert _avail(s) == 70 and _signals(s).count(LAUNCH_SETTLED_SIGNAL) == 1


# ---- E3c in-process: preconditions inside the critical section, fail-closed lock ----------------------------------
def test_the_sweep_rechecks_the_completion_spool_inside_the_settle(monkeypatch):
    """A completion landing AFTER the sweep's up-front spool snapshot but before it settles blocks the refund;
    the drain then charges the run."""
    from sigil.inbound.completion_spool import CompletionSpoolWatcher
    from sigil.ui.launch_governance import provision_launch_governance
    from vigil_core.delegation import DelegationCert
    from vigil_integration.jobs.completion_signal import emit_completion_signal
    from vigil_integration.live.governance_identity import (
        DEFAULT_GOVERNANCE_KEY_FILE, GOVERNANCE_KEY_ID, load_or_create_governance_keypair,
    )
    s = _store()
    _seat(s)
    r = _reserve(s, publish=True)
    deleg_path = provision_launch_governance(slug=r["slug"], not_after=9_000_000_000, base_dir=_base())
    gov = load_or_create_governance_keypair(path=os.path.join(_base(), DEFAULT_GOVERNANCE_KEY_FILE))
    spool = tempfile.mkdtemp()
    (Path(spool) / "incoming").mkdir()
    gate = LaunchGate(s)
    real = gate.settle_launch

    def _completion_lands_then_settle(**kw):
        emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="completed",
                               signers=[(GOVERNANCE_KEY_ID, gov.private_key_b64)], spool_dir=spool)
        return real(**kw)

    monkeypatch.setattr(gate, "settle_launch", _completion_lands_then_settle)
    out = ops_sweeps.sweep_abandoned_reservations(gate, now=LATE, ttl_s=50, apply=True, completion_spool=spool)
    assert [i["status"] for i in out["items"]] == ["completion_pending"] and _avail(s) == 70
    assert not is_lease_settled(_base(), r["slug"], r["nonce"])      # nothing was written
    deleg = DelegationCert.model_validate_json(Path(deleg_path).read_text(encoding="utf-8"))
    drained = CompletionSpoolWatcher(s, spool_dir=spool, owner_pubkey=ensure_owner_keypair().public_key_b64,
                                     delegation=deleg, scope=r["slug"], base_dir=_base(),
                                     now_fn=lambda: LATE).drain()
    assert drained["settled"] == 1 and _avail(s) == 70               # charged by the drain, never refunded


def test_a_precondition_that_cannot_answer_refuses_the_settle():
    s = _store()
    _seat(s)
    r = _reserve(s)
    tip = s.next_seq - 1

    def _boom():
        raise OSError("spool unreadable")

    st = _settle(s, r, 0, refuse_if=_boom)
    assert st["ok"] is False and st["refused"].startswith("precondition check failed"), st
    assert _avail(s) == 70 and _signals(s, tip) == [] and not is_lease_settled(_base(), r["slug"], r["nonce"])


def test_a_settle_lock_that_cannot_be_taken_fails_closed():
    s = _store()
    _seat(s)
    r = _reserve(s)
    settle_lock_path(s).mkdir()                                      # the lockfile path is unusable
    st = _settle(s, r, 0)
    assert st["ok"] is False and "settle lock" in st["error"], st
    assert _avail(s) == 70 and not is_lease_settled(_base(), r["slug"], r["nonce"])


def test_a_marker_lock_that_cannot_be_taken_fails_closed():
    s = _store()
    _seat(s)
    r = _reserve(s)
    root = settlements_root(_base())
    root.mkdir(parents=True)
    (root / f"{r['slug']}.json.lock").mkdir()                        # the marker's lockfile path is unusable
    st = _settle(s, r, 0)
    assert st["ok"] is False and "fail-closed" in st["error"] and _avail(s) == 70, st


def test_launch_cancel_rechecks_started_inside_the_settle(monkeypatch):
    """A launch_start landing between launch_cancel's up-front "started?" check and its settle: the re-check
    inside the settle's critical section refuses the full refund of a now-started launch."""
    from sigil.ui import launch_gate as lg
    from sigil.ui.provision import ProvisionDenied, build_provisioner
    s = _store()
    _seat(s)
    r = _reserve(s)
    real = lg.LaunchGate.settle_launch

    def _start_lands_then_settle(self, **kw):
        assert LaunchGate(s).publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
        return real(self, **kw)

    monkeypatch.setattr(lg.LaunchGate, "settle_launch", _start_lands_then_settle)
    with pytest.raises(ProvisionDenied, match="has been started and must settle"):
        build_provisioner(s).launch_cancel("u", ORG, r["lease"], now=NOW + 60)
    assert _avail(s) == 70 and read_credit_lease(_base(), r["slug"]) is not None
    assert not is_lease_settled(_base(), r["slug"], r["nonce"])
