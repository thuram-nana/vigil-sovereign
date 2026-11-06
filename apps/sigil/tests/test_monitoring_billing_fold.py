"""AEGIS AE-5/AE-7 fold — billing standing bounds monitoring CONTINUOUSLY, and AEGIS billing never disturbs the
credit-plan subscription.

  1  a monitoring plan mints its OWN owner-signed line (governor.monitoring_subscription) — a credit plan and an
     AEGIS plan coexist and the credit refill is unaffected; the line crosses a hard prune (snapshot v7 + tripwire);
  2  every grant's not_after is clamped to the monitoring plan's period_end;
  3  cancel / past_due on the monitoring line cascades: every grant of the org is revoked + unpublished;
  4  a plan change retires block grants without respond and grants beyond the slot count (earliest kept), and a
     renewal re-mints surviving grants with the new window (owner key, republished);
  5  the sweep (reconcile_monitoring / `sigil monitoring-reconcile` / the drain watch loop) catches a lapse;
  6  with VIGIL_CUSTOMER_MONITORING_ENABLED off the AEGIS plans are not priced, listed or mintable;
  8  a slot is held only by an active_at grant (window + current matching ownership proof).
"""
from __future__ import annotations

import json
import os
import tempfile

import pytest

from test_provision_monitoring import _iso, _iss, _prov, _prove, _seat  # noqa: F401


def _msub(store, org, plan_id, *, ps=0.0, pe=1e12):
    from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
    return MonitoringSubscriptionRegistry(store).subscribe(org, plan_id, 0, period_start=ps, period_end=pe,
                                                           issued_at=float(next(_iss)))


def _rig(hosts=("a1.cm", "a2.cm", "a3.cm")):
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "alice", "org_admin")
    for h in hosts:
        _prove(s, "org_a", h)
    return p, s


def _reg(s):
    from sigil.governor.monitoring_authority import MonitoringAuthorityRegistry
    return MonitoringAuthorityRegistry(s, owner_key=None)


def _published(org, host):
    from sigil import config
    from sigil.governor.monitoring_authority import monitoring_filename
    return (config.monitoring_publish_dir() / monitoring_filename(org, host)).exists()


def _auth(p, host, *, mode="observe", now=None, **kw):
    t = float(next(_iss)) if now is None else now
    return p.monitor_authorize("alice", "org_a", host, mode=mode, now=t, **kw)


# --- 1: separate line ----------------------------------------------------------------------------------------
def _signer(s):
    from sigil.governor import catalog as cat
    from sigil.governor.billing import (EVENT_SUBSCRIPTION_ACTIVE, BillingSigner, Entitlement,
                                        MockBillingProvider)
    from sigil.governor.metering import PlanCreditLedger
    from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
    from sigil.governor.subscription import SubscriptionRegistry
    from sigil.governor.wallet import WalletRegistry
    subs, msubs = SubscriptionRegistry(s), MonitoringSubscriptionRegistry(s)
    plan = PlanCreditLedger(s)
    ents = {"price_pro": Entitlement(kind=EVENT_SUBSCRIPTION_ACTIVE, plan_id="pro", allotment=6000,
                                     period_s=1e6),
            "price_aegis": cat.entitlements()["vigil_aegis_respond_1h_monthly"]}
    mock = MockBillingProvider("sek")
    calls = []
    signer = BillingSigner(mock, wallet=WalletRegistry(s), subscriptions=subs, plan=plan, catalog=ents,
                           monitoring_subscriptions=msubs, on_monitoring_change=lambda o, t: calls.append((o, t)))
    return signer, mock, subs, msubs, plan, calls


def _event(mock, eid, kind, created, price):
    body = json.dumps({"event_id": eid, "kind": kind, "org_id": "org_a", "created": created,
                       "price_id": price}).encode()
    return body, mock.sign(body)


def test_credit_plan_and_aegis_plan_coexist_and_refill_is_unaffected():
    from sigil.governor.billing import EVENT_SUBSCRIPTION_ACTIVE, EVENT_SUBSCRIPTION_CANCELED
    p, s = _rig()
    signer, mock, subs, msubs, plan, calls = _signer(s)
    assert signer.ingest(*_event(mock, "e1", EVENT_SUBSCRIPTION_ACTIVE, 100.0, "price_pro"), now=100.0)
    before = plan.available("org_a", now=150.0)
    assert before == 6000
    assert signer.ingest(*_event(mock, "e2", EVENT_SUBSCRIPTION_ACTIVE, 200.0, "price_aegis"), now=200.0)
    assert subs.subscription("org_a").plan_id == "pro"                       # credit line untouched
    assert msubs.subscription("org_a").plan_id == "aegis_respond_1h"         # monitoring on its own line
    assert plan.available("org_a", now=250.0) == before                      # refill unaffected
    assert calls == [("org_a", 200.0)]                                        # provisioner hook fired
    # canceling the AEGIS plan must not cancel the credit plan (and vice versa)
    signer.ingest(*_event(mock, "e3", EVENT_SUBSCRIPTION_CANCELED, 300.0, "price_aegis"), now=300.0)
    assert subs.subscription("org_a").status == "active" and msubs.subscription("org_a").status == "canceled"


def test_monitoring_line_refuses_a_non_monitoring_plan():
    from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
    _p, s = _rig()
    with pytest.raises(ValueError):
        MonitoringSubscriptionRegistry(s).subscribe("org_a", "pro", 0, period_start=0.0, period_end=1.0,
                                                    issued_at=float(next(_iss)))


def _segmented(tmp_path):
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.spine.store import SpineStore
    ensure_owner_keypair()
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    _msub(s, "org_a", "aegis_observe_1h")                                    # seq 0
    for _ in range(4):
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})
    s.rotate()
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})
    s.rotate()
    return s


def test_monitoring_line_crosses_a_hard_prune_and_tripwire_detects_a_stranding_seed(tmp_path, monkeypatch):
    from sigil.spine import prune
    from sigil.spine.manifest import read_manifest
    from sigil.spine.snapshot import SnapshotState, build
    from sigil.governor.identity import owner_pubkey
    s = _segmented(tmp_path)
    archived = prune.check_prune_safe(s, 5)
    assert prune.stranded_active_monitoring_subscriptions(s, archived, 5) == []
    below = []
    for seg in archived:
        below.extend(prune.read_segment_records(s._layout.seg_path(seg)))
    seed = SnapshotState.model_validate(build(below, trusted_pubkey=owner_pubkey(), base_seq=5,
                                              snapshot_seq=-1).model_dump())
    assert seed.schema_version == 8
    assert dict(seed.monitoring_subscription_state)["org_a"] == "active"
    assert seed.subscription_state == []                                      # never folded into the credit line
    real_build = prune.build

    def stranding(records, **kw):
        sd = real_build(records, **kw)
        return sd.model_copy(update={"monitoring_subscription_state": [], "monitoring_subscription_issued": [],
                                     "monitoring_subscription_row": []})

    monkeypatch.setattr(prune, "build", stranding)
    below_segs = [g for g in read_manifest(s._layout).sealed_in_order() if g.last_seq is not None and g.last_seq < 5]
    assert prune.stranded_active_monitoring_subscriptions(s, below_segs, 5) == ["org_a"]
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "monitoring subscription" in str(e.value)


def test_monitoring_line_reads_from_the_snapshot_seed():
    from sigil.governor.identity import owner_pubkey
    from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
    from sigil.spine.snapshot import SnapshotState
    from sigil.spine.store import SpineStore
    seed = SnapshotState(trusted_pubkey=owner_pubkey(), base_seq=0,
                         monitoring_subscription_state=[["org_a", "active"]],
                         monitoring_subscription_issued=[["org_a", 5.0]],
                         monitoring_subscription_row=[["org_a", "aegis_observe_1h", 0.0, 1e12, 0]])
    s = SpineStore(os.path.join(tempfile.mkdtemp(), "spine.jsonl"))
    import sigil.governor.subscription as sub_mod
    orig = sub_mod.SnapshotState.load
    try:
        sub_mod.SnapshotState.load = staticmethod(lambda store: seed)
        r = MonitoringSubscriptionRegistry(s).subscription("org_a")
    finally:
        sub_mod.SnapshotState.load = orig
    assert r is not None and r.plan_id == "aegis_observe_1h" and r.status == "active"


# --- 2: clamp to period_end ------------------------------------------------------------------------------------
def test_grant_not_after_is_clamped_to_the_monitoring_period_end():
    p, s = _rig()
    _msub(s, "org_a", "aegis_observe_5h", pe=50_000.0)
    r = _auth(p, "a1.cm")
    assert r["not_after"] == 50_000.0
    assert _reg(s).grant_for("org_a", "a1.cm").not_after == 50_000.0
    assert r["authority"]["document"]["not_after"].startswith("1970-01-01T13:53:20")


# --- 3: down-path cascade --------------------------------------------------------------------------------------
@pytest.mark.parametrize("down", ["cancel", "past_due"])
def test_monitoring_cancel_or_past_due_retires_every_grant(down):
    from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
    p, s = _rig()
    _msub(s, "org_a", "aegis_respond_5h")
    _auth(p, "a1.cm")
    _auth(p, "a2.cm", mode="block")
    assert _published("org_a", "a1.cm") and _published("org_a", "a2.cm")
    r = MonitoringSubscriptionRegistry(s)
    if down == "cancel":
        r.cancel("org_a")
    else:
        r.mark_past_due("org_a", issued_at=1e15)
    assert _reg(s).grants("org_a") == []
    assert not _published("org_a", "a1.cm") and not _published("org_a", "a2.cm")


def test_stale_past_due_webhook_does_not_cascade():
    from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
    p, s = _rig()
    _msub(s, "org_a", "aegis_respond_5h")
    _auth(p, "a1.cm")
    MonitoringSubscriptionRegistry(s).mark_past_due("org_a", issued_at=1.0)   # older than the activation
    assert _reg(s).grant_for("org_a", "a1.cm") is not None and _published("org_a", "a1.cm")


def test_stale_replayed_monitoring_subscribe_does_not_trigger_enforcement():
    from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
    p, s = _rig()
    _msub(s, "org_a", "aegis_respond_5h")
    _auth(p, "a1.cm")
    # a stale (issued_at below the high-water) record for a far-future period is inert in the fold, so it must
    # not run enforcement "as of" its own period_start (where the honored plan has lapsed)
    MonitoringSubscriptionRegistry(s).subscribe("org_a", "aegis_observe_1h", 0, period_start=2e12, period_end=3e12,
                                                issued_at=1.0)
    assert _reg(s).grant_for("org_a", "a1.cm") is not None and _published("org_a", "a1.cm")


# --- 4: plan change ---------------------------------------------------------------------------------------------
def test_downgrade_to_observe_retires_block_grants():
    p, s = _rig()
    _msub(s, "org_a", "aegis_respond_5h")
    _auth(p, "a1.cm", mode="block")
    _auth(p, "a2.cm")
    t = float(next(_iss))
    _msub(s, "org_a", "aegis_observe_5h", ps=t, pe=1e12)
    assert [g.host for g in _reg(s).grants("org_a")] == ["a2.cm"]
    assert not _published("org_a", "a1.cm") and _published("org_a", "a2.cm")


def test_fewer_slots_retires_beyond_count_keeping_earliest_issued():
    p, s = _rig()
    _msub(s, "org_a", "aegis_respond_5h")
    _auth(p, "a3.cm")
    _auth(p, "a1.cm")
    _auth(p, "a2.cm")
    _msub(s, "org_a", "aegis_respond_1h", ps=float(next(_iss)), pe=1e12)
    assert [g.host for g in _reg(s).grants("org_a")] == ["a3.cm"]             # earliest-issued, not host order
    assert _published("org_a", "a3.cm") and not _published("org_a", "a1.cm") and not _published("org_a", "a2.cm")


def test_same_tier_renewal_remints_with_the_new_window_and_republishes():
    from sigil import config
    from sigil.governor.monitoring_authority import monitoring_filename
    from vigil_core.monitoring_authority import SignedMonitoringAuthority, verify_monitoring_authority
    from test_provision_monitoring import _owner_root
    p, s = _rig()
    p1 = float(next(_iss)) + 100.0
    _msub(s, "org_a", "aegis_observe_1h", pe=p1)
    _auth(p, "a1.cm")
    assert _reg(s).grant_for("org_a", "a1.cm").not_after == p1
    p2 = p1 + 10_000.0
    _msub(s, "org_a", "aegis_observe_1h", ps=p1, pe=p2)                       # renewal: next period
    assert _reg(s).active_at("org_a", "a1.cm", now=p1 + 5) is None            # old window ended
    r = p.monitor_plan_changed("org_a", now=p1 + 5)
    assert r["renewed"] == ["a1.cm"] and r["retired"] == []
    g = _reg(s).active_at("org_a", "a1.cm", now=p1 + 6)
    assert g is not None and g.not_after == p2 and g.mode == "observe"
    raw = (config.monitoring_publish_dir() / monitoring_filename("org_a", "a1.cm")).read_bytes()
    doc = SignedMonitoringAuthority.model_validate_json(raw)
    assert int(doc.document.not_after.timestamp()) == int(p2)
    assert verify_monitoring_authority(doc, _owner_root())[0] is True
    assert p.monitor_plan_changed("org_a", now=p1 + 7)["renewed"] == []      # current-period grant: no churn


# --- 5: sweep ---------------------------------------------------------------------------------------------------
def test_reconcile_sweep_retires_on_lapse_without_a_webhook():
    from sigil.governor.monitoring_subscription import reconcile_monitoring
    p, s = _rig()
    pe = float(next(_iss)) + 100.0
    _msub(s, "org_a", "aegis_observe_5h", pe=pe)
    _auth(p, "a1.cm")
    assert reconcile_monitoring(s, now=pe - 1) == []
    from sigil import config
    grace = float(config.MONITORING_RENEWAL_GRACE_SECONDS)
    assert reconcile_monitoring(s, now=pe + 1) == []                          # in renewal grace: kept (inert)
    assert reconcile_monitoring(s, now=pe + grace + 1) == [("org_a", "a1.cm")]
    assert _reg(s).grants("org_a") == [] and not _published("org_a", "a1.cm")


def _isolate_cli(monkeypatch, store):
    import sigil.spine.upgrade as _up
    from sigil import cli
    from sigil.spine.store import SpineStore
    fresh = SpineStore(os.path.join(tempfile.mkdtemp(), "spine.jsonl"))
    monkeypatch.setattr(_up, "SpineStore", lambda: fresh)
    monkeypatch.setattr(cli, "SpineStore", lambda: store)
    return cli


def test_cli_reconcile_verb_and_drain_watch_loop_sweep(monkeypatch, tmp_path, capsys):
    import time as _time
    p, s = _rig()
    pe = float(next(_iss)) + 1000.0                                           # long lapsed at wall-clock now
    _msub(s, "org_a", "aegis_observe_5h", pe=pe)
    _auth(p, "a1.cm")
    _auth(p, "a2.cm")
    cli = _isolate_cli(monkeypatch, s)
    monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED")
    with pytest.raises(SystemExit):
        cli.main(["monitoring-reconcile"])                                   # default-OFF
    assert len(_reg(s).grants("org_a")) == 2
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
    from sigil.governor.monitoring_authority import MonitoringAuthorityRegistry
    MonitoringAuthorityRegistry(s, owner_key=None).revoke("org_a", "a2.cm")  # (so the watch loop has one left)
    # the watch loop sweeps before draining
    monkeypatch.setattr(_time, "sleep", lambda _s: (_ for _ in ()).throw(KeyboardInterrupt()))
    cli.main(["monitoring-drain", "watch", "--spool", str(tmp_path / "sp"), "--secrets-dir", str(tmp_path)])
    assert _reg(s).grants("org_a") == [] and not _published("org_a", "a1.cm")
    assert "retired monitoring grant a1.cm" in capsys.readouterr().out
    cli.main(["monitoring-reconcile"])
    assert "0 grant(s) retired" in capsys.readouterr().out


# --- 6: flag off => byte-identical pre-AEGIS catalog ------------------------------------------------------------
def test_flag_off_hides_aegis_plans_from_catalog_and_signer(monkeypatch):
    from sigil.governor import catalog as cat
    on_plans, on_ents, on_amt = cat.plans(), cat.entitlements(), cat.expected_amounts()
    aegis = {e.price_id for e in cat._CATALOG if e.monitor_hosts}
    assert aegis and aegis <= set(on_ents)
    monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED")
    pre = [e for e in cat._CATALOG if not e.monitor_hosts]
    assert cat.plans() == [e.public() for e in pre]
    assert cat.entitlements() == {e.price_id: e.entitlement() for e in pre}
    assert cat.expected_amounts() == {e.price_id: (e.amount_minor, e.currency) for e in pre}
    assert not aegis & {x["price_id"] for x in cat.plans()} and not aegis & set(cat.entitlements())
    assert json.dumps(cat.plans()) == json.dumps([x for x in on_plans if x["price_id"] not in aegis])
    assert len(on_amt) == len(cat.expected_amounts()) + len(aegis)


# --- 8: slot predicate == active_at -----------------------------------------------------------------------------
def test_expired_grant_frees_its_slot():
    p, s = _rig()
    _msub(s, "org_a", "aegis_observe_1h")
    t = float(next(_iss))
    _auth(p, "a1.cm", now=t, window_s=5)
    _auth(p, "a2.cm", now=t + 50)                                             # a1 expired: slot is free


def test_ownership_lapsed_grant_frees_its_slot():
    from sigil.ui.provision import ProvisionDenied
    p, s = _rig()
    _msub(s, "org_a", "aegis_observe_1h")
    _auth(p, "a1.cm")
    with pytest.raises(ProvisionDenied):
        _auth(p, "a2.cm")                                                    # slot held
    _prove(s, "org_a", "a1.cm")                                              # proof REPLACED: grant inert
    assert _reg(s).grant_for("org_a", "a1.cm") is not None
    assert _reg(s).active_at("org_a", "a1.cm", now=float(next(_iss))) is None
    assert _auth(p, "a2.cm")["host"] == "a2.cm"



# --- fold 2 / A: down-event routing by the FULL catalog --------------------------------------------------------
def _real_signer(s):
    from sigil.governor import catalog as cat
    from sigil.governor.billing import BillingSigner, MockBillingProvider
    from sigil.governor.metering import PlanCreditLedger
    from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
    from sigil.governor.subscription import SubscriptionRegistry
    from sigil.governor.wallet import WalletRegistry
    subs, msubs = SubscriptionRegistry(s), MonitoringSubscriptionRegistry(s)
    mock = MockBillingProvider("sek")
    signer = BillingSigner(mock, wallet=WalletRegistry(s), subscriptions=subs, plan=PlanCreditLedger(s),
                           catalog=cat.entitlements(), expected=cat.expected_amounts(), monitoring_subscriptions=msubs)
    return signer, mock, subs, msubs


@pytest.mark.parametrize("flag", [True, False])
def test_aegis_cancel_routes_to_monitoring_only_whatever_the_flag(monkeypatch, flag):
    from sigil.governor.billing import EVENT_SUBSCRIPTION_ACTIVE, EVENT_SUBSCRIPTION_CANCELED
    p, s = _rig()
    _msub(s, "org_a", "aegis_observe_5h")
    _auth(p, "a1.cm")
    if not flag:
        monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED")
    signer, mock, subs, msubs = _real_signer(s)
    assert signer.ingest(*_event(mock, "c1", EVENT_SUBSCRIPTION_ACTIVE, 100.0, "vigil_pro_monthly"), now=100.0)
    signer.ingest(*_event(mock, "c2", EVENT_SUBSCRIPTION_CANCELED, 200.0, "vigil_aegis_observe_5h_monthly"),
                  now=200.0)
    assert subs.subscription("org_a").status == "active"                      # credit plan intact
    assert msubs.subscription("org_a").status == "canceled"                   # monitoring canceled
    assert _reg(s).grants("org_a") == []


@pytest.mark.parametrize("flag", [True, False])
def test_aegis_payment_failed_retires_grants_not_credit_plan(monkeypatch, flag):
    from sigil.governor.billing import EVENT_PAYMENT_FAILED, EVENT_SUBSCRIPTION_ACTIVE
    p, s = _rig()
    _msub(s, "org_a", "aegis_observe_5h")
    _auth(p, "a1.cm")
    if not flag:
        monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED")
    signer, mock, subs, msubs = _real_signer(s)
    assert signer.ingest(*_event(mock, "f1", EVENT_SUBSCRIPTION_ACTIVE, 100.0, "vigil_pro_monthly"), now=100.0)
    signer.ingest(*_event(mock, "f2", EVENT_PAYMENT_FAILED, 1e15, "vigil_aegis_observe_5h_monthly"), now=1e15)
    assert subs.subscription("org_a").status == "active"
    assert msubs.subscription("org_a").status == "past_due"
    assert _reg(s).grants("org_a") == [] and not _published("org_a", "a1.cm")


def test_unknown_price_down_event_keeps_pre_aegis_behaviour():
    from sigil.governor.billing import EVENT_SUBSCRIPTION_ACTIVE, EVENT_SUBSCRIPTION_CANCELED
    p, s = _rig()
    signer, mock, subs, msubs = _real_signer(s)
    assert signer.ingest(*_event(mock, "u1", EVENT_SUBSCRIPTION_ACTIVE, 100.0, "vigil_pro_monthly"), now=100.0)
    signer.ingest(*_event(mock, "u2", EVENT_SUBSCRIPTION_CANCELED, 200.0, "nope"), now=200.0)
    assert subs.subscription("org_a").status == "canceled"


# --- fold 2 / B: renewal grace ---------------------------------------------------------------------------------
def test_lapse_then_renewal_inside_grace_remints_and_republishes():
    from sigil import config
    from sigil.governor.monitoring_authority import monitoring_filename
    from sigil.governor.monitoring_subscription import reconcile_monitoring
    from vigil_core.monitoring_authority import SignedMonitoringAuthority
    p, s = _rig()
    p1 = float(next(_iss)) + 100.0
    _msub(s, "org_a", "aegis_observe_1h", pe=p1)
    _auth(p, "a1.cm")
    t = p1 + 3600.0                                                           # lapsed, inside grace
    assert reconcile_monitoring(s, now=t) == []
    # inert at the gateway during grace: the published artifact's window has ended
    assert _reg(s).active_at("org_a", "a1.cm", now=t) is None
    raw = (config.monitoring_publish_dir() / monitoring_filename("org_a", "a1.cm")).read_bytes()
    assert SignedMonitoringAuthority.model_validate_json(raw).document.not_after.timestamp() <= t
    p2 = t + 10_000.0
    _msub(s, "org_a", "aegis_observe_1h", ps=t, pe=p2)
    r = p.monitor_plan_changed("org_a", now=t + 1)
    assert r["renewed"] == ["a1.cm"]
    assert _reg(s).active_at("org_a", "a1.cm", now=t + 2).not_after == p2
    raw = (config.monitoring_publish_dir() / monitoring_filename("org_a", "a1.cm")).read_bytes()
    assert int(SignedMonitoringAuthority.model_validate_json(raw).document.not_after.timestamp()) == int(p2)


def test_lapse_past_grace_retires():
    from sigil import config
    from sigil.governor.monitoring_subscription import reconcile_monitoring
    p, s = _rig()
    p1 = float(next(_iss)) + 100.0
    _msub(s, "org_a", "aegis_observe_1h", pe=p1)
    _auth(p, "a1.cm")
    t = p1 + float(config.MONITORING_RENEWAL_GRACE_SECONDS) + 1
    assert reconcile_monitoring(s, now=t) == [("org_a", "a1.cm")]
    assert not _published("org_a", "a1.cm")
    _msub(s, "org_a", "aegis_observe_1h", ps=t, pe=t + 1e4)                   # late renewal: nothing to re-mint
    assert p.monitor_plan_changed("org_a", now=t + 1)["renewed"] == []
