"""E7 — one outstanding launch per (org, host), and the release of a reservation a later launch superseded.

Every launch of one (org, host) shares one slug, and the seam holds ONE lease per slug, so a launch whose lease a
later launch of the same target replaced is no longer on the seam: its job is refused at the arm (its nonce is not
the one on the seam) and its completion is quarantined by the settle-drain (nonce mismatch).

* With ``VIGIL_ONE_LAUNCH_PER_HOST`` on, ``reserve_launch`` / ``launch_start`` refuse the second launch while the
  first is outstanding (decided under the cross-process settle lock — the multi-process half lives in
  ``test_one_launch_cross_process.py``); with it off, both behave exactly as before.
* ``ops-sweep reservations`` also reads the RESERVATIONS from the spine and reports — with ``--apply`` releases,
  through the same exactly-once settle — one a later launch superseded on the seam, once its grace is over, and
  never one whose run may charge or whose settlement evidence is contradictory.

Run: PYTHONPATH=apps/sigil:integration:packages/core/vigil_core python -m pytest \
     apps/sigil/tests/test_one_launch_per_host.py
"""
from __future__ import annotations

import argparse
import itertools
import json
import os
import tempfile
from pathlib import Path

import pytest

from sigil import ops_sweeps
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.launch_reservations import scan_reservations
from sigil.governor.launch_settlement import scan_settlement
from sigil.governor.orgs import OrgRegistry
from sigil.governor.postpaid import PostpaidArrearsLedger, PostpaidRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import _MAX_LEASE_HOURS, LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_core import AuthorizerKey, TrustRoot, generate_keypair, sign_credit_launch_lease
from vigil_integration.live.credit_lease_broker import (
    is_lease_settled, read_credit_lease, settlement_path, write_credit_lease,
)

_iss = itertools.count(1)
ORG, HOST, NOW = "org_a", "apme.cm", 2000.0
TTL = 50.0
EDGE = NOW + _MAX_LEASE_HOURS * 3600.0 + TTL           # the longest lease window + the sweep grace, from the reserve
LATE = EDGE + 1.0
BUSY = "finish or cancel the launch already in progress"


@pytest.fixture(autouse=True, params=["", "1"], ids=["record_off", "record_on"])
def _iso(monkeypatch, request):
    """Every test runs with the settle record (``VIGIL_SETTLE_SPINE_RECORD``) off and on, whatever the caller's env."""
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.delenv("VIGIL_ONE_LAUNCH_PER_HOST", raising=False)
    monkeypatch.delenv("VIGIL_SETTLE_SPINE_RECORD", raising=False)
    if request.param:
        monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", request.param)


@pytest.fixture
def one_on(monkeypatch):
    monkeypatch.setenv("VIGIL_ONE_LAUNCH_PER_HOST", "1")


def _base() -> str:
    return os.environ["VIGIL_BASE_DIR"]


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _seat(store, *, credits=100, hosts=(HOST,), org=ORG, postpaid=None, plan=None):
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(org, org, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(org, "u", "operator", issued_at=float(next(_iss)))
    if credits:
        WalletRegistry(store).grant(org, credits, "trial", entry_id=f"trial:{org}", issued_at=float(next(_iss)))
    if plan is not None:
        from sigil.governor.metering import PlanCreditLedger, refill_active_subscription
        from sigil.governor.subscription import SubscriptionRegistry
        subs = SubscriptionRegistry(store)
        subs.subscribe(org, "pro", plan, period_start=0.0, period_end=1e12, issued_at=float(next(_iss)))
        refill_active_subscription(subs, PlanCreditLedger(store), org, issued_at=float(next(_iss)))
    if postpaid is not None:
        PostpaidRegistry(store).set_account(org, postpaid[0], postpaid[1], issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    for h in hosts:
        ch = reg.issue_challenge(org, h, issued_at=float(next(_iss)))
        reg.verify_and_record(org, h, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
        assert add_customer_target(h, org_id=org, store=store, now=NOW)["ok"]


def _try_reserve(store, *, units=30, now=NOW, host=HOST, org=ORG, nonce=None):
    return LaunchGate(store).reserve_launch(requester="u", org_id=org, host=host, units=units, now=now,
                                            duration_hours=1, nonce=nonce)


def _reserve(store, *, publish=False, **kw):
    r = _try_reserve(store, **kw)
    assert r["ok"], r
    if publish:
        assert _publish(store, r)["ok"]
    return r


def _reauthorize(store, now):
    """Renew the owner-signed engagement authority (it has its own window) so a reserve at ``now`` is admitted."""
    assert add_customer_target(HOST, org_id=ORG, store=store, now=now)["ok"]


def _publish(store, r):
    return LaunchGate(store).publish_lease(signed_lease=r["lease"], expect_org_id=r["org_id"])


def _avail(store, org=ORG):
    return WalletRegistry(store).available(org)


def _seam_nonce(slug):
    b = read_credit_lease(_base(), slug)
    return None if b is None else b.signed_lease.document.nonce


def _superseded(store, units=30):
    """main's E7 state (flag OFF): A reserved + started, then B reserved + started over it."""
    a = _reserve(store, units=units, publish=True)
    b = _reserve(store, units=units, publish=True)
    assert _seam_nonce(a["slug"]) == b["nonce"] and not is_lease_settled(_base(), a["slug"], a["nonce"])
    return a, b


def _spool(*claims):
    """A completion spool with the drain's subdirs; ``claims`` = (subdir, slug, nonce, outcome) envelopes."""
    d = Path(tempfile.mkdtemp())
    for sub in ("incoming", "working", "processed", "rejected"):
        (d / sub).mkdir()
    for i, (sub, slug, nonce, outcome) in enumerate(claims):
        doc = {"engagement_slug": slug, "nonce": nonce, "outcome": outcome}
        (d / sub / f"c{i}.json").write_text(json.dumps({"document": doc}), encoding="utf-8")
    return str(d)


def _sweep(store, *, now=LATE, apply=False, spool=None):
    return ops_sweeps.sweep_superseded_reservations(LaunchGate(store), now=now, ttl_s=TTL, apply=apply,
                                                    completion_spool=spool if spool is not None else _spool())


def _statuses(out):
    return [(i["nonce"], i["status"]) for i in out["items"]]


# ---- flag OFF: byte-identical ------------------------------------------------------------------------------------
def test_flag_off_a_second_launch_reserves_and_starts_exactly_as_before():
    s = _store()
    _seat(s)
    a = _reserve(s, publish=True)
    tip = s.next_seq - 1
    b = _reserve(s, publish=True)                     # the second launch of the same (org, host): allowed, as on main
    assert _seam_nonce(a["slug"]) == b["nonce"] and _avail(s) == 40
    sigs = [(x.payload or {}).get("signal") for x in s.iter_records(since_seq=tip)]
    assert sigs == ["governor.credit_debit"]          # the reserve wrote its debit and nothing else


# ---- flag ON: the reserve refusal ------------------------------------------------------------------------------
def test_a_second_reserve_is_refused_while_the_first_is_started_and_unsettled(one_on):
    from sigil.ui.provision import ProvisionDenied, build_provisioner
    s = _store()
    _seat(s)
    p = build_provisioner(s)
    a = p.launch_reserve("u", ORG, HOST, now=NOW)
    p.launch_start("u", ORG, a["lease"], now=NOW)
    tip, before = s.next_seq, _avail(s)
    with pytest.raises(ProvisionDenied, match=BUSY):
        p.launch_reserve("u", ORG, HOST, now=NOW + 5)
    assert _avail(s) == before                        # nothing debited
    assert not [x for x in s.iter_records(since_seq=tip - 1)
                if (x.payload or {}).get("signal") == "governor.credit_debit"]
    assert _seam_nonce(a["slug"]) == a["nonce"]       # the first launch's lease is untouched


def test_a_second_reserve_is_refused_while_the_first_is_reserved_but_not_started(one_on):
    s = _store()
    _seat(s)
    _reserve(s)
    r = _try_reserve(s, now=NOW + 5)
    assert not r["ok"] and BUSY in r["error"] and "reserving a new one" in r["error"] and _avail(s) == 70


def test_another_host_or_another_org_is_not_blocked(one_on):
    s = _store()
    _seat(s, hosts=(HOST, "b.apme.cm"))
    _seat(s, org="org_b")
    _reserve(s, publish=True)
    assert _try_reserve(s, host="b.apme.cm")["ok"]
    assert _try_reserve(s, org="org_b")["ok"]


def test_a_completed_first_launch_frees_the_target(one_on):
    s = _store()
    _seat(s)
    a = _reserve(s, publish=True)
    assert LaunchGate(s).settle_launch(signed_lease=a["lease"], consumed_units=30, now=NOW + 60)["refunded"] == 0
    recorded = bool(os.environ.get("VIGIL_SETTLE_SPINE_RECORD"))
    assert scan_settlement(s, ensure_owner_keypair().public_key_b64, org_id=ORG, slug=a["slug"],
                           nonce=a["nonce"]).settled is recorded  # record off: only the seam marker records it
    assert _try_reserve(s, now=NOW + 120)["ok"]


def test_a_refund_on_the_spine_frees_the_target_even_with_the_marker_lost(one_on):
    s = _store()
    _seat(s)
    a = _reserve(s)
    assert LaunchGate(s).settle_launch(signed_lease=a["lease"], consumed_units=0, now=NOW + 60)["refunded"] == 30
    settlement_path(_base(), a["slug"]).unlink()      # the seam marker is gone; the spine refund grant is not
    assert _try_reserve(s, now=NOW + 120)["ok"]


def test_an_old_reservation_that_is_not_on_the_seam_does_not_block(one_on):
    s = _store()
    _seat(s)
    _reserve(s)                                       # reserved at NOW, never started (its lease is long expired)
    edge = NOW + _MAX_LEASE_HOURS * 3600.0
    _reauthorize(s, edge - 1)
    r = _try_reserve(s, now=edge - 1)
    assert not r["ok"] and BUSY in r["error"]         # inside the longest possible window: still outstanding
    assert _try_reserve(s, now=edge)["ok"]


def test_a_started_lease_blocks_even_after_its_window(one_on):
    s = _store()
    _seat(s)
    _reserve(s, publish=True)                         # on the seam: it may still be running past not_after
    _reauthorize(s, NOW + _MAX_LEASE_HOURS * 3600.0 + 1)
    r = _try_reserve(s, now=NOW + _MAX_LEASE_HOURS * 3600.0 + 1)
    assert not r["ok"] and BUSY in r["error"]


def test_a_lease_on_the_seam_that_does_not_verify_does_not_block(one_on):
    s = _store()
    _seat(s)
    a = _reserve(s)
    LaunchGate(s).settle_launch(signed_lease=a["lease"], consumed_units=0, now=NOW + 1)
    from vigil_core import CreditLaunchLease
    foreign = generate_keypair()
    doc = CreditLaunchLease.model_validate({**a["lease"]["document"], "nonce": "foreign1"})
    signed = sign_credit_launch_lease(doc, {"owner": foreign.private_key_b64})
    write_credit_lease(_base(), a["slug"], signed, TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=foreign.public_key_b64)]))
    assert _try_reserve(s, now=NOW + 5)["ok"]         # it can never arm, so it is no launch in progress


def test_reserve_fails_closed_when_the_check_cannot_run(one_on, monkeypatch):
    import sigil.governor.launch_reservations as lr
    s = _store()
    _seat(s)

    def _boom(*a, **k):
        raise OSError("spine unreadable")

    monkeypatch.setattr(lr, "scan_reservations", _boom)
    r = _try_reserve(s)
    assert not r["ok"] and "fail-closed" in r["error"] and _avail(s) == 100


# ---- flag ON: the start refusal ---------------------------------------------------------------------------------
def test_start_never_replaces_another_launchs_unsettled_lease(monkeypatch):
    from sigil.ui.provision import ProvisionDenied, build_provisioner
    s = _store()
    _seat(s)
    a, b = _reserve(s, publish=True), _reserve(s)     # pre-existing state (flag was off): two reservations
    monkeypatch.setenv("VIGIL_ONE_LAUNCH_PER_HOST", "1")
    with pytest.raises(ProvisionDenied, match=BUSY):
        build_provisioner(s).launch_start("u", ORG, b["lease"], now=NOW + 5)
    assert _seam_nonce(a["slug"]) == a["nonce"]       # A's job keeps its lease
    assert _publish(s, a)["ok"]                       # re-publishing the SAME lease is not "another launch"
    LaunchGate(s).settle_launch(signed_lease=a["lease"], consumed_units=30, now=NOW + 60)
    assert _publish(s, b)["ok"] and _seam_nonce(a["slug"]) == b["nonce"]   # A settled: B may start now


# ---- the reservation index agrees with the settle claim it builds on -----------------------------------------
def test_scan_reservations_agrees_with_scan_settlement(monkeypatch):
    s = _store()
    _seat(s, credits=500)
    pub = ensure_owner_keypair().public_key_b64
    g = LaunchGate(s)
    leases = [_reserve(s) for _ in range(4)]
    g.settle_launch(signed_lease=leases[0]["lease"], consumed_units=0, now=NOW + 1)     # full refund
    g.settle_launch(signed_lease=leases[1]["lease"], consumed_units=10, now=NOW + 1)    # partial refund
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")
    g.settle_launch(signed_lease=leases[2]["lease"], consumed_units=30, now=NOW + 1)    # completed + decision record
    ix = scan_reservations(s, pub)
    for r in leases:
        key = (ORG, r["slug"], r["nonce"])
        assert ix.reservations[key].reserved == 30 and ix.reservations[key].issued_at == NOW
        assert (key in ix.settled) is scan_settlement(s, pub, org_id=ORG, slug=r["slug"], nonce=r["nonce"]).settled
    assert [(ORG, r["slug"], r["nonce"]) in ix.settled for r in leases] == [True, True, True, False]
    assert scan_reservations(s, None).reservations == {}          # no owner key: nothing is trusted


# ---- the superseded-reservation sweep: the real superseded state, end to end ---------------------------------
def test_sweep_releases_a_superseded_reservation_exactly_once_after_its_completion_was_quarantined():
    from sigil.inbound.completion_spool import CompletionSpoolWatcher
    from sigil.ui.launch_governance import provision_launch_governance
    from vigil_core.delegation import DelegationCert
    from vigil_integration.jobs.completion_signal import emit_completion_signal
    from vigil_integration.live.governance_identity import (
        DEFAULT_GOVERNANCE_KEY_FILE, GOVERNANCE_KEY_ID, load_or_create_governance_keypair,
    )
    s = _store()
    owner = ensure_owner_keypair()
    _seat(s)
    a, b = _superseded(s)
    assert _avail(s) == 40
    # A's job is refused at the arm (its nonce is not on the seam) and its terminal attempt emits a FAILED
    # completion, which the real settle-drain quarantines: nothing settles A.
    deleg = DelegationCert.model_validate_json(Path(provision_launch_governance(
        slug=a["slug"], not_after=int(LATE) + 10**6, base_dir=_base())).read_text(encoding="utf-8"))
    kp = load_or_create_governance_keypair(path=os.path.join(_base(), DEFAULT_GOVERNANCE_KEY_FILE))
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=a["slug"], nonce=a["nonce"], outcome="failed",
                           signers=[(GOVERNANCE_KEY_ID, kp.private_key_b64)], spool_dir=spool)
    out = CompletionSpoolWatcher(s, spool_dir=spool, owner_pubkey=owner.public_key_b64, delegation=deleg,
                                 scope=a["slug"], base_dir=_base(), now_fn=lambda: NOW + 10).drain()
    assert out["rejected"] == 1 and _avail(s) == 40
    # the seam-lease sweep cannot see A at all
    assert [i["nonce"] for i in ops_sweeps.sweep_abandoned_reservations(
        LaunchGate(s), now=LATE, ttl_s=TTL, completion_spool=spool)["items"]] == [b["nonce"]]
    dry = _sweep(s, spool=spool)
    assert dry == {"applied": False, "items": [{"slug": a["slug"], "org_id": ORG, "nonce": a["nonce"],
                                                 "units_reserved": 30, "reserved_at": NOW,
                                                 "status": "superseded"}]}
    assert _avail(s) == 40                            # a dry run moves nothing
    done = _sweep(s, apply=True, spool=spool)
    assert _statuses(done) == [(a["nonce"], "released")] and done["items"][0]["refunded"] == 30
    assert _avail(s) == 70 and is_lease_settled(_base(), a["slug"], a["nonce"])
    assert _seam_nonce(a["slug"]) == b["nonce"]       # B's lease is untouched
    assert _sweep(s, apply=True, spool=spool)["items"] == []          # a re-run finds it settled
    # every other settle path now finds A settled: nothing more moves
    later = LaunchGate(s).settle_launch(signed_lease=a["lease"], consumed_units=0, now=LATE)
    assert later["action"] == "launch_already_settled" and later["refunded"] == 0 and _avail(s) == 70


def test_a_customer_cancel_first_makes_the_release_a_no_op():
    s = _store()
    _seat(s)
    a, _b = _superseded(s)
    assert LaunchGate(s).settle_launch(signed_lease=a["lease"], consumed_units=0, now=NOW + 60)["refunded"] == 30
    assert _sweep(s, apply=True)["items"] == [] and _avail(s) == 70
    r = LaunchGate(s).release_superseded_reservation(org_id=ORG, slug=a["slug"], nonce=a["nonce"], now=LATE,
                                                     grace_s=TTL)
    assert r["action"] == "launch_already_settled" and r["refunded"] == 0 and _avail(s) == 70


@pytest.mark.parametrize("sub", ["incoming", "working", "processed", "rejected"])
def test_a_charging_completion_anywhere_in_the_spool_blocks_the_release(sub):
    s = _store()
    _seat(s)
    a, _b = _superseded(s)
    spool = _spool((sub, a["slug"], a["nonce"], "completed"), ("rejected", a["slug"], a["nonce"], "failed"))
    assert _statuses(_sweep(s, apply=True, spool=spool)) == [(a["nonce"], "completion_pending")]
    assert _avail(s) == 40 and not is_lease_settled(_base(), a["slug"], a["nonce"])


def test_a_refund_outcome_does_not_block_and_an_unreadable_spool_does():
    s = _store()
    _seat(s)
    a, _b = _superseded(s)
    ok = _spool(("rejected", a["slug"], a["nonce"], "canceled"))
    assert _statuses(_sweep(s, spool=ok)) == [(a["nonce"], "superseded")]
    bad = _spool()
    (Path(bad) / "incoming" / "torn.json").write_text("{", encoding="utf-8")
    assert _statuses(_sweep(s, apply=True, spool=bad)) == [(a["nonce"], "completion_unknown")]
    assert _statuses(_sweep(s, apply=True, spool=tempfile.mkdtemp())) == [(a["nonce"], "completion_unknown")]
    assert _avail(s) == 40


def test_a_completion_landing_after_the_scan_is_rechecked_inside_the_settle(monkeypatch):
    s = _store()
    _seat(s)
    a, _b = _superseded(s)
    spool = _spool()
    real = ops_sweeps._release_block

    def _late(sp, pair):                              # the completion lands between the sweep's read and the settle
        (Path(sp) / "incoming" / "late.json").write_text(json.dumps({"document": {
            "engagement_slug": pair[0], "nonce": pair[1], "outcome": "completed"}}), encoding="utf-8")
        return real(sp, pair)

    monkeypatch.setattr(ops_sweeps, "_release_block", _late)
    assert _statuses(_sweep(s, apply=True, spool=spool)) == [(a["nonce"], "completion_pending")]
    assert _avail(s) == 40


def test_the_newest_reservation_of_a_target_is_not_superseded():
    s = _store()
    _seat(s)
    _reserve(s)                                       # reserved, never started, long expired — but the newest
    assert _sweep(s, apply=True)["items"] == [] and _avail(s) == 70


def test_a_superseded_reservation_inside_its_grace_is_left_alone():
    s = _store()
    _seat(s)
    a, _b = _superseded(s)
    assert _sweep(s, now=EDGE - 1, apply=True)["items"] == [] and _avail(s) == 40
    assert _statuses(_sweep(s, now=EDGE)) == [(a["nonce"], "superseded")]


def test_a_started_lease_belongs_to_the_abandoned_sweep():
    s = _store()
    _seat(s)
    a = _reserve(s, publish=True)
    _reserve(s)                                       # a later reservation, never started: A is still on the seam
    assert _sweep(s, apply=True)["items"] == [] and _avail(s) == 40
    assert _seam_nonce(a["slug"]) == a["nonce"]


def test_a_drained_settle_on_the_spine_is_never_released_even_with_the_marker_lost():
    s = _store()
    _seat(s)
    a, _b = _superseded(s)
    s.append(kind="assessment_outcome", source="sigil", actor="settle-drain",   # what the drain projects
             payload={"engagement_slug": a["slug"], "org_id": ORG, "outcome": "completed", "nonce": a["nonce"],
                      "ts": NOW + 30})
    assert _statuses(_sweep(s, apply=True)) == [(a["nonce"], "outcome_recorded")] and _avail(s) == 40


def test_a_lost_settlement_marker_blocks_every_release_of_the_target():
    s = _store()
    _seat(s)
    c = _reserve(s)
    assert LaunchGate(s).settle_launch(signed_lease=c["lease"], consumed_units=0, now=NOW + 1)["refunded"] == 30
    a, _b = _superseded(s)
    settlement_path(_base(), a["slug"]).unlink()      # the marker (spine shows C settled; the seam no longer does)
    assert _statuses(_sweep(s, apply=True)) == [(a["nonce"], "seam_inconsistent")] and _avail(s) == 40


def test_a_superseded_postpaid_reservation_reverses_its_draw():
    s = _store()
    _seat(s, credits=0, postpaid=(500, 30))
    a, _b = _superseded(s)
    arr = PostpaidArrearsLedger(s)
    assert arr.accrued(ORG) == 60
    assert _statuses(_sweep(s, apply=True)) == [(a["nonce"], "released")]
    assert arr.accrued(ORG) == 30 and arr.in_flight_reserved(ORG) == 30


def test_a_superseded_reservation_returns_plan_credits_to_their_tranche():
    from sigil.governor.metering import PlanCreditLedger
    s = _store()
    _seat(s, credits=100, plan=20)
    a, _b = _superseded(s)                            # A drew 20 plan + 10 wallet; B drew 30 wallet
    plan = PlanCreditLedger(s)
    assert plan.available(ORG, NOW) == 0 and _avail(s) == 60
    out = _sweep(s, apply=True)
    assert _statuses(out) == [(a["nonce"], "released")] and out["items"][0]["refunded"] == 30
    assert plan.available(ORG, NOW) == 20 and _avail(s) == 70     # each bucket gets back exactly what it gave


# ---- release_superseded_reservation re-decides inside the settle critical section -----------------------------
def _release(s, a, *, now=LATE, **kw):
    return LaunchGate(s).release_superseded_reservation(org_id=ORG, slug=a["slug"], nonce=a["nonce"], now=now,
                                                        grace_s=TTL, **kw)


def test_release_refuses_a_reservation_that_is_not_superseded():
    s = _store()
    _seat(s)
    a = _reserve(s)
    r = _release(s, a)
    assert r["refused"] == "not_superseded" and _avail(s) == 70
    assert not is_lease_settled(_base(), a["slug"], a["nonce"])


def test_release_refuses_a_lease_started_meanwhile():
    s = _store()
    _seat(s)
    a = _reserve(s)
    _reserve(s)
    assert _publish(s, a)["ok"]                       # started after the sweep looked
    assert _release(s, a)["refused"] == "started" and _avail(s) == 40


def test_release_refuses_inside_the_grace():
    s = _store()
    _seat(s)
    a, _b = _superseded(s)
    assert _release(s, a, now=EDGE - 1)["refused"] == "in_grace" and _avail(s) == 40


def test_release_runs_the_callers_precondition_inside_the_settle():
    s = _store()
    _seat(s)
    a, _b = _superseded(s)
    assert _release(s, a, refuse_if=lambda: "completion_pending")["refused"] == "completion_pending"
    assert _avail(s) == 40 and not is_lease_settled(_base(), a["slug"], a["nonce"])


def test_release_needs_a_consistent_owner_signed_reservation():
    from sigil.governor.wallet import WalletRegistry as W
    s = _store()
    _seat(s, credits=100, postpaid=(500, 30))
    a, _b = _superseded(s)                            # postpaid draws
    r = LaunchGate(s).release_superseded_reservation(org_id=ORG, slug=a["slug"], nonce="nope", now=LATE)
    assert not r["ok"] and "no owner-signed reservation" in r["error"]
    W(s).debit(ORG, 5, engagement_id=a["slug"], entry_id=f"reserve-wallet:{a['slug']}:{a['nonce']}",
               issued_at=NOW)                         # a prepaid draw under the same launch: contradictory
    r = _release(s, a)
    assert not r["ok"] and "inconsistent" in r["error"] and PostpaidArrearsLedger(s).accrued(ORG) == 60


# ---- the CLI wiring ----------------------------------------------------------------------------------------------
def _cli_sweep(monkeypatch, capsys, store, **kw):
    import sigil.cli as cli
    monkeypatch.setattr(cli, "SpineStore", lambda: store)
    ns = argparse.Namespace(sweep_cmd="reservations", ttl=TTL, apply=False, base_dir="", completion_spool="",
                            checkouts="", spool="", now=LATE)
    for k, v in kw.items():
        setattr(ns, k, v)
    cli.cmd_ops_sweep(ns)
    return json.loads(capsys.readouterr().out)


def test_ops_sweep_reservations_reports_and_applies_the_superseded_rows(monkeypatch, capsys):
    s = _store()
    _seat(s)
    a, b = _superseded(s)
    out = _cli_sweep(monkeypatch, capsys, s)
    assert _statuses(out) == [(b["nonce"], "abandoned"), (a["nonce"], "superseded")] and _avail(s) == 40
    monkeypatch.setenv("VIGIL_OPS_SWEEP_APPLY_ENABLED", "1")
    out = _cli_sweep(monkeypatch, capsys, s, apply=True, completion_spool=_spool())
    assert _statuses(out) == [(b["nonce"], "refunded"), (a["nonce"], "released")] and _avail(s) == 100


# ---- the release follows the settle exactly-once slice: spool lock, busy lock, interrupted settle -------------
def _watcher(store, a, spool):
    from sigil.governor.identity import delegate_offense_governance
    from sigil.inbound.completion_spool import CompletionSpoolWatcher
    owner = ensure_owner_keypair()
    gov = generate_keypair()
    deleg = delegate_offense_governance(
        owner, authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=gov.public_key_b64)],
        threshold=1, scope=a["slug"], not_after=9_000_000_000)
    return CompletionSpoolWatcher(store, spool_dir=spool, owner_pubkey=owner.public_key_b64, delegation=deleg,
                                  scope=a["slug"], base_dir=_base(), now_fn=lambda: NOW + 10)


def test_the_release_recheck_sees_a_completion_reclaimed_between_its_globs(monkeypatch):
    """A completed run's claim stranded in working/ is moved back to incoming/ by the drain's reclaim exactly while the
    release's in-lock re-check is between its incoming/ and working/ globs: the reclaim waits on the spool lock the
    re-check holds shared, so the re-check still sees the completion and refuses the refund."""
    import threading
    s = _store()
    _seat(s)
    a, _b = _superseded(s)
    spool = _spool()
    w = _watcher(s, a, spool)
    gate = LaunchGate(s)
    real_release = gate.release_superseded_reservation
    real_glob = Path.glob
    seen: dict = {"armed": False, "alive": None}
    reclaim = threading.Thread(target=w._reclaim_working)

    def _strand_then_release(**kw):                       # after the sweep's up-front read of the spool
        (Path(spool) / "working" / "c.json").write_text(json.dumps({"document": {
            "engagement_slug": a["slug"], "nonce": a["nonce"], "outcome": "completed"}}), encoding="utf-8")
        seen["armed"] = True
        return real_release(**kw)

    def _glob(self, pattern):
        if seen["armed"] and self == Path(spool) / "working":
            seen["armed"] = False
            reclaim.start()                               # the drain's reclaim, between the two globs
            reclaim.join(0.5)
            seen["alive"] = reclaim.is_alive()
        return real_glob(self, pattern)

    monkeypatch.setattr(gate, "release_superseded_reservation", _strand_then_release)
    monkeypatch.setattr(Path, "glob", _glob)
    out = ops_sweeps.sweep_superseded_reservations(gate, now=LATE, ttl_s=TTL, apply=True, completion_spool=spool)
    reclaim.join(10)
    assert seen["alive"] is True                          # it waited for the re-check's shared hold
    assert _statuses(out) == [(a["nonce"], "completion_pending")] and _avail(s) == 40, out
    assert not is_lease_settled(_base(), a["slug"], a["nonce"])
    assert len(list((Path(spool) / "incoming").glob("*.json"))) == 1      # ...and then reclaimed it


@pytest.mark.parametrize("kind", ["dir", "fifo", "symlink"])
def test_an_unlockable_spool_is_completion_unknown_for_a_release(kind):
    s = _store()
    _seat(s)
    a, _b = _superseded(s)
    spool = _spool()
    p = Path(spool) / ".spool.lock"
    if kind == "dir":
        p.mkdir()
    elif kind == "fifo":
        os.mkfifo(p)
    else:
        (Path(spool) / "elsewhere").write_text("", encoding="utf-8")
        p.symlink_to(Path(spool) / "elsewhere")
    assert _statuses(_sweep(s, apply=True, spool=spool)) == [(a["nonce"], "completion_unknown")]
    assert _avail(s) == 40 and not is_lease_settled(_base(), a["slug"], a["nonce"])


def test_a_mispointed_spool_gets_no_lock_file_from_the_release_sweep():
    s = _store()
    _seat(s)
    a, _b = _superseded(s)
    spool = tempfile.mkdtemp()                            # none of the drain's subdirs
    assert _statuses(_sweep(s, apply=True, spool=spool)) == [(a["nonce"], "completion_unknown")]
    assert os.listdir(spool) == [] and _avail(s) == 40


def test_a_busy_settle_lock_defers_the_release(monkeypatch):
    from sigil.governor.launch_settlement import settle_lock
    s = _store()
    _seat(s)
    a, _b = _superseded(s)
    monkeypatch.setenv("VIGIL_SETTLE_LOCK_WAIT_S", "0.1")
    with settle_lock(s):                                  # another settle holds the cross-process lock
        out = _sweep(s, apply=True)
    assert _statuses(out) == [(a["nonce"], "deferred")] and "retry" in out["items"][0]["error"]
    assert _avail(s) == 40 and not is_lease_settled(_base(), a["slug"], a["nonce"])
    assert _statuses(_sweep(s, apply=True)) == [(a["nonce"], "released")] and _avail(s) == 70


def test_a_release_interrupted_after_its_decision_is_finished_exactly_once(monkeypatch):
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")
    s = _store()
    _seat(s)
    a, _b = _superseded(s)
    real_grant = WalletRegistry.grant

    def _crash(self, *a_, **k):                           # the money move dies after the decision + the marker
        raise OSError("disk full")

    monkeypatch.setattr(WalletRegistry, "grant", _crash)
    assert _statuses(_sweep(s, apply=True)) == [(a["nonce"], "deferred")]
    monkeypatch.setattr(WalletRegistry, "grant", real_grant)
    assert is_lease_settled(_base(), a["slug"], a["nonce"]) and _avail(s) == 40
    dry = _sweep(s)                                       # report-only: what the recorded decision still owes
    assert _statuses(dry) == [(a["nonce"], "settle_interrupted")] and dry["items"][0]["pending_wallet"] == 30
    assert _avail(s) == 40
    done = _sweep(s, apply=True)
    assert _statuses(done) == [(a["nonce"], "settle_completed")] and done["items"][0]["refunded"] == 30
    assert _avail(s) == 70
    assert _sweep(s, apply=True)["items"] == [] and _sweep(s)["items"] == []      # landed: nothing more, ever
    assert _avail(s) == 70


def test_a_settled_reservation_is_left_to_the_abandoned_sweep_while_its_lease_is_on_the_seam(monkeypatch):
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")
    s = _store()
    _seat(s)
    a = _reserve(s, publish=True)
    _reserve(s)                                           # a later reservation: A is no longer the newest
    real_grant = WalletRegistry.grant
    monkeypatch.setattr(WalletRegistry, "grant", lambda self, *a_, **k: (_ for _ in ()).throw(OSError("disk full")))
    assert not LaunchGate(s).settle_launch(signed_lease=a["lease"], consumed_units=0, now=NOW + 60)["ok"]
    monkeypatch.setattr(WalletRegistry, "grant", real_grant)
    assert _seam_nonce(a["slug"]) == a["nonce"]           # its tombstone never landed: the seam still holds it
    assert _sweep(s, apply=True)["items"] == [] and _avail(s) == 40


def test_a_release_that_finds_a_settle_interrupted_meanwhile_reports_what_it_moved(monkeypatch):
    # the sweep read A as unsettled; before its release takes the settle lock a customer cancel of A records its
    # decision and the marker, then dies before the money: the release finishes THAT decision, at its amounts
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")
    s = _store()
    _seat(s)
    a, _b = _superseded(s)
    gate = LaunchGate(s)
    real_release = gate.release_superseded_reservation

    def _cancel_dies_first(**kw):
        real_grant = WalletRegistry.grant
        monkeypatch.setattr(WalletRegistry, "grant", lambda self, *a_, **k: (_ for _ in ()).throw(OSError("full")))
        r = LaunchGate(s).settle_launch(signed_lease=a["lease"], consumed_units=0, now=NOW + 60, basis="cancel")
        assert r.get("retry") and not r["ok"]
        monkeypatch.setattr(WalletRegistry, "grant", real_grant)
        return real_release(**kw)

    monkeypatch.setattr(gate, "release_superseded_reservation", _cancel_dies_first)
    out = ops_sweeps.sweep_superseded_reservations(gate, now=LATE, ttl_s=TTL, apply=True, completion_spool=_spool())
    assert _statuses(out) == [(a["nonce"], "settle_completed")] and out["items"][0]["refunded"] == 30, out
    assert _avail(s) == 70 and _sweep(s, apply=True)["items"] == []


def test_finish_only_never_releases_an_unsettled_reservation():
    s = _store()
    _seat(s)
    a, _b = _superseded(s)
    r = _release(s, a, finish_only=True)
    assert r["ok"] and r["action"] == "launch_not_settled" and r["refunded"] == 0
    assert _avail(s) == 40 and not is_lease_settled(_base(), a["slug"], a["nonce"])


# ---- the remaining E7 guards, each pinned ------------------------------------------------------------------------
def test_start_fails_closed_when_the_check_cannot_run(one_on, monkeypatch):
    import sigil.governor.launch_reservations as lr
    s = _store()
    _seat(s)
    a = _reserve(s)
    monkeypatch.setattr(lr, "scan_reservations", lambda *a_, **k: (_ for _ in ()).throw(OSError("spine unreadable")))
    out = _publish(s, a)
    assert not out["ok"] and "fail-closed" in out["error"] and _seam_nonce(a["slug"]) is None


def test_the_release_rescans_the_spine_inside_the_settle(monkeypatch):
    # a drained settle's outcome record lands after the release's unlocked scan: the in-lock continued scan sees it
    import sigil.governor.launch_reservations as lr
    s = _store()
    _seat(s)
    a, _b = _superseded(s)
    real = lr.scan_reservations
    calls = {"n": 0}

    def _then_outcome(*args, **kw):
        out = real(*args, **kw)
        calls["n"] += 1
        if calls["n"] == 1:
            s.append(kind="assessment_outcome", source="sigil", actor="settle-drain",
                     payload={"engagement_slug": a["slug"], "org_id": ORG, "outcome": "completed",
                              "nonce": a["nonce"], "ts": NOW + 30})
        return out

    monkeypatch.setattr(lr, "scan_reservations", _then_outcome)
    r = _release(s, a)
    assert r.get("refused") == "outcome_recorded" and _avail(s) == 40, r


def test_apply_needs_the_completion_spool():
    s = _store()
    _seat(s)
    with pytest.raises(ValueError, match="completion_spool"):
        ops_sweeps.sweep_superseded_reservations(LaunchGate(s), now=LATE, ttl_s=TTL, apply=True)


def _append_signed(store, core, key):
    from sigil.governor.authn import signed_payload
    store.append(kind="event", source="governor", actor="WARDEN",
                 payload={**signed_payload(core, key), "by": "owner", "requested_by": "owner", "tier": "A0",
                          "decision": "auto", "reason": "test"})


def test_a_legacy_owner_signed_settle_record_settles_the_reservation_as_scan_settlement_reads_it():
    from sigil.governor.launch_settlement import LAUNCH_SETTLED_SIGNAL
    s = _store()
    _seat(s)
    kp = ensure_owner_keypair()
    a = _reserve(s)
    _append_signed(s, {"signal": LAUNCH_SETTLED_SIGNAL, "org_id": ORG, "slug": a["slug"], "nonce": a["nonce"],
                       "consumed": 0, "issued_at": NOW}, kp)                      # the v1 draft record
    key = (ORG, a["slug"], a["nonce"])
    assert scan_settlement(s, kp.public_key_b64, org_id=ORG, slug=a["slug"], nonce=a["nonce"]).settled
    assert key in scan_reservations(s, kp.public_key_b64).settled


def test_forged_reservation_and_settle_evidence_is_ignored():
    from sigil.governor.launch_settlement import LAUNCH_SETTLED_SIGNAL
    s = _store()
    _seat(s)
    kp = ensure_owner_keypair()
    a = _reserve(s)
    foreign = generate_keypair()
    _append_signed(s, {"signal": LAUNCH_SETTLED_SIGNAL, "v": 2, "org_id": ORG, "slug": a["slug"],
                       "nonce": a["nonce"], "mode": "prepaid", "reserved": 30, "consumed": 0, "refund_plan": 0,
                       "refund_wallet": 30, "refund_postpaid": 0, "plan_period_end": 0.0, "basis": "cancel",
                       "issued_at": NOW}, foreign)                                # not the owner's key
    WalletRegistry(s, owner_key=foreign).debit(ORG, 5, engagement_id=a["slug"], entry_id=f"reserve-wallet:{a['slug']}:x9",
                                               issued_at=NOW)                    # a foreign "reservation"
    ix = scan_reservations(s, kp.public_key_b64)
    assert (ORG, a["slug"], a["nonce"]) not in ix.settled
    assert (ORG, a["slug"], "x9") not in ix.reservations and (ORG, a["slug"], a["nonce"]) in ix.reservations


def test_a_reused_nonce_never_inflates_the_released_amount():
    # a refused re-reserve with the same nonce appends a second (idempotent, no-op) reserve record under the same
    # entry id: the release refunds the reservation's credits once, from its first record
    s = _store()
    _seat(s)
    a = _reserve(s, publish=True, nonce="n-a")
    again = LaunchGate(s).reserve_launch(requester="u", org_id=ORG, host=HOST, units=30, now=NOW, duration_hours=1,
                                         nonce="n-a")
    assert not again["ok"] and "nonce already used" in again["error"]
    _reserve(s, publish=True)
    assert scan_reservations(s, ensure_owner_keypair().public_key_b64).reservations[
        (ORG, a["slug"], "n-a")].reserved == 30
    out = _sweep(s, apply=True)
    assert _statuses(out) == [("n-a", "released")] and out["items"][0]["refunded"] == 30 and _avail(s) == 70


# ---- a launch published metered is charged for what it used: never released as a full refund -----------------
def _mark_metered(r):
    from sigil import config
    from sigil.model_gateway import GrantMeter
    from vigil_core.model_grant import meter_id
    GrantMeter(config.MODEL_METER_DIR).mark_metered(meter_id(r["slug"], r["nonce"]))


def test_a_superseded_reservation_published_metered_is_never_released(monkeypatch, tmp_path):
    from sigil import config
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "meters")
    s = _store()
    _seat(s)
    a, _b = _superseded(s)
    _mark_metered(a)                                      # its run was billed metered when it was published
    assert _statuses(_sweep(s)) == [(a["nonce"], "metered")]
    assert _statuses(_sweep(s, apply=True)) == [(a["nonce"], "metered")]
    assert _release(s, a)["refused"] == "metered"
    assert _avail(s) == 40 and not is_lease_settled(_base(), a["slug"], a["nonce"])


def test_an_unreadable_billing_mode_is_never_released(monkeypatch):
    s = _store()
    _seat(s)
    a, _b = _superseded(s)
    monkeypatch.setattr(LaunchGate, "_launch_was_metered",
                        staticmethod(lambda slug, nonce: (_ for _ in ()).throw(OSError("meter dir unreadable"))))
    assert _statuses(_sweep(s, apply=True)) == [(a["nonce"], "metered_unknown")]
    assert _avail(s) == 40 and not is_lease_settled(_base(), a["slug"], a["nonce"])
