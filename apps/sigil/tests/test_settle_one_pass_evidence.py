"""E3bc — every sweep reads the spine's settlement evidence in ONE pass for all the launches it lists.

``launch_settlement.scan_settlements`` and ``launch_reservations.scan_reservations(evidence=True)`` give, per lease,
exactly what ``launch_settlement.scan_settlement`` gives — its first verified decision record and the owner-signed
settle entries that landed — so ``ops-sweep reservations`` (the abandoned-lease half's report and the superseded
half, report and ``--apply``) visits each spine record O(1) times, however many launches the spine holds, and calls
the per-lease finish path only for a launch whose recorded decision still has money to land.

Mutation-verify targets (each neuter turns a NAMED test red):
  * scan_settlements / the evidence index drift from scan_settlement (first decision, landed tags, forged records)
                                                            -> test_one_pass_evidence_equals_scan_settlement_per_lease
  * the superseded sweep rescans the spine per settled launch
                                                            -> test_the_superseded_sweep_visits_each_spine_record_...
  * the abandoned sweep's report rescans the spine per listed lease
                                                            -> test_the_abandoned_sweep_report_visits_each_spine_...

Run: PYTHONPATH=apps/sigil:integration:packages/core/vigil_core python -m pytest \
     apps/sigil/tests/test_settle_one_pass_evidence.py
"""
from __future__ import annotations

import itertools
import os
import tempfile

import pytest

from sigil import config
from sigil import ops_sweeps
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.authn import signed_payload
from sigil.governor.identity import delegate_offense_governance, ensure_owner_keypair
from sigil.governor.launch_reservations import scan_reservations
from sigil.governor.launch_settlement import LAUNCH_SETTLED_SIGNAL, scan_settlement, scan_settlements
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.orgs import OrgRegistry
from sigil.governor.postpaid import PostpaidRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.inbound.completion_spool import CompletionSpoolWatcher
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_core import AuthorizerKey, generate_keypair
from vigil_core import model_metering as mm
from vigil_integration.live import credit_lease_broker as B
from vigil_integration.live.credit_lease_broker import read_credit_lease

_iss = itertools.count(1)
ORG, HOST, NOW = "org_a", "apme.cm", 2000.0
_NONE = {"settled": 0, "noop": 0, "rejected": 0, "deduped": 0}


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    for k in ("VIGIL_METERED_BILLING", mm.MARGIN_ENV, mm.CANCEL_ENV, "VIGIL_RUN_FLOOR_CREDITS", "VIGIL_MODEL_PRICES",
              "VIGIL_MODEL_GATEWAY_ENABLED", "VIGIL_RUN_MODEL", "VIGIL_SETTLE_SPINE_RECORD", "VIGIL_SETTLE_LOCK_WAIT_S",
              "VIGIL_COST_LEDGER_WRITE", "VIGIL_PAUSED_EXPIRY_SETTLE", "VIGIL_PAUSED_EXPIRY_SETTLE_GRACE_SECONDS",
              "VIGIL_ONE_LAUNCH_PER_HOST", *mm.OBSOLETE_PRICING_ENVS):
        monkeypatch.delenv(k, raising=False)


@pytest.fixture
def record_on(monkeypatch):
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")


def _base() -> str:
    return os.environ["VIGIL_BASE_DIR"]


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _add_host(store, host, *, org=ORG, now=NOW):
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=now, ttl_seconds=1e12)
    assert add_customer_target(host, org_id=org, store=store, now=now)["ok"]


def _seat(store, *, credits=100, postpaid=None, plan=None, hosts=(HOST,), now=NOW):
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
    if postpaid is not None:
        PostpaidRegistry(store).set_account(ORG, postpaid[0], postpaid[1], issued_at=float(next(_iss)))
    for h in hosts:
        _add_host(store, h, now=now)


def _reserve(store, *, units=30, nonce=None, publish=False, hours=1, host=HOST, now=NOW):
    g = LaunchGate(store)
    r = g.reserve_launch(requester="u", org_id=ORG, host=host, units=units, now=now, duration_hours=hours, nonce=nonce)
    assert r["ok"], r
    if publish:
        assert g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    return r


def _settle(store, r, consumed, now=NOW + 60, **kw):
    return LaunchGate(store).settle_launch(signed_lease=r["lease"], consumed_units=consumed, now=now, **kw)


def _relaunch(s, units, nonce):
    r = LaunchGate(s).reserve_launch(requester="u", org_id=ORG, host=HOST, units=units, now=NOW + 120,
                                     duration_hours=8, nonce=nonce)
    assert r["ok"], r
    return r, LaunchGate(s).publish_lease(signed_lease=r["lease"], expect_org_id=ORG)


def _avail(store):
    return WalletRegistry(store).available(ORG)


def _plan(store):
    return PlanCreditLedger(store).available(ORG, NOW)


def _decisions(store):
    return [x for x in store.iter_records() if (x.payload or {}).get("signal") == LAUNCH_SETTLED_SIGNAL]


def _outcomes(store):
    return [x.payload["outcome"] for x in store.iter_records() if x.kind == "assessment_outcome"]


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


def _watcher(store, slug, *, now=NOW + 60):
    """A settle drain scoped to ``slug`` (its owner-signed governance delegation), over an empty completion spool."""
    owner = ensure_owner_keypair()
    key = generate_keypair()
    deleg = delegate_offense_governance(
        owner, authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=key.public_key_b64)],
        threshold=1, scope=slug, not_after=9_000_000_000)
    return CompletionSpoolWatcher(store, spool_dir=_spool(), owner_pubkey=owner.public_key_b64, delegation=deleg,
                                  scope=slug, base_dir=_base(), now_fn=lambda: now)


def _published(r) -> bool:
    b = read_credit_lease(_base(), r["slug"])
    return b is not None and b.signed_lease.document.nonce == r["nonce"]



# =====================================================================================================================
# ONE pass over the spine per sweep / drain pass
# =====================================================================================================================
def _v2_core(slug, nonce, **over):
    core = {"signal": LAUNCH_SETTLED_SIGNAL, "v": 2, "org_id": ORG, "slug": slug, "nonce": nonce,
            "mode": "prepaid", "reserved": 30, "consumed": 0, "refund_plan": 0, "refund_wallet": 30,
            "refund_postpaid": 0, "plan_period_end": 0.0, "basis": "cancel", "issued_at": NOW}
    core.update(over)
    return core


def _append_signed(store, core, key):
    store.append(kind="event", source="governor", actor="WARDEN",
                 payload={**signed_payload(core, key), "by": "owner", "requested_by": "owner", "tier": "A0",
                          "decision": "auto", "reason": "test"})


def test_one_pass_evidence_equals_scan_settlement_per_lease(monkeypatch):
    s = _store()
    _seat(s, credits=5_000, plan=200)
    kp = ensure_owner_keypair()
    rs = [_reserve(s, units=30, nonce=f"n{i:02d}") for i in range(10)]
    _settle(s, rs[0], 0, basis="cancel")                                     # flag off: settle entries only
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", "1")
    _settle(s, rs[1], 10, basis="cancel")                                    # decision + entries
    _settle(s, rs[2], 30, basis="completion:completed")                      # decision, refund 0
    restore = _kill(monkeypatch, PlanCreditLedger, "grant", exc=OSError("disk full"))
    _settle(s, rs[3], 0, basis="cancel")                                     # decision + marker, nothing landed
    restore()
    _append_signed(s, _v2_core(rs[4]["slug"], rs[4]["nonce"]), generate_keypair())   # forged: ignored
    _append_signed(s, _v2_core(rs[4]["slug"], rs[4]["nonce"], basis="sweep:refund"), kp)
    _append_signed(s, _v2_core(rs[4]["slug"], rs[4]["nonce"], consumed=30, refund_wallet=0), kp)   # later: loses
    _append_signed(s, {"signal": LAUNCH_SETTLED_SIGNAL, "org_id": ORG, "slug": rs[5]["slug"], "nonce": rs[5]["nonce"],
                       "consumed": 0, "issued_at": NOW}, kp)                 # legacy v1: settled, malformed
    _append_signed(s, _v2_core(rs[6]["slug"], rs[6]["nonce"], refund_wallet=29), kp)  # owner-signed, bad split
    v1 = {"signal": LAUNCH_SETTLED_SIGNAL, "org_id": ORG, "slug": rs[9]["slug"], "nonce": rs[9]["nonce"],
          "consumed": 0, "issued_at": NOW}
    unsigned_v2 = {k: v for k, v in _v2_core(rs[9]["slug"], rs[9]["nonce"]).items() if k not in v1}
    s.append(kind="event", source="governor", actor="WARDEN",
             payload={**signed_payload(v1, kp), **unsigned_v2})              # signed as v1; its v2 split is not signed
    tail = f"{rs[7]['slug']}:{rs[7]['nonce']}"
    WalletRegistry(s).grant(ORG, 30, "refund", entry_id=f"settle-wallet:{tail}", issued_at=NOW)   # entry first ...
    _append_signed(s, _v2_core(rs[7]["slug"], rs[7]["nonce"]), kp)          # ... then its decision
    WalletRegistry(s, owner_key=generate_keypair()).grant(ORG, 1, "refund", entry_id=f"settle-wallet:{rs[8]['slug']}:"
                                                          f"{rs[8]['nonce']}", issued_at=NOW)   # forged entry
    keys = [(ORG, r["slug"], r["nonce"]) for r in rs] + [(ORG, rs[0]["slug"], "absent"), ("other_org", rs[1]["slug"],
                                                                                          rs[1]["nonce"])]
    many = scan_settlements(s, kp.public_key_b64, keys=keys)
    ix = scan_reservations(s, kp.public_key_b64, evidence=True)
    fields = ("through", "record_seq", "decision", "malformed", "landed")
    for k in keys:
        one = scan_settlement(s, kp.public_key_b64, org_id=k[0], slug=k[1], nonce=k[2])
        assert [getattr(many[k], f) for f in fields] == [getattr(one, f) for f in fields], k
        got = ix.settlement(k)
        assert [getattr(got, f) for f in fields] == [getattr(one, f) for f in fields], k
        assert (k in ix.settled) is one.settled, k
    assert many[(ORG, rs[3]["slug"], rs[3]["nonce"])].decision.refund_plan == 30      # the one left to finish
    assert [many[(ORG, r["slug"], r["nonce"])].malformed for r in (rs[5], rs[6], rs[9])] == [True, True, True]
    assert many[(ORG, rs[4]["slug"], rs[4]["nonce"])].decision.basis == "sweep:refund"   # the first VERIFIED wins
    assert many[(ORG, rs[7]["slug"], rs[7]["nonce"])].landed == {"wallet"} and not many[
        (ORG, rs[8]["slug"], rs[8]["nonce"])].settled                                  # a forged entry is no evidence
    assert scan_reservations(s, kp.public_key_b64).evidence is None                  # opt-in: E7 checks unchanged
    with pytest.raises(ValueError):
        scan_reservations(s, kp.public_key_b64, since=scan_reservations(s, kp.public_key_b64), evidence=True)
    with pytest.raises(ValueError):
        scan_reservations(s, kp.public_key_b64).settlement(keys[0])
    assert scan_settlements(s, None, keys=keys[:1])[keys[0]].settled is False        # no owner key: nothing trusted
    other = ("other_org", rs[1]["slug"], rs[1]["nonce"])                             # org_a's records are not its
    alone = scan_settlements(s, kp.public_key_b64, keys=[other])[other]
    assert not alone.settled and alone.landed == set() and alone.record_seq is None


def _counting(monkeypatch, s):
    seen = {"visits": 0, "passes": 0}
    real = type(s).iter_records

    def counting(self, *a, **kw):
        seen["passes"] += 1
        for r in real(self, *a, **kw):
            seen["visits"] += 1
            yield r
    monkeypatch.setattr(type(s), "iter_records", counting)
    return seen, sum(1 for _ in real(s)), lambda: monkeypatch.setattr(type(s), "iter_records", real)


@pytest.mark.parametrize("k", [6, 24])
def test_the_superseded_sweep_visits_each_spine_record_a_bounded_number_of_times(record_on, k, monkeypatch):
    s = _store()
    _seat(s, credits=100_000)
    for i in range(k):
        r = _reserve(s, units=10, publish=True, nonce=f"n{i:06d}x")
        assert _settle(s, r, 10, basis="completion:completed")["ok"]
    later = NOW + 10 * 86400
    for apply in (False, True):
        seen, n, restore = _counting(monkeypatch, s)
        out = ops_sweeps.sweep_superseded_reservations(LaunchGate(s), now=later, ttl_s=50, apply=apply,
                                                       completion_spool=_spool())
        restore()
        assert out["items"] == []
        assert seen["visits"] <= 3 * n, (k, apply, seen, n)                  # O(1) per record, whatever k


@pytest.mark.parametrize("k", [3, 12])
def test_the_abandoned_sweep_report_visits_each_spine_record_a_bounded_number_of_times(record_on, k, monkeypatch):
    s = _store()
    hosts = [f"h{i}.example" for i in range(k)]
    _seat(s, credits=100_000, hosts=hosts)
    leases = [_reserve(s, units=10, publish=True, host=h, nonce=f"m{i:06d}x") for i, h in enumerate(hosts)]
    for r in leases[: k // 3]:                          # a third settled with only the tombstone left
        restore = _kill(monkeypatch, B, "tombstone_credit_lease")
        with pytest.raises(SystemExit):
            _settle(s, r, 10, basis="completion:completed")
        restore()
    seen, n, restore = _counting(monkeypatch, s)
    rows = ops_sweeps.sweep_abandoned_reservations(LaunchGate(s), now=NOW + 60, ttl_s=50, apply=False)["items"]
    restore()
    assert rows == [] and seen["visits"] <= 3 * n, (k, seen, n)               # one pass for every listed lease
