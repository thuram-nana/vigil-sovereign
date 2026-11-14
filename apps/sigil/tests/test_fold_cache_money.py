"""Front C S0c — the money folds on the verified incremental fold cache: the persistent wallet, the
period-scoped plan-credit ledger (incl. the settle path's `debited_entry`) and the subscription lines — i.e.
everything `CreditMeter.available`, the launch gate's spend check, reads.

Money is where a cache must be provably invisible. Every test compares the CACHED public API against the SAME
API with the flag OFF (the unchanged full folds / scan) over the same spine, across a grid of `now` instants
for the time-dependent reads, and checks the cached reads did not silently fall back to the full folds. The
generic trust-model cases (anchor, rotation, genesis, build race, faults, concurrency) are proven on the shared
substrate in `test_fold_cache_customers.py`.

  * seeded randomized equivalence over every money op: wallet grant/debit with entry ids reused ACROSS
    directions, plan grants/debits over several periods incl. an entry id re-signed for a DIFFERENT period,
    replays, forged / unsigned records, subscribe / renew / webhook past-due (fresh and stale) / owner latch /
    cancel on BOTH subscription lines, and a second store instance;
  * O(new records): a warm `CreditMeter.available` verifies ZERO signatures; k appends cost exactly k;
  * the two subscription lines are cached apart;
  * a seeded hard prune keeps pruned balances, tranches and consumed entry ids (a pruned grant cannot be
    replayed to re-credit); the pubkey bypass folds the live window only;
  * flag OFF: no money cache is consulted.
"""
from __future__ import annotations

import itertools
import random

import pytest

from sigil.governor import metering as mt
from sigil.governor import monitoring_subscription as ms
from sigil.governor import subscription as sb
from sigil.governor import wallet as wl
from sigil.governor.authn import signed_payload
from sigil.reuse import generate_keypair
from sigil.spine import fold_cache
from sigil.spine.snapshot import SnapshotError, SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64
ATTACKER = generate_keypair()
ORGS = ["acme", "globex", "initech"]
PERIODS = [1000.0, 2000.0, 3000.0]
NOWS = [None, 0.0, 999.0, 1000.0, 1500.0, 2500.0, 3500.0]
_issue = itertools.count(1)


def _iss() -> float:
    return float(next(_issue))


@pytest.fixture(autouse=True)
def _cache_on(monkeypatch):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    fold_cache.clear_all()
    yield
    fold_cache.clear_all()


class _Regs:
    def __init__(self, store, key=OWNER, pub=OWNER_PUB):
        kw = {"owner_key": key, "trusted_pubkey": pub}
        self.wallet = wl.WalletRegistry(store, **kw)
        self.plan = mt.PlanCreditLedger(store, **kw)
        self.subs = sb.SubscriptionRegistry(store, **kw)
        self.msubs = ms.MonitoringSubscriptionRegistry(store, **kw)
        self.meter = mt.CreditMeter(self.wallet, self.plan, self.subs)


@pytest.fixture
def no_full_fold(monkeypatch):
    calls = {"n": 0}
    for cls in (wl.WalletRegistry, mt.PlanCreditLedger, sb.SubscriptionRegistry):
        real = cls._fold

        def spy(self, _real=real):
            calls["n"] += 1
            return _real(self)

        monkeypatch.setattr(cls, "_fold", spy)
    return calls


def _answers(regs, entry_ids):
    out = {"balances": regs.wallet.balances(), "subs": regs.subs.subscriptions(),
           "msubs": regs.msubs.subscriptions()}
    for o in ORGS + ["nope"]:
        out[("bal", o)] = regs.wallet.balance(o)
        out[("avail", o)] = regs.wallet.available(o)
        out[("tranches", o)] = regs.plan.tranches(o)
        out[("sub", o)] = regs.subs.subscription(o)
        out[("msub", o)] = regs.msubs.subscription(o)
        for pe in PERIODS + [0.0]:
            out[("rem", o, pe)] = regs.plan.remaining_for_period(o, pe)
        for now in NOWS:
            out[("plan_avail", o, now)] = regs.plan.available(o, now)
            out[("active", o, now)] = regs.subs.active_subscription(o, now)
            out[("meter", o, now)] = regs.meter.available(o, now)
        for eid in entry_ids:
            out[("debited_entry", o, eid)] = regs.plan.debited_entry(o, eid)
    return out


def _assert_equivalent(regs, entry_ids, monkeypatch, no_full_fold=None):
    before = no_full_fold["n"] if no_full_fold is not None else 0
    cached = _answers(regs, entry_ids)
    if no_full_fold is not None:
        assert no_full_fold["n"] == before, "a cached money read fell back to a full fold"
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "")
    try:
        full = _answers(regs, entry_ids)
    finally:
        monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    assert cached == full


def _fails_closed_both_ways(monkeypatch, *reads):
    """Every read RAISES `SnapshotError`, with the fold cache ON and OFF alike (never an answer from an empty start)."""
    for flag in ("1", ""):
        monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", flag)
        for read in reads:
            with pytest.raises(SnapshotError, match="does not succeed"):
                read()
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")


@pytest.mark.parametrize("seed", [21, 22, 23])
def test_randomized_equivalence_with_the_full_money_folds(tmp_path, seed, monkeypatch, no_full_fold):
    rng = random.Random(seed)
    path = str(tmp_path / "spine.jsonl")
    store, other = SpineStore(path), SpineStore(path)
    regs, regs_other = _Regs(store), _Regs(other)
    entry_ids = [f"e{i}" for i in range(5)]
    captured: list = []
    for step in range(70):
        o, eid, pe = rng.choice(ORGS), rng.choice(entry_ids), rng.choice(PERIODS)
        r = regs_other if rng.random() < 0.2 else regs
        op = rng.choice(["wgrant", "wdebit", "pgrant", "pdebit", "pdebit", "subscribe", "past_due", "stale_due",
                         "latch", "cancel", "msubscribe", "mcancel", "replay", "forged", "unsigned", "noise"])
        seq = None
        if op == "wgrant":
            seq = r.wallet.grant(o, rng.randint(1, 50), rng.choice(sorted(wl.GRANT_KINDS)), entry_id=eid,
                                 issued_at=_iss())
        elif op == "wdebit":
            seq = r.wallet.debit(o, rng.randint(1, 20), entry_id=eid, issued_at=_iss())
        elif op == "pgrant":
            seq = r.plan.grant(o, rng.randint(1, 50), period_end=pe, entry_id=eid, issued_at=_iss())
        elif op == "pdebit":                       # an entry id may be re-signed for a DIFFERENT period
            seq = r.plan.debit(o, rng.randint(1, 20), period_end=pe, entry_id=eid, issued_at=_iss())
        elif op == "subscribe":
            seq = r.subs.subscribe(o, "pro", rng.randint(10, 100), period_start=pe - 1000.0, period_end=pe,
                                   issued_at=_iss())
        elif op == "past_due":                     # webhook-driven, fresher than the last activation
            r.subs.mark_past_due(o, issued_at=_iss() + 0.5)
        elif op == "stale_due":                    # webhook-driven, OLDER than any activation: ignored
            r.subs.mark_past_due(o, issued_at=0.25)
        elif op == "latch":                        # the owner-manual latch (0.0): honoured on sight
            r.subs.mark_past_due(o)
        elif op == "cancel":
            r.subs.cancel(o)
        elif op == "msubscribe":
            seq = r.msubs.subscribe(o, "aegis_observe_1h", rng.randint(1, 5), period_start=pe - 1000.0, period_end=pe,
                                    issued_at=_iss())
        elif op == "mcancel":
            r.msubs.cancel(o)
        elif op == "replay" and captured:
            store.append(kind="event", source="governor", actor="WARDEN", payload=rng.choice(captured))
        elif op == "forged":
            core = {"signal": wl.CREDIT_GRANT_SIGNAL, "org_id": o, "entry_id": f"f{step}", "credits": 10**6,
                    "kind": "topup", "source_ref": "", "issued_at": _iss()}
            store.append(kind="event", source="governor", actor="WARDEN", payload=signed_payload(core, ATTACKER))
        elif op == "unsigned":
            store.append(kind="event", source="governor", actor="WARDEN",
                         payload={"signal": mt.PLAN_GRANT_SIGNAL, "org_id": o, "entry_id": f"u{step}",
                                  "credits": 10**6, "period_end": pe, "issued_at": _iss()})
        else:
            store.append(kind="event", source="t", actor="u", payload={"signal": "noise", "i": step})
        if seq is not None:
            captured.append(store.get(seq).payload)
        _assert_equivalent(regs, entry_ids, monkeypatch, no_full_fold)
    assert wl._WALLET_FOLD._entries and mt._PLAN_FOLD._entries


def test_a_warm_meter_read_verifies_no_signature_and_appends_cost_one_each(tmp_path, monkeypatch):
    regs = _Regs(SpineStore(str(tmp_path / "spine.jsonl")))
    regs.subs.subscribe("acme", "pro", 100, period_start=0.0, period_end=2000.0, issued_at=_iss())
    regs.plan.grant("acme", 100, period_end=2000.0, issued_at=_iss())
    for _ in range(10):
        regs.wallet.grant("acme", 5, "topup", issued_at=_iss())
    count = {"n": 0}
    for mod in (wl, mt, sb):
        real = mod.verify_signed

        def counting(*a, _real=real, **kw):
            count["n"] += 1
            return _real(*a, **kw)

        monkeypatch.setattr(mod, "verify_signed", counting)
    assert regs.meter.available("acme", 1500.0) == 150
    assert count["n"] == 12                                  # cold: every grant verified once
    count["n"] = 0
    for _ in range(5):
        assert regs.meter.available("acme", 1500.0) == 150
    assert count["n"] == 0, "a warm meter read must not re-verify any signature"
    regs.wallet.debit("acme", 20, issued_at=_iss())
    regs.plan.debit("acme", 30, period_end=2000.0, issued_at=_iss())
    assert regs.meter.available("acme", 1500.0) == 100
    assert count["n"] == 2
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "")
    count["n"] = 0
    assert regs.meter.available("acme", 1500.0) == 100
    assert count["n"] == 14, "control: OFF re-verifies every money record"


def test_the_two_subscription_lines_are_cached_apart(tmp_path, monkeypatch, no_full_fold):
    regs = _Regs(SpineStore(str(tmp_path / "spine.jsonl")))
    regs.subs.subscribe("acme", "pro", 100, period_start=0.0, period_end=2000.0, issued_at=_iss())
    regs.msubs.subscribe("acme", "aegis_observe_1h", 3, period_start=0.0, period_end=2000.0, issued_at=_iss())
    regs.msubs.cancel("acme")
    _assert_equivalent(regs, [], monkeypatch, no_full_fold)
    assert regs.subs.subscription("acme").status == "active"
    assert regs.msubs.subscription("acme").status == "canceled"
    assert set(sb._SUB_FOLDS) == {sb.SUBSCRIPTION_SIGNAL, ms.MONITORING_SUBSCRIPTION_SIGNAL}


class _PrunedView:
    def __init__(self, inner):
        self._inner, self.K, self.path = inner, 0, inner.path

    def iter_records(self, *, since_seq=-1):
        for r in self._inner.iter_records(since_seq=since_seq):
            if r.seq >= self.K:
                yield r

    def get(self, seq):
        return self._inner.get(seq) if seq >= self.K else None

    def append(self, **kw):
        return self._inner.append(**kw)


def _pruned_money(tmp_path, monkeypatch, *, snap_pub):
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    view = _PrunedView(store)
    regs = _Regs(view)
    g = regs.wallet.grant("acme", 40, "topup", entry_id="paid-1", issued_at=_iss())
    regs.wallet.debit("acme", 15, entry_id="spend-1", issued_at=_iss())
    regs.subs.subscribe("acme", "pro", 100, period_start=0.0, period_end=2000.0, issued_at=_iss())
    regs.plan.grant("acme", 100, period_end=2000.0, entry_id="refill-1", issued_at=_iss())
    d = regs.plan.debit("acme", 30, period_end=2000.0, entry_id="res-1", issued_at=_iss())
    captured = [store.get(g).payload, store.get(d).payload]
    assert regs.meter.available("acme", 1500.0) == 95          # warm, unpruned
    k = store.append(kind="event", source="t", actor="u", payload={"signal": "marker"})
    snap = build([r for r in store.iter_records() if r.seq < k], trusted_pubkey=snap_pub, base_seq=k,
                 snapshot_seq=k - 1)
    view.K = k
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    return store, regs, snap, captured


def test_a_seeded_prune_keeps_balances_tranches_and_consumed_entry_ids(tmp_path, monkeypatch, no_full_fold):
    store, regs, snap, captured = _pruned_money(tmp_path, monkeypatch, snap_pub=OWNER_PUB)
    assert snap.wallet_granted_map() and snap.plan_granted_map(), "the seed carries the pruned money"
    for p in captured:                                          # replay the pruned grant + debit live
        store.append(kind="event", source="governor", actor="WARDEN", payload=p)
    regs.wallet.grant("acme", 5, "topup", entry_id="paid-2", issued_at=_iss())
    _assert_equivalent(regs, ["res-1", "paid-1"], monkeypatch, no_full_fold)
    assert regs.wallet.balance("acme").granted == 45, "a pruned grant replayed live cannot re-credit"
    assert regs.meter.available("acme", 1500.0) == 100
    assert regs.plan.debited_entry("acme", "res-1") is not None, "the live replay of the debit is found"


def test_a_foreign_key_reader_of_a_pruned_snapshot_fails_closed(tmp_path, monkeypatch):
    """A PRUNED snapshot folded under a key the reader's owner-key succession does not reach (a swapped key, a
    re-genesis) is never trusted, and an empty start over the deleted prefix is not an answer either: every read
    fails CLOSED, cached and uncached alike."""
    store, _regs, _snap, _captured = _pruned_money(tmp_path, monkeypatch, snap_pub=OWNER_PUB)
    new_owner = generate_keypair()
    reader = _Regs(_regs.wallet.store, key=new_owner, pub=new_owner.public_key_b64)
    _fails_closed_both_ways(monkeypatch, lambda: reader.wallet.balance("acme"), lambda: reader.plan.tranches("acme"),
                            lambda: reader.subs.subscription("acme"))


@pytest.mark.parametrize("value", ["", "0", "off"])
def test_flag_off_never_consults_a_money_cache(tmp_path, monkeypatch, value):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", value)

    def boom(*_a, **_kw):
        raise AssertionError("a money fold cache was consulted with the flag OFF")

    for c in (wl._WALLET_FOLD, mt._PLAN_FOLD, sb._sub_fold(sb.SUBSCRIPTION_SIGNAL),
              sb._sub_fold(ms.MONITORING_SUBSCRIPTION_SIGNAL)):
        monkeypatch.setattr(c, "read", boom)
    regs = _Regs(SpineStore(str(tmp_path / "spine.jsonl")))
    regs.subs.subscribe("acme", "pro", 100, period_start=0.0, period_end=2000.0, issued_at=_iss())
    regs.plan.grant("acme", 100, period_end=2000.0, issued_at=_iss())
    regs.plan.debit("acme", 10, period_end=2000.0, entry_id="r1", issued_at=_iss())
    regs.wallet.grant("acme", 5, "topup", issued_at=_iss())
    regs.msubs.subscribe("acme", "aegis_observe_1h", 1, period_start=0.0, period_end=2000.0, issued_at=_iss())
    assert regs.meter.available("acme", 1500.0) == 95
    assert regs.plan.debited_entry("acme", "r1") == (10, 2000.0)
    assert regs.wallet.balances()[0].granted == 5 and regs.msubs.subscription("acme") is not None
