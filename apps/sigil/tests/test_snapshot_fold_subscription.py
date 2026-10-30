"""Prune-survival proof for the SnapshotState-seeded `SubscriptionRegistry._fold` (SaaS subscription).

A subscription is a per-org LWW state (active / past_due / canceled) with a per-org anti-replay high-water —
so, like orgs/accounts, both the state AND the high-water must survive a hard prune, or the first prune would
drop the plan AND reset the high-water (re-opening replay of a lapsed plan via a captured `active` grant).

PHYSICAL-PRUNE HARNESS (identical to test_snapshot_fold_accounts.py): a `PrunedView` physically hides
`seq < K` from `iter_records` regardless of `since_seq`, so only the SEED can carry the pruned state.

MUTATION-VERIFIED: reverting the fold to a genesis scan (no seed) fails the survival + split tests; dropping
ONLY the carried high-water re-opens replay (the dedicated neutered control below).

  (a) an active subscription whose only grant is pruned STILL reads active — from the seed alone;
  (b) the per-org high-water SURVIVES the prune, so a replayed pruned `active` does NOT resurrect a canceled
      plan (neutered control strips ONLY `subscription_issued` to isolate that carry);
  (c) empty-load == genesis scan byte-identity (split == full with the prefix physically absent);
  (d) `check_prune_safe`'s floor DETECTS a seed that would strand an active subscription and refuses.

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:integration \
     .venv-sovereign/bin/python -m pytest apps/sigil/tests/test_snapshot_fold_subscription.py -q
"""
import itertools
import tempfile

import pytest

from sigil.governor.authn import signed_payload
from sigil.governor.subscription import STATUS_ACTIVE, STATUS_CANCELED, SUBSCRIPTION_SIGNAL, SubscriptionRegistry
from sigil.reuse import generate_keypair
from sigil.spine import prune
from sigil.spine.manifest import read_manifest
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64
ATTACKER = generate_keypair()

_issue = itertools.count(1)


def _iss() -> float:
    return float(next(_issue))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store):
    return SubscriptionRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)


class PrunedView:
    def __init__(self, inner, K):
        self._inner = inner
        self._K = K

    def iter_records(self, *, since_seq=-1):
        for r in self._inner.iter_records(since_seq=since_seq):
            if r.seq >= self._K:
                yield r

    def get(self, seq):
        return self._inner.get(seq)

    def append(self, **kw):
        return self._inner.append(**kw)


# ---- (a) an active subscription whose only grant is PHYSICALLY PRUNED survives via the seed ----------
def test_active_subscription_survives_a_hard_prune(monkeypatch):
    store = _store()
    r = _reg(store)
    r.subscribe("acme", "pro", 6000, period_start=1.0, period_end=1e18, issued_at=5.0)              # seq 0
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})  # seq 1
    prefix = [rec for rec in store.iter_records() if rec.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    assert snap.subscription_state_map().get("acme") == STATUS_ACTIVE
    assert snap.subscription_issued_map().get("acme") == 5.0
    assert any(row[0] == "acme" and row[1] == "pro" for row in snap.subscription_row)

    pruned = PrunedView(store, k)
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    r2 = SubscriptionRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    sub = r2.subscription("acme")
    assert sub is not None and sub.status == STATUS_ACTIVE and sub.plan_id == "pro" and sub.allotment == 6000
    assert r2.active_subscription("acme") is not None

    # NEUTERED control (== pre-fix genesis scan): no seed over the pruned store ⇒ the subscription vanishes.
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    r2b = SubscriptionRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert r2b.subscription("acme") is None


# ---- (b) the per-org high-water survives the prune (no replay resurrection of a canceled plan) --------
def test_high_water_survives_the_prune_no_replay_resurrection(monkeypatch):
    store = _store()
    r = _reg(store)
    sub_seq = r.subscribe("acme", "pro", 6000, period_start=1.0, period_end=1e18, issued_at=5.0)   # seq 0
    captured = store.get(sub_seq).payload
    r.cancel("acme")                                                                                # seq 1
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})  # seq 2
    prefix = [rec for rec in store.iter_records() if rec.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    assert snap.subscription_state_map().get("acme") == STATUS_CANCELED
    assert snap.subscription_issued_map().get("acme") == 5.0        # the high-water that must cross the prune

    store.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # seq 3: replay (live)
    pruned = PrunedView(store, k)

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    r2 = SubscriptionRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert r2.subscription("acme").status == STATUS_CANCELED, "replayed pruned active must NOT resurrect (seed high-water)"

    # NEUTERED control: carry the STATUS but strip ONLY the high-water. Now the replayed active (issued_at 5
    # > -inf) overrides canceled back to active — proving the high-water carry (not just the status carry) is
    # what closes replay-resurrection across a prune.
    snap_no_hw = snap.model_copy(update={"subscription_issued": []})
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap_no_hw))
    r2b = SubscriptionRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert r2b.subscription("acme").status == STATUS_ACTIVE, "dropping the high-water ⇒ the replayed active resurrects"


# ---- (b2) a subscribed-THEN-canceled plan whose grant is pruned STILL reads (row carried, not vanished) --
def test_canceled_after_subscribe_survives_prune_not_dropped_as_phantom(monkeypatch):
    # Guards the phantom-filter fix against a false drop: `_fold` now omits a tenant with ONLY a bare
    # down-state (never subscribed), but a plan canceled AFTER a real subscribe keeps its `row`, which the
    # seed carries across a hard prune — so it must still read `canceled` with its retained plan, not None.
    store = _store()
    r = _reg(store)
    r.subscribe("acme", "pro", 6000, period_start=1.0, period_end=1e18, issued_at=5.0)   # seq 0 (sets row)
    r.cancel("acme")                                                                       # seq 1 (down)
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})  # seq 2
    prefix = [rec for rec in store.iter_records() if rec.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    assert snap.subscription_state_map().get("acme") == STATUS_CANCELED
    assert any(row[0] == "acme" and row[1] == "pro" for row in snap.subscription_row)   # row carried in seed

    pruned = PrunedView(store, k)
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    r2 = SubscriptionRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    sub = r2.subscription("acme")
    assert sub is not None and sub.status == STATUS_CANCELED and sub.plan_id == "pro", \
        "a canceled-after-subscribe plan must survive the prune via the carried row (not be dropped as a phantom)"
    assert r2.active_subscription("acme") is None


# ---- (c) empty-load == genesis scan, proven by split == full == known-correct ------------------------
def _populate(store):
    r = _reg(store)
    r.subscribe("seeded", "pro", 6000, period_start=1.0, period_end=1e18, issued_at=_iss())   # seed-only active
    r.subscribe("downlive", "starter", 1000, period_start=1.0, period_end=1e18, issued_at=_iss())  # canceled live
    r.subscribe("renew", "starter", 1000, period_start=1.0, period_end=1e18, issued_at=_iss())
    r.cancel("renew")                                                                          # canceled in prefix
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})
    r.cancel("downlive")                                                                       # LWW down live
    r.subscribe("renew", "pro", 6000, period_start=1.0, period_end=1e18, issued_at=_iss())     # recovers live
    r.subscribe("live", "pro", 6000, period_start=1.0, period_end=1e18, issued_at=_iss())      # live-only
    core = {"signal": SUBSCRIPTION_SIGNAL, "org_id": "seeded", "plan_id": "pro", "period_start": 1.0,
            "period_end": 1e18, "allotment": 9999, "status": "active", "issued_at": 9_999.0}
    store.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(core, ATTACKER)})
    return k


_EXPECTED = {"seeded": STATUS_ACTIVE, "downlive": STATUS_CANCELED, "renew": STATUS_ACTIVE, "live": STATUS_ACTIVE}


def _status_map(reg):
    return {s.org_id: s.status for s in reg.subscriptions()}


def test_subscription_empty_load_matches_known_correct():
    store = _store()
    _populate(store)
    assert SnapshotState.load(store).base_seq == 0
    assert _status_map(_reg(store)) == _EXPECTED
    assert _reg(store).subscription("seeded").allotment == 6000      # forged 9999 active stayed inert


def test_split_fold_equals_full_scan_with_prefix_physically_absent(monkeypatch):
    store = _store()
    k = _populate(store)
    full = _status_map(_reg(store))
    assert full == _EXPECTED

    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    assert snap.subscription_state_map().get("seeded") == STATUS_ACTIVE
    assert snap.trusted_pubkey == OWNER_PUB

    pruned = PrunedView(store, k)
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    split = _status_map(SubscriptionRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB))
    assert split == full, f"subscription fold != scan over a physically-pruned store\n full={full}\n split={split}"

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    split_neutered = _status_map(SubscriptionRegistry(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB))
    assert split_neutered != full and "seeded" not in split_neutered


# ---- (d) check_prune_safe referential floor ----------------------------------------------------------
def _sub_segmented_store(tmp_path):
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    r = SubscriptionRegistry(s, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    r.subscribe("acme", "pro", 6000, period_start=1.0, period_end=1e18, issued_at=1.0)   # seq 0
    for _ in range(4):
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})             # seq 1..4
    s.rotate()                                                                           # seal [0..5)
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})            # seq 5..9
    s.rotate()
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "tail"})
    return s


def _archived_below(store, K):
    return [seg for seg in read_manifest(store._layout).sealed_in_order()
            if seg.last_seq is not None and seg.last_seq < K]


def test_check_prune_safe_allows_a_carried_subscription(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _sub_segmented_store(tmp_path)
    archived = prune.check_prune_safe(s, 5)
    assert [seg.first_seq for seg in archived] == [0]
    assert prune.stranded_active_subscriptions(s, archived, 5) == []
    below = []
    for seg in archived:
        below.extend(prune.read_segment_records(s._layout.seg_path(seg)))
    seed = build(below, trusted_pubkey=OWNER_PUB, base_seq=5, snapshot_seq=-1)
    assert seed.subscription_state_map().get("acme") == STATUS_ACTIVE


def test_referential_floor_detects_a_seed_that_omits_a_subscription(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _sub_segmented_store(tmp_path)
    real_build = prune.build

    def incomplete_build(records, **kw):
        seed = real_build(records, **kw)
        return seed.model_copy(update={
            "subscription_state": [r for r in seed.subscription_state if r[0] != "acme"],
            "subscription_issued": [r for r in seed.subscription_issued if r[0] != "acme"],
            "subscription_row": [r for r in seed.subscription_row if r[0] != "acme"],
        })

    monkeypatch.setattr(prune, "build", incomplete_build)
    assert prune.stranded_active_subscriptions(s, _archived_below(s, 5), 5) == ["acme"]
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    msg = str(e.value).lower()
    assert "strand" in msg and "acme" in msg and "subscription" in msg


def test_check_prune_safe_reraises_a_nonempty_subscription_floor_wiring_only(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _sub_segmented_store(tmp_path)
    monkeypatch.setattr(prune, "stranded_active_subscriptions", lambda store, archived, K: ["ghost-tenant"])
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "strand" in str(e.value).lower() and "ghost-tenant" in str(e.value)
