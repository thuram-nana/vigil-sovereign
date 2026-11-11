"""Prune-survival proof for the SnapshotState-seeded `PlanCreditLedger._fold` (SaaS period-scoped plan credits).

A plan tranche's remainder is a running total keyed per (org, period_end) (like the wallet, unlike the per-UTC-day
budget), so it MUST seed from `SnapshotState` or the first hard prune below a tenant's grants would (1) ZERO an
unexpired tranche and (2) drop the consumed-`entry_id` set — re-opening plan-grant REPLAY. NON-ROLLOVER expiry is
applied at READ time (`available(now)`), so the seed carries every tranche's granted/debited regardless of
expiry; expiry drops a tranche only when read.

PHYSICAL-PRUNE HARNESS (identical to test_snapshot_fold_wallet.py): a `PrunedView` physically hides seq < K from
`iter_records` regardless of `since_seq`, so only the SEED can carry the pruned state.

MUTATION-VERIFIED: reverting the fold to a genesis scan (no seed) fails the survival + split tests; dropping ONLY
the carried `plan_seen` set re-opens replay-recredit (the dedicated neutered control below).

  (a) an unexpired tranche whose grants are PHYSICALLY PRUNED keeps its balance from the seed — AND still expires
      at read time (non-rollover holds across a prune);
  (b) the consumed `entry_id` set SURVIVES the prune, so a replayed pruned grant does NOT re-credit (neutered
      control strips ONLY `plan_seen`);
  (c) empty-load == genesis scan byte-identity (split == full with the prefix physically absent);
  (d) `check_prune_safe` DETECTS a seed that would strand a tenant's plan tranche and refuses.

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:integration \
     .venv-sovereign/bin/python -m pytest apps/sigil/tests/test_snapshot_fold_metering.py -q
"""
import itertools
import tempfile

import pytest

from sigil.governor.authn import signed_payload
from sigil.governor.metering import PLAN_GRANT_SIGNAL, PlanCreditLedger
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
    return PlanCreditLedger(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)


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


# ---- (a) an unexpired tranche survives a hard prune via the seed AND still expires at read time ------
def test_tranche_survives_a_hard_prune_and_still_expires(monkeypatch):
    store = _store()
    p = _reg(store)
    p.grant("acme", 6000, period_end=200.0, issued_at=_iss(), entry_id="g1")                          # seq 0
    p.debit("acme", 100, period_end=200.0, engagement_id="e", issued_at=_iss(), entry_id="d1")         # seq 1
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})    # seq 2
    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    assert snap.plan_granted_map().get(("acme", 200.0)) == 6000
    assert snap.plan_debited_map().get(("acme", 200.0)) == 100

    pruned = PrunedView(store, k)
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    p2 = PlanCreditLedger(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert p2.available("acme", now=150.0) == 5900, "pruned tranche remainder must survive via the seed"
    assert p2.available("acme", now=250.0) == 0, "non-rollover holds across a prune: expired tranche reads 0"

    # NEUTERED control (== pre-fix genesis scan): no seed over the pruned store ⇒ the tranche vanishes.
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    p2b = PlanCreditLedger(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert p2b.available("acme", now=150.0) == 0


# ---- (b) the consumed entry_id set survives the prune (no replay re-credit) ---------------------------
def test_seen_set_survives_the_prune_no_replay_recredit(monkeypatch):
    store = _store()
    p = _reg(store)
    gseq = p.grant("acme", 500, period_end=200.0, issued_at=_iss(), entry_id="g1")    # seq 0
    captured = store.get(gseq).payload
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})  # seq 1
    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    assert (PLAN_GRANT_SIGNAL, "acme", "g1") in snap.plan_seen_set()

    store.append(kind="event", source="governor", actor="WARDEN", payload=captured)  # seq 2: replay (live)
    pruned = PrunedView(store, k)

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    p2 = PlanCreditLedger(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert p2.available("acme", now=150.0) == 500, "replayed pruned grant must NOT re-credit (seed seen-set)"

    # NEUTERED control: carry the balance but strip ONLY the seen-set ⇒ the replayed grant re-credits to 1000.
    snap_no_seen = snap.model_copy(update={"plan_seen": []})
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap_no_seen))
    p2b = PlanCreditLedger(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert p2b.available("acme", now=150.0) == 1000, "dropping the seen-set ⇒ the replayed pruned grant re-credits"


# ---- (c) empty-load == genesis scan, proven by split == full == known-correct ------------------------
def _populate(store):
    p = _reg(store)
    # ---- prefix [0..K) ----
    p.grant("seeded", 100, period_end=1e18, issued_at=_iss(), entry_id="gs")        # seed-only tenant
    p.grant("mixed", 50, period_end=1e18, issued_at=_iss(), entry_id="gm1")         # extended live
    p.debit("mixed", 20, period_end=1e18, engagement_id="e", issued_at=_iss(), entry_id="dm1")
    k = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})
    # ---- live [K..T) ----
    p.grant("mixed", 30, period_end=1e18, issued_at=_iss(), entry_id="gm2")
    p.grant("live", 200, period_end=1e18, issued_at=_iss(), entry_id="gl")          # live-only tenant
    p.debit("live", 10, period_end=1e18, engagement_id="e", issued_at=_iss(), entry_id="dl")
    core = {"signal": PLAN_GRANT_SIGNAL, "org_id": "seeded", "entry_id": "evil", "credits": 9999,
            "period_end": 1e18, "issued_at": 9_999.0}
    store.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(core, ATTACKER)})
    return k


_EXPECTED = {"seeded": 100, "mixed": 60, "live": 190}      # available per tenant (all tranches far-future-dated)


def _avail_map(reg, orgs):
    return {o: reg.available(o, now=1.0) for o in orgs if reg.available(o, now=1.0) > 0}


def test_two_prune_fold_of_fold_carries_plan():
    """build(seed=prior) across TWO prunes must carry tranche totals + seen-set forward == a single scan."""
    store = _store()
    p = _reg(store)
    p.grant("acme", 100, period_end=1e18, issued_at=_iss(), entry_id="g1")              # seq 0
    p.debit("acme", 30, period_end=1e18, engagement_id="e", issued_at=_iss(), entry_id="d1")  # seq 1
    k1 = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "m1"})  # seq 2
    p.grant("acme", 40, period_end=1e18, issued_at=_iss(), entry_id="g2")               # seq 3
    k2 = store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "m2"})  # seq 4

    recs = list(store.iter_records())
    snap1 = build([r for r in recs if r.seq < k1], trusted_pubkey=OWNER_PUB, base_seq=k1, snapshot_seq=k1 - 1)
    snap2 = build([r for r in recs if k1 <= r.seq < k2], trusted_pubkey=OWNER_PUB,
                  base_seq=k2, snapshot_seq=k2 - 1, seed=snap1)                         # fold-of-fold
    full = build([r for r in recs if r.seq < k2], trusted_pubkey=OWNER_PUB, base_seq=k2, snapshot_seq=k2 - 1)

    assert snap2.plan_granted_map() == full.plan_granted_map() == {("acme", 1e18): 140}
    assert snap2.plan_debited_map() == full.plan_debited_map() == {("acme", 1e18): 30}
    assert snap2.plan_seen_set() == full.plan_seen_set()
    assert (PLAN_GRANT_SIGNAL, "acme", "g1") in snap2.plan_seen_set()                   # carried across prune #2


def test_plan_empty_load_matches_known_correct():
    store = _store()
    _populate(store)
    assert SnapshotState.load(store).base_seq == 0
    assert _avail_map(_reg(store), ["seeded", "mixed", "live"]) == _EXPECTED
    assert _reg(store).available("seeded", now=1.0) == 100     # forged +9999 grant stayed inert


def test_split_fold_equals_full_scan_with_prefix_physically_absent(monkeypatch):
    store = _store()
    k = _populate(store)
    full = _avail_map(_reg(store), ["seeded", "mixed", "live"])
    assert full == _EXPECTED

    prefix = [r for r in store.iter_records() if r.seq < k]
    snap = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
    assert snap.plan_granted_map().get(("seeded", 1e18)) == 100
    assert snap.trusted_pubkey == OWNER_PUB

    pruned = PrunedView(store, k)
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    split = _avail_map(PlanCreditLedger(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB),
                       ["seeded", "mixed", "live"])
    assert split == full, f"plan fold != scan over a physically-pruned store\n full={full}\n split={split}"

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    split_neutered = _avail_map(PlanCreditLedger(pruned, owner_key=OWNER, trusted_pubkey=OWNER_PUB),
                                ["seeded", "mixed", "live"])
    assert split_neutered != full and "seeded" not in split_neutered


# ---- (d) check_prune_safe referential floor ----------------------------------------------------------
def _plan_segmented_store(tmp_path):
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    p = PlanCreditLedger(s, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    p.grant("acme", 6000, period_end=1e18, issued_at=1.0, entry_id="g1")                 # seq 0
    p.debit("acme", 25, period_end=1e18, engagement_id="e", issued_at=2.0, entry_id="d1")  # seq 1
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})             # seq 2..4
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


def test_check_prune_safe_allows_a_carried_plan(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _plan_segmented_store(tmp_path)
    archived = prune.check_prune_safe(s, 5)
    assert [seg.first_seq for seg in archived] == [0]
    assert prune.stranded_active_plan_tranches(s, archived, 5) == []
    below = []
    for seg in archived:
        below.extend(prune.read_segment_records(s._layout.seg_path(seg)))
    seed = build(below, trusted_pubkey=OWNER_PUB, base_seq=5, snapshot_seq=-1)
    assert seed.plan_granted_map().get(("acme", 1e18)) == 6000
    assert seed.plan_debited_map().get(("acme", 1e18)) == 25


def test_referential_floor_detects_a_seed_that_omits_a_plan_tranche(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _plan_segmented_store(tmp_path)
    real_build = prune.build

    def incomplete_build(records, **kw):
        seed = real_build(records, **kw)
        return seed.model_copy(update={
            "plan_granted": [r for r in seed.plan_granted if r[0] != "acme"],
            "plan_debited": [r for r in seed.plan_debited if r[0] != "acme"],
            "plan_seen": [r for r in seed.plan_seen if r[1] != "acme"],
        })

    monkeypatch.setattr(prune, "build", incomplete_build)
    assert prune.stranded_active_plan_tranches(s, _archived_below(s, 5), 5) == ["acme"]
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    msg = str(e.value).lower()
    assert "strand" in msg and "acme" in msg and "plan" in msg


def test_referential_floor_detects_a_dropped_plan_seen_key(tmp_path, monkeypatch):
    """Isolate the ANTI-REPLAY-DURABILITY branch of stranded_active_plan_tranches (`for (_sig,o,_e) in seen-ss`).
    Drop ONLY `plan_seen` for acme while KEEPING its granted/debited totals exact: the first loop (balance
    mismatch) then finds nothing, so ONLY the seen-set branch can flag acme. Mutation-killing: deleting that
    loop lets a prune drop the consumed entry_ids (re-opening plan-grant replay across a hard prune) UNDETECTED.
    """
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _plan_segmented_store(tmp_path)
    real_build = prune.build

    def seen_dropping_build(records, **kw):
        seed = real_build(records, **kw)
        return seed.model_copy(update={"plan_seen": [r for r in seed.plan_seen if r[1] != "acme"]})

    monkeypatch.setattr(prune, "build", seen_dropping_build)
    # balances are intact in the seed, so only the seen-set durability branch can detect the stranded tenant
    assert prune.stranded_active_plan_tranches(s, _archived_below(s, 5), 5) == ["acme"]
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "strand" in str(e.value).lower() and "acme" in str(e.value)


def test_check_prune_safe_reraises_a_nonempty_plan_floor_wiring_only(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OWNER_PUB)
    s = _plan_segmented_store(tmp_path)
    monkeypatch.setattr(prune, "stranded_active_plan_tranches", lambda store, archived, K: ["ghost-tenant"])
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "strand" in str(e.value).lower() and "ghost-tenant" in str(e.value)
