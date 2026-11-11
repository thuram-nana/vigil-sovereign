"""Prune-survival proof for the SnapshotState-seeded cost-envelope fold (EC-4): the ADDITIVE per-tenant
token-cost ledger (`governor/cost_ledger.py`).

One property, like the postpaid arrears ledger: the cost ledger is a per-org additive pair of totals
(reserved envelope + settled actual) with a consumed-entry_id seen-set — ALL THREE must survive a hard prune, or
a prune would silently LOWER a tenant's committed real cost (corrupting the per-tenant margin record), zero its
reserved envelope, and/or drop the anti-replay seen-set (re-opening reserve/settle replay — a pruned record
re-appended above K would double-count a tenant's cost).

PHYSICAL-PRUNE HARNESS (identical to test_snapshot_fold_postpaid.py): a `PrunedView` physically hides
`seq < K` from `iter_records`, so only the SEED can carry the pruned state.

MUTATION-VERIFIED intent: dropping the carried totals re-opens cost-zeroing; dropping the carried seen-set
re-opens cost double-count (the neutered controls below isolate each carry).

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:integration \
     .venv-sovereign/bin/python -m pytest apps/sigil/tests/test_snapshot_fold_cost_ledger.py -q
"""
import itertools
import tempfile

import pytest

from sigil.governor.authn import signed_payload
from sigil.governor.cost_ledger import COST_RESERVE_SIGNAL, COST_SETTLE_SIGNAL, CostEnvelopeLedger
from sigil.reuse import generate_keypair
from sigil.spine import prune
from sigil.spine.manifest import read_manifest
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()

_issue = itertools.count(1)


def _iss() -> float:
    return float(next(_issue))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _led(store):
    return CostEnvelopeLedger(store, owner_key=OWNER, trusted_pubkey=OP)


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


def _marker(store):
    return store.append(kind="event", source="governor", actor="WARDEN", payload={"signal": "marker"})


# ---- (c) the reserved/settled totals AND the seen-set survive a hard prune ----------------------------
def test_cost_totals_and_seen_survive_a_hard_prune(monkeypatch):
    store = _store()
    L = _led(store)
    L.reserve("acme", 1000, entry_id="reserve-cost:acme:n1", issued_at=1.0)   # seq 0
    L.settle("acme", 700, entry_id="settle-cost:acme:n1", issued_at=2.0)      # seq 1
    captured_reserve = store.get(0).payload
    k = _marker(store)                                                        # seq 2
    prefix = [rec for rec in store.iter_records() if rec.seq < k]
    snap = build(prefix, trusted_pubkey=OP, base_seq=k, snapshot_seq=k - 1)
    assert snap.cost_reserved_map().get("acme") == 1000
    assert snap.cost_settled_map().get("acme") == 700
    assert (COST_RESERVE_SIGNAL, "acme", "reserve-cost:acme:n1") in snap.cost_seen_set()

    store.append(kind="event", source="governor", actor="WARDEN", payload=captured_reserve)  # seq 3: replay (live)
    pruned = PrunedView(store, k)

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    led2 = CostEnvelopeLedger(pruned, owner_key=OWNER, trusted_pubkey=OP)
    assert led2.committed_cost("acme") == 700, "settled carried across the prune"
    assert led2.reserved_total("acme") == 1000, \
        "reserved total carried + replayed pruned reserve ignored (seen-set in seed)"

    snap_no_seen = snap.model_copy(update={"cost_seen": []})
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap_no_seen))
    assert CostEnvelopeLedger(pruned, owner_key=OWNER, trusted_pubkey=OP).reserved_total("acme") == 2000, \
        "dropping the seen-set ⇒ the replayed reserve double-counts (isolates the seen-set carry)"


# ---- (c2) the settle discriminator (was_reserved) is PRUNE-DURABLE -----------------------------------
def test_was_reserved_is_prune_durable(monkeypatch):
    # A hard prune can drop the individual cost_reserve record while the seed carries only the per-org totals +
    # seen-set. The settle seam binds a settle to a real reserve via was_reserved, which MUST read the SEEDED
    # seen-set (not a live scan) — else it reads False post-prune and a legitimate settle looks un-reserved.
    store = _store()
    L = _led(store)
    eid = "reserve-cost:cust_x:n1"
    L.reserve("acme", 1000, entry_id=eid, issued_at=1.0)                      # seq 0 (only record for the reserve)
    k = _marker(store)                                                        # seq 1
    prefix = [rec for rec in store.iter_records() if rec.seq < k]
    snap = build(prefix, trusted_pubkey=OP, base_seq=k, snapshot_seq=k - 1)
    assert (COST_RESERVE_SIGNAL, "acme", eid) in snap.cost_seen_set()
    pruned = PrunedView(store, k)                                             # the reserve (seq 0) now hidden
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    assert CostEnvelopeLedger(pruned, owner_key=OWNER, trusted_pubkey=OP).was_reserved("acme", eid) is True, \
        "the cost-settle discriminator must survive the prune via the seeded seen-set"
    snap_no_seen = snap.model_copy(update={"cost_seen": []})
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap_no_seen))
    assert CostEnvelopeLedger(pruned, owner_key=OWNER, trusted_pubkey=OP).was_reserved("acme", eid) is False, \
        "isolates the seen-set carry: without it the discriminator reads False"


# ---- (c3) RED-PEN MED: in_flight_envelope is prune-durable against a replayed settled reserve ---------
def test_in_flight_is_prune_durable_against_a_replayed_settled_reserve(monkeypatch):
    # A FULLY SETTLED launch (reserve+settle both below K) is prunable — stranded_active_cost_reserves allows it
    # because the reserve is settled. If its reserve record is then replayed above K, in_flight_envelope MUST still
    # read 0: the settle was pruned (cannot pair live), so only the seeded seen-set stops the replay from
    # resurrecting as a PHANTOM pending pool draw. _in_flight seeds its seen-set from the snapshot exactly as
    # _fold; the neutered control (seen stripped) reproduces the phantom (the confirmed red-pen MED).
    store = _store()
    L = _led(store)
    L.reserve("acme", 1000, entry_id="reserve-cost:acme:n1", issued_at=1.0)   # seq 0
    L.settle("acme", 300, entry_id="settle-cost:acme:n1", issued_at=2.0)      # seq 1 (fully settled)
    captured_reserve = store.get(0).payload
    k = _marker(store)                                                        # seq 2
    prefix = [rec for rec in store.iter_records() if rec.seq < k]
    snap = build(prefix, trusted_pubkey=OP, base_seq=k, snapshot_seq=k - 1)
    assert (COST_RESERVE_SIGNAL, "acme", "reserve-cost:acme:n1") in snap.cost_seen_set()

    store.append(kind="event", source="governor", actor="WARDEN", payload=captured_reserve)  # seq 3: replay (live)
    pruned = PrunedView(store, k)                                             # reserve+settle (seq 0,1) now hidden

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    assert CostEnvelopeLedger(pruned, owner_key=OWNER, trusted_pubkey=OP).in_flight_envelope("acme") == 0, \
        "a replayed already-settled+pruned reserve must NOT resurrect as a phantom in-flight draw (seeded seen-set)"

    snap_no_seen = snap.model_copy(update={"cost_seen": []})
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap_no_seen))
    assert CostEnvelopeLedger(pruned, owner_key=OWNER, trusted_pubkey=OP).in_flight_envelope("acme") == 1000, \
        "isolates the seed carry: without it the replayed reserve resurrects as 1000 phantom in-flight tokens"


# ---- (d) build() == scan over a mixed population -----------------------------------------------------
def test_cost_build_equals_scan_mixed():
    store = _store()
    L = _led(store)
    L.reserve("a1", 1000, entry_id="reserve-cost:a1:n1", issued_at=1.0)
    L.settle("a1", 700, entry_id="settle-cost:a1:n1", reserved_cap=1000, issued_at=2.0)
    L.reserve("a1", 500, entry_id="reserve-cost:a1:n2", issued_at=3.0)        # in-flight (no settle)
    L.reserve("a2", 2000, entry_id="reserve-cost:a2:n1", issued_at=4.0)
    L.settle("a2", 2500, entry_id="settle-cost:a2:n1", reserved_cap=2000, issued_at=5.0)  # over-report -> clamp 2000

    scan_reserved, scan_settled, scan_seen = L._fold()
    b = build(list(store.iter_records()), trusted_pubkey=OP, base_seq=0, snapshot_seq=-1)
    assert b.cost_reserved_map() == scan_reserved
    assert b.cost_settled_map() == scan_settled
    assert b.cost_seen_set() == scan_seen
    assert L.committed_cost("a1") == 700 and L.committed_cost("a2") == 2000   # a2 settle clamped to the reserve
    assert L.in_flight_envelope("a1") == 500 and L.in_flight_envelope("a2") == 0
    assert L.reserved_total("a1") == 1500 and L.reserved_total("a2") == 2000


# ---- (d2) build()'s OWN fold guards (independent of the ledger fold — build==scan only tests clean data) ----
def test_build_fold_rejects_a_forged_cost_record():
    # build() is a SEPARATE fold from CostEnvelopeLedger._fold; a forged (attacker-signed) record must be inert in
    # the SEED path too, or a hard prune would bake a forged tenant cost into the snapshot. Isolates build()'s
    # verify_signed(p, clcore, vpk) guard.
    store = _store()
    L = _led(store)
    L.reserve("acme", 1000, entry_id="reserve-cost:acme:n1", issued_at=1.0)
    forged = {"signal": COST_RESERVE_SIGNAL, "org_id": "acme", "entry_id": "reserve-cost:acme:forge",
              "tokens": 999999, "engagement_id": "", "issued_at": 2.0}
    store.append(kind="event", source="governor", actor="WARDEN", payload={**signed_payload(forged, ATTACKER)})
    b = build(list(store.iter_records()), trusted_pubkey=OP, base_seq=0, snapshot_seq=-1)
    assert b.cost_reserved_map().get("acme") == 1000, "the forged reserve must be inert in the build seed"
    assert (COST_RESERVE_SIGNAL, "acme", "reserve-cost:acme:forge") not in b.cost_seen_set()


def test_build_fold_is_idempotent_on_a_replay():
    # a verbatim replay inside the folded window is counted ONCE by build() (its `clkey not in cl_seen` guard), or a
    # snapshot would double-count a tenant's cost. Isolates build()'s idempotency guard.
    store = _store()
    L = _led(store)
    seq = L.reserve("acme", 1000, entry_id="reserve-cost:acme:n1", issued_at=1.0)
    captured = store.get(seq).payload
    store.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # verbatim replay
    b = build(list(store.iter_records()), trusted_pubkey=OP, base_seq=0, snapshot_seq=-1)
    assert b.cost_reserved_map().get("acme") == 1000, "build() must count a replayed reserve once"


# ---- (e) check_prune_safe referential floor ----------------------------------------------------------
def _cl_segmented_store(tmp_path):
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    L = CostEnvelopeLedger(s, owner_key=OWNER, trusted_pubkey=OP)
    L.reserve("acme", 1000, entry_id="reserve-cost:acme:n1", issued_at=1.0)   # seq 0
    L.settle("acme", 700, entry_id="settle-cost:acme:n1", issued_at=2.0)      # seq 1 (settled -> not in-flight)
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})  # seq 2..4
    s.rotate()                                                                # seal [0..5)
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})  # seq 5..9
    s.rotate()
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "tail"})
    return s


def _archived_below(store, K):
    return [seg for seg in read_manifest(store._layout).sealed_in_order()
            if seg.last_seq is not None and seg.last_seq < K]


def test_check_prune_safe_allows_carried_cost_ledger(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _cl_segmented_store(tmp_path)
    archived = prune.check_prune_safe(s, 5)
    assert [seg.first_seq for seg in archived] == [0]
    assert prune.stranded_cost_ledger(s, archived, 5) == []
    assert prune.stranded_active_cost_reserves(s, archived, 5) == []


def test_floor_detects_a_seed_that_omits_cost_totals(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _cl_segmented_store(tmp_path)
    real_build = prune.build

    def incomplete_build(records, **kw):
        seed = real_build(records, **kw)
        # drop ONLY the settled total (keep the seen-set) -> ISOLATES the committed-cost compare clause (the exact
        # "tenant's attributed cost zeroed" corruption: a lowered settled total the seed fails to carry).
        return seed.model_copy(update={
            "cost_settled": [r for r in seed.cost_settled if r[0] != "acme"],
        })

    monkeypatch.setattr(prune, "build", incomplete_build)
    assert prune.stranded_cost_ledger(s, _archived_below(s, 5), 5) == ["acme"]
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    msg = str(e.value).lower()
    assert "strand" in msg and "acme" in msg and "cost" in msg


def test_floor_detects_a_seed_that_drops_only_the_cost_seen_key(tmp_path, monkeypatch):
    # isolates the SEEN-set clause of stranded_cost_ledger (anti-replay durability): a seed that keeps the totals
    # but DROPS the consumed entry_id must still be flagged (a pruned record re-appended above K would re-count).
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _cl_segmented_store(tmp_path)
    real_build = prune.build

    def incomplete_build(records, **kw):
        seed = real_build(records, **kw)
        return seed.model_copy(update={
            "cost_seen": [r for r in seed.cost_seen if r[1] != "acme"],
        })

    monkeypatch.setattr(prune, "build", incomplete_build)
    assert prune.stranded_cost_ledger(s, _archived_below(s, 5), 5) == ["acme"]
    with pytest.raises(prune.PruneUnsafe):
        prune.check_prune_safe(s, 5)


def test_check_prune_safe_reraises_nonempty_cost_floor_wiring_only(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _cl_segmented_store(tmp_path)
    monkeypatch.setattr(prune, "stranded_cost_ledger", lambda store, archived, K: ["ghost-tenant"])
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "strand" in str(e.value).lower() and "ghost-tenant" in str(e.value)


# ---- (f) in-flight cost reserve prune tripwire -------------------------------------------------------
def _reserve_store(tmp_path, *, settled: bool):
    """A segmented store with a cost RESERVE in the sealed [0..5) prefix. When `settled`, a matching settle record
    lands in the LIVE tail, so the reserve is no longer in-flight (and is therefore prunable)."""
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    L = CostEnvelopeLedger(s, owner_key=OWNER, trusted_pubkey=OP)
    L.reserve("acme", 1000, entry_id="reserve-cost:acme:n1", issued_at=1.0)   # seq 0 reserve
    for _ in range(4):
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})  # seq 1..4
    s.rotate()                                                                # seal [0..5)
    # second segment [5..10): when `settled`, the matching settle lands here (seq >= K=5, LIVE vs the pruned
    # prefix) — the reserve is then no longer in-flight; otherwise this slot is a pad and the reserve stays open.
    if settled:
        L.settle("acme", 700, entry_id="settle-cost:acme:n1", issued_at=3.0)  # seq 5 (live)
    else:
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})  # seq 5 (pad)
    for _ in range(4):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})  # seq 6..9
    s.rotate()                                                                # seal [5..10)
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "tail"})  # seq 10..12 (active)
    return s


def test_prune_refuses_to_strand_an_in_flight_cost_reserve(tmp_path, monkeypatch):
    # an UNSETTLED reserve in the pruned prefix would be hidden from in_flight_envelope's live scan -> the pending
    # pool draw silently vanishes (EC-5 pool meter under-counts). The tripwire fail-closed REFUSES the prune. (The
    # aggregate cost-ledger floor PERMITS it — it carries only per-org totals + the seen-set, which the reserve's
    # record still satisfies.)
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _reserve_store(tmp_path, settled=False)
    archived = _archived_below(s, 5)
    assert prune.stranded_cost_ledger(s, archived, 5) == []                   # the aggregate floor does NOT catch it
    assert prune.stranded_active_cost_reserves(s, archived, 5) == ["acme"]
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    msg = str(e.value).lower()
    assert "in-flight" in msg and "acme" in msg


def test_prune_allows_a_settled_cost_reserve(tmp_path, monkeypatch):
    # a reserve whose settle has landed (in the live tail) is NOT in-flight -> prunable (committed cost is
    # snapshot-seeded and in_flight_envelope stays 0 even with the reserve pruned).
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _reserve_store(tmp_path, settled=True)
    archived = _archived_below(s, 5)
    assert prune.stranded_active_cost_reserves(s, archived, 5) == []
    assert prune.check_prune_safe(s, 5) == archived                           # the whole safety check passes


def test_check_prune_safe_reraises_nonempty_cost_reserve_floor_wiring_only(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _cl_segmented_store(tmp_path)
    monkeypatch.setattr(prune, "stranded_active_cost_reserves", lambda store, archived, K: ["ghost-tenant"])
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "in-flight" in str(e.value).lower() and "ghost-tenant" in str(e.value)
