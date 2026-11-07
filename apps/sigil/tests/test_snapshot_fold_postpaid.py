"""Prune-survival proof for the SnapshotState-seeded postpaid folds (PP-1): the account-mode LWW registry AND
the ADDITIVE arrears ledger (`governor/postpaid.py`).

Two properties, like subscription + wallet:
  * the ACCOUNT is a per-org LWW (enabled) with a per-org anti-replay high-water — both the state AND the
    high-water must survive a hard prune, or the first prune drops the line AND resets the high-water
    (re-opening replay of a disabled line via a captured `set_account`);
  * the ARREARS is a per-org additive balance (debits − reversals) with a consumed-entry_id seen-set — both the
    balance AND the seen-set must survive, or a prune would LOWER the drawn balance (letting a tenant draw past
    their line) and/or re-open accrual replay.

PHYSICAL-PRUNE HARNESS (identical to test_snapshot_fold_subscription.py): a `PrunedView` physically hides
`seq < K` from `iter_records`, so only the SEED can carry the pruned state.

MUTATION-VERIFIED intent: dropping the carried high-water re-opens account resurrection; dropping the carried
seen-set re-opens arrears double-count (the neutered controls below isolate each carry).

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:integration \
     .venv-sovereign/bin/python -m pytest apps/sigil/tests/test_snapshot_fold_postpaid.py -q
"""
import itertools
import tempfile

import pytest

from sigil.governor.postpaid import POSTPAID_DEBIT_SIGNAL, PostpaidArrearsLedger, PostpaidRegistry
from sigil.reuse import generate_keypair
from sigil.spine import prune
from sigil.spine.manifest import read_manifest
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64

_issue = itertools.count(1)


def _iss() -> float:
    return float(next(_issue))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store):
    return PostpaidRegistry(store, owner_key=OWNER, trusted_pubkey=OP)


def _arr(store):
    return PostpaidArrearsLedger(store, owner_key=OWNER, trusted_pubkey=OP)


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


# ---- (a) an ENABLED account whose only set_account is PHYSICALLY PRUNED survives via the seed ----------
def test_postpaid_account_survives_a_hard_prune(monkeypatch):
    store = _store()
    r = _reg(store)
    r.set_account("acme", 500, 30, issued_at=5.0)              # seq 0
    k = _marker(store)                                         # seq 1
    prefix = [rec for rec in store.iter_records() if rec.seq < k]
    snap = build(prefix, trusted_pubkey=OP, base_seq=k, snapshot_seq=k - 1)
    assert {row[0]: row[1] for row in snap.postpaid_state}.get("acme") is True
    assert {row[0]: row[1] for row in snap.postpaid_issued}.get("acme") == 5.0
    assert any(row[0] == "acme" and row[1] == 500 and row[2] == 30 for row in snap.postpaid_row)

    pruned = PrunedView(store, k)
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    r2 = PostpaidRegistry(pruned, owner_key=OWNER, trusted_pubkey=OP)
    assert r2.is_postpaid("acme") and r2.account("acme").credit_limit == 500

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: SnapshotState.empty()))
    assert PostpaidRegistry(pruned, owner_key=OWNER, trusted_pubkey=OP).account("acme") is None


# ---- (b) the per-org high-water survives (no replay resurrection of a disabled line) ------------------
def test_account_high_water_survives_no_replay_resurrection(monkeypatch):
    store = _store()
    r = _reg(store)
    seq = r.set_account("acme", 500, 30, issued_at=5.0)       # seq 0
    captured = store.get(seq).payload
    r.disable("acme")                                          # seq 1 (safe direction, on sight)
    k = _marker(store)                                         # seq 2
    prefix = [rec for rec in store.iter_records() if rec.seq < k]
    snap = build(prefix, trusted_pubkey=OP, base_seq=k, snapshot_seq=k - 1)
    assert {row[0]: row[1] for row in snap.postpaid_state}.get("acme") is False
    assert {row[0]: row[1] for row in snap.postpaid_issued}.get("acme") == 5.0   # the high-water that must cross

    store.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # seq 3: replay enable (live)
    pruned = PrunedView(store, k)

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    assert PostpaidRegistry(pruned, owner_key=OWNER, trusted_pubkey=OP).is_postpaid("acme") is False, \
        "a replayed pruned enable must NOT re-open a disabled line (seed high-water)"

    snap_no_hw = snap.model_copy(update={"postpaid_issued": []})
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap_no_hw))
    assert PostpaidRegistry(pruned, owner_key=OWNER, trusted_pubkey=OP).is_postpaid("acme") is True, \
        "dropping the high-water ⇒ the replayed enable resurrects the line (isolates the hw carry)"


# ---- (c) the arrears balance AND the seen-set survive a hard prune ------------------------------------
def test_arrears_balance_and_seen_survive_a_hard_prune(monkeypatch):
    store = _store()
    a = _arr(store)
    a.accrue("acme", 100, entry_id="r:1", issued_at=1.0)       # seq 0
    a.reverse("acme", 30, entry_id="s:1", issued_at=2.0)       # seq 1
    captured_debit = store.get(0).payload
    k = _marker(store)                                         # seq 2
    prefix = [rec for rec in store.iter_records() if rec.seq < k]
    snap = build(prefix, trusted_pubkey=OP, base_seq=k, snapshot_seq=k - 1)
    assert snap.postpaid_arrears_debited_map().get("acme") == 100
    assert snap.postpaid_arrears_credited_map().get("acme") == 30
    assert (POSTPAID_DEBIT_SIGNAL, "acme", "r:1") in snap.postpaid_arrears_seen_set()

    store.append(kind="event", source="governor", actor="WARDEN", payload=captured_debit)   # seq 3: replay (live)
    pruned = PrunedView(store, k)

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    assert PostpaidArrearsLedger(pruned, owner_key=OWNER, trusted_pubkey=OP).accrued("acme") == 70, \
        "balance carried + replayed pruned debit ignored (seen-set in seed)"

    snap_no_seen = snap.model_copy(update={"postpaid_arrears_seen": []})
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap_no_seen))
    assert PostpaidArrearsLedger(pruned, owner_key=OWNER, trusted_pubkey=OP).accrued("acme") == 170, \
        "dropping the seen-set ⇒ the replayed debit double-counts (isolates the seen-set carry)"


# ---- (c2) RED-PEN HIGH regression: the settle discriminator (was_accrued) is PRUNE-DURABLE -------------
def test_was_accrued_is_prune_durable(monkeypatch):
    # A hard prune can drop the individual reserve-postpaid debit record while the seed carries only the per-org
    # balance + seen-set. settle detects a postpaid reservation via was_accrued, which MUST read the SEEDED
    # seen-set (not a live scan) — else it reads False post-prune and settle mis-refunds the draw into the
    # prepaid wallet (the confirmed HIGH). The neutered control (seen stripped) reproduces that False.
    store = _store()
    a = _arr(store)
    eid = "reserve-postpaid:cust_x:n1"
    a.accrue("acme", 100, entry_id=eid, issued_at=1.0)        # seq 0 (the only spine record for the reservation)
    k = _marker(store)                                        # seq 1
    prefix = [rec for rec in store.iter_records() if rec.seq < k]
    snap = build(prefix, trusted_pubkey=OP, base_seq=k, snapshot_seq=k - 1)
    assert (POSTPAID_DEBIT_SIGNAL, "acme", eid) in snap.postpaid_arrears_seen_set()
    pruned = PrunedView(store, k)                             # the debit record (seq 0) is now physically hidden
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    assert PostpaidArrearsLedger(pruned, owner_key=OWNER, trusted_pubkey=OP).was_accrued("acme", eid) is True, \
        "the postpaid-settle discriminator must survive the prune via the seeded seen-set"
    snap_no_seen = snap.model_copy(update={"postpaid_arrears_seen": []})
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap_no_seen))
    assert PostpaidArrearsLedger(pruned, owner_key=OWNER, trusted_pubkey=OP).was_accrued("acme", eid) is False, \
        "isolates the seen-set carry: without it the discriminator reads False and settle would mis-refund"


# ---- (d) build() == scan over a mixed population ------------------------------------------------------
def test_postpaid_build_equals_scan_mixed():
    store = _store()
    r = _reg(store)
    a = _arr(store)
    r.set_account("a1", 500, 30, issued_at=1.0)                # enabled
    r.set_account("a2", 200, 15, issued_at=2.0)
    r.disable("a2")                                            # enabled-then-disabled (row retained)
    r.disable("ghost")                                         # bare disable, never opened (absent)
    a.accrue("a1", 100, entry_id="r:1", issued_at=3.0)
    a.accrue("a1", 50, entry_id="r:2", issued_at=4.0)
    a.reverse("a1", 20, entry_id="s:1", issued_at=5.0)
    a.accrue("a2", 10, entry_id="b:1", issued_at=6.0)

    scan = r._fold()
    scan_deb, scan_cred, scan_seen = a._fold()
    b = build(list(store.iter_records()), trusted_pubkey=OP, base_seq=0, snapshot_seq=-1)
    bstate = {row[0]: row[1] for row in b.postpaid_state}
    brow = {row[0]: [row[1], row[2]] for row in b.postpaid_row}

    assert bstate.get("a1") is True and brow.get("a1") == [500, 30]
    assert bstate.get("a2") is False and brow.get("a2") == [200, 15]
    assert bstate.get("ghost") is False and "ghost" not in brow
    assert scan.get("a1").credit_limit == 500 and scan.get("a1").enabled is True
    assert scan.get("a2").enabled is False and "ghost" not in scan
    # arrears build == scan, exactly
    assert b.postpaid_arrears_debited_map() == scan_deb
    assert b.postpaid_arrears_credited_map() == scan_cred
    assert b.postpaid_arrears_seen_set() == scan_seen
    assert a.accrued("a1") == 130 and a.accrued("a2") == 10


def _assert_acct_build_eq_scan(store, oid, expected_enabled):
    scan = _reg(store)._fold().get(oid)
    scan_enabled = scan.enabled if scan is not None else None
    built = {row[0]: row[1] for row in build(list(store.iter_records()), trusted_pubkey=OP,
                                             base_seq=0, snapshot_seq=-1).postpaid_state}
    assert scan_enabled == expected_enabled, f"scan enabled {scan_enabled!r} != {expected_enabled!r}"
    assert built.get(oid) == expected_enabled, f"build enabled {built.get(oid)!r} != {expected_enabled!r}"


def test_build_fold_mirrors_scan_account_webhook_freshness():
    # build()'s disable freshness gate must mirror PostpaidRegistry._fold() EXACTLY (build() == scan): a STALE
    # webhook close (issued_at < the open high-water) is ignored by BOTH; a FRESH one honored by BOTH; the
    # owner-manual 0.0 latch honored on sight by BOTH. A drift would bake a wrong enabled-state into a seed.
    store = _store()
    r = _reg(store)
    r.set_account("acme", 500, 30, issued_at=100.0)
    r.disable("acme", issued_at=50.0)        # STALE (< 100) -> ignored by both
    _assert_acct_build_eq_scan(store, "acme", True)
    r.disable("acme", issued_at=200.0)       # FRESH (> 100) -> honored by both
    _assert_acct_build_eq_scan(store, "acme", False)


# ---- (e) check_prune_safe referential floor ----------------------------------------------------------
def _pp_segmented_store(tmp_path):
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    r = PostpaidRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    a = PostpaidArrearsLedger(s, owner_key=OWNER, trusted_pubkey=OP)
    r.set_account("acme", 500, 30, issued_at=1.0)              # seq 0
    a.accrue("acme", 100, entry_id="r:1", issued_at=2.0)       # seq 1
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})    # seq 2..4
    s.rotate()                                                 # seal [0..5)
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})   # seq 5..9
    s.rotate()
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "tail"})
    return s


def _archived_below(store, K):
    return [seg for seg in read_manifest(store._layout).sealed_in_order()
            if seg.last_seq is not None and seg.last_seq < K]


def test_check_prune_safe_allows_carried_postpaid(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _pp_segmented_store(tmp_path)
    archived = prune.check_prune_safe(s, 5)
    assert [seg.first_seq for seg in archived] == [0]
    assert prune.stranded_active_postpaid(s, archived, 5) == []
    assert prune.stranded_postpaid_arrears(s, archived, 5) == []


def test_floor_detects_a_seed_that_omits_a_postpaid_account(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _pp_segmented_store(tmp_path)
    real_build = prune.build

    def incomplete_build(records, **kw):
        seed = real_build(records, **kw)
        return seed.model_copy(update={
            "postpaid_state": [r for r in seed.postpaid_state if r[0] != "acme"],
            "postpaid_issued": [r for r in seed.postpaid_issued if r[0] != "acme"],
            "postpaid_row": [r for r in seed.postpaid_row if r[0] != "acme"],
        })

    monkeypatch.setattr(prune, "build", incomplete_build)
    assert prune.stranded_active_postpaid(s, _archived_below(s, 5), 5) == ["acme"]
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    msg = str(e.value).lower()
    assert "strand" in msg and "acme" in msg and "postpaid" in msg


def test_floor_detects_a_seed_that_omits_postpaid_arrears(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _pp_segmented_store(tmp_path)
    real_build = prune.build

    def incomplete_build(records, **kw):
        seed = real_build(records, **kw)
        # drop ONLY the drawn balance (keep the seen-set) -> ISOLATES the balance-compare clause (the exact
        # "tenant draws past the line" corruption: a lowered drawn balance the seed fails to carry).
        return seed.model_copy(update={
            "postpaid_arrears_debited": [r for r in seed.postpaid_arrears_debited if r[0] != "acme"],
        })

    monkeypatch.setattr(prune, "build", incomplete_build)
    assert prune.stranded_postpaid_arrears(s, _archived_below(s, 5), 5) == ["acme"]
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "strand" in str(e.value).lower() and "acme" in str(e.value)


def test_floor_detects_a_seed_that_drops_only_the_arrears_seen_key(tmp_path, monkeypatch):
    # isolates the SEEN-set clause of stranded_postpaid_arrears (anti-replay durability): a seed that keeps the
    # balance but DROPS the consumed entry_id must still be flagged (a pruned debit re-appended above K would
    # re-accrue). Complements the balance-clause isolation above.
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _pp_segmented_store(tmp_path)
    real_build = prune.build

    def incomplete_build(records, **kw):
        seed = real_build(records, **kw)
        return seed.model_copy(update={
            "postpaid_arrears_seen": [r for r in seed.postpaid_arrears_seen if r[1] != "acme"],
        })

    monkeypatch.setattr(prune, "build", incomplete_build)
    assert prune.stranded_postpaid_arrears(s, _archived_below(s, 5), 5) == ["acme"]
    with pytest.raises(prune.PruneUnsafe):
        prune.check_prune_safe(s, 5)


def test_check_prune_safe_reraises_nonempty_postpaid_floor_wiring_only(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _pp_segmented_store(tmp_path)
    monkeypatch.setattr(prune, "stranded_active_postpaid", lambda store, archived, K: ["ghost-tenant"])
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "strand" in str(e.value).lower() and "ghost-tenant" in str(e.value)


# ---- (f) PP-2 in-flight reserve prune tripwire (red-pen MED) ------------------------------------------
def _reserve_store(tmp_path, *, settled: bool):
    """A segmented store with a postpaid RESERVE in the sealed [0..5) prefix. When `settled`, a matching settle
    credit lands in the LIVE tail, so the reserve is no longer in-flight (and is therefore prunable)."""
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    r = PostpaidRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    a = PostpaidArrearsLedger(s, owner_key=OWNER, trusted_pubkey=OP)
    r.set_account("acme", 500, 30, issued_at=1.0)                                              # seq 0
    a.accrue("acme", 100, engagement_id="acme", entry_id="reserve-postpaid:acme:n1", issued_at=2.0)  # seq 1 reserve
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})                   # seq 2..4
    s.rotate()                                                                                 # seal [0..5)
    # second segment [5..10): when `settled`, a matching settle lands here (seq >= K=5, so LIVE vs the pruned
    # prefix) — the reserve is then no longer in-flight; otherwise this slot is a pad and the reserve stays open.
    if settled:
        a.settle("acme", 40, entry_id="settle-postpaid:acme:n1", issued_at=3.0)                # seq 5 (live)
    else:
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})                  # seq 5 (pad)
    for _ in range(4):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})                  # seq 6..9
    s.rotate()                                                                                 # seal [5..10)
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "tail"})                  # seq 10..12 (active)
    return s


def test_prune_refuses_to_strand_an_in_flight_postpaid_reserve(tmp_path, monkeypatch):
    # RED-PEN MED (FOLD): an UNSETTLED reserve in the pruned prefix would be hidden from in_flight_reserved's live
    # scan -> net_settled inflates toward accrued -> the (possibly cancelled) in-flight launch is over-billed. The
    # tripwire fail-closed REFUSES the prune. (The aggregate arrears floor PERMITS it — it carries only balances.)
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _reserve_store(tmp_path, settled=False)
    archived = _archived_below(s, 5)
    assert prune.stranded_postpaid_arrears(s, archived, 5) == []          # the aggregate floor does NOT catch it
    assert prune.stranded_active_postpaid_reserves(s, archived, 5) == ["acme"]
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    msg = str(e.value).lower()
    assert "in-flight" in msg and "acme" in msg


def test_prune_allows_a_settled_postpaid_reserve(tmp_path, monkeypatch):
    # a reserve whose settle has landed (in the live tail) is NOT in-flight -> prunable (accrued is snapshot-seeded
    # and in_flight_reserved stays 0 even with the reserve pruned).
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _reserve_store(tmp_path, settled=True)
    archived = _archived_below(s, 5)
    assert prune.stranded_active_postpaid_reserves(s, archived, 5) == []
    assert prune.check_prune_safe(s, 5) == archived                       # the whole safety check passes


def test_check_prune_safe_reraises_nonempty_reserve_floor_wiring_only(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _pp_segmented_store(tmp_path)
    monkeypatch.setattr(prune, "stranded_active_postpaid_reserves", lambda store, archived, K: ["ghost-tenant"])
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "in-flight" in str(e.value).lower() and "ghost-tenant" in str(e.value)


# ---- (g) in_flight_reserved is prune-durable against a replayed settled reserve (EC-4 red-pen cross-finding) ----
def test_in_flight_reserved_is_prune_durable_against_a_replayed_settled_reserve(monkeypatch):
    # A FULLY SETTLED postpaid reserve (reserve debit + settle credit both below K) is prunable — the in-flight
    # tripwire allows it (the reserve is settled). If its reserve DEBIT is then replayed above K, in_flight_reserved
    # MUST still read 0: the settle was pruned (cannot pair live), so only the SNAPSHOT-SEEDED seen-set stops the
    # replay from resurrecting as a phantom in-flight draw — which would UNDER-count net_settled_consumed = accrued
    # - in_flight (an UNDER-BILL / revenue leak). The neutered control (seen stripped) reproduces the phantom. This
    # is the pattern-level finding the EC-4 cost-ledger red-pen surfaced in postpaid's mirror of _in_flight.
    store = _store()
    a = _arr(store)
    a.accrue("acme", 100, entry_id="reserve-postpaid:acme:n1", issued_at=1.0)  # seq 0 reserve (debit)
    a.settle("acme", 40, entry_id="settle-postpaid:acme:n1", issued_at=2.0)    # seq 1 settle (credit) -> fully settled
    captured_reserve = store.get(0).payload
    k = _marker(store)                                                         # seq 2
    prefix = [rec for rec in store.iter_records() if rec.seq < k]
    snap = build(prefix, trusted_pubkey=OP, base_seq=k, snapshot_seq=k - 1)
    assert (POSTPAID_DEBIT_SIGNAL, "acme", "reserve-postpaid:acme:n1") in snap.postpaid_arrears_seen_set()

    store.append(kind="event", source="governor", actor="WARDEN", payload=captured_reserve)  # seq 3: replay (live)
    pruned = PrunedView(store, k)                                             # reserve+settle (seq 0,1) now hidden

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    assert PostpaidArrearsLedger(pruned, owner_key=OWNER, trusted_pubkey=OP).in_flight_reserved("acme") == 0, \
        "a replayed already-settled+pruned reserve must NOT resurrect as a phantom in-flight draw (seeded seen-set)"

    snap_no_seen = snap.model_copy(update={"postpaid_arrears_seen": []})
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap_no_seen))
    assert PostpaidArrearsLedger(pruned, owner_key=OWNER, trusted_pubkey=OP).in_flight_reserved("acme") == 100, \
        "isolates the seed carry: without it the replayed reserve resurrects as 100 phantom in-flight credits"
