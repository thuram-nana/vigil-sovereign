"""SCALE-C1 — group commit on SpineStore: append_many writes N records under ONE lock + ONE fsync, chained in
list order, with the SAME seal/chain/record math as append() (they share _write_record_locked).

The per-record fsync under the write lock is the single-writer throughput bottleneck; these pin both the
CORRECTNESS (chain contiguity, verify(), equivalence to append) and the OPTIMISATION (one fsync per batch).
Sovereign leg: PYTHONPATH=apps/sigil:packages/core/vigil_core.
"""
from __future__ import annotations

import tempfile

from sigil.spine import store as store_mod
from sigil.spine.models import KINDS
from sigil.spine.store import SpineStore

_KIND = sorted(KINDS)[0]


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _spec(i):
    return {"kind": _KIND, "source": "gc", "actor": "test", "payload": {"i": i}}


def test_append_many_chains_in_order_and_verifies():
    s = _store()
    seqs = s.append_many([_spec(i) for i in range(5)])
    assert seqs == [0, 1, 2, 3, 4]
    recs = list(s.iter_records())
    assert [r.seq for r in recs] == [0, 1, 2, 3, 4]
    ok, reason = s.verify()
    assert ok, reason                                    # the hash-chain is contiguous + intact across the batch


def test_append_many_then_append_continues_the_same_chain():
    s = _store()
    s.append_many([_spec(i) for i in range(3)])
    nxt = s.append(kind=_KIND, source="gc", actor="test", payload={"i": 3})
    assert nxt == 3
    ok, reason = s.verify()
    assert ok, reason
    assert [r.seq for r in s.iter_records()] == [0, 1, 2, 3]   # the single append continued the batch's chain


def test_single_element_batch_is_chain_equivalent_to_append():
    # a 1-record append_many must produce the byte-identical record a single append() would (shared core)
    a = _store()
    sa = a.append(kind=_KIND, source="gc", actor="test", payload={"i": 7})
    b = _store()
    sb = b.append_many([{"kind": _KIND, "source": "gc", "actor": "test", "payload": {"i": 7}}])[0]
    assert sa == sb == 0
    ra = list(a.iter_records())[0]
    rb = list(b.iter_records())[0]
    # same seq/kind/source/actor + a verifying chain on both (ts differs, so compare the stable fields)
    assert (ra.seq, ra.kind, ra.source, ra.actor) == (rb.seq, rb.kind, rb.source, rb.actor)
    assert a.verify()[0] and b.verify()[0]


def test_empty_batch_is_a_noop():
    s = _store()
    assert s.append_many([]) == []
    assert list(s.iter_records()) == []


def test_append_many_fails_closed_on_an_unknown_kind_before_any_write():
    import pytest
    s = _store()
    s.append_many([_spec(0)])                            # one good record first (seq 0)
    with pytest.raises(store_mod.SpineError):
        s.append_many([_spec(1), {"kind": "definitely-not-a-real-kind", "source": "x",
                                  "actor": "x", "payload": {}}])
    # the whole batch was refused BEFORE any lock/byte — nothing from the bad batch landed (still just seq 0)
    assert [r.seq for r in s.iter_records()] == [0]
    assert s.verify()[0]


def test_append_many_uses_one_fsync_for_the_whole_batch(monkeypatch):
    # the group-commit property: N records cost ONE fsync, not N (the whole point of the batch API)
    calls = {"n": 0}
    real = store_mod.os.fsync

    def _count(fd):
        calls["n"] += 1
        return real(fd)
    monkeypatch.setattr(store_mod.os, "fsync", _count)

    s = _store()
    s.append_many([_spec(i) for i in range(4)])
    assert calls["n"] == 1, f"append_many([4]) must fsync ONCE, got {calls['n']}"

    # contrast: 4 single appends fsync 4 times (one per record) — proves the amortisation is real
    calls["n"] = 0
    t = _store()
    for i in range(4):
        t.append(kind=_KIND, source="gc", actor="test", payload={"i": i})
    assert calls["n"] == 4, f"4 single appends must fsync 4 times, got {calls['n']}"
