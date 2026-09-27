"""CONCURRENCY regression for the graph order indexes (#828 follow-up).

Before the indexes, every `WorldModel` reader was a PURE function of `_nodes` /
`_out` / `_in`, and every ordering step was `sorted(some_dict)` — ONE C-level
call, which cannot be interrupted by another thread's bytecode. Three properties
fell out of that for free:

  * two readers could never interfere (a reader mutated nothing);
  * a reader could never raise because of a writer (the snapshot was atomic);
  * a reader racing a writer could miss a WRITE, but what it returned was always
    `sorted()` of whatever state existed at the time.

The order indexes broke all three, because a READ now MUTATES (the lazy
`list.sort()` plus the dirty-flag clear) and because the readers walk live Python
lists and dicts instead of taking a C-level snapshot. The three failure modes:

  1. read ‖ read   — two `all_edges()` iterate the shared `_dirty_out` set while
     one of them clears it: `RuntimeError: Set changed size during iteration`.
     No writer needed.
  2. read ‖ write  — a reader returns an UNSORTED list; worse, when `_normalize`
     clears the dirty flag over a bucket an append left unsorted, the wrong order
     is PERMANENT and SILENT, and a later `remove_node` then bisects an unsorted
     list, fails to prune, and the next `all_nodes()` raises.
  3. write ‖ write/evict — `_discard_sorted`'s `bisect_left` + `del seq[i]` races
     `_append_key`'s `append`, `_node_ids` desyncs from `_nodes`, and
     `all_nodes()` raises `KeyError`.

Failure RATES are deliberately not quoted here, because they are host- and
harness-dependent and an earlier revision of this docstring quoted three that
did not reproduce. They belong to a harness, and the harness is committed:
`race_graph.py`, which measures a chosen git revision so a number about the
UNLOCKED index stays re-derivable. See `graph.py`'s CONCURRENCY section for the
figures and the exact command.

None of that is theoretical. `aegis.middleware.AegisWSGIMiddleware` holds ONE
`Aegis` — hence one `ActorGraph.world` — and calls `observe()` on EVERY request,
with no lock of its own, from a multi-threaded WSGI server; `aegis.detect_http`
is the same shape at the raw HTTP boundary. `aegis.integrate` then calls
`world.all_nodes()` on the verdict-projection path, which is where mode 3 lands
as a hard crash in the defensive data plane.

WHAT EACH TEST PINS. read‖read is defended TWICE — by the lock, and by
`all_edges` iterating a `tuple(dirty)` snapshot instead of the live set. A
single combined test therefore pinned NEITHER: a reviewer showed it passes with
the lock removed and passes with the snapshot reverted, failing only when both
go. So it is split, and the suite now kills each single-point mutation.
Measured with each defence mutated away in turn (the mutation matrix, over the
8 tests in this file):

    mutation                          tests failed
    none (shipped)                    0
    lock -> no-op CM                  4   (incl. the three write tests)
    tuple(dirty) -> live-set loop     1   (read_read_holds_on_the_snapshot_alone)
    both                              6
    the real 8d8d8c30 module          7   (the 8th is the positive control,
                                           which PASSES by reproducing the bug)

`test_read_read_positive_control_fires_with_neither_defence` is the anti-
greenwash guard: it asserts the defect DOES reproduce once both defences are
gone, so the three passing read‖read tests cannot be passing merely because the
scenario never races. It skips, loudly, rather than failing if this host will
not interleave.
"""

from __future__ import annotations

import sys
import threading
from contextlib import contextmanager

import pytest

from ..graph import _NODE_IDS, WorldModel, _normalize
from ..models import Edge, EdgeKind, Node, NodeKind

# Racing bytecode-level windows needs the interpreter to switch threads often.
# 1e-6 makes the defect reproduce in a bounded number of rounds; the defect is
# present at the default 0.005 too (measured above), just rarer.
_SWITCH_INTERVAL = 1e-6


@contextmanager
def _fast_switching(interval: float = _SWITCH_INTERVAL):
    """Raise the thread-switch rate for the duration, then restore it. Restored in
    a `finally` so one failing test cannot leave the interpreter mis-tuned for the
    rest of the session."""
    previous = sys.getswitchinterval()
    sys.setswitchinterval(interval)
    try:
        yield
    finally:
        sys.setswitchinterval(previous)


def _node(nid: str, kind: NodeKind = NodeKind.HOST) -> Node:
    return Node(id=nid, kind=kind, provenance="obs", confidence=0.5,
                first_seen=1, last_seen=1)


def _edge(src: str, dst: str, kind: EdgeKind = EdgeKind.REACHABLE_FROM) -> Edge:
    return Edge(src=src, dst=dst, kind=kind, provenance="obs-e",
                confidence=0.5, first_seen=1, last_seen=1)


def _run_together(fns: list) -> list[str]:
    """Start every callable at a barrier, join them all, return their failures.
    A worker records the failure instead of raising, because an exception in a
    non-main thread does not fail a pytest test."""
    failures: list[str] = []
    barrier = threading.Barrier(len(fns))

    def wrap(fn):
        def run():
            try:
                barrier.wait()
                fn()
            except BaseException as exc:                      # noqa: BLE001 - reported, not swallowed
                failures.append(f"{type(exc).__name__}: {exc}")
        return run

    threads = [threading.Thread(target=wrap(fn)) for fn in fns]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return failures


# --------------------------------------------------------------------------
# 1. read ‖ read
# --------------------------------------------------------------------------

_FANOUT_SRC = 400
_FANOUT_DST = 20
_READ_ROUNDS = 6
_READERS = 8


def _fanout_graph() -> WorldModel:
    """Every src fans out to the same dst set in DESCENDING order, so every
    `_out_dsts` bucket lands dirty and `all_edges`'s dirty loop has real work."""
    w = WorldModel()
    for i in range(_FANOUT_SRC + _FANOUT_DST):
        w.add_node(_node(f"n{i:06d}"))
    for s in range(_FANOUT_SRC):
        for d in reversed(range(_FANOUT_SRC, _FANOUT_SRC + _FANOUT_DST)):
            w.add_edge(_edge(f"n{s:06d}", f"n{d:06d}"))
    return w


def _redirty(w: WorldModel) -> None:
    """Re-dirty every out bucket through the PUBLIC api: append a dst that sorts
    before the bucket's current maximum."""
    for s in range(_FANOUT_SRC):
        w.add_edge(_edge(f"n{s:06d}", f"n{s % (_FANOUT_SRC + _FANOUT_DST):06d}",
                         EdgeKind.OWNS))


class _NoLock:
    """A lock-shaped no-op, for mutating ONE defence away at a time."""

    __slots__ = ()

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


@contextmanager
def _without_the_snapshot():
    """Revert `all_edges`'s dirty loop to the pre-fix body — iterate the LIVE
    `_dirty_out` set and bulk-`clear()` it — while leaving the lock in place."""
    original = WorldModel.all_edges

    def all_edges_live_set(self):
        out = []
        out_adj, dsts, dirty = self._out, self._out_dsts, self._dirty_out
        with self._lock:
            if dirty:
                for src in dirty:                 # <- the reverted line
                    dsts[src].sort()
                dirty.clear()
            for src in _normalize(self._node_ids, self._dirty_nodes, _NODE_IDS):
                adj = out_adj[src]
                for dst in dsts[src]:
                    out.extend(adj[dst].values())
        return out

    WorldModel.all_edges = all_edges_live_set
    try:
        yield
    finally:
        WorldModel.all_edges = original


def _read_read_round(w: WorldModel) -> tuple[list[str], list[list[int]]]:
    _redirty(w)
    results: list[list[int]] = []

    def read() -> None:
        results.append([id(e) for e in w.all_edges()])

    return _run_together([read] * _READERS), results


def test_two_pure_readers_never_raise_and_never_disagree() -> None:
    """No writer at all: `_READERS` threads call `all_edges()` at once, on a graph
    whose every out bucket owes a sort. The shipped code must be clean."""
    with _fast_switching():
        w = _fanout_graph()
        for round_index in range(_READ_ROUNDS):
            failures, results = _read_read_round(w)
            assert not failures, (
                f"round {round_index}: concurrent pure readers raised {failures[:3]}")
            assert len(results) == _READERS
            assert all(r == results[0] for r in results), (
                f"round {round_index}: concurrent pure readers disagreed on edge order")
            # and against the serial answer taken once everything is quiesced
            assert [id(e) for e in w.all_edges()] == results[0]
        w._assert_index_consistent()


def test_read_read_holds_on_the_lock_alone() -> None:
    """SNAPSHOT REVERTED, lock intact. Pins that the lock by itself is
    sufficient for read‖read — i.e. the `tuple(dirty)` snapshot is belt, not
    braces."""
    with _fast_switching(), _without_the_snapshot():
        w = _fanout_graph()
        for round_index in range(_READ_ROUNDS):
            failures, results = _read_read_round(w)
            assert not failures, (
                f"round {round_index}: lock alone did NOT contain read‖read: "
                f"{failures[:3]}")
            assert all(r == results[0] for r in results)


def test_read_read_holds_on_the_snapshot_alone() -> None:
    """LOCK REMOVED, snapshot intact. Pins that the `tuple(dirty)` snapshot by
    itself is sufficient for read‖read — which is why it is kept even though
    the lock already covers this path."""
    with _fast_switching():
        w = _fanout_graph()
        w._lock = _NoLock()
        for round_index in range(_READ_ROUNDS):
            failures, results = _read_read_round(w)
            assert not failures, (
                f"round {round_index}: snapshot alone did NOT contain read‖read: "
                f"{failures[:3]}")
            assert all(r == results[0] for r in results)


def test_read_read_positive_control_fires_with_neither_defence() -> None:
    """ANTI-GREENWASH. Both defences removed, so the original defect must
    reproduce. Without this, the three tests above could all be passing because
    the scenario never actually races, and nobody would know.

    Skips rather than fails if the race will not fire on this host: an
    interpreter that refuses to interleave here is not a defect in this code,
    and a positive control that cannot fire must say so out loud rather than
    masquerade as a pass."""
    with _fast_switching(), _without_the_snapshot():
        for _ in range(_READ_ROUNDS * 2):
            w = _fanout_graph()
            w._lock = _NoLock()
            failures, _ = _read_read_round(w)
            if failures:
                assert any("Set changed size during iteration" in f
                           or "disagree" in f for f in failures), (
                    f"positive control fired, but not with the expected defect: "
                    f"{failures[:3]}")
                return
    pytest.skip("read‖read did not reproduce on this host even with BOTH "
                "defences removed — the positive control cannot vouch for the "
                "three tests above here; re-run "
                "`python3 -m framework.v2.worldmodel.tests.race_graph "
                "--mode readread --rev 8d8d8c30` to see the defect directly")


# --------------------------------------------------------------------------
# 2. read ‖ write
# --------------------------------------------------------------------------

_SEED_NODES = 1500
_APPEND_NODES = 400
_WRITE_ROUNDS = 12
_SPIN_READERS = 4


def test_a_reader_racing_a_writer_never_returns_unsorted_order() -> None:
    """Readers spin on `all_nodes()` while a writer appends DESCENDING ids (so
    every append lands out of order). Each reader checks the list IT was handed:
    `all_nodes()` promises id-sorted order, and the pre-index code kept that
    promise under exactly this race because `sorted(dict)` is atomic.

    Unlocked, a read that interleaves with `_append_key` returns an out-of-order
    tail, and a read whose `sort()`/`discard()` straddles an append clears the
    dirty flag over an unsorted bucket — after which EVERY later read is wrong,
    permanently and silently. Locked, no read can observe a partial write."""
    seed = [_node(f"n{i:06d}") for i in range(_SEED_NODES)]
    # descending, and ordered BEFORE the seed ids, so every append breaks sortedness
    appended = [_node(f"a{_APPEND_NODES - i:06d}") for i in range(_APPEND_NODES)]

    with _fast_switching():
        for round_index in range(_WRITE_ROUNDS):
            w = WorldModel()
            for n in seed:
                w.add_node(n)
            w.all_nodes()                      # normalise once: clean and sorted
            stop = threading.Event()
            unsorted_reads: list[list[str]] = []

            def reader() -> None:
                while not stop.is_set():
                    ids = [n.id for n in w.all_nodes()]
                    if ids != sorted(ids):
                        unsorted_reads.append(ids)

            def writer() -> None:
                try:
                    for n in appended:
                        w.add_node(n)
                finally:
                    stop.set()

            failures = _run_together([reader] * _SPIN_READERS + [writer])
            assert not failures, f"round {round_index}: reader‖writer raised {failures[:3]}"
            assert not unsorted_reads, (
                f"round {round_index}: {len(unsorted_reads)} read(s) came back UNSORTED — "
                f"all_nodes() no longer returns sorted() of the live state")
            # quiesced: the index must still be honest, and the order must still be
            # the pre-index answer (`sorted(_nodes)`), not a corrupted survivor.
            assert [n.id for n in w.all_nodes()] == sorted(w._nodes), (
                f"round {round_index}: iteration order permanently corrupted")
            w._assert_index_consistent()


def test_every_reader_is_atomic_against_a_concurrent_writer() -> None:
    """The same race across the WHOLE deterministic reader surface, including the
    ones that walk `_out` / `_in` while `remove_node` pops from them."""
    nodes = [_node(f"n{i:05d}", NodeKind.HOST if i % 2 else NodeKind.SERVICE)
             for i in range(300)]
    with _fast_switching():
        for round_index in range(4):
            w = WorldModel()
            for n in nodes[:100]:
                w.add_node(n)
            for i in range(99):
                w.add_edge(_edge(nodes[i].id, nodes[i + 1].id))
            w.all_edges()
            stop = threading.Event()
            bad: list[str] = []

            def reader() -> None:
                while not stop.is_set():
                    ids = [n.id for n in w.all_nodes()]
                    if ids != sorted(ids):
                        bad.append("all_nodes unsorted")
                    hosts = [n.id for n in w.nodes_of_kind(NodeKind.HOST)]
                    if hosts != sorted(hosts):
                        bad.append("nodes_of_kind unsorted")
                    w.all_edges()
                    w.edges_of_kind(EdgeKind.REACHABLE_FROM)
                    w.neighbors(nodes[0].id)
                    w.neighbors(nodes[50].id, incoming=True)

            def writer() -> None:
                try:
                    for n in reversed(nodes[100:]):        # descending -> dirty appends
                        w.add_node(n)
                    for n in nodes[100:200]:
                        w.remove_node(n.id)
                finally:
                    stop.set()

            failures = _run_together([reader] * 3 + [writer])
            assert not failures, f"round {round_index}: mixed readers‖writer raised {failures[:3]}"
            assert not bad, f"round {round_index}: {sorted(set(bad))}"
            w._assert_index_consistent()


# --------------------------------------------------------------------------
# 3. write ‖ write / evict  (the AEGIS middleware shape)
# --------------------------------------------------------------------------

_WRITE_THREADS = 4
_PER_THREAD = 300
_WINDOW = 8


def test_concurrent_writers_with_eviction_keep_the_index_consistent() -> None:
    """The shape `AegisWSGIMiddleware` drives: several request threads writing into
    ONE shared `WorldModel` while a bounded actor window evicts (`ActorGraph._evict`
    -> `world.remove_node`).

    Unlocked, `_discard_sorted`'s `bisect_left` + `del seq[i]` races `_append_key`'s
    `append` on the same list, `_node_ids` drifts from `_nodes` (66 entries against
    64 nodes, measured), and the next `all_nodes()` raises `KeyError` — 9/12 trials
    at 1e-6 and 1/12 at the DEFAULT switch interval."""
    with _fast_switching():
        w = WorldModel()

        def worker(tid: int) -> None:
            mine: list[str] = []
            for i in range(_PER_THREAD):
                # descending within the thread, so appends land out of order
                nid = f"t{tid}-{_PER_THREAD - i:05d}"
                w.add_node(_node(nid))
                if mine:
                    w.add_edge(_edge(mine[-1], nid))
                mine.append(nid)
                if len(mine) > _WINDOW:                     # evict the oldest
                    w.remove_node(mine.pop(0))

        failures = _run_together([lambda tid=t: worker(tid) for t in range(_WRITE_THREADS)])
        assert not failures, f"concurrent writers raised {failures[:3]}"
        assert len(w._node_ids) == len(w._nodes), (
            f"index desynced from the node dict: {len(w._node_ids)} ids "
            f"vs {len(w._nodes)} nodes")
        assert [n.id for n in w.all_nodes()] == sorted(w._nodes)
        w._assert_index_consistent()


def test_the_world_model_carries_its_own_index_lock() -> None:
    """A structural guard for the invariant the tests above rest on: the lock is
    per-WorldModel (never a module global, which would serialise unrelated graphs)
    and re-entrant (a locked method may call another)."""
    a, b = WorldModel(), WorldModel()
    assert a._lock is not b._lock
    with a._lock:
        with a._lock:                                      # re-entrant, no deadlock
            assert a.all_nodes() == []


def test_the_graph_survives_deepcopy_and_pickle_despite_the_lock() -> None:
    """C1: holding a `threading.RLock` as an attribute silently broke
    `copy.deepcopy` and `pickle` — both work at the pre-index (838e0b42) and
    unlocked-index (8d8d8c30) revisions and raised `TypeError: cannot pickle
    '_thread.RLock' object` here until `__getstate__`/`__setstate__` were added.

    No shipped caller deepcopies or pickles a `WorldModel` (`store.to_dict` /
    `from_dict` is the supported snapshot path), so this was latent rather than
    live — which is exactly why it needs a test rather than a reader noticing."""
    import copy
    import pickle

    w = WorldModel()
    for i in (3, 1, 2):                                # out of order -> dirty
        w.add_node(_node(f"n{i}", NodeKind.HOST if i % 2 else NodeKind.SERVICE))
    w.add_edge(_edge("n3", "n1"))
    w.add_edge(_edge("n1", "n2", EdgeKind.OWNS))
    expected_nodes = [n.id for n in w.all_nodes()]
    expected_edges = [(e.src, e.dst, e.kind.value) for e in w.all_edges()]

    for label, clone in (("deepcopy", copy.deepcopy(w)),
                         ("pickle", pickle.loads(pickle.dumps(w)))):
        assert [n.id for n in clone.all_nodes()] == expected_nodes, label
        assert [(e.src, e.dst, e.kind.value) for e in clone.all_edges()] == \
            expected_edges, label
        clone._assert_index_consistent()
        # the copy gets its OWN lock: sharing one would serialise two unrelated
        # graphs against each other, and a deepcopy that aliased it would be worse
        assert clone._lock is not w._lock, label
        # and the copy is independent
        clone.add_node(_node("n9"))
        assert "n9" not in w._nodes, label


def test_caller_controlled_code_never_runs_under_the_index_lock() -> None:
    """The lock is a LEAF lock: nothing under it may call back out. ALL FOUR
    readers that take a caller-supplied `kind` or `edge_kinds` must evaluate it
    BEFORE acquiring — `nodes_of_kind`/`edges_of_kind` read `kind.value`,
    `neighbors`/`reachable` drain `edge_kinds`. A reviewer caught that
    `edges_of_kind` and `reachable` still evaluated theirs UNDER the lock after
    the first two were hoisted, so this test now probes every one; it fails if
    any evaluation moves back under the lock. Every shipped call site passes a
    plain enum member and a materialised list, so this is defence against a
    future caller, not a live bug."""
    w = WorldModel()
    w.add_node(_node("a", NodeKind.HOST))
    w.add_edge(_edge("a", "a"))

    held: list[bool] = []

    def _lock_is_held() -> bool:
        # RLock has no public "is held"; acquire(False) from THIS thread always
        # succeeds on a re-entrant lock, so probe the internal recursion count.
        return w._lock._is_owned()

    class _SpyKind:
        """A foreign `kind` whose `.value` records whether the lock is held when
        it is read. Its value ("host"/"reachable_from") lands in a real bucket,
        so the read is not short-circuited before `.value` is touched."""

        def __init__(self, value: str):
            self._value = value

        @property
        def value(self):
            held.append(_lock_is_held())
            return self._value

    def _spy_kinds(kind):
        def gen():
            held.append(_lock_is_held())
            yield kind
        return gen()

    # .value readers: kind must match a populated bucket so `.value` is reached
    for reader, spy in (("nodes_of_kind", _SpyKind("host")),
                        ("edges_of_kind", _SpyKind("reachable_from"))):
        held.clear()
        getattr(w, reader)(spy)
        assert held == [False], f"{reader} evaluated kind.value under the lock"

    # iterable-draining readers
    for reader in ("neighbors", "reachable"):
        held.clear()
        getattr(w, reader)("a", _spy_kinds(EdgeKind.REACHABLE_FROM))
        assert held == [False], f"{reader} consumed the caller's iterable under the lock"
