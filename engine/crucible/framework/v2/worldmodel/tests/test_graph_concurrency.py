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
lists and dicts instead of taking a C-level snapshot. Measured on the unlocked
index (CPython 3.13.14):

  1. read ‖ read   — two `all_edges()` iterate the shared `_dirty_out` set while
     one of them clears it: `RuntimeError: Set changed size during iteration`,
     120/120 trials at `switchinterval=1e-6`, and reachable at the DEFAULT 0.005
     once the dirty loop (4.27 ms at 6,000 buckets) outruns the 5 ms GIL quantum.
  2. read ‖ write  — a reader returns an UNSORTED list; worse, when `_normalize`
     clears the dirty flag over a bucket an append left unsorted, the wrong order
     is PERMANENT and SILENT (4/30 trials), and a later `remove_node` then
     bisects an unsorted list, fails to prune, and the next `all_nodes()` raises.
  3. write ‖ write/evict — `_discard_sorted`'s `bisect_left` + `del seq[i]` races
     `_append_key`'s `append`, `_node_ids` desyncs from `_nodes`, and
     `all_nodes()` raises `KeyError` (9/12 trials at 1e-6; 1/12 at the DEFAULT
     0.005, i.e. a crash on stock interpreter settings).

None of that is theoretical. `aegis.middleware.AegisWSGIMiddleware` holds ONE
`Aegis` — hence one `ActorGraph.world` — and calls `observe()` on EVERY request,
with no lock of its own, from a multi-threaded WSGI server; `aegis.detect_http`
is the same shape at the raw HTTP boundary. `aegis.integrate` then calls
`world.all_nodes()` on the verdict-projection path, which is where mode 3 lands
as a hard crash in the defensive data plane.

`WorldModel._lock` (one re-entrant lock, taken by every method that touches an
index) closes all three. These tests FAIL against the unlocked index and pass
deterministically with it — a lock either holds or it does not, so there is no
flake window to tune.
"""

from __future__ import annotations

import sys
import threading
from contextlib import contextmanager

from ..graph import WorldModel
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


def test_two_pure_readers_never_raise_and_never_disagree() -> None:
    """No writer at all: `_READERS` threads call `all_edges()` at once, on a graph
    whose every out bucket owes a sort. Unlocked this raises `RuntimeError: Set
    changed size during iteration` in 120/120 trials and completes only ~16% of
    the reads; locked, every reader returns the identical edge sequence."""
    with _fast_switching():
        w = _fanout_graph()
        for round_index in range(_READ_ROUNDS):
            _redirty(w)
            results: list[list[int]] = []

            def read() -> None:
                results.append([id(e) for e in w.all_edges()])

            failures = _run_together([read] * _READERS)
            assert not failures, (
                f"round {round_index}: concurrent pure readers raised {failures[:3]}")
            assert len(results) == _READERS
            assert all(r == results[0] for r in results), (
                f"round {round_index}: concurrent pure readers disagreed on edge order")
            # and against the serial answer taken once everything is quiesced
            assert [id(e) for e in w.all_edges()] == results[0]
        w._assert_index_consistent()


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
