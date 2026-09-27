"""The COMMITTED harness behind the performance numbers in `graph.py`'s module
docstring. Not a test (no `test_` prefix, so pytest does not collect it) — a
re-runnable measurement, so the docstring cites a number anyone can reproduce
instead of a number someone once saw.

    PYTHONPATH=engine/crucible python3 -m framework.v2.worldmodel.tests.bench_graph
    ... --sizes 1000,5000,20000 --repeat 3

Why the reference implementations live HERE rather than being diffed against an
old commit: the claim the docstring makes is "the index is faster than
re-`sorted()`-ing on every call", and the functions below ARE the pre-index
bodies, copied verbatim from the commit before the index (`838e0b42`). Timing
the live reader against its own predecessor on the SAME graph is both the
honest comparison and one that keeps working after that commit ages out.

Each reference is also ASSERTED equal to the live reader before it is timed, so
this file doubles as an order-identity check: a speedup over a reference that
returns something different would be meaningless.
"""

from __future__ import annotations

import argparse
import gc
import time
import tracemalloc

from ..graph import WorldModel
from ..models import Edge, EdgeKind, Node, NodeKind

_NK = list(NodeKind)
_EK = list(EdgeKind)


# ---------------------------------------------------------------------------
# The pre-index reader bodies, verbatim from 838e0b42:worldmodel/graph.py.
# ---------------------------------------------------------------------------

def ref_all_nodes(w: WorldModel) -> list[Node]:
    return [w._nodes[k] for k in sorted(w._nodes)]


def ref_nodes_of_kind(w: WorldModel, kind) -> list[Node]:
    return [n for _, n in sorted(w._nodes.items()) if n.kind == kind]


def ref_all_edges(w: WorldModel) -> list[Edge]:
    out: list[Edge] = []
    for src in sorted(w._out):
        for dst in sorted(w._out[src]):
            for kv in sorted(w._out[src][dst]):
                out.append(w._out[src][dst][kv])
    return out


def ref_edges_of_kind(w: WorldModel, kind) -> list[Edge]:
    out: list[Edge] = []
    for src in sorted(w._out):
        for dst in sorted(w._out[src]):
            edge = w._out[src][dst].get(kind.value)
            if edge is not None:
                out.append(edge)
    return out


def ref_neighbors(w: WorldModel, node_id: str, *, incoming: bool = False) -> list[Edge]:
    adj = w._in if incoming else w._out
    buckets = adj.get(node_id, {})
    out: list[Edge] = []
    for other in sorted(buckets):
        for kv in sorted(buckets[other]):
            out.append(buckets[other][kv])
    return out


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _node(nid: str, kind: NodeKind) -> Node:
    return Node(id=nid, kind=kind, provenance="obs", confidence=0.5,
                first_seen=1, last_seen=1)


def _edge(src: str, dst: str, kind: EdgeKind) -> Edge:
    return Edge(src=src, dst=dst, kind=kind, provenance="obs-e",
                confidence=0.5, first_seen=1, last_seen=1)


def build(n: int) -> WorldModel:
    """n nodes round-robin over every NodeKind, 3 out-edges each round-robin
    over every EdgeKind. Ids ASCEND, which is the common real case (ids are
    generated in order) and therefore the case the lazy index is tuned for."""
    w = WorldModel()
    for i in range(n):
        w.add_node(_node(f"n{i:07d}", _NK[i % len(_NK)]))
    for i in range(n):
        for j in (1, 2, 3):
            w.add_edge(_edge(f"n{i:07d}", f"n{(i * 7 + j) % n:07d}", _EK[(i + j) % len(_EK)]))
    return w


def _time(fn, reps: int) -> float:
    gc.collect()
    t0 = time.perf_counter()
    for _ in range(reps):
        fn()
    return (time.perf_counter() - t0) / reps


def _same(a: list, b: list) -> bool:
    """Object identity, position by position — not just equality, so a reader
    that rebuilt an equal list would still be caught."""
    return len(a) == len(b) and all(x is y for x, y in zip(a, b))


# ---------------------------------------------------------------------------

def measure(n: int, reps: int) -> dict[str, tuple[float, float]]:
    w = build(n)
    probe = [f"n{i:07d}" for i in range(0, n, max(1, n // 200))]
    cases = {
        "all_nodes":     (w.all_nodes,                      lambda: ref_all_nodes(w)),
        "nodes_of_kind": (lambda: w.nodes_of_kind(_NK[0]),  lambda: ref_nodes_of_kind(w, _NK[0])),
        "all_edges":     (w.all_edges,                      lambda: ref_all_edges(w)),
        "edges_of_kind": (lambda: w.edges_of_kind(_EK[0]),  lambda: ref_edges_of_kind(w, _EK[0])),
        "neighbors":     (lambda: [e for i in probe for e in w.neighbors(i)],
                          lambda: [e for i in probe for e in ref_neighbors(w, i)]),
    }
    out: dict[str, tuple[float, float]] = {}
    for name, (live, ref) in cases.items():
        got, want = live(), ref()
        if not _same(got, want):
            raise AssertionError(
                f"{name}: the indexed reader does NOT return the pre-index result "
                f"(len {len(got)} vs {len(want)}) — a speedup here would be meaningless")
        out[name] = (_time(ref, reps), _time(live, reps))
    return out


def construction(n: int) -> float:
    gc.collect()
    t0 = time.perf_counter()
    build(n)
    return time.perf_counter() - t0


def heap(n: int) -> int:
    """Heap held by the graph alone, via tracemalloc — the memory axis the
    docstring used to omit."""
    gc.collect()
    tracemalloc.start()
    before = tracemalloc.take_snapshot()
    w = build(n)
    w.all_nodes()
    w.all_edges()
    gc.collect()
    after = tracemalloc.take_snapshot()
    total = sum(s.size_diff for s in after.compare_to(before, "filename"))
    tracemalloc.stop()
    del w
    return total


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sizes", default="1000,5000,20000")
    ap.add_argument("--repeat", type=int, default=1,
                    help="repeat the whole sweep; report the BEST (least noisy) run")
    ap.add_argument("--heap", action="store_true", help="also measure heap (slow)")
    args = ap.parse_args(argv)
    sizes = [int(s) for s in args.sizes.split(",") if s.strip()]

    print(f"{'N':>7}  {'reader':14s} {'pre-index(ms)':>14} {'indexed(ms)':>12} {'speedup':>9}")
    best: dict[str, float] = {}
    worst: dict[str, float] = {}
    for n in sizes:
        reps = max(3, min(60, 200_000 // n))
        runs = [measure(n, reps) for _ in range(args.repeat)]
        for name in runs[0]:
            ref_t = min(r[name][0] for r in runs)
            live_t = min(r[name][1] for r in runs)
            sp = ref_t / live_t
            best[name] = max(best.get(name, 0.0), sp)
            worst[name] = min(worst.get(name, 1e9), sp)
            print(f"{n:>7}  {name:14s} {ref_t * 1e3:>14.4f} {live_t * 1e3:>12.4f} {sp:>8.1f}x")
        c = min(construction(n) for _ in range(args.repeat))
        print(f"{n:>7}  {'CONSTRUCT':14s} {'':>14} {c * 1e3:>12.1f} {'(indexed)':>9}")
        if args.heap:
            h = heap(n)
            print(f"{n:>7}  {'HEAP':14s} {'':>14} {h / 1048576:>12.4f} {'MB':>9}")

    print("\nmeasured read-speedup envelope (this host, this fixture):")
    for name in sorted(best):
        print(f"  {name:14s} {worst[name]:5.1f}x .. {best[name]:5.1f}x")
    print(f"  OVERALL        {min(worst.values()):5.1f}x .. {max(best.values()):5.1f}x")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
