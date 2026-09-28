"""The COMMITTED harness behind every performance number in `graph.py`'s module
docstring. Not a test (no `test_` prefix, so pytest does not collect it) — a
re-runnable measurement, so the docstring cites numbers anyone can reproduce
instead of numbers someone once saw.

    PYTHONPATH=engine/crucible python3 -m framework.v2.worldmodel.tests.bench_graph
    ... --sizes 1000,10000 --repeat 3 --order asc,desc --heap
    ... --compare-rev 838e0b42          # vs the PRE-INDEX revision
    ... --compare-rev 8d8d8c30          # vs the UNLOCKED-index revision
    ... --mode operators                # the knowledge/operators consumer shape

Three things this file exists to prevent, each of which actually happened to
this docstring:

  * A speedup quoted against a DIFFERENT ANSWER. Every reader is asserted
    element-for-element identical to its pre-index body (by object identity)
    BEFORE it is timed.
  * A number with no harness. `--compare-rev` extracts an old `graph.py`
    straight out of git and measures against it, so the cross-revision claims
    (index vs pre-index, locked vs unlocked) are reproducible from one command
    rather than from a vanished scratch script.
  * A benchmark that only measures the FAVOURABLE case. `build()` used to
    insert ids ASCENDING only, which leaves the lazy-sort path essentially
    unexercised — measured on `build(500)`: 0 dirty node buckets, 0 dirty kind
    buckets, 0 dirty in/pair buckets, and 2 of 500 dirty out buckets. `--order
    desc` inserts descending so every bucket goes dirty and every read pays a
    sort, which is the worst case the docstring claims a bound for.

The reference implementations below are the pre-index bodies, copied verbatim
from the commit before the index (838e0b42). Timing the live reader against its
own predecessor on the SAME graph is the honest comparison, and it keeps working
after that commit ages out of easy reach.
"""

from __future__ import annotations

import argparse
import contextlib
import gc
import os
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path

from ..graph import WorldModel
from ..models import Edge, EdgeKind, Node, NodeKind

_NK = list(NodeKind)
_EK = list(EdgeKind)


# ---------------------------------------------------------------------------
# The pre-index reader bodies, verbatim from 838e0b42:worldmodel/graph.py.
# ---------------------------------------------------------------------------

def ref_all_nodes(w) -> list[Node]:
    return [w._nodes[k] for k in sorted(w._nodes)]


def ref_nodes_of_kind(w, kind) -> list[Node]:
    return [n for _, n in sorted(w._nodes.items()) if n.kind == kind]


def ref_all_edges(w) -> list[Edge]:
    out: list[Edge] = []
    for src in sorted(w._out):
        for dst in sorted(w._out[src]):
            for kv in sorted(w._out[src][dst]):
                out.append(w._out[src][dst][kv])
    return out


def ref_edges_of_kind(w, kind) -> list[Edge]:
    out: list[Edge] = []
    for src in sorted(w._out):
        for dst in sorted(w._out[src]):
            edge = w._out[src][dst].get(kind.value)
            if edge is not None:
                out.append(edge)
    return out


def ref_neighbors(w, node_id: str, *, incoming: bool = False) -> list[Edge]:
    adj = w._in if incoming else w._out
    buckets = adj.get(node_id, {})
    out: list[Edge] = []
    for other in sorted(buckets):
        for kv in sorted(buckets[other]):
            out.append(buckets[other][kv])
    return out


# ---------------------------------------------------------------------------
# Loading an old revision's WorldModel, for the cross-revision claims
# ---------------------------------------------------------------------------

_REL = "engine/crucible/framework/v2/worldmodel/graph.py"


@contextlib.contextmanager
def revision_world_model(rev: str):
    """Yield the `WorldModel` class from `graph.py` AT GIT REVISION `rev`.

    NO FILE IS WRITTEN. `graph.py` uses package-relative imports (`from .models
    import ...`), which resolve off the module's `__package__`, so the extracted
    source is exec'd into an in-memory module whose `__package__` is set to
    `framework.v2.worldmodel`. An earlier version wrote the source into the
    package directory, which meant a SIGKILL mid-run could strand a syntactically
    valid copy of an OLD `graph.py` inside the shipped package where `git add -A`
    would sweep it in — this cannot happen now, because there is nothing on disk
    to strand. `encoding='utf-8'` is explicit because `graph.py` contains
    non-ASCII (‖ — →) and the harness must not depend on the host locale.
    Only ever used by this benchmark, never at runtime."""
    import types

    repo = Path(__file__).resolve()
    while repo != repo.parent and not (repo / ".git").exists():
        repo = repo.parent
    src = subprocess.run(["git", "-C", str(repo), "show", f"{rev}:{_REL}"],
                         capture_output=True, text=True, encoding="utf-8",
                         check=True).stdout
    mod_name = f"_bench_rev_{abs(hash(rev)) % 10**8}"
    qualified = f"framework.v2.worldmodel.{mod_name}"
    mod = types.ModuleType(qualified)
    mod.__package__ = "framework.v2.worldmodel"   # makes `from .models import` resolve
    mod.__file__ = f"<git:{rev}:{_REL}>"
    sys.modules[qualified] = mod
    try:
        exec(compile(src, mod.__file__, "exec"), mod.__dict__)
        yield mod.WorldModel
    finally:
        sys.modules.pop(qualified, None)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _node(nid: str, kind: NodeKind) -> Node:
    return Node(id=nid, kind=kind, provenance="obs", confidence=0.5,
                first_seen=1, last_seen=1)


def _edge(src: str, dst: str, kind: EdgeKind) -> Edge:
    return Edge(src=src, dst=dst, kind=kind, provenance="obs-e",
                confidence=0.5, first_seen=1, last_seen=1)


def build(n: int, order: str = "asc", cls=None):
    """n nodes round-robin over every NodeKind, out-edges round-robin over every
    EdgeKind.

    order="asc"  — ids ASCEND, and each source's destinations are appended in
                   ascending order. The common real case (ids are generated in
                   order) and the one the lazy index is tuned for: almost nothing
                   ever goes dirty, so reads never pay a sort.
    order="desc" — ids DESCEND (nodes and sources). Every NODE-index and
                   per-source append breaks sortedness. Note this still leaves
                   the OUT-index (`_out_dsts`) essentially clean, because each
                   source's 3 dsts still arrive ascending — see `dstdesc`.
    order="dstdesc" — ids ascend, but each source fans out to a block of
                   destinations appended in DESCENDING id order, so every
                   `_out_dsts[src]` bucket goes dirty. This is the fixture that
                   actually exercises the lazy sort on the OUT path that
                   `all_edges`/`neighbors` read — the path the CONCURRENCY
                   section is about — which neither `asc` nor `desc` did.
    Every case's `dirty_profile` is printed with the sweep, so which paths a run
    exercised is never left to inference. The docstring's "never worse than
    pre-index" bound is about `desc`+`dstdesc` together (every index dirty)."""
    W = cls or WorldModel
    w = W()
    rng = range(n) if order != "desc" else range(n - 1, -1, -1)
    for i in rng:
        w.add_node(_node(f"n{i:07d}", _NK[i % len(_NK)]))
    if order == "dstdesc":
        # fan each source out to a block of dsts appended HIGH id first, so the
        # out bucket is unsorted-on-append and owes a sort on the next read
        for i in rng:
            for off in (53, 29, 11, 3):
                w.add_edge(_edge(f"n{i:07d}", f"n{(i + off) % n:07d}",
                                 _EK[(i + off) % len(_EK)]))
    else:
        for i in rng:
            for j in (1, 2, 3):
                w.add_edge(_edge(f"n{i:07d}", f"n{(i * 7 + j) % n:07d}",
                                 _EK[(i + j) % len(_EK)]))
    return w


def dirty_profile(w) -> str:
    """How much of the lazy-sort path a fixture actually exercises. Printed with
    every sweep, so a favourable fixture cannot be mistaken for a general one."""
    if not hasattr(w, "_dirty_out"):
        return "n/a (pre-index revision has no dirty sets)"
    return (f"dirty nodes={len(w._dirty_nodes)} kinds={len(w._dirty_kinds)} "
            f"out={len(w._dirty_out)}/{len(w._out_dsts)} "
            f"in={len(w._dirty_in)}/{len(w._in_srcs)} "
            f"pairs={len(w._dirty_pairs)}/{len(w._kind_pairs)}")


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


def _cases(w, probe):
    return {
        "all_nodes":     (w.all_nodes,                     lambda: ref_all_nodes(w)),
        "nodes_of_kind": (lambda: w.nodes_of_kind(_NK[0]), lambda: ref_nodes_of_kind(w, _NK[0])),
        "all_edges":     (w.all_edges,                     lambda: ref_all_edges(w)),
        "edges_of_kind": (lambda: w.edges_of_kind(_EK[0]), lambda: ref_edges_of_kind(w, _EK[0])),
        "neighbors":     (lambda: [e for i in probe for e in w.neighbors(i)],
                          lambda: [e for i in probe for e in ref_neighbors(w, i)]),
    }


# ---------------------------------------------------------------------------

def measure(n: int, reps: int, order: str) -> dict[str, tuple[float, float]]:
    """Each live reader vs its pre-index body, on one graph."""
    w = build(n, order)
    probe = [f"n{i:07d}" for i in range(0, n, max(1, n // 200))]
    out: dict[str, tuple[float, float]] = {}
    for name, (live, ref) in _cases(w, probe).items():
        got, want = live(), ref()
        if not _same(got, want):
            raise AssertionError(
                f"{name}: the indexed reader does NOT return the pre-index result "
                f"(len {len(got)} vs {len(want)}) — a speedup here would be meaningless")
        out[name] = (_time(ref, reps), _time(live, reps))
    return out


def measure_revision(n: int, reps: int, order: str, cls) -> dict[str, float]:
    """Absolute reader timings for ONE WorldModel class (possibly an old
    revision's), so two revisions can be compared directly rather than each
    against the in-file reference."""
    w = build(n, order, cls=cls)
    probe = [f"n{i:07d}" for i in range(0, n, max(1, n // 200))]
    return {name: _time(live, reps) for name, (live, _) in _cases(w, probe).items()}


def construction(n: int, order: str, cls=None) -> float:
    gc.collect()
    t0 = time.perf_counter()
    build(n, order, cls=cls)
    return time.perf_counter() - t0


def heap(n: int, order: str = "asc") -> int:
    """Bytes allocated while building the graph and taking one full read of it.

    Precisely: the sum of `tracemalloc` `size_diff` across all files between a
    snapshot taken before `build()` and one taken after `build()` +
    `all_nodes()` + `all_edges()`. That is NOT "the graph alone" — it includes
    the two reader result lists and whatever pydantic allocates on the way — so
    treat the ABSOLUTE figure as an upper bound. The revision-to-revision DELTA
    is the meaningful output, and it is valid because both revisions run the
    identical workload."""
    gc.collect()
    tracemalloc.start()
    before = tracemalloc.take_snapshot()
    w = build(n, order)
    w.all_nodes()
    w.all_edges()
    gc.collect()
    after = tracemalloc.take_snapshot()
    total = sum(s.size_diff for s in after.compare_to(before, "filename"))
    tracemalloc.stop()
    del w
    return total


def operators_shape(n: int, reps: int, cls=None) -> tuple[float, int]:
    """The `knowledge/operators` consumer shape: the REAL `saturate()` run to a
    fixpoint over a pre-built world (operators.py:352-356 is `for op in ops: for
    node in world.all_nodes()`, with `nodes_of_kind` inside the per-node
    predicate match, mutating the graph as it goes).

    This exists because the docstring twice claimed a large speedup for this
    shape from a harness nobody committed. Measure it; do not assert it."""
    from ...knowledge.catalog import CATALOG
    from ...knowledge.catalog_ext import EXTENDED_CATALOG
    from ...knowledge.operators import saturate

    ops = [*CATALOG, *EXTENDED_CATALOG]
    attacker = "attacker"
    # every role an operator effect can reference, so none aborts with
    # OperatorError once the synthetic graph is large enough to match it
    seeds = {op.id: {"actor": attacker, "resource": "n0000001", "app": "n0000002"}
             for op in ops}
    best, applied_n = None, 0
    for r in range(reps):
        w = build(n, "asc", cls=cls)            # fresh: saturate mutates to a fixpoint
        w.add_node(_node(attacker, NodeKind.PRINCIPAL))
        gc.collect()
        t0 = time.perf_counter()
        applied = saturate(ops, w, seq_start=10_000 + r * 100_000, seeds=seeds)
        dt = time.perf_counter() - t0
        best = dt if best is None else min(best, dt)
        applied_n = len(applied)
    return best, applied_n


# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sizes", default="1000,10000")
    ap.add_argument("--order", default="asc",
                    help="asc, desc, or asc,desc (see build())")
    ap.add_argument("--repeat", type=int, default=1,
                    help="repeat the sweep; the BEST (least noisy) run is reported")
    ap.add_argument("--heap", action="store_true", help="also measure heap (slow)")
    ap.add_argument("--compare-rev", default=None, metavar="REV",
                    help="also measure git revision REV's graph.py and report "
                         "current/REV, for the cross-revision claims")
    ap.add_argument("--mode", default="readers", choices=("readers", "operators"))
    args = ap.parse_args(argv)
    sizes = [int(s) for s in args.sizes.split(",") if s.strip()]
    orders = [o.strip() for o in args.order.split(",") if o.strip()]

    print(f"python {sys.version.split()[0]}  pid {os.getpid()}  "
          f"switchinterval {sys.getswitchinterval()}")

    if args.mode == "operators":
        for n in sizes:
            t, applied = operators_shape(n, max(3, args.repeat))
            line = f"N={n:>6}  saturate() {t * 1e3:>9.3f} ms   ({applied} facts applied)"
            if args.compare_rev:
                with revision_world_model(args.compare_rev) as RevWM:
                    rt, _ = operators_shape(n, max(3, args.repeat), cls=RevWM)
                line += f"   vs {args.compare_rev}: {rt * 1e3:>9.3f} ms  -> {rt / t:>5.2f}x"
            print(line)
        return 0

    for order in orders:
        print(f"\n=== fixture order={order} ===")
        print(f"{'N':>7}  {'reader':14s} {'pre-index(ms)':>14} {'indexed(ms)':>12} {'speedup':>9}")
        best: dict[str, float] = {}
        worst: dict[str, float] = {}
        for n in sizes:
            reps = max(3, min(60, 200_000 // n))
            runs = [measure(n, reps, order) for _ in range(args.repeat)]
            for name in runs[0]:
                ref_t = min(r[name][0] for r in runs)
                live_t = min(r[name][1] for r in runs)
                sp = ref_t / live_t
                best[name] = max(best.get(name, 0.0), sp)
                worst[name] = min(worst.get(name, 1e9), sp)
                print(f"{n:>7}  {name:14s} {ref_t * 1e3:>14.4f} {live_t * 1e3:>12.4f} {sp:>8.1f}x")
            c = min(construction(n, order) for _ in range(args.repeat))
            print(f"{n:>7}  {'CONSTRUCT':14s} {'':>14} {c * 1e3:>12.1f} {'(indexed)':>9}")
            print(f"{n:>7}  {'fixture':14s} {dirty_profile(build(n, order))}")
            if args.heap:
                print(f"{n:>7}  {'HEAP':14s} {'':>14} {heap(n, order) / 1048576:>12.4f} {'MB':>9}")

            if args.compare_rev:
                with revision_world_model(args.compare_rev) as RevWM:
                    rc = min(construction(n, order, cls=RevWM) for _ in range(args.repeat))
                    rruns = [measure_revision(n, reps, order, RevWM) for _ in range(args.repeat)]
                cruns = [measure_revision(n, reps, order, None) for _ in range(args.repeat)]
                print(f"{n:>7}  -- vs {args.compare_rev} (current/rev; >1 means current is SLOWER) --")
                for name in sorted(rruns[0]):
                    rv = min(r[name] for r in rruns)
                    cv = min(r[name] for r in cruns)
                    print(f"{n:>7}  {name:14s} {rv * 1e3:>14.4f} {cv * 1e3:>12.4f} {cv / rv:>8.2f}x")
                print(f"{n:>7}  {'CONSTRUCT':14s} {rc * 1e3:>14.1f} {c * 1e3:>12.1f} {c / rc:>8.2f}x")

        print(f"\nmeasured read-speedup envelope (order={order}, this host):")
        for name in sorted(best):
            print(f"  {name:14s} {worst[name]:5.1f}x .. {best[name]:5.1f}x")
        print(f"  OVERALL        {min(worst.values()):5.1f}x .. {max(best.values()):5.1f}x")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
