"""The COMMITTED harness behind every CONCURRENCY number in `graph.py`'s module
docstring. Not a test (no `test_` prefix, so pytest does not collect it) — a
race lab, so a failure rate quoted for the unlocked index can be re-derived
instead of taken on trust.

    PYTHONPATH=engine/crucible python3 -m framework.v2.worldmodel.tests.race_graph \
        --mode readread --rev 8d8d8c30 --switchinterval 0.005 --trials 15
    ... --mode readwrite   --rev 8d8d8c30 --switchinterval 1e-6
    ... --mode aegis       --rev 8d8d8c30            # the shipped middleware shape
    ... --mode dirtyloop   --rev 8d8d8c30            # why read||read needs a big graph
    ... --mode all         --rev 8d8d8c30            # everything, both intervals

`--rev` measures the `graph.py` at a git revision instead of the current tree,
which is the only way to keep a number about the UNLOCKED index reproducible now
that the tree is locked. With no `--rev` it measures the current tree, which
should report 0 failures everywhere.

WHY THE THRESHOLDS ARE HOST-DEPENDENT, and why this file prints the mechanism
rather than a magic constant: read||read needs a second reader to be scheduled
*inside* `all_edges`'s dirty loop, which at the DEFAULT switch interval means
the loop must run longer than the 5 ms GIL quantum. `--mode dirtyloop` times
that loop directly. On the machine this docstring was written on it crosses 5 ms
between 3,000 and 7,500 dirty buckets; on a faster machine a reviewer measured
4.84 ms at 7,500 (i.e. still under, so 0/15 there) and 14.74 ms at 20,000. Both
observations are the same rule. Quote the rule, not the bucket count.
"""

from __future__ import annotations

import argparse
import contextlib
import sys
import threading
import time

from .bench_graph import revision_world_model
from ..graph import WorldModel as CurrentWorldModel
from ..models import Edge, EdgeKind, Node, NodeKind

DEFAULT_INTERVAL = 0.005
FAST_INTERVAL = 1e-6


def _node(nid: str, kind: NodeKind = NodeKind.HOST) -> Node:
    return Node(id=nid, kind=kind, provenance="obs", confidence=0.5,
                first_seen=1, last_seen=1)


def _edge(src: str, dst: str, kind: EdgeKind = EdgeKind.REACHABLE_FROM) -> Edge:
    return Edge(src=src, dst=dst, kind=kind, provenance="obs-e",
                confidence=0.5, first_seen=1, last_seen=1)


@contextlib.contextmanager
def _switching(interval: float):
    prev = sys.getswitchinterval()
    sys.setswitchinterval(interval)
    try:
        yield
    finally:
        sys.setswitchinterval(prev)


def _run(fns) -> list[str]:
    """Start every callable at a barrier, join, return failures as strings."""
    failures: list[str] = []
    barrier = threading.Barrier(len(fns))

    def wrap(fn):
        def run():
            try:
                barrier.wait()
                fn()
            except BaseException as exc:                 # noqa: BLE001 - reported
                failures.append(f"{type(exc).__name__}: {exc}")
        return run

    threads = [threading.Thread(target=wrap(f)) for f in fns]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return failures


# ---------------------------------------------------------------------------
# 1. read || read  — two pure readers, NO writer
# ---------------------------------------------------------------------------

def _fanout(WM, src: int, dst: int = 20):
    w = WM()
    for i in range(src + dst):
        w.add_node(_node(f"n{i:06d}"))
    for s in range(src):
        for d in reversed(range(src, src + dst)):        # descending -> all dirty
            w.add_edge(_edge(f"n{s:06d}", f"n{d:06d}"))
    return w


def _redirty(w, src: int, dst: int = 20):
    for s in range(src):
        w.add_edge(_edge(f"n{s:06d}", f"n{s % (src + dst):06d}", EdgeKind.OWNS))


def readread(WM, trials: int, readers: int = 8, buckets: int = 7500) -> list[str]:
    out = []
    for t in range(trials):
        w = _fanout(WM, buckets)
        _redirty(w, buckets)
        results: list[list[int]] = []

        def read():
            results.append([id(e) for e in w.all_edges()])

        failures = _run([read] * readers)
        if failures:
            out.append(f"trial {t}: {failures[0]} ({len(results)}/{readers} completed)")
        elif any(r != results[0] for r in results):
            out.append(f"trial {t}: readers DISAGREED on edge order")
    return out


def dirtyloop(WM, _trials: int) -> list[str]:
    """Not a race — the MECHANISM. Times `all_edges`'s dirty loop against the
    GIL quantum, which is what decides whether read||read is reachable at the
    default switch interval on a given host."""
    quantum_ms = DEFAULT_INTERVAL * 1e3
    print(f"  GIL quantum (default switchinterval) = {quantum_ms:.3f} ms")
    for buckets in (3000, 7500, 12000, 20000):
        w = _fanout(WM, buckets)
        w.all_edges()
        _redirty(w, buckets)
        if not hasattr(w, "_dirty_out"):
            print("  (pre-index revision has no dirty loop)")
            return []
        dirty, dsts = w._dirty_out, w._out_dsts
        n = len(dirty)
        t0 = time.perf_counter()
        for src in tuple(dirty):
            b = dsts.get(src)
            if b is not None:
                b.sort()
        dt = (time.perf_counter() - t0) * 1e3
        verdict = "EXCEEDS" if dt > quantum_ms else "under  "
        print(f"  buckets={n:>6}  dirty-loop={dt:>8.3f} ms  {verdict} the quantum"
              f"  -> read||read {'IS' if dt > quantum_ms else 'is NOT'} reachable "
              f"at the default interval")
    return []


# ---------------------------------------------------------------------------
# 2. read || write  — silent, permanent order corruption
# ---------------------------------------------------------------------------

def readwrite(WM, trials: int, seed: int = 1500, append: int = 400,
              readers: int = 4) -> list[str]:
    out = []
    seed_nodes = [_node(f"n{i:06d}") for i in range(seed)]
    appended = [_node(f"a{append - i:06d}") for i in range(append)]
    for t in range(trials):
        w = WM()
        for n in seed_nodes:
            w.add_node(n)
        w.all_nodes()                                    # normalise: clean+sorted
        stop = threading.Event()
        bad: list[int] = []

        def reader():
            while not stop.is_set():
                ids = [n.id for n in w.all_nodes()]
                if ids != sorted(ids):
                    bad.append(len(ids))

        def writer():
            try:
                for n in appended:
                    w.add_node(n)
            finally:
                stop.set()

        failures = _run([reader] * readers + [writer])
        if failures:
            out.append(f"trial {t}: {failures[0]}")
        elif bad:
            out.append(f"trial {t}: {len(bad)} read(s) came back UNSORTED")
        elif [n.id for n in w.all_nodes()] != sorted(w._nodes):
            out.append(f"trial {t}: order PERMANENTLY corrupted after quiesce")
    return out


# ---------------------------------------------------------------------------
# 3. write || write / evict  — the shipped AEGIS middleware shape
# ---------------------------------------------------------------------------

def aegis(WM, trials: int, threads: int = 4, per_thread: int = 300,
          max_actors: int = 64, concurrent_read: bool = True) -> list[str]:
    """`AegisWSGIMiddleware` holds ONE `Aegis` -> one `ActorGraph` -> one
    `WorldModel` and calls `observe()` per request from a multi-threaded WSGI
    server; `aegis.integrate` reads `all_nodes()` on the verdict path.

    concurrent_read=False is the ISOLATING CONTROL. It matters: the PRE-INDEX
    `all_nodes` is `[self._nodes[k] for k in sorted(self._nodes)]`, and while
    `sorted()` is atomic the COMPREHENSION is not, so a concurrent
    `remove_node` can KeyError it too. That race predates the index. With the
    read removed, any failure is the index desyncing under write||write, which
    is the defect this slice introduced."""
    from ...aegis.actor_graph import ActorGraph
    from ...intel.models import IntelSourceKind, Observation
    from ...intel.refs import EntityRef

    def obs(tid, i):
        ref = EntityRef(kind=NodeKind.HOST, key=f"t{tid}-{per_thread - i:05d}.example")
        return Observation(obs_id=f"o-{tid}-{i}", source="wsgi",
                           source_kind=IntelSourceKind.REQUEST_TELEMETRY,
                           subject=ref, confidence=0.5, seq=i + 1)

    out = []
    for t in range(trials):
        ag = ActorGraph(WM(), max_actors=max_actors)

        def worker(tid):
            for i in range(per_thread):
                ag.observe(obs(tid, i))
                if concurrent_read and i % 25 == 0:
                    ag.world.all_nodes()

        failures = _run([lambda tid=k: worker(tid) for k in range(threads)])
        w = ag.world
        if failures:
            out.append(f"trial {t}: {failures[0]}")
            continue
        if hasattr(w, "_node_ids") and len(w._node_ids) != len(w._nodes):
            out.append(f"trial {t}: DESYNC _node_ids={len(w._node_ids)} "
                       f"_nodes={len(w._nodes)}")
            continue
        try:
            ids = [n.id for n in w.all_nodes()]
        except BaseException as e:                       # noqa: BLE001
            out.append(f"trial {t}: post/all_nodes {type(e).__name__}: {e}")
            continue
        if ids != sorted(w._nodes):
            out.append(f"trial {t}: post/order corrupted")
    return out


_MODES = {
    "readread": readread,
    "readwrite": readwrite,
    "aegis": aegis,
    "aegis-control": lambda WM, t: aegis(WM, t, concurrent_read=False),
    "dirtyloop": dirtyloop,
}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", default="all",
                    choices=(*_MODES, "all"))
    ap.add_argument("--rev", default=None,
                    help="measure this git revision's graph.py (e.g. 8d8d8c30 for "
                         "the UNLOCKED index) instead of the current tree")
    ap.add_argument("--trials", type=int, default=15)
    ap.add_argument("--switchinterval", type=float, default=None,
                    help="default: run BOTH 0.005 and 1e-6")
    ap.add_argument("--buckets", type=int, default=7500,
                    help="readread: dirty out-buckets (see the module docstring "
                         "-- the threshold is host-dependent)")
    args = ap.parse_args(argv)

    modes = list(_MODES) if args.mode == "all" else [args.mode]
    intervals = ([args.switchinterval] if args.switchinterval
                 else [DEFAULT_INTERVAL, FAST_INTERVAL])

    ctx = (revision_world_model(args.rev) if args.rev
           else contextlib.nullcontext(CurrentWorldModel))
    with ctx as WM:
        label = args.rev or "CURRENT TREE"
        print(f"python {sys.version.split()[0]}  target={label}  trials={args.trials}")
        rc = 0
        for mode in modes:
            fn = _MODES[mode]
            if mode == "dirtyloop":
                print(f"\n-- {mode} ({label}) --")
                fn(WM, args.trials)
                continue
            for interval in intervals:
                with _switching(interval):
                    if mode == "readread":
                        fails = readread(WM, args.trials, buckets=args.buckets)
                    else:
                        fails = fn(WM, args.trials)
                print(f"{mode:14s} {label:12s} switchinterval={interval:<8g} "
                      f"FAIL {len(fails)}/{args.trials}")
                for f in fails[:2]:
                    print(f"    {f}")
                if fails:
                    rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
