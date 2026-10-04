#!/usr/bin/env python3
"""VIGIL performance-regression gate (W2-6, issue #423).

WHY THIS EXISTS. The only regression gate in CI was *accuracy* (`make bench` — the signed
recall/precision scorecard). A change that halved throughput or doubled peak memory of the
hot integrity paths shipped green. This harness adds the missing dimension: a committed
WALL-CLOCK / THROUGHPUT / PEAK-MEMORY floor over the shared integrity substrate, checked on
every PR by an advisory workflow, with a proven-non-no-op NEGATIVE CONTROL.

WHAT IT MEASURES. Real, load-bearing, deterministic hot paths: the `vigil_core` integrity
primitives (canonical JSON, payload digests, the hash-linked spine chain build + verify) AND
a fixed-corpus `scan` case driving the planner's real super-linear loop (`saturate` to a
fixpoint then `best_paths` — the #828 shape). Plus pure-stdlib synthetic-N cases that model
the on-tree complexity of the three hot-path shapes (chaining / pathsearch / saturate); the
on-tree variants are gated, and each ships a planted O(N^2) twin that is the ALGORITHMIC
negative control (see `cmd_selftest` and the synthetic_* factories). For each case it records:

  * wall_s              — best-of-N wall clock for one full case run (min => least jitter).
  * throughput_ops_s    — logical work units per second.
  * peak_bytes          — tracemalloc PEAK python-allocated bytes for one run (deterministic,
                          machine-independent) — the gated memory floor.
  * maxrss_kb           — resource.getrusage ru_maxrss, RECORDED for humans, NOT gated
                          (process-wide + monotonic => a poor gate; peak_bytes is the sound
                          proxy for the "doubles peak RSS" regression the issue names).
  * rel_speed           — throughput_ops_s / a same-run CALIBRATION probe (see below).

PORTABILITY — why the time gate is normalised. Absolute wall clock is meaningless across
machines (a dev box vs a shared GitHub runner), so committing an absolute wall-clock floor
would false-fail forever. Each run first measures a CALIBRATION probe and gates on the
dimensionless ratio rel_speed = case_throughput / calibration_throughput. A CPU that is 2x
faster speeds BOTH numerator and denominator, so the ratio is stable; a code change that
slows only the case (not the calibration) moves the ratio, and the gate fires.

The probe exercises the SAME stdlib primitives the hot paths lean on (json.dumps + hashlib
.sha256) over FIXED neutral data, but NEVER through vigil_core. That is deliberate: those
primitives are C-accelerated and their speed relative to pure bytecode swings widely across
CPUs (e.g. SHA-NI), so a pure-bytecode probe would drift the ratio machine-to-machine. Sharing
the primitives makes the hardware acceleration cancel. It still catches every regression in the
code we OWN — a slowdown *inside* canonical_json / digest_payload / build_chain moves the case
but not the probe (the probe calls json/hashlib directly, not our wrappers) — the only thing it
cannot see is a regression in json/hashlib themselves, which are stdlib and not ours to break.

THE GATE (see `evaluate`, a pure function of numbers so the negative control is exercised
in-process, not merely described):

  * throughput floor : FAIL if measured rel_speed < baseline.rel_speed * (1 - REGRESS_FRAC).
  * memory floor     : FAIL if measured peak_bytes > baseline.peak_bytes * (1 + GROW_FRAC)
                       + a small absolute slack (tiny allocations are noisy).

Updating a baseline is an explicit, reviewed change: `perf_bench.py record` REWRITES the
committed JSON, which shows up in the diff and goes through review like any other file. CI
never self-updates it.

Deliberately stdlib-only at import time (json, time, tracemalloc, resource, statistics,
argparse, pathlib, platform). The real `vigil_core` cases are imported LAZILY inside their
setup, so `import perf_bench` is safe in the pytest-only `docs/tests` job (which installs no
third-party packages) — that is where the negative-control self-test rides a REQUIRED check.
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
import time
import tracemalloc
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

try:  # Unix only; present on ubuntu-latest and every dev box. Absence only drops ru_maxrss.
    import resource
except Exception:  # pragma: no cover - non-Unix fallback
    resource = None  # type: ignore[assignment]

HERE = Path(__file__).resolve().parent
DEFAULT_BASELINE = HERE / "baselines" / "perf-baseline.json"

# --- gate bands ------------------------------------------------------------------------------
# REGRESS_FRAC 0.45 => fail when throughput drops below 55% of baseline (a >=1.82x slowdown),
# which catches the "halves throughput" (2x -> 50% < 55%) regression the issue names while
# tolerating cross-machine ratio drift. GROW_FRAC 0.30 => fail when peak allocation exceeds
# 130% of baseline, catching "doubles peak RSS" (2x -> 200% > 130%) with wide margin.
REGRESS_FRAC = 0.45
GROW_FRAC = 0.30
MEM_SLACK_BYTES = 8192

# Measurement shape. Small enough that the whole gate runs in a few seconds.
WARMUP = 2
REPEATS = 7


# --- calibration ------------------------------------------------------------------------------
import hashlib as _hashlib  # noqa: E402  (calibration primitive; the hot paths use it via vigil_core)
import json as _json  # noqa: E402

# Fixed neutral data for the probe — NOT the payloads the cases use, and never routed through
# vigil_core. Exercising json+sha here (the same C primitives the cases lean on) cancels their
# hardware acceleration in the ratio while leaving our own code's cost fully visible.
_PROBE_OBJ = {"k": list(range(24)), "s": "probe" * 12, "n": {"a": 1, "b": 2, "c": [3, 4, 5]}}
CALIBRATION_OPS = 4000


def _calibration_probe() -> None:
    for _ in range(CALIBRATION_OPS):
        b = _json.dumps(_PROBE_OBJ, sort_keys=True, separators=(",", ":")).encode("utf-8")
        _hashlib.sha256(b).hexdigest()


def _best_wall(fn: Callable[[Any], None], state: Any, repeats: int, warmup: int) -> float:
    for _ in range(warmup):
        fn(state)
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn(state)
        samples.append(time.perf_counter() - t0)
    return min(samples)  # min = the run least perturbed by the scheduler/GC


def calibrate() -> float:
    """Return the calibration probe throughput (ops/sec) on THIS machine, this run."""
    wall = _best_wall(lambda _s: _calibration_probe(), None, REPEATS, WARMUP)
    return CALIBRATION_OPS / wall if wall > 0 else float("inf")


# --- cases ------------------------------------------------------------------------------------
@dataclass
class Case:
    name: str
    setup: Callable[[], Any]
    run: Callable[[Any], None]
    ops: int  # logical work units per single run() call (for throughput)
    real: bool = True  # real => needs vigil_core; synthetic => pure stdlib (self-test only)
    warmup: int = WARMUP
    repeats: int = REPEATS


@dataclass
class Measurement:
    wall_s: float
    throughput_ops_s: float
    peak_bytes: int
    maxrss_kb: int
    rel_speed: float
    extra: dict[str, Any] = field(default_factory=dict)


def measure(case: Case, calibration_ops_s: float) -> Measurement:
    state = case.setup()
    wall = _best_wall(case.run, state, case.repeats, case.warmup)
    throughput = case.ops / wall if wall > 0 else float("inf")

    # peak python-allocated bytes for ONE run — deterministic, machine-independent.
    tracemalloc.start()
    tracemalloc.reset_peak()
    case.run(state)
    _cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    maxrss = 0
    if resource is not None:
        maxrss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)

    rel = throughput / calibration_ops_s if calibration_ops_s > 0 else 0.0
    return Measurement(
        wall_s=wall, throughput_ops_s=throughput, peak_bytes=int(peak),
        maxrss_kb=maxrss, rel_speed=rel,
    )


# ---- real vigil_core cases (lazy import; only loaded when the gate actually runs) ----
def _real_cases() -> list[Case]:
    from vigil_core import build_chain, verify_chain  # noqa: PLC0415 (lazy on purpose)
    from vigil_core.canonical import canonical_json, digest_payload, sha256_hex  # noqa: PLC0415

    payload = {
        "finding": "boolean_sqli", "seq": 42,
        "nested": {"a": [1, 2, 3, {"x": "y"}], "b": "z" * 64},
        "scope": ["127.0.0.1"], "tags": ["OBSIDIAN-TEST"] * 8,
    }

    def canon_setup() -> Any:
        return payload

    def canon_run(p: Any) -> None:
        for _ in range(2000):
            canonical_json(p)

    def digest_run(p: Any) -> None:
        for _ in range(2000):
            digest_payload(p)

    blob = b"x" * 1024

    def sha_run(b: Any) -> None:
        for _ in range(2000):
            sha256_hex(b)

    def chain_setup() -> Any:
        return [sha256_hex(str(i).encode()) for i in range(1000)]

    def build_run(digests: Any) -> None:
        build_chain(digests)

    def verify_setup() -> Any:
        return build_chain([sha256_hex(str(i).encode()) for i in range(1000)])

    def verify_run(entries: Any) -> None:
        verify_chain(entries)

    return [
        Case("canonical_json.nested", canon_setup, canon_run, ops=2000),
        Case("digest_payload.nested", canon_setup, digest_run, ops=2000),
        Case("sha256_hex.1kb", lambda: blob, sha_run, ops=2000),
        Case("build_chain.1000", chain_setup, build_run, ops=1000),
        Case("verify_chain.1000", verify_setup, verify_run, ops=1000),
    ]


# ---- synthetic cases: pure stdlib, used ONLY by the self-test / negative control ----
def synthetic_fast_setup() -> Any:
    return list(range(5000))


def synthetic_fast_run(data: Any) -> None:
    total = 0
    for v in data:
        total += (v * v) % 97
    _ = total


def synthetic_slow_run(data: Any) -> None:
    """A deliberately slowed + memory-heavy variant of synthetic_fast_run.

    Same logical output, but ~10x the work and an O(n) throwaway allocation per element — the
    'artificially slowed path' the negative control asserts the gate must reject.
    """
    total = 0
    for v in data:
        junk = [v] * 32  # extra allocation the fast path never makes
        for _ in range(10):  # ~10x redundant work
            total += (v * v) % 97
        total += len(junk) - 32
    _ = total


def synthetic_fast_case() -> Case:
    return Case("synthetic.fast", synthetic_fast_setup, synthetic_fast_run, ops=5000, real=False)


def synthetic_slow_case() -> Case:
    return Case("synthetic.slow", synthetic_fast_setup, synthetic_slow_run, ops=5000, real=False)


# ---- synthetic-N ALGORITHMIC cases: the regression gate that would have caught #828 ----------
# The vigil_core cases above catch a slowdown in the integrity primitives. #828 was a different
# animal: a ~2h *scan*, whose cost is dominated by the planner's two super-linear hot paths —
# forward-chaining the world to a fixpoint (knowledge.operators.saturate) and ranking crown-jewel
# routes (worldmodel.pathsearch.best_paths) — plus the hash-linked spine chaining. A constant-
# factor gate is the wrong shape for that class: the danger is an ALGORITHMIC regression (an
# O(N log N) / O(N) path quietly becoming O(N^2)), which is invisible at a tiny N and catastrophic
# at scan scale.
#
# These three cases MODEL the on-tree complexity SHAPE of exactly those paths in pure stdlib, each
# with a planted O(N^2) twin that returns the IDENTICAL logical result — so when the gate rejects
# the twin, "slower" is the only thing it can be reacting to. They are pure stdlib on purpose:
#   * the on-tree variants are GATED against the committed baseline (`check`), like any hot path;
#   * the quadratic twins are the NEGATIVE CONTROL (selftest + the required docs/tests proof),
#     which needs no engine/vigil_core import so it rides the already-required pytest job.
# Each planted twin is the realistic form of the regression at its site (named in its docstring),
# and the gate catches it because at the committed N the quadratic twin is many× slower — far
# beyond the -45% band or any cross-machine ratio drift.
#
# N is chosen so the on-tree variant runs in ~1-3 ms (the gate stays a few seconds) while the
# quadratic twin is tens-to-hundreds of ms (decisively over the band): see tools/perf/README.md.
SYNTH_CHAIN_N = 400       # hash-linked fold          -> models vigil_core.build_chain / the spine
SYNTH_PATH_N = 1500       # Dijkstra min-extraction    -> models worldmodel.pathsearch
SYNTH_SATURATE_N = 2500   # fixpoint seen-set dedup    -> models knowledge.operators.saturate
SCAN_CORPUS_N = 80        # fixed-corpus scan: real saturate + best_paths over an N-node world


def _chain_fast(n: int) -> bytes:
    """O(n) rolling hash-link fold — the spine's shape: each step folds ONE item into a 32-byte
    running digest."""
    h = b"\x00" * 32
    for i in range(n):
        h = _hashlib.sha256(h + i.to_bytes(8, "big")).digest()
    return h


def _chain_quadratic(n: int) -> bytes:
    """Same final digest as `_chain_fast`, computed in O(n^2): the rolling hash replaced by re-
    folding the WHOLE prefix every step (the regression where an accumulating buffer is re-hashed
    from scratch instead of chained). The last step folds 0..n-1, so the result is identical."""
    final = b"\x00" * 32
    for i in range(n):
        h = b"\x00" * 32
        for j in range(i + 1):
            h = _hashlib.sha256(h + j.to_bytes(8, "big")).digest()
        final = h
    return final


def _synth_graph(n: int) -> dict[int, list[tuple[int, int]]]:
    """A deterministic n-node digraph, out-degree 4, mirroring the scan world's fan-out."""
    return {i: [((i * 7 + j) % n, 1 + ((i + j) % 4)) for j in (1, 2, 3, 5)] for i in range(n)}


def _dijkstra_fast(adj: dict[int, list[tuple[int, int]]]) -> dict[int, int]:
    """O(E log V) single-source shortest paths via a min-heap — pathsearch's on-tree shape."""
    import heapq  # noqa: PLC0415 (stdlib; local so `import perf_bench` stays trivially cheap)
    dist: dict[int, int] = {0: 0}
    heap: list[tuple[int, int]] = [(0, 0)]
    settled: set[int] = set()
    while heap:
        d, u = heapq.heappop(heap)
        if u in settled:
            continue
        settled.add(u)
        for v, w in adj[u]:
            nd = d + w
            if v not in dist or nd < dist[v]:
                dist[v] = nd
                heapq.heappush(heap, (nd, v))
    return dist


def _dijkstra_quadratic(adj: dict[int, list[tuple[int, int]]]) -> dict[int, int]:
    """Same shortest-distance map as `_dijkstra_fast`, computed in O(V^2): the min-priority heap
    replaced by a linear scan for the nearest unsettled node every step — the classic way an
    O(E log V) search regresses to O(V^2), exactly the pathsearch hot loop's risk."""
    dist: dict[int, int] = {0: 0}
    settled: set[int] = set()
    while True:
        u = None
        best = None
        for k, dv in dist.items():
            if k in settled:
                continue
            if best is None or dv < best:
                best = dv
                u = k
        if u is None:
            break
        settled.add(u)
        for v, w in adj[u]:
            nd = best + w  # type: ignore[operator]
            if v not in dist or nd < dist[v]:
                dist[v] = nd
    return dist


def _synth_sigs(n: int) -> list[tuple[str, ...]]:
    """n derived-fact signatures with duplicates, the shape saturate dedups against its seen-set."""
    return [("E", f"n{i % 97}", f"n{(i * 7) % 97}", f"k{i % 11}") for i in range(n)]


def _dedup_fast(sigs: list[tuple[str, ...]]) -> int:
    """O(n) fixpoint dedup via a seen-SET — knowledge.operators.saturate's on-tree shape."""
    seen: set[tuple[str, ...]] = set()
    new = 0
    for s in sigs:
        if s in seen:
            continue
        seen.add(s)
        new += 1
    return new


def _dedup_quadratic(sigs: list[tuple[str, ...]]) -> int:
    """Same new-fact count as `_dedup_fast`, computed in O(n^2): the seen-SET turned into a seen-
    LIST, so every membership test is O(n) — precisely the regression that would turn saturate's
    seen-set (operators.py, the set that defines the fixpoint closure) back into the quadratic
    fixpoint it exists to avoid."""
    seen: list[tuple[str, ...]] = []
    new = 0
    for s in sigs:
        if s in seen:
            continue
        seen.append(s)
        new += 1
    return new


def synthetic_chaining_case() -> Case:
    return Case("synthetic.chaining", lambda: SYNTH_CHAIN_N,
                lambda n: _chain_fast(n), ops=SYNTH_CHAIN_N, real=False)


def synthetic_chaining_quadratic_case() -> Case:
    return Case("synthetic.chaining.quadratic", lambda: SYNTH_CHAIN_N,
                lambda n: _chain_quadratic(n), ops=SYNTH_CHAIN_N, real=False)


def synthetic_pathsearch_case() -> Case:
    return Case("synthetic.pathsearch", lambda: _synth_graph(SYNTH_PATH_N),
                lambda adj: _dijkstra_fast(adj), ops=SYNTH_PATH_N, real=False)


def synthetic_pathsearch_quadratic_case() -> Case:
    return Case("synthetic.pathsearch.quadratic", lambda: _synth_graph(SYNTH_PATH_N),
                lambda adj: _dijkstra_quadratic(adj), ops=SYNTH_PATH_N, real=False)


def synthetic_saturate_case() -> Case:
    return Case("synthetic.saturate", lambda: _synth_sigs(SYNTH_SATURATE_N),
                lambda sigs: _dedup_fast(sigs), ops=SYNTH_SATURATE_N, real=False)


def synthetic_saturate_quadratic_case() -> Case:
    return Case("synthetic.saturate.quadratic", lambda: _synth_sigs(SYNTH_SATURATE_N),
                lambda sigs: _dedup_quadratic(sigs), ops=SYNTH_SATURATE_N, real=False)


# The on-tree / planted-quadratic pairs, in one place so the selftest and the required pytest
# prove the SAME set. Each triple is (label, on-tree case, planted-O(N^2) twin).
def synthetic_algorithmic_pairs() -> list[tuple[str, Case, Case]]:
    return [
        ("synthetic.chaining", synthetic_chaining_case(), synthetic_chaining_quadratic_case()),
        ("synthetic.pathsearch", synthetic_pathsearch_case(), synthetic_pathsearch_quadratic_case()),
        ("synthetic.saturate", synthetic_saturate_case(), synthetic_saturate_quadratic_case()),
    ]


# ---- real fixed-corpus scan case (lazy engine import; only built when the gate runs) ----------
def _scan_case() -> Case:
    """The fixed-corpus SCAN case: the planner's real hot loop — forward-chain the world to a
    fixpoint (`knowledge.operators.saturate`) then rank crown-jewel routes
    (`worldmodel.pathsearch.best_paths`) — over a FIXED, deterministic N-node world. This is the
    #828 shape (the ~2h scan's cost is dominated by exactly these two) shrunk to run in well under
    a second, but still a live sensor: a slowdown INSIDE the real saturate / best_paths moves this
    case's rel_speed off its committed baseline. The world is rebuilt inside `run` because saturate
    mutates it to a fixpoint, so build + expand + rank are all measured. Engine is imported lazily
    so `import perf_bench` stays stdlib-only for the required docs/tests job."""
    from framework.v2.knowledge.catalog import CATALOG  # noqa: PLC0415 (lazy on purpose)
    from framework.v2.knowledge.catalog_ext import EXTENDED_CATALOG  # noqa: PLC0415
    from framework.v2.knowledge.operators import saturate  # noqa: PLC0415
    from framework.v2.worldmodel import pathsearch  # noqa: PLC0415
    from framework.v2.worldmodel.graph import WorldModel  # noqa: PLC0415
    from framework.v2.worldmodel.models import Edge, EdgeKind, Node, NodeKind  # noqa: PLC0415

    n = SCAN_CORPUS_N
    node_kinds = list(NodeKind)
    edge_kinds = list(EdgeKind)
    ops = [*CATALOG, *EXTENDED_CATALOG]
    seeds = {op.id: {"actor": "attacker", "resource": "n0000001", "app": "n0000002"} for op in ops}
    objective_kinds = [NodeKind.DATASTORE, NodeKind.CLOUD_RESOURCE]

    def _node(nid: str, kind: Any) -> Any:
        return Node(id=nid, kind=kind, provenance="obs", confidence=0.5, first_seen=1, last_seen=1)

    def _edge(src: str, dst: str, kind: Any) -> Any:
        return Edge(src=src, dst=dst, kind=kind, provenance="obs-e", confidence=0.5, first_seen=1, last_seen=1)

    def _build() -> Any:
        w = WorldModel()
        for i in range(n):
            w.add_node(_node(f"n{i:07d}", node_kinds[i % len(node_kinds)]))
        for i in range(n):
            for j in (1, 2, 3):
                w.add_edge(_edge(f"n{i:07d}", f"n{(i * 7 + j) % n:07d}", edge_kinds[(i + j) % len(edge_kinds)]))
        return w

    def run(_state: Any) -> None:
        w = _build()
        w.add_node(_node("attacker", NodeKind.PRINCIPAL))
        saturate(ops, w, seq_start=10_000, seeds=seeds)
        pathsearch.best_paths(w, "n0000000", objective_kinds, k=5)

    return Case("scan.plan_fixed_corpus", lambda: None, run, ops=n, real=True)


def saturate_delta_derivation_counts(chain_n: int = 5, inert_n: int = 60) -> tuple[int, int, bool]:
    """Proof for M2.1 (#828): the worklist ``knowledge.operators.saturate`` reaches the
    IDENTICAL saturated graph as the retained full-rescan reference ``_saturate_full`` while
    making STRICTLY FEWER operator-derivations.

    The win is proportional to (rounds-1) x (clean-failed candidate pairs), so this builds the
    shape where it shows: a reverse-ordered SET_ATTR chain of length ``chain_n`` (which takes
    ``chain_n + 1`` rounds to converge) over one active node, among ``inert_n`` same-kind nodes
    that are candidates of every chain operator but RE-FAIL the attr precondition every round.
    The full rescan re-probes those inert candidates each round; the worklist probes them once
    (the first sweep) and never re-visits them, because nothing they read ever changes.

    Returns ``(full_derivations, worklist_derivations, byte_identical)``. Counts ``derive``
    CALLS (the 'derivation count' the win is measured in — NOT wall clock), by swapping the
    module-global both functions call. Engine is imported lazily so ``import perf_bench`` stays
    stdlib-only for the required ``docs/tests`` job; a bare-stdlib environment raises
    ``ImportError`` here and the caller skips the proof rather than failing it."""
    from framework.v2.knowledge import operators as _ops  # noqa: PLC0415 (lazy on purpose)
    from framework.v2.knowledge.models import (  # noqa: PLC0415
        AttrOp, Effect, EffectKind, Operator, Predicate, PredicateKind)
    from framework.v2.worldmodel.graph import WorldModel  # noqa: PLC0415
    from framework.v2.worldmodel.models import Node, NodeKind  # noqa: PLC0415

    H = NodeKind.HOST
    ops = [Operator(id=f"pstep{i}", name=f"p{i}", technique_ref=["X"],
                    preconditions=[Predicate(kind=PredicateKind.NODE_KIND, node_kind=H),
                                   Predicate(kind=PredicateKind.NODE_ATTR, attr=f"s{i - 1}",
                                             op=AttrOp.TRUTHY)],
                    effects=[Effect(kind=EffectKind.SET_ATTR, attr=f"s{i}", value=True)])
           for i in range(chain_n, 0, -1)]

    def build() -> Any:
        w = WorldModel()
        w.add_node(Node(id="active", kind=H, attrs={"s0": True}, provenance="o",
                        confidence=1.0, first_seen=1, last_seen=1))
        for i in range(inert_n):
            w.add_node(Node(id=f"inert_{i:04d}", kind=H, provenance="o",
                            confidence=1.0, first_seen=1, last_seen=1))
        return w

    real = _ops.derive
    n = [0]

    def counting(*a: Any, **k: Any) -> Any:
        n[0] += 1
        return real(*a, **k)

    _ops.derive = counting  # type: ignore[assignment]
    try:
        wf = build()
        n[0] = 0
        _ops._saturate_full(ops, wf, 1000)
        full_n = n[0]
        ww = build()
        n[0] = 0
        _ops.saturate(ops, ww, 1000)
        wl_n = n[0]
    finally:
        _ops.derive = real  # type: ignore[assignment]
    identical = (wf.all_nodes() == ww.all_nodes()) and (wf.all_edges() == ww.all_edges())
    return full_n, wl_n, identical


def gated_cases() -> list[Case]:
    """Every case the committed-baseline gate (`check` / `record`) covers: the vigil_core hot
    paths, the fixed-corpus scan sensor, and the on-tree synthetic-N algorithmic cases. The
    quadratic twins are deliberately NOT here — they exist only for the negative control."""
    return [
        *_real_cases(),
        _scan_case(),
        synthetic_chaining_case(),
        synthetic_pathsearch_case(),
        synthetic_saturate_case(),
    ]


# --- gate ------------------------------------------------------------------------------------
def evaluate(
    name: str,
    baseline_entry: dict[str, Any],
    measured: Measurement,
    *,
    regress_frac: float = REGRESS_FRAC,
    grow_frac: float = GROW_FRAC,
    mem_slack: int = MEM_SLACK_BYTES,
) -> tuple[bool, list[str]]:
    """Pure gate over plain numbers. Returns (ok, reasons-for-failure).

    Kept free of measurement so the negative control can feed it synthetic numbers in-process
    and prove it bites (and prove it passes an at-baseline measurement).
    """
    reasons: list[str] = []

    base_rel = float(baseline_entry["rel_speed"])
    rel_floor = base_rel * (1.0 - regress_frac)
    if measured.rel_speed < rel_floor:
        reasons.append(
            f"{name}: throughput regressed — rel_speed {measured.rel_speed:.4f} < floor "
            f"{rel_floor:.4f} (baseline {base_rel:.4f}, band -{regress_frac:.0%})"
        )

    base_mem = int(baseline_entry["peak_bytes"])
    mem_ceiling = int(base_mem * (1.0 + grow_frac)) + mem_slack
    if measured.peak_bytes > mem_ceiling:
        reasons.append(
            f"{name}: peak memory grew — {measured.peak_bytes} B > ceiling {mem_ceiling} B "
            f"(baseline {base_mem} B, band +{grow_frac:.0%} + {mem_slack} B slack)"
        )

    return (not reasons), reasons


def _entry_from_measurement(m: Measurement) -> dict[str, Any]:
    return {
        "rel_speed": round(m.rel_speed, 6),
        "peak_bytes": m.peak_bytes,
        "throughput_ops_s": round(m.throughput_ops_s, 2),
        "wall_s": round(m.wall_s, 6),
    }


# --- commands --------------------------------------------------------------------------------
def _load_baseline(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def cmd_record(baseline_path: Path) -> int:
    cal = calibrate()
    cases = gated_cases()
    doc: dict[str, Any] = {
        "schema": 1,
        "note": (
            "COMMITTED performance baseline for the VIGIL hot integrity paths (W2-6/#423). "
            "Regenerate with `python tools/perf/perf_bench.py record` (or `make bench-perf-record`) "
            "and COMMIT the diff — updating a baseline is an explicit, reviewed change; CI never "
            "self-updates it. Time metrics are gated on the machine-independent rel_speed ratio; "
            "peak_bytes is a deterministic tracemalloc figure. See tools/perf/README.md."
        ),
        "bands": {"regress_frac": REGRESS_FRAC, "grow_frac": GROW_FRAC, "mem_slack_bytes": MEM_SLACK_BYTES},
        "recorded_on": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "calibration_ops_s": round(cal, 2),
        "cases": {},
    }
    for case in cases:
        m = measure(case, cal)
        doc["cases"][case.name] = _entry_from_measurement(m)
        print(f"recorded {case.name:24s} rel_speed={m.rel_speed:.4f} peak={m.peak_bytes}B")
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"\nwrote {baseline_path}")
    return 0


def cmd_check(baseline_path: Path) -> int:
    if not baseline_path.is_file():
        print(f"ERROR: no committed baseline at {baseline_path} — run `make bench-perf-record`.", file=sys.stderr)
        return 2
    baseline = _load_baseline(baseline_path)
    bands = baseline.get("bands", {})
    regress_frac = float(bands.get("regress_frac", REGRESS_FRAC))
    grow_frac = float(bands.get("grow_frac", GROW_FRAC))
    mem_slack = int(bands.get("mem_slack_bytes", MEM_SLACK_BYTES))

    cal = calibrate()
    cases = gated_cases()
    print(f"calibration: {cal:,.0f} ops/s  ({platform.machine()}, py{platform.python_version()})")
    print(f"{'case':24s} {'rel_speed':>10s} {'floor':>10s} {'peak_B':>10s} {'ceil_B':>10s}  status")
    all_ok = True
    all_reasons: list[str] = []
    for case in cases:
        if case.name not in baseline.get("cases", {}):
            print(f"{case.name:24s}  (no baseline entry — run record) ")
            all_ok = False
            all_reasons.append(f"{case.name}: missing baseline entry")
            continue
        entry = baseline["cases"][case.name]
        m = measure(case, cal)
        ok, reasons = evaluate(case.name, entry, m, regress_frac=regress_frac, grow_frac=grow_frac, mem_slack=mem_slack)
        rel_floor = float(entry["rel_speed"]) * (1.0 - regress_frac)
        mem_ceiling = int(int(entry["peak_bytes"]) * (1.0 + grow_frac)) + mem_slack
        print(f"{case.name:24s} {m.rel_speed:10.4f} {rel_floor:10.4f} {m.peak_bytes:10d} {mem_ceiling:10d}  {'ok' if ok else 'FAIL'}")
        if not ok:
            all_ok = False
            all_reasons.extend(reasons)
    if not all_ok:
        print("\nPERF REGRESSION:", file=sys.stderr)
        for r in all_reasons:
            print("  - " + r, file=sys.stderr)
        return 1
    print("\nperf gate: PASS")
    return 0


def cmd_selftest(_baseline_path: Path) -> int:
    """End-to-end proof the gate is not a no-op, runnable by hand (mirrors test_perf_gate.py).

    Records a baseline for the FAST synthetic case, then measures the deliberately-SLOWED
    variant against it and asserts the gate REJECTS it. Also asserts an at-baseline
    measurement PASSES.
    """
    cal = calibrate()
    fast = synthetic_fast_case()
    slow = synthetic_slow_case()
    fast_m = measure(fast, cal)
    base = _entry_from_measurement(fast_m)

    ok_clean, _ = evaluate("synthetic.fast", base, fast_m)
    if not ok_clean:
        print("SELFTEST BUG: clean measurement failed its own baseline", file=sys.stderr)
        return 1

    slow_m = measure(slow, cal)
    ok_slow, reasons = evaluate("synthetic.slow", base, slow_m)
    if ok_slow:
        print("NEGATIVE CONTROL FAILED: the slowed path was NOT rejected", file=sys.stderr)
        return 1
    print("negative control OK — slowed path rejected:")
    for r in reasons:
        print("  - " + r)

    # Algorithmic negative control (#828 class): for each hot-path SHAPE, record the on-tree
    # variant's baseline in THIS run (so the proof is immune to cross-machine ratio drift), then
    # measure the planted O(N^2) twin against it and assert the gate REJECTS it while the on-tree
    # variant PASSES. The twin returns the identical logical result, so "slower" is the only
    # difference the gate can be reacting to.
    for label, ontree, quad in synthetic_algorithmic_pairs():
        on_m = measure(ontree, cal)
        on_base = _entry_from_measurement(on_m)
        ok_on, on_reasons = evaluate(label, on_base, on_m)
        if not ok_on:
            print(f"SELFTEST BUG: {label} on-tree failed its own baseline: {on_reasons}", file=sys.stderr)
            return 1
        quad_m = measure(quad, cal)
        ok_quad, quad_reasons = evaluate(f"{label}.quadratic", on_base, quad_m)
        if ok_quad:
            print(f"NEGATIVE CONTROL FAILED: planted O(N^2) {label} was NOT rejected", file=sys.stderr)
            return 1
        print(f"planted O(N^2) {label} rejected (on-tree passes):")
        for r in quad_reasons:
            print("  - " + r)

    # M2.1 (#828) delta-fixpoint proof: the worklist `saturate` reaches the IDENTICAL closure
    # as the full rescan with STRICTLY FEWER operator-derivations. Engine-gated so this stays a
    # pure-stdlib import; where the engine is not importable the proof is SKIPPED, not failed.
    try:
        full_n, wl_n, identical = saturate_delta_derivation_counts()
    except ImportError as exc:  # pragma: no cover - only in a bare-stdlib environment
        print(f"saturate delta-fixpoint proof skipped (engine not importable: {exc})")
    else:
        if not identical:
            print("SATURATE DELTA BUG: worklist result is NOT byte-identical to the full rescan",
                  file=sys.stderr)
            return 1
        if not wl_n < full_n:
            print(f"SATURATE DELTA CONTROL FAILED: worklist {wl_n} not < full rescan {full_n}",
                  file=sys.stderr)
            return 1
        print(f"saturate delta-fixpoint OK — worklist {wl_n} derivations < full rescan {full_n} "
              f"({100 * (full_n - wl_n) / full_n:.0f}% fewer), byte-identical closure")

    print("clean path passes its baseline. self-test PASS")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="VIGIL performance-regression gate (W2-6/#423)")
    ap.add_argument("command", choices=["check", "record", "selftest"], help="check | record | selftest")
    ap.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    ns = ap.parse_args(argv)
    if ns.command == "record":
        return cmd_record(ns.baseline)
    if ns.command == "selftest":
        return cmd_selftest(ns.baseline)
    return cmd_check(ns.baseline)


if __name__ == "__main__":
    raise SystemExit(main())
