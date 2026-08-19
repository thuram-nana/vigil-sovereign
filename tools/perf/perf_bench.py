#!/usr/bin/env python3
"""VIGIL performance-regression gate (W2-6, issue #423).

WHY THIS EXISTS. The only regression gate in CI was *accuracy* (`make bench` — the signed
recall/precision scorecard). A change that halved throughput or doubled peak memory of the
hot integrity paths shipped green. This harness adds the missing dimension: a committed
WALL-CLOCK / THROUGHPUT / PEAK-MEMORY floor over the shared integrity substrate, checked on
every PR by an advisory workflow, with a proven-non-no-op NEGATIVE CONTROL.

WHAT IT MEASURES. Real, load-bearing, deterministic hot paths in `vigil_core` (canonical
JSON, payload digests, the hash-linked spine chain build + verify) plus a couple of
pure-stdlib synthetic cases used only by the self-test. For each case it records:

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
    cases = _real_cases()
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
    cases = _real_cases()
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
