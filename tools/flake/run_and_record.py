"""W11-5 (#486) — run a pytest target N times and record each per-test outcome into the flake ledger.

This is what CI (and a local seeding run) call to build the historical pass-rate record for the
concurrency stress suite. It runs the target with a JUnit-XML report (stdlib-parseable — no pytest
plugin needed), records one outcome row per testcase per repeat into the JSONL ledger, then prints the
quarantine-candidate report. Repetition here IS the "repeat stress": each repeat is a fresh interpreter,
so a scheduler-timing flake in the threaded stress test surfaces across repeats.

Usage:
  python tools/flake/run_and_record.py --target apps/sigil/tests/test_spine_concurrency_stress.py \
      --repeat 5 --run-id local-seed --ledger docs/flake/ledger.jsonl

Exit code is non-zero if ANY repeat had a failing/erroring testcase, so CI fails loudly on a real break
while still recording the outcome for the historical rate.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import flake_tracker  # noqa: E402  (same-dir import; see sys.path insert above)


def _outcome_of(case: ET.Element) -> str:
    """Map a JUnit <testcase> to a ledger outcome."""
    for child in case:
        tag = child.tag.split("}")[-1]                     # strip any namespace
        if tag == "failure":
            return "fail"
        if tag == "error":
            return "error"
        if tag == "skipped":
            return "skip"
    return "pass"


def _run_once(target: str, extra: list[str]) -> tuple[int, list[tuple[str, str]]]:
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf:
        xml_path = tf.name
    try:
        cmd = [sys.executable, "-m", "pytest", target, "-q", f"--junit-xml={xml_path}", *extra]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        results: list[tuple[str, str]] = []
        try:
            root = ET.parse(xml_path).getroot()
        except (ET.ParseError, FileNotFoundError):
            return proc.returncode or 1, results          # no XML == a hard pytest failure; report it
        for case in root.iter("testcase"):
            name = case.get("name", "")
            classname = case.get("classname", "")
            nodeid = f"{classname}::{name}" if classname else name
            results.append((nodeid, _outcome_of(case)))
        return proc.returncode, results
    finally:
        try:
            os.unlink(xml_path)
        except OSError:
            pass


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", required=True, help="pytest target (file/dir/nodeid)")
    ap.add_argument("--repeat", type=int, default=int(os.environ.get("SIGIL_STRESS_REPEAT", "5")))
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--ledger", default=str(flake_tracker.DEFAULT_LEDGER))
    ap.add_argument("--threshold", type=float, default=1.0)
    ap.add_argument("--min-runs", type=int, default=1)
    ap.add_argument("--pytest-arg", action="append", default=[], help="extra arg passed to pytest")
    args = ap.parse_args(argv)

    worst = 0
    for rep in range(args.repeat):
        rc, results = _run_once(args.target, args.pytest_arg)
        worst = worst or rc
        for nodeid, outcome in results:
            flake_tracker.record_outcome(args.ledger, test_id=nodeid, outcome=outcome,
                                         run_id=f"{args.run_id}#{rep}")
        print(f"[flake] repeat {rep + 1}/{args.repeat}: rc={rc}, {len(results)} cases recorded")

    print("\n[flake] historical pass-rate report:")
    for tid, st in sorted(flake_tracker.historical_report(args.ledger).items()):
        rate = "n/a" if st["rate"] is None else f"{st['rate']:.3f}"
        print(f"  {tid}: {st['passes']}/{st['runs']} = {rate} (skips={st['skips']})")

    flaky = flake_tracker.flaky_tests(args.ledger, threshold=args.threshold, min_runs=args.min_runs)
    if flaky:
        print(f"\n[flake] QUARANTINE CANDIDATES (rate < {args.threshold} over >= {args.min_runs} runs):")
        for st in flaky:
            print(f"  {st['test_id']}: {st['passes']}/{st['runs']} = {st['rate']:.3f}")
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
