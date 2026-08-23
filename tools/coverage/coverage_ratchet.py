#!/usr/bin/env python3
"""Ratcheting line + branch coverage floors, per package (W2-4, #421).

WHY THIS EXISTS. There was NO coverage measurement anywhere. The "coverage guards" only proved a
path *collected* >0 tests (`pytest --collect-only`) — "a skipped proof and a passing proof are the
same colour on a dashboard". The project could not state what fraction of its security-critical code
any test touches. This adds real `pytest-cov` measurement (line AND branch) with committed per-package
floors that CI enforces: if measured coverage drops below the floor, the build goes red.

THE CONTRACT the guard enforces (see `evaluate`), reading a coverage.py JSON report and the committed
floors in `tools/coverage/coverage-thresholds.json`:

  * measured LINE coverage of the package must be >= its committed `line` floor;
  * measured BRANCH coverage of the package must be >= its committed `branch` floor.

RATCHET DIRECTION. The floors are a committed high-water baseline. Raising a floor (as tests improve
coverage) is a tightening; lowering one is a loosening that shows up as an explicit, reviewable diff
line — the same review-enforced monotonicity the perf gate and the mypy ratchet use. Deleting a test
that covers a floored package drops measured coverage below the floor and reddens CI, so an
improvement cannot silently rot. `update` rewrites a package's floors to floor(measured) so raising
the ratchet is one command.

HONEST LIMIT (do NOT overclaim). This guard checks whatever package(s) are listed in the thresholds
file and measured in CI. It is NOT a whole-monorepo coverage number; a package with no entry is not
gated. Percentages are computed from the report's raw counts (covered/total) rather than a coverage.py
`percent_*` field, so the gate is stable across coverage versions.

Deterministic, standard-library only, imports neither trust domain — safe in the reads-only CI legs.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _pct(covered: int, total: int) -> float:
    """Percentage covered; a target with zero of a measure is 100% of that measure (nothing to miss)
    — matching coverage.py's own convention and avoiding a divide-by-zero that would fail-open."""
    return 100.0 if total == 0 else 100.0 * covered / total


def measured_from_report(report: dict) -> tuple[float, float]:
    """(line_pct, branch_pct) from a coverage.py JSON report's `totals`, from raw counts."""
    t = report["totals"]
    line = _pct(int(t["covered_lines"]), int(t["num_statements"]))
    branch = _pct(int(t["covered_branches"]), int(t["num_branches"]))
    return line, branch


def evaluate(
    package: str,
    line_pct: float,
    branch_pct: float,
    floor_line: float,
    floor_branch: float,
) -> tuple[bool, list[str]]:
    """Pure gate over plain numbers. Returns (ok, reasons-for-failure).

    Kept free of I/O so the negative controls can feed it synthetic numbers in-process and prove it
    bites (and prove it passes an at-or-above-floor measurement)."""
    reasons: list[str] = []
    # A tiny epsilon absorbs float round-trip noise ONLY (e.g. 85.0 stored vs 84.99999997 recomputed);
    # it is far smaller than one statement/branch, so a real regression of even one line still fails.
    eps = 1e-9
    if line_pct + eps < floor_line:
        reasons.append(
            f"{package}: LINE coverage regressed — {line_pct:.2f}% < floor {floor_line:.2f}%. "
            "Add tests, or (loosening) lower the committed floor in an explicit, reviewed commit."
        )
    if branch_pct + eps < floor_branch:
        reasons.append(
            f"{package}: BRANCH coverage regressed — {branch_pct:.2f}% < floor {floor_branch:.2f}%. "
            "Add tests, or (loosening) lower the committed floor in an explicit, reviewed commit."
        )
    return (not reasons), reasons


# --- thresholds file -------------------------------------------------------------------------------
def load_thresholds(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data.get("packages"), dict) or not data["packages"]:
        raise ValueError("thresholds file has no `packages` map")
    return data


def package_floors(thresholds: dict, package: str) -> tuple[float, float]:
    pkgs = thresholds["packages"]
    if package not in pkgs:
        raise KeyError(package)
    entry = pkgs[package]
    return float(entry["line"]), float(entry["branch"])


# --- commands --------------------------------------------------------------------------------------
def cmd_check(thresholds_path: Path, package: str, report_path: Path) -> int:
    try:
        thresholds = load_thresholds(thresholds_path)
        floor_line, floor_branch = package_floors(thresholds, package)
    except (OSError, ValueError, KeyError) as e:
        print(f"::error::coverage ratchet: no committed floor for {package!r} in "
              f"{thresholds_path} ({e}) — the gate must not fail-open", file=sys.stderr)
        return 1
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        line_pct, branch_pct = measured_from_report(report)
    except (OSError, ValueError, KeyError) as e:
        print(f"::error::coverage ratchet: unreadable coverage report {report_path} ({e})",
              file=sys.stderr)
        return 1
    ok, reasons = evaluate(package, line_pct, branch_pct, floor_line, floor_branch)
    if ok:
        print(f"coverage ratchet OK — {package}: line {line_pct:.2f}% (floor {floor_line:.2f}%), "
              f"branch {branch_pct:.2f}% (floor {floor_branch:.2f}%).")
        return 0
    for r in reasons:
        print(f"::error::coverage ratchet: {r}", file=sys.stderr)
    return 1


def cmd_update(thresholds_path: Path, package: str, report_path: Path) -> int:
    import math
    thresholds = load_thresholds(thresholds_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    line_pct, branch_pct = measured_from_report(report)
    # floor() so the committed floor always sits at or just below measured (never above — that would
    # red the very run that set it) while still ratcheting up as coverage climbs a whole point.
    thresholds["packages"].setdefault(package, {})
    thresholds["packages"][package]["line"] = float(math.floor(line_pct))
    thresholds["packages"][package]["branch"] = float(math.floor(branch_pct))
    thresholds_path.write_text(json.dumps(thresholds, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    print(f"updated {package}: line floor {math.floor(line_pct)}, branch floor {math.floor(branch_pct)}"
          f" (measured {line_pct:.2f}% / {branch_pct:.2f}%).")
    return 0


def cmd_selftest() -> int:
    assert evaluate("p", 84.9, 75.0, 85.0, 75.0)[0] is False, "line regression not caught"
    assert evaluate("p", 85.0, 74.9, 85.0, 75.0)[0] is False, "branch regression not caught"
    assert evaluate("p", 85.0, 75.0, 85.0, 75.0)[0] is True, "at-floor rejected"
    assert evaluate("p", 90.0, 80.0, 85.0, 75.0)[0] is True, "above-floor rejected"
    fake = {"totals": {"covered_lines": 90, "num_statements": 100,
                       "covered_branches": 3, "num_branches": 4}}
    line, branch = measured_from_report(fake)
    assert abs(line - 90.0) < 1e-9 and abs(branch - 75.0) < 1e-9, (line, branch)
    print("coverage_ratchet selftest OK")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Ratcheting line+branch coverage floors (W2-4/#421)")
    ap.add_argument("command", choices=["check", "update", "selftest"])
    ap.add_argument("--thresholds", type=Path, help="path to coverage-thresholds.json")
    ap.add_argument("--package", help="package key in the thresholds file")
    ap.add_argument("--report", type=Path, help="path to the coverage.py JSON report")
    ns = ap.parse_args(argv)
    if ns.command == "selftest":
        return cmd_selftest()
    if not (ns.thresholds and ns.package and ns.report):
        ap.error("--thresholds, --package and --report are required for check/update")
    if ns.command == "update":
        return cmd_update(ns.thresholds, ns.package, ns.report)
    return cmd_check(ns.thresholds, ns.package, ns.report)


if __name__ == "__main__":
    raise SystemExit(main())
