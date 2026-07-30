"""P2 — a deterministic confidence-calibration report + reliability diagram over the oracle-confirmed corpus.

Reuses the existing calibration math (``reliability_report`` → ECE + Brier + reliability bins). The report
is what makes the tool's OWN accuracy honest and visible: a well-calibrated detector has predicted ≈ observed
in every bin.

INVARIANT (load-bearing): calibration ONLY re-scores the *displayed* confidence of already-graded findings.
It NEVER promotes a lead to a fact and NEVER feeds the oracle / SCE / calibration-of-record inputs — a fired
deterministic oracle remains the sole authority for a FACT. This module reads outcomes and reports; it changes
no grade.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from .calibrate import reliability_report
from .models import CalibrationReport, Outcome, Prediction

_INVARIANT = ("calibration re-scores DISPLAYED confidence only — it never promotes a lead to a fact and "
              "never feeds the oracle/SCE inputs; a fired deterministic oracle is the sole authority for a fact.")


def report_from_pairs(pairs: Iterable[tuple[Prediction, Outcome]], *, n_bins: int = 10) -> dict:
    """Build the calibration report dict (n, ece, brier, reliability bins) from labelled prediction/outcome
    pairs. Pure + deterministic (no wallclock/rng); the raw-score reliability (calibrator=None)."""
    rep: CalibrationReport = reliability_report(list(pairs), None, n_bins=n_bins)
    d = rep.model_dump()
    d["invariant"] = _INVARIANT
    return d


def report_from_ledger(ledger_path: str | Path, *, n_bins: int = 10) -> dict:
    """Load an OutcomeLedger JSON and report its calibration. An absent/unreadable ledger yields an honest
    empty report (n=0), never an error."""
    try:
        from .ledger import OutcomeLedger
        led = OutcomeLedger.load(ledger_path)
        pairs = led.pairs()
    except Exception:  # noqa: BLE001 — no/invalid ledger ⇒ empty, honest report
        pairs = []
    return report_from_pairs(pairs, n_bins=n_bins)


def render_markdown(report: dict) -> str:
    """A readable reliability table + the ECE/Brier headline + the honesty invariant."""
    n = report.get("n", 0)
    lines = [
        "# Confidence calibration report",
        "",
        f"**n = {n}**  ·  **ECE = {report.get('ece', 0.0):.4f}**  ·  **Brier = {report.get('brier', 0.0):.4f}**  "
        "(lower is better; a perfectly calibrated detector has predicted ≈ observed in every bin)",
        "",
        "| bin | range | count | mean predicted | observed rate | gap |",
        "|---|---|---|---|---|---|",
    ]
    for b in report.get("bins", []):
        gap = abs(float(b.get("mean_pred", 0.0)) - float(b.get("mean_actual", 0.0)))
        lines.append(f"| {b['index']} | {b['lower']:.1f}–{b['upper']:.1f} | {b['count']} | "
                     f"{b['mean_pred']:.3f} | {b['mean_actual']:.3f} | {gap:.3f} |")
    if not report.get("bins"):
        lines.append("| — | — | 0 | — | — | — |")
    lines += ["", f"> {report.get('invariant', _INVARIANT)}"]
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    """CLI: ``calibration report [--ledger PATH] [--json OUT] [--bins N]`` — print the reliability table."""
    import argparse
    import json

    ap = argparse.ArgumentParser(prog="python3 -m framework.v2 calibration",
                                 description="Confidence-calibration report over the oracle-confirmed corpus.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("report", help="print the reliability diagram (ECE + Brier + bins) for a ledger")
    r.add_argument("--ledger", default=None, help="OutcomeLedger JSON path (default: an empty report)")
    r.add_argument("--json", default=None, help="also write the report JSON to this path")
    r.add_argument("--bins", type=int, default=10)
    args = ap.parse_args(argv)

    report = report_from_ledger(args.ledger, n_bins=args.bins) if args.ledger else report_from_pairs([], n_bins=args.bins)
    print(render_markdown(report))
    if args.json:
        Path(args.json).expanduser().write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                                encoding="utf-8")
        print(f"wrote {args.json}")
    return 0
