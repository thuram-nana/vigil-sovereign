"""
analysis.cli — `python3 -m framework.v2 analysis <subcommand>`.

Subcommands:

    scan       --root <path> [--ext .py ...] [--max-files N]
                   Run the analyzers over a tree and print findings.

    index      --root <path> [--symbols]
                   Build the Python symbol index; print a summary (or the
                   full symbol list with --symbols).

    analyzers  Show which analyzers are available on this host.

DAA is the deep-sensing layer; scanning is gated on
DEEP_STATIC_ANALYSIS under an enforced deployment.
"""

from __future__ import annotations

import argparse
import json

from .index import build_symbol_index
from .models import AnalysisTarget, DEFAULT_EXTENSIONS
from .orchestrator import default_analyzers, run_analysis


def _target(args: argparse.Namespace) -> AnalysisTarget:
    exts = tuple(args.ext) if args.ext else DEFAULT_EXTENSIONS
    return AnalysisTarget(root=args.root, extensions=exts, max_files=args.max_files)


def _scan(args: argparse.Namespace) -> int:
    report = run_analysis(_target(args))
    print(json.dumps(
        {
            "root": report.root,
            "files_scanned": report.files_scanned,
            "analyzers_run": report.analyzers_run,
            "analyzers_skipped": [s.model_dump() for s in report.analyzers_skipped],
            "severity_counts": report.severity_counts(),
            "findings": [f.model_dump() for f in report.findings],
        },
        indent=2,
    ))
    # Exit non-zero if any high/critical finding — usable as a gate.
    worst = {f.severity for f in report.findings}
    return 1 if ("high" in worst or "critical" in worst) else 0


def _index(args: argparse.Namespace) -> int:
    idx = build_symbol_index(_target(args))
    payload: dict[str, object] = {
        "files_indexed": idx.files_indexed,
        "summary": idx.summary(),
        "parse_errors": idx.parse_errors,
    }
    if args.symbols:
        payload["symbols"] = [s.model_dump() for s in idx.symbols]
    print(json.dumps(payload, indent=2))
    return 0


def _analyzers(_args: argparse.Namespace) -> int:
    rows = []
    for a in default_analyzers():
        available, reason = a.is_available()
        rows.append({"name": a.name, "available": available, "reason": reason})
    print(json.dumps(rows, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 analysis",
        description="DAA — deep static analysis and symbol indexing.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="run analyzers over a tree")
    p.add_argument("--root", required=True)
    p.add_argument("--ext", action="append", default=[], help="extension filter (repeatable)")
    p.add_argument("--max-files", type=int, default=5000)
    p.set_defaults(fn=_scan)

    p = sub.add_parser("index", help="build the Python symbol index")
    p.add_argument("--root", required=True)
    p.add_argument("--ext", action="append", default=[])
    p.add_argument("--max-files", type=int, default=5000)
    p.add_argument("--symbols", action="store_true", help="print the full symbol list")
    p.set_defaults(fn=_index)

    p = sub.add_parser("analyzers", help="show analyzer availability")
    p.add_argument("--root", default=".")
    p.add_argument("--ext", action="append", default=[])
    p.add_argument("--max-files", type=int, default=5000)
    p.set_defaults(fn=_analyzers)

    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    fn = args.fn  # type: ignore[attr-defined]
    return int(fn(args))


if __name__ == "__main__":  # pragma: no cover
    import sys

    sys.exit(main(sys.argv[1:]))
