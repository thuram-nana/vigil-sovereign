"""
imports.cli — ``python3 -m framework.v2 imports``.

Import a third-party tool's export into the world-model as leads, from the command
line (the daemon-free path). Reads the export from a file or stdin, parses it, mints
GROUNDING_INTEL leads, and prints the ``ImportResult`` as JSON. Persistence to the
durable intel store is OPT-IN (``--persist``) so a dry inspection touches nothing.
"""

from __future__ import annotations

import argparse
import json
import sys

from .importer import import_report
from .models import ImportAdapterError
from .parsers import available_formats, detect_format


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 imports",
        description="Import a third-party tool export (Nuclei/ZAP/Burp/sqlmap/generic) into "
                    "the world-model as GROUNDING_INTEL leads (never facts).",
    )
    parser.add_argument("file", nargs="?", default="-",
                        help="Export file to import (default: stdin).")
    parser.add_argument("--format", "-f", default="",
                        help=f"Export format (one of: {', '.join(available_formats())}). "
                             "Omit to auto-detect.")
    parser.add_argument("--source-tool", default="",
                        help="Provenance label for the leads (defaults to the format).")
    parser.add_argument("--slug", default="",
                        help="Engagement slug to associate the leads with (for --persist).")
    parser.add_argument("--persist", action="store_true",
                        help="Persist the leads to the durable intel store (default: dry, "
                             "in-memory only).")
    args = parser.parse_args(argv)

    try:
        raw = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8").read()
    except OSError as e:
        print(f"error: could not read {args.file}: {e}", file=sys.stderr)
        return 2

    fmt = (args.format or "").strip().lower() or (detect_format(raw) or "")
    if not fmt:
        print("error: could not auto-detect format; pass --format", file=sys.stderr)
        return 2

    store = None
    if args.persist:
        try:
            from ..intel.store import IntelStore
            from ..memory.store import Store
            store = IntelStore(Store())
        except Exception as e:  # noqa: BLE001
            print(f"warning: persistence unavailable ({e}); importing in-memory only",
                  file=sys.stderr)

    try:
        result = import_report(fmt, raw, store=store, engagement_slug=args.slug,
                               source_tool=(args.source_tool or None))
    except ImportAdapterError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3

    print(json.dumps(result.model_dump(), indent=2, default=str))
    return 0
