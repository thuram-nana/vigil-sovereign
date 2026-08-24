#!/usr/bin/env python3
"""Fail-closed tool preflight for the live-fire scripts (W11-2).

A live-fire run whose required tool is ABSENT cannot prove anything, so a run that cannot run must not
report success. The older path TOLERATED a missing tool: ``livefire-full`` set
``VIGIL_LIVEFIRE_ALLOW_MISSING`` and the exposed-secret live-fire SKIPPED cleanly when ``gh`` was absent
— a green run that measured nothing. This preflight makes a missing REQUIRED tool a HARD FAILURE: it
names every required binary that is not resolvable on PATH and exits non-zero, UNLESS the tool is
explicitly acknowledged as optional (``allow_missing``), which is the only way a run may proceed without
it and is reported, never silent.

It is deliberately PURE and stdlib-only (``shutil``/``os``/``sys``) so it is deterministically
falsifiable in required CI: point it at a binary that certainly does not exist and it MUST go red — that
is the negative control the scheduled live-fire jobs rely on to know the gate is not a no-op.

CLI::

    require_tools.py docker python3 git                       # each must be present, or exit non-zero
    require_tools.py --allow-missing zaproxy nmap zaproxy     # zaproxy absent is acknowledged, not fatal
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from typing import Iterable, List, Sequence


def _normalize(names: Iterable[str]) -> List[str]:
    """Trimmed, non-empty tool names, order preserved."""
    return [n.strip() for n in names if n and n.strip()]


def missing_tools(required: Iterable[str], allow_missing: Iterable[str] = ()) -> List[str]:
    """The sorted, de-duplicated list of REQUIRED tools not resolvable on PATH, excluding any tool
    explicitly acknowledged in ``allow_missing``.

    Pure: it resolves names with ``shutil.which`` and neither spawns a process nor mutates state, which
    is what lets the test battery exercise it against a deliberately-absent binary without side effects.
    """
    allow = {n.lower() for n in _normalize(allow_missing)}
    absent = set()
    for name in _normalize(required):
        if name.lower() in allow:
            continue
        if shutil.which(name) is None:
            absent.add(name)
    return sorted(absent)


def require_tools(required: Iterable[str], allow_missing: Iterable[str] = ()) -> bool:
    """Fail closed on a missing required tool.

    Returns ``True`` when every required tool is present (or explicitly acknowledged). Otherwise it
    prints a GitHub-annotated ``::error::`` line per missing tool and raises ``SystemExit`` with a
    non-zero code. It never returns as if a run may proceed when a required binary is absent — that
    return-instead-of-raise is exactly the toleration this gate exists to remove.
    """
    absent = missing_tools(required, allow_missing)
    if absent:
        for name in absent:
            print(
                f"::error::required tool {name!r} is not installed — the live-fire cannot be proven "
                "without it, and a run that cannot run must not report success",
                file=sys.stderr,
            )
        raise SystemExit("live-fire preflight FAILED: missing required tool(s): " + ", ".join(absent))
    return True


def _parse_allow_missing(values: Sequence[str] | None) -> List[str]:
    """``--allow-missing`` accepts repetition and comma lists, and also honours the same
    ``VIGIL_LIVEFIRE_ALLOW_MISSING`` env var the table driver uses, so one acknowledgement covers both.
    """
    out: List[str] = []
    for v in values or []:
        out.extend(p for p in v.split(",") if p.strip())
    env = os.environ.get("VIGIL_LIVEFIRE_ALLOW_MISSING", "")
    out.extend(p for p in env.split(",") if p.strip())
    return out


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="fail closed on a missing required live-fire tool (W11-2)")
    parser.add_argument("tools", nargs="+", help="required tool names (all must be on PATH)")
    parser.add_argument(
        "--allow-missing", action="append", default=[],
        help="tool(s) acknowledged as optional, so their absence is reported not fatal "
             "(comma-separated or repeated)")
    args = parser.parse_args(argv)
    allow = _parse_allow_missing(args.allow_missing)
    require_tools(args.tools, allow)  # raises SystemExit(non-zero) on any missing required tool
    present = ", ".join(sorted({t.strip() for t in args.tools if t.strip()}))
    print(f"preflight OK — every required tool is present: {present}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
