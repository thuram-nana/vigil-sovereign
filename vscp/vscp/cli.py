"""Minimal VSCP CLI (W13-7 / #500) — a thin operational surface over the skeleton.

Subcommands:
  * ``vscp-ctl doctor``          — resolve config, print the isolated paths, and run the
                                   import-isolation self-scan (non-zero exit on any breach).
  * ``vscp-ctl routes``          — print the route -> permission table with reviewer access.
  * ``vscp-ctl migrate``         — open the VSCP store, applying migrations, and list them.

Stdlib + VSCP only; no product import. This is intentionally small — the fuller admin
surface is staged (see ROADMAP.md).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .config import VscpConfig, VscpIsolationError, product_data_roots
from .isolation import scan_tree_for_import_violations
from .rbac_routes import audit_routes, reviewer_readonly_report


def _cmd_doctor(_args: argparse.Namespace) -> int:
    try:
        cfg = VscpConfig.resolve()
    except VscpIsolationError as exc:
        print(f"ISOLATION ERROR: {exc}", file=sys.stderr)
        return 2
    print("VSCP isolated paths:")
    print(f"  data_dir         = {cfg.data_dir}")
    print(f"  db_path          = {cfg.db_path}")
    print(f"  signing_key_path = {cfg.signing_key_path}")
    print("product data roots kept out of:")
    for r in sorted(product_data_roots()):
        print(f"  - {r}")
    pkg_root = Path(__file__).resolve().parent
    violations = scan_tree_for_import_violations(pkg_root)
    if violations:
        print("\nIMPORT ISOLATION BREACHES:", file=sys.stderr)
        for v in violations:
            print(f"  {v.file}: {v.reason}", file=sys.stderr)
        return 1
    print("\nimport isolation: OK (no forbidden or off-allowlist imports)")
    return 0


def _cmd_routes(_args: argparse.Namespace) -> int:
    for a in audit_routes():
        flag = "reviewer" if a.reviewer_allowed else "gated"
        print(f"  {a.method:6} {a.path:40} perm={a.permission!s:16} [{flag}]")
    errs = reviewer_readonly_report()
    if errs:
        print("\nREVIEWER READ-ONLY VIOLATIONS:", file=sys.stderr)
        for e in errs:
            print(f"  {e}", file=sys.stderr)
        return 1
    print("\nreviewer read-only: OK (every mutating route is above the reviewer)")
    return 0


def _cmd_migrate(_args: argparse.Namespace) -> int:
    from .store import open_store

    try:
        cfg = VscpConfig.resolve()
    except VscpIsolationError as exc:
        print(f"ISOLATION ERROR: {exc}", file=sys.stderr)
        return 2
    cfg.ensure_data_dir()
    with open_store(cfg) as store:
        print(f"store: {store.db_path}")
        for m in store.applied_migrations():
            print(f"  applied: {m}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vscp-ctl", description="VIGIL Sovereign Control Plane (skeleton)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor", help="print isolated paths + run the import-isolation self-scan")
    sub.add_parser("routes", help="print the route->permission table + reviewer read-only check")
    sub.add_parser("migrate", help="open the VSCP store, applying migrations")
    args = parser.parse_args(argv)
    return {"doctor": _cmd_doctor, "routes": _cmd_routes, "migrate": _cmd_migrate}[args.cmd](args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
