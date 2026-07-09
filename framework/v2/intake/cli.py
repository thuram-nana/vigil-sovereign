"""
intake.cli — `python3 -m framework.v2 intake [--url <url> | <url>]`.

Subcommands:

    intake <url>                run UTI against <url>
    intake authorize <url>      append an attestation to the ledger
    intake fingerprint <url>    fingerprint only — no scaffold, no MLS write
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from ..common import ethics, paths
from . import intake


def _print_outcome(outcome: object) -> None:
    print(json.dumps(outcome, indent=2, default=str))


def _run(args: argparse.Namespace) -> int:
    out = intake.run(
        args.url, slug=args.slug,
        operator_name=args.operator or "<name>",
        business_context=args.context or "",
        known_concerns=args.concern or [],
        budget=args.budget,
    )
    _print_outcome({
        "target_url": out.target_url,
        "slug": out.slug,
        "scaffold_dir": out.scaffold_dir,
        "charter_draft": out.charter_draft_path,
        "threat_model": out.threat_model_path,
        "attack_tree": out.attack_tree_path,
        "fingerprint_json": out.fingerprint_json_path,
        "request_count": out.request_count,
        "primary_archetype": {
            "slug": out.classification.primary.archetype.slug,
            "name": out.classification.primary.archetype.name,
            "score": round(out.classification.primary.score, 3),
        },
        "best_per_category": {
            cat: {"label": d.label, "confidence": d.confidence}
            for cat, d in out.fingerprint.best_per_category().items()
        },
        "notes": out.notes,
    })
    return 0


def _authorize(args: argparse.Namespace) -> int:
    """Append an attestation line to the ledger."""
    from urllib.parse import urlparse
    full = args.url if "://" in args.url else "https://" + args.url
    host = urlparse(full).hostname
    if not host:
        print(f"error: cannot parse hostname from {args.url!r}", file=sys.stderr)
        return 2

    led = ethics.authorization_ledger()
    if not led.exists():
        ethics.init_authorization_ledger()      # X2: secure_write → 0600 on fresh create

    line = f"{ethics.now_iso()} | {args.operator} | {host}\n"
    with led.open("a", encoding="utf-8") as f:
        f.write(line)
    # X2: re-tighten a pre-existing loose ledger (e.g. a pre-X2 0644 file) on every append,
    # so a leaky legacy ledger self-heals — matching the DB stores that secure_existing on
    # each connect. open("a") never re-chmods on its own.
    paths.secure_existing(led)
    print(f"appended to {led}: {line.strip()}")
    return 0


def _fingerprint_only(args: argparse.Namespace) -> int:
    """Run intake but don't scaffold or record."""
    out = intake.run(
        args.url, slug=args.slug or "tmp-fingerprint",
        operator_name="<diagnostic>", business_context="",
        budget=args.budget, record_to_memory=False,
    )
    _print_outcome({
        "target_url": out.target_url,
        "primary_archetype": {
            "slug": out.classification.primary.archetype.slug,
            "name": out.classification.primary.archetype.name,
            "score": round(out.classification.primary.score, 3),
        },
        "fingerprint": out.fingerprint.model_dump(mode="json"),
    })
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 intake",
        description="UTI — Universal Target Intake.",
    )
    sub = parser.add_subparsers(dest="cmd")

    # Default subcommand: positional URL means "run".
    p = sub.add_parser("run", help="full intake (default)")
    p.add_argument("url")
    p.add_argument("--slug", default=None)
    p.add_argument("--operator", default="<name>")
    p.add_argument("--context", default="")
    p.add_argument("--concern", action="append", default=None)
    p.add_argument("--budget", type=int, default=50)
    p.set_defaults(fn=_run)

    p = sub.add_parser("authorize", help="add an attestation to the ledger")
    p.add_argument("url")
    p.add_argument("--operator", required=True)
    p.set_defaults(fn=_authorize)

    p = sub.add_parser("fingerprint", help="fingerprint only; do not scaffold")
    p.add_argument("url")
    p.add_argument("--slug", default=None)
    p.add_argument("--budget", type=int, default=20)
    p.set_defaults(fn=_fingerprint_only)

    # Allow bare URL (treat as 'run')
    if argv and not argv[0].startswith("-") and argv[0] not in {"run", "authorize", "fingerprint"}:
        argv = ["run"] + argv

    args = parser.parse_args(argv)
    if not getattr(args, "fn", None):
        parser.print_help()
        return 2
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
