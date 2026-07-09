"""
authority.cli — `python3 -m framework.v2 authority <subcommand>`.

Subcommands:

    status    --slug S
                  Show the engagement authority and kill-switch state.

    halt      --slug S --reason "..."
                  Trip the kill-switch — the persistent hard stop. Every
                  subsequent action is refused until cleared.

    clear     --slug S --by NAME
                  Deliberately lift the halt (logged).

    authorize --slug S --target URL [--destructive] [--kind K]
                  Evaluate one action against the stored authority +
                  kill-switch. Exits 1 if denied — usable as a guard.
"""

from __future__ import annotations

import argparse
import json

from ..common import paths
from .gate import authorize_action
from .killswitch import KillSwitch
from .models import ActionRequest
from .store import load_authority


def _status(args: argparse.Namespace) -> int:
    ks = KillSwitch(args.slug)
    out: dict[str, object] = {
        "slug": args.slug,
        "kill_switch_tripped": ks.is_tripped(),
        "kill_switch_reason": ks.reason(),
    }
    try:
        authority = load_authority(args.slug)
        out["authority"] = authority.model_dump(mode="json")
    except Exception as e:  # AuthorityError or absent
        out["authority"] = None
        out["authority_error"] = str(e)
    print(json.dumps(out, indent=2))
    return 0


def _halt(args: argparse.Namespace) -> int:
    ks = KillSwitch(args.slug)
    ks.trip(args.reason)
    print(f"kill-switch TRIPPED for {args.slug!r}: {args.reason}")
    return 0


def _clear(args: argparse.Namespace) -> int:
    ks = KillSwitch(args.slug)
    if not ks.is_tripped():
        print(f"kill-switch for {args.slug!r} is not tripped")
        return 0
    ks.clear(args.by)
    print(f"kill-switch CLEARED for {args.slug!r} by {args.by}")
    return 0


def _authorize(args: argparse.Namespace) -> int:
    authority = load_authority(args.slug)
    ks = KillSwitch(args.slug)
    decision = authorize_action(
        authority,
        ActionRequest(target=args.target, action_kind=args.kind, destructive=args.destructive),
        killswitch=ks,
    )
    print(json.dumps(decision.model_dump(mode="json"), indent=2))
    return 0 if decision.allowed else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 authority",
        description="Engagement authority and the kill-switch.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("status", help="show authority + kill-switch state")
    p.add_argument("--slug", required=True)
    p.set_defaults(fn=_status)

    p = sub.add_parser("halt", help="trip the kill-switch (hard stop)")
    p.add_argument("--slug", required=True)
    p.add_argument("--reason", required=True)
    p.set_defaults(fn=_halt)

    p = sub.add_parser("clear", help="deliberately lift the halt")
    p.add_argument("--slug", required=True)
    p.add_argument("--by", required=True)
    p.set_defaults(fn=_clear)

    p = sub.add_parser("authorize", help="evaluate one action (exit 1 if denied)")
    p.add_argument("--slug", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--kind", default="generic")
    p.add_argument("--destructive", action="store_true")
    p.set_defaults(fn=_authorize)

    return parser


def main(argv: list[str]) -> int:
    paths.tighten_umask()   # X2: owner-only files even when this CLI is run standalone
    parser = build_parser()
    args = parser.parse_args(argv)
    fn = args.fn  # type: ignore[attr-defined]
    return int(fn(args))


if __name__ == "__main__":  # pragma: no cover
    import sys

    sys.exit(main(sys.argv[1:]))
