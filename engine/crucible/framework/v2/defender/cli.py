"""
defender.cli — `python3 -m framework.v2 defender <subcommand>`.

Subcommands:

    score    --kind K [--surface S] [--method M] [--requests N]
             [--attr k=v ...] [--ruleset path]
                 Self-detection score for one action.

    annotate --kind K --posture TEST|EMULATE [...as score...]
                 Detectability plus posture-appropriate, defensive-only
                 guidance.

    rules    [--ruleset path]
                 List the active detection rules.

Defensive only: this surface reports footprint. It never emits an
evasion payload.
"""

from __future__ import annotations

import argparse
import json

from .models import ActionDescriptor, ActionKind, Posture
from .posture import annotate_action
from .rules import DetectionRuleset, default_ruleset
from .scoring import score_action


def _descriptor(args: argparse.Namespace) -> ActionDescriptor:
    attributes: dict[str, str] = {}
    for pair in args.attr or []:
        if "=" not in pair:
            raise SystemExit(f"--attr expects k=v, got {pair!r}")
        k, v = pair.split("=", 1)
        attributes[k.strip()] = v.strip()
    return ActionDescriptor(
        kind=ActionKind(args.kind),
        target_surface=args.surface,
        method=args.method,
        requests=args.requests,
        attributes=attributes,
    )


def _ruleset(args: argparse.Namespace) -> DetectionRuleset:
    return DetectionRuleset.from_file(args.ruleset) if args.ruleset else default_ruleset()


def _score(args: argparse.Namespace) -> int:
    score = score_action(_descriptor(args), _ruleset(args))
    print(json.dumps(score.model_dump(mode="json"), indent=2))
    return 0


def _annotate(args: argparse.Namespace) -> int:
    annotation = annotate_action(_descriptor(args), Posture(args.posture), _ruleset(args))
    print(json.dumps(annotation.model_dump(mode="json"), indent=2))
    return 0


def _rules(args: argparse.Namespace) -> int:
    rs = _ruleset(args)
    print(json.dumps([r.model_dump(mode="json") for r in rs.rules], indent=2))
    return 0


def _add_action_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--kind", required=True, choices=[k.value for k in ActionKind])
    p.add_argument("--surface", default="")
    p.add_argument("--method", default="GET")
    p.add_argument("--requests", type=int, default=1)
    p.add_argument("--attr", action="append", default=[], help="k=v (repeatable)")
    p.add_argument("--ruleset", default="")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 defender",
        description="DEL (defensive subset) — model telemetry and self-detection.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("score", help="self-detection score for one action")
    _add_action_args(p)
    p.set_defaults(fn=_score)

    p = sub.add_parser("annotate", help="score plus posture guidance")
    _add_action_args(p)
    p.add_argument("--posture", required=True, choices=[x.value for x in Posture])
    p.set_defaults(fn=_annotate)

    p = sub.add_parser("rules", help="list active detection rules")
    p.add_argument("--ruleset", default="")
    p.set_defaults(fn=_rules)

    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    fn = args.fn  # type: ignore[attr-defined]
    return int(fn(args))


if __name__ == "__main__":  # pragma: no cover
    import sys

    sys.exit(main(sys.argv[1:]))
