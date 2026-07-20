"""
kernel.cli — `python3 -m framework.v2 kernel <subcommand>`.

Subcommands map 1:1 to URK bindings. Each takes a small set of flags
and prints the parsed result as JSON. Useful for ad-hoc invocation
and for the operator to inspect what URK produces against a known
input.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import critique, decide, hypothesize, opsec, pivot, threat_model
from .llm import get_backend


def _dump(parsed: Any, trace: Any) -> None:
    print(json.dumps(
        {"parsed": parsed.model_dump(by_alias=True),
         "trace": trace.model_dump()},
        indent=2, default=str,
    ))


def _hypothesize(args: argparse.Namespace) -> int:
    parsed, trace = hypothesize(
        observation=args.observation,
        surface=args.surface or "",
        context=args.context or "",
    )
    _dump(parsed, trace)
    return 0


def _critique(args: argparse.Namespace) -> int:
    parsed, trace = critique(
        claim=args.claim,
        evidence=args.evidence or "",
        context=args.context or "",
    )
    _dump(parsed, trace)
    return 0


def _pivot(args: argparse.Namespace) -> int:
    parsed, trace = pivot(
        stuck_thread=args.thread,
        last_observation=args.observation or "",
        posture=args.posture,
    )
    _dump(parsed, trace)
    return 0


def _decide(args: argparse.Namespace) -> int:
    parsed, trace = decide(
        finding_summary=args.summary,
        affected_endpoint=args.endpoint or "",
        preconditions=args.preconditions or "",
        impact_observed=args.impact or "",
    )
    _dump(parsed, trace)
    return 0


def _opsec(args: argparse.Namespace) -> int:
    parsed, trace = opsec(
        action_summary=args.action,
        posture=args.posture,
        target_url=args.target or "",
        expected_traffic=args.traffic or "",
    )
    _dump(parsed, trace)
    return 0


def _threat_model(args: argparse.Namespace) -> int:
    parsed, trace = threat_model(
        target_name=args.target,
        business_context=args.context or "",
        archetype=args.archetype or "",
        known_concerns=args.concerns or [],
    )
    _dump(parsed, trace)
    return 0


def _backend(args: argparse.Namespace) -> int:
    be = get_backend()
    ok, note = be.is_available()
    print(json.dumps({"name": be.name, "available": ok, "note": note,
                      "is_dryrun": be.is_dryrun}, indent=2))
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 kernel",
        description="URK — invoke a single cognitive binding from the CLI.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("hypothesize", help="generate >=5 hypotheses")
    p.add_argument("--observation", required=True)
    p.add_argument("--surface", default="")
    p.add_argument("--context", default="")
    p.set_defaults(fn=_hypothesize)

    p = sub.add_parser("critique", help="adversarial review of a claim")
    p.add_argument("--claim", required=True)
    p.add_argument("--evidence", default="")
    p.add_argument("--context", default="")
    p.set_defaults(fn=_critique)

    p = sub.add_parser("pivot", help="propose lateral moves")
    p.add_argument("--thread", required=True)
    p.add_argument("--observation", default="")
    p.add_argument("--posture", default="TEST",
                   choices=["TEST", "AUDIT", "EMULATE"])
    p.set_defaults(fn=_pivot)

    p = sub.add_parser("decide", help="severity / report decision")
    p.add_argument("--summary", required=True)
    p.add_argument("--endpoint", default="")
    p.add_argument("--preconditions", default="")
    p.add_argument("--impact", default="")
    p.set_defaults(fn=_decide)

    p = sub.add_parser("opsec", help="posture-aware guidance for an action")
    p.add_argument("--action", required=True)
    p.add_argument("--posture", default="TEST",
                   choices=["TEST", "AUDIT", "EMULATE"])
    p.add_argument("--target", default="")
    p.add_argument("--traffic", default="")
    p.set_defaults(fn=_opsec)

    p = sub.add_parser("threat-model", help="generate a structured threat model")
    p.add_argument("--target", required=True)
    p.add_argument("--context", default="")
    p.add_argument("--archetype", default="")
    p.add_argument("--concerns", nargs="*", default=[])
    p.set_defaults(fn=_threat_model)

    p = sub.add_parser("backend", help="show the active LLM backend")
    p.set_defaults(fn=_backend)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
