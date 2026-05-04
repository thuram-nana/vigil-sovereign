"""
memory.cli — `python3 -m framework.v2 memory <subcommand>`.

Subcommands:

    status                    row counts and DB path
    seed --slug <name>        seed from a v1 target (mrbeanpanel only for now)
    similar --text "..."      similar past engagements by cosine
    wins --archetype "..."    confirmed hypotheses for an archetype
    payloads --bug-class X    successful-payload priors
    priors --archetype "..."  archetype priors ranked
    postmortem --slug <name>  generate postmortem for an engagement
"""

from __future__ import annotations

import argparse
import json
import sys

from . import postmortem, priors, recall
from .store import open_store


def _status(_args: argparse.Namespace) -> int:
    with open_store() as s:
        summary = s.engagement_summary()
        print(json.dumps({"db": str(s.path), "rows": summary}, indent=2))
    return 0


def _seed(args: argparse.Namespace) -> int:
    if args.slug != "mrbeanpanel":
        print(f"error: only --slug mrbeanpanel is supported in this session "
              f"(got {args.slug!r})", file=sys.stderr)
        return 2
    from . import seed_mrbeanpanel
    with open_store() as s:
        stats = seed_mrbeanpanel.seed(s)
    print(json.dumps(stats, indent=2, default=str))
    return 0


def _similar(args: argparse.Namespace) -> int:
    with open_store() as s:
        results = recall.similar_targets(s, text=args.text, limit=args.limit)
    out = [
        {
            "score": round(r.score, 4),
            "slug": r.slug,
            "archetype": r.archetype,
            "target_url": r.target_url,
            "engagement_id": r.provenance.engagement_id,
        }
        for r in results
    ]
    print(json.dumps(out, indent=2))
    return 0


def _wins(args: argparse.Namespace) -> int:
    with open_store() as s:
        rs = recall.winning_hypotheses(
            s, archetype=args.archetype, bug_class=args.bug_class or "",
            text=args.text or "", limit=args.limit,
        )
    out = [
        {
            "score": round(r.score, 4),
            "handle": r.handle,
            "bug_class": r.bug_class,
            "surface": r.surface,
            "engagement_slug": r.provenance.engagement_slug,
            "summary": r.summary,
        }
        for r in rs
    ]
    print(json.dumps(out, indent=2))
    return 0


def _payloads(args: argparse.Namespace) -> int:
    with open_store() as s:
        rs = recall.payload_priors(
            s, bug_class=args.bug_class, archetype=args.archetype or "",
            limit=args.limit,
        )
    out = [
        {
            "score": round(r.score, 3),
            "successes": r.success_count,
            "attempts": r.outcome_count,
            "payload": r.payload_text,
            "surface": r.target_surface,
            "archetype": r.archetype,
        }
        for r in rs
    ]
    print(json.dumps(out, indent=2))
    return 0


def _priors(args: argparse.Namespace) -> int:
    with open_store() as s:
        rows = priors.top_priors_for(s, archetype=args.archetype, limit=args.limit)
    out = [
        {
            "archetype": p.archetype, "bug_class": p.bug_class,
            "surface_pattern": p.surface_pattern,
            "successes": p.successes, "attempts": p.attempts,
            "mean": round(p.mean, 3), "lower_bound_95": round(p.lower_bound, 3),
        }
        for p in rows
    ]
    print(json.dumps(out, indent=2))
    return 0


def _postmortem(args: argparse.Namespace) -> int:
    with open_store() as s:
        path = postmortem.run(s, args.slug)
    print(str(path))
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 memory",
        description="MLS — query the memory & learning substrate.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("status", help="row counts and DB path")
    p.set_defaults(fn=_status)

    p = sub.add_parser("seed", help="seed from a v1 target")
    p.add_argument("--slug", required=True)
    p.set_defaults(fn=_seed)

    p = sub.add_parser("similar", help="similar past engagements")
    p.add_argument("--text", required=True)
    p.add_argument("--limit", type=int, default=5)
    p.set_defaults(fn=_similar)

    p = sub.add_parser("wins", help="confirmed hypotheses for an archetype")
    p.add_argument("--archetype", default="")
    p.add_argument("--bug-class", default="")
    p.add_argument("--text", default="")
    p.add_argument("--limit", type=int, default=10)
    p.set_defaults(fn=_wins)

    p = sub.add_parser("payloads", help="successful-payload priors")
    p.add_argument("--bug-class", required=True)
    p.add_argument("--archetype", default="")
    p.add_argument("--limit", type=int, default=10)
    p.set_defaults(fn=_payloads)

    p = sub.add_parser("priors", help="archetype priors ranked")
    p.add_argument("--archetype", required=True)
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(fn=_priors)

    p = sub.add_parser("postmortem", help="run engagement postmortem")
    p.add_argument("--slug", required=True)
    p.set_defaults(fn=_postmortem)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
