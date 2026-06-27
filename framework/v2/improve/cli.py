"""
improve.cli — `python3 -m framework.v2 improve <subcommand>`.

Subcommands:

    review   --snapshot <snapshot.json> [--min-priority N] [--out-dir D]
                 Mine an engagement snapshot for capability gaps and draft
                 reviewable proposals.

    horizon  --feed <feed.json> [--min-priority N] [--out-dir D]
                 Fold a CVE/technique feed into gaps and draft proposals.

    show     --proposal <path>
                 Render a proposal's human-review markdown.

SIL writes proposals to its own area and never to the framework's canon.
Authorising a merge is a separate, key-gated act (see merge_gate).
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from ..common.errors import EvalError
from .horizon import ingest_horizon, load_horizon_feed
from .models import EngagementSnapshot, ImprovementProposal
from .patcher import draft_proposals, render_proposal_markdown
from .reviewer import review_snapshot
from .store import load_proposal, save_gaps, save_proposals


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _load_snapshot(path: str) -> EngagementSnapshot:
    p = Path(path).expanduser()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise EvalError(f"cannot read snapshot {p}: {e}") from e
    except json.JSONDecodeError as e:
        raise EvalError(f"snapshot {p} is not valid JSON: {e}") from e
    try:
        return EngagementSnapshot.model_validate(data)
    except ValidationError as e:
        raise EvalError(f"snapshot {p} is not a valid EngagementSnapshot: {e}") from e


def _emit(gaps_len: int, proposals: list[ImprovementProposal], out_dir: str) -> int:
    paths_written = save_proposals(proposals, out_dir or None)
    print(json.dumps(
        {
            "gaps": gaps_len,
            "proposals": len(proposals),
            "written": [str(p) for p in paths_written],
        },
        indent=2,
    ))
    return 0


def _review(args: argparse.Namespace) -> int:
    snapshot = _load_snapshot(args.snapshot)
    now = _now()
    gaps = review_snapshot(snapshot, now=now)
    save_gaps(gaps, None)
    proposals = draft_proposals(gaps, now=now, min_priority=args.min_priority)
    return _emit(len(gaps), proposals, args.out_dir)


def _horizon(args: argparse.Namespace) -> int:
    items = load_horizon_feed(args.feed)
    now = _now()
    gaps = ingest_horizon(items, now=now)
    save_gaps(gaps, None)
    proposals = draft_proposals(gaps, now=now, min_priority=args.min_priority)
    return _emit(len(gaps), proposals, args.out_dir)


def _show(args: argparse.Namespace) -> int:
    proposal = load_proposal(args.proposal)
    print(render_proposal_markdown(proposal))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 improve",
        description="SIL — mine gaps and draft reviewable improvement proposals.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("review", help="mine an engagement snapshot for gaps")
    p.add_argument("--snapshot", required=True)
    p.add_argument("--min-priority", type=int, default=0)
    p.add_argument("--out-dir", default="")
    p.set_defaults(fn=_review)

    p = sub.add_parser("horizon", help="fold a CVE/technique feed into gaps")
    p.add_argument("--feed", required=True)
    p.add_argument("--min-priority", type=int, default=0)
    p.add_argument("--out-dir", default="")
    p.set_defaults(fn=_horizon)

    p = sub.add_parser("show", help="render a proposal's review markdown")
    p.add_argument("--proposal", required=True)
    p.set_defaults(fn=_show)

    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    fn = args.fn  # type: ignore[attr-defined]
    return int(fn(args))


if __name__ == "__main__":  # pragma: no cover
    import sys

    sys.exit(main(sys.argv[1:]))
