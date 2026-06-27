"""
socialdefense.cli — `python3 -m framework.v2 socialdefense <subcommand>`.

    assess --message <file.json>
        Score an inbound message (JSON MessageArtifact) for
        social-engineering indicators. Exits 1 for HIGH/CRITICAL so it is
        usable as a mail-pipeline gate.

Defensive only: it reads a message you received and reports risk. It
sends nothing and generates no content.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import ValidationError

from ..common.errors import CrucibleError
from .detectors import assess_message
from .models import MessageArtifact, RiskBand


class SocialDefenseError(CrucibleError):
    """Malformed message artifact."""


def _load_message(path: str) -> MessageArtifact:
    p = Path(path).expanduser()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise SocialDefenseError(f"cannot read message {p}: {e}") from e
    try:
        return MessageArtifact.model_validate(data)
    except ValidationError as e:
        raise SocialDefenseError(f"{p} is not a valid message artifact: {e}") from e


def _assess(args: argparse.Namespace) -> int:
    assessment = assess_message(_load_message(args.message))
    print(json.dumps(assessment.model_dump(mode="json"), indent=2))
    return 1 if assessment.band in (RiskBand.HIGH, RiskBand.CRITICAL) else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 socialdefense",
        description="Defensive detection of inbound social-engineering.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("assess", help="score an inbound message (exit 1 on high/critical)")
    p.add_argument("--message", required=True)
    p.set_defaults(fn=_assess)
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    fn = args.fn  # type: ignore[attr-defined]
    return int(fn(args))


if __name__ == "__main__":  # pragma: no cover
    import sys

    sys.exit(main(sys.argv[1:]))
