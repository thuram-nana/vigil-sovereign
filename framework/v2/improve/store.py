"""
improve.store — persist gaps and reviewable proposals.

SIL writes only to its own writable area (`framework/v2/.improve/`,
gitignored). It never writes to the framework's canon — that is what the
merge gate plus a human apply step are for. Proposals are written as
both a JSON record (machine-readable, signable) and a markdown writeup
(human review).
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from ..common import paths
from ..common.errors import EvalError
from .models import CapabilityGap, ImprovementProposal
from .patcher import render_proposal_markdown


def save_gaps(gaps: list[CapabilityGap], path: str | Path | None = None) -> Path:
    p = Path(path).expanduser() if path is not None else paths.gaps_dir() / "gaps.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps([g.model_dump(mode="json") for g in gaps], indent=2),
        encoding="utf-8",
    )
    return p


def save_proposal(proposal: ImprovementProposal, directory: str | Path | None = None) -> Path:
    d = Path(directory).expanduser() if directory is not None else paths.proposals_dir()
    d.mkdir(parents=True, exist_ok=True)
    json_path = d / f"{proposal.id}.json"
    md_path = d / f"{proposal.id}.md"
    json_path.write_text(
        json.dumps(proposal.model_dump(mode="json"), indent=2), encoding="utf-8"
    )
    md_path.write_text(render_proposal_markdown(proposal), encoding="utf-8")
    return json_path


def load_proposal(path: str | Path) -> ImprovementProposal:
    p = Path(path).expanduser()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise EvalError(f"cannot read proposal {p}: {e}") from e
    except json.JSONDecodeError as e:
        raise EvalError(f"proposal {p} is not valid JSON: {e}") from e
    try:
        return ImprovementProposal.model_validate(data)
    except ValidationError as e:
        raise EvalError(f"proposal {p} is not a valid ImprovementProposal: {e}") from e


def save_proposals(
    proposals: list[ImprovementProposal], directory: str | Path | None = None
) -> list[Path]:
    return [save_proposal(p, directory) for p in proposals]
