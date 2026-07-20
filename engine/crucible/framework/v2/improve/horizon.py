"""
improve.horizon — fold newly disclosed CVEs / techniques into gaps.

The horizon scanner keeps the flagship current: when a new vulnerability
class or technique is disclosed, it becomes a CapabilityGap the patcher
can turn into a proposed new signature, playbook step, or technique.

Input is a feed of `HorizonItem`s. This module does NOT fetch the feed
over the network — a live fetcher would have to pass the sovereignty
egress guard and is deferred (V2-LIMITATIONS). The operator supplies a
JSON feed file; `load_horizon_feed` validates it; `ingest_horizon`
converts items to gaps deterministically.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from ..common.errors import EvalError
from .models import CapabilityGap, GapKind, HorizonItem

_SEVERITY_PRIORITY: dict[str, int] = {
    "critical": 95,
    "high": 80,
    "medium": 60,
    "low": 40,
    "info": 20,
}


def load_horizon_feed(path: str | Path) -> list[HorizonItem]:
    """Load and validate a JSON array of HorizonItems."""
    p = Path(path).expanduser()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise EvalError(f"cannot read horizon feed {p}: {e}") from e
    except json.JSONDecodeError as e:
        raise EvalError(f"horizon feed {p} is not valid JSON: {e}") from e
    if not isinstance(data, list):
        raise EvalError("horizon feed must be a JSON array of horizon items")
    items: list[HorizonItem] = []
    for i, raw in enumerate(data):
        try:
            items.append(HorizonItem.model_validate(raw))
        except ValidationError as e:
            raise EvalError(f"horizon feed item #{i} invalid: {e}") from e
    return items


def ingest_horizon(items: list[HorizonItem], *, now: datetime) -> list[CapabilityGap]:
    """Convert horizon items to capability gaps, highest severity first."""
    gaps: list[CapabilityGap] = []
    for item in items:
        priority = _SEVERITY_PRIORITY.get(item.severity, 60)
        arch = ", ".join(item.affected_archetypes) if item.affected_archetypes else "any"
        gaps.append(
            CapabilityGap(
                id=f"gap-horizon-{item.id.lower()}",
                kind=GapKind.HORIZON,
                priority=priority,
                title=f"Horizon: {item.id} ({item.severity})",
                description=(
                    f"{item.summary} "
                    f"Bug class: {item.bug_class or 'unspecified'}. "
                    f"Affected archetypes: {arch}. "
                    f"Consider adding a signature/technique/playbook step so the "
                    f"framework tests for this going forward."
                ),
                source=f"horizon:{item.source}",
                bug_class=item.bug_class,
                evidence=[item.id, *item.references],
                discovered_at=now,
            )
        )
    gaps.sort(key=lambda g: (-g.priority, g.id))
    return gaps
