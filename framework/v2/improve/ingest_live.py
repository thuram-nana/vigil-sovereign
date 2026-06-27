"""
improve.ingest_live — assemble an EngagementSnapshot from live sources.

SIL's reviewer is pure over an `EngagementSnapshot`. This adapter builds
that snapshot from the real subsystems: hypotheses and observed surfaces
from the engagement's Blackboard, and the archetype's known bug classes
from MLS. The reviewer then mines gaps from real engagement state.

Kept out of `improve/__init__` on purpose: importing it pulls the agents
and memory layers, and the SIL core must stay importable without them.

Status mapping. The blackboard tracks six hypothesis states
(open/claimed/tested/confirmed/refuted/deferred); the reviewer reasons in
three (open/confirmed/refuted). We normalize: confirmed->confirmed,
refuted->refuted, everything else->open, and mark a hypothesis executed
once it has reached tested/confirmed/refuted. So an open-or-claimed
hypothesis that never ran shows up as UNREACHED, a refuted one as a
REFUTED_THREAD, and a tested-but-inconclusive one is neither (it ran).
"""

from __future__ import annotations

from ..agents.blackboard import Blackboard, BlackboardError
from ..agents.models import HypothesisPayload, ObservationPayload
from ..memory.recall import winning_hypotheses
from ..memory.store import Store
from .models import EngagementSnapshot, HypothesisRecord

_EXECUTED_STATES = {"tested", "confirmed", "refuted"}


def _normalize_status(status: str) -> str:
    if status in ("confirmed", "refuted"):
        return status
    return "open"


def hypothesis_records(bb: Blackboard, slug: str) -> list[HypothesisRecord]:
    """Flatten the engagement's hypothesis events into reviewer records."""
    try:
        rows = bb.read(engagement=slug, kinds=["hypothesis"])
    except BlackboardError:
        return []
    out: list[HypothesisRecord] = []
    for row in rows:
        try:
            h = HypothesisPayload.model_validate(row.payload)
        except Exception:
            continue
        out.append(
            HypothesisRecord(
                handle=h.handle,
                bug_class=h.bug_class,
                surface=h.surface,
                status=_normalize_status(h.status),
                executed=h.status in _EXECUTED_STATES,
                event_id=str(row.id),
            )
        )
    return out


def discovered_surfaces(bb: Blackboard, slug: str) -> list[str]:
    """Unique surfaces observed during recon/exploitation, in first-seen order."""
    try:
        rows = bb.read(engagement=slug, kinds=["observation"])
    except BlackboardError:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for row in rows:
        try:
            obs = ObservationPayload.model_validate(row.payload)
        except Exception:
            continue
        surface = obs.surface.strip()
        if surface and surface not in seen:
            seen.add(surface)
            out.append(surface)
    return out


def archetype_bug_classes(store: Store, archetype: str) -> list[str]:
    """Bug classes MLS has confirmed for this archetype — the coverage
    yardstick. Returns [] if MLS is empty or unavailable."""
    try:
        wins = winning_hypotheses(store, archetype=archetype, limit=100)
    except Exception:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for w in wins:
        bug_class = getattr(w, "bug_class", "")
        if bug_class and bug_class not in seen:
            seen.add(bug_class)
            out.append(bug_class)
    return out


def snapshot_from_blackboard(
    bb: Blackboard,
    slug: str,
    *,
    archetype: str = "generic-web",
    store: Store | None = None,
    extra_known_classes: list[str] | None = None,
) -> EngagementSnapshot:
    """Build the reviewer's input from live engagement state. `store`
    (MLS) supplies the archetype's known bug classes; `extra_known_classes`
    augments them (e.g. from a charter or threat model)."""
    known: list[str] = []
    if store is not None:
        known.extend(archetype_bug_classes(store, archetype))
    for extra in extra_known_classes or []:
        if extra and extra not in known:
            known.append(extra)

    return EngagementSnapshot(
        slug=slug,
        archetype=archetype,
        hypotheses=hypothesis_records(bb, slug),
        discovered_surfaces=discovered_surfaces(bb, slug),
        known_archetype_bug_classes=known,
    )
