"""
improve.reviewer — mine an engagement for capability gaps.

Deterministic, LLM-free gap mining over an `EngagementSnapshot`:

  COVERAGE_GAP          a bug class MLS associates with the archetype
                        that no hypothesis this engagement even tried.
  UNREACHED_SURFACE     a discovered surface no hypothesis touched.
  UNREACHED_HYPOTHESIS  an open hypothesis that was never executed.
  REFUTED_THREAD        a thread we tried and could not confirm — a
                        candidate for a sharper technique.

These signals come straight from the blackboard event log and MLS
priors; no model call is required, which is what makes the reviewer
deterministic and offline-testable. An LLM binding that proposes
*novel* gaps (classes MLS doesn't know yet) is a future enhancement
noted in V2-LIMITATIONS — it would add gaps, never remove these.

`review_snapshot` is pure: same snapshot + same `now` -> same gaps,
with stable ids. An adapter assembles the snapshot from a live
Blackboard; that adapter is the only impure part and is kept thin.
"""

from __future__ import annotations

import hashlib
from datetime import datetime

from .models import CapabilityGap, EngagementSnapshot, GapKind

_PRIORITY: dict[GapKind, int] = {
    GapKind.COVERAGE_GAP: 80,
    GapKind.UNREACHED_SURFACE: 55,
    GapKind.UNREACHED_HYPOTHESIS: 50,
    GapKind.REFUTED_THREAD: 30,
    GapKind.HORIZON: 60,
}


def _norm(s: str) -> str:
    return "".join(ch for ch in s.strip().lower() if ch.isalnum())


def _gap_id(kind: GapKind, slug: str, key: str) -> str:
    digest = hashlib.sha256(f"{kind.value}|{slug}|{key}".encode("utf-8")).hexdigest()[:12]
    return f"gap-{kind.value}-{digest}"


def _surface_covered(surface: str, hypothesis_surfaces: list[str]) -> bool:
    ns = _norm(surface)
    if not ns:
        return True  # an empty surface is not a coverage signal
    for hs in hypothesis_surfaces:
        nh = _norm(hs)
        if nh and (nh == ns or nh in ns or ns in nh):
            return True
    return False


def review_snapshot(snapshot: EngagementSnapshot, *, now: datetime) -> list[CapabilityGap]:
    """Return capability gaps for one engagement, ordered by descending
    priority then by id for stability."""
    gaps: list[CapabilityGap] = []

    tried_classes = {_norm(h.bug_class) for h in snapshot.hypotheses if h.bug_class}
    hypothesis_surfaces = [h.surface for h in snapshot.hypotheses if h.surface]

    # 1. coverage gaps — known archetype classes we never tried
    for bug_class in snapshot.known_archetype_bug_classes:
        if _norm(bug_class) and _norm(bug_class) not in tried_classes:
            gaps.append(
                CapabilityGap(
                    id=_gap_id(GapKind.COVERAGE_GAP, snapshot.slug, _norm(bug_class)),
                    kind=GapKind.COVERAGE_GAP,
                    priority=_PRIORITY[GapKind.COVERAGE_GAP],
                    title=f"No hypothesis covered known class {bug_class!r}",
                    description=(
                        f"MLS associates bug class {bug_class!r} with archetype "
                        f"{snapshot.archetype!r}, but no hypothesis this engagement "
                        f"tested it. The framework's hypothesis generation may have "
                        f"a blind spot for this class on this archetype."
                    ),
                    source=snapshot.slug,
                    bug_class=bug_class,
                    discovered_at=now,
                )
            )

    # 2. unreached surfaces — discovered but untested
    for surface in snapshot.discovered_surfaces:
        if not _surface_covered(surface, hypothesis_surfaces):
            gaps.append(
                CapabilityGap(
                    id=_gap_id(GapKind.UNREACHED_SURFACE, snapshot.slug, _norm(surface)),
                    kind=GapKind.UNREACHED_SURFACE,
                    priority=_PRIORITY[GapKind.UNREACHED_SURFACE],
                    title=f"Discovered surface never tested: {surface}",
                    description=(
                        f"Surface {surface!r} was discovered during recon but no "
                        f"hypothesis targeted it. Attack surface left unexamined."
                    ),
                    source=snapshot.slug,
                    surface=surface,
                    discovered_at=now,
                )
            )

    # 3. unreached / refuted hypotheses
    for h in snapshot.hypotheses:
        if h.status == "open" and not h.executed:
            gaps.append(
                CapabilityGap(
                    id=_gap_id(GapKind.UNREACHED_HYPOTHESIS, snapshot.slug, h.handle),
                    kind=GapKind.UNREACHED_HYPOTHESIS,
                    priority=_PRIORITY[GapKind.UNREACHED_HYPOTHESIS],
                    title=f"Open hypothesis never executed: {h.handle}",
                    description=(
                        f"Hypothesis {h.handle!r} ({h.bug_class} on {h.surface}) was "
                        f"posted but never executed. The planner may have exhausted "
                        f"budget or deprioritised it incorrectly."
                    ),
                    source=snapshot.slug,
                    bug_class=h.bug_class,
                    surface=h.surface,
                    evidence=[h.event_id] if h.event_id else [],
                    discovered_at=now,
                )
            )
        elif h.status == "refuted":
            gaps.append(
                CapabilityGap(
                    id=_gap_id(GapKind.REFUTED_THREAD, snapshot.slug, h.handle),
                    kind=GapKind.REFUTED_THREAD,
                    priority=_PRIORITY[GapKind.REFUTED_THREAD],
                    title=f"Refuted thread, candidate for a sharper technique: {h.handle}",
                    description=(
                        f"Hypothesis {h.handle!r} ({h.bug_class} on {h.surface}) was "
                        f"refuted. If the bug class is plausible for this archetype, a "
                        f"more capable technique might confirm what this attempt could not."
                    ),
                    source=snapshot.slug,
                    bug_class=h.bug_class,
                    surface=h.surface,
                    evidence=[h.event_id] if h.event_id else [],
                    discovered_at=now,
                )
            )

    gaps.sort(key=lambda g: (-g.priority, g.id))
    return gaps
