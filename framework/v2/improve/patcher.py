"""
improve.patcher — turn capability gaps into reviewable proposals.

The patcher maps each gap to a precise, reviewable `ImprovementProposal`
describing *what* should change and *where*. It does NOT fabricate code
diffs and never self-applies anything: a proposal's `patch` is left
empty (described-only) unless a human or a future LLM binding fills it,
and even a filled patch is only ever *authorised* by the merge gate, then
applied by a human. Emitting a described-only proposal is honest — it
states the change precisely without pretending to have written code it
did not write.

Mapping is deterministic so the same gaps yield the same proposals.
"""

from __future__ import annotations

from datetime import datetime

from .models import (
    CapabilityGap,
    GapKind,
    ImprovementProposal,
    ProposedChange,
)


def _slugify(raw: str) -> str:
    out = "".join(ch if ch.isalnum() else "-" for ch in raw.strip().lower())
    while "--" in out:
        out = out.replace("--", "-")
    return out.strip("-") or "unspecified"


def _change_for(gap: CapabilityGap) -> ProposedChange:
    bug_slug = _slugify(gap.bug_class) if gap.bug_class else "unspecified"

    if gap.kind is GapKind.COVERAGE_GAP:
        return ProposedChange(
            target_artifact=f"framework/knowledge-base/attack-techniques/{bug_slug}.md",
            change_type="add_technique",
            summary=(
                f"Extend hypothesis generation so the {gap.bug_class!r} class is "
                f"proposed for this archetype. Add/clarify the technique note and a "
                f"generation cue so the kernel stops blind-spotting it."
            ),
        )
    if gap.kind is GapKind.UNREACHED_SURFACE:
        return ProposedChange(
            target_artifact="framework/playbooks/03-surface-mapping.md",
            change_type="extend_playbook",
            summary=(
                f"Ensure surface enumeration reaches {gap.surface!r}-shaped endpoints; "
                f"this surface was discovered but never fed into hypothesis generation."
            ),
        )
    if gap.kind is GapKind.UNREACHED_HYPOTHESIS:
        return ProposedChange(
            target_artifact="framework/v2/planner/planner.py",
            change_type="code_fix",
            summary=(
                "Investigate planner prioritisation/budget so open hypotheses are not "
                "left unexecuted. Either raise the budget signal or fix the ranking "
                "that deprioritised this thread."
            ),
        )
    if gap.kind is GapKind.REFUTED_THREAD:
        return ProposedChange(
            target_artifact=f"framework/knowledge-base/attack-techniques/{bug_slug}.md",
            change_type="add_technique",
            summary=(
                f"A {gap.bug_class!r} thread was refuted; if the class is plausible "
                f"here, add a sharper technique variant the executor can try next time."
            ),
        )
    # HORIZON
    return ProposedChange(
        target_artifact=f"signatures/{_slugify(gap.title)}.yaml",
        change_type="add_signature",
        summary=(
            f"Add a detection signature/technique for this disclosure so the framework "
            f"tests for it going forward. {gap.description}"
        ),
    )


def draft_proposals(
    gaps: list[CapabilityGap],
    *,
    now: datetime,
    min_priority: int = 0,
) -> list[ImprovementProposal]:
    """One proposal per gap at or above `min_priority`, highest priority
    first. Deterministic: stable proposal ids derived from gap ids."""
    selected = sorted(
        (g for g in gaps if g.priority >= min_priority),
        key=lambda g: (-g.priority, g.id),
    )
    proposals: list[ImprovementProposal] = []
    for gap in selected:
        proposals.append(
            ImprovementProposal(
                id=f"prop-{gap.id}",
                title=gap.title,
                rationale=gap.description,
                gap_ids=[gap.id],
                change=_change_for(gap),
                created_at=now,
            )
        )
    return proposals


def render_proposal_markdown(proposal: ImprovementProposal) -> str:
    """Human-reviewable writeup of a proposal."""
    lines = [
        f"# Improvement proposal: {proposal.id}",
        "",
        f"**Title:** {proposal.title}",
        f"**Status:** {proposal.status.value}",
        f"**Created:** {proposal.created_at.isoformat()}",
        f"**Closes gaps:** {', '.join(proposal.gap_ids) or '—'}",
        f"**Content digest:** `{proposal.content_digest()}`",
        "",
        "## Rationale",
        "",
        proposal.rationale or "_(none)_",
        "",
        "## Proposed change",
        "",
        f"- **Target:** `{proposal.change.target_artifact}`",
        f"- **Type:** {proposal.change.change_type}",
        f"- **Summary:** {proposal.change.summary}",
        "",
    ]
    if proposal.change.patch:
        lines += ["## Patch", "", "```diff", proposal.change.patch, "```", ""]
    else:
        lines += [
            "## Patch",
            "",
            "_Described-only. No diff was authored by SIL; a human or an LLM "
            "binding implements the change, the eval harness scores it, and the "
            "merge gate authorises it before a human applies it._",
            "",
        ]
    return "\n".join(lines)
