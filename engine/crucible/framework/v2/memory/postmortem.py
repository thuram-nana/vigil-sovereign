"""
memory.postmortem — engagement-end retrospective.

Reads everything MLS recorded during an engagement and writes a
structured postmortem to targets/<slug>/postmortem.md, plus updates
archetype priors based on the engagement's outcomes.

Idempotent — running it twice produces the same content the second
time, modulo any new rows recorded between runs. Prior updates are
idempotent too: an engagement's outcomes are credited to
archetype_priors AT MOST ONCE (a per-engagement schema_meta marker), so
re-running never re-bumps a prior.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..common import paths
from . import priors
from .store import Store


@dataclass
class PostmortemSummary:
    slug: str
    engagement_id: int
    archetype: str
    findings_total: int
    findings_by_severity: dict[str, int]
    hypotheses_total: int
    hypotheses_by_status: dict[str, int]
    payloads_by_outcome: dict[str, int]
    dead_ends_total: int
    playbook_yields: list[tuple[str, int, int]]  # (playbook_id, total_yield, sample_size)


def _query_summary(store: Store, slug: str) -> PostmortemSummary:
    eid = store.engagement_id(slug)
    arch_row = store.fetchone(
        "SELECT archetype FROM engagements WHERE id=?", (eid,)
    )
    archetype = arch_row["archetype"] if arch_row else ""

    findings_rows = store.fetchall(
        "SELECT severity, COUNT(*) as c FROM findings WHERE engagement_id=? GROUP BY severity",
        (eid,),
    )
    findings_total = sum(r["c"] for r in findings_rows)
    findings_by_severity = {r["severity"]: int(r["c"]) for r in findings_rows}

    hyp_rows = store.fetchall(
        "SELECT status, COUNT(*) as c FROM hypotheses WHERE engagement_id=? GROUP BY status",
        (eid,),
    )
    hyp_total = sum(r["c"] for r in hyp_rows)
    hyp_by_status = {r["status"]: int(r["c"]) for r in hyp_rows}

    payload_rows = store.fetchall(
        "SELECT outcome, COUNT(*) as c FROM payloads WHERE engagement_id=? GROUP BY outcome",
        (eid,),
    )
    payloads_by_outcome = {r["outcome"]: int(r["c"]) for r in payload_rows}

    de_row = store.fetchone(
        "SELECT COUNT(*) as c FROM dead_ends WHERE engagement_id=?", (eid,)
    )
    dead_ends_total = int(de_row["c"]) if de_row else 0

    pb_rows = store.fetchall(
        "SELECT playbook_id, SUM(findings_yielded) AS total_yield, "
        "       COUNT(*) AS sample_size "
        "FROM playbook_outcomes WHERE engagement_id=? GROUP BY playbook_id",
        (eid,),
    )
    playbook_yields = [
        (r["playbook_id"], int(r["total_yield"] or 0), int(r["sample_size"] or 0))
        for r in pb_rows
    ]

    return PostmortemSummary(
        slug=slug, engagement_id=eid, archetype=archetype,
        findings_total=findings_total,
        findings_by_severity=findings_by_severity,
        hypotheses_total=hyp_total,
        hypotheses_by_status=hyp_by_status,
        payloads_by_outcome=payloads_by_outcome,
        dead_ends_total=dead_ends_total,
        playbook_yields=playbook_yields,
    )


def _update_priors_from_engagement(store: Store, slug: str) -> int:
    """Credit archetype_priors from THIS engagement's outcomes — each (archetype, bug_class, surface)
    exactly ONCE (success-dominant), and the whole engagement AT MOST ONCE.

    Two double-counts are fixed here (W16-STD-5):

      * WITHIN a run — a single confirmed finding is recorded BOTH as a confirmed hypothesis AND as a
        successful payload on the SAME (bug_class, surface); crediting both inflated the prior to two
        successes/attempts for one outcome (observed: webhook-forgery succ=2 att=2 after one seed).
        Outcomes are now MERGED per (bug_class, surface) key and credited once — a success anywhere on
        the key dominates a same-key attempt — so one confirmed finding is one success/attempt, matching
        the reward-bus "one credit per finding" doctrine.
      * ACROSS runs — ``postmortem.run()`` is invoked by ``seed()`` and can be re-run from the CLI /
        console; re-crediting the same engagement re-bumped the priors. A per-engagement marker in
        ``schema_meta`` makes prior application idempotent: a second run is a no-op.

    Returns the number of (bug_class, surface) keys credited (0 on a re-run or an archetype-less engagement).
    """
    eid = store.engagement_id(slug)

    # ACROSS-run idempotency: apply an engagement's priors at most once (schema_meta is a stdlib kv table).
    marker = f"priors_applied:{eid}"
    if store.fetchone("SELECT 1 FROM schema_meta WHERE key=?", (marker,)) is not None:
        return 0

    row = store.fetchone("SELECT archetype FROM engagements WHERE id=?", (eid,))
    archetype = (row["archetype"] if row is not None else "") or ""
    if not archetype:
        return 0

    # Merge every recorded outcome onto its (bug_class, surface) key; True == a success occurred on that
    # key this engagement (a success dominates a same-key attempt). Hypotheses (reasoning-level) and
    # payloads (execution-level) are two VIEWS of the same weakness on a surface, so crediting each key
    # once dedups the finding-vs-payload overlap that caused the double-count.
    outcomes: dict[tuple[str, str], bool] = {}

    for r in store.fetchall(
        "SELECT bug_class, surface, status FROM hypotheses WHERE engagement_id=?", (eid,)
    ):
        bc = r["bug_class"] or ""
        if not bc:
            continue
        key = (bc, r["surface"] or "")
        if r["status"] == "confirmed":
            outcomes[key] = True
        elif r["status"] in ("refuted", "deferred"):
            outcomes.setdefault(key, False)

    for r in store.fetchall(
        "SELECT bug_class, target_surface, outcome FROM payloads WHERE engagement_id=?", (eid,)
    ):
        bc = r["bug_class"] or ""
        if not bc:
            continue
        key = (bc, r["target_surface"] or "")
        if r["outcome"] == "success":
            outcomes[key] = True
        else:
            outcomes.setdefault(key, False)

    for (bc, surface), success in outcomes.items():
        if success:
            priors.bump_success(store, archetype, bc, surface)
        else:
            priors.bump_attempt(store, archetype, bc, surface)

    store.execute(
        "INSERT INTO schema_meta(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (marker, "1"),
    )
    store.commit()
    return len(outcomes)


def _render_markdown(s: PostmortemSummary) -> str:
    lines: list[str] = []
    lines.append(f"# Postmortem — `{s.slug}`")
    lines.append("")
    lines.append(
        f"Generated by MLS at {datetime.now(timezone.utc).isoformat(timespec='seconds')}."
    )
    lines.append(f"Archetype: `{s.archetype or '?'}`")
    lines.append("")
    lines.append("## Findings")
    if s.findings_total:
        lines.append(f"Total: **{s.findings_total}**.")
        for sev in ("Critical", "High", "Medium", "Low", "Info"):
            n = s.findings_by_severity.get(sev, 0)
            if n:
                lines.append(f"- {sev}: {n}")
    else:
        lines.append("(none recorded)")
    lines.append("")

    lines.append("## Hypotheses")
    if s.hypotheses_total:
        lines.append(f"Total: **{s.hypotheses_total}**.")
        for status, c in sorted(s.hypotheses_by_status.items()):
            lines.append(f"- {status}: {c}")
    else:
        lines.append("(none recorded)")
    lines.append("")

    lines.append("## Payloads")
    if s.payloads_by_outcome:
        for k, v in sorted(s.payloads_by_outcome.items()):
            lines.append(f"- {k}: {v}")
    else:
        lines.append("(none recorded)")
    lines.append("")

    lines.append("## Dead ends")
    lines.append(f"Recorded: **{s.dead_ends_total}**.")
    lines.append("")

    lines.append("## Playbook yield")
    if s.playbook_yields:
        for pb, y, n in s.playbook_yields:
            rate = y / n if n else 0.0
            lines.append(f"- `{pb}`: {y} findings across {n} sections (rate={rate:.2f})")
    else:
        lines.append("(no playbook outcomes recorded)")
    lines.append("")

    lines.append("## Priors updated")
    lines.append(
        "Archetype priors were updated based on hypothesis closures and payload "
        "outcomes recorded during this engagement.  See "
        "`framework/v2/.memory/store.sqlite` for the current state, or run "
        "`python3 -m framework.v2 memory priors --archetype "
        f"\"{s.archetype}\"`."
    )
    lines.append("")
    return "\n".join(lines)


def run(store: Store, slug: str) -> Path:
    """Generate the postmortem and update priors. Returns the path written."""
    summary = _query_summary(store, slug)
    _update_priors_from_engagement(store, slug)

    out = paths.target_dir(slug) / "postmortem.md"
    paths.secure_write(out, _render_markdown(summary))   # X2: engagement postmortem is owner-only
    return out
