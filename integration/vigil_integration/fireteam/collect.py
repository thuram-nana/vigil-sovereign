"""
fireteam.collect — the sovereign fan-in: member findings roll up as LEADs, only the oracle mints FACTs
(VIGIL-FUSION F6, C5).

redamon's ``fireteam_collect_node`` merges each member's findings into parent memory. VIGIL keeps the
roll-up but binds it to the sovereign rule: **a member finding is a LEAD, period.** ``collect``:

  * downgrades EVERY member-supplied :class:`~agent.state.Finding` to a LEAD (stripping any status /
    ``evidence_ref`` it carries) — a member can never hand up a pre-forged "fact", even one with a
    plausible-looking evidence ref;
  * re-fires the INJECTED deterministic oracle over each member's retained raw output + inline analysis
    via the F2 ``agent.react.intake_result`` — the load-bearing anti-hallucination seam — so a claimed
    exploit becomes a FACT only on an oracle confirmation (a signed evidence ref). No oracle wired ⇒
    nothing is promoted (fail-closed);
  * rolls up each member's pending escalations for the parent to route through the confirmation
    registry.

Deterministic ordering (by member_id); never raises on a malformed member result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from ..agent.react import OracleFn, intake_result
from ..agent.state import Finding
from .models import EscalationRequest, MemberFindingClaim, MemberResult


def _as_lead(finding: Finding, source: str) -> Finding:
    """A fresh LEAD copy of a member-supplied finding — status forced to ``lead`` and ``evidence_ref``
    stripped. This is the trust boundary: whatever the member claimed, collect re-derives the veracity."""
    return Finding(
        ref=finding.ref,
        bug_class=finding.bug_class,
        title=finding.title,
        severity=finding.severity,
        status="lead",
        evidence_ref="",
        source=source or finding.source or "",
    )


@dataclass(frozen=True)
class CollectOutcome:
    """The fan-in result. ``facts`` are oracle-confirmed (each carries a signed evidence ref); ``leads``
    are unproven proposals; ``escalations`` are pending dangerous-tool requests for the parent."""

    facts: list[Finding] = field(default_factory=list)
    leads: list[Finding] = field(default_factory=list)
    escalations: list[EscalationRequest] = field(default_factory=list)


def collect(
    member_results: Iterable[Any],
    *,
    oracle: Optional[OracleFn] = None,
    source_prefix: str = "fireteam",
) -> CollectOutcome:
    """Roll up member results, honestly. Every member finding becomes a LEAD (attributed to its member);
    an ``exploit_succeeded`` claim is re-checked by the injected ``oracle`` over the retained raw output
    and only an oracle confirmation yields a FACT. Deterministic (members sorted by id). Total on
    untrusted input — a non-:class:`MemberResult`, a bad claim, or a non-``Finding`` lead is skipped,
    never crashes the fan-in."""
    facts: list[Finding] = []
    leads: list[Finding] = []
    escalations: list[EscalationRequest] = []

    results = [r for r in (member_results or []) if isinstance(r, MemberResult)]
    for r in sorted(results, key=lambda m: m.member_id):
        src = f"{source_prefix}:{r.member_id}"
        for lead in r.leads:
            if isinstance(lead, Finding):
                leads.append(_as_lead(lead, src))
        for claim in r.claims:
            if not isinstance(claim, MemberFindingClaim):
                continue
            res = intake_result(claim.raw_output, claim.analysis, oracle=oracle, source=src)
            facts.extend(res.facts)   # oracle-confirmed only — the ONLY path to a FACT here
            leads.extend(res.leads)
        for esc in r.escalations:
            if isinstance(esc, EscalationRequest):
                escalations.append(esc)

    return CollectOutcome(facts=facts, leads=leads, escalations=escalations)
