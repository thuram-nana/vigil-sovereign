"""
Priority: the roadmap orders by impact ÷ effort deterministically — a High-severity
quick win outranks a Critical that needs weeks — and leads never enter the order.
"""

from __future__ import annotations

from framework.v2.agents.models import FindingPayload
from framework.v2.report.grounding import GRADE_FACT, GradedFinding, grade_findings
from framework.v2.report.priority import (
    effort_size,
    impact_weight,
    prioritize,
    priority_score,
)

from .conftest import make_fact, make_lead


def _fact(slug: str, severity: str, bug_class: str) -> GradedFinding:
    """A GradedFinding fixed as a FACT — prioritisation is a pure function of severity +
    bug_class, so we build the grade directly rather than routing an oracle re-fire for
    every (severity, class) combination."""
    return GradedFinding(
        finding=FindingPayload(
            finding_slug=slug, title=f"finding {slug}", severity=severity,
            bug_class=bug_class, surface="/", summary="s",
        ),
        grade=GRADE_FACT,
    )


def test_effort_size_mapping() -> None:
    assert effort_size("header_hsts") == "S"
    assert effort_size("missing_signature") == "S"
    assert effort_size("idor") == "M"
    assert effort_size("boolean_sqli") == "L"
    assert effort_size("supply_chain") == "XL"
    assert effort_size("something_unknown") == "M"   # default
    assert effort_size("") == "M"


def test_impact_and_score() -> None:
    assert impact_weight("Critical") == 5.0
    assert impact_weight("Info") == 1.0
    # Critical (5) / L-effort (3) = 1.6667; High (4) / S-effort (1) = 4.0
    assert priority_score("Critical", "boolean_sqli") == round(5.0 / 3.0, 4)
    assert priority_score("High", "header_hsts") == 4.0


def test_quick_win_outranks_a_bigger_but_costlier_finding() -> None:
    # impact×effort, not severity alone: a High/S quick win (score 4.0) must rank ABOVE a
    # Critical/L finding (score ~1.67).
    crit_hard = _fact("010-sqli", "Critical", "boolean_sqli")
    high_quick = _fact("011-hdr", "High", "header_hsts")
    rows = prioritize([crit_hard, high_quick])
    assert [r.graded.finding.finding_slug for r in rows] == ["011-hdr", "010-sqli"]
    assert rows[0].rank == 1 and rows[0].score > rows[1].score
    assert rows[0].tier == 0            # severe + small effort → stop-the-bleeding tier


def test_ordering_is_total_and_deterministic() -> None:
    facts = [
        _fact("a", "Medium", "idor"),
        _fact("b", "Medium", "idor"),   # tie with a → slug breaks it
        _fact("c", "Critical", "header_hsts"),
    ]
    r1 = [r.graded.finding.finding_slug for r in prioritize(facts)]
    r2 = [r.graded.finding.finding_slug for r in prioritize(facts)]
    assert r1 == r2                     # deterministic
    assert r1[0] == "c"                 # Critical/S (score 5.0) first
    assert r1[1:] == ["a", "b"]         # tie broken by slug


def test_leads_are_excluded_from_prioritisation() -> None:
    rows = prioritize(grade_findings([make_fact(slug="020-sqli"), make_lead(slug="021-idor")]))
    slugs = [r.graded.finding.finding_slug for r in rows]
    assert slugs == ["020-sqli"]        # only the proven fact
