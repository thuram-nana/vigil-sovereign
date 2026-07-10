"""
framework.v2.report — deterministic engagement-report automation.

Turns a completed engagement's confirmed findings (+ world-model + evidence
certificates) into the three operator-facing documents CLAUDE.md §X requires —
an EXECUTIVE summary, a TECHNICAL report, and a REMEDIATION roadmap — rendered
DETERMINISTICALLY as Markdown from what was actually PROVEN.

Prove-don't-guess is enforced IN THE OUTPUT. Every finding is re-graded at report
time by RE-EXECUTING its retained ``oracle_context`` through the veracity firewall
(the same deterministic authority ``agents/reporter_agent.py`` uses — see
``grounding.admit_for_report``). A finding whose proof re-fires is stated as a
FACT with its certificate reference; a finding recorded oracle-confirmed whose
proof no longer reproduces, or a finding with no oracle signal at all, is rendered
as a LEAD — labelled, never inflated to a fact.

The render is a pure function of the graded findings + metadata: no wallclock and
no RNG on the deterministic path, so a fixture engagement renders byte-identically
twice. Reporting is OFF the scanner/oracle path — it can only ever demote, never
promote a claim the oracle refused.
"""

from .grounding import (
    GRADE_DEMOTED,
    GRADE_FACT,
    GRADE_LEAD,
    GradedFinding,
    admit_for_report,
    coerce_finding,
    grade_finding,
    grade_findings,
)
from .priority import (
    PriorityRow,
    effort_size,
    impact_weight,
    prioritize,
    priority_score,
)
from .generate import (
    ReportMeta,
    generate_reports,
    render_executive,
    render_remediation,
    render_technical,
)

__all__ = [
    "GRADE_FACT",
    "GRADE_LEAD",
    "GRADE_DEMOTED",
    "GradedFinding",
    "admit_for_report",
    "coerce_finding",
    "grade_finding",
    "grade_findings",
    "PriorityRow",
    "effort_size",
    "impact_weight",
    "priority_score",
    "prioritize",
    "ReportMeta",
    "generate_reports",
    "render_executive",
    "render_technical",
    "render_remediation",
]
