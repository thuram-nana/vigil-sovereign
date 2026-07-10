"""
report.priority — the deterministic impact × effort ordering for the roadmap.

Two pure axes, no wallclock and no RNG, so the roadmap is a reproducible function
of the findings:

  * IMPACT   business weight from severity (Critical=5 … Info=1). Severity is the
             CONTEXT-adjusted rating the finding already carries (CLAUDE.md §VII:
             CVSS base + reasoned contextual delta), so we key on it directly rather
             than re-deriving from the raw CVSS base.
  * EFFORT   a class-level fix-effort estimate (S/M/L/XL) from the bug_class, via a
             fixed lookup. This is an HONEST heuristic — surfaced as an estimate in
             the report, never as a measured fact — and it is deterministic.

  priority_score = impact_weight / effort_weight

so a high-impact / low-effort finding (a "quick win") scores highest and sorts
first, exactly as the remediation-roadmap template prescribes. Ordering ties break
on severity rank then finding slug, so the sequence is total and stable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .grounding import GradedFinding

# Business impact by severity. Higher = worse. These are relative weights, not CVSS.
_SEVERITY_IMPACT: dict[str, float] = {
    "Critical": 5.0,
    "High": 4.0,
    "Medium": 3.0,
    "Low": 2.0,
    "Info": 1.0,
}

# Deterministic display/tie-break order for severities.
SEVERITY_RANK: dict[str, int] = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Info": 4,
}

# Engineering effort to fix correctly, mirroring the roadmap template's sizes.
_EFFORT_WEIGHT: dict[str, float] = {"S": 1.0, "M": 2.0, "L": 3.0, "XL": 4.0}

# bug_class → effort size. Matched by substring against a normalised bug_class, first
# hit wins, default M. Deliberately conservative and stable; the report states this is
# a class-level estimate, so being approximate is honest, and being FIXED is what makes
# the roadmap reproducible.
_EFFORT_RULES: tuple[tuple[tuple[str, ...], str], ...] = (
    (
        (
            "header", "hsts", "csp", "cookie", "clickjack", "cors", "default_cred",
            "default-cred", "verbose_error", "error_disclosure", "info_disclosure",
            "info-disclosure", "rate_limit", "rate-limit", "mass_assignment",
            "mass-assignment", "open_redirect", "open-redirect", "signature",
            "missing_signature", "weak_cipher", "weak_tls", "tls_weakness",
            "directory_listing", "version_disclosure", "cache_control",
        ),
        "S",
    ),
    (
        (
            "idor", "bola", "bfla", "csrf", "reflected_xss", "stored_xss", "xss",
            "ssrf", "path_traversal", "lfi", "rfi", "xxe", "broken_object",
            "broken_function", "insecure_direct", "reflection_context", "dom_execution",
        ),
        "M",
    ),
    (
        (
            "sqli", "sql_injection", "boolean_sqli", "rce", "command_injection",
            "os_command", "deserial", "auth_bypass", "authentication_bypass",
            "authorization", "authz", "business_logic", "ssti", "template_injection",
            "evaluation", "privilege_escalation", "priv_esc",
        ),
        "L",
    ),
    (
        ("supply_chain", "supply-chain", "dependency", "framework_version", "outdated"),
        "XL",
    ),
)


def effort_size(bug_class: str) -> str:
    """Class-level fix-effort estimate: 'S' | 'M' | 'L' | 'XL'. Deterministic; default 'M'."""
    b = (bug_class or "").strip().lower()
    if b:
        for keys, size in _EFFORT_RULES:
            if any(k in b for k in keys):
                return size
    return "M"


def impact_weight(severity: str) -> float:
    """Business-impact weight from the (context-adjusted) severity. Default 1.0 (Info)."""
    return _SEVERITY_IMPACT.get(severity, 1.0)


def priority_score(severity: str, bug_class: str) -> float:
    """impact / effort — higher sorts first (a quick win). Rounded to 4 dp for a
    stable, displayable, deterministic key."""
    return round(impact_weight(severity) / _EFFORT_WEIGHT[effort_size(bug_class)], 4)


def _tier(severity: str, size: str) -> int:
    """Remediation tier, derived deterministically from severity + effort:
    0 = stop the bleeding (severe AND a quick fix), 1 = severe, 2 = medium, 3 = low/info."""
    if severity in ("Critical", "High") and size == "S":
        return 0
    if severity in ("Critical", "High"):
        return 1
    if severity == "Medium":
        return 2
    return 3


_TIER_LABEL: dict[int, str] = {
    0: "Tier 0 — Stop the bleeding (quick wins on severe findings)",
    1: "Tier 1 — Close the most-likely attack paths",
    2: "Tier 2 — Hardening",
    3: "Tier 3 — Low / informational",
}


@dataclass(frozen=True)
class PriorityRow:
    """One prioritised, proven finding — the row the roadmap orders by ``score``."""

    graded: GradedFinding
    rank: int
    impact: float
    effort: str
    score: float
    tier: int

    @property
    def tier_label(self) -> str:
        return _TIER_LABEL[self.tier]


def _sort_key(g: GradedFinding) -> tuple[float, int, str]:
    f = g.finding
    return (
        -priority_score(f.severity, f.bug_class),
        SEVERITY_RANK.get(f.severity, 5),
        f.finding_slug,
    )


def prioritize(graded: Iterable[GradedFinding]) -> list[PriorityRow]:
    """Order PROVEN findings by impact × effort (descending priority score). Leads are
    excluded here on purpose — an unproven lead is never presented in the prioritised
    fix order; the roadmap lists leads in their own labelled, un-prioritised section."""
    facts = [g for g in graded if g.is_fact]
    facts.sort(key=_sort_key)
    rows: list[PriorityRow] = []
    for i, g in enumerate(facts, start=1):
        f = g.finding
        size = effort_size(f.bug_class)
        rows.append(
            PriorityRow(
                graded=g,
                rank=i,
                impact=impact_weight(f.severity),
                effort=size,
                score=priority_score(f.severity, f.bug_class),
                tier=_tier(f.severity, size),
            )
        )
    return rows
