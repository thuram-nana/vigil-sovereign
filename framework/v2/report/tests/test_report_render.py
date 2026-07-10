"""
Rendering: the three documents assemble from graded findings, a FACT is stated as a
fact (with its proof), and a LEAD is labelled a lead — never inflated to a fact.
"""

from __future__ import annotations

from framework.v2.report import ReportMeta, generate_reports
from framework.v2.report.generate import (
    render_executive,
    render_remediation,
    render_technical,
)
from framework.v2.report.grounding import grade_findings

from .conftest import make_demoted, make_fact, make_lead


def _graded():
    return grade_findings([make_fact(), make_demoted(), make_lead()])


def test_bundle_has_three_documents() -> None:
    docs = generate_reports([make_fact(), make_lead()], ReportMeta(target="acme"))
    assert set(docs) == {"executive", "technical", "remediation-roadmap"}
    assert all(v.strip() for v in docs.values())
    for v in docs.values():
        assert "acme" in v  # the target flows into every header


def test_executive_lists_fact_as_confirmed_and_lead_separately() -> None:
    graded = _graded()
    md = render_executive(graded, ReportMeta(target="acme"))
    found, _, leads_section = md.partition("## Leads to verify")
    # the proven finding appears under "What we found"; the lead appears only under leads.
    assert "Blind SQL injection in product search" in found
    assert "Possible IDOR on order lookup" not in found
    assert "Possible IDOR on order lookup" in leads_section
    # the demoted finding is a lead, never presented as a confirmed capability.
    assert "stale evidence" not in found
    assert "stale evidence" in leads_section
    # plain-language impact leads the confirmed bullet.
    assert "extract every row of the users table" in found


def test_executive_grounding_counts_are_honest() -> None:
    md = render_executive(_graded(), ReportMeta(target="acme"))
    # 1 fact, 2 leads (one of which is a demoted/failed-reverification lead).
    assert "**1** oracle-confirmed fact(s)" in md
    assert "**2** unconfirmed lead(s)" in md
    assert "failed re-verification" in md


def test_technical_shows_oracle_proof_for_fact_and_labels_leads() -> None:
    md = render_technical(_graded(), ReportMeta(target="acme"))
    # FACT: the proof is shown, not merely asserted.
    assert "Verification (deterministic oracle) — PROVEN FACT" in md
    assert "differential_response" in md
    assert "0.870" in md                 # calibrated confidence
    assert "1.000" not in md             # never a hardcoded certainty
    assert "sha256:" in md               # re-runnable certificate reference
    assert "framework.v2 verify" in md
    # DEMOTED: recorded-oracle but unverified at report time → a lead.
    assert "unverified at report time" in md
    # LEAD: llm-advisory → a lead, not a fact.
    assert "LEAD (unconfirmed)" in md
    # remediation guidance appears per finding.
    assert "parameterised queries" in md


def test_technical_overview_grounding_column_never_calls_a_lead_a_fact() -> None:
    md = render_technical(_graded(), ReportMeta(target="acme"))
    overview = md.split("## Findings detail")[0]
    # the fact row is FACT; the lead/demoted rows are LEAD — assert no lead slug is on a FACT row.
    for line in overview.splitlines():
        if "003-idor" in line or "002-stale" in line:
            assert "LEAD" in line and "| FACT " not in line


def test_remediation_orders_facts_and_excludes_leads() -> None:
    md = render_remediation(_graded(), ReportMeta(target="acme"))
    order, _, leads_section = md.partition("## Unconfirmed leads")
    # the proven finding is in the prioritised order; the leads are NOT.
    assert "001-sqli" in order
    assert "003-idor" not in order and "002-stale" not in order
    assert "003-idor" in leads_section and "002-stale" in leads_section
    # the summary total counts only proven findings.
    assert "| **Total** | **1** |" in md


def test_render_with_no_facts_states_nothing_confirmed() -> None:
    md = render_executive(grade_findings([make_lead()]), ReportMeta(target="acme"))
    assert "No findings were confirmed" in md
    # the lead is still surfaced (labelled), never dropped.
    assert "Possible IDOR" in md
