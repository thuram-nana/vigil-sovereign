"""
Shared fixtures for the report tests — a small engagement of confirmed findings and
leads. The FACT findings carry a REAL, re-firing FindingContext (a divergent
differential response), so the report layer grades them by re-execution exactly as it
would a live finding; the demoted finding carries a non-divergent context whose oracle
will NOT re-fire; the leads carry no oracle at all.
"""

from __future__ import annotations

import pytest

from framework.v2.agents.models import FindingPayload
from framework.v2.verify.adapter import FindingContext

_BASE = {"status": 200, "body": "No results found."}
_DIVERGENT = {"status": 200, "body": "id=1 name=alice role=user\nid=2 name=bob role=admin"}


def firing_ctx() -> dict:
    """A differential context whose oracle DOES re-fire (base vs divergent)."""
    return FindingContext.from_http_responses(
        _BASE, _DIVERGENT, bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]},
    ).model_dump(mode="json")


def nonfiring_ctx() -> dict:
    """A context whose oracle does NOT re-fire (base vs base — no divergence)."""
    return FindingContext.from_http_responses(
        _BASE, _BASE, bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]},
    ).model_dump(mode="json")


def make_fact(slug: str = "001-sqli", *, severity: str = "Critical",
              bug_class: str = "boolean_sqli") -> FindingPayload:
    """A genuinely oracle-confirmed finding whose retained proof re-fires → a FACT."""
    return FindingPayload(
        finding_slug=slug, title="Blind SQL injection in product search",
        severity=severity, bug_class=bug_class, surface="GET /search?q=",
        summary="An unauthenticated attacker can read arbitrary database rows blind.",
        impact="An attacker can extract every row of the users table (including password "
               "hashes) with crafted search requests, no authentication required.",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", cvss_base=7.5,
        verified_by_oracle=True, oracle_kind="differential_response", confidence=0.87,
        oracle_rationale="differential fired across status+length+lexical dimensions",
        critique_status="confirmed", oracle_context=firing_ctx(),
    )


def make_demoted(slug: str = "002-stale") -> FindingPayload:
    """Recorded oracle-confirmed, but its retained proof no longer re-fires → DEMOTED lead."""
    return FindingPayload(
        finding_slug=slug, title="Recorded-confirmed finding with stale evidence",
        severity="High", bug_class="boolean_sqli", surface="GET /x?q=", summary="s",
        verified_by_oracle=True, oracle_kind="differential_response", confidence=0.9,
        oracle_rationale="claimed differential", critique_status="confirmed",
        oracle_context=nonfiring_ctx(),
    )


def make_lead(slug: str = "003-idor", *, severity: str = "Medium",
              bug_class: str = "idor") -> FindingPayload:
    """An LLM-advisory finding with no oracle signal → a LEAD."""
    return FindingPayload(
        finding_slug=slug, title="Possible IDOR on order lookup",
        severity=severity, bug_class=bug_class, surface="GET /order/{id}",
        summary="Order objects may be readable across accounts.",
        impact="If confirmed, an attacker could read other users' orders.",
        critique_status="llm_advisory",
    )


@pytest.fixture()
def fact() -> FindingPayload:
    return make_fact()


@pytest.fixture()
def demoted() -> FindingPayload:
    return make_demoted()


@pytest.fixture()
def lead() -> FindingPayload:
    return make_lead()
