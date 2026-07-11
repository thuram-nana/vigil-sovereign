"""
Producer unification — every producer reaches the unified report, HONESTLY GRADED.

The unified ``report`` composes ``finding`` events. Before this seam only the scanner's active,
oracle-confirmed findings emitted those events; passive findings and fused-sensor leads never
reached the report. These tests pin the two lead adapters:

  * ``intel.project.observation_to_finding_payload`` — a fused-sensor ``Observation`` → a LEAD.
  * ``engage._passive_finding_payload``               — a scanner passive finding → a LEAD.

Both must grade as LEADS (no oracle_context → never a fact) and both must be REPORTABLE (the
``llm_advisory`` bucket the report reads), so prove-don't-guess is preserved while coverage widens.
"""

from __future__ import annotations

from framework.v2.engage import _passive_finding_payload
from framework.v2.intel.models import IntelSourceKind, Observation, SourceReliability
from framework.v2.intel.project import observation_to_finding_payload
from framework.v2.intel.refs import EntityRef
from framework.v2.report.generate import ReportMeta, generate_reports
from framework.v2.report.grounding import grade_finding
from framework.v2.scanner.passive import PassiveFinding
from framework.v2.worldmodel.models import NodeKind


def _lead_observation() -> Observation:
    return Observation(
        obs_id="cloud:iam:1:role-x",
        source="scoutsuite",
        source_kind=IntelSourceKind.CLOUD_POSTURE,
        collector="cloud",
        subject=EntityRef(kind=NodeKind.HOST, key="10.0.0.5"),
        attrs={"bug_class": "iam_overbroad_trust", "severity": "High"},
        confidence=0.5,
        seq=1,
        evidence="role trusts * (overbroad AssumeRole)",
        source_reliability=SourceReliability(),
    )


# --------------------------------------------------------------------------- fused sensor lead


def test_observation_to_finding_payload_grades_as_lead():
    obs = _lead_observation()
    payload = observation_to_finding_payload(obs)
    assert payload["critique_status"] == "llm_advisory"     # reportable...
    assert payload["verified_by_oracle"] is False
    assert payload["oracle_context"] is None
    assert payload["bug_class"] == "iam_overbroad_trust"
    assert payload["severity"] == "High"
    g = grade_finding(payload)
    assert g.is_lead is True and g.is_fact is False        # ...but a LEAD, never a fact


def test_observation_without_bug_class_falls_back_to_source_kind():
    obs = Observation(
        obs_id="dns:1:host", source="doh", source_kind=IntelSourceKind.DNS, collector="dns",
        subject=EntityRef(kind=NodeKind.DOMAIN, key="acme.test"), seq=1)
    payload = observation_to_finding_payload(obs)
    assert payload["bug_class"] == "dns"
    assert payload["severity"] == "Info"     # unknown severity → safe default
    assert grade_finding(payload).is_lead is True


# --------------------------------------------------------------------------- passive finding lead


def test_passive_finding_payload_grades_as_lead():
    pf = PassiveFinding(check_id="missing-content-security-policy",
                        title="Missing Content-Security-Policy", severity="Medium",
                        confidence="Certain", url="https://acme.test/",
                        evidence="content-security-policy header absent")
    payload = _passive_finding_payload(pf)
    assert payload["critique_status"] == "llm_advisory"
    assert payload["verified_by_oracle"] is False
    assert payload["oracle_context"] is None
    assert payload["severity"] == "Medium"
    assert payload["bug_class"] == "missing-content-security-policy"
    g = grade_finding(payload)
    assert g.is_lead is True and g.is_fact is False


def test_passive_finding_odd_severity_is_coerced():
    pf = PassiveFinding(check_id="weird", title="w", severity="Unknown",
                        confidence="Tentative", url="", evidence="")
    payload = _passive_finding_payload(pf)
    assert payload["severity"] == "Info"     # not in the Literal → coerced, so bb.post won't drop


# --------------------------------------------------------------------------- report composes both


def test_report_lists_lead_producers_separately_from_facts():
    obs_lead = observation_to_finding_payload(_lead_observation())
    passive_lead = _passive_finding_payload(
        PassiveFinding(check_id="missing-hsts", title="Missing HSTS", severity="Low",
                       confidence="Certain", url="https://acme.test/", evidence="hsts absent"))
    docs = generate_reports([obs_lead, passive_lead], ReportMeta(target="unify"))
    exec_doc = docs["executive"]
    # neither producer is asserted as a proven fact; both live under leads-to-verify.
    assert "Leads to verify" in exec_doc
    assert "_No findings were confirmed by a deterministic oracle in this engagement._" in exec_doc
    tech = docs["technical"]
    assert "LEAD" in tech
    assert "PROVEN FACT" not in tech
