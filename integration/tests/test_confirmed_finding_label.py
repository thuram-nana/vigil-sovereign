"""A confirmed FACT is labelled with the class the ORACLE confirmed (from the signed evidence ref, else the
claimed class), never the tool that surfaced it — so the Findings screen reads 'open_redirect', not 'httpx'.
react.py is import-clean (pydantic + stdlib), so no framework is needed."""
from __future__ import annotations

from types import SimpleNamespace

from vigil_integration.agent.react import _confirmed_class, intake_result
from vigil_integration.agent.state import OutputAnalysis


def _oracle(ref):
    return lambda raw, an: ref


def test_web_fact_labelled_from_the_evidence_ref():
    oa = OutputAnalysis(exploit_succeeded=True, extracted_info={"bug_class": "open_redirect"})
    res = intake_result("raw", oa, oracle=_oracle("web:open_redirect:http://x#open_redirect.location_header"),
                        source="httpx")
    assert len(res.facts) == 1 and not res.leads
    f = res.facts[0]
    assert f.bug_class == "open_redirect"          # the confirmed class, NOT the tool
    assert "open_redirect" in f.title and f.ref == "exploit:open_redirect"
    assert f.evidence_ref.startswith("web:open_redirect")
    assert f.source == "httpx"                     # the tool is still recorded (as the surface)


def test_runtime_fact_labelled_path_traversal():
    oa = OutputAnalysis(exploit_succeeded=True, extracted_info={"bug_class": "path_traversal"})
    res = intake_result("raw", oa, oracle=_oracle("rt:path_traversal:http://x#path_traversal.file_signature"),
                        source="httpx")
    assert res.facts[0].bug_class == "path_traversal"


def test_sqli_falls_back_to_the_claimed_class_when_ref_has_no_class():
    oa = OutputAnalysis(exploit_succeeded=True, extracted_info={"bug_class": "error_based_sqli"})
    res = intake_result("raw", oa, oracle=_oracle("finding"), source="httpx")
    assert res.facts[0].bug_class == "error_based_sqli"


def test_unconfirmed_stays_a_lead_and_is_not_mislabelled():
    oa = OutputAnalysis(exploit_succeeded=True, extracted_info={"bug_class": "open_redirect"})
    res = intake_result("raw", oa, oracle=_oracle(""), source="httpx")   # oracle did not fire
    assert not res.facts and len(res.leads) == 1
    assert "UNCONFIRMED" in res.leads[0].title


def test_confirmed_class_helper_parses_refs():
    assert _confirmed_class("web:cors:http://x#cors.reflected_origin_with_credentials", None) == "cors"
    assert _confirmed_class("rt:exposure:http://x#exposure.secret_signature", None) == "exposure"
    assert _confirmed_class("", SimpleNamespace(extracted_info={"bug_class": "XSS"})) == "xss"
