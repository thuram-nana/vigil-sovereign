"""Robustness: OutputAnalysis.findings tolerates the list-of-STRINGS shape real models emit, so one
malformed advisory field can no longer reject the whole LLMDecision and drop exploit_succeeded /
extracted_info (which would silently downgrade a genuine confirmation to ask_user and starve the re-drive).

state.py is import-clean (pydantic + stdlib only), so this needs no framework."""
from __future__ import annotations

from vigil_integration.agent.state import OutputAnalysis


def test_findings_as_strings_are_coerced_and_do_not_drop_exploit_succeeded():
    oa = OutputAnalysis(exploit_succeeded=True,
                        findings=["/auth/continue exposes an open redirect via the next parameter"],
                        extracted_info={"bug_class": "open_redirect"})
    assert oa.exploit_succeeded is True                       # the confirmation survives
    assert oa.extracted_info["bug_class"] == "open_redirect"  # so does the re-drive spec seed
    assert oa.findings == [{"summary": "/auth/continue exposes an open redirect via the next parameter"}]


def test_bare_string_findings_becomes_a_singleton_list():
    assert OutputAnalysis(findings="just a string").findings == [{"summary": "just a string"}]


def test_dict_findings_are_preserved():
    f = [{"title": "x", "severity": "high"}]
    assert OutputAnalysis(findings=f).findings == f


def test_mixed_and_nonstring_findings_are_coerced():
    oa = OutputAnalysis(findings=[{"title": "keep"}, "coerce me", 42])
    assert oa.findings == [{"title": "keep"}, {"summary": "coerce me"}, {"summary": "42"}]


def test_none_findings_is_empty():
    assert OutputAnalysis(findings=None).findings == []
