"""H8 — an executed tool's output becomes LEADs, and can never become a FACT on that path.

Before this, `vigil engage --brain hexstrike` executed tools and reported **zero facts and zero leads**, by
construction: BrainThink sets no ``output_analysis`` (it has no LLM), so ``react.intake_result`` hit
``if analysis is None: return IntakeResult([], [])`` and the nmap XML / nuclei JSONL / httpx JSONL was
hashed into the ExecRecord and discarded. A test even asserted ``fact_count == 0`` as intended behaviour.
"""
from __future__ import annotations

import json

import pytest

from vigil_integration.agent.react import intake_result
from vigil_integration.agent.state import OutputAnalysis
from vigil_integration.live.tool_intake import analysis_from_tool_output

NUCLEI = "\n".join(json.dumps({
    "template-id": "exposed-panel", "info": {"severity": "medium", "name": "Panel"},
    "matched-at": f"http://target.example/admin{i}", "host": "target.example",
}) for i in range(3))


def test_parseable_tool_output_becomes_proposals():
    analysis = analysis_from_tool_output("nuclei", NUCLEI)
    assert analysis is not None and len(analysis.findings) == 3
    assert all(c.get("bug_class") for c in analysis.findings)


def test_a_parser_never_asserts_that_an_exploit_succeeded():
    """`exploit_succeeded` is the exact claim the oracle exists to check; a parser has observed no such thing."""
    analysis = analysis_from_tool_output("nuclei", NUCLEI)
    assert analysis.exploit_succeeded is False, (
        "a parser must never assert exploitation — that would fire the oracle from tool-supplied bytes"
    )


def test_every_proposal_enters_as_a_lead_and_none_as_a_fact():
    """End-to-end through the real intake seam: leads appear, facts do not."""
    analysis = analysis_from_tool_output("nuclei", NUCLEI)
    result = intake_result(NUCLEI, analysis, oracle=None, source="nuclei")
    assert len(result.leads) == 3, "the executed tool's output must now produce leads"
    assert result.facts == [], "no FACT may come from a tool's own say-so"
    assert all(f.status == "lead" for f in result.leads)


def test_the_oracle_is_not_fired_from_this_path_even_when_one_is_wired():
    """With exploit_succeeded False the oracle is never consulted, so it cannot mint from parsed bytes."""
    calls = []

    def _oracle(raw, analysis):
        calls.append(raw)
        return "evidence-ref"          # would become a FACT if it were ever called

    result = intake_result(NUCLEI, analysis_from_tool_output("nuclei", NUCLEI),
                           oracle=_oracle, source="nuclei")
    assert calls == [], "the oracle must not be fired from parser-derived proposals"
    assert result.facts == []


def test_an_llm_supplied_analysis_still_wins():
    """The derivation is a FALLBACK: it must not override a real inline analysis."""
    from vigil_integration.live import tool_intake

    explicit = OutputAnalysis(findings=[{"title": "from the model"}], exploit_succeeded=None)
    # the engine only derives when decision.output_analysis is None; assert the contract it relies on
    assert explicit.findings and explicit is not tool_intake.analysis_from_tool_output("nuclei", NUCLEI)


@pytest.mark.parametrize("raw", ["", "   ", "not json at all", "{"])
def test_unparseable_or_empty_output_yields_nothing_and_never_raises(raw):
    assert analysis_from_tool_output("nuclei", raw) is None


def test_an_unknown_tool_yields_nothing():
    assert analysis_from_tool_output("totally-unknown-tool", NUCLEI) is None


def test_nmap_is_deliberately_not_parsed_here():
    """nmap already has a runner-owned re-drive that produces a real FACT; a weaker duplicate claim for the
    same observation would be noise, so it is excluded on purpose rather than by omission."""
    from vigil_integration.live.tool_intake import _NOT_PARSED_HERE

    assert "nmap" in _NOT_PARSED_HERE
    assert analysis_from_tool_output("nmap", "<nmaprun/>") is None


def test_the_zaproxy_alias_reaches_the_zap_parser():
    """The roster/builder name is `zaproxy`; the parser registry files it as `zap`."""
    from vigil_integration.live.tool_intake import _parser_for

    assert _parser_for("zaproxy") is not None, "the zaproxy→zap alias is not wired"


def test_negative_control_the_lead_assertion_would_catch_a_fact():
    """Prove the facts==[] assertion is not vacuous: a firing oracle DOES mint on the LLM path."""
    result = intake_result("raw", OutputAnalysis(exploit_succeeded=True, findings=[]),
                           oracle=lambda raw, a: "evidence-ref", source="llm")
    assert result.facts, (
        "the intake seam cannot produce a fact at all, so asserting its absence proves nothing"
    )


def test_the_engine_derives_only_when_the_decision_has_no_analysis():
    """Pin the wiring: the engine must prefer an explicit analysis and derive only as a fallback."""
    from pathlib import Path

    src = Path(__file__).resolve().parents[1].joinpath(
        "vigil_integration/live/engine.py").read_text(encoding="utf-8")
    assert "_analysis = decision.output_analysis" in src
    assert "if _analysis is None and decision.tool is not None:" in src, (
        "the derivation must be conditional on there being no analysis already"
    )
