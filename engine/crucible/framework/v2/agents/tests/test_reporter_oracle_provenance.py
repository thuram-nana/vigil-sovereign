"""
Reporter surfaces oracle provenance (Wave 4, item 2).

Prove-don't-guess is only credible if the report shows the proof. For every
oracle-verified finding the technical report must render WHICH oracle fired, the
CALIBRATED confidence (never 1.0), and the oracle's rationale. An LLM-advisory
confirmation instead says so plainly, so the two are never confused.

The test runs a real finding through the critique-agent (so `oracle_kind`,
`confidence`, and `oracle_rationale` are populated by the oracle path, not hand-
set), then renders it and asserts the proof is visible.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.agents import critique_agent as critique_mod
from framework.v2.agents.blackboard import Blackboard, open_blackboard
from framework.v2.agents.critique_agent import CritiqueAgent
from framework.v2.agents.models import FindingPayload
from framework.v2.agents.reporter_agent import ReporterAgent
from framework.v2.calibration.ledger import OutcomeLedger
from framework.v2.kernel.models import CallTrace, CritiqueResult, Objection
from framework.v2.verify.adapter import FindingContext

_SLUG = "reporter-oracle"


def _stub_urk(decision: str):
    def _fake(claim: str, *, evidence: str = "", context: str = "", backend=None):
        cr = CritiqueResult(
            claim=claim, decision=decision, deception_check="stubbed",
            objections=[Objection(concern="x", severity="major", evidence_request="n/a")]
            if decision == "objections" else [],
        )
        trace = CallTrace(
            backend="stub", is_dryrun=True, cognitive_doc="self-critique",
            cognitive_sections=[], timestamp="2026-07-03T00:00:00+00:00",
        )
        return cr, trace

    return _fake


def _firing_ctx() -> dict:
    return FindingContext.from_http_responses(
        {"status": 200, "body": "No results found."},
        {"status": 200, "body": "id=1 name=alice role=user\nid=2 name=bob role=admin"},
        bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]},
    ).model_dump()


def _finding(slug: str, ctx: dict | None) -> FindingPayload:
    return FindingPayload(
        finding_slug=slug, title=f"finding {slug}", severity="High",
        bug_class="boolean_sqli", surface="GET /search?q=",
        summary="reporter provenance finding", oracle_context=ctx,
    )


@pytest.fixture()
def bb(tmp_path: Path) -> Blackboard:
    b = open_blackboard(db_path=tmp_path / "bb.sqlite")
    b.engagement_id(_SLUG)
    yield b
    b.close()


def _post(bb: Blackboard, payload: FindingPayload) -> None:
    bb.post(engagement=_SLUG, kind="finding", agent_name="exploit",
            payload=payload.model_dump())


def _reportable_rows(bb: Blackboard):
    # oracle-confirmed AND llm_advisory — the report shows both, distinctly labelled.
    return [
        r for r in bb.read(engagement=_SLUG, kinds=["finding"])
        if r.payload.get("critique_status") in ("confirmed", "llm_advisory")
    ]


def test_report_shows_oracle_kind_confidence_and_rationale(
    bb: Blackboard, monkeypatch: pytest.MonkeyPatch
) -> None:
    # LLM objects; only the oracle can confirm — so what the report shows is the
    # oracle's provenance, not the LLM's.
    monkeypatch.setattr(critique_mod, "urk_critique", _stub_urk("objections"))
    _post(bb, _finding("001-verified", _firing_ctx()))
    CritiqueAgent(bb, _SLUG, ledger=OutcomeLedger()).step()

    rows = _reportable_rows(bb)
    assert len(rows) == 1
    payload = rows[0].payload
    # The oracle path populated the provenance fields.
    assert payload["verified_by_oracle"] is True
    kind = payload["oracle_kind"]
    conf = payload["confidence"]
    assert kind, "oracle_kind must be populated by the oracle path"
    assert conf is not None and conf != 1.0 and 0.0 < conf < 1.0
    assert payload["oracle_rationale"], "oracle rationale must be recorded"

    md = ReporterAgent(bb, _SLUG)._render(rows)

    assert "Verification (deterministic oracle)" in md
    assert kind in md, "the report must name which oracle fired"
    assert f"{conf:.3f}" in md, "the report must show the calibrated (non-1.0) score"
    assert "1.000" not in md, "the report must never show a hardcoded certainty"
    # A recognisable slice of the oracle rationale is present.
    assert payload["oracle_rationale"][:12] in md


def test_report_marks_llm_advisory_confirmation(
    bb: Blackboard, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A finding with no oracle evidence is confirmed by the LLM only; the report
    # must say so rather than imply a deterministic proof.
    monkeypatch.setattr(critique_mod, "urk_critique", _stub_urk("confirm"))
    _post(bb, _finding("002-advisory", None))
    CritiqueAgent(bb, _SLUG).step()

    rows = _reportable_rows(bb)
    md = ReporterAgent(bb, _SLUG)._render(rows)
    assert "LLM-advisory confirmation" in md
    assert "deterministic oracle signal" in md
