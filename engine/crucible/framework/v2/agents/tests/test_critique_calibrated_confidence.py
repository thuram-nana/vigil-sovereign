"""
Calibrated score at the confirmation site (Wave 4, item 4).

The audit finding: a confirmed finding carried a hardcoded 1.0 confidence. Now
the critique-agent sets `FindingPayload.confidence` from the fired oracle's
signal confidence mapped through calibration (identity under sparse data, PAV
isotonic once the OutcomeLedger has enough labels) — never a constant, never 1.0.

Acceptance: two confirmed findings of DIFFERING evidence strength receive
DIFFERENT calibrated scores, both != 1.0 (and, since calibration is monotone,
the stronger differential scores higher). Probed oracle confidences: a 3-row
differential fires at ~0.97, a 1-row differential at ~0.83.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.agents import critique_agent as critique_mod
from framework.v2.agents.blackboard import Blackboard, open_blackboard
from framework.v2.agents.critique_agent import CritiqueAgent
from framework.v2.agents.models import FindingPayload
from framework.v2.calibration.ledger import OutcomeLedger
from framework.v2.kernel.models import CallTrace, CritiqueResult, Objection
from framework.v2.verify.adapter import FindingContext

_SLUG = "calib"
_BASE = {"status": 200, "body": "No results found."}
_STRONG = {
    "status": 200,
    "body": (
        "id=1 name=alice role=user\n"
        "id=2 name=bob role=admin\n"
        "id=3 name=carol role=user"
    ),
}
_WEAK = {"status": 200, "body": "id=2 name=bob role=admin"}


def _stub_urk(decision: str):
    def _fake(claim: str, *, evidence: str = "", context: str = "", backend=None):
        cr = CritiqueResult(
            claim=claim, decision=decision, deception_check="stubbed", objections=[],
        )
        trace = CallTrace(
            backend="stub", is_dryrun=True, cognitive_doc="self-critique",
            cognitive_sections=[], timestamp="2026-07-03T00:00:00+00:00",
        )
        return cr, trace

    return _fake


def _ctx(mutated: dict) -> dict:
    return FindingContext.from_http_responses(
        _BASE, mutated, bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]},
    ).model_dump()


def _finding(slug: str, ctx: dict | None) -> FindingPayload:
    return FindingPayload(
        finding_slug=slug, title=f"finding {slug}", severity="High",
        bug_class="boolean_sqli", surface="GET /search?q=",
        summary="calibration test finding", oracle_context=ctx,
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


def _live(bb: Blackboard, slug: str) -> dict:
    rows = bb.read(engagement=_SLUG, kinds=["finding"])
    m = [r.payload for r in rows if r.payload.get("finding_slug") == slug]
    assert len(m) == 1
    return m[0]


def test_confirmed_findings_get_distinct_calibrated_confidences(
    bb: Blackboard, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(critique_mod, "urk_critique", _stub_urk("objections"))
    _post(bb, _finding("001-strong", _ctx(_STRONG)))
    _post(bb, _finding("002-weak", _ctx(_WEAK)))

    agent = CritiqueAgent(bb, _SLUG, ledger=OutcomeLedger())
    while agent.should_run():
        agent.step()

    strong = _live(bb, "001-strong")
    weak = _live(bb, "002-weak")

    assert strong["critique_status"] == "confirmed"
    assert weak["critique_status"] == "confirmed"

    c_strong = strong["confidence"]
    c_weak = weak["confidence"]
    assert c_strong is not None and c_weak is not None, "confirmed findings must carry a score"

    # The core of the audit fix: never a hardcoded 1.0, always in (0, 1).
    assert c_strong != 1.0 and c_weak != 1.0
    assert 0.0 < c_weak < 1.0 and 0.0 < c_strong < 1.0

    # Differing evidence strength -> differing calibrated scores, monotone in it.
    assert c_strong != c_weak, "distinct evidence must yield distinct scores"
    assert c_strong > c_weak, "the stronger differential must score higher"


def test_legacy_confirmed_finding_has_no_oracle_score(
    bb: Blackboard, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An LLM-advisory confirmation (no oracle_context) leaves the oracle-site
    # `confidence` unset — it never fabricates a calibrated score it did not earn.
    monkeypatch.setattr(critique_mod, "urk_critique", _stub_urk("confirm"))
    _post(bb, _finding("003-legacy", None))

    CritiqueAgent(bb, _SLUG, ledger=OutcomeLedger()).step()

    live = _live(bb, "003-legacy")
    # No oracle backs it, so an LLM "confirm" can never reach "confirmed" — it is
    # llm_advisory (recorded + shown, never promoted as fact) and earns no oracle score.
    assert live["critique_status"] == "llm_advisory"
    assert live["verified_by_oracle"] is False
    assert live["confidence"] is None
