"""
OutcomeLedger wire-in (Wave 4, item 3).

Every oracle-adjudicated finding appends a deterministic prediction to a
`calibration.OutcomeLedger`. The OUTCOME label, however, is resolved WITHOUT
circularity (Wave 3): the old code labelled EXPLOITABLE iff the oracle fired and
fed that same oracle's confidence in as the prediction, so the calibrator learned
P(exploitable|oracle)~=1.0 by construction — certifying the oracle against itself.
Now a single confirming oracle resolves to DISPUTED (honest abstention, excluded
from every fit); only genuine cross-oracle corroboration resolves EXPLOITABLE
autonomously, and real labels otherwise come from an independent adjudicator.

The critique-agent is unchanged when no ledger is supplied (backward-compatible);
these tests pass one in and assert the recorded predictions + abstained outcomes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.agents import critique_agent as critique_mod
from framework.v2.agents.blackboard import Blackboard, open_blackboard
from framework.v2.agents.critique_agent import CritiqueAgent
from framework.v2.agents.models import FindingPayload
from framework.v2.calibration.ledger import OutcomeLedger
from framework.v2.calibration.models import OutcomeLabel
from framework.v2.kernel.models import CallTrace, CritiqueResult, Objection
from framework.v2.verify.adapter import FindingContext

_SLUG = "ledger"


def _stub_urk(decision: str, *, objections: list[str] | None = None):
    def _fake(claim: str, *, evidence: str = "", context: str = "", backend=None):
        cr = CritiqueResult(
            claim=claim, decision=decision, deception_check="stubbed",
            objections=[
                Objection(concern=o, severity="major", evidence_request="n/a")
                for o in (objections or [])
            ],
        )
        trace = CallTrace(
            backend="stub", is_dryrun=True, cognitive_doc="self-critique",
            cognitive_sections=[], timestamp="2026-07-03T00:00:00+00:00",
        )
        return cr, trace

    return _fake


def _firing_context() -> dict:
    return FindingContext.from_http_responses(
        {"status": 200, "body": "No results found."},
        {"status": 200, "body": "id=1 name=alice role=user\nid=2 name=bob role=admin"},
        bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]},
    ).model_dump()


def _non_firing_context() -> dict:
    same = {"status": 200, "body": "No results found."}
    return FindingContext.from_http_responses(
        same, dict(same), bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]},
    ).model_dump()


def _finding(slug: str, ctx: dict | None) -> FindingPayload:
    return FindingPayload(
        finding_slug=slug, title=f"finding {slug}", severity="High",
        bug_class="boolean_sqli", surface="GET /search?q=",
        summary="ledger test finding", oracle_context=ctx,
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


def test_ledger_records_predictions_and_abstains_on_single_oracle(
    bb: Blackboard, monkeypatch: pytest.MonkeyPatch
) -> None:
    # LLM stubbed to OBJECT throughout, to prove the ledger tracks the ORACLE
    # path, not the LLM.
    monkeypatch.setattr(critique_mod, "urk_critique", _stub_urk("objections"))

    _post(bb, _finding("001-fires", _firing_context()))
    _post(bb, _finding("002-fires", _firing_context()))
    _post(bb, _finding("003-silent", _non_firing_context()))

    ledger = OutcomeLedger()
    agent = CritiqueAgent(bb, _SLUG, ledger=ledger)
    while agent.should_run():
        agent.step()

    # Three findings -> three predictions recorded.
    assert len(ledger) == 3

    # Each fires exactly ONE oracle kind (the differential), which is NOT
    # independent enough to auto-confirm — so every outcome is DISPUTED (honest
    # abstention), and none contributes a target to a fit.
    from framework.v2.calibration.models import label_to_target
    labels = [e.outcome.label for e in ledger.entries() if e.outcome is not None]
    assert labels and all(l == OutcomeLabel.DISPUTED for l in labels)
    assert all(label_to_target(l) is None for l in labels), "DISPUTED must be excluded from fits"

    # Predictions still carry the honest raw oracle confidence + the
    # oracle_confirmed flag: fired -> >0/True, silent -> 0.0/False.
    by_conf = {e.prediction.oracle_confirmed: e.prediction.raw_score for e in ledger.entries()}
    assert by_conf[True] > 0.0
    assert by_conf[False] == 0.0


def test_legacy_findings_are_not_recorded(
    bb: Blackboard, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A finding with NO oracle_context takes the legacy LLM path; there is no
    # deterministic ground truth, so nothing is written to the ledger.
    monkeypatch.setattr(critique_mod, "urk_critique", _stub_urk("confirm"))
    _post(bb, _finding("004-legacy", None))

    ledger = OutcomeLedger()
    CritiqueAgent(bb, _SLUG, ledger=ledger).step()

    assert len(ledger) == 0, "LLM-advisory findings must not enter the outcome ledger"


def test_no_ledger_is_backward_compatible(
    bb: Blackboard, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Absent a ledger, critique behaviour is exactly as before (no crash, the
    # oracle still confirms).
    monkeypatch.setattr(critique_mod, "urk_critique", _stub_urk("objections"))
    _post(bb, _finding("005-no-ledger", _firing_context()))

    CritiqueAgent(bb, _SLUG).step()  # no ledger= kwarg

    rows = bb.read(engagement=_SLUG, kinds=["finding"])
    live = [r.payload for r in rows if r.payload.get("finding_slug") == "005-no-ledger"]
    assert live and live[0]["critique_status"] == "confirmed"
    assert live[0]["verified_by_oracle"] is True
