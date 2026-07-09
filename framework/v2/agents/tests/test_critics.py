"""
Nervous-System N3 — the multi-critic panel.

Differentiated deterministic critics review each finding through their own lens; their
verdicts (endorse | object | abstain — NEVER confirm) aggregate with abstain-on-disagreement.
A single strong objection demotes; disagreement routes to needs_evidence. Oracle authority is
preserved: no critic can promote a finding to a fact.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.agents.blackboard import open_blackboard
from framework.v2.agents.critics import (
    CalibrationCritic,
    CriticVerdict,
    GroundingCritic,
    MultiCriticAgent,
    ProvenanceCritic,
    aggregate_panel,
    panel_verdict_for,
    run_panel,
)
from framework.v2.agents.models import FindingPayload
from framework.v2.verify.adapter import FindingContext

_BASE = {"status": 200, "body": "No results found."}
_DIVERGENT = {"status": 200, "body": "id=1 alice user\nid=2 bob admin"}


def _ctx(mutated=_DIVERGENT) -> dict:
    return FindingContext.from_http_responses(
        _BASE, mutated, bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]}).model_dump(mode="json")


def _finding(**kw) -> FindingPayload:
    base = dict(finding_slug="001", title="t", severity="High", bug_class="boolean_sqli",
                surface="query:q", summary="s", verified_by_oracle=True,
                oracle_kind="differential_response", confidence=0.87, oracle_context=_ctx())
    base.update(kw)
    return FindingPayload(**base)


# ---- verdicts can never be 'confirm' ----------------------------------------


def test_critic_verdict_can_never_be_confirm() -> None:
    with pytest.raises(ValueError, match="never 'confirm'"):
        CriticVerdict("x", "confirm")
    for v in ("endorse", "object", "abstain"):
        assert CriticVerdict("x", v).verdict == v


# ---- individual lenses -------------------------------------------------------


def test_grounding_critic_endorses_regrounding_and_objects_otherwise() -> None:
    assert GroundingCritic().review(_finding()).verdict == "endorse"
    stale = _finding(oracle_context=_ctx(_BASE))            # non-divergent → oracle won't re-fire
    v = GroundingCritic().review(stale)
    assert v.verdict == "object" and v.severity == "major"


def test_provenance_critic_objects_unbacked_verification() -> None:
    unbacked = _finding(verified_by_oracle=True, oracle_context=None)
    assert ProvenanceCritic().review(unbacked).verdict == "object"
    assert ProvenanceCritic().review(_finding()).verdict == "endorse"


def test_calibration_critic_objects_hardcoded_certainty() -> None:
    assert CalibrationCritic().review(_finding(confidence=1.0)).verdict == "object"
    assert CalibrationCritic().review(_finding(verified_by_oracle=True, confidence=None)).verdict == "abstain"
    assert CalibrationCritic().review(_finding(confidence=0.8)).verdict == "endorse"


# ---- aggregation -------------------------------------------------------------


def test_strong_objection_stands() -> None:
    vs = [CriticVerdict("a", "endorse"), CriticVerdict("b", "object", severity="major"),
          CriticVerdict("c", "endorse")]
    assert aggregate_panel(vs).verdict == "object"


def test_disagreement_abstains() -> None:
    vs = [CriticVerdict("a", "endorse"), CriticVerdict("b", "abstain"),
          CriticVerdict("c", "object", severity="minor")]           # 3-way split → high entropy
    assert aggregate_panel(vs).verdict == "abstain"


def test_unanimous_endorse() -> None:
    vs = [CriticVerdict("a", "endorse"), CriticVerdict("b", "endorse"), CriticVerdict("c", "endorse")]
    p = aggregate_panel(vs)
    assert p.verdict == "endorse" and p.agreement == 1.0


def test_panel_never_confirms_a_genuine_finding() -> None:
    # even a fully-endorsed finding yields at most 'endorse' — never 'confirm'.
    assert aggregate_panel(run_panel(_finding())).verdict in ("endorse", "object", "abstain")


# ---- the schedulable agent + quorum -----------------------------------------


def test_multi_critic_agent_posts_verdicts_and_quorum(tmp_path: Path) -> None:
    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    bb.engagement_id("e")
    fe = bb.post(engagement="e", kind="finding", agent_name="exploit", payload=_finding().model_dump())
    agent = MultiCriticAgent(bb, "e")
    assert agent.should_run()
    posted = agent.step()
    assert posted == 3                                             # one verdict per default critic
    assert not agent.should_run()                                 # nothing left unreviewed
    verdicts = bb.read(engagement="e", kinds=["critic_verdict"])
    assert len(verdicts) == 3 and all(v.payload["verdict"] != "confirm" for v in verdicts)
    # the quorum over a genuine finding endorses (grounds + provenance ok + calibrated)
    assert panel_verdict_for(bb, "e", fe).verdict == "endorse"
    bb.close()


def test_multi_critic_agent_reviews_each_finding_exactly_once(tmp_path: Path) -> None:
    # cursor-based: a second tick posts nothing and the agent quiesces — no re-review or
    # duplicate verdicts (the N3 review's runaway defect). A new finding IS picked up.
    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    bb.engagement_id("e")
    bb.post(engagement="e", kind="finding", agent_name="x", payload=_finding(finding_slug="1").model_dump())
    agent = MultiCriticAgent(bb, "e")
    assert agent.step() == 3
    assert agent.step() == 0 and not agent.should_run()          # no re-review; quiesces
    # a NEW finding is reviewed on the next tick, and only it
    bb.post(engagement="e", kind="finding", agent_name="x", payload=_finding(finding_slug="2").model_dump())
    assert agent.should_run() and agent.step() == 3
    assert len(bb.read(engagement="e", kinds=["critic_verdict"])) == 6   # exactly 3 per finding, no dupes
    bb.close()
