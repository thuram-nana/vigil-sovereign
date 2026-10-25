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


# ATTRIBUTED evidence. The confirmable fixture below is a path_traversal FILE-CONTENT signature with
# its benign CONTROL retained: the signature is present under the payload and ABSENT from the
# control, so the read is attributable. It used to be a boolean_sqli benign-vs-payload differential,
# which is LEAD-only now — that inference has no attribution step (its control is a DIFFERENT
# STRING, not a same-shape negative) and minted High FACTs at rate 1.0 against a static page behind
# a WAF tautology rule and against strict input validation, on targets with no database. See
# verify.verifier.DIFFERENTIAL_LEAD_ONLY_CLASSES. Nothing under test here changes — only the
# evidence it is anchored to.
_SIGNATURE = "root:x:0:0:"
_READ_SINK = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
_CONTROL_SINK = "<p>ordinary document</p>"
_PT = "path_traversal"


def _pt_ctx(*, firing: bool = True) -> "FindingContext":
    """A path_traversal side-effect context. ``firing=False`` puts the signature in the CONTROL too,
    so it is not attributable and the oracle stays silent."""
    return FindingContext.from_side_effect(
        _SIGNATURE, _READ_SINK, bug_class=_PT,
        control_sink=_READ_SINK if not firing else _CONTROL_SINK)


_BASE = _READ_SINK          # the NON-attributable control value (signature already present)
_DIVERGENT = _CONTROL_SINK  # the genuine control: the signature is ABSENT from it


def _ctx(mutated=_CONTROL_SINK) -> dict:
    return FindingContext.from_side_effect(
        _SIGNATURE, _READ_SINK, bug_class=_PT, control_sink=mutated).model_dump(mode="json")


def _finding(**kw) -> FindingPayload:
    base = dict(finding_slug="001", title="t", severity="High", bug_class="path_traversal",
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


def test_multi_critic_agent_skips_leads_but_still_reviews_facts(tmp_path: Path) -> None:
    # Wave-2 flood gate: a LEAD (no oracle_context AND not verified_by_oracle) gets NO advisory panel.
    # A whole-app run posts HUNDREDS of passive-hygiene leads as finding events; reviewing each (3
    # verdicts => 3 synchronous spine commits) was the dominant event-flood that lagged the Live UI.
    # The skip must: leak no verdict, still ADVANCE the cursor (quiesce, no re-review), and NOT
    # suppress a genuine FACT's panel. (The oracle stays sole authority; the panel never promoted.)
    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    bb.engagement_id("e")
    lead = bb.post(engagement="e", kind="finding", agent_name="passive",
                   payload=_finding(finding_slug="L", verified_by_oracle=False,
                                    oracle_context=None).model_dump())
    agent = MultiCriticAgent(bb, "e")
    assert agent.should_run()                                     # the lead IS unreviewed...
    assert agent.step() == 0                                      # ...but the panel is skipped — 0 verdicts
    assert not agent.should_run()                                 # cursor advanced past it; quiesces, no re-review
    assert bb.read(engagement="e", kinds=["critic_verdict"]) == []
    assert panel_verdict_for(bb, "e", lead).verdict == "abstain"  # empty panel for a lead — no crash
    # a genuine FACT posted after is still FULLY reviewed — the gate is selective, not an off-switch.
    fe = bb.post(engagement="e", kind="finding", agent_name="exploit",
                 payload=_finding(finding_slug="F").model_dump())
    assert agent.should_run() and agent.step() == 3
    assert len(bb.read(engagement="e", kinds=["critic_verdict"])) == 3
    assert panel_verdict_for(bb, "e", fe).verdict == "endorse"
    bb.close()


def test_panel_verdict_isolates_and_indexes_by_parent(tmp_path: Path) -> None:
    # X3 O(N^2) fix: panel_verdict_for reads ONLY the verdicts about the target finding, via the
    # indexed parent_id — not every verdict in the engagement filtered in Python. Correctness:
    # two findings each get their own 3-verdict panel; and the DB filter (not a full scan) is used.
    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    bb.engagement_id("e")
    fe1 = bb.post(engagement="e", kind="finding", agent_name="x", payload=_finding(finding_slug="1").model_dump())
    fe2 = bb.post(engagement="e", kind="finding", agent_name="x", payload=_finding(finding_slug="2").model_dump())
    agent = MultiCriticAgent(bb, "e")
    assert agent.step() == 6                                       # 3 verdicts per finding
    # each finding's panel is computed from exactly its own 3 verdicts — no cross-contamination.
    assert panel_verdict_for(bb, "e", fe1).verdict == "endorse"
    assert len(panel_verdict_for(bb, "e", fe1).verdicts) == 3
    assert len(panel_verdict_for(bb, "e", fe2).verdicts) == 3
    # the read is a parent_id-filtered query: a finding with no verdicts reads zero rows.
    assert bb.read(engagement="e", kinds=["critic_verdict"], parent_id=999_999) == []
    assert len(bb.read(engagement="e", kinds=["critic_verdict"], parent_id=fe1)) == 3
    bb.close()


def test_panel_includes_spinesink_posted_verdicts(tmp_path: Path) -> None:
    # X3 regression (review HIGH): the parent_id-filtered panel read must still see a verdict
    # posted via the shipped SpineSink helper — which the old target_event_id-payload scan caught.
    # SpineSink.critic_verdict now sets parent_id=target_event_id so the indexed read includes it.
    from framework.v2.agents.spine_sink import SpineSink

    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    bb.engagement_id("e")
    fe = bb.post(engagement="e", kind="finding", agent_name="exploit", payload=_finding().model_dump())
    sink = SpineSink(bb, "e")
    assert sink.critic_verdict("soundness", target_event_id=fe, verdict="object", severity="major") is not None
    panel = panel_verdict_for(bb, "e", fe)
    assert len(panel.verdicts) == 1 and panel.verdict == "object"   # the spine verdict is counted
    bb.close()
