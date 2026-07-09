"""
Nervous-System N2 — temporal credit assignment over the spine provenance DAG.

When a finding is confirmed, the choices that led to it (decision ← hypothesis ← plan) should
accrue credit so the planner/scheduler can later re-rank on what pays off. credit_finding_path
walks the parent_id chain backward and posts a reward crediting each ancestral choice.
"""

from __future__ import annotations

from pathlib import Path

from framework.v2.agents.blackboard import open_blackboard
from framework.v2.agents.spine_credit import credit_finding_path


def _chain(bb):
    dec = bb.post(engagement="e", kind="decision", agent_name="coord",
                  payload={"question": "which surface?", "choice": "search", "rationale": "hot"})
    hyp = bb.post(engagement="e", kind="hypothesis", agent_name="hyp", parent_id=dec,
                  payload={"handle": "H-1", "surface": "/search", "bug_class": "boolean_sqli",
                           "given": "g", "if_action": "a", "then_observation": "o",
                           "because_model": "m", "refute_on": "r", "cheap_test": "c"})
    plan = bb.post(engagement="e", kind="plan", agent_name="hyp", parent_id=hyp,
                   payload={"plan_id": "P-1", "targets_hypothesis": "H-1", "next_action": "probe q"})
    act = bb.post(engagement="e", kind="action", agent_name="exploit", parent_id=plan,
                  payload={"action_id": "A-1", "plan_id": "P-1", "tool": "curl", "args_summary": "?q=1'"})
    res = bb.post(engagement="e", kind="result", agent_name="exploit", parent_id=act,
                  payload={"action_id": "A-1", "success": True, "status_code": 200})
    fnd = bb.post(engagement="e", kind="finding", agent_name="exploit", parent_id=res,
                  payload={"finding_slug": "001-sqli", "title": "SQLi", "severity": "High",
                           "bug_class": "boolean_sqli", "surface": "/search",
                           "summary": "rows diverged"})
    return dec, hyp, plan, act, res, fnd


def test_credit_walks_the_provenance_chain(tmp_path: Path) -> None:
    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    bb.engagement_id("e")
    dec, hyp, plan, act, res, fnd = _chain(bb)

    credited = credit_finding_path(bb, "e", fnd, reward=1.0)
    # the CHOICES (decision/hypothesis/plan) are credited; action/result are not creditable
    assert set(credited) == {dec, hyp, plan}
    rewards = bb.read(engagement="e", kinds=["reward"])
    assert len(rewards) == 3
    assert all(rw.payload["source"] == "credit" and rw.payload["reward"] == 1.0 for rw in rewards)
    assert {rw.payload["target_event_id"] for rw in rewards} == {dec, hyp, plan}
    bb.close()


def test_credit_is_cycle_safe_and_bounded(tmp_path: Path) -> None:
    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    bb.engagement_id("e")
    # a lone finding with no provenance credits nobody (and does not crash)
    fnd = bb.post(engagement="e", kind="finding", agent_name="x",
                  payload={"finding_slug": "1", "title": "t", "severity": "Low",
                           "bug_class": "x", "surface": "s", "summary": "y"})
    assert credit_finding_path(bb, "e", fnd, reward=1.0) == []
    bb.close()
