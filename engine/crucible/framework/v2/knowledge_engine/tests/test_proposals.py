"""
K2 — the propose-to-learn drafter (`knowledge_engine.proposals`).

Doctrine under test:
  * DETERMINISTIC ranking — known-exploited first, then severity, then CVSS, then id (stable);
  * READ-ONLY — a proposal is ``status="proposed"`` and authorises nothing; drafting mints no fact,
    fires no oracle, and never mutates its input;
  * total — a lead with no id is skipped; ``limit`` bounds the queue.
"""

from __future__ import annotations

from framework.v2.knowledge_engine.proposals import LearnProposal, draft_proposals


def _lead(id, *, ek=False, sev="", cvss=None):
    return {"id": id, "exploit_known": ek, "severity": sev, "cvss": cvss}


def test_ranking_is_deterministic_kev_then_severity_then_cvss():
    leads = [
        _lead("CVE-A", ek=False, sev="HIGH", cvss=7.5),
        _lead("CVE-B", ek=True, sev="MEDIUM", cvss=5.0),
        _lead("CVE-C", ek=True, sev="CRITICAL", cvss=9.8),
        _lead("CVE-D", ek=True, sev="CRITICAL", cvss=6.0),   # same KEV+sev as C → CVSS breaks the tie
    ]
    out = draft_proposals(leads)
    assert [p.vuln_id for p in out] == ["CVE-C", "CVE-D", "CVE-B", "CVE-A"]
    assert [p.rank for p in out] == [1, 2, 3, 4]
    # deterministic: same input → identical order twice
    assert [p.vuln_id for p in draft_proposals(leads)] == [p.vuln_id for p in out]


def test_proposals_authorise_nothing_and_never_mutate_input():
    leads = [_lead("CVE-X", ek=True, sev="CRITICAL", cvss=9.9)]
    snapshot = [dict(x) for x in leads]
    out = draft_proposals(leads)
    assert all(isinstance(p, LearnProposal) and p.status == "proposed" for p in out)
    p = out[0]
    assert p.exploit_known is True and p.vuln_id == "CVE-X"
    assert "known-exploited" in p.rationale and "advisory" in p.rationale
    assert leads == snapshot                                   # input untouched (pure)


def test_no_id_lead_skipped_and_limit_bounds_queue():
    leads = [_lead(""), _lead("CVE-1", ek=True), _lead("CVE-2", ek=True), _lead("CVE-3", ek=True)]
    assert [p.vuln_id for p in draft_proposals(leads)] == ["CVE-1", "CVE-2", "CVE-3"]  # empty id dropped
    assert len(draft_proposals(leads, limit=2)) == 2
    assert draft_proposals([], limit=10) == []
    assert draft_proposals(leads, limit=0) == []
