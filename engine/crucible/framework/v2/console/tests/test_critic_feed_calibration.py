"""The Activity/critic feed CALIBRATION (view-only, oracle-authority-preserving).

The grounding critic objects (severity 'major') to every finding that does not re-ground as a fact —
which for a whole-app scan is the whole flood of PASSIVE LEADS, rendering as dozens of "(major)" alarms
even though each finding was correctly kept a LEAD. ``BlackboardTailer`` annotates each critic_verdict's
EMITTED view (never the append-only row) so the UI can tell an EXPECTED objection-to-a-lead (calm, folded)
from a GENUINE demotion (a critic objecting to a real oracle-confirmed FACT — stays loud).

These pin the server half; the fold + muted rendering is JS (node --check only, per repo convention)."""
from __future__ import annotations

from framework.v2.agents.blackboard import open_blackboard
from framework.v2.console.blackboard_sse import BlackboardTailer

SLUG = "cal-test"


def _critics(evs):
    return [ev["payload"] for _id, ev in evs if ev["kind"] == "critic_verdict"]


def test_object_on_a_lead_is_expected_and_downgraded(tmp_path):
    db = tmp_path / "bb.sqlite"
    b = open_blackboard(db_path=db)
    lead = b.post(engagement=SLUG, kind="finding", agent_name="scanner",
                  payload={"finding_slug": "passive:csp", "title": "Missing CSP", "severity": "Medium", "bug_class": "missing-content-security-policy", "surface": "http://127.0.0.1:19010/", "summary": "CSP header absent", "verified_by_oracle": False})
    b.post(engagement=SLUG, kind="critic_verdict", agent_name="grounding",
           payload={"critic": "grounding", "target_event_id": lead, "verdict": "object", "severity": "major"})
    b.close()
    t = BlackboardTailer(SLUG, db_path=db)
    cv = _critics(t.read_new())[0]
    t.close()
    assert cv["target_grounding"] == "lead"
    assert cv["routine"] is True
    assert cv["expected"] is True
    assert cv["display_severity"] == "info"          # 'major' -> 'info' for display only
    assert "lead" in cv["display_note"]


def test_object_on_a_confirmed_fact_stays_loud(tmp_path):
    db = tmp_path / "bb.sqlite"
    b = open_blackboard(db_path=db)
    fact = b.post(engagement=SLUG, kind="finding", agent_name="scanner",
                  payload={"finding_slug": "xss:q:0", "title": "xss confirmed", "severity": "High", "bug_class": "xss", "surface": "q", "summary": "xss confirmed", "verified_by_oracle": True, "oracle_context": {"bug_class": "xss"}})
    b.post(engagement=SLUG, kind="critic_verdict", agent_name="grounding",
           payload={"critic": "grounding", "target_event_id": fact, "verdict": "object", "severity": "major"})
    b.post(engagement=SLUG, kind="critic_verdict", agent_name="provenance",
           payload={"critic": "provenance", "target_event_id": fact, "verdict": "endorse", "severity": "info"})
    b.close()
    t = BlackboardTailer(SLUG, db_path=db)
    cvs = _critics(t.read_new())
    t.close()
    obj = [c for c in cvs if c["verdict"] == "object"][0]
    assert obj["target_grounding"] == "fact"
    assert obj["routine"] is False                   # a demotion is NOT folded away
    assert obj["expected"] is False
    assert obj["display_severity"] == "major"        # and it stays loud
    endorse = [c for c in cvs if c["verdict"] == "endorse"][0]
    assert endorse["routine"] is False               # verdicts about a fact are never routine


def test_reconnect_cache_miss_reads_the_target_directly(tmp_path):
    """A tailer that resumes AFTER the finding (its grounding not in the running cache) still classifies
    the verdict by reading the target row directly — so a reconnect never mislabels a lead objection."""
    db = tmp_path / "bb.sqlite"
    b = open_blackboard(db_path=db)
    lead = b.post(engagement=SLUG, kind="finding", agent_name="scanner",
                  payload={"finding_slug": "passive:banner", "title": "Server banner", "severity": "Info", "bug_class": "info-server-banner", "surface": "http://127.0.0.1:19010/", "summary": "server banner", "verified_by_oracle": False})
    b.post(engagement=SLUG, kind="critic_verdict", agent_name="grounding",
           payload={"critic": "grounding", "target_event_id": lead, "verdict": "object", "severity": "major"})
    b.close()
    t = BlackboardTailer(SLUG, since_id=lead, db_path=db)   # resume PAST the finding event
    cvs = _critics(t.read_new())
    t.close()
    assert cvs and cvs[0]["target_grounding"] == "lead" and cvs[0]["expected"] is True


def test_the_stored_row_is_never_mutated(tmp_path):
    """The calibration enriches the EMITTED view only; the append-only spine row keeps its original payload
    (no display_severity/expected/routine leaks back into storage)."""
    db = tmp_path / "bb.sqlite"
    b = open_blackboard(db_path=db)
    lead = b.post(engagement=SLUG, kind="finding", agent_name="scanner",
                  payload={"finding_slug": "passive:xfo", "title": "Missing XFO", "severity": "Low", "bug_class": "missing-x-frame-options", "surface": "http://127.0.0.1:19010/", "summary": "XFO absent", "verified_by_oracle": False})
    cvid = b.post(engagement=SLUG, kind="critic_verdict", agent_name="grounding",
                  payload={"critic": "grounding", "target_event_id": lead, "verdict": "object", "severity": "major"})
    BlackboardTailer(SLUG, db_path=db).read_new()   # emit (and enrich the view)
    stored = b.get(cvid).payload
    b.close()
    assert "display_severity" not in stored and "expected" not in stored and "routine" not in stored
    assert stored["severity"] == "major"            # the real recorded severity is untouched
