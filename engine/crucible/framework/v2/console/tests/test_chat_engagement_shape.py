"""Engagement shape (Phase A3/A4) — the chat can answer "what have we not covered?" and "is this a lead
or a fact?" from the ENGINE'S OWN read-only record, not a guess. ``_engagement_shape`` assembles scope,
kill-switch, confirmed-vs-lead totals, per-run coverage, refusals-with-reason, and how many actions
await a signature; ``_engagement_prompt_block`` renders it for the model.

Properties pinned here:
  * fact-ness is read from each finding's ``grounding`` (the engine's label), never invented;
  * the shape degrades part-by-part (one unreadable reader omits its part, never the whole);
  * the assembled shape is passed through the same context redactor the session context uses;
  * ``_reason_wanted`` now also fires for a chat scoped to a live engagement (so "how is it going?"
    reasons even with nothing attached), still gated on a key.

Every api reader is faked — no real engagement or run is touched.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import api, chat, sessions


CHAT = "shape-chat"


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    yield tmp_path


def _wire_engine(monkeypatch, *, report=None, runs=None, charter=None, detail=None, pending=2):
    """Point sessions + api at a fake engagement 'eng-1' with one run 'r1'."""
    monkeypatch.setattr(sessions, "get_session", lambda cid: {"slug": "eng-1", "run_ids": ["r1"]})
    monkeypatch.setattr(sessions, "_session_engagements", lambda rec: ["eng-1"])
    monkeypatch.setattr(api, "charter_status",
                        lambda slug: charter if charter is not None
                        else {"scope": ["127.0.0.1:8080"], "is_loopback_only": True})
    monkeypatch.setattr(api, "engagement_detail",
                        lambda slug: detail if detail is not None
                        else {"killswitch": {"tripped": False, "reason": None}})
    monkeypatch.setattr(api, "status_data", lambda: {"pending_approvals": pending})
    monkeypatch.setattr(api, "list_runs",
                        lambda slug="": {"runs": runs if runs is not None
                                         else [{"run_id": "r1", "status": "running", "mode": "url",
                                                "target": "http://127.0.0.1:8080"}]})
    monkeypatch.setattr(api, "run_report",
                        lambda rid: report if report is not None
                        else {"findings": [{"grounding": "fact", "title": "sqli"},
                                           {"grounding": "lead", "title": "maybe"}],
                              "discovered_endpoints": ["/a", "/b", "/c"],
                              "refusals": [{"gate": "warden", "action": "exec_command",
                                            "reason": "A3 tier needs a signed approval"}]})


# ---------------------------------------------------------------------------------------------------
# _report_shape
# ---------------------------------------------------------------------------------------------------

def test_report_shape_counts_by_grounding_not_status():
    rep = {"findings": [{"grounding": "fact"}, {"grounding": "fact"}, {"grounding": "lead"},
                        {"status": "fact"}]}   # a 'status' key is NOT the engine's fact label — ignored
    facts, leads, refusals, eps = chat._report_shape(rep)
    assert facts == 2 and leads == 1 and refusals == [] and eps is None


def test_report_shape_extracts_refusals_and_endpoints():
    rep = {"findings": [], "discovered_endpoints": ["/x", "/y"],
           "refusals": [{"gate": "warden", "action": "exec", "reason": "queued"}]}
    facts, leads, refusals, eps = chat._report_shape(rep)
    assert eps == 2 and refusals[0]["gate"] == "warden" and refusals[0]["reason"] == "queued"


def test_report_shape_is_total_on_junk():
    assert chat._report_shape(None) == (0, 0, [], None)
    assert chat._report_shape({"findings": ["not a dict", 3]}) == (0, 0, [], None)


# ---------------------------------------------------------------------------------------------------
# _engagement_shape
# ---------------------------------------------------------------------------------------------------

def test_shape_assembles_the_engine_record(monkeypatch):
    _wire_engine(monkeypatch)
    s = chat._engagement_shape(CHAT)
    assert s["slug"] == "eng-1"
    assert s["scope"] == ["127.0.0.1:8080"] and s["loopback_only"] is True
    assert s["killswitch"] == {"tripped": False, "reason": None}
    assert s["pending_approvals"] == 2
    assert s["confirmed_total"] == 1 and s["lead_total"] == 1
    run = s["runs"][0]
    assert run["status"] == "running" and run["facts"] == 1 and run["leads"] == 1
    assert run["endpoints_discovered"] == 3
    assert s["refusals"][0]["reason"] == "A3 tier needs a signed approval"


def test_shape_is_empty_when_the_chat_is_tied_to_no_engagement(monkeypatch):
    monkeypatch.setattr(sessions, "get_session", lambda cid: {"slug": "", "run_ids": []})
    monkeypatch.setattr(sessions, "_session_engagements", lambda rec: [])
    assert chat._engagement_shape(CHAT) == {}


def test_shape_degrades_part_by_part_when_a_reader_raises(monkeypatch):
    _wire_engine(monkeypatch)
    monkeypatch.setattr(api, "charter_status", lambda slug: (_ for _ in ()).throw(RuntimeError("boom")))
    s = chat._engagement_shape(CHAT)
    assert "scope" not in s                  # the failed part is omitted...
    assert s["slug"] == "eng-1" and s["pending_approvals"] == 2 and s["runs"]   # ...the rest survives


def test_shape_is_passed_through_the_context_redactor(monkeypatch):
    _wire_engine(monkeypatch)
    ran = {}
    orig = actions_mod._redact_ctx

    def spy(obj):
        ran["yes"] = True
        return orig(obj)

    monkeypatch.setattr(actions_mod, "_redact_ctx", spy)
    chat._engagement_shape(CHAT)
    assert ran.get("yes") is True, "the shape must pass through the load-bearing context redactor"


def test_prompt_block_labels_and_serialises(monkeypatch):
    _wire_engine(monkeypatch)
    block = chat._engagement_prompt_block(chat._engagement_shape(CHAT))
    assert block.startswith("ENGAGEMENT SHAPE")
    assert "FACT is oracle-confirmed" in block and "127.0.0.1:8080" in block


def test_prompt_block_empty_for_empty_shape():
    assert chat._engagement_prompt_block({}) == ""


# ---------------------------------------------------------------------------------------------------
# _reason_wanted now fires for a live-engagement chat (with a key)
# ---------------------------------------------------------------------------------------------------

def test_reason_wanted_fires_for_an_engagement_scoped_chat_with_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setattr(sessions, "connections_of", lambda cid: [])
    monkeypatch.setattr(sessions, "get_session", lambda cid: {"slug": "eng-1", "run_ids": []})
    assert chat._reason_wanted(CHAT, {}) is True


def test_reason_wanted_stays_false_for_an_engagement_scoped_chat_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(sessions, "connections_of", lambda cid: [])
    monkeypatch.setattr(sessions, "get_session", lambda cid: {"slug": "eng-1", "run_ids": []})
    assert chat._reason_wanted(CHAT, {}) is False   # keyless keeps the ask-for-a-target reply
