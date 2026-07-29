"""U3 — the read-only agent-inbox provider (api.inbox).

The directed agent-to-agent ``agent_message`` events are COORDINATION only: a message is structurally NOT
evidence — no fact-building path reads this kind — so the provider marks the payload ``advisory`` and can
never promote a finding. It reads the append-only blackboard spine read-only, is bounded, secret-scrubbed,
and total (an unregistered/absent engagement → an empty list, never a traceback).
"""

from __future__ import annotations

import json

from framework.v2.agents.blackboard import Blackboard
from framework.v2.console import api


def _bb_with(tmp_path, monkeypatch, name="bb.sqlite"):
    db = tmp_path / name
    monkeypatch.setattr("framework.v2.agents.blackboard.open_blackboard",
                        lambda db_path=None: Blackboard(db_path=db))
    return Blackboard(db_path=db)


def _msg(sender, recipient, body, topic="coord"):
    # the S5 agent_message payload shape; sender MUST equal the posting agent (anti-spoof).
    return {"sender": sender, "recipient": recipient, "topic": topic, "body": body, "refs": []}


def test_inbox_reads_directed_agent_messages(tmp_path, monkeypatch):
    bb = _bb_with(tmp_path, monkeypatch)
    bb.post(engagement="loopback", kind="agent_message", agent_name="scout",
            payload=_msg("scout", "exploiter", "boolean sqli looks live on tfSearch"))
    bb.post(engagement="loopback", kind="agent_message", agent_name="exploiter",
            payload=_msg("exploiter", "scout", "confirmed — differential 200->500"))
    bb.close()

    r = api.inbox("loopback")
    assert r["ok"] is True and r["advisory"] is True and r["slug"] == "loopback"
    bodies = [m["body"] for m in r["messages"]]
    assert "boolean sqli looks live on tfSearch" in bodies
    assert any(m["sender"] == "exploiter" and m["recipient"] == "scout" for m in r["messages"])


def test_inbox_empty_for_unregistered_engagement(tmp_path, monkeypatch):
    _bb_with(tmp_path, monkeypatch).close()             # a fresh, empty blackboard
    r = api.inbox("never-started")                      # engagement_id(create=False) raises → handled
    assert r["ok"] is True and r["messages"] == []


def test_inbox_blank_slug_is_empty(tmp_path, monkeypatch):
    _bb_with(tmp_path, monkeypatch).close()
    assert api.inbox("")["messages"] == []


def test_inbox_scrubs_a_secret_in_a_message_body(tmp_path, monkeypatch):
    bb = _bb_with(tmp_path, monkeypatch)
    bb.post(engagement="loopback", kind="agent_message", agent_name="scout",
            payload=_msg("scout", "exploiter", "leaked sk-ant-INBOXSECRET0123456789 in the response"))
    bb.close()
    r = api.inbox("loopback")
    assert "sk-ant-INBOXSECRET0123456789" not in json.dumps(r)   # scrubbed before egress
    assert r["messages"]                                          # the message row still surfaces (redacted)
