"""Hypotheses as first-class objects (Phase C). A suspicion recorded from the conversation becomes a
stored object — statement, confirm/refute tests, status — that CLOSES ITSELF when an oracle confirms a
matching finding. These tests pin the store (append-only supersede, safe ids, caps) and the HONEST
auto-close: only a precise bug_class + overlapping-surface match closes a hypothesis, and it is closed
as ``confirmed`` carrying the finding's ref — a vague hunch never auto-confirms off an unrelated finding.
Plus the chat-side extractor/validator and the ``chat_hypotheses`` accessor.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import chat, hypotheses


CHAT = "hyp-chat"


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    yield tmp_path


# --- store ------------------------------------------------------------------------------------------

def test_record_then_list_shows_it_open():
    h = hypotheses.record(CHAT, "reset token is guessable", would_confirm="predict a token",
                          would_refute="256-bit random", bug_class="weak_token", surface="/reset", now=1.0)
    assert h["status"] == "open" and h["id"]
    got = hypotheses.list_for(CHAT)
    assert len(got) == 1 and got[0]["statement"] == "reset token is guessable"


def test_record_refuses_empty_statement_and_unsafe_id():
    with pytest.raises(ValueError):
        hypotheses.record(CHAT, "   ")
    with pytest.raises(ValueError):
        hypotheses.record("../evil", "x")


def test_close_supersedes_append_only():
    h = hypotheses.record(CHAT, "idor on /api/user", bug_class="idor", surface="/api/user", now=1.0)
    hypotheses.close(CHAT, h["id"], status="confirmed", finding_ref="run-9", now=2.0)
    got = hypotheses.list_for(CHAT)
    assert len(got) == 1, "close must SUPERSEDE, not duplicate"
    assert got[0]["status"] == "confirmed" and got[0]["finding_ref"] == "run-9"


def test_reconcile_closes_only_on_a_precise_match():
    open_match = hypotheses.record(CHAT, "idor on the user API", bug_class="idor", surface="/api/user", now=1.0)
    open_wrongclass = hypotheses.record(CHAT, "sqli somewhere", bug_class="sqli", surface="/api/user", now=1.0)
    open_sibling = hypotheses.record(CHAT, "idor on orders", bug_class="idor", surface="/api/v2/orders", now=1.0)
    open_nohint = hypotheses.record(CHAT, "auth feels weak", now=1.0)   # no bug_class → never auto-closes
    facts = [
        {"bug_class": "idor", "surface": "http://t/api/user/1?x=1", "ref": "run-42"},        # closes open_match
        {"bug_class": "idor", "surface": "http://t/api/v2/orders-legacy-export", "ref": "r"},  # SIBLING → no
    ]
    closed = hypotheses.reconcile_confirmed(CHAT, facts, now=3.0)
    assert [c["id"] for c in closed] == [open_match["id"]], "only the precise bug_class+path match closes"
    by_id = {x["id"]: x for x in hypotheses.list_for(CHAT)}
    assert by_id[open_match["id"]]["status"] == "confirmed"
    assert by_id[open_match["id"]]["finding_ref"] == "run-42" and by_id[open_match["id"]]["finding_ref"]
    assert by_id[open_wrongclass["id"]]["status"] == "open"    # different bug_class → untouched
    assert by_id[open_sibling["id"]]["status"] == "open"       # RED-PEN F1: sibling endpoint → untouched
    assert by_id[open_nohint["id"]]["status"] == "open"        # no bug_class → untouched


def test_confirmed_close_requires_a_finding_ref():
    """RED-PEN F6: a 'confirmed' close is an evidence claim — with no proof pointer it must be refused,
    so a hypothesis can never read 'confirmed' with nothing to point at."""
    h = hypotheses.record(CHAT, "idor", bug_class="idor", surface="/api/user", now=1.0)
    assert hypotheses.close(CHAT, h["id"], status="confirmed", finding_ref="", now=2.0) == {}
    assert hypotheses.list_for(CHAT)[0]["status"] == "open"
    # a fact with no ref cannot auto-confirm either
    hypotheses.reconcile_confirmed(CHAT, [{"bug_class": "idor", "surface": "/api/user/1", "ref": ""}], now=3.0)
    assert hypotheses.list_for(CHAT)[0]["status"] == "open"


def test_matches_precision():
    # exact endpoint, or the fact strictly UNDER it at a segment boundary → match
    assert hypotheses._matches({"bug_class": "idor", "surface": "/api/user"},
                               {"bug_class": "idor", "surface": "/api/user"}) is True
    assert hypotheses._matches({"bug_class": "idor", "surface": "/api/user"},
                               {"bug_class": "idor", "surface": "/api/user/1"}) is True
    # different class → no
    assert hypotheses._matches({"bug_class": "idor", "surface": "/api/user"},
                               {"bug_class": "xss", "surface": "/api/user"}) is False
    # RED-PEN F1: a SIBLING endpoint must NOT match (substring containment would have said yes)
    assert hypotheses._matches({"bug_class": "idor", "surface": "/api/user"},
                               {"bug_class": "idor", "surface": "/api/user-legacy-export"}) is False
    # RED-PEN F2: a bug_class-only hunch (no/blank/root surface) never auto-confirms
    assert hypotheses._matches({"bug_class": "idor", "surface": ""},
                               {"bug_class": "idor", "surface": "/anything"}) is False
    assert hypotheses._matches({"bug_class": "idor", "surface": "/"},
                               {"bug_class": "idor", "surface": "/api/invoices"}) is False
    # a generic root FACT location does not close a specific hypothesis
    assert hypotheses._matches({"bug_class": "idor", "surface": "/api/user"},
                               {"bug_class": "idor", "surface": "/"}) is False
    # the fact's surface may be a full URL — matching is over the PATH, not the URL text
    assert hypotheses._matches({"bug_class": "idor", "surface": "/api/user"},
                               {"bug_class": "idor", "location": "http://t:18080/api/user/9?x=1"}) is True


# --- chat-side extractor / validator / accessor -----------------------------------------------------

def test_extract_hypotheses_parses_a_terminated_block():
    clean, raw = chat._extract_hypotheses('answer\n```vigil-hypotheses\n[{"statement":"x"}]\n```')
    assert raw == [{"statement": "x"}] and "vigil-hypotheses" not in clean and clean.startswith("answer")


def test_extract_hypotheses_strips_even_unterminated_but_parses_none():
    # parse is fail-closed (no closing fence → no parse); strip is robust (raw JSON never leaks)
    clean, raw = chat._extract_hypotheses('answer\n```vigil-hypotheses\n[{"statement":"x"}]')
    assert raw == [] and "vigil-hypotheses" not in clean and '"statement"' not in clean
    assert clean.startswith("answer")


def test_validate_hypotheses_requires_statement_and_caps():
    raw = [{"would_confirm": "no statement"}, {"statement": "s", "bug_class": "idor", "surface": "/u"}]
    out = chat._validate_hypotheses(raw)
    assert len(out) == 1 and out[0]["statement"] == "s" and out[0]["bug_class"] == "idor"
    big = [{"statement": "s%d" % i} for i in range(50)]
    assert len(chat._validate_hypotheses(big)) <= chat._MAX_HYP_PROPOSALS


def test_chat_hypotheses_accessor_and_unsafe_id():
    hypotheses.record(CHAT, "a suspicion", now=1.0)
    out = chat.chat_hypotheses(CHAT)
    assert out["chat_id"] == CHAT and len(out["hypotheses"]) == 1
    with pytest.raises(ValueError):
        chat.chat_hypotheses("../../etc/passwd")


# --- end to end through chat_send --------------------------------------------------------------------

def test_chat_send_records_model_hypotheses(monkeypatch):
    reply = ('Plan: I suspect the reset flow.\n\n```vigil-hypotheses\n'
             '[{"statement":"reset token is guessable","would_confirm":"predict one","bug_class":"weak_token","surface":"/reset"}]\n```')
    mod = types.ModuleType("anthropic")

    class _B:
        type = "text"

        def __init__(self, t):
            self.text = t

    class _R:
        stop_reason = "end_turn"

        def __init__(self, t):
            self.content = [_B(t)]

    class _C:
        def __init__(self, api_key=None, **kw):
            self.messages = self

        def create(self, **kw):
            return _R(reply)

    mod.Anthropic = _C
    monkeypatch.setitem(sys.modules, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    out = chat.chat_send({"chat_id": CHAT, "message": "look at auth", "reason_mode": "plan"})
    assert out["status"] == "answer", out
    assert "vigil-hypotheses" not in out["reply"], "the raw block must not reach the operator"
    hyps = out.get("hypotheses") or []
    assert any(hp["statement"] == "reset token is guessable" for hp in hyps)
    # and it PERSISTS (visible via the accessor on a plain reload)
    assert any(hp["statement"] == "reset token is guessable"
               for hp in chat.chat_hypotheses(CHAT)["hypotheses"])
