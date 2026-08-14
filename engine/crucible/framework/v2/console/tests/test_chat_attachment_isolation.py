"""Chat attachments — MEMORY ISOLATION and the operator-consented LINK between chats.

The product promise is two things at once, and they pull in opposite directions:

  * each chat's memory is INDEPENDENT — what the operator uploaded into one engagement's chat, and
    what they said in it, must not turn up while they are reasoning about another. On a shared
    console that is a confidentiality boundary between two clients' material, not a tidiness
    preference;
  * a chat can be CONNECTED to another so it reasons with that chat's history — connectable,
    disconnectable, several at once.

The reconciliation the console already uses for sessions is a READ-TIME SCOPE, not a graph merge:
nothing of B is copied into A, so a disconnect re-isolates A on its very next retrieval with no
residue. These tests hold the feature to that model in BOTH directions — the link must actually carry
the other chat's history (a link that carries nothing is a lie in the UI), and disconnecting must
actually remove it (a link whose removal leaves a copy behind is a lie about the boundary).

The model-facing payload for a chat is assembled from two independent halves — the redacted session
context and the fenced attachment block — so every assertion here is made against BOTH, never against
one of them. A leak through the half a test forgot to look at is still a leak.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import attachments, chat, sessions
from framework.v2.console.tests.attach_fixtures import upload, zip_bytes

ALPHA, BETA, GAMMA = "alpha-chat", "beta-chat", "gamma-chat"

ALPHA_CODE = b"def login(u, p):\n    # MARKER_ALPHA_FILE_BODY\n    return check(u, p)\n"
ALPHA_SAID = "MARKER_ALPHA_QUESTION does the billing service verify the JWT signature?"
ALPHA_ANSWER = "MARKER_ALPHA_ANSWER a lead: the verify call passes verify=False"
GAMMA_SAID = "MARKER_GAMMA_QUESTION what does the payment webhook trust?"


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    attachments._UPLOADS.clear()
    yield tmp_path
    attachments._UPLOADS.clear()


def payload(chat_id: str) -> str:
    """Everything about ``chat_id`` that a turn would send to the model: the redacted session context
    (which is where a CONNECTED chat's knowledge arrives) plus the fenced attachment block. Assertions
    are made against the concatenation so neither half can hide a leak from the other."""
    block, _truncated = chat._attachment_block(chat_id)
    return chat._context_block(chat_id) + "\n" + block


def seed_alpha() -> dict:
    man = upload(ALPHA, "billing.zip", zip_bytes([("src/auth/login.py", ALPHA_CODE)]))
    assert man.get("ok"), man
    sessions.ensure_session(ALPHA, kind="chat")
    chat._append(ALPHA, {"role": "user", "text": ALPHA_SAID})
    chat._append(ALPHA, {"role": "assistant", "text": ALPHA_ANSWER, "kind": "answer"})
    chat._append(ALPHA, chat._record_for(man))
    return man


def seed_gamma() -> None:
    sessions.ensure_session(GAMMA, kind="chat")
    chat._append(GAMMA, {"role": "user", "text": GAMMA_SAID})


def seed_beta() -> None:
    sessions.ensure_session(BETA, kind="chat")
    chat._append(BETA, {"role": "user", "text": "MARKER_BETA_QUESTION unrelated question"})


# ---------------------------------------------------------------------------------------------------
# 5a. independent by default
# ---------------------------------------------------------------------------------------------------

def test_attachments_belong_to_one_chat_only():
    """The upload lands in ALPHA. BETA must see no trace of it — not the file, not the manifest, not
    the extracted directory it would offer for a gated scan."""
    seed_alpha()
    seed_beta()

    assert attachments.list_attachments(BETA) == []
    ctx = attachments.build_context(BETA, 100_000)
    assert ctx["files"] == [] and ctx["text"] == "" and ctx["images"] == [] and ctx["root"] == ""

    assert "MARKER_ALPHA_FILE_BODY" not in payload(BETA)
    assert "billing.zip" not in payload(BETA)


def test_an_unconnected_chats_transcript_is_invisible():
    seed_alpha()
    seed_beta()
    body = payload(BETA)
    for marker in ("MARKER_ALPHA_QUESTION", "MARKER_ALPHA_ANSWER", "MARKER_ALPHA_FILE_BODY"):
        assert marker not in body, f"{marker} leaked into an unconnected chat"

    # ...and the reasoning path knows there is nothing to reason over, so the turn stays the plain
    # ask-for-a-target reply rather than a model call over an empty context.
    assert chat._reason_wanted(BETA, {}) is False


# ---------------------------------------------------------------------------------------------------
# 5b. connecting carries the other chat's history — and only its history
# ---------------------------------------------------------------------------------------------------

def test_connecting_a_chat_brings_its_transcript_into_the_context():
    seed_alpha()
    seed_beta()
    assert sessions.connect_session(BETA, ALPHA).get("ok"), "the connection was refused"

    body = payload(BETA)
    assert "MARKER_ALPHA_QUESTION" in body, "the linked chat's history did not arrive"
    assert "MARKER_ALPHA_ANSWER" in body
    assert ALPHA in body, "the linked material is not tagged with its origin session"
    assert chat._reason_wanted(BETA, {}) is True

    # non-authoritative: a linked chat's talk is background, never this chat's proven ground.
    ctx = actions_mod.session_context(session_id=BETA)
    linked = ctx.get("linked_chat_history") or []
    assert linked and all(entry.get("authoritative") is False for entry in linked)
    assert all(msg.get("session") == ALPHA for entry in linked for msg in entry["messages"])


def test_a_connected_chats_uploads_are_declared_but_their_contents_are_not_shared():
    """Both halves of the boundary at once.

    DECLARED: an upload is an event in the linked chat's history. If BETA cannot see that ALPHA has a
    codebase attached, "link another chat for deeper context" is delivering a conversation with its
    subject removed — and the omission is silent, so nothing tells the operator.

    NOT SHARED: the link is a read-time scope, not a bytes merge. ALPHA's file CONTENT must still not
    appear in BETA's payload, and BETA's own attachment block must stay empty — otherwise connecting
    two chats quietly widens what leaves the host.
    """
    seed_alpha()
    seed_beta()
    assert sessions.connect_session(BETA, ALPHA).get("ok")

    body = payload(BETA)
    assert "MARKER_ALPHA_FILE_BODY" not in body, "connecting a chat copied its file contents across"
    assert attachments.build_context(BETA, 100_000)["files"] == []
    assert attachments.list_attachments(BETA) == []

    assert "billing.zip" in body, \
        "the linked chat's attachment is missing from its history — silently, and not counted as omitted"


def test_several_chats_can_be_connected_at_once_and_removed_one_at_a_time():
    seed_alpha()
    seed_gamma()
    seed_beta()
    assert sessions.connect_session(BETA, ALPHA).get("ok")
    assert sessions.connect_session(BETA, GAMMA).get("ok")
    assert sorted(sessions.connections_of(BETA)) == sorted([ALPHA, GAMMA])

    body = payload(BETA)
    assert "MARKER_ALPHA_QUESTION" in body and "MARKER_GAMMA_QUESTION" in body

    assert sessions.disconnect_session(BETA, ALPHA).get("ok")
    body = payload(BETA)
    assert "MARKER_ALPHA_QUESTION" not in body, "disconnecting one link dropped the wrong one"
    assert "MARKER_GAMMA_QUESTION" in body, "disconnecting one link dropped the others too"


def test_the_link_is_directional():
    """A draws on B does not make B draw on A. Otherwise one operator connecting their chat to a
    colleague's would silently publish their own material into it."""
    seed_alpha()
    seed_beta()
    assert sessions.connect_session(BETA, ALPHA).get("ok")

    alpha_body = payload(ALPHA)
    assert "MARKER_BETA_QUESTION" not in alpha_body, "the link carried knowledge backwards"
    assert sessions.connections_of(ALPHA) == []


# ---------------------------------------------------------------------------------------------------
# 5c. disconnect is immediate and leaves no residue
# ---------------------------------------------------------------------------------------------------

def test_disconnecting_removes_the_history_from_the_very_next_call():
    seed_alpha()
    seed_beta()
    sessions.connect_session(BETA, ALPHA)
    assert "MARKER_ALPHA_QUESTION" in payload(BETA)

    assert sessions.disconnect_session(BETA, ALPHA).get("ok")
    body = payload(BETA)                                     # the VERY NEXT call — no cache, no residue
    for marker in ("MARKER_ALPHA_QUESTION", "MARKER_ALPHA_ANSWER", "billing.zip"):
        assert marker not in body, f"{marker} survived the disconnect"
    assert chat._reason_wanted(BETA, {}) is False

    # nothing of ALPHA was ever copied into BETA's own state, so there is nothing left to leak.
    assert sessions.connections_of(BETA) == []
    assert json.dumps(actions_mod.session_context(session_id=BETA)).count(ALPHA) == 0


def test_reconnecting_picks_up_what_the_other_chat_said_in_the_meantime():
    """A read-time scope reads at read time: the link is not a snapshot taken when it was made."""
    seed_alpha()
    seed_beta()
    sessions.connect_session(BETA, ALPHA)
    sessions.disconnect_session(BETA, ALPHA)

    chat._append(ALPHA, {"role": "user", "text": "MARKER_ALPHA_LATER and the refresh token path?"})
    assert "MARKER_ALPHA_LATER" not in payload(BETA)

    sessions.connect_session(BETA, ALPHA)
    assert "MARKER_ALPHA_LATER" in payload(BETA)


def test_a_linked_transcript_is_bounded_and_says_how_much_it_omitted():
    """``chat.read_session`` is unbounded on disk, so the fusion has to cap. What matters is that the
    cap is REPORTED: an answer drawn from 12 of 400 messages is a different claim from one drawn from
    all of them."""
    seed_beta()
    sessions.ensure_session(ALPHA, kind="chat")
    for i in range(60):
        chat._append(ALPHA, {"role": "user", "text": f"MARKER_ALPHA_MSG_{i:03d} " + "detail " * 200})
    sessions.connect_session(BETA, ALPHA)

    ctx = actions_mod.session_context(session_id=BETA)
    entry = (ctx.get("linked_chat_history") or [{}])[0]
    assert entry.get("included", 0) > 0
    assert entry.get("omitted", 0) > 0, "a truncated transcript reported nothing omitted"
    assert entry["included"] + entry["omitted"] == 60
    assert len(entry["messages"]) == entry["included"] <= actions_mod._CTX_MAX_LINKED_CHAT_MSGS
    body = "".join(m["text"] for m in entry["messages"])
    assert len(body) <= actions_mod._CTX_MAX_LINKED_CHAT_CHARS + len(entry["messages"])
    # newest first — the recent turns are the ones worth carrying.
    assert "MARKER_ALPHA_MSG_059" in body and "MARKER_ALPHA_MSG_000" not in body


def test_a_credential_in_a_linked_transcript_is_masked_before_it_egresses():
    """The linked half goes through the same mandatory redaction as everything else in the context —
    it is another chat's free text, and the operator may well have pasted a token into it."""
    seed_beta()
    sessions.ensure_session(ALPHA, kind="chat")
    chat._append(ALPHA, {"role": "user",
                         "text": "here is the header Authorization: Bearer sk-ant-LEAKED-TOKEN-VALUE"})
    sessions.connect_session(BETA, ALPHA)
    body = payload(BETA)
    assert "sk-ant-LEAKED-TOKEN-VALUE" not in body
    assert "Authorization" in body                            # the NAME survives; the value does not
