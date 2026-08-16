"""Four visibly-distinct sources (Phase A2) — the "grounded in" legend. CHAT-VISION: an answer comes
from evidence-in-engagement / attached material / a linked chat / the model's own inference, and those
"must be visibly distinguishable … rendering the fourth in the same register as the first is the single
most damaging thing this screen could do."

A chat answer is ALWAYS a lead (the Lead badge on the bubble). This legend adds the two sources the
model may VERIFIABLY cite — an attached file that really appears in the block it was shown, and a chat
that is really linked. The load-bearing property tested here: the SERVER, not the model, decides which
citations are real. The model can never self-declare "evidence"/"confirmed"; an unverifiable citation
is dropped and simply falls under model inference. So a lead can never wear a confirmed finding's
clothes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import chat


CHAT = "src-chat"
VIEW = {"text": (chat._FILE_LABEL + "app/auth/login.py\n"
                 "1 def check(pw): return pw == SECRET\n"
                 + chat._FILE_LABEL + "app/util/hash.py\n"
                 "1 import hashlib\n")}


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    yield tmp_path


def _no_connections(monkeypatch, ids=()):
    from framework.v2.console import sessions
    monkeypatch.setattr(sessions, "connections_of", lambda cid: list(ids))


# ---------------------------------------------------------------------------------------------------
# _extract_sources
# ---------------------------------------------------------------------------------------------------

def test_extract_strips_the_sources_block_and_parses_it():
    text = ("answer\n\n```vigil-sources\n"
            "[{\"kind\":\"attached\",\"ref\":\"app/auth/login.py\"}]\n```")
    clean, raw = chat._extract_sources(text)
    assert clean == "answer" and "vigil-sources" not in clean
    assert raw == [{"kind": "attached", "ref": "app/auth/login.py"}]


def test_extract_malformed_sources_block_is_stripped_and_empty():
    clean, raw = chat._extract_sources("a\n```vigil-sources\n{bad json\n```")
    assert raw == [] and "vigil-sources" not in clean and "bad json" not in clean


def test_extract_unterminated_sources_fence_is_still_stripped():
    """Red-pen F1 mirror: an unterminated vigil-sources fence must not leak its raw JSON to the operator."""
    clean, raw = chat._extract_sources('answer\n```vigil-sources\n[{"kind":"evidence","ref":"x"}]')
    assert raw == [] and "vigil-sources" not in clean and "evidence" not in clean
    assert clean.startswith("answer")


# ---------------------------------------------------------------------------------------------------
# _validate_sources — the server is the authority on what is a real source
# ---------------------------------------------------------------------------------------------------

def test_attached_ref_must_actually_appear_in_the_block(monkeypatch):
    _no_connections(monkeypatch)
    raw = [{"kind": "attached", "ref": "app/auth/login.py", "note": "the compare"},
           {"kind": "attached", "ref": "app/NOT/shown.py", "note": "invented"}]
    out = chat._validate_sources(CHAT, raw, VIEW)
    assert [s["ref"] for s in out] == ["app/auth/login.py"], "a file the model was not shown was accepted"


def test_attached_basename_resolves_only_when_unambiguous(monkeypatch):
    _no_connections(monkeypatch)
    # "login.py" is a unique tail → resolves to the full path; "x.py" matches nothing → dropped
    out = chat._validate_sources(CHAT, [{"kind": "attached", "ref": "login.py"},
                                        {"kind": "attached", "ref": "x.py"}], VIEW)
    assert [s["ref"] for s in out] == ["app/auth/login.py"]


def test_a_model_declared_evidence_kind_is_refused(monkeypatch):
    """The cardinal A2 rule: the model may NOT self-declare confirmed evidence. Even with a real file
    path, kind='evidence' (or 'confirmed'/'fact') is dropped — that register is the engine's alone."""
    _no_connections(monkeypatch)
    raw = [{"kind": "evidence", "ref": "app/auth/login.py"},
           {"kind": "confirmed", "ref": "app/auth/login.py"},
           {"kind": "fact", "ref": "app/auth/login.py"}]
    assert chat._validate_sources(CHAT, raw, VIEW) == []


def test_linked_ref_must_be_a_real_connection(monkeypatch):
    _no_connections(monkeypatch, ids=["chat-friend"])
    raw = [{"kind": "linked", "ref": "chat-friend", "note": "prior lead"},
           {"kind": "linked", "ref": "chat-stranger", "note": "not connected"}]
    out = chat._validate_sources(CHAT, raw, VIEW)
    assert [s["ref"] for s in out] == ["chat-friend"], "an unlinked chat was accepted as a source"


def test_sources_dedup_and_cap(monkeypatch):
    _no_connections(monkeypatch)
    raw = [{"kind": "attached", "ref": "app/auth/login.py"}] * 5
    out = chat._validate_sources(CHAT, raw, VIEW)
    assert len(out) == 1
    assert len(chat._validate_sources(CHAT, [{"kind": "attached", "ref": "login.py"}] * 50, VIEW)) <= chat._MAX_SOURCES


def test_note_is_length_capped(monkeypatch):
    _no_connections(monkeypatch)
    out = chat._validate_sources(CHAT, [{"kind": "attached", "ref": "login.py", "note": "N" * 999}], VIEW)
    assert len(out[0]["note"]) <= chat._SOURCE_NOTE_MAX


def test_empty_view_grounds_nothing_as_attached(monkeypatch):
    _no_connections(monkeypatch)
    assert chat._validate_sources(CHAT, [{"kind": "attached", "ref": "login.py"}], {"text": ""}) == []
