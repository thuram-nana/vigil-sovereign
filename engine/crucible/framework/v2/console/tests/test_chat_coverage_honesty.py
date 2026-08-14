"""Coverage honesty — "go through the entire codebase" is TWO different things, and the reply must
not blur them (``console.chat._coverage_of`` / ``_answer_footer``).

  * The CHAT ANSWER reads a budget-limited selection, because a model's context is finite. The store
    already knows exactly how many files it opened and how many it did not.
  * The GATED REAL SCAN walks the whole tree. That is the honest route to full coverage.

An operator who believes the whole repository was read when 40 of 900 files were is being misled —
not by a false sentence but by the absence of a true one. So these tests assert that the counts are
STATED, that they are the store's real numbers rather than a comforting approximation, that they are
in the reply TEXT (the interface redraws the transcript from the saved records, so anything carried
only beside the reply is gone by the next redraw), and that the gated scan is offered as the way to
cover everything.

The model client is faked throughout — no API call is ever made.
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import attachments, chat
from framework.v2.console.tests.attach_fixtures import png_bytes, source_file, upload, zip_bytes

CHAT = "cov-chat"
ANSWER = "Lead: the password comparison is not constant time."


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(actions_mod, "launch_assessment",
                        lambda body: pytest.fail(f"a question turn must launch nothing: {body}"))
    attachments._UPLOADS.clear()
    yield tmp_path
    attachments._UPLOADS.clear()


@pytest.fixture()
def sent(monkeypatch: pytest.MonkeyPatch) -> dict:
    """A fake ``anthropic`` module that records what was sent and answers with ``ANSWER``."""
    captured: dict = {}
    mod = types.ModuleType("anthropic")

    class _Block:
        type = "text"

        def __init__(self, text):
            self.text = text

    class _Resp:
        stop_reason = "end_turn"

        def __init__(self, text):
            self.content = [_Block(text)]

    class _Client:
        def __init__(self, api_key=None, **kw):
            self.messages = self

        def create(self, **kw):
            captured.setdefault("calls", []).append(kw)
            return _Resp(ANSWER)

    mod.Anthropic = _Client
    monkeypatch.setitem(sys.modules, "anthropic", mod)
    return captured


def _prompt(sent: dict) -> str:
    return json.dumps(sent["calls"][0]["messages"], ensure_ascii=False)


# ---------------------------------------------------------------------------------------------------
# a partial read says it is partial
# ---------------------------------------------------------------------------------------------------

def test_a_partial_read_states_how_many_files_it_read_and_did_not(sent):
    """80 files go in; a handful come out. The reply must carry both numbers."""
    upload(CHAT, "big.zip", zip_bytes([(f"mod{i:03d}/handler.py", source_file(i)) for i in range(80)]))

    out = chat.chat_send({"chat_id": CHAT, "message": "any auth weaknesses?"})
    assert out["status"] == "answer", out

    cov = out.get("coverage") or {}
    assert cov, "an answer over a codebase carried no coverage at all"
    assert cov["total"] == 80 and cov["read"] < 80 and cov["omitted"] == 80 - cov["read"]

    reply = out["reply"]
    assert reply.startswith(ANSWER), "the model's own answer was altered"
    assert f"I read {cov['read']} of {cov['total']} file(s)" in reply, reply
    assert f"{cov['omitted']} were not read" in reply, reply


def test_the_count_is_what_the_model_ACTUALLY_GOT_not_what_the_store_assembled(sent):
    """The claim has to be checkable against the wire, and this is where it nearly was not.

    The store assembles its block to a budget counted over quoted BODY characters, so the finished
    string — labels, guard prefixes, header — is bigger than that budget. The chat bounds it again.
    While that second bound was a plain character slice it threw the last files off the END of the
    string, and the store's file list still counted them: the operator was told "38 files read" when
    32 file sections reached the model. So: ``read`` must equal the number of file sections in the
    payload that actually went out, and the payload must contain only WHOLE files."""
    upload(CHAT, "big.zip", zip_bytes([(f"mod{i:03d}/handler.py", source_file(i)) for i in range(80)]))
    out = chat.chat_send({"chat_id": CHAT, "message": "any auth weaknesses?"})
    cov = out["coverage"]

    prompt = _prompt(sent)
    assert cov["read"] == prompt.count("### file: "), \
        "the operator was told a file count the model never received"

    ctx = attachments.build_context(CHAT, chat._MAX_ATTACH_CTX_CHARS)
    assert cov["total"] == len(ctx["files"]) + ctx["omitted"], "the denominator lost files"
    assert cov["read"] <= len(ctx["files"])
    assert cov["read"] + cov["omitted"] == cov["total"]

    # whole files only: every quoted file still carries its END marker
    for i in range(80):
        if f"### file: big.zip/mod{i:03d}/handler.py" in prompt:
            assert f"MARK_END_{i:02d}" in prompt, f"mod{i:03d} was quoted but cut in half"


def test_the_coverage_survives_a_redraw_because_it_is_in_the_text(sent):
    """The interface redraws from the transcript. A caveat that lived only on the live response would
    be gone on the next redraw, and the partial read would then look like a complete one."""
    upload(CHAT, "big.zip", zip_bytes([(f"mod{i:03d}/handler.py", source_file(i)) for i in range(80)]))
    out = chat.chat_send({"chat_id": CHAT, "message": "any auth weaknesses?"})

    tail = chat.read_session(CHAT)[-1]
    assert tail["role"] == "assistant" and tail["kind"] == "answer"
    assert tail["text"] == out["reply"], "the saved turn is not what the operator was shown"
    assert "I read" in tail["text"] and "were not read" in tail["text"]
    assert tail["coverage"]["total"] == 80


def test_the_model_is_told_the_same_numbers_the_operator_is_told(sent):
    """It cannot avoid describing a partial read as a whole-codebase review if it does not know."""
    upload(CHAT, "big.zip", zip_bytes([(f"mod{i:03d}/handler.py", source_file(i)) for i in range(80)]))
    out = chat.chat_send({"chat_id": CHAT, "message": "any auth weaknesses?"})
    cov = out["coverage"]

    prompt = _prompt(sent)
    assert f"this is {cov['read']} of {cov['total']} file(s) in the upload" in prompt, prompt[:400]
    assert "were NOT read" in prompt
    assert "Do not describe this as a review of the whole codebase" in prompt


def test_the_gated_scan_is_offered_as_the_route_to_full_coverage(sent):
    upload(CHAT, "big.zip", zip_bytes([(f"mod{i:03d}/handler.py", source_file(i)) for i in range(80)]))
    out = chat.chat_send({"chat_id": CHAT, "message": "any auth weaknesses?"})

    assert out["scan_offer"]["mode"] == "codebase"
    assert Path(out["scan_offer"]["target"]).is_dir()
    assert "run the gated scan on these files" in out["reply"].lower()
    assert "walks the whole tree" in out["reply"]


# ---------------------------------------------------------------------------------------------------
# a complete read says THAT, and only when it is true
# ---------------------------------------------------------------------------------------------------

def test_a_complete_read_says_so(sent):
    upload(CHAT, "small.zip", zip_bytes([("a.py", b"x = 1\n"), ("b.py", b"y = 2\n")]))
    out = chat.chat_send({"chat_id": CHAT, "message": "anything wrong?"})

    cov = out["coverage"]
    assert cov == {"read": 2, "omitted": 0, "total": 2, "complete": True}
    assert "I read all 2 file(s)" in out["reply"], out["reply"]
    assert "were not read" not in out["reply"]


def test_a_binary_inside_the_upload_counts_as_not_read(sent):
    """"Not read" means not read — an indexed binary the model never saw is part of the gap, and
    counting it as covered would be the same lie in a smaller font."""
    upload(CHAT, "mixed.zip", zip_bytes([("a.py", b"x = 1\n"), ("logo.bin", b"\x00\x01\x02\x03" * 64)]))
    out = chat.chat_send({"chat_id": CHAT, "message": "anything wrong?"})

    cov = out["coverage"]
    assert cov["total"] == 2 and cov["read"] == 1 and cov["omitted"] == 1
    assert "I read 1 of 2 file(s)" in out["reply"]


# ---------------------------------------------------------------------------------------------------
# no codebase, no coverage claim
# ---------------------------------------------------------------------------------------------------

def test_an_attached_screenshot_alone_makes_no_coverage_claim(sent):
    """A coverage line about a single PNG that WAS sent as an image would be noise, and noise is how a
    statement that matters stops being read."""
    upload(CHAT, "shot.png", png_bytes())
    out = chat.chat_send({"chat_id": CHAT, "message": "what is in this screenshot?"})

    assert out["status"] == "answer"
    assert not out.get("coverage")
    assert "I read" not in out["reply"]


def test_a_turn_with_nothing_attached_is_unchanged():
    """The pre-attachment behaviour is byte-identical: no attachments, no connected chat — the turn is
    still the ask-for-a-target reply, with no coverage footer bolted onto it."""
    out = chat.chat_send({"chat_id": "empty-chat", "message": "please find bugs"})
    assert out["status"] == "need_target"
    assert "coverage" not in out and "I read" not in out["reply"]


# ---------------------------------------------------------------------------------------------------
# notes are not lost either
# ---------------------------------------------------------------------------------------------------

def test_a_note_about_material_that_could_not_be_sent_reaches_the_transcript(sent, monkeypatch):
    """The image note used to live only on the live response, which the interface drops on redraw. It
    belongs in the text with the rest of the honesty."""
    upload(CHAT, "app.zip", zip_bytes([("a.py", b"x = 1\n")]))
    monkeypatch.setattr(chat, "_image_blocks", lambda cid: ([], "2 attached image(s) were NOT sent."))

    out = chat.chat_send({"chat_id": CHAT, "message": "anything wrong?"})
    assert "2 attached image(s) were NOT sent." in out["reply"]
    assert "2 attached image(s) were NOT sent." in chat.read_session(CHAT)[-1]["text"]
