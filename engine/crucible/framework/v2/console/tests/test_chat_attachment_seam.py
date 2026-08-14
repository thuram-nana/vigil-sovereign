"""Chat attachments — the OPERATOR-FACING path (``console.chat`` → ``console.attachments``).

Everything the other attachment suites prove is about the store. This one is about the seam the
operator actually touches: the three POST routes the browser calls (``/api/chat/attach/begin`` →
``chunk`` × N → ``finish``), the small transcript pointer the upload leaves behind, and — the point of
the whole feature — whether the uploaded material reaches the model at all when the operator asks a
question about it.

A seam is exactly where a feature dies quietly. Both halves can be individually correct while the
call between them is wrong: a name that does not resolve, an argument that is not passed, a refusal
shape that is not recognised. Nothing about that shows up in a test of either half alone, and nothing
about it shows up at runtime either — the console keeps working, the upload appears to succeed, the
model simply answers about a codebase it was never shown. So these tests drive the public functions
end to end and assert on OBSERVABLE OUTCOMES: an upload id comes back, the manifest describes what
landed, the block that goes to the model contains the operator's code, the offer of a gated real scan
names a directory that exists.

The final test is the whole feature in one call: an operator attaches a zip, asks a question, and gets
an answer that is explicitly a LEAD with a gated scan on offer — with the model client mocked, so no
API call and no launch ever happens.
"""

from __future__ import annotations

import base64
import json
import sys
import types
from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import attachments, chat
from framework.v2.console.tests.attach_fixtures import digest, png_bytes, upload, zip_bytes

CHAT = "seam-chat"
CODE = b"def login(u, p):\n    # MARKER_SEAM_BODY\n    return check(u, p)\n"


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    attachments._UPLOADS.clear()
    yield tmp_path
    attachments._UPLOADS.clear()


def _post_upload(chat_id: str, filename: str, raw: bytes) -> dict:
    """The browser's sequence, through the exact functions the POST routes dispatch to."""
    begin = chat.attach_begin({"chat_id": chat_id, "filename": filename})
    assert not begin.get("error"), f"attach_begin refused the upload: {begin}"
    upload_id = str(begin.get("upload_id") or "")
    assert upload_id, f"attach_begin returned no upload id to send chunks to: {begin}"

    step = min(chat._CHUNK_BYTES_HINT, attachments._MAX_CHUNK_BYTES)
    for seq, off in enumerate(range(0, len(raw), step)):
        res = chat.attach_chunk({"chat_id": chat_id, "upload_id": upload_id, "seq": seq,
                                 "b64": base64.b64encode(raw[off:off + step]).decode("ascii")})
        assert not res.get("error"), f"attach_chunk refused chunk {seq}: {res}"
    return chat.attach_finish({"chat_id": chat_id, "upload_id": upload_id})


# ---------------------------------------------------------------------------------------------------
# the three routes
# ---------------------------------------------------------------------------------------------------

def test_the_upload_routes_are_wired_to_the_store():
    """begin → chunk → finish. Each returns something the next step can use, and the manifest at the
    end describes what actually landed on disk."""
    raw = zip_bytes([("src/auth/login.py", CODE), ("README.md", b"# app\n")])
    man = _post_upload(CHAT, "app.zip", raw)

    assert not man.get("error"), man
    assert man.get("ok") is True, man
    assert man.get("kind") == "archive" and man.get("files") == 2
    assert man.get("sha256") == digest(raw)

    stored = attachments.list_attachments(CHAT)
    assert len(stored) == 1
    root = attachments._att_dir(CHAT, stored[0]["attachment_id"]) / "files"
    assert (root / "src/auth/login.py").read_bytes() == CODE


def test_the_transcript_holds_a_pointer_never_the_bytes():
    """``read_session`` slurps a whole transcript and ``list_sessions`` re-parses every transcript per
    sidebar render, and ``_append`` leans on O_APPEND atomicity, which only holds for short lines. So
    the record must carry the manifest — name, digest, size, counts — and nothing else."""
    raw = zip_bytes([("src/auth/login.py", CODE)])
    man = _post_upload(CHAT, "app.zip", raw)
    assert man.get("ok"), man

    records = chat.read_session(CHAT)
    attach_records = [r for r in records if r.get("role") == "attachment"]
    assert len(attach_records) == 1, f"expected exactly one attachment pointer, got {records}"
    rec = attach_records[0]

    assert rec["name"] == "app.zip"
    assert rec["digest"] == digest(raw), "the transcript pointer lost the upload's digest"
    assert rec["size"] > 0 and rec["counts"]["files"] == 1
    assert rec["attachment_id"] == man["attachment_id"]

    line = json.dumps(rec)
    assert len(line) < 4096, "the transcript record is too large to be appended atomically"
    assert "MARKER_SEAM_BODY" not in line and base64.b64encode(raw).decode() not in line


def test_a_refused_upload_records_nothing_in_the_transcript():
    """A store refusal must reach the operator AS a refusal. Recording a phantom attachment for an
    archive that was thrown away tells them their codebase is attached when it is not — and every
    later answer is then made over material that does not exist."""
    hostile = zip_bytes([("../escape", b"OWNED\n")])
    out = _post_upload(CHAT, "evil.zip", hostile)

    assert out.get("ok") is not True, f"a refused archive was reported as a success: {out}"
    assert str(out.get("refused") or out.get("error") or "").strip(), \
        "the refusal reached the operator without a reason"
    assert [r for r in chat.read_session(CHAT) if r.get("role") == "attachment"] == []
    assert attachments.list_attachments(CHAT) == []


def test_the_attachments_list_route_returns_the_manifests():
    _post_upload(CHAT, "app.zip", zip_bytes([("src/auth/login.py", CODE)]))
    out = chat.attachments_list(CHAT)
    assert out["chat_id"] == CHAT
    assert [m.get("name") for m in out["attachments"]] == ["app.zip"]


# ---------------------------------------------------------------------------------------------------
# does the material actually reach the model?
# ---------------------------------------------------------------------------------------------------

def test_the_model_facing_block_carries_the_uploaded_code():
    """The one that matters. Everything upstream can be perfect and the answer still be about nothing:
    if this block comes back empty the model is asked the operator's question with no codebase
    attached, and it will answer anyway."""
    upload(CHAT, "app.zip", zip_bytes([("src/auth/login.py", CODE)]))

    block, truncated = chat._attachment_block(CHAT)
    assert block.strip(), "the attachment block is EMPTY — the model would never see the upload"
    assert block.startswith(attachments._HEADER), "the block is not fenced as untrusted material"
    assert "MARKER_SEAM_BODY" in block
    assert "### file: app.zip/src/auth/login.py" in block
    assert truncated is False


def test_an_oversized_upload_is_flagged_truncated_rather_than_quietly_clipped():
    """The block is bounded again at the chat layer. When it binds, the caller must be TOLD — a
    partial view the operator is not told about is exactly how a false "looks clean" gets minted."""
    big = zip_bytes([(f"mod{i:03d}/handler.py", b"def f():\n    return 1\n" * 400) for i in range(80)])
    upload(CHAT, "big.zip", big)

    block, truncated = chat._attachment_block(CHAT)
    assert block.strip(), "the attachment block is EMPTY"
    assert len(block) <= chat._MAX_ATTACH_CTX_CHARS
    if truncated:
        # The chat-layer bound cuts on a FILE boundary, not on a character. It used to be `text[:cap]`,
        # which sliced the last files off the END of the string while the store's file list — and
        # therefore the count the operator was given — still counted them. So what must hold when the
        # bound binds is that the block stays inside the cap, holds only whole file sections, and that
        # the view's own `read` is exactly how many of them survived.
        view = chat._attachment_view(CHAT)
        assert view["read"] == block.count("### file: "), \
            "the coverage count does not match the files that actually went to the model"
        assert view["read"] + view["omitted"] == 80, "the coverage denominator lost files"

    # 80 files went in and only a few came out. Whichever bound did the cutting, the model must be
    # told the coverage is partial — an answer over 4 of 80 files is a different claim from one over
    # all 80, and the difference is invisible unless it is stated.
    assert block.count("### file: ") < 80
    assert truncated or "## NOT READ:" in block, \
        "most of the upload was not read and nothing in the block says so"


def test_an_attached_image_reaches_the_model_as_an_image_block():
    """The operator drops a screenshot in and asks about it. Either it is sent, or the reply says it
    was not — this asserts the first, because the store already carries the image and its sniffed
    media type."""
    raw = png_bytes()
    upload(CHAT, "screenshot.png", raw)

    blocks, note = chat._image_blocks(CHAT)
    assert blocks, f"the attached image never reached the model (note: {note!r})"
    assert len(blocks) == 1
    block = blocks[0]
    assert block["type"] == "image"
    assert block["source"]["type"] == "base64"
    assert block["source"]["media_type"] == "image/png"
    assert base64.b64decode(block["source"]["data"]) == raw


def test_an_extracted_codebase_is_offered_for_a_gated_real_scan():
    """The honest upgrade from a lead to a fact. The offer must name a directory that EXISTS, because
    it is handed straight to ``launch_assessment`` in codebase mode."""
    upload(CHAT, "app.zip", zip_bytes([("src/auth/login.py", CODE)]))

    offer = chat._scan_offer(CHAT)
    assert offer, "a chat holding an extracted codebase offered no gated scan"
    assert offer["mode"] == "codebase"
    target = Path(offer["target"])
    assert target.is_dir(), f"the offered scan target does not exist: {target}"
    assert (target / "src/auth/login.py").read_bytes() == CODE
    assert offer["name"] == "app.zip"
    assert "lead" in offer["note"].lower()


# ---------------------------------------------------------------------------------------------------
# the whole feature, in one turn
# ---------------------------------------------------------------------------------------------------

class _FakeBlock:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _FakeResp:
    def __init__(self, text, stop_reason="end_turn"):
        self.content = [_FakeBlock(text)]
        self.stop_reason = stop_reason


def _install_fake_anthropic(monkeypatch, reply_text, captured):
    """A fake ``anthropic`` module — same shape the terminal suites use, so no API call is ever made."""
    mod = types.ModuleType("anthropic")

    class _Client:
        def __init__(self, api_key=None, **kw):
            captured["api_key"] = api_key
            self.messages = self

        def create(self, **kw):
            captured.setdefault("calls", []).append(kw)
            return _FakeResp(reply_text)

    mod.Anthropic = _Client
    monkeypatch.setitem(sys.modules, "anthropic", mod)


def test_asking_a_question_about_an_upload_answers_from_it_and_stays_a_lead(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setattr(actions_mod, "launch_assessment",
                        lambda body: pytest.fail(f"a question turn must launch nothing: {body}"))
    captured: dict = {}
    _install_fake_anthropic(monkeypatch, "Lead: the password comparison is not constant time.", captured)

    upload(CHAT, "app.zip", zip_bytes([("src/auth/login.py", CODE)]))
    out = chat.chat_send({"chat_id": CHAT, "message": "does this codebase have weaknesses in its auth?"})

    assert out["status"] == "answer", f"the question was not answered from the upload: {out}"
    assert out["grounding"] == "lead", "an answer about uploaded material must be a LEAD, never a fact"
    assert out["reply"].startswith("Lead:")

    call = captured["calls"][0]
    assert call["system"] is chat._CHAT_SYSTEM, "the system prompt was not held separately"
    # ensure_ascii=False: the fence header and the guard prefix are non-ASCII ("—", "│"), and the default
    # escaping would re-encode them to \uXXXX — so a payload that IS correctly fenced would fail the
    # check below for no reason but this line's own serialisation. Compare against the real characters.
    sent = json.dumps(call["messages"], ensure_ascii=False)
    assert "does this codebase have weaknesses in its auth?" in sent
    assert "MARKER_SEAM_BODY" in sent, "the model was asked about a codebase it was never shown"
    assert attachments._HEADER in sent, "the uploaded material was not fenced as untrusted"

    assert out.get("scan_offer", {}).get("mode") == "codebase", \
        "the reply did not offer the gated scan that could turn this lead into a fact"

    tail = chat.read_session(CHAT)[-1]
    assert tail["role"] == "assistant" and tail["grounding"] == "lead"


def test_without_a_key_the_answer_is_honest_and_the_gated_scan_is_still_offered(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(actions_mod, "launch_assessment",
                        lambda body: pytest.fail(f"a question turn must launch nothing: {body}"))

    upload(CHAT, "app.zip", zip_bytes([("src/auth/login.py", CODE)]))
    out = chat.chat_send({"chat_id": CHAT, "message": "any auth weaknesses?"})

    assert out["status"] == "need_key"
    assert "key" in out["reply"].lower()
    assert out.get("scan_offer", {}).get("mode") == "codebase", \
        "the deterministic path must stay on offer when the model is unavailable"
