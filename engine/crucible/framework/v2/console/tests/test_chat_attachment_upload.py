"""Chat attachments — the CHUNKED RECEIVE protocol (``console.attachments.save_chunk`` /
``finish_upload``).

A file cannot arrive as one POST: the console's body cap is 1 MiB and — the trap that made this
protocol necessary — an oversize body silently degrades to an empty dict, so a too-large upload would
look to the handler like a request with no parameters rather than an error. The file therefore arrives
as an ordered base64 chunk sequence.

What this suite pins:
  * REASSEMBLY IS EXACT. The digest the operator is shown is the digest of the bytes they sent, and
    the material stored is byte-identical across chunk boundaries. A digest computed over what was
    *stored* rather than what *arrived* would be a self-certifying lie, so both are checked against a
    hash taken before the upload started.
  * THE TOTAL CAP BINDS MID-STREAM, and binds BEFORE the bytes land — a cap that only refuses after
    writing has already spent the disk it was protecting.
  * AN UNKNOWN UPLOAD IS REFUSED, including a replayed finish of an upload already sealed. The store
    is fail-closed here on purpose: an upload this process did not receive end to end cannot be
    vouched for, and indexing a possibly-truncated file is how a "clean" answer gets minted over half
    a codebase.
  * A CHUNK IS ORDERED AND BOUNDED. Out-of-order, duplicated, over-large and non-base64 chunks are
    refused rather than silently reinterpreted.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import attachments, chat, server
from framework.v2.console.tests.attach_fixtures import digest, upload, zip_bytes

CHAT = "upload-chat"


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    attachments._UPLOADS.clear()
    yield tmp_path
    attachments._UPLOADS.clear()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# ---------------------------------------------------------------------------------------------------
# reassembly
# ---------------------------------------------------------------------------------------------------

def test_chunks_reassemble_to_exactly_the_bytes_sent(tmp_path: Path):
    """A 1.2 MB incompressible payload across three chunks. The manifest's digest must equal a hash
    taken of the source bytes BEFORE the upload, and the stored file must be byte-identical — a
    boundary that dropped or duplicated a byte would move both."""
    raw = os.urandom(1_200_000)
    expected = digest(raw)

    uid = "u-exact"
    step = attachments._MAX_CHUNK_BYTES
    sent = 0
    for seq, off in enumerate(range(0, len(raw), step)):
        piece = raw[off:off + step]
        res = attachments.save_chunk(CHAT, uid, seq, _b64(piece))
        assert res["ok"], res
        sent += len(piece)
        assert res["received"] == seq + 1 and res["bytes"] == sent
    assert sent == len(raw)

    man = attachments.finish_upload(CHAT, uid, "blob.bin")
    assert man.get("ok"), man
    assert man["sha256"] == expected, "the digest is not of the bytes that were sent"
    assert man["upload_bytes"] == len(raw)

    stored = attachments._att_dir(CHAT, man["attachment_id"]) / "files"
    body = next(p for p in stored.rglob("*") if p.is_file()).read_bytes()
    assert body == raw, "the reassembled file is not byte-identical to the upload"
    assert digest(body) == expected


def test_a_multi_chunk_archive_extracts_to_the_same_content(tmp_path: Path):
    """The same property one layer up: an archive spanning several chunks must extract to the file
    contents the operator packed, not merely to a matching digest."""
    members = [(f"pkg/mod{i:03d}/handler.py", os.urandom(4096)) for i in range(300)]
    raw = zip_bytes(members)
    assert len(raw) > attachments._MAX_CHUNK_BYTES, "fixture must span more than one chunk"

    man = upload(CHAT, "big.zip", raw)
    assert man.get("ok"), man
    assert man["sha256"] == digest(raw)
    assert man["files"] == len(members)

    root = attachments._att_dir(CHAT, man["attachment_id"]) / "files"
    for name, data in members:
        assert (root / name).read_bytes() == data


# ---------------------------------------------------------------------------------------------------
# the total cap
# ---------------------------------------------------------------------------------------------------

def test_a_chunk_that_would_exceed_the_total_cap_is_refused_before_it_is_written(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The cap is enforced against the RUNNING total, so an upload cannot walk past it a chunk at a
    time. The refusal must also be clean: the ``.part`` sink keeps exactly the bytes already accepted,
    the sequence counter does not advance, and the sender can continue with a chunk that fits."""
    monkeypatch.setattr(attachments, "_MAX_UPLOAD_BYTES", 4096)
    uid = "u-cap"

    assert attachments.save_chunk(CHAT, uid, 0, _b64(b"a" * 3000))["ok"]
    part = attachments._part_path(CHAT, uid)
    assert part.stat().st_size == 3000

    over = attachments.save_chunk(CHAT, uid, 1, _b64(b"b" * 2000))
    assert over.get("ok") is not True, "the total cap did not bind"
    assert "limit" in str(over.get("refused", "")).lower()
    assert part.stat().st_size == 3000, "the refused chunk was written anyway"

    again = attachments.save_chunk(CHAT, uid, 1, _b64(b"c" * 1000))
    assert again["ok"] and again["bytes"] == 4000, "a refusal wedged the upload"

    man = attachments.finish_upload(CHAT, uid, "capped.bin")
    assert man.get("ok"), man
    assert man["sha256"] == digest(b"a" * 3000 + b"c" * 1000)


def test_an_over_large_single_chunk_is_refused(tmp_path: Path):
    res = attachments.save_chunk(CHAT, "u-big", 0, _b64(b"x" * (attachments._MAX_CHUNK_BYTES + 1)))
    assert res.get("ok") is not True and "chunk" in str(res.get("refused", "")).lower()
    assert not attachments._part_path(CHAT, "u-big").exists()


def test_a_chunk_at_the_cap_still_fits_the_console_body_limit(tmp_path: Path):
    """The protocol only works if a maximal chunk fits inside the 1 MiB console body cap — which must
    NOT be raised, because it bounds every other console action on a threading server. Serialise the
    real request envelope and measure it."""
    body = json.dumps({"chat_id": CHAT, "upload_id": "u-fit", "seq": 0,
                       "b64": "A" * attachments._MAX_CHUNK_B64})
    assert len(body.encode()) < server._MAX_CONSOLE_BODY
    assert attachments._MAX_CHUNK_B64 <= chat._MAX_CHUNK_B64, \
        "the store accepts a chunk larger than the chat layer will forward"


# ---------------------------------------------------------------------------------------------------
# unknown / replayed uploads
# ---------------------------------------------------------------------------------------------------

def test_an_unknown_upload_id_is_refused(tmp_path: Path):
    """A chunk for an upload this process never opened, and a finish for one it never received."""
    mid = attachments.save_chunk(CHAT, "u-ghost", 3, _b64(b"data"))
    assert mid.get("ok") is not True
    assert "no longer in progress" in str(mid.get("refused", "")).lower()
    assert not attachments._part_path(CHAT, "u-ghost").exists()

    fin = attachments.finish_upload(CHAT, "u-ghost", "ghost.zip")
    assert fin.get("ok") is not True and str(fin.get("refused", "")).strip()
    assert attachments.list_attachments(CHAT) == []


def test_a_replayed_finish_is_refused_and_does_not_duplicate_the_attachment(tmp_path: Path):
    uid = "u-once"
    assert attachments.save_chunk(CHAT, uid, 0, _b64(b"hello\n"))["ok"]
    first = attachments.finish_upload(CHAT, uid, "notes.txt")
    assert first.get("ok"), first

    replay = attachments.finish_upload(CHAT, uid, "notes.txt")
    assert replay.get("ok") is not True, "a sealed upload could be finished twice"
    assert len(attachments.list_attachments(CHAT)) == 1


def test_a_reused_upload_id_never_appends_onto_leftover_bytes(tmp_path: Path):
    """After a crash or a sweep a ``.part`` sink can survive. A fresh upload reusing that id must
    start from empty — otherwise the operator's file is silently prefixed with someone else's."""
    uid = "u-reuse"
    assert attachments.save_chunk(CHAT, uid, 0, _b64(b"STALE-LEFTOVER"))["ok"]
    attachments._UPLOADS.clear()                       # the crash: the sink survives, the table does not

    assert attachments.save_chunk(CHAT, uid, 0, _b64(b"fresh\n"))["ok"]
    man = attachments.finish_upload(CHAT, uid, "fresh.txt")
    assert man.get("ok"), man
    assert man["sha256"] == digest(b"fresh\n")


# ---------------------------------------------------------------------------------------------------
# ordering + encoding
# ---------------------------------------------------------------------------------------------------

def test_out_of_order_and_duplicated_chunks_are_refused(tmp_path: Path):
    uid = "u-order"
    assert attachments.save_chunk(CHAT, uid, 0, _b64(b"one"))["ok"]

    skipped = attachments.save_chunk(CHAT, uid, 2, _b64(b"three"))
    assert skipped.get("ok") is not True and "order" in str(skipped.get("refused", "")).lower()

    replayed = attachments.save_chunk(CHAT, uid, 0, _b64(b"one"))
    assert replayed.get("ok") is not True, "a replayed chunk was appended a second time"

    assert attachments._part_path(CHAT, uid).stat().st_size == 3


def test_a_non_base64_chunk_is_refused_not_reinterpreted(tmp_path: Path):
    for junk in ("not base64!!", "", "AAAA****"):
        res = attachments.save_chunk(CHAT, "u-junk", 0, junk)
        assert res.get("ok") is not True, f"{junk!r} was accepted"
    assert not attachments._part_path(CHAT, "u-junk").exists()


def test_an_empty_upload_is_refused(tmp_path: Path):
    uid = "u-empty"
    attachments.save_chunk(CHAT, uid, 0, _b64(b"x"))
    attachments._part_path(CHAT, uid).write_bytes(b"")
    res = attachments.finish_upload(CHAT, uid, "empty.bin")
    assert res.get("ok") is not True and str(res.get("refused", "")).strip()


def test_an_unsafe_chat_or_upload_id_raises_rather_than_writing(tmp_path: Path):
    """Fail-closed on the id: the server maps ValueError to a clean 404. A store that "sanitised" the
    id instead would let ``../`` name a directory outside the chat."""
    for bad in ("../escape", "a/b", ".hidden", ""):
        with pytest.raises(ValueError):
            attachments.save_chunk(bad, "u1", 0, _b64(b"x"))
        with pytest.raises(ValueError):
            attachments.save_chunk(CHAT, bad, 0, _b64(b"x"))
        with pytest.raises(ValueError):
            attachments.finish_upload(CHAT, bad, "x.bin")
    assert not (tmp_path / "live" / "chats").exists() or attachments.list_attachments(CHAT) == []


def test_the_per_chat_attachment_count_is_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(attachments, "_MAX_ATTACHMENTS", 3)
    for i in range(3):
        assert upload(CHAT, f"f{i}.txt", f"file {i}\n".encode()).get("ok")
    over = upload(CHAT, "f3.txt", b"file 3\n")
    assert over.get("ok") is not True and "attachments" in str(over.get("refused", "")).lower()
    assert len(attachments.list_attachments(CHAT)) == 3
