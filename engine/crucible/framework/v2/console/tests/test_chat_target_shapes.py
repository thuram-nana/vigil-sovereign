"""The three shapes an operator hands over — a URL, a FOLDER, an ARCHIVE — and the honesty of what
comes back (``console.chat._resolve_target`` / ``console.attachments.ingest_path``).

WHY THIS SUITE EXISTS. A zip is the most likely way anyone hands over a codebase, and it used to be
the one shape that did not work: ``_infer_mode`` called any existing path a "codebase", so the zip
itself was passed to an agent that requires an existing DIRECTORY. The run failed somewhere
downstream with nothing on screen connecting the failure to the fact that the target was still
packed. That is the worst kind of defect — not a wrong answer, but no answer and no reason.

So every test here asserts on what the OPERATOR ends up with:

  * a folder and a URL still resolve exactly as they did (no regression on the shapes that worked);
  * a zip / tar.gz resolves to an EXTRACTED DIRECTORY that exists and holds the code, and the scan is
    launched against that directory rather than the archive;
  * a refusal from the hardened extractor reaches the operator VERBATIM — "a file that would be
    written outside the upload folder" is the whole value of the refusal;
  * every path that cannot become a target says what was looked for and what was found instead, and
    launches nothing;
  * a local archive goes through the SAME funnel an uploaded one goes through (same refusals), and
    the operator's own file on disk is only ever READ.

The launcher is stubbed throughout: this suite proves what is HANDED to the gated launcher, never
that a scan runs.
"""

from __future__ import annotations

import io
import os
import stat
import tarfile
from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import attachments, chat
from framework.v2.console.tests.attach_fixtures import upload, zip_bytes

CHAT = "shape-chat"
CODE = b"def login(u, p):\n    # MARKER_SHAPE_BODY\n    return check(u, p)\n"


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    attachments._UPLOADS.clear()
    yield tmp_path
    attachments._UPLOADS.clear()


@pytest.fixture()
def launches(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    """Capture what would be handed to the gated launcher, and launch nothing."""
    calls: list[dict] = []

    def _fake(body):
        calls.append(body)
        return {"run_id": "r1", "slug": "s1", "stream": "none"}

    monkeypatch.setattr(chat.actions, "launch_assessment", _fake)
    return calls


def _zip_at(dirpath: Path, name: str, entries) -> Path:
    p = dirpath / name
    p.write_bytes(zip_bytes(entries))
    return p


def _targz_at(dirpath: Path, name: str, entries) -> Path:
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        for arc, data in entries:
            ti = tarfile.TarInfo(arc)
            ti.size = len(data)
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(data))
    p = dirpath / name
    p.write_bytes(bio.getvalue())
    return p


# ---------------------------------------------------------------------------------------------------
# the shapes that already worked must keep working
# ---------------------------------------------------------------------------------------------------

def test_a_url_still_resolves_to_a_url_run(launches, tmp_path):
    out = chat.chat_send({"chat_id": CHAT, "message": "scan http://127.0.0.1:8080/ please"})
    assert out["status"] == "running"
    assert launches[0]["mode"] == "url" and launches[0]["target"] == "http://127.0.0.1:8080/"


def test_a_directory_still_resolves_to_a_codebase_run(launches, tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "login.py").write_bytes(CODE)

    out = chat.chat_send({"chat_id": CHAT, "message": "check the auth", "target": str(repo)})
    assert out["status"] == "running", out
    assert launches[0]["mode"] == "codebase" and launches[0]["target"] == str(repo)


# ---------------------------------------------------------------------------------------------------
# the shape that did not work: an archive
# ---------------------------------------------------------------------------------------------------

def test_a_zip_path_is_extracted_and_the_run_targets_the_extracted_directory(launches, tmp_path):
    """The defect this suite is named for. The launcher must receive a DIRECTORY that exists and holds
    the operator's code — never the .zip, which the agent downstream cannot open."""
    src = _zip_at(tmp_path, "app.zip", [("src/auth/login.py", CODE), ("README.md", b"# app\n")])

    out = chat.chat_send({"chat_id": CHAT, "message": "look for auth bugs", "target": str(src)})
    assert out["status"] == "running", out

    handed = launches[0]["target"]
    assert handed != str(src), "the ARCHIVE itself was handed to the launcher — the run cannot work"
    root = Path(handed)
    assert root.is_dir(), f"the launcher was handed something that is not a directory: {handed}"
    assert (root / "src/auth/login.py").read_bytes() == CODE
    assert launches[0]["mode"] == "codebase"

    # the operator is TOLD it was unpacked, and the chat now holds it as an attachment
    assert "unpacked" in out["reply"].lower() and "app.zip" in out["reply"]
    assert [m["name"] for m in attachments.list_attachments(CHAT)] == ["app.zip"]
    ptrs = [r for r in chat.read_session(CHAT) if r.get("role") == "attachment"]
    assert len(ptrs) == 1 and ptrs[0]["counts"]["files"] == 2

    # and the operator's own archive is untouched on disk — the store only ever READ it
    assert src.exists() and src.read_bytes() == zip_bytes(
        [("src/auth/login.py", CODE), ("README.md", b"# app\n")])


@pytest.mark.parametrize("name", ["app.tar.gz", "app.tgz", "bundle"])
def test_a_tarball_path_is_extracted_too_whatever_it_is_called(launches, tmp_path, name):
    """The suffix is a hint for the error message; what decides is the magic bytes. A tarball called
    ``bundle`` works, and a run against it targets its extracted tree."""
    src = _targz_at(tmp_path, name, [("app/handler.py", CODE)])

    out = chat.chat_send({"chat_id": CHAT, "message": "any bugs?", "target": str(src)})
    assert out["status"] == "running", out
    root = Path(launches[0]["target"])
    assert root.is_dir() and (root / "app/handler.py").read_bytes() == CODE


def test_an_explicit_codebase_mode_over_a_zip_is_extracted_as_well(launches, tmp_path):
    src = _zip_at(tmp_path, "app.zip", [("src/login.py", CODE)])
    out = chat.chat_send({"chat_id": CHAT, "message": "audit this", "target": str(src),
                          "mode": "codebase"})
    assert out["status"] == "running", out
    assert Path(launches[0]["target"]).is_dir()


# ---------------------------------------------------------------------------------------------------
# a refusal is the whole value: it must arrive verbatim
# ---------------------------------------------------------------------------------------------------

def test_an_escaping_archive_is_refused_verbatim_and_launches_nothing(launches, tmp_path):
    """The reason IS the value. "this archive contains a file that would be written outside the upload
    folder" tells the operator something real about the archive they were given."""
    src = tmp_path / "evil.zip"
    src.write_bytes(zip_bytes([("../escape", b"OWNED\n")]))

    out = chat.chat_send({"chat_id": CHAT, "message": "scan it", "target": str(src)})
    assert out["status"] == "refused", out
    assert not launches, "a refused archive still reached the gated launcher"

    reply = out["reply"]
    assert "escape the upload folder" in reply, f"the extractor's reason did not reach the operator: {reply}"
    assert "'../escape'" in reply, "the refusal lost the member that caused it"
    # nothing was retained: no attachment, no transcript pointer
    assert attachments.list_attachments(CHAT) == []
    assert [r for r in chat.read_session(CHAT) if r.get("role") == "attachment"] == []
    # and the refusal is in the transcript, so a redraw still shows it
    assert chat.read_session(CHAT)[-1]["kind"] == "refused"


def test_a_bomb_is_refused_verbatim(launches, tmp_path):
    """A ratio bomb refusal names what it is. Same funnel as an upload, same words."""
    src = tmp_path / "bomb.zip"
    src.write_bytes(zip_bytes([("big.bin", b"A" * (12 * 1024 * 1024))]))

    out = chat.chat_send({"chat_id": CHAT, "message": "scan it", "target": str(src)})
    assert out["status"] == "refused", out
    assert "decompression bomb" in out["reply"], out["reply"]
    assert not launches


# ---------------------------------------------------------------------------------------------------
# every path that cannot become a target explains itself
# ---------------------------------------------------------------------------------------------------

def test_a_path_that_is_not_there_names_what_was_looked_for(launches, tmp_path):
    missing = tmp_path / "no-such-repo"
    out = chat.chat_send({"chat_id": CHAT, "message": "scan it", "target": str(missing)})
    assert out["status"] == "refused", out
    assert str(missing) in out["reply"], "the reply did not name the path it looked for"
    assert not launches


def test_a_plain_file_says_it_is_a_file_not_a_codebase(launches, tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("just some notes\n")
    out = chat.chat_send({"chat_id": CHAT, "message": "scan it", "target": str(f)})
    assert out["status"] == "refused", out
    assert str(f) in out["reply"] and "not a folder" in out["reply"]
    assert not launches
    assert attachments.list_attachments(CHAT) == [], "a plain file was silently attached"


def test_a_file_named_like_an_archive_but_not_one_says_so(launches, tmp_path):
    f = tmp_path / "app.zip"
    f.write_bytes(b"this is not a zip file at all\n")
    out = chat.chat_send({"chat_id": CHAT, "message": "scan it", "target": str(f)})
    assert out["status"] == "refused", out
    assert "named like an archive" in out["reply"], out["reply"]
    assert not launches


def test_a_mistyped_target_keeps_the_gated_scan_of_what_is_already_attached_on_offer(launches, tmp_path):
    """A typo must not take away what the chat holds. The refusal explains the typo AND still offers
    the scan of the codebase already extracted into this chat."""
    src = _zip_at(tmp_path, "app.zip", [("src/login.py", CODE)])
    first = chat.chat_send({"chat_id": CHAT, "message": "unpack this", "target": str(src)})
    assert first["status"] == "running", first

    out = chat.chat_send({"chat_id": CHAT, "message": "now this one",
                          "target": str(tmp_path / "typo-repo")})
    assert out["status"] == "refused"
    assert out["scan_offer"]["mode"] == "codebase"
    assert Path(out["scan_offer"]["target"]).is_dir()


def test_a_dangling_symlink_says_it_is_dangling(launches, tmp_path):
    link = tmp_path / "repo-link"
    os.symlink(tmp_path / "gone", link)
    out = chat.chat_send({"chat_id": CHAT, "message": "scan it", "target": str(link)})
    assert out["status"] == "refused", out
    assert "symlink" in out["reply"], out["reply"]
    assert not launches


# ---------------------------------------------------------------------------------------------------
# pasted into the message, not typed into the target box
# ---------------------------------------------------------------------------------------------------

def test_a_folder_pasted_into_the_message_is_picked_up(launches, tmp_path):
    repo = tmp_path / "myrepo"
    (repo).mkdir()
    (repo / "app.py").write_bytes(CODE)
    out = chat.chat_send({"chat_id": CHAT, "message": f"go through {repo} for auth bugs"})
    assert out["status"] == "running", out
    assert launches[0]["mode"] == "codebase" and launches[0]["target"] == str(repo)


def test_an_archive_pasted_into_the_message_is_picked_up_and_extracted(launches, tmp_path):
    src = _zip_at(tmp_path, "app.zip", [("src/login.py", CODE)])
    out = chat.chat_send({"chat_id": CHAT, "message": f"have a look at {src}"})
    assert out["status"] == "running", out
    assert Path(launches[0]["target"]).is_dir()


def test_a_message_that_merely_mentions_a_path_is_unchanged(launches, tmp_path):
    """Conservative on purpose: only an existing folder or a real archive is taken as a target, so a
    turn that just talks about a path is still a question, exactly as before."""
    out = chat.chat_send({"chat_id": CHAT, "message": "is /etc/passwd handling a problem here?"})
    assert out["status"] == "need_target", out
    assert not launches


def test_a_chosen_mode_is_never_overridden_by_a_path_in_the_message(launches, tmp_path):
    """The operator picked "url / API / infra". Mentioning a folder must not silently turn the turn
    into a codebase run behind their back."""
    repo = tmp_path / "repo"
    repo.mkdir()
    out = chat.chat_send({"chat_id": CHAT, "message": f"the app in {repo} serves it", "mode": "url"})
    assert out["status"] != "running" or launches[0]["mode"] == "url"
    assert not any(c["mode"] == "codebase" for c in launches)


# ---------------------------------------------------------------------------------------------------
# the store: one funnel, and the operator's file is only ever read
# ---------------------------------------------------------------------------------------------------

def test_ingest_path_refuses_exactly_what_an_upload_of_the_same_bytes_refuses(tmp_path):
    """The point of routing a local archive through ``begin`` → ``chunk`` → ``finish``: an archive read
    off disk gets the same verdict, in the same words, as one that arrived over HTTP."""
    hostile = zip_bytes([("../escape", b"OWNED\n")])
    src = tmp_path / "evil.zip"
    src.write_bytes(hostile)

    uploaded = upload("upload-chat", "evil.zip", hostile)
    ingested = attachments.ingest_path("ingest-chat", str(src))

    assert uploaded.get("ok") is not True and ingested.get("ok") is not True
    assert ingested["refused"] == uploaded["refused"], \
        "the local-path route gave a different verdict from the upload route"
    assert attachments.list_attachments("ingest-chat") == []


def test_ingest_path_produces_the_same_manifest_an_upload_produces(tmp_path):
    raw = zip_bytes([("src/auth/login.py", CODE), ("README.md", b"# app\n")])
    src = tmp_path / "app.zip"
    src.write_bytes(raw)

    uploaded = upload("upload-chat", "app.zip", raw)
    ingested = attachments.ingest_path("ingest-chat", str(src))

    assert ingested.get("ok") is True, ingested
    for field in ("kind", "files", "bytes", "upload_bytes", "sha256", "name"):
        assert ingested[field] == uploaded[field], f"{field} differs between the two routes"


def test_ingest_path_never_touches_the_operators_own_file(tmp_path):
    raw = zip_bytes([("a.py", b"x = 1\n")])
    src = tmp_path / "keep-me.zip"
    src.write_bytes(raw)
    before = src.stat()

    man = attachments.ingest_path(CHAT, str(src))
    assert man.get("ok") is True, man
    assert src.exists(), "the store deleted the operator's own archive"
    assert src.read_bytes() == raw
    assert src.stat().st_mode == before.st_mode


def test_ingest_path_refuses_a_folder_a_pipe_and_an_unreadable_path(tmp_path):
    d = tmp_path / "adir"
    d.mkdir()
    assert "folder" in attachments.ingest_path(CHAT, str(d))["refused"]

    fifo = tmp_path / "afifo"
    os.mkfifo(fifo)
    out = attachments.ingest_path(CHAT, str(fifo))
    assert out.get("ok") is not True and "regular file" in out["refused"]

    assert attachments.ingest_path(CHAT, str(tmp_path / "nope"))["refused"]
    assert attachments.ingest_path(CHAT, "")["refused"]
    assert attachments.list_attachments(CHAT) == [], "a refused ingest left something behind"


def test_ingest_path_refuses_a_file_over_the_upload_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(attachments, "_MAX_UPLOAD_BYTES", 1024)
    big = tmp_path / "big.bin"
    big.write_bytes(b"A" * 4096)
    out = attachments.ingest_path(CHAT, str(big))
    assert out.get("ok") is not True and "limit" in out["refused"]


def test_path_kind_reads_the_bytes_not_the_name(tmp_path):
    z = tmp_path / "misnamed.txt"
    z.write_bytes(zip_bytes([("a.py", b"x = 1\n")]))
    assert attachments.path_kind(str(z)) == "archive"

    t = tmp_path / "app.zip"
    t.write_bytes(b"plain text pretending\n")
    assert attachments.path_kind(str(t)) == "file"

    d = tmp_path / "d"
    d.mkdir()
    assert attachments.path_kind(str(d)) == ""
    assert attachments.path_kind(str(tmp_path / "missing")) == ""


def test_extracted_files_are_never_executable(tmp_path, launches):
    """Whatever the archive claims, the mode comes from the store. Re-asserted on the local-path route
    because that is the route this slice added."""
    src = tmp_path / "app.zip"
    src.write_bytes(zip_bytes([("run.sh", b"#!/bin/sh\necho hi\n",
                                (stat.S_IFREG | 0o777) << 16)]))
    man = attachments.ingest_path(CHAT, str(src))
    assert man.get("ok") is True, man
    root = Path(attachments.scan_root(CHAT, man["attachment_id"]))
    mode = stat.S_IMODE((root / "run.sh").stat().st_mode)
    assert not (mode & 0o111), f"an extracted file kept an executable bit: {oct(mode)}"


# ---------------------------------------------------------------------------------------------------
# the attach-a-local-path route
# ---------------------------------------------------------------------------------------------------

def test_attach_path_attaches_without_asking_a_question(tmp_path):
    src = tmp_path / "app.zip"
    src.write_bytes(zip_bytes([("src/login.py", CODE)]))

    out = chat.attach_path({"chat_id": CHAT, "path": str(src)})
    assert out.get("ok") is True, out
    assert out["kind"] == "archive"
    assert out["scan_offer"]["mode"] == "codebase"
    assert Path(out["scan_offer"]["target"]).is_dir()
    assert [r["name"] for r in chat.read_session(CHAT) if r.get("role") == "attachment"] == ["app.zip"]


def test_the_attachment_turn_says_what_was_attached(tmp_path):
    """The interface redraws from these records, so an attachment pointer with no ``text`` drew as an
    empty bubble — the one turn that says "these files are part of this conversation now" saying
    nothing at all."""
    src = tmp_path / "app.zip"
    src.write_bytes(zip_bytes([("src/login.py", CODE), ("README.md", b"# app\n")]))

    out = chat.attach_path({"chat_id": CHAT, "path": str(src)})
    assert out.get("ok") is True, out
    rec = [r for r in chat.read_session(CHAT) if r.get("role") == "attachment"][-1]
    assert rec["text"].startswith("Attached app.zip")
    assert "2 files" in rec["text"] and "archive" in rec["text"]
    assert len(rec["text"]) < 200 and "MARKER_SHAPE_BODY" not in rec["text"]


def test_attach_path_records_nothing_when_the_store_refuses(tmp_path):
    src = tmp_path / "evil.zip"
    src.write_bytes(zip_bytes([("../escape", b"OWNED\n")]))

    out = chat.attach_path({"chat_id": CHAT, "path": str(src)})
    assert out.get("ok") is not True, out
    assert "escape the upload folder" in str(out.get("error") or "")
    assert [r for r in chat.read_session(CHAT) if r.get("role") == "attachment"] == []


def test_attach_path_needs_a_path_and_a_safe_chat_id(tmp_path):
    assert chat.attach_path({"chat_id": CHAT, "path": ""})["error"]
    with pytest.raises(ValueError):
        chat.attach_path({"chat_id": "../etc", "path": str(tmp_path)})
