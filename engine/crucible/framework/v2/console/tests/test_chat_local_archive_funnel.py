"""The local-path archive route is the SAME funnel as an upload — proven by firing the upload
route's own hostile corpus at it, and by requiring the refusal to arrive in the extractor's own
characters (``console.chat._resolve_target`` → ``console.attachments.ingest_path``).

WHY A SECOND SUITE. ``test_chat_target_shapes.py`` proves the shapes resolve and that a couple of
refusals survive the trip. This one is about the claim underneath that: a path the operator NAMES
must go through the SAME acceptance rules as a file they UPLOAD, with no looser second route. That
claim cannot be established by reading either half — a second route looks like working code right up
until the day an archive the upload path refuses is unpacked by the other one. The only way to
establish it is to take the corpus the upload route is measured against and fire it at this one.

Three things are pinned here that nothing else pins:

  * EVERY archive suffix the code PROMISES really resolves. The suffix list is what decides the
    plain-English refusal ("named like an archive, but…"), and ``_ARCHIVE_HELP`` is what the operator
    is told to hand over next. A promise that has drifted from what the extractor accepts sends the
    operator away to make an archive that will be refused when they come back.
  * The WHOLE hostile corpus, through the local path: escape, backslash escape, absolute member,
    over-deep path, symlink, hard link, device node, symlinked parent, ratio bomb, understated
    header, duplicate paths, member flood. Each refused, nothing retained, nothing launched, and the
    canary outside the store untouched.
  * The refusal reaches the operator CHARACTER FOR CHARACTER. The expected string is never written
    down here — it is taken from the upload funnel's own answer to the same bytes, so the test cannot
    drift into blessing a reworded reason. "the archive contains a path that would escape the upload
    folder ('../escape')" is a fact about the archive the operator was sent; "that file was refused"
    is indistinguishable from a bug in this console.

Nothing launches: ``launch_assessment`` is a recorder.
"""

from __future__ import annotations

import io
import os
import re
import stat
import tarfile
from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import attachments, chat
from framework.v2.console.tests.attach_fixtures import (
    CHARDEV_ATTR, SYMLINK_ATTR, png_bytes, tar_bytes, tree, upload, zip_bytes,
    zip_understating_declared_size,
)

CHAT = "funnel-chat"
CODE = b"def login(u, p):\n    # MARKER_FUNNEL_BODY\n    return check(u, p)\n"
CANARY = b"CANARY-INTACT"


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
    """What WOULD be handed to the gated launcher. A refusal test asserts this stayed empty, which is
    a stronger claim than "the reply said no": a run that started anyway would leave a real process
    behind whatever the operator was told."""
    calls: list[dict] = []
    monkeypatch.setattr(actions_mod, "launch_assessment",
                        lambda body: (calls.append(dict(body))
                                      or {"run_id": "r1", "slug": "s1", "stream": "none"}))
    return calls


@pytest.fixture()
def outside(tmp_path: Path) -> Path:
    """A directory OUTSIDE the attachment store holding a canary, so "did anything escape" is a
    question about real bytes on a real disk rather than about a refusal message."""
    d = tmp_path / "outside"
    d.mkdir()
    (d / "canary.txt").write_bytes(CANARY)
    return d


def _send(message: str, **body) -> dict:
    return chat.chat_send({"chat_id": CHAT, "message": message, **body})


# ---------------------------------------------------------------------------------------------------
# archive builders, keyed by the suffix an operator would actually use
# ---------------------------------------------------------------------------------------------------

_TAR_MODES = {".tar": "w", ".tar.gz": "w:gz", ".tgz": "w:gz",
              ".tar.bz2": "w:bz2", ".tbz": "w:bz2", ".tbz2": "w:bz2",
              ".tar.xz": "w:xz", ".txz": "w:xz"}


def _archive_bytes(suffix: str, entries) -> bytes:
    if suffix == ".zip":
        return zip_bytes(entries)
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode=_TAR_MODES[suffix]) as tf:
        for arc, data in entries:
            ti = tarfile.TarInfo(arc)
            ti.size = len(data)
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(data))
    return bio.getvalue()


def _promised_suffixes() -> list[str]:
    """The suffixes the operator is TOLD to hand over, parsed out of the help sentence itself rather
    than copied — a copy would keep passing after the sentence changed."""
    return sorted(set(re.findall(r"\.[a-z0-9]+(?:\.[a-z0-9]+)?", chat._ARCHIVE_HELP)))


# ===================================================================================================
# 1. every archive shape the code PROMISES really resolves
# ===================================================================================================

def test_the_help_text_promises_nothing_the_suffix_list_does_not_know():
    """A refusal ends by telling the operator what to hand over instead. If that sentence names a
    shape the code does not recognise, the advice sends them to build an archive that will be refused
    when they bring it back."""
    unknown = [s for s in _promised_suffixes() if s not in chat._ARCHIVE_SUFFIXES]
    assert not unknown, f"the refusal text promises {unknown}, which the suffix list does not accept"


@pytest.mark.parametrize("suffix", sorted(set(chat._ARCHIVE_SUFFIXES)))
def test_every_named_archive_shape_extracts_and_scans_the_extracted_directory(
        suffix: str, tmp_path: Path, launches: list[dict]):
    """Each shape end to end, because "we support tarballs" is a claim about eight distinct code
    paths through two extractors and three compressors. The suffix only ever picks the WORDS of a
    refusal — the magic bytes decide — so a shape that works for gzip and dies for xz is invisible
    until an operator hands over an xz."""
    src = tmp_path / f"app{suffix}"
    src.write_bytes(_archive_bytes(suffix, [("src/app.py", CODE), ("README.md", b"# app\n")]))

    out = _send("review this", target=str(src))

    assert out["status"] == "running", f"a {suffix} target did not resolve: {out}"
    assert len(launches) == 1
    handed = Path(launches[0]["target"])
    assert handed != src, f"the {suffix} ARCHIVE itself was handed to the launcher"
    assert handed.is_dir(), f"the launcher was handed something that is not a directory: {handed}"
    assert (handed / "src/app.py").read_bytes() == CODE
    assert "Unpacked" in out["reply"] and f"app{suffix}" in out["reply"]


def test_an_archive_with_no_suffix_at_all_still_resolves(tmp_path: Path, launches: list[dict]):
    """``curl -o bundle`` leaves no suffix. The magic bytes are what decide, so this must work."""
    src = tmp_path / "bundle"
    src.write_bytes(_archive_bytes(".tar.xz", [("src/app.py", CODE)]))

    out = _send("review this", target=str(src))
    assert out["status"] == "running", out
    assert (Path(launches[0]["target"]) / "src/app.py").read_bytes() == CODE


# ===================================================================================================
# 2. the whole hostile corpus, through the LOCAL-PATH route
# ===================================================================================================

def _hostile(outside: Path) -> dict:
    """The corpus the UPLOAD route is measured against, built the same way — by hand, with the mode
    words a real attacker sets, never through a convenience API that would sanitise them."""
    deep = "/".join(f"d{i}" for i in range(attachments._MAX_DEPTH + 8)) + "/f.txt"
    return {
        "dotdot escape": ("trav.zip", zip_bytes([("ok.txt", b"ok\n"), ("../escape", b"OWNED\n")])),
        "backslash escape": ("back.zip", zip_bytes([("..\\..\\outside\\escape", b"OWNED\n")])),
        "absolute member": ("abs.zip", zip_bytes([("/etc/evil", b"OWNED\n")])),
        "over-deep path": ("deep.zip", zip_bytes([(deep, b"x\n")])),
        "zip symlink": ("link.zip", zip_bytes([("passwd", b"/etc/passwd", SYMLINK_ATTR)])),
        "device node": ("dev.zip", zip_bytes([("node", b"", CHARDEV_ATTR)])),
        "tar symlink": ("link.tar", tar_bytes([
            {"name": "notes.txt", "data": b"hello\n"},
            {"name": "passwd", "type": tarfile.SYMTYPE, "link": "/etc/passwd"}])),
        "tar hardlink": ("hard.tar", tar_bytes([
            {"name": "real.txt", "data": b"hello\n"},
            {"name": "hard", "type": tarfile.LNKTYPE, "link": "real.txt"}])),
        "symlinked parent": ("slip.zip", zip_bytes([
            ("d", str(outside).encode()), ("d/canary.txt", b"OWNED\n")])),
        "ratio bomb": ("bomb.zip", zip_bytes([("bomb.bin", b"\0" * (30 * 1024 * 1024))])),
        "understated header": ("lie.zip", zip_understating_declared_size(
            "lie.txt", b"A" * (5 * 1024 * 1024), declared=16)),
        "duplicate paths": ("dup.zip", zip_bytes(
            [("dup.txt", b"first"), ("dup.txt", b"second")], allow_duplicate_names=True)),
        "member flood": ("flood.zip", zip_bytes(
            [(f"f{i:05d}.txt", b"x") for i in range(attachments._MAX_MEMBERS + 1)])),
    }


@pytest.mark.parametrize("label", sorted(_hostile(Path("/nonexistent"))))
def test_every_extractor_guard_still_holds_for_an_archive_the_operator_NAMES(
        label: str, tmp_path: Path, outside: Path, launches: list[dict]):
    name, raw = _hostile(outside)[label]
    src = tmp_path / name
    src.write_bytes(raw)

    out = _send("scan this", target=str(src))

    assert out["status"] == "refused", f"{label} was ACCEPTED through the local-path route: {out}"
    assert str(out.get("reply") or "").strip(), f"{label} was refused with no reason to read"
    assert out.get("error") == out["reply"], f"{label}: the reason did not reach the error field"
    assert launches == [], f"{label} still reached the gated launcher"

    # nothing retained, on disk or in the model's view
    assert attachments.list_attachments(CHAT) == [], f"{label} was still indexed as an attachment"
    assert attachments.build_context(CHAT, 50_000)["files"] == [], \
        f"{label} still contributed material to the model context"
    assert [r for r in chat.read_session(CHAT) if r.get("role") == "attachment"] == [], \
        f"{label} left a phantom attachment pointer in the transcript"

    # nothing escaped: the canary is untouched and no member landed outside the store
    assert (outside / "canary.txt").read_bytes() == CANARY, f"{label} overwrote the canary"
    assert not (outside / "escape").exists() and not (tmp_path / "escape").exists()

    # ...and nothing of the archive is on disk either. Both quiet failure modes at once: a member
    # written before the archive was judged (an attachment directory), and an abandoned staging sink
    # still holding the operator's bytes (a leftover .part). A refused archive may leave neither.
    kept = {p.name for p in attachments._att_root(CHAT).iterdir() if p.name != ".incoming"}
    assert not kept, f"{label} left an extracted attachment behind: {sorted(kept)}"
    assert list(attachments._incoming_dir(CHAT).iterdir()) == [], \
        f"{label} left an abandoned .part sink holding the operator's bytes"


def test_the_refusal_is_still_in_the_transcript_after_a_redraw(tmp_path: Path, outside: Path,
                                                               launches: list[dict]):
    """The interface redraws from the saved records. A refusal that lived only on the live response
    would leave the operator looking at a chat where their archive simply never happened."""
    src = tmp_path / "trav.zip"
    src.write_bytes(zip_bytes([("../escape", b"OWNED\n")]))

    out = _send("scan this", target=str(src))
    tail = chat.read_session(CHAT)[-1]

    assert tail["role"] == "assistant" and tail["kind"] == "refused"
    assert tail["text"] == out["reply"], "the saved refusal is not what the operator was shown"


# ===================================================================================================
# 3. the refusal arrives character for character
# ===================================================================================================

@pytest.mark.parametrize("label", ["dotdot escape", "zip symlink", "duplicate paths", "ratio bomb"])
def test_the_extractor_refusal_reaches_the_operator_CHARACTER_FOR_CHARACTER(
        label: str, tmp_path: Path, outside: Path, launches: list[dict]):
    """The expected string is not written down in this test. It is whatever the UPLOAD funnel says
    about the same bytes — so the two routes cannot diverge in wording without failing here, and a
    reason that got summarised on the way out is caught even though it still "mentions the problem"."""
    name, raw = _hostile(outside)[label]

    control = upload("verbatim-control", name, raw)
    assert control.get("ok") is False, f"the control upload was accepted: {control}"
    expected = str(control["refused"])
    assert expected.strip()

    src = tmp_path / name
    src.write_bytes(raw)
    out = _send("scan this", target=str(src))

    assert out["status"] == "refused", out
    assert out["reply"] == expected, (
        f"{label}: the extractor's reason was reworded on its way to the operator\n"
        f"  extractor: {expected!r}\n"
        f"  operator:  {out['reply']!r}")
    assert out["error"] == expected


def test_a_named_archive_and_an_uploaded_one_produce_the_same_extracted_tree(tmp_path: Path,
                                                                             launches: list[dict]):
    """The positive half of the same claim: identical bytes in, identical material out — same file
    list, same digest, same inert permissions. A second route that merely *accepts* the same archives
    while unpacking them differently is still a second route."""
    raw = zip_bytes([("src/app.py", CODE), ("bin/run.sh", b"#!/bin/sh\necho hi\n",
                                            (stat.S_IFREG | 0o777) << 16)])
    src = tmp_path / "app.zip"
    src.write_bytes(raw)

    uploaded = upload("upload-chat", "app.zip", raw)
    assert uploaded.get("ok") is True, uploaded

    out = _send("review this", target=str(src))
    assert out["status"] == "running", out
    named_root = Path(launches[0]["target"])
    upload_root = Path(attachments.scan_root("upload-chat", uploaded["attachment_id"]))

    assert tree(named_root) == tree(upload_root), "the two routes unpacked to different trees"
    for rel in sorted(tree(named_root)):
        a, b = named_root / rel, upload_root / rel
        if a.is_dir():
            continue
        assert a.read_bytes() == b.read_bytes(), f"{rel} differs between the two routes"
        assert stat.S_IMODE(a.stat().st_mode) == stat.S_IMODE(b.stat().st_mode), \
            f"{rel} has a different mode on the local-path route"
        assert not (a.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)), \
            f"{rel} kept an executable bit"


# ===================================================================================================
# 4. the remaining shapes that are neither a folder nor an archive
# ===================================================================================================

def test_an_image_path_says_it_is_an_image_and_what_to_do_with_it(tmp_path: Path,
                                                                  launches: list[dict]):
    """A screenshot is a perfectly reasonable thing to hand over — just not as a scan TARGET. The
    refusal has to say which of the two it is, or the operator reads "not a codebase" and concludes
    the console cannot look at screenshots at all."""
    shot = tmp_path / "screenshot.png"
    shot.write_bytes(png_bytes())

    out = _send("what is wrong here?", target=str(shot))

    assert out["status"] == "refused", out
    assert "image" in out["reply"].lower()
    assert "attach it" in out["reply"].lower(), \
        "the operator is not told how to hand an image over instead"
    assert launches == []
    assert attachments.list_attachments(CHAT) == [], "an image target was silently attached anyway"


def test_a_fifo_target_says_it_is_not_a_regular_file(tmp_path: Path, launches: list[dict]):
    """A named pipe would block a console handler thread forever if it were opened and read. It is
    refused by what it IS, and the reply says so rather than blaming the operator's spelling."""
    fifo = tmp_path / "afifo"
    os.mkfifo(fifo)

    out = _send("scan this", target=str(fifo))

    assert out["status"] == "refused", out
    assert "regular readable file" in out["reply"]
    assert str(fifo) in out["reply"]
    assert launches == []


def test_a_device_target_says_the_same_thing():
    if not Path("/dev/null").exists():
        pytest.skip("no /dev/null on this host")
    out = _send("scan this", target="/dev/null")
    assert out["status"] == "refused", out
    assert "regular readable file" in out["reply"]


def test_without_the_attachment_store_an_archive_is_not_called_a_codebase(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, launches: list[dict]):
    """The original defect, made honest for the one build that genuinely cannot unpack: with no
    extractor available the archive is NOT quietly labelled a codebase and handed to an agent that
    needs a directory — the operator is told this build cannot unpack it, and what to give instead."""
    src = tmp_path / "app.zip"
    src.write_bytes(zip_bytes([("src/app.py", CODE)]))
    monkeypatch.setattr(chat, "_attach_fn", lambda name: None)

    out = _send("review this", target=str(src))

    assert out["status"] == "refused", out
    assert str(src) in out["reply"]
    assert "cannot unpack" in out["reply"].lower()
    assert "folder" in out["reply"].lower(), "the refusal does not say what to hand over instead"
    assert launches == [], "an unpackable-but-unpacked archive still reached the launcher"


def test_a_folder_never_goes_near_the_extractor(tmp_path: Path, launches: list[dict]):
    """A directory needs no unpacking, and must not acquire an attachment on its way to the scan —
    the run reads it where it lies."""
    repo = tmp_path / "repo" / "src"
    repo.mkdir(parents=True)
    (repo / "app.py").write_bytes(CODE)

    out = _send("review this", target=str(tmp_path / "repo"))

    assert out["status"] == "running", out
    assert launches[0]["target"] == str(tmp_path / "repo")
    assert attachments.list_attachments(CHAT) == [], "a folder target was copied into the store"
    assert "unpacked" not in out["reply"].lower()
