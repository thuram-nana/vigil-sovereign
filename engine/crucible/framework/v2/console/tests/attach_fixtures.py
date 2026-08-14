"""Builders shared by the chat-attachment test modules.

Deliberately NOT named ``test_*`` — pytest's ``python_files`` glob skips it, so it is a plain helper
module the attachment suites import.

Everything here builds HOSTILE input by hand rather than through a convenience API, because the point
of the suite is that a permissive extractor cannot pass it. In particular:

  * ``zip_bytes`` writes each member through an explicit ``ZipInfo`` so a test can set the
    ``external_attr`` mode word — a symlink flag, a device type, a 0777 executable bit — which is the
    only way to build the archives a real attacker sends.
  * ``zip_understating_declared_size`` patches the uncompressed-size fields in BOTH the local header
    and the central directory after the fact, so the archive's own declaration is a lie. An extractor
    that budgets from the declared size (the obvious implementation) is fooled by it.
  * ``upload`` drives the REAL chunked receive path (``save_chunk`` × N → ``finish_upload``), never a
    private helper, so what the tests exercise is what the console's POST routes call.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import secrets
import stat
import struct
import tarfile
import warnings
import zipfile
import zlib
from pathlib import Path

from framework.v2.console import attachments

# ---------------------------------------------------------------------------------------------------
# mode words for a zip member's `external_attr` (the high 16 bits are the unix mode)
# ---------------------------------------------------------------------------------------------------

SYMLINK_ATTR = (stat.S_IFLNK | 0o777) << 16
CHARDEV_ATTR = (stat.S_IFCHR | 0o666) << 16
FIFO_ATTR = (stat.S_IFIFO | 0o666) << 16
EXEC_FILE_ATTR = (stat.S_IFREG | 0o777) << 16
EXEC_DIR_ATTR = (stat.S_IFDIR | 0o777) << 16
SETUID_FILE_ATTR = (stat.S_IFREG | 0o4755) << 16


# ---------------------------------------------------------------------------------------------------
# archive builders
# ---------------------------------------------------------------------------------------------------

def zip_bytes(entries, *, allow_duplicate_names: bool = False) -> bytes:
    """A zip built from ``(arcname, data)`` or ``(arcname, data, external_attr)`` tuples.

    Members are DEFLATED explicitly: ``writestr`` only honours the archive's compression when handed a
    plain name, so a ZipInfo-built member would otherwise be stored uncompressed and a "decompression
    bomb" test would silently test nothing.
    """
    bio = io.BytesIO()
    with warnings.catch_warnings():
        if allow_duplicate_names:
            warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
            for entry in entries:
                arc, data = entry[0], entry[1]
                ext = entry[2] if len(entry) > 2 else None
                zi = zipfile.ZipInfo(arc)
                zi.compress_type = zipfile.ZIP_DEFLATED
                if ext is not None:
                    zi.external_attr = ext
                zf.writestr(zi, data)
    return bio.getvalue()


def zip_understating_declared_size(arcname: str, data: bytes, declared: int = 16) -> bytes:
    """A zip whose member DECLARES ``declared`` uncompressed bytes while really holding ``len(data)``.

    Both size fields are patched — the local file header (offset 22) and the central directory record
    (offset 24) — so nothing in the archive's own metadata betrays the lie. An extractor that trusts
    the declaration to budget, allocate or bound the write is defeated by this archive; the only sound
    defence is to count bytes as they actually arrive.
    """
    buf = bytearray(zip_bytes([(arcname, data)]))
    local = buf.find(b"PK\x03\x04")
    central = buf.find(b"PK\x01\x02")
    assert local >= 0 and central >= 0, "malformed fixture archive"
    struct.pack_into("<I", buf, local + 22, declared)
    struct.pack_into("<I", buf, central + 24, declared)
    return bytes(buf)


def tar_bytes(members) -> bytes:
    """A tar from a list of member specs. Each is a dict:

        {"name": str, "data": bytes}                          — a regular file
        {"name": str, "type": tarfile.SYMTYPE, "link": str}   — a symlink
        {"name": str, "type": tarfile.LNKTYPE, "link": str}   — a hard link
        {"name": str, "type": tarfile.DIRTYPE}                — a directory

    ``mode`` may be set on any of them (that is how the executable-bit test gets a 0777 member onto
    the wire; tar carries the real unix mode, so an extractor using ``extractall`` restores it).
    """
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as tf:
        for spec in members:
            ti = tarfile.TarInfo(spec["name"])
            ti.type = spec.get("type", tarfile.REGTYPE)
            ti.mode = spec.get("mode", 0o644)
            if "link" in spec:
                ti.linkname = spec["link"]
            data = spec.get("data")
            if data is not None and ti.type == tarfile.REGTYPE:
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
            else:
                tf.addfile(ti)
    return bio.getvalue()


def png_bytes(width: int = 2, height: int = 2) -> bytes:
    """A real, minimal PNG — magic bytes included, so the store's content sniff sees an image."""
    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (struct.pack(">I", len(payload)) + tag + payload
                + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    scanlines = b"".join(b"\x00" + b"\xff\x00\x00" * width for _ in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(scanlines)) + chunk(b"IEND", b""))


def source_file(tag: int, functions: int = 18) -> bytes:
    """A plausible source file with a unique START and END marker, so a test can tell "this file was
    quoted" from "this file was quoted in full"."""
    head = f"# MARK_START_{tag:02d}\n"
    body = "".join(f"def handler_{tag:02d}_{k:03d}(request, user):\n"
                   f"    return validate(request, user)\n" for k in range(functions))
    return (head + body + f"# MARK_END_{tag:02d}\n").encode()


# ---------------------------------------------------------------------------------------------------
# the real upload path
# ---------------------------------------------------------------------------------------------------

def upload(chat_id: str, filename: str, raw: bytes, *, upload_id: str = "",
           chunk_bytes: int = 0) -> dict:
    """Drive the store's REAL chunked receive: ``save_chunk`` for every slice, then ``finish_upload``.

    Returns whatever ``finish_upload`` returns — a manifest on success, ``{"ok": False, "refused": …}``
    on a refusal. Every ``save_chunk`` must succeed; a chunk-level refusal is a test-setup error and
    is raised loudly rather than being mistaken later for an extraction refusal.
    """
    uid = upload_id or ("u" + secrets.token_hex(8))
    step = chunk_bytes or attachments._MAX_CHUNK_BYTES
    seq = 0
    for off in range(0, max(len(raw), 1), step):
        piece = raw[off:off + step]
        if not piece:
            break
        res = attachments.save_chunk(chat_id, uid, seq, base64.b64encode(piece).decode("ascii"))
        assert res.get("ok"), f"chunk {seq} was refused during test setup: {res}"
        seq += 1
    return attachments.finish_upload(chat_id, uid, filename)


# ---------------------------------------------------------------------------------------------------
# filesystem assertions
# ---------------------------------------------------------------------------------------------------

def tree(root: Path) -> set[str]:
    """Every path under ``root``, relative and sorted-comparable — the snapshot a refusal is measured
    against. ``lstat`` semantics: a symlink is recorded as the link itself, never followed, so an
    extractor that planted one cannot hide it behind its target."""
    out: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        for name in list(dirnames) + list(filenames):
            out.add(str(Path(dirpath, name).relative_to(root)))
    return out


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
