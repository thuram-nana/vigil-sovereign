"""authorization_requests_store — the UNSIGNED owner-review requests a customer drops from the read-only
Authorizations surface (legal/governance S12), kept SERVER-SIDE, per ORG.

The customer Authorizations screen (VIGIL_CUSTOMER_AUTHORIZATIONS) shows a workspace, read-only, the owner-signed
EngagementAuthorities on record for its OWN proven-owned hosts. When a host is not actively authorized the customer may
"request authorization" — ask the owner to sign an assessment authority for it. THAT ASK LANDS HERE.

It is deliberately NOT an authority and NOT a signed spine record: it mints nothing, moves no money, is never
owner-signed, and never widens scope. The owner still signs the real :class:`EngagementAuthority` in the cockpit
(``ui/target_authorization.py``). This store only records the unsigned request so it is not lost between the customer
dropping it and the owner acting on it — exactly the honest boundary S12 draws (surface = read + drop; authority =
owner-signed, elsewhere).

Shape: one small JSON file per ORG under ``config.CUSTOMER_AUTHORIZATION_REQUESTS_DIR``
(``$SIGIL_HOME/customer_authorization_requests``), named by a domain-separated sha256 of the org_id (no org_id in a
path), written atomically (``spine.atomicio``; the temp file is 0600) in a 0700 directory. The record is a map
``{host -> {"requested_by", "note", "at"}}`` — the LATEST request per host (a re-request updates it in place), so the
file never grows without bound. Only hosts the SOVEREIGN caller has already checked the org proven-owns are ever written
(the provisioner enforces that), and only valid-text string fields are stored.

A save merges ONLY the host it names onto what is stored, one save at a time (``_SAVE_LOCK``). A missing or symlinked
file holds no requests: it reads as the empty ``{}`` (the safe direction), and a save replaces a symlink (the atomic
rename), never writes through it. A file that is there but cannot be read as a whole requests record (an I/O error, not
a regular file, oversized, not UTF-8, or not the record this store writes) is treated as empty by the lenient read, and
a save is REFUSED rather than blanking it (``RequestsUnreadable``). The open never blocks (``O_NONBLOCK``).

This is an operational owner-review queue, not durable trust state: the backup EXCLUDES it with a documented reason
(``backup._EXCLUSION_REASONS``) — a restore drops any pending request (the customer re-requests; the authoritative
owner-signed authorities live on the authority seam), so nothing recovery-critical is lost.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
import threading
from pathlib import Path

from ..reuse import assert_no_offense

assert_no_offense()

#: the CLOSED per-request field allowlist — plain, non-secret strings. Nothing here is a secret, an authority grant, or
#: a money value; a request mints NOTHING.
REQUEST_KEYS = ("requested_by", "note", "at")
_MAX_BYTES = 65536               # the largest requests record the store reads, in SERIALISED bytes
_MAX_HOSTS = 256                 # a bound on distinct hosts per org (defence in depth; the provisioner gates ownership)
_MAX_VALUE_LEN = 1024            # per string value, in characters
_SYMLINK_ERRNOS = frozenset({errno.ELOOP, errno.EMLINK})
_SAVE_LOCK = threading.Lock()


class RequestsUnreadable(OSError):
    """An org's requests file is there but could not be read as a whole record: an I/O error, not a regular file, more
    than ``_MAX_BYTES``, bytes that are not UTF-8, or not the record this store writes. A save is refused (a merge onto
    the empty defaults would drop every host the save does not name), nothing written."""


def _dir() -> Path:
    from .. import config
    return Path(config.CUSTOMER_AUTHORIZATION_REQUESTS_DIR)


def _name(org_id: str) -> str:
    return hashlib.sha256(b"vigil-authz-requests\x00" + org_id.encode("utf-8")).hexdigest() + ".json"


def _is_text(v: object) -> bool:
    if not isinstance(v, str):
        return False
    try:
        v.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _read_stored(path: Path) -> "bytes | None":
    """The bytes of the org's file in full — ``None`` when it holds no stored requests (no file, or a symlink: never
    followed). Raises ``RequestsUnreadable`` for a file that is there but cannot be read. The open never blocks."""
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return None
    except OSError as e:
        if e.errno in _SYMLINK_ERRNOS:
            return None
        raise RequestsUnreadable(e.errno, "the stored requests could not be opened") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RequestsUnreadable(errno.EINVAL, "the stored requests are not a regular file")
        chunks, size = [], 0
        while size <= _MAX_BYTES:
            chunk = os.read(fd, _MAX_BYTES + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    except RequestsUnreadable:
        raise
    except OSError as e:
        raise RequestsUnreadable(e.errno, "the stored requests could not be read") from None
    finally:
        os.close(fd)
    if size > _MAX_BYTES:
        raise RequestsUnreadable(errno.EFBIG, "the stored requests are larger than this store writes")
    return b"".join(chunks)


def _load(org_id: str, *, strict: bool) -> dict:
    """The org's stored requests as ``{host -> {requested_by, note, at}}`` (only valid-text fields surfaced). A missing
    or symlinked file reads as ``{}``. A file that cannot be read as a whole record reads as ``{}`` too — unless
    ``strict``, which raises ``RequestsUnreadable`` (a save merges onto this, so it may not take an unread file for an
    empty one)."""
    out: dict = {}
    try:
        raw = _read_stored(_dir() / _name(org_id))
        if raw is None:
            return out
        try:
            doc = json.loads(raw.decode("utf-8"))
        except ValueError:
            raise RequestsUnreadable(errno.EINVAL, "the stored requests are not valid") from None
        saved = doc.get("requests") if isinstance(doc, dict) else None
        if not isinstance(saved, dict):
            raise RequestsUnreadable(errno.EINVAL, "the stored requests are not a requests record")
    except RequestsUnreadable:
        if strict:
            raise
        return out
    for host, rec in saved.items():
        if not (isinstance(host, str) and _is_text(host) and isinstance(rec, dict)):
            continue
        clean: dict[str, object] = {}  # holds str fields (requested_by, note) and a float 'at'
        for k in REQUEST_KEYS:
            v = rec.get(k)
            if isinstance(v, str) and _is_text(v):
                clean[k] = v
            elif k == "at" and isinstance(v, (int, float)) and not isinstance(v, bool):
                clean[k] = float(v)
        out[host] = clean
    return out


def read_requests(org_id: str, *, strict: bool = False) -> dict:
    """The org's dropped owner-review requests as ``{host -> {requested_by, note, at}}``. A missing or symlinked file
    reads as ``{}``; the lenient read never raises. An org_id with no UTF-8 form holds no requests (``{}``)."""
    o = str(org_id or "")
    if not o or not _is_text(o):
        return {}
    return _load(o, strict=strict)


def pending_hosts(org_id: str) -> "list[str]":
    """The hosts this org currently has an open owner-review request for, in sorted order. Lenient (never raises)."""
    try:
        return sorted(read_requests(org_id))
    except RequestsUnreadable:
        return []


def record_request(org_id: str, *, host: str, requested_by: str, note: str = "", now: float) -> dict:
    """Record (or update) the org's owner-review request for ``host`` and return the full stored requests map. This
    mints NOTHING and is never owner-signed — it only drops the unsigned ask.

    Refused with ``ValueError``, nothing written: an empty org_id/host (or either with no UTF-8 form), a non-string
    field, an over-long value, or a record that would exceed ``_MAX_BYTES`` / ``_MAX_HOSTS``. Refused with ``OSError``,
    nothing written: a stored file that cannot be read as a whole record (``RequestsUnreadable``), or a directory that
    cannot be written."""
    o, h = str(org_id or ""), str(host or "")
    if not o or not _is_text(o):
        raise ValueError("an authorization request needs the org")
    if not h or not _is_text(h):
        raise ValueError("an authorization request needs a host")
    if len(h) > _MAX_VALUE_LEN:
        raise ValueError("host is too long")
    rb, nt = str(requested_by or ""), str(note or "")
    if not _is_text(rb) or not _is_text(nt):
        raise ValueError("an authorization request field is not valid text")
    if len(rb) > _MAX_VALUE_LEN or len(nt) > _MAX_VALUE_LEN:
        raise ValueError("an authorization request field is too long")
    entry = {"requested_by": rb, "note": nt, "at": float(now)}
    from ..spine.atomicio import atomic_write_text
    with _SAVE_LOCK:
        merged = _load(o, strict=True)
        if host not in merged and len(merged) >= _MAX_HOSTS:
            raise ValueError("too many outstanding authorization requests for this org")
        merged[h] = entry
        data = json.dumps({"requests": merged, "at": float(now)}, sort_keys=True)
        if len(data.encode("utf-8")) > _MAX_BYTES:
            raise ValueError("the requests record is too long to store")
        d = _dir()
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        atomic_write_text(d / _name(o), data)
    return merged
