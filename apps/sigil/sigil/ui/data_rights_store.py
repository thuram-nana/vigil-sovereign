"""data_rights_store — the customer DATA-RIGHTS request ledger (owner-signed, append-only), per account.

Legal/governance S3. When a customer records a close-account / deletion request from the Data-rights screen
(``VIGIL_CUSTOMER_DATA_RIGHTS``), it is kept as a DURABLE record the owner acts on — one owner-signed row per request,
appended to a per-account file. It is NOT money and NOT authority: the record unlocks nothing by itself, grants no
role, mints no credit, and is NEVER written to the hot signed spine (no audit row). It is the data-subject-request
ITEM the owner's published process works from (the 30-day response, ``info@sigilsovereign.com``); the owner-gated
hard-prune (VAULT-PRUNE) is what actually removes records from the immutable spine — this ledger does not, and never
claims to.

Modeled on two existing primitives:
  * ``ui/preferences_store.py``'s file discipline — one domain-separated-sha256-named 0600 file per account (no
    username / email in a path) in a 0700 directory of its own, opened ``O_NOFOLLOW``/``O_NONBLOCK`` (a symlink or a
    special file at the path holds no ledger and never blocks), bounded, and the whole file read to its end;
  * ``governor/invoices.py``'s owner-signed, verify-on-read, idempotent-by-id shape — each row carries the owner's
    signature over its authenticated CORE, and a read VERIFIES every row under the trusted owner pubkey and DROPS a
    forged / tampered one (fail-closed: a row a forger slipped into the file must never appear as the customer's).

Append-only and idempotent: a row whose ``request_id`` is already present (and verifies) is never duplicated — a
replay is a no-op, not a second record. A request that cannot be owner-signed (no owner key — a sealed/locked vault)
is REFUSED rather than written unverifiable: a row that could never verify on read must not be recorded.

Stdlib + the sovereign ``reuse``/``governor.authn`` signing primitives only — no framework/strix (``assert_no_offense``
at import), so nothing here crosses FATAL-2.
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

from ..governor.authn import signed_payload, verify_signed  # noqa: E402

#: the signal (type tag) inside every row's signed core — distinct from any governor spine signal; this ledger is a
#: per-account file, never the hot spine.
DATA_RIGHTS_SIGNAL = "customer.data_rights_request"
#: the kinds of data-rights request a customer can record. ``export`` = "I exported my data" (the synchronous export is
#: served live; recording it is an optional audit the edge does not require); ``close_account`` = a close-account /
#: deletion request the owner acts on. A kind outside this set is refused.
KINDS = ("export", "close_account")
#: the owner-signed authenticated CORE. ``request_id`` is inside it so a captured row cannot be re-stamped with a fresh
#: idempotency key to forge a duplicate; ``username``/``org_id``/``kind`` are inside it so a row for one account/org can
#: never be re-aimed at another or have its kind rewritten without breaking the signature.
_CORE = ("signal", "username", "org_id", "request_id", "kind", "created_at")

_MAX_BYTES = 262144                 # the largest ledger file this store reads (a larger file is not one it wrote)
_MAX_ROWS = 1000                    # the most rows one account's ledger holds (a larger one is refused a new row)
_MAX_ID_LEN = 128                   # per request_id, in characters
_MAX_ORG_LEN = 256                  # per org_id, in characters
# What opening a symlink with O_NOFOLLOW fails with (ELOOP on Linux, EMLINK on the BSDs): a symlink where an account's
# file goes holds no ledger, so a record replaces nothing through it (the append opens the real path only).
_SYMLINK_ERRNOS = frozenset({errno.ELOOP, errno.EMLINK})
# One writer at a time, PROCESS-WIDE (the cockpit is the one process that writes this store, on request threads): a
# record's read -> idempotency check -> append is never interleaved with another's, so two requests for the same id can
# never both append.
_WRITE_LOCK = threading.Lock()


class LedgerUnreadable(OSError):
    """An account's ledger file is there but could not be read as a whole ledger: an I/O error, not a regular file, or
    more than ``_MAX_BYTES``. What it holds is unknown, so a record is refused (nothing appended) rather than risk a
    duplicate, and the screen's read reports it rather than show an empty history."""


def _dir() -> Path:
    from .. import config
    return Path(config.CUSTOMER_DATA_RIGHTS_DIR)


def _name(username: str) -> str:
    return hashlib.sha256(b"vigil-data-rights\x00" + username.encode("utf-8")).hexdigest() + ".jsonl"


def _is_text(v: object) -> bool:
    """Whether ``v`` is a string that is valid text (has a UTF-8 form). A lone UTF-16 surrogate has none: stored, it
    would break every page that shows it, and it could never canonicalize to a signed core."""
    if not isinstance(v, str):
        return False
    try:
        v.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _read_bytes(path: Path) -> "bytes | None":
    """The whole ledger file's bytes — ``None`` when it holds no ledger (no file, or a symlink: never followed). Raises
    ``LedgerUnreadable`` for a file that is there but cannot be read: any other ``OSError``, anything but a regular file,
    or more than ``_MAX_BYTES``. The open never blocks (``O_NONBLOCK``) and the read loops to the end."""
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return None
    except OSError as e:
        if e.errno in _SYMLINK_ERRNOS:
            return None
        raise LedgerUnreadable(e.errno, "the data-rights ledger could not be opened") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise LedgerUnreadable(errno.EINVAL, "the data-rights ledger is not a regular file")
        chunks, size = [], 0
        while size <= _MAX_BYTES:
            chunk = os.read(fd, _MAX_BYTES + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    except LedgerUnreadable:
        raise
    except OSError as e:
        raise LedgerUnreadable(e.errno, "the data-rights ledger could not be read") from None
    finally:
        os.close(fd)
    if size > _MAX_BYTES:
        raise LedgerUnreadable(errno.EFBIG, "the data-rights ledger is larger than this store writes")
    return b"".join(chunks)


def _rows(raw: bytes, *, trusted_pubkey: "str | None") -> list:
    """Every VERIFIED row in the ledger bytes, in file order. Each line is one JSON record; a line that is not a record,
    or whose owner signature does not verify under ``trusted_pubkey`` over ``_CORE``, is DROPPED (fail-closed — a forged
    / tampered row must not appear as the customer's)."""
    out = []
    for line in raw.decode("utf-8", "strict").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict) or rec.get("signal") != DATA_RIGHTS_SIGNAL:
            continue
        if not verify_signed(rec, _CORE, trusted_pubkey):
            continue
        out.append(rec)
    return out


def _view(rec: dict) -> dict:
    """The customer-safe view of one row — its own request_id, kind, org and time. Never the signature or pubkey."""
    return {"request_id": rec.get("request_id"), "kind": rec.get("kind"),
            "org_id": rec.get("org_id"), "created_at": rec.get("created_at")}


def list_requests(username: str, *, trusted_pubkey: "str | None", strict: bool = False) -> list:
    """The account's recorded data-rights requests, newest first — each a customer-safe view, VERIFIED under
    ``trusted_pubkey``. A missing or symlinked file is an empty history. A file that is there but cannot be read as a
    whole ledger reads as an empty history in the lenient read (the default); ``strict`` raises ``LedgerUnreadable`` for
    it (the screen reads strictly so it reports such a file rather than show an empty history for a stored one)."""
    u = str(username or "")
    if not u or not _is_text(u):
        return []
    try:
        raw = _read_bytes(_dir() / _name(u))
    except LedgerUnreadable:
        if strict:
            raise
        return []
    if raw is None:
        return []
    rows = _rows(raw, trusted_pubkey=trusted_pubkey)
    rows.sort(key=lambda r: (float(r.get("created_at") or 0.0)), reverse=True)
    return [_view(r) for r in rows]


def record_request(username: str, org_id: str, kind: str, request_id: str, *, owner_key, now: float) -> dict:
    """Record one owner-signed data-rights request for the account, appending it to the per-account ledger, and return
    ``{"recorded": bool, "request": view}`` — ``recorded`` False iff the ``request_id`` was already present (idempotent
    replay: no second row). Only the ``KINDS`` set is accepted; ``request_id``/``org_id`` must be valid text within
    their bounds.

    Refused with ``ValueError``, nothing written: an unknown kind, a non-string / empty / over-long / non-text
    ``request_id`` or ``org_id``, or an empty or non-text ``username`` — the caller's INPUT. Refused with ``OSError``,
    nothing written (a STORE / environment fault, not the input): no owner key to sign with (a locked vault — a row
    that could never verify on read must not be recorded, fail-closed), a ledger file that is there but cannot be read
    (``LedgerUnreadable``, so idempotency cannot be checked), one already at ``_MAX_ROWS``, or a directory that cannot
    be written."""
    u = str(username or "")
    if not u or not _is_text(u):
        raise ValueError("a data-rights request needs the account")
    if kind not in KINDS:
        raise ValueError(f"unknown data-rights request kind: {kind!r}")
    o = str(org_id or "")
    if not o or not _is_text(o) or len(o) > _MAX_ORG_LEN:
        raise ValueError("a data-rights request needs a valid org")
    rid = str(request_id or "")
    if not rid or not _is_text(rid) or len(rid) > _MAX_ID_LEN:
        raise ValueError("a data-rights request needs a valid request id")
    if owner_key is None:
        # fail-closed: a request that cannot be owner-signed would never verify on read, so it is never recorded. This
        # is a STORE / environment fault (a locked vault), NOT the caller's input — an OSError, so the provisioner
        # surfaces it as the cockpit's clean 500, never a 400 that blames (or reveals anything about) the request.
        raise LedgerUnreadable(errno.EIO, "a data-rights request cannot be signed (the owner key is unavailable)")
    trusted = getattr(owner_key, "public_key_b64", None)
    with _WRITE_LOCK:                               # read -> idempotency check -> append as one step (see _WRITE_LOCK)
        existing = _read_bytes(_dir() / _name(u))   # LedgerUnreadable here refuses the record (never a blind duplicate)
        rows = _rows(existing, trusted_pubkey=trusted) if existing is not None else []
        for r in rows:
            if r.get("request_id") == rid:
                return {"recorded": False, "request": _view(r)}
        if len(rows) >= _MAX_ROWS:
            raise LedgerUnreadable(errno.EFBIG, "too many data-rights requests on this account")
        core = {"signal": DATA_RIGHTS_SIGNAL, "username": u, "org_id": o, "request_id": rid,
                "kind": kind, "created_at": float(now)}
        row = signed_payload(core, owner_key)
        line = (json.dumps(row, sort_keys=True) + "\n").encode("utf-8")
        d = _dir()
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(d / _name(u)), flags, 0o600)
        try:
            os.write(fd, line)                      # one write of one line (< PIPE_BUF): an atomic append
        finally:
            os.close(fd)
        return {"recorded": True, "request": _view(row)}
