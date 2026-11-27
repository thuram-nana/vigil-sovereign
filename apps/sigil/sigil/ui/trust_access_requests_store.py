"""trust_access_requests_store - the "Request security documentation" queue for the PUBLIC Trust Center.

A visitor on the Security & Trust Center (``/trust``) may ask for the documents that sit behind an access request
(the customer-readable Data Retention Policy and Security Incident Response Policy). That ask lands HERE.

It is deliberately NOT an authority and NOT money: it mints nothing, grants no access, delivers no document, and is
NEVER owner-signed (the public plane is keyless and cookieless by construction - ``pubui``). This store only records
the unsigned request so it is not lost between the visitor dropping it and the owner-side intake acting on it. The
neutral acknowledgement the endpoint returns promises only that the request was received - never that access was
granted or a document sent.

Security posture (the honest boundary of a keyless plane):
  * every field is VALIDATED here (required, length-bounded, text-only; the email against a format) before anything
    is written - a request that does not validate is refused, nothing stored;
  * each request is one small JSON file under ``config.TRUST_ACCESS_REQUESTS_DIR``, written atomically
    (``spine.atomicio``; the temp file is 0600) in a 0700 directory, named by time + a random token - the filename
    carries NO submitted field, so no PII ever reaches a path;
  * the public plane never logs (``pubui`` ``log_message`` is a no-op) and this store prints nothing, so the raw PII
    is never written to a log in plaintext. The queue file itself is protected at rest by the 0600/0700 permissions;
    the keyless plane holds no key to seal it with, so the owner-side intake is where it is read and actioned;
  * a directory bound (``_MAX_QUEUED``) caps how many pending requests accumulate (anti-exhaustion); the per-source
    rate-limit (``ui/login_ratelimit.LoginRateLimiter``, wired in ``pubui``) is the first gate in front of this store.

Modeled on ``ui/authorization_requests_store.py`` (the unsigned owner-review queue). Stdlib + the sovereign
``reuse``/``spine.atomicio`` primitives only - no framework/strix (``assert_no_offense`` at import), so nothing here
crosses FATAL-2.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import time
from pathlib import Path

from ..reuse import assert_no_offense

assert_no_offense()

#: The closed set of submitted fields, in record order. All are plain, non-secret strings; a request mints NOTHING.
FIELDS = ("full_name", "organisation", "email", "job_title", "reason")

#: Per-field maximum length, in characters. Bounds each record so ``_MAX_QUEUED`` (not a byte ceiling) is the binding
#: cap, and keeps a single field from being used to exhaust disk.
_MAX_LEN = {
    "full_name": 200,
    "organisation": 200,
    "email": 254,            # RFC 5321 maximum
    "job_title": 120,
    "reason": 2000,
}
#: Fields that must be a single line (no raw line breaks / control chars). ``reason`` alone may contain newlines.
_SINGLE_LINE = ("full_name", "organisation", "email", "job_title")
#: A pragmatic email format: one ``@``, a dotted domain, no whitespace. Not an attempt to prove deliverability.
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
#: Control characters that must never appear in a stored field (C0 controls except the tab/newline handled per field).
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_MAX_QUEUED = 10000          # a bound on pending requests in the dir (defence in depth; the limiter gates volume)


def _is_text(v: object) -> bool:
    """Whether ``v`` is a string with a valid UTF-8 form (a lone surrogate has none and is refused)."""
    if not isinstance(v, str):
        return False
    try:
        v.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def validate(fields: "dict[str, object]") -> "tuple[dict[str, str], dict[str, str]]":
    """Validate a submitted access request. Returns ``(clean, errors)``:

      * ``clean`` - the stripped, validated values for every field, when ``errors`` is empty;
      * ``errors`` - ``{field: reason}`` for each field that is missing, empty, over-long, not text, carries a
        control character (or a line break where one is not allowed), or - for ``email`` - is not a valid address.

    The reasons are generic and name no submitted value, so an error response echoes nothing back.
    """
    clean: "dict[str, str]" = {}
    errors: "dict[str, str]" = {}
    data = fields if isinstance(fields, dict) else {}
    for key in FIELDS:
        raw = data.get(key)
        if raw is None or not _is_text(raw):
            errors[key] = "this field is required"
            continue
        value = raw.strip()
        if not value:
            errors[key] = "this field is required"
            continue
        if len(value) > _MAX_LEN[key]:
            errors[key] = f"keep this to {_MAX_LEN[key]} characters or fewer"
            continue
        # reason may hold newlines/tabs; the single-line fields may not. Either way, no other control chars.
        to_check = value.replace("\r", "").replace("\n", " ").replace("\t", " ") if key == "reason" else value
        if key in _SINGLE_LINE and ("\r" in value or "\n" in value):
            errors[key] = "this field must be a single line"
            continue
        if _CONTROL_RE.search(to_check):
            errors[key] = "this field contains invalid characters"
            continue
        if key == "email" and not _EMAIL_RE.fullmatch(value):
            errors[key] = "enter a valid email address"
            continue
        clean[key] = value
    return clean, errors


def _dir(requests_dir: "str | os.PathLike | None" = None) -> Path:
    if requests_dir is not None:
        return Path(requests_dir)
    from .. import config
    return Path(config.TRUST_ACCESS_REQUESTS_DIR)


class QueueFull(OSError):
    """The pending-request directory already holds ``_MAX_QUEUED`` requests: a new one is refused rather than let the
    directory grow without bound. The endpoint surfaces this as a neutral "try again later", never as success."""


def record_request(clean: "dict[str, str]", *, requests_dir: "str | os.PathLike | None" = None,
                   now: "float | None" = None) -> str:
    """Record one VALIDATED access request as its own 0600 JSON file in a 0700 directory and return the opaque record
    id (the filename stem). ``clean`` MUST be the output of :func:`validate` with no errors - this writer re-checks the
    field set and bounds fail-closed, but it is not the input validator.

    Refused with ``ValueError`` (nothing written): a field missing from ``clean``, not text, or over-long. Refused with
    ``OSError`` (nothing written): a full queue (``QueueFull``) or a directory that cannot be written. On success the
    record is on disk before the id is returned, so the endpoint never acknowledges a request it did not store.
    """
    out: "dict[str, str]" = {}
    for key in FIELDS:
        v = clean.get(key) if isinstance(clean, dict) else None
        if not _is_text(v):
            raise ValueError(f"missing field {key!r}")
        v = v.strip()  # type: ignore[union-attr]
        if not v or len(v) > _MAX_LEN[key]:
            raise ValueError(f"field {key!r} is not within bounds")
        out[key] = v
    ts = time.time() if now is None else float(now)
    record = {"received_at": ts, "schema": "trust.access_request.v1", **out}
    d = _dir(requests_dir)
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    # Anti-exhaustion: count existing queued files (cheap scandir) and refuse past the bound.
    try:
        queued = sum(1 for e in os.scandir(d) if e.name.endswith(".json"))
    except OSError:
        queued = 0
    if queued >= _MAX_QUEUED:
        raise QueueFull("the access-request queue is full")
    # A collision-resistant id: UTC-ish time prefix (sortable) + random token. No submitted field in the name.
    rid = f"{int(ts)}-{secrets.token_hex(12)}"
    from ..spine.atomicio import atomic_write_text
    atomic_write_text(d / f"{rid}.json", json.dumps(record, sort_keys=True, ensure_ascii=False))
    return rid


def pending_count(requests_dir: "str | os.PathLike | None" = None) -> int:
    """How many access requests are queued (lenient: a missing dir is zero). For owner-side tooling / tests."""
    try:
        return sum(1 for e in os.scandir(_dir(requests_dir)) if e.name.endswith(".json"))
    except OSError:
        return 0
