"""customer_chat_store - the per-(org, session) append-only CONVERSATION transcript behind the chat command box.

This is the CONTINUITY store: the customer's own typed box lines and the grounded advice answers, kept so a reopened
box reads like ONE running conversation (and, optionally, so the grounded assistant can see recent prior turns). It is
COSMETIC continuity only - it holds no authority, no money and no finding, and nothing read from it can mint one.

Money / tenant / privacy doctrine, enforced BY CONSTRUCTION (not by a runtime filter):

  * TENANT-ISOLATED by path. Each org's transcripts live under its OWN directory, named by a DOMAIN-SEPARATED one-way
    hash of a validated ``org_id`` (``_org_root``) - distinct from every other per-org hashed namespace (the knowledge
    corpus, the authz-requests dir, ``_customer_slug``), so one org's transcript can never be another's and NONE of
    them is ever the owner's global store. Inside it, ONE append-only file per ``session_key`` (the edge's one-way hash
    of the session id - a 64-hex token that is opaque, non-reversible and a safe single path component). The org and
    the session are therefore STRUCTURAL: a caller cannot name another tenant's or another session's transcript.

  * MINIMAL by content. A stored turn is ONLY ``{role, text, ts}`` - role in a closed allowlist (``user`` /
    ``assistant``), text capped and control-stripped, ts a float. It carries no org_id, no username, no session id, no
    IP and no secret. The org/requester/session are the hop-bound session principal the caller already resolved
    server-side; this module never receives, stores or trusts a body-supplied identity.

  * BOUNDED. Per (org, session) the file keeps at most ``MAX_TURNS`` turns AND at most ``MAX_BYTES`` on disk; on each
    append the OLDEST turns are trimmed to fit, so a long conversation can never grow without bound or exhaust disk.

  * FAIL-CLOSED on a bad identity (an invalid org_id / session_key / role raises before any path is built), and the
    READ re-asserts isolation (a turn whose file is not THIS (org, session)'s is impossible by the per-path layout).
    The WRITE is best-effort at the CALLER (the provisioner wraps it so a store fault never breaks a command); a read
    fault returns an empty transcript, never another tenant's data.

FATAL-2: sovereign-only, pure-stdlib, ``assert_no_offense()`` at import. It imports no offense-plane module and no
mint primitive; it is a plain append-only JSONL store (never the owner-signed cryptographic spine - a continuity
transcript must never be able to gate, or be confused with, an authority / money / finding record).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from .. import config
from ..governor.orgs import _check_org_id

__all__ = ["append", "history", "ChatStoreError", "ROLES", "MAX_TURNS", "MAX_BYTES", "MAX_TEXT_CHARS"]

#: Domain separation for the per-org transcript directory hash - distinct from every other per-org hashed-name
#: namespace, so a transcript dir can never collide with another per-org store (e.g. the knowledge corpus).
_CHAT_CONTEXT = b"vigil-customer-chat\x00"
#: A session key is the edge's SHA-256 of the session id: a fixed 64-hex token, opaque and a safe single path
#: component (no traversal). Anything else is refused fail-closed.
_SESSION_RE = re.compile(r"[0-9a-f]{64}")
#: The closed role allowlist a stored turn may carry. Everything else is refused (the transcript is a plain
#: user/assistant conversation; no other role is meaningful or stored).
ROLES = ("user", "assistant")
#: Per (org, session) bounds. The file keeps at most this many turns AND at most this many bytes on disk; on each
#: append the oldest are trimmed to fit both. A single turn's text is capped before it is stored.
MAX_TURNS = 200
MAX_BYTES = 128 * 1024
MAX_TEXT_CHARS = 4000


class ChatStoreError(RuntimeError):
    """A transcript-store operation failed on a bad identity or a corrupt store. Raised (never swallowed here) so the
    caller fails closed; the provisioner wraps the WRITE so a fault never breaks a command, and the READ degrades to an
    empty transcript."""


def _check_session_key(session_key: str) -> str:
    """The validated session key, or raise. It is the edge's one-way hash of the session id (a 64-hex token); anything
    else is refused BEFORE any path is built, so the file name can never traverse or name another session."""
    s = str(session_key or "").strip().lower()
    if not _SESSION_RE.fullmatch(s):
        raise ChatStoreError("session_key must be a 64-hex session hash (the edge derives it from the session id)")
    return s


def _org_root(org_id: str) -> Path:
    """The root directory of ``org_id``'s transcripts, strictly inside ``config.CUSTOMER_CHAT_DIR``. Fail-closed: the
    org id is validated (``_check_org_id`` - an alphanumeric-start tenant id, no separators / traversal), the directory
    name is a 64-char hex digest (no traversal possible), and the resolved root's parent MUST be the chat base dir - so
    this can never resolve onto the owner's global stores or another dir. A bad org id is re-raised as a
    :class:`ChatStoreError` (the store's one fail-closed identity error)."""
    try:
        oid = _check_org_id(org_id)
    except ValueError as e:
        raise ChatStoreError("org_id is not a valid tenant id") from e
    digest = hashlib.sha256(_CHAT_CONTEXT + oid.encode("utf-8")).hexdigest()
    base = Path(config.CUSTOMER_CHAT_DIR)
    root = (base / digest).resolve()
    if root.parent != base.resolve():
        raise ChatStoreError("refusing a transcript path outside the customer chat base dir")
    return root


def _session_path(org_id: str, session_key: str) -> Path:
    """The append-only JSONL file for ONE (org, session), inside the org's own validated root. The file name is the
    validated 64-hex session key, so it is a safe single component that can never traverse or name another session.

    Defence-in-depth at the single path chokepoint every read/write flows through: after building the file path we
    ``resolve()`` it and REQUIRE it to stay inside the org root (the same ``resolve()`` + ``is_relative_to(root)``
    barrier the UI file servers use - see ``static_site.py`` / ``pubui.py``). The 64-hex ``fullmatch`` already makes
    traversal impossible, so this guard can only ever hold; it makes the containment explicit at the sink and keeps a
    corrupt ``CUSTOMER_CHAT_DIR`` from ever landing a transcript op outside this tenant's own directory."""
    root = _org_root(org_id)
    path = (root / (_check_session_key(session_key) + ".jsonl")).resolve()
    if not path.is_relative_to(root):
        raise ChatStoreError("refusing a transcript path outside the org root")
    return path


def _clean_text(text: Any) -> str:
    """The stored turn text: a string, control characters (except a plain newline/tab) stripped, capped at
    ``MAX_TEXT_CHARS``. The transcript is cosmetic, so a turn text is bounded tidy-up only - it drives nothing."""
    s = str(text if text is not None else "")
    s = "".join(ch for ch in s if ch in ("\n", "\t") or ord(ch) >= 0x20)
    return s[:MAX_TEXT_CHARS]


def _read_turns(path: Path) -> "list[dict[str, Any]]":
    """The turns already on disk for a (org, session), oldest-first. A missing file is an empty conversation; a torn /
    unreadable line is skipped (continuity is best-effort - a corrupt transcript never raises on read)."""
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except OSError as e:
        raise ChatStoreError("the transcript file could not be read") from e
    out: "list[dict[str, Any]]" = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue                                    # a torn line is skipped, never fatal
        if (isinstance(rec, dict) and rec.get("role") in ROLES and isinstance(rec.get("text"), str)):
            out.append({"role": rec["role"], "text": rec["text"],
                        "ts": float(rec["ts"]) if isinstance(rec.get("ts"), (int, float)) else 0.0})
    return out


def _bounded(turns: "list[dict[str, Any]]") -> "list[dict[str, Any]]":
    """Trim ``turns`` (oldest-first) to at most ``MAX_TURNS`` AND at most ``MAX_BYTES`` of serialized JSONL, dropping
    the OLDEST first. A single over-sized turn is still kept (its text is already capped at append), so the store can
    never be driven empty by one big turn."""
    kept = turns[-MAX_TURNS:]
    while len(kept) > 1 and len(_serialize(kept)) > MAX_BYTES:
        kept = kept[1:]
    return kept


def _serialize(turns: "list[dict[str, Any]]") -> bytes:
    return ("".join(json.dumps(t, ensure_ascii=False, sort_keys=True) + "\n" for t in turns)).encode("utf-8")


def _atomic_write(path: Path, data: bytes) -> None:
    """Replace the transcript file atomically, 0600, inside its own dir (tmp + os.replace). Never a partial file a
    concurrent read could see torn."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=".jsonl")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError as e:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise ChatStoreError("the transcript file could not be written") from e


def append(org_id: str, session_key: str, role: str, text: str, *, now: "Optional[float]" = None) -> dict:
    """Append ONE turn (``{role, text, ts}``) to this (org, session)'s append-only transcript, then trim the OLDEST to
    the per-(org, session) caps. ``org_id`` + ``session_key`` are the hop-bound session identity the caller resolved
    server-side (never a body field). A bad identity / role raises (fail-closed). Returns ``{"turns": <kept count>}``.

    The transcript is cosmetic CONTINUITY: this writes NO authority, money or finding record and touches no owner key;
    it appends only the turn text + role + timestamp to the tenant-scoped per-session file."""
    if str(role) not in ROLES:
        raise ChatStoreError(f"role must be one of {ROLES}")
    path = _session_path(org_id, session_key)           # validates org + session fail-closed before any write
    t = time.time() if now is None else float(now)
    turns = _read_turns(path)
    turns.append({"role": str(role), "text": _clean_text(text), "ts": t})
    kept = _bounded(turns)
    _atomic_write(path, _serialize(kept))
    return {"turns": len(kept)}


def history(org_id: str, session_key: str, *, limit: int = MAX_TURNS) -> dict:
    """The recent turns of this (org, session)'s transcript, OLDEST-FIRST, at most ``limit`` (capped at ``MAX_TURNS``).
    ``org_id`` + ``session_key`` are the hop-bound session identity (never a body field). Returns
    ``{"turns": [{role, text, ts}, ...], "count": n}``. A missing / corrupt transcript reads as empty (never another
    tenant's data - the per-(org, session) path makes a cross-tenant read structurally impossible)."""
    path = _session_path(org_id, session_key)           # validates org + session fail-closed before any read
    n = max(0, min(int(limit), MAX_TURNS))
    turns = _read_turns(path)[-n:] if n else []
    return {"turns": turns, "count": len(turns)}
