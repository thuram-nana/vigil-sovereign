"""Hypotheses as first-class objects (Phase C) — the memory that closes the loop.

CHAT-VISION: "A hypothesis should be a first-class object minted from a conversation: a statement, what
would confirm it, what would refute it, and a status. When an oracle later fires, the hypothesis closes
itself, and the chat can say: the thing you suspected on Tuesday is now confirmed — here is the proof."

This module is the store + the honest auto-close. Design mirrors the chat transcript store: an
append-only JSONL per chat under ``<live>/hypotheses/<chat_id>.jsonl``, one record per line, superseded
by appending a new record with the same ``id`` (never rewritten in place). A hypothesis is a LEAD until
an oracle-confirmed FACT closes it — and it is closed as ``confirmed`` ONLY on a precise match (same
bug_class AND overlapping surface/target), always carrying the ``finding_ref`` so the close is auditable.
The chat mints no facts here; it records suspicions and links the engine's own confirmations to them.

Offense-console plane, stdlib-only aside from the sibling console modules it reuses for the live dir and
the path-component guard — no `framework` heavy deps, no sovereign import.
"""
from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path

from . import actions  # for the shared path-component guard + id minting (console-plane, already imported by chat)

_MAX_ID = 128
_MAX_STATEMENT = 2000
_MAX_FIELD = 1000
_MAX_HYPS = 500              # per chat, a sane ceiling on the ledger
_SCHEMA = "vigil-hypothesis-v1"
_OPEN = "open"
_CONFIRMED = "confirmed"
_REFUTED = "refuted"
_STATUSES = frozenset({_OPEN, _CONFIRMED, _REFUTED})


def _live_dir() -> Path:
    from . import sessions
    return sessions._live_dir()      # noqa: SLF001 — one resolver for the console's live base


def _safe_chat_id(raw: str) -> str:
    rid = actions._safe_run_id(str(raw or ""))
    if len(rid) > _MAX_ID:
        raise ValueError(f"chat id too long (> {_MAX_ID})")
    return rid


def _dir() -> Path:
    d = _live_dir() / "hypotheses"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def _path(chat_id: str) -> Path:
    return _dir() / f"{_safe_chat_id(chat_id)}.jsonl"


def _append(chat_id: str, rec: dict) -> None:
    line = json.dumps(rec, ensure_ascii=False)
    fd = os.open(str(_path(chat_id)), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def _read_records(chat_id: str) -> list[dict]:
    """Every record in order; a torn/blank last line (crash mid-write) is skipped, never fatal."""
    try:
        raw = _path(chat_id).read_text(encoding="utf-8")
    except (OSError, ValueError):
        return []
    out: list[dict] = []
    for ln in raw.split("\n"):
        ln = ln.strip()
        if not ln:
            continue
        try:
            obj = json.loads(ln)
        except Exception:  # noqa: BLE001 — a torn last line is not an error
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _collapse(records: list[dict]) -> list[dict]:
    """Append-only supersede: the LAST record for each id wins (a close appends a new record with the same
    id). Returns the current hypotheses, open first, then newest-created first."""
    latest: dict = {}
    for r in records:
        hid = str(r.get("id") or "")
        if hid:
            latest[hid] = r
    vals = list(latest.values())
    vals.sort(key=lambda r: (r.get("status") != _OPEN, -float(r.get("created_at") or 0)))
    return vals


def _clip(s, n: int) -> str:
    return str(s or "").strip()[:n]


def record(chat_id: str, statement: str, *, would_confirm: str = "", would_refute: str = "",
           bug_class: str = "", surface: str = "", source: str = "chat", now: float | None = None) -> dict:
    """Mint an OPEN hypothesis. Returns the stored record. Raises ValueError on an unsafe chat id or an
    empty statement (fail-closed). ``bug_class``/``surface`` are the (optional) structured hooks the
    honest auto-close matches on — a hypothesis without them is still recorded, it just will not
    auto-close (it can only be closed by hand)."""
    _safe_chat_id(chat_id)                                   # raises on unsafe id
    stmt = _clip(statement, _MAX_STATEMENT)
    if not stmt:
        raise ValueError("a hypothesis needs a statement")
    if len(_read_records(chat_id)) >= _MAX_HYPS:
        raise ValueError("hypothesis ledger is full for this chat")
    rec = {
        # a collision-proof id — a hypothesis id only needs to be UNIQUE (not sortable), and
        # ``_new_run_id`` can repeat for two records minted in the same instant, which would collapse two
        # distinct hypotheses into one. token_hex never collides.
        "schema": _SCHEMA, "id": secrets.token_hex(8), "status": _OPEN,
        "statement": stmt, "would_confirm": _clip(would_confirm, _MAX_FIELD),
        "would_refute": _clip(would_refute, _MAX_FIELD), "bug_class": _clip(bug_class, 80),
        "surface": _clip(surface, 200), "source": _clip(source, 40) or "chat",
        "chat_id": chat_id, "created_at": float(now if now is not None else time.time()),
    }
    _append(chat_id, rec)
    return rec


def list_for(chat_id: str) -> list[dict]:
    """The current hypotheses for a chat (collapsed to the latest per id), open first. Total: [] on any
    read problem or an unsafe id — never a traceback."""
    try:
        return _collapse(_read_records(chat_id))
    except Exception:  # noqa: BLE001
        return []


def close(chat_id: str, hyp_id: str, *, status: str, finding_ref: str = "", note: str = "",
          now: float | None = None) -> dict:
    """Close an open hypothesis (``confirmed`` / ``refuted``), superseding it with a new record carrying
    the outcome + an auditable ``finding_ref``. Returns the closing record, or ``{}`` if the id is
    unknown or already closed to the same status."""
    if status not in (_CONFIRMED, _REFUTED):
        raise ValueError(f"close status must be {_CONFIRMED!r} or {_REFUTED!r}")
    # A "confirmed" close is an evidence claim — it MUST carry a proof pointer or it is not auditable
    # (red-pen F6). A refuted close needs none. Fail-closed: a confirmed close without a ref is refused.
    if status == _CONFIRMED and not str(finding_ref or "").strip():
        return {}
    current = {r["id"]: r for r in list_for(chat_id) if r.get("id")}
    cur = current.get(str(hyp_id))
    if not cur or cur.get("status") == status:
        return {}
    rec = {**cur, "status": status, "finding_ref": _clip(finding_ref, 200),
           "close_note": _clip(note, _MAX_FIELD), "closed_at": float(now if now is not None else time.time())}
    _append(chat_id, rec)
    return rec


def _path_of(s) -> str:
    """The comparable PATH of a surface string. A finding's surface is a full URL
    (``http://host/api/user/1?q=x``); a hypothesis's is usually a path (``/api/user``). Reduce both to a
    normalised path — scheme+host+query+fragment dropped, trailing slash trimmed, root kept as ``/`` —
    so the match is over the endpoint, not the incidental URL text."""
    s = str(s or "").strip().lower()
    if not s:
        return ""
    if "://" in s:
        try:
            from urllib.parse import urlsplit
            s = urlsplit(s).path or "/"
        except Exception:  # noqa: BLE001
            pass
    for sep in ("?", "#"):
        i = s.find(sep)
        if i >= 0:
            s = s[:i]
    s = s.rstrip("/")
    return s or "/"


def _matches(hyp: dict, fact: dict) -> bool:
    """A PRECISE, path-segment-aware match between an open hypothesis and an oracle-confirmed FACT.

    Honest by construction (red-pen F1/F2): auto-close requires the same bug_class AND a SPECIFIC surface
    on the hypothesis AND the fact's endpoint to be AT or UNDER that surface at a PATH-SEGMENT boundary.
    Raw substring containment is NOT used — ``/api/user`` must not "confirm" a finding at
    ``/api/user-legacy-export``, and a bare hunch (no surface, or just ``/``) never auto-confirms off an
    unrelated finding; it stays open until the operator closes it or restates it with a specific surface."""
    hb = str(hyp.get("bug_class") or "").strip().lower()
    fb = str(fact.get("bug_class") or "").strip().lower()
    if not hb or hb != fb:
        return False
    hs = _path_of(hyp.get("surface"))
    if not hs or hs == "/":             # require a SPECIFIC endpoint on the hypothesis (a hunch stays open)
        return False
    fs = _path_of(fact.get("surface") or fact.get("location"))
    if not fs:
        return False                    # the fact does not name an endpoint → cannot precisely match
    # the fact's endpoint is EXACTLY the hypothesis's, or strictly under it at a segment boundary
    return fs == hs or fs.startswith(hs + "/")


def reconcile_confirmed(chat_id: str, facts: list, *, now: float | None = None) -> list[dict]:
    """Close every OPEN hypothesis that a confirmed FACT now settles, precisely (``_matches``). ``facts``
    is a list of the engine's oracle-confirmed findings, each ``{bug_class, surface|location, ref}``.
    Returns the closing records. Conservative + auditable: only a precise bug_class+surface match closes,
    and every close carries the finding's ref. Total: [] on any problem."""
    if not isinstance(facts, list) or not facts:
        return []
    closed: list[dict] = []
    try:
        for hyp in list_for(chat_id):
            if hyp.get("status") != _OPEN:
                continue
            for fact in facts:
                if not isinstance(fact, dict):
                    continue
                if _matches(hyp, fact):
                    ref = str(fact.get("ref") or fact.get("run_id") or fact.get("evidence_ref") or "")
                    rec = close(chat_id, str(hyp.get("id")), status=_CONFIRMED,
                                finding_ref=ref, note="auto-closed: an oracle confirmed a matching finding",
                                now=now)
                    if rec:
                        closed.append(rec)
                    break
    except Exception:  # noqa: BLE001 — reconciliation is best-effort; a hiccup never breaks a chat turn
        return closed
    return closed
