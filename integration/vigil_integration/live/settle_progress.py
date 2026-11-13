"""settle_progress — the recorded settles the settle drain has NOT been able to finish, and since when (E3bc).

With ``VIGIL_SETTLE_SPINE_RECORD`` on, every settle-drain pass finishes each recorded settle of a lease on the seam
that a crash or an error interrupted. A settle it cannot finish (its lock busy, a ledger or the seam not writable, a
recorded decision it refuses to move) holds the customer's relaunch on that host — whether or not the settle got as
far as its seam settlement marker. So the drain records, beside its completion spool, which leases it left unfinished
and since when, and whether its finish pass itself could not run:

  ``<spool>/.settle-unfinished.json``  ``{"schema": ..., "leases": [{"slug", "nonce", "first_seen"}, ...],
                                         "pass_error": {"since", "error"} | null}``

written atomically (0600), at most :data:`MAX_LEASES` leases (the longest-held kept) and :data:`MAX_BYTES`. A lease
leaves it on the first pass that does not leave it unfinished; the file is removed when nothing is left. Past
:data:`UNFINISHED_SETTLE_GRACE_S` the drain prints an ALARM and exits non-zero (its unit stays FAILED), and
``vigil doctor`` raises a HARD issue from the same file — so such a hold is never silent.

Operational state, never a money input: it decides no settle. Stdlib only — read by ``vigil doctor`` (which never
imports ``sigil``) and written by the sovereign drain (FATAL-2: safe to import on either plane).
"""
from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Iterable, Optional

__all__ = ["STATE_NAME", "UNFINISHED_SETTLE_GRACE_S", "state_path", "read_state", "update_state", "overdue"]

#: The state file's name in the completion spool directory.
STATE_NAME = ".settle-unfinished.json"
_SCHEMA = "vigil-settle-unfinished-v1"
#: How long a recorded settle may stay unfinished (or the finish pass keep failing) before the settle drain ALARMs and
#: ``vigil doctor`` reports it as a hard issue. A settle retires its lease within moments and the drain (every ~60 s)
#: finishes an interrupted one, so a lasting one is an issue; a settle in progress is not.
UNFINISHED_SETTLE_GRACE_S = 600.0
#: The most leases the file keeps (the longest-held first), and its size bound.
MAX_LEASES = 512
MAX_BYTES = 256 * 1024
_MAX_ID = 128


def state_path(spool_dir: Any) -> Path:
    return Path(spool_dir) / STATE_NAME


def _empty() -> dict:
    return {"schema": _SCHEMA, "leases": [], "pass_error": None}


def _ident(v: Any) -> Optional[str]:
    return v if isinstance(v, str) and 0 < len(v) <= _MAX_ID and v.isprintable() else None


def _num(v: Any) -> Optional[float]:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v != v or v in (float("inf"), float("-inf")):
        return None
    return float(v)


def read_state(spool_dir: Any) -> dict:
    """The state in ``spool_dir`` (an empty one when there is none). Raises ``ValueError`` when the file exists but
    is not a bounded regular file holding exactly what :func:`update_state` writes (the caller decides: the drain
    starts afresh, ``vigil doctor`` reports it)."""
    path = state_path(spool_dir)
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return _empty()
    except OSError as exc:
        raise ValueError(f"unreadable: {type(exc).__name__}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_BYTES:
            raise ValueError("not a bounded regular file")
        raw = os.read(fd, MAX_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"unreadable: {type(exc).__name__}") from exc
    finally:
        os.close(fd)
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("not JSON") from exc
    if not isinstance(obj, dict) or obj.get("schema") != _SCHEMA or not isinstance(obj.get("leases"), list):
        raise ValueError("unexpected schema")
    leases = []
    for e in obj["leases"][:MAX_LEASES]:
        slug, nonce, first = (_ident(e.get("slug")), _ident(e.get("nonce")), _num(e.get("first_seen"))) \
            if isinstance(e, dict) else (None, None, None)
        if slug is None or nonce is None or first is None:
            raise ValueError("malformed lease entry")
        leases.append({"slug": slug, "nonce": nonce, "first_seen": first})
    pe = obj.get("pass_error")
    if pe is not None:
        since = _num(pe.get("since")) if isinstance(pe, dict) else None
        if since is None:
            raise ValueError("malformed pass_error")
        pe = {"since": since, "error": str(pe.get("error") or "")[:_MAX_ID]}
    return {"schema": _SCHEMA, "leases": leases, "pass_error": pe}


def update_state(spool_dir: Any, *, now: float, unfinished: "Optional[Iterable[tuple[str, str]]]",
                 error: Optional[str] = None) -> dict:
    """Record one finish pass and return the new state. ``unfinished`` is every ``(slug, nonce)`` the pass left
    unfinished — each keeps its ``first_seen`` from the previous state (else ``now``) and every other lease is dropped;
    ``None`` means the pass itself could not run (``error``): the leases are kept as they were and ``pass_error``
    keeps its ``since``. A pass that ran clears ``pass_error``. With nothing to record the file is removed. A previous
    state that cannot be read counts as empty. Raises ``OSError`` when the file cannot be written or removed (the
    caller then cannot tell how long anything has been held, so it alarms)."""
    try:
        prev = read_state(spool_dir)
    except ValueError:
        prev = _empty()
    path = state_path(spool_dir)
    if unfinished is None:
        leases = prev["leases"]
        since = prev["pass_error"]["since"] if prev["pass_error"] else float(now)
        pass_error: Optional[dict] = {"since": since, "error": str(error or "")[:_MAX_ID]}
    else:
        seen = {(e["slug"], e["nonce"]): e["first_seen"] for e in prev["leases"]}
        leases, done = [], set()
        for slug, nonce in unfinished:
            key = (str(slug), str(nonce))
            if key in done or _ident(key[0]) is None or _ident(key[1]) is None:
                continue
            done.add(key)
            leases.append({"slug": key[0], "nonce": key[1], "first_seen": float(seen.get(key, now))})
        leases = sorted(leases, key=lambda e: (e["first_seen"], e["slug"], e["nonce"]))[:MAX_LEASES]
        pass_error = None
    state = {"schema": _SCHEMA, "leases": leases, "pass_error": pass_error}
    if not leases and pass_error is None:
        try:
            os.unlink(str(path))
        except FileNotFoundError:
            pass
        return state
    data = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".settle-unfinished-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return state


def overdue(state: dict, *, now: float, grace: float = UNFINISHED_SETTLE_GRACE_S) -> "tuple[list[tuple[str, str]], Optional[str]]":
    """``(leases, pass_error)``: every ``(slug, nonce)`` held unfinished for at least ``grace`` seconds, and the
    finish pass's error when it has kept failing for at least ``grace`` seconds (else None)."""
    leases = [(e["slug"], e["nonce"]) for e in state.get("leases") or [] if now - e["first_seen"] >= grace]
    pe = state.get("pass_error")
    err = (pe.get("error") or "error") if pe and now - pe["since"] >= grace else None
    return leases, err
