"""Offense-local operator-instruction queue — the operator's mid-run, natural-language guidance for a live
engagement ("also check the admin API", "focus on auth").

SAFETY MODEL (why this needs no owner signature of its own): an instruction is **advisory** — it is folded
into the think step's UNTRUSTED context exactly like the initial ``objective``. It fires nothing. Every
action the engine then proposes STILL passes ``authorize_edge`` (the WARDEN gate + the owner approve-then-run
leg) and every claimed exploit STILL needs the deterministic oracle. So an instruction can neither run a
tool, relax scope, nor mint a fact — it is no more privileged than the objective the run already carried.

Storage: append-only JSONL at ``<VIGIL_LIVE_DIR|.vigil-live>/instructions/<slug>.jsonl`` (one object per
line) with a sibling ``<slug>.cursor`` recording how many lines a consumer has drained, so the OODA loop
picks up only NEW instructions each iteration and a resumed run does not replay old ones. Offense-local:
the console (chat) enqueues and the offense engine drains — no boundary crossing, no secret.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Optional

# a slug is a single path component (mirrors the console's run-id guard) — no separator / .. / leading dot,
# so it can never traverse out of the instructions dir.
_SAFE_SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_MAX_SLUG = 128
_MAX_TEXT = 4000
_MAX_PENDING = 200          # bound a single drain so a flood can't blow up a think prompt


def _safe_slug(slug: str) -> str:
    s = str(slug or "")
    if ".." in s or len(s) > _MAX_SLUG or not _SAFE_SLUG.match(s):
        raise ValueError(f"unsafe engagement slug: {slug!r}")
    return s


def _base(base: Optional[str] = None) -> Path:
    # explicit `base` (the engagement's --base-dir) wins over the env, so an enqueue and the running
    # engagement always agree on WHERE the queue lives; default keeps standalone use working.
    d = Path(base or os.environ.get("VIGIL_LIVE_DIR") or ".vigil-live") / "instructions"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)          # operator free-text is not world-readable
    except OSError:
        pass
    return d


def _path(slug: str, base: Optional[str] = None) -> Path:
    return _base(base) / (_safe_slug(slug) + ".jsonl")


def _cursor_path(slug: str, base: Optional[str] = None) -> Path:
    return _base(base) / (_safe_slug(slug) + ".cursor")


def enqueue(slug: str, text: str, *, base: Optional[str] = None) -> dict:
    """Append one operator instruction for ``slug``. Text is trimmed + length-bounded; JSON encoding makes
    a newline/control char inert (it can never break the JSONL framing). Returns {ok, slug, seq} or raises
    ValueError on an unsafe slug / empty text (fail-closed — the caller surfaces it honestly)."""
    slug = _safe_slug(slug)
    text = str(text or "").strip()[:_MAX_TEXT]
    if not text:
        raise ValueError("empty instruction")
    p = _path(slug, base)
    seq = sum(1 for _ in p.read_text(encoding="utf-8").split("\n") if _.strip()) if p.exists() else 0
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"seq": seq, "ts": time.time(), "text": text}, ensure_ascii=False) + "\n")
    return {"ok": True, "slug": slug, "seq": seq}


def _read_all(slug: str, base: Optional[str] = None) -> list[dict]:
    p = _path(slug, base)
    if not p.exists():
        return []
    out: list[dict] = []
    for ln in p.read_text(encoding="utf-8").split("\n"):
        ln = ln.strip()
        if not ln:
            continue
        try:
            rec = json.loads(ln)
        except (json.JSONDecodeError, ValueError):
            continue                 # a torn last line (crash mid-write) is skipped, never fatal
        if isinstance(rec, dict) and rec.get("text"):
            out.append(rec)
    return out


def pending(slug: str, *, base: Optional[str] = None) -> list[str]:
    """The instructions for ``slug`` NOT yet drained (peek — does NOT advance the cursor)."""
    cur = _cursor(slug, base)
    return [str(r["text"]) for r in _read_all(slug, base)[cur:cur + _MAX_PENDING]]


def _cursor(slug: str, base: Optional[str] = None) -> int:
    cp = _cursor_path(slug, base)
    try:
        return max(0, int(cp.read_text(encoding="utf-8").strip() or "0"))
    except (OSError, ValueError):
        return 0


def drain(slug: str, *, base: Optional[str] = None) -> list[str]:
    """Return the NEW instructions for ``slug`` (since the last drain) and advance the cursor. A single
    SEQUENTIAL drainer (the one OODA loop, incl. a resumed run in a later process) consumes each exactly
    once and never replays. The cursor is not file-locked, so two CONCURRENT drainers could re-deliver an
    instruction — benign here because an instruction is advisory + fully gated (a re-delivery only re-adds
    the same text to the think context; it fires nothing). Never raises for a missing file / unsafe slug
    (returns [])."""
    try:
        slug = _safe_slug(slug)
    except ValueError:
        return []
    all_recs = _read_all(slug, base)
    cur = _cursor(slug, base)
    fresh = all_recs[cur:cur + _MAX_PENDING]
    if fresh:
        new_cursor = cur + len(fresh)
        fd = os.open(str(_cursor_path(slug, base)), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(str(new_cursor))
    return [str(r["text"]) for r in fresh]
