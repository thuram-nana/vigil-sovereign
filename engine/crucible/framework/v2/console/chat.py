"""
console.chat — the operator chatbot: a natural-language front door to the SAME gated assessment launcher,
with an append-only per-session transcript saved on the operator's machine
(``<VIGIL_LIVE_DIR|.vigil-live>/chats/<id>.jsonl``).

Design invariants (why this is safe):
  * The chat only ADVISES which gated run to start; every launch goes through ``actions.launch_assessment``,
    which enforces scope (charter-signed, never an argument), refuses a remote engage without a signed
    charter, and keeps every target-touching/destructive step behind the WARDEN approve-then-run gate. The
    chat can therefore neither relax scope nor bypass a gate.
  * The chat mints NO facts. A finding is a FACT only when a deterministic oracle fires inside the engine;
    the launched run mirrors onto the blackboard exactly as a hand-run engagement does.
  * Offense-side only. This module imports nothing sovereign; the transcript holds the operator's own text
    and the run pointers, never a secret value.
  * Persist-by-default (the Phase-D ephemeral toggle will skip the writes; A4a always persists).
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from . import actions

# a target URL embedded in free-text ("scan http://127.0.0.1:8080 for me") — a convenience so the operator
# can just talk; an explicit `target` in the request always wins over this.
_URL_RE = re.compile(r"https?://[^\s'\"<>]+")
_MAX_MSG = 4000
_MAX_SESSIONS = 200
_MAX_ID = 128            # a chat id is a single filename component; cap length so an over-long id is a clean
#                         refusal (ValueError → 404), never an OSError("File name too long") → 500 path leak.


def _live_dir() -> Path:
    """The operator-machine base for chat transcripts. `vigil up` sets VIGIL_LIVE_DIR to the same
    ``.vigil-live`` the rest of the live plane uses; default keeps the console usable standalone."""
    return Path(os.environ.get("VIGIL_LIVE_DIR") or ".vigil-live")


def _safe_chat_id(raw: str) -> str:
    """The console's path-component guard (no separators / .. / leading dot — no traversal) PLUS a length
    cap, so a character-safe but over-long id is refused cleanly rather than raising OSError deep in a write
    (which the server would map to a 500 that discloses the chats-dir path). Raises ValueError → server 404."""
    rid = actions._safe_run_id(raw)
    if len(rid) > _MAX_ID:
        raise ValueError(f"chat id too long (> {_MAX_ID})")
    return rid


def _chats_dir() -> Path:
    d = _live_dir() / "chats"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)              # operator free-text engagement context is not world-readable
    except OSError:
        pass
    return d


def _chat_path(chat_id: str) -> Path:
    return _chats_dir() / (_safe_chat_id(chat_id) + ".jsonl")


def _append(chat_id: str, rec: dict) -> None:
    line = json.dumps({"ts": time.time(), **rec}, ensure_ascii=False)
    p = _chat_path(chat_id)
    # create 0600 up-front (no world-readable window); append-only, one JSON object per line.
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def read_session(chat_id: str) -> list[dict]:
    """Replay one transcript in order. A torn/blank last line (crash mid-write) is skipped, never fatal."""
    p = _chat_path(chat_id)
    if not p.exists():
        return []
    out: list[dict] = []
    for ln in p.read_text(encoding="utf-8").split("\n"):
        ln = ln.strip()
        if not ln:
            continue
        try:
            out.append(json.loads(ln))
        except (json.JSONDecodeError, ValueError):
            continue
    return out


def list_sessions() -> dict:
    """The saved chats (newest first): id, title (first user line), turn count, updated ts. Never a value."""
    d = _chats_dir()
    rows = []
    for f in sorted(d.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)[:_MAX_SESSIONS]:
        turns = read_session(f.stem)
        title = ""
        for t in turns:
            if t.get("role") == "user" and t.get("text"):
                title = str(t["text"])[:80]
                break
        rows.append({"id": f.stem, "title": title or "(empty)", "turns": len(turns),
                     "updated": f.stat().st_mtime})
    return {"sessions": rows}


def get_session(chat_id: str) -> dict:
    """One transcript for the UI (fail-closed: an unsafe id raises ValueError → the server maps it to 404)."""
    return {"chat_id": _safe_chat_id(chat_id), "messages": read_session(chat_id)}


def _infer_mode(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return "url"
    if target and Path(target).expanduser().exists():
        return "codebase"
    return ""


def chat_send(body: dict) -> dict:
    """One chat turn. Persists the user message, then — if a target + mode resolve — launches the SAME
    gated assessment a hand-run engagement uses and persists the assistant reply with the run pointer.
    Returns {chat_id, status, reply, run_id?, slug?, stream}. Never raises a traceback into the server
    for an operator-input problem (a clean status is returned); an unsafe chat id raises ValueError which
    the server maps to a 404."""
    chat_id = _safe_chat_id(str(body.get("chat_id") or "").strip() or actions._new_run_id())
    message = str(body.get("message") or "").strip()[:_MAX_MSG]
    if not message:
        return {"chat_id": chat_id, "status": "error", "reply": "Say what you'd like me to test.",
                "error": "empty message", "stream": "none"}

    mode = str(body.get("mode") or "").strip().lower()
    target = str(body.get("target") or "").strip()
    if not target:                                        # NL convenience: pull a URL out of the message
        m = _URL_RE.search(message)
        if m:
            target = m.group(0)
    if not mode:
        mode = _infer_mode(target)
    model = str(body.get("model") or "").strip()[:64]
    effort = str(body.get("effort") or "").strip().lower()

    _append(chat_id, {"role": "user", "text": message, "target": target, "mode": mode,
                      "model": model, "effort": effort})

    if not target or mode not in actions._MODES:
        reply = ("Tell me what to test and give me a target — a URL like http://127.0.0.1:8080 for a "
                 "web / API / infra target, or a path to a codebase. I'll launch a gated, oracle-confirmed "
                 "run and stream it here; any target-touching step waits for your approval.")
        _append(chat_id, {"role": "assistant", "text": reply, "kind": "need_target"})
        return {"chat_id": chat_id, "status": "need_target", "reply": reply, "stream": "none"}

    launch = actions.launch_assessment({
        "mode": mode, "target": target, "objective": message,
        "scan_mode": str(body.get("scan_mode", "standard")),
        "slug": str(body.get("slug", "")), "model": model,
        "tools": [str(t) for t in (body.get("tools") or [])],
    })
    if launch.get("error"):
        reply = "I couldn't start that: " + launch["error"]
        _append(chat_id, {"role": "assistant", "text": reply, "kind": "refused", "error": launch["error"]})
        return {"chat_id": chat_id, "status": "refused", "reply": reply, "error": launch["error"],
                "stream": "none"}

    reply = (f"Started a {mode} run against {target} (engagement '{launch['slug']}'). Watch it live below — "
             f"findings are oracle-confirmed and any target-touching step waits for your approval.")
    _append(chat_id, {"role": "assistant", "text": reply, "kind": "launched",
                      "run_id": launch.get("run_id"), "slug": launch.get("slug"),
                      "stream": launch.get("stream")})
    return {"chat_id": chat_id, "status": "running", "reply": reply,
            "run_id": launch.get("run_id"), "slug": launch.get("slug"), "stream": launch.get("stream")}
