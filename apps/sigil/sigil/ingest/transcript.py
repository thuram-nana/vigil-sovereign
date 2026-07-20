"""Parse a Claude Code JSONL transcript → spine events (SIGIL §3).

Streams line-by-line (never loads the 110 MB session whole). Walks the uuid/parentUuid
thread for `parent_id`. Faithfully splits an assistant record's typed content blocks
(text/thinking/tool_use/tool_result) into distinct spine events. Filters `isMeta` noise.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from ..spine.store import SpineStore


def _text_of(content: Any) -> str:
    """Flatten a tool_result content (string | list of blocks) to text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for b in content:
            if isinstance(b, dict):
                parts.append(b.get("text") or b.get("content") or "")
            else:
                parts.append(str(b))
        return "\n".join(p for p in parts if p)
    return "" if content is None else str(content)


def _events_for(rec: dict[str, Any], project: str) -> Iterator[tuple[str, str, dict]]:
    """Yield (kind, actor, payload) for one transcript record."""
    t = rec.get("type")
    if t == "ai-title":
        title = rec.get("aiTitle") or rec.get("title")
        if title:
            yield ("session", "system", {"session_id": rec.get("sessionId"), "project": project, "text": title})
        return
    if t not in ("user", "assistant"):
        return
    msg = rec.get("message") or {}
    role = msg.get("role") or t
    base = {
        "session_id": rec.get("sessionId"), "project": project, "role": role,
        "model": msg.get("model"), "cwd": rec.get("cwd"), "git_branch": rec.get("gitBranch"),
        "uuid": rec.get("uuid"), "sidechain": bool(rec.get("isSidechain")),
    }
    content = msg.get("content")
    if isinstance(content, str):
        if content.strip():
            yield ("message", role, {**base, "text": content})
        return
    if isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                continue
            bt = block.get("type")
            if bt == "text" and block.get("text", "").strip():
                yield ("message", role, {**base, "text": block["text"]})
            elif bt == "thinking" and block.get("thinking", "").strip():
                yield ("message", role, {**base, "text": block["thinking"], "thinking": True})
            elif bt == "tool_use":
                yield ("tool_call", role, {**base, "tool": block.get("name"),
                                           "tool_input": block.get("input"), "tool_use_id": block.get("id")})
            elif bt == "tool_result":
                txt = _text_of(block.get("content"))
                if txt.strip():
                    yield ("tool_result", role, {**base, "tool_use_id": block.get("tool_use_id"), "text": txt[:20000]})


def ingest_transcript(store: SpineStore, path: Path, project: str, *,
                      skip_records: int = 0, max_events: int | None = None,
                      source: str = "claude-code", extra: dict[str, Any] | None = None) -> tuple[int, int]:
    """Ingest one transcript file, resuming after `skip_records` already-ingested records.
    Returns (events_appended, records_seen) — records_seen is the new cursor for this file.

    `source` tags provenance (subagent transcripts use "claude-code-subagent"); `extra` is
    merged into every event's payload AFTER the base fields, so it can override `session_id`
    (e.g. to key a subagent's events under its own agentId) or add spawn linkage."""
    uuid_to_seq: dict[str, int] = {}
    added = 0
    records_seen = 0  # every non-blank line counts (the durable cursor position)
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records_seen += 1
            if records_seen <= skip_records:
                continue  # already ingested in a prior run
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("isMeta"):
                continue
            parent_seq = uuid_to_seq.get(rec.get("parentUuid"))
            first_seq_of_record: int | None = None
            for kind, actor, payload in _events_for(rec, project):
                if extra:
                    payload = {**payload, **extra}  # extra wins (can re-key session_id)
                seq = store.append(kind=kind, source=source, actor=actor,
                                   payload=payload, parent_id=parent_seq, ts=rec.get("timestamp"))
                if first_seq_of_record is None:
                    first_seq_of_record = seq
                added += 1
            if first_seq_of_record is not None and rec.get("uuid"):
                uuid_to_seq[rec["uuid"]] = first_seq_of_record
            if max_events is not None and added >= max_events:
                break
    return added, records_seen
