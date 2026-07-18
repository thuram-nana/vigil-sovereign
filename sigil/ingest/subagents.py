"""Subagent-transcript ingestion (SIGIL §2 `subagents.py`).

A Claude Code session spawns subagents whose full transcripts live under
`<session>/subagents/agent-<id>.jsonl`, each with a sibling `agent-<id>.meta.json`
(`{agentType, description, toolUseId, spawnDepth}`). These hold the DETAIL of delegated
work (domain builds, reviews, research) that never appears in the parent thread — so
without them, memory can't recall what a subagent actually did.

Each subagent is ingested as its OWN session: its events are re-keyed under the agentId
(via `extra.session_id`), and a `session` header record titled by the meta `description`
makes it a first-class, recallable thread (and a titled Session node in the graph). The
spawning `toolUseId` and parent session are recorded in every event's payload for linkage.
Incremental via the shared per-file cursor (keyed by the transcript path), exactly like the
main transcript.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from ..spine.store import SpineStore
from .transcript import ingest_transcript

_SUBAGENT_SOURCE = "claude-code-subagent"


def _pairs(subdir: Path) -> Iterator[tuple[Path, dict]]:
    """Yield (transcript_path, meta) for each subagent under a session's subagents/ dir."""
    if not subdir.is_dir():
        return
    for jsonl in sorted(subdir.glob("agent-*.jsonl")):
        meta_path = jsonl.with_suffix(".meta.json")
        meta = {}
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                meta = {}
        yield jsonl, meta


def ingest_subagents(store: SpineStore, cursor: dict, project: str, session_id: str,
                     session_dir: Path, *, max_events: int | None = None) -> int:
    """Ingest all subagent transcripts under `session_dir`/subagents/. Returns events added.
    Mutates `cursor` in place (caller saves) — each transcript keyed by its path, like main."""
    added = 0
    for jsonl, meta in _pairs(session_dir / "subagents"):
        agent_id = jsonl.stem  # "agent-a049e70b32cc11c73"
        key = str(jsonl)
        skip = cursor.get(key, 0)
        extra = {
            "session_id": agent_id,              # re-key: this subagent is its own thread
            "subagent": True,
            "agent_type": meta.get("agentType"),
            "description": meta.get("description"),
            "parent_session": session_id,
            "spawn_tool_use_id": meta.get("toolUseId"),
        }
        # session header (title = description) — emitted once, on first ingest of this agent.
        if skip == 0 and meta.get("description"):
            store.append(kind="session", source=_SUBAGENT_SOURCE, actor="system",
                         payload={"session_id": agent_id, "project": project,
                                  "text": f"[subagent · {meta.get('agentType', '?')}] {meta['description']}",
                                  "subagent": True, "agent_type": meta.get("agentType"),
                                  "parent_session": session_id,
                                  "spawn_tool_use_id": meta.get("toolUseId")})
            added += 1
        events, seen = ingest_transcript(store, jsonl, project, skip_records=skip,
                                         max_events=max_events, source=_SUBAGENT_SOURCE, extra=extra)
        cursor[key] = seen
        added += events
    return added
