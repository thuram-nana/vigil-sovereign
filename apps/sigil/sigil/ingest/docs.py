"""Ingest the owner's curated `memory/*.md` program notes as chunked document events.

These are hand-written, high-signal summaries of decisions/programs — ideal seed material.
Chunked (~1200 chars) so the whole doc is semantically searchable, not just its head.
"""
from __future__ import annotations

import re

from ..config import CLAUDE_PROJECTS
from ..spine.store import SpineStore

_FRONTMATTER = re.compile(r"^\s*---\n.*?\n---\n", re.S)


def _strip_frontmatter(text: str) -> str:
    return _FRONTMATTER.sub("", text, count=1).strip()


def _chunks(text: str, size: int = 1200, overlap: int = 150) -> list[str]:
    text = text.strip()
    if len(text) <= size:
        return [text] if text else []
    out, i = [], 0
    while i < len(text):
        out.append(text[i:i + size])
        i += size - overlap
    return out


def ingest_docs(store: SpineStore, project: str = "-home-kali-Pictures-PENTEST-main") -> int:
    d = CLAUDE_PROJECTS / project / "memory"
    if not d.exists():
        return 0
    added = 0
    for md in sorted(d.glob("*.md")):
        body = _strip_frontmatter(md.read_text(encoding="utf-8", errors="replace"))
        for j, chunk in enumerate(_chunks(body)):
            store.append(kind="document", source="doc", actor=md.stem,
                         payload={"text": chunk, "title": md.stem, "chunk": j,
                                  "path": str(md), "project": project})
            added += 1
    return added
