"""Corpus discovery over ~/.claude/projects (allowlist + ephemeral filter)."""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

from ..config import CLAUDE_PROJECTS, EPHEMERAL_PREFIXES, PROJECT_ALLOWLIST


def is_real_project(name: str) -> bool:
    if name.startswith(EPHEMERAL_PREFIXES):
        return False
    if PROJECT_ALLOWLIST and PROJECT_ALLOWLIST != [""]:
        return name in PROJECT_ALLOWLIST
    return True


def real_projects() -> Iterator[Path]:
    """Allowlisted, non-ephemeral project dirs under ~/.claude/projects."""
    if not CLAUDE_PROJECTS.exists():
        return
    for d in sorted(CLAUDE_PROJECTS.iterdir()):
        if d.is_dir() and is_real_project(d.name):
            yield d


def session_files(project_dir: Path) -> list[Path]:
    """Top-level <sessionId>.jsonl session transcripts, newest first (by mtime)."""
    files = [p for p in project_dir.glob("*.jsonl") if p.is_file()]
    return sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)
