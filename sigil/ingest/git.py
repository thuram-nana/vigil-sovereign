"""Git commit-history ingestion (SIGIL §3 / §6.2 git source).

Backfills commit messages (subject + body) from allowlisted repos as `commit` spine
events. Excludes the huge/binary repos (RECOR 257 GB, vendored flutter) per the disk
allowlist doctrine. A `post-commit`/`post-merge` hook (0b) keeps it live going forward.

**Incremental by construction.** Each repo's last-ingested commit hash is persisted in the
shared ingest cursor under a `git:<repo>` key, so re-running (which the hook does on *every*
commit) appends only new commits — never the whole history again. Commits are appended
oldest-first so the spine's seq order tracks chronology.
"""
from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from . import cursor as cur
from ..config import INGEST_REPOS as DEFAULT_REPOS  # env SIGIL_INGEST_REPOS → host-relative default
from ..spine.store import SpineStore

_log = logging.getLogger(__name__)

_SEP_FIELD = "\x1f"
_SEP_REC = "\x1e"
_FMT = _SEP_FIELD.join(["%H", "%an", "%aI", "%s", "%b"]) + _SEP_REC


def git_log(repo: Path, *, since: str | None = None, max_commits: int = 5000) -> list[dict]:
    """Newest-first list of commits. With `since`, only commits after that hash (`since..HEAD`)."""
    if not (repo / ".git").exists():
        return []
    # range (if any) must come immediately AFTER `log`, before the pretty/limit flags.
    rev = [f"{since}..HEAD"] if since else []
    cmd = ["git", "-C", str(repo), "log", *rev, f"--pretty=format:{_FMT}", "-n", str(max_commits)]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout
    except (subprocess.SubprocessError, OSError):
        return []
    commits = []
    for rec in out.split(_SEP_REC):
        rec = rec.strip()
        if not rec:
            continue
        parts = rec.split(_SEP_FIELD)
        if len(parts) >= 4:
            commits.append({"hash": parts[0], "author": parts[1], "date": parts[2],
                            "subject": parts[3], "body": parts[4] if len(parts) > 4 else ""})
    return commits


def ingest_git(store: SpineStore, repos: list[str] | None = None, *,
               cursor: dict | None = None, max_commits: int = 5000) -> int:
    # when the caller owns the cursor (cmd_ingest), mutate its dict in place and let it save —
    # saving our own copy here would be clobbered by the caller's later save. Standalone → own it.
    own = cursor is None
    cursor = cur.load() if own else cursor
    added = 0
    for repo in (repos or DEFAULT_REPOS):
        p = Path(repo)
        key = f"git:{p.name}"
        since = cursor.get(key) or None
        commits = git_log(p, since=since, max_commits=max_commits)  # newest-first
        if not commits:
            continue
        newest = commits[0]["hash"]
        for c in reversed(commits):  # append oldest-first → spine seq tracks chronology
            text = c["subject"] + (("\n\n" + c["body"]) if c["body"].strip() else "")
            store.append(kind="commit", source="git", actor=c["author"],
                         payload={"text": text[:4000], "hash": c["hash"], "repo": p.name,
                                  "subject": c["subject"]}, ts=c["date"])
            added += 1
        cursor[key] = newest
        _log.info("git ingest: %d commit(s) from %s", len(commits), p.name)
    if own:
        cur.save(cursor)
    return added
