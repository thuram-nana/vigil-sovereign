"""Kùzu DDL for the deterministic structural layer of the personal ontology (SIGIL §6.2).

Only the entities and edges that are DETERMINISTICALLY derivable from spine records live
here — no extraction, no inference. Every node carries provenance: a spine `anchor_seq` +
`anchor_hash` (the record that minted it) so a graph answer resolves back to tamper-evident
memory. The semantic node/edge kinds (Person, Org, Decision, Commitment, depends_on,
decided_in, contradicts, …) are added by the consolidation pass and are intentionally
absent until a grounded producer exists for them.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

# Node tables. Each structural node stores an anchor into the spine for provenance.
NODE_DDL = [
    # a project / repo the owner works in (names normalized: transcript-slug ⇄ repo basename)
    """CREATE NODE TABLE Project(
        name STRING, sessions INT64, commits INT64, documents INT64, messages INT64,
        PRIMARY KEY(name))""",
    # one Claude session (deduped by session_id; title from its latest ai-title record)
    """CREATE NODE TABLE Session(
        id STRING, title STRING, project STRING, messages INT64,
        first_seq INT64, last_seq INT64, first_ts STRING, last_ts STRING,
        anchor_seq INT64, anchor_hash STRING, PRIMARY KEY(id))""",
    # a curated memory document (deduped by path; chunks counted)
    """CREATE NODE TABLE Document(
        path STRING, title STRING, project STRING, chunks INT64,
        anchor_seq INT64, anchor_hash STRING, PRIMARY KEY(path))""",
    # a git commit
    """CREATE NODE TABLE Commit(
        hash STRING, repo STRING, subject STRING, author STRING, date STRING,
        anchor_seq INT64, anchor_hash STRING, PRIMARY KEY(hash))""",
]

# Relationship tables — containment only (the deterministic backbone).
REL_DDL = [
    "CREATE REL TABLE IN_PROJECT_S(FROM Session TO Project)",
    "CREATE REL TABLE IN_PROJECT_D(FROM Document TO Project)",
    "CREATE REL TABLE IN_PROJECT_C(FROM Commit TO Project)",
]

DDL = NODE_DDL + REL_DDL


@lru_cache(maxsize=1)
def _known_project_map() -> dict[str, str]:
    """Map both the transcript slug (abs-path with '/'→'-') AND the plain repo basename of
    every known repo onto the repo basename. Slugs are ambiguous under naive dash-splitting
    (a dir named 'PENTEST-main' collides with a path separator), so we disambiguate by
    reconstructing the slug from the KNOWN repo paths instead of guessing."""
    from ..ingest.git import DEFAULT_REPOS
    m: dict[str, str] = {}
    for p in DEFAULT_REPOS:
        name = Path(p).name
        m[p.replace("/", "-")] = name   # transcript slug ('-home-kali-…-PENTEST-main') → basename
        m[name] = name                  # repo basename passes through
    return m


def normalize_project(raw: str) -> str:
    """Collapse a transcript project slug and a git repo name that denote the SAME project
    onto one canonical name (its basename)."""
    if not raw:
        return "unknown"
    s = raw.strip()
    known = _known_project_map()
    if s in known:
        return known[s]
    return s.rstrip("/").split("/")[-1] if "/" in s else s  # best-effort for unknown inputs
