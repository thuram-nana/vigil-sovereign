"""
knowledge_engine.retrieve — the graph-as-skillset READ (K3).

An advisory bundle for a query: the FIND/DETECT/PREVENT skills K3 wrote, plus the defensive CATALOG
operators that match, plus the doctrine. Everything is ADVISORY — a skill/operator is guidance, never a
fact; only a fired oracle confirms. Bounded like the integration SkillLoader: at most ``MAX_SKILLS``
(id-sorted) skills per query, and every file is path-traversal-guarded to ``skills_dir``.
"""

from __future__ import annotations

from pathlib import Path

MAX_SKILLS = 5   # mirror integration SkillLoader's hard cap on loadable skills per query


def _parse_frontmatter(text: str) -> tuple[dict, str]:
    """Split scalar ``---`` frontmatter (id/name/description/category) from the body. Stdlib-only, no PyYAML;
    an authority-claiming key would be parsed but is never surfaced (skills carry no tier)."""
    meta: dict = {}
    if not text.startswith("---"):
        return meta, text
    end = text.find("\n---", 3)
    if end == -1:
        return meta, text
    for line in text[3:end].splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            k = k.strip().lower()
            if k in ("id", "name", "description", "category"):
                meta[k] = v.strip()
    body = text[end + 4:].lstrip("\n")
    return meta, body


def _read_skills(skills_dir: Path, query: str, max_skills: int) -> list[dict]:
    root = Path(skills_dir).resolve()
    if not root.is_dir():
        return []
    q = (query or "").strip().lower()
    found: dict[str, dict] = {}
    for p in sorted(root.rglob("*.md"), key=lambda x: str(x)):
        try:
            if not p.resolve().is_relative_to(root):     # path-traversal guard (symlink escape)
                continue
        except (OSError, ValueError):
            continue
        meta, _ = _parse_frontmatter(p.read_text(encoding="utf-8"))
        sid = meta.get("id") or p.stem
        hay = " ".join([sid, meta.get("name", ""), meta.get("description", ""),
                        meta.get("category", ""), p.stem]).lower()
        if q and q not in hay:
            continue
        if sid not in found:                              # first wins (deterministic, id-sorted below)
            found[sid] = {"id": sid, "name": meta.get("name", ""),
                          "description": meta.get("description", ""),
                          "category": meta.get("category", ""), "file": str(p.relative_to(root))}
    return [found[k] for k in sorted(found)][:max(0, int(max_skills))]


def retrieve_skillset(query: str, *, skills_dir: Path, max_skills: int = MAX_SKILLS,
                      with_catalog: bool = True) -> dict:
    """Advisory skillset for ``query``: matching K3 skills (capped), matching CATALOG operators, doctrine.

    Read-only; never mints or promotes anything. ``query`` matches a skill by id/name/description/category
    and an operator by its ATT&CK/CWE/CAPEC technique_ref.
    """
    skills = _read_skills(skills_dir, query, max_skills)
    operators: list[dict] = []
    if with_catalog:
        try:
            from ..knowledge import catalog
            q = (query or "").strip()
            ops = catalog.by_technique(q) if q else []
            operators = [{"id": op.id, "name": op.name, "technique_ref": list(op.technique_ref)} for op in ops]
        except Exception:
            operators = []
    return {
        "query": query,
        "skills": skills,
        "operators": operators,
        "doctrine": ("Advisory skillset — skills and operators are guidance, never facts; the vulnerability "
                     "leads they cover stay intel-tier. Only a fired deterministic oracle mints a FACT."),
    }
