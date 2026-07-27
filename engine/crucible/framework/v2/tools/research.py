"""
tools.research — per-tool deep-research pointers (Phase B3).

Tool-consciousness includes being able to RESEARCH a tool. For an arsenal tool the researched knowledge
already lives in its Strix ``skills/tooling/<name>.md`` playbook; this surfaces the canonical, offline
pointers from it — the official-docs URLs and the exact ``web_search`` query the agent uses when uncertain —
so the operator (and the reasoning loop) can look a tool up before acting.

Advisory + offline + boundary-clean: it only READS the vendored playbook (no network, no egress, no
sovereign import). A LIVE lookup (Strix ``web_search`` over the returned query, or the sovereign corpus)
happens inside a gated run, not here. Name is path-guarded (it maps to a filename), fail-closed to empty.
"""
from __future__ import annotations

import re
from pathlib import Path

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_URL = re.compile(r"https?://[^\s)>\]]+")


def _tooling_dir() -> Path | None:
    """The Strix tooling skill-doc directory, via the installed package. Lazy + fail-open (no Strix → no
    docs, honestly) so the framework never hard-depends on Strix."""
    try:
        import strix.skills as sk
    except Exception:  # noqa: BLE001
        return None
    try:
        d = Path(sk.__file__).resolve().parent / "tooling"
        return d if d.is_dir() else None
    except Exception:  # noqa: BLE001
        return None


def _default_query(name: str, purpose: str) -> str:
    tail = f" — {purpose}" if purpose else ""
    return f"{name} CLI usage: official docs, high-signal flags, and safe automation defaults{tail}"


def research_refs(name: str, *, purpose: str = "") -> dict:
    """The offline research pointers for a tool: its playbook's official-docs URLs + the canonical
    web_search query. Returns {name, has_doc, docs, query, summary}. Fail-closed: an unsafe/unknown name or
    an absent playbook yields has_doc=False with a generated query — never raises, never reads outside the
    tooling dir."""
    name = str(name or "").strip().lower()
    generated = _default_query(name, purpose)
    # len>200 refused BEFORE any filesystem touch: "<name>.md" must stay under NAME_MAX (255) or os.stat
    # would raise ENAMETOOLONG — this keeps the "never raises" contract true (red-pen BLOCK-1).
    if not name or ".." in name or len(name) > 200 or not _SAFE_NAME.match(name):
        return {"name": name, "has_doc": False, "docs": [], "query": generated,
                "summary": "", "note": "no CLI-usage playbook for this tool"}
    d = _tooling_dir()
    if d is None:
        return {"name": name, "has_doc": False, "docs": [], "query": generated,
                "summary": "", "note": "no CLI-usage playbook — research via the query below"}
    doc = d / f"{name}.md"
    # ALL filesystem access (stat + resolve + read) is inside the guard, confined to the tooling dir
    # (defence in depth against a resolved symlink escaping); any OSError → honest empty, never a raise.
    try:
        if not doc.is_file() or d not in doc.resolve().parents:
            return {"name": name, "has_doc": False, "docs": [], "query": generated,
                    "summary": "", "note": "no CLI-usage playbook — research via the query below"}
        text = doc.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"name": name, "has_doc": False, "docs": [], "query": generated, "summary": ""}

    lines = text.split("\n")
    summary = ""
    for ln in lines:
        m = re.match(r"\s*description:\s*(.+)$", ln)   # frontmatter one-liner
        if m:
            summary = m.group(1).strip().strip('"').strip("'")[:300]
            break

    docs: list[str] = []
    query = generated
    section = ""
    for ln in lines:
        low = ln.strip().lower()
        if low.startswith("official docs"):
            section = "docs"
            continue
        if low.startswith("if uncertain, query web_search with"):
            section = "query"
            continue
        if section == "docs":
            urls = _URL.findall(ln)
            if urls:
                docs.extend(urls)
            elif ln.strip() and not ln.strip().startswith("-"):
                section = ""          # left the docs block
        elif section == "query":
            q = ln.strip().strip("`").strip()
            if q:
                query = q[:300]
                section = ""

    # de-dupe docs, keep order, bound the count
    seen: set = set()
    docs = [u for u in docs if not (u in seen or seen.add(u))][:12]
    return {"name": name, "has_doc": True, "docs": docs, "query": query, "summary": summary}
