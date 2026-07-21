"""
kb.skills — the markdown SKILLS loader (VIGIL-FUSION F12).

A reimplementation of redamon's ``skill_loader`` (MIT): discover ``.md`` playbook skills under a root,
parse their YAML frontmatter, expose a small catalog, and load one skill's body by id — capped at
``MAX_SKILLS`` and guarded against path traversal with an ``is_relative_to`` check. The sovereign
inversions:

  * **A skill grants NO authority.** A skill is ADVISORY prompt context only — an operator-authored
    playbook that guides the model's approach. It authorizes nothing and confers no WARDEN tier. The
    loader reads ONLY ``id``/``name``/``description``/``category`` from the frontmatter; any
    authority-claiming key (``tier``, ``phase``, ``authorize``, ``destructive``, …) is parsed but
    NEVER surfaced or acted on, and :class:`Skill` has no tier field, so a crafted skill can never
    talk its way into a capability. Authority comes solely from the conjunctive gate.
  * **Path traversal is refused.** Every candidate file is resolved and checked
    ``is_relative_to(root)`` at BOTH discovery (defeats a symlink pointing outside the root) and load
    time; a file that escapes the root is dropped, never read. Lookups are by catalog id, not by
    joining an untrusted path, so ``../`` in a ``skill_id`` simply misses the catalog.
  * **Bounded.** The catalog is capped at ``MAX_SKILLS`` (deterministic, sorted by id) and a load of
    any id past the cap is refused.
  * **Total.** A missing root, an unreadable file, malformed frontmatter, or a weird ``skill_id`` all
    degrade to an empty catalog / ``None`` — never a raise.

No YAML dependency (stdlib only): a tiny, total scalar-frontmatter parser handles the simple
``key: value`` block redamon skills use.

Import-clean: stdlib only (``pathlib``/``os``); no framework/strix/network/PyYAML.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

MAX_SKILLS = 5   # redamon's cap — a hard bound on how many skills are ever loadable

# The ONLY frontmatter keys ever surfaced. Anything else (an authority claim like `tier`/`phase`) is
# intentionally dropped so a skill can never grant a capability.
_CATALOG_KEYS = ("id", "name", "description", "category")


@dataclass(frozen=True)
class Skill:
    """A catalog entry. Note the ABSENCE of any tier/phase/authority field — a skill is advisory
    context and confers nothing. ``file`` is a display reference (the path relative to the skills root)."""

    id: str
    name: str
    description: str
    category: str
    file: str


def _parse_frontmatter(text: object) -> tuple[dict[str, str], str]:
    """Parse a leading ``---`` … ``---`` scalar frontmatter block into ``(meta, body)``, totally.

    Only simple ``key: value`` scalar lines are recognised (quotes trimmed); comment/blank lines are
    skipped. No closing fence, or no leading fence, means "no frontmatter" and the whole text is the
    body. Never raises."""
    if not isinstance(text, str):
        return {}, ""
    s = text.lstrip("﻿")
    lines = s.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text
    meta: dict[str, str] = {}
    body_start: Optional[int] = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            body_start = i + 1
            break
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" in line:
            k, _sep, v = line.partition(":")
            key = k.strip().lower()
            val = v.strip().strip('"').strip("'")
            if key and key not in meta:
                meta[key] = val
    if body_start is None:
        return {}, text   # unterminated frontmatter is not frontmatter → treat all as body
    return meta, "\n".join(lines[body_start:])


def _within(root_resolved: Optional[Path], candidate: Path) -> bool:
    """True iff ``candidate`` resolves to a path inside ``root_resolved`` — the path-traversal /
    symlink-escape guard. Fail-closed: an unresolvable path or a missing root is NOT within."""
    if root_resolved is None:
        return False
    try:
        cand = candidate.resolve()
    except (OSError, RuntimeError, ValueError):
        return False
    try:
        return cand.is_relative_to(root_resolved)
    except AttributeError:  # pragma: no cover — is_relative_to exists on 3.9+ (repo is 3.11+)
        try:
            return os.path.commonpath([str(cand), str(root_resolved)]) == str(root_resolved)
        except (ValueError, OSError):
            return False


class SkillLoader:
    """Loads advisory markdown skills from ``skills_dir``. Read-only, deterministic, fail-closed."""

    def __init__(self, skills_dir: object, *, max_skills: int = MAX_SKILLS) -> None:
        # A non-None, non-PathLike config value (int/object/bytes) must fail-closed to an empty catalog,
        # not raise: Path() rejects such args with TypeError/ValueError.
        self._root: Optional[Path]
        if skills_dir is None:
            self._root = None
        else:
            try:
                self._root = Path(skills_dir)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                self._root = None
        try:
            self._max = int(max_skills)
        except Exception:  # noqa: BLE001
            self._max = MAX_SKILLS
        if self._max < 0:
            self._max = 0

    def _root_resolved(self) -> Optional[Path]:
        if self._root is None:
            return None
        try:
            return self._root.resolve()
        except (OSError, RuntimeError, ValueError):
            return None

    def _discover(self) -> list[Skill]:
        """Discover, guard, parse and cap. Deterministic: files are sorted by resolved path, ids are
        de-duplicated (first wins), and the result is capped at ``max_skills``."""
        root_resolved = self._root_resolved()
        if root_resolved is None:
            return []
        try:
            paths = [p for p in self._root.rglob("*.md") if p.is_file()]  # type: ignore[union-attr]
        except (OSError, RuntimeError, ValueError):
            return []
        paths.sort(key=lambda p: str(p))
        skills: list[Skill] = []
        seen: set[str] = set()
        for path in paths:
            if not _within(root_resolved, path):
                continue   # symlink or entry escaping the root — refuse
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                continue
            meta, _body = _parse_frontmatter(text)
            skill_id = (meta.get("id") or path.stem).strip()
            if not skill_id or skill_id in seen:
                continue
            seen.add(skill_id)
            try:
                rel = str(path.resolve().relative_to(root_resolved))
            except (ValueError, OSError, RuntimeError):
                rel = path.name
            skills.append(Skill(
                id=skill_id,
                name=meta.get("name", "").strip() or skill_id,
                description=meta.get("description", "").strip(),
                category=meta.get("category", "").strip(),
                file=rel,
            ))
            if len(skills) >= self._max:
                break
        return skills

    def list_skills(self) -> list[Skill]:
        """The loadable skill catalog (advisory metadata only), capped at ``max_skills``."""
        return self._discover()

    def catalog(self) -> list[dict[str, str]]:
        """The catalog as plain dicts with EXACTLY the advisory keys — no tier/authority ever leaks."""
        return [{k: getattr(s, k) for k in (*_CATALOG_KEYS, "file")} for s in self._discover()]

    def load_skill_content(self, skill_id: object) -> Optional[str]:
        """Return the advisory body of ``skill_id`` (frontmatter stripped), or ``None`` if it is not in
        the capped catalog, escapes the root, or cannot be read. Grants nothing — the body is context.

        Lookups are by catalog id (never by joining an untrusted path), and the file is re-guarded
        ``is_relative_to(root)`` before it is read, so path traversal cannot reach an out-of-root file."""
        if not isinstance(skill_id, str) or not skill_id.strip():
            return None
        wanted = skill_id.strip()
        root_resolved = self._root_resolved()
        if root_resolved is None:
            return None
        for skill in self._discover():   # only ids in the capped, guarded catalog are loadable
            if skill.id != wanted:
                continue
            candidate = (self._root / skill.file) if self._root is not None else None
            if candidate is None or not _within(root_resolved, candidate):
                return None
            try:
                text = candidate.read_text(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                return None
            _meta, body = _parse_frontmatter(text)
            return body
        return None
