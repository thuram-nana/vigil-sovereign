"""
common.docs — load v1 markdown into a structured form so URK can
render prompts from it without re-reading and re-parsing on every
call. The cognitive layer is the source of truth; URK wraps it.

This module never modifies v1 files. Read-only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from . import paths


_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$", re.MULTILINE)
_SLUG_DROP = re.compile(r"[^\w\s-]")
_SLUG_GAP = re.compile(r"\s+")


def _slugify(heading: str) -> str:
    s = _SLUG_DROP.sub("", heading.lower())
    s = _SLUG_GAP.sub("-", s.strip())
    return s


@dataclass(frozen=True)
class Section:
    level: int          # 1..6 (matches the heading depth)
    heading: str        # raw heading text without leading hashes
    anchor: str         # github-style slug for cross-reference
    body: str           # everything between this heading and the next, stripped

    def excerpt(self, max_chars: int = 1500) -> str:
        if len(self.body) <= max_chars:
            return self.body
        return self.body[: max_chars].rstrip() + "\n\n[...truncated...]"


@dataclass(frozen=True)
class Document:
    path: Path
    full_text: str
    sections: tuple[Section, ...]

    def section(self, anchor: str) -> Section:
        for s in self.sections:
            if s.anchor == anchor:
                return s
        raise KeyError(f"section {anchor!r} not in {self.path}")

    def find(self, *substrings: str) -> Section | None:
        """First section whose heading contains all substrings (case-insensitive)."""
        for s in self.sections:
            if all(sub.lower() in s.heading.lower() for sub in substrings):
                return s
        return None

    def at_level(self, level: int) -> tuple[Section, ...]:
        return tuple(s for s in self.sections if s.level == level)


def _parse(text: str, path: Path) -> Document:
    matches = list(_HEADING.finditer(text))
    sections: list[Section] = []
    for i, m in enumerate(matches):
        level = len(m.group(1))
        heading = m.group(2).strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        sections.append(
            Section(
                level=level,
                heading=heading,
                anchor=_slugify(heading),
                body=body,
            )
        )
    return Document(path=path, full_text=text, sections=tuple(sections))


@lru_cache(maxsize=128)
def load(path_str: str) -> Document:
    """Load and parse a markdown document. Cached by path string."""
    p = Path(path_str)
    return _parse(p.read_text(encoding="utf-8"), p)


# Convenience wrappers — typed paths from common.paths.

def cognitive(stem: str) -> Document:
    return load(str(paths.cognitive_doc(stem)))


def template(stem: str) -> Document:
    return load(str(paths.template(stem)))


def playbook(stem: str) -> Document:
    return load(str(paths.playbook(stem)))


def attack_technique(stem: str) -> Document:
    return load(str(paths.attack_technique(stem)))
