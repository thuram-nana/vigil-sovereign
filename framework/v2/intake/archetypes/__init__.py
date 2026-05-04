"""
intake.archetypes — registry of stack archetypes loaded from YAML.

The YAML files in this directory are the canonical source. The
classifier reads them at runtime; tests load them; UTI reports cite
them. Adding a new archetype means dropping a new YAML — no Python
changes.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from ..models import Archetype


@lru_cache(maxsize=1)
def load_all() -> list[Archetype]:
    here = Path(__file__).parent
    out: list[Archetype] = []
    for path in sorted(here.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        out.append(Archetype.model_validate(data))
    return out


def find(slug: str) -> Archetype | None:
    for a in load_all():
        if a.slug == slug:
            return a
    return None


def reset_cache() -> None:
    load_all.cache_clear()
