"""
memory — MLS, the Memory & Learning Substrate.

Persistent SQLite-backed store of engagements, findings, hypotheses,
payloads, dead ends, and archetype priors. Every URK call and every
UTI intake hooks through `recorder.*` to capture facts; every future
engagement queries `recall.*` for priors.

Public surface:

    from framework.v2.memory import open_store, recorder, recall, priors
    from framework.v2.memory.postmortem import run as run_postmortem

The store lives at framework/v2/.memory/store.sqlite (gitignored).
"""

from __future__ import annotations

from .store import Store, open_store

__all__ = ["Store", "open_store"]
