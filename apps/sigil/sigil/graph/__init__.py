"""SIGIL entity graph (Kùzu) — a DETERMINISTIC mirror of the spine.

The graph is never a source of truth; it is a rebuilt VIEW. `rebuild.py` replays the
append-only spine in seq order into a fresh Kùzu database and atomically swaps it in, so
the graph can always be regenerated from the signed spine and every node cites the spine
records that produced it (prove-don't-guess). This module ships the deterministic
STRUCTURAL layer (Project/Session/Document/Commit + containment) — 100% grounded, zero LLM
cost. The semantic layer (Person/Decision/Commitment/…) is added later by the agent-driven
consolidation pass, on top of this same rebuild.
"""
from .rebuild import MirrorHealth, rebuild
from .query import entity, health, query

__all__ = ["rebuild", "query", "entity", "health", "MirrorHealth"]
