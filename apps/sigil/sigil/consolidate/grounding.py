"""Grounding taxonomy + domain-neutral Beta belief math (SIGIL §6.3, ported from
worldmodel/models.py). Grounding is queryable METADATA that never moves belief; belief is a
Beta(alpha,beta) whose mean/LCB only ever drop on refutation (demote-only)."""
from __future__ import annotations

import math

# the source stamped on every consolidation-written record (distinguishes it from ingest).
CONSOLIDATE_SOURCE = "archivist"

# grounding tags. A record is a FACT only if its grounding starts with GROUNDED_PREFIX.
GROUNDED_PREFIX = "ingest:"          # traces to real spine records that re-verified
UNGROUNDED = "llm:ungrounded"        # the model asserted it but re-execution failed → commentary


def ground_tag(min_seq: int) -> str:
    return f"{GROUNDED_PREFIX}seq={min_seq}"


def is_grounded(grounding: str | None) -> bool:
    return bool(grounding and grounding.startswith(GROUNDED_PREFIX))


def belief_mean(alpha: float, beta: float) -> float:
    a, b = max(1e-9, alpha), max(1e-9, beta)
    return a / (a + b)


def belief_lcb(alpha: float, beta: float, z: float = 1.0) -> float:
    """Lower confidence bound = mean − z·sd of Beta(alpha,beta). A wide, low-support belief
    has a collapsed LCB even when its mean looks acceptable (the consistency.py insight)."""
    a, b = max(1e-9, alpha), max(1e-9, beta)
    mean = a / (a + b)
    var = (a * b) / ((a + b) ** 2 * (a + b + 1.0))
    return max(0.0, mean - z * math.sqrt(var))
