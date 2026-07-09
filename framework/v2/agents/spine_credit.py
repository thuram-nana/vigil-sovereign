"""
agents.spine_credit — temporal credit assignment over the spine's provenance DAG.

A confirmed finding does not appear from nowhere: on the spine it hangs off a chain of
``parent_id`` links (finding ← result ← action ← plan ← hypothesis ← decision). When the
finding is confirmed, the CHOICES that led there deserve credit — otherwise the planner and
the agent scheduler never learn which decisions/hypotheses pay off. ``credit_finding_path``
walks that provenance chain backward and emits a ``reward`` event crediting each ancestral
decision / hypothesis / plan.

Deterministic, bounded, best-effort, and DEMOTE-safe: it only records credit onto the
append-only stream (the planner may LATER re-rank on it) — it never gates a surface, never
promotes a finding, and never touches the oracle path.
"""

from __future__ import annotations

from .blackboard import Blackboard

# The ancestor kinds worth crediting — the CHOICES a learner can re-rank on.
_CREDITABLE = ("decision", "hypothesis", "plan")


def credit_finding_path(
    bb: Blackboard,
    engagement: str | int,
    finding_event_id: int,
    *,
    reward: float,
    signal: str = "finding_confirmed",
    agent_name: str = "credit",
    max_depth: int = 64,
) -> list[int]:
    """Walk the provenance chain backward from ``finding_event_id`` and post a ``reward``
    event crediting each ancestral decision/hypothesis/plan. Returns the ids credited.
    Bounded by ``max_depth`` and cycle-guarded; every write is best-effort."""
    r = max(0.0, min(1.0, float(reward)))
    credited: list[int] = []
    seen: set[int] = set()
    cur = bb.get(finding_event_id)
    depth = 0
    while cur is not None and cur.parent_id is not None and depth < max_depth:
        pid = cur.parent_id
        if pid in seen:
            break
        seen.add(pid)
        parent = bb.get(pid)
        if parent is None:
            break
        if parent.kind in _CREDITABLE:
            try:
                bb.post(engagement=engagement, kind="reward", agent_name=agent_name,
                        payload={"source": "credit", "arm": parent.kind, "signal": signal,
                                 "reward": r, "target_event_id": pid,
                                 "rationale": f"credit from confirmed finding {finding_event_id}"},
                        parent_id=pid)
                credited.append(pid)
            except Exception:
                pass   # crediting is value-add; a spine write must never sink the loop
        cur = parent
        depth += 1
    return credited
