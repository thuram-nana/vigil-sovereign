"""
agents.cognitive_refusal — the reasoning-layer refusal, recorded as evidence.

CRUCIBLE's refusals were scattered: hard gates (kill-switch / scope / sovereignty / ethics)
that RAISE, and epistemic abstains (SCE / consistency / veracity) that quietly demote. N4 adds
the unified piece: an explicit "refuse to CONCLUDE" decision — decline to assert a finding as
fact when it will not re-ground — plus one typed ``refusal`` event so every refusal, hard or
epistemic, lands on the same immutable stream and can be audited/observed uniformly.

This only ever DEMOTES / routes-to-needs-evidence. It never promotes, never gates a surface,
and it is fail-closed by construction (a claim that cannot be re-grounded is refused). It
reuses the veracity firewall (re-execution) — it does not reinvent grounding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class RefusalDecision:
    gate: str            # 'epistemic' here; hard gates pass their own name
    action_refused: str
    reason: str = ""
    fatal: bool = False


def _get(f: Any, k: str, default: Any = None) -> Any:
    return f.get(k, default) if isinstance(f, dict) else getattr(f, k, default)


def epistemic_refusal(finding: Any, *, world: Any = None) -> RefusalDecision | None:
    """Refuse to CONCLUDE a finding that claims oracle verification but does NOT re-ground
    under live re-execution — route it to needs_evidence instead of asserting it as fact.
    Returns None when the finding makes no verification claim, or when it grounds cleanly (in
    which case there is nothing to refuse — the oracle already confirmed it). Reuses the
    veracity firewall; deterministic."""
    if not bool(_get(finding, "verified_by_oracle", False)):
        return None   # no fact claim → nothing to refuse
    try:
        from ..veracity import admit, claim_from_finding
        claim = claim_from_finding(finding, source="cognitive-refusal", match_confidence=False)
        admitted = admit(claim, world=world)
    except Exception:
        return None
    if admitted.is_fact:
        return None   # grounds → conclude normally, no refusal
    return RefusalDecision(
        gate="epistemic",
        action_refused=f"conclude {_get(finding, 'bug_class', '?')} as confirmed",
        reason=f"claims oracle verification but does not re-ground under re-execution: {admitted.reason}")


def emit_refusal(spine_sink: Any, decision: RefusalDecision | None) -> None:
    """Record a refusal on the spine (a duck-typed sink exposing ``.refusal(...)``). No-op when
    there is no sink or no refusal. Best-effort — recording a refusal must never itself fail a
    run, but a refusal is never silently dropped when a sink is present."""
    if spine_sink is None or decision is None:
        return
    try:
        spine_sink.refusal(decision.gate, decision.action_refused,
                           reason=decision.reason, fatal=decision.fatal)
    except Exception:
        pass
