"""
veracity.consistency — deterministic claim-vs-fact contradiction detection.

An LLM (or any proposer) can assert something the deterministic substrate already believes
is FALSE. This is not an NLI model — it is a structural check over the Bayesian world-model:
a claim that names an entity the graph holds at a NET-REFUTED belief contradicts an
established fact. That signal exists only because the world-model has a refutation channel
(``graph._update_belief`` lowers belief on a failed re-observation) — a max-confidence merge
never could.

Two triggers, both conservative:

  * the posterior MEAN sits below ``_REFUTED_FLOOR`` — the graph, on balance, disbelieves it;
  * the posterior LOWER CONFIDENCE BOUND sits below ``_REFUTED_LCB_FLOOR`` — even the
    optimistic-mean case is undercut by a collapsed lower bound (a wide, low-support belief).

The LCB trigger catches a refuted entity whose mean is marginally above the floor but whose
credible interval has fallen out from under it — a fact the mean-only check would miss.

Returns ``(is_contradiction, score, reason)``; ``admit()`` treats a positive result as
CONTRADICTED and feeds the refutation back, so a finding that argues against the graph is
auto-demoted even on the no-oracle path. Pure and read-only on the world-model.
"""

from __future__ import annotations

_REFUTED_FLOOR = 0.35       # below this posterior mean the graph actively disbelieves the entity
_REFUTED_LCB_FLOOR = 0.20   # below this lower-confidence-bound the belief has collapsed
_LCB_Z = 1.0                # z for the belief lower bound (matches the firewall's floor check)


def _lcb(node) -> float:
    """The node's belief lower-confidence bound, falling back to the mean when a node
    type does not expose one."""
    if hasattr(node, "belief_lcb"):
        try:
            return float(node.belief_lcb(_LCB_Z))
        except Exception:
            return float(node.belief_mean)
    return float(node.belief_mean)


def contradicts(entity_refs, world) -> tuple[bool, float, str]:
    """Does any entity the claim names sit at a net-refuted belief in ``world``? Returns
    (is_contradiction, score, reason). Pure and read-only on the world-model."""
    if world is None:
        return (False, 0.0, "no world-model to check against")
    worst = 0.0
    worst_ref = ""
    worst_reason = ""
    for ref in entity_refs or []:
        node = world.get_node(ref)
        if node is None:
            continue
        mean = float(node.belief_mean)
        lcb = _lcb(node)
        # the strongest refutation across the two conservative triggers
        if mean < _REFUTED_FLOOR:
            score = 1.0 - mean
            if score > worst:
                worst, worst_ref = score, ref
                worst_reason = (f"world-model holds it at a net-refuted mean belief "
                                f"({mean:.2f} < {_REFUTED_FLOOR})")
        if lcb < _REFUTED_LCB_FLOOR:
            score = 1.0 - lcb
            if score > worst:
                worst, worst_ref = score, ref
                worst_reason = (f"world-model belief lower bound has collapsed "
                                f"({lcb:.2f} < {_REFUTED_LCB_FLOOR})")
    if worst > 0.0:
        return (True, round(worst, 4), f"claim asserts {worst_ref!r} which the {worst_reason}")
    return (False, 0.0, "no asserted entity is net-refuted by the world-model")
