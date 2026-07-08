"""
veracity.consistency — deterministic claim-vs-fact contradiction detection.

An LLM can assert something the deterministic substrate already believes is FALSE. This
is not an NLI model — it is a structural check over the Bayesian world-model: a claim that
names an entity the graph holds at a NET-REFUTED belief (belief_mean below a floor, i.e.
the conjugate updates drove it down on failed re-observation) contradicts an established
fact. That signal exists only because the world-model has a refutation channel
(``graph._update_belief`` lowers belief on a failed re-check) — max-confidence never could.

Returns a score in [0, 1]; ``admit()`` treats a positive score as CONTRADICTED and feeds
the refutation back, so an LLM finding that argues against the graph is auto-demoted even
on the no-oracle path.
"""

from __future__ import annotations

_REFUTED_FLOOR = 0.35   # below this the graph actively disbelieves the entity


def contradicts(entity_refs, world) -> tuple[bool, float, str]:
    """Does any entity the claim names sit at a net-refuted belief in ``world``? Returns
    (is_contradiction, score, reason). Pure and read-only on the world-model."""
    if world is None:
        return (False, 0.0, "no world-model to check against")
    worst = 0.0
    worst_ref = ""
    for ref in entity_refs or []:
        node = world.get_node(ref)
        if node is None:
            continue
        b = node.belief_mean
        if b < _REFUTED_FLOOR:
            score = 1.0 - b
            if score > worst:
                worst, worst_ref = score, ref
    if worst > 0.0:
        return (True, round(worst, 4),
                f"claim asserts {worst_ref!r} which the world-model holds at a net-refuted "
                f"belief ({1.0 - worst:.2f} < {_REFUTED_FLOOR})")
    return (False, 0.0, "no asserted entity is net-refuted by the world-model")
