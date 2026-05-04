"""
planner.seed — initial goal tree from a stack archetype.

Given a UTI archetype, build a goal tree whose root is the engagement
objective, whose goals are the archetype's `attack_tree_seeds`, and
whose leaves are `(bug_class, surface)` pairs derived from the
archetype's `common_vulnerabilities` list.

If MLS has priors for `(archetype, bug_class)`, leaf priors are
seeded from those.  Otherwise a flat default is used.
"""

from __future__ import annotations

from typing import Any

from ..common import logging as v2log
from ..intake.archetypes import find as find_archetype
from ..memory import priors as mls_priors
from ..memory.store import Store
from .goal_tree import CostEstimate, GoalTree


_log = v2log.get_logger(__name__)


_DEFAULT_LEAF_PRIOR = 0.4


def seed_tree(
    *,
    archetype_slug: str,
    target_url: str = "",
    surfaces: list[str] | None = None,
    mls_store: Store | None = None,
) -> GoalTree:
    """Build the initial goal tree.

    Args:
        archetype_slug: the slug of the archetype UTI classified.
        target_url: the engagement target (used for label readability).
        surfaces: list of known endpoints from UTI's fingerprint paths_probed.
            If empty, leaves are pinned to '(generic surface)'.
        mls_store: if provided, leaf priors come from MLS archetype priors.
    """
    arch = find_archetype(archetype_slug)
    tree = GoalTree()
    root_label = (
        f"Engagement against {target_url}"
        if target_url else "Engagement objective"
    )
    root_id = tree.add(label=root_label, kind="root", prior=1.0, value=1.0)

    if arch is None:
        _log.warning(
            "planner.seed.no_archetype", archetype_slug=archetype_slug,
        )
        tree.add(
            parent_id=root_id,
            label="No archetype matched — generic OWASP coverage",
            kind="leaf",
            bug_class="unclassified", surface="(unknown)",
            prior=_DEFAULT_LEAF_PRIOR, value=1.0,
        )
        return tree

    # Priors lookup
    def prior_for(bug_class: str) -> float:
        if mls_store is None:
            return _DEFAULT_LEAF_PRIOR
        try:
            p = mls_priors.get_prior(mls_store, archetype_slug, bug_class)
        except Exception:
            return _DEFAULT_LEAF_PRIOR
        if p is None:
            return _DEFAULT_LEAF_PRIOR
        # blend the Laplace mean with the default so a single early
        # success doesn't pin a leaf to 1.0
        return 0.5 * p.mean + 0.5 * _DEFAULT_LEAF_PRIOR

    surfaces = surfaces or ["(generic surface)"]

    for seed in arch.attack_tree_seeds:
        goal_id = tree.add(
            parent_id=root_id, label=seed, kind="goal",
            prior=0.6, value=1.0,
        )
        for vuln in arch.common_vulnerabilities:
            for surface in surfaces:
                p = prior_for(vuln)
                tree.add(
                    parent_id=goal_id,
                    label=f"{vuln} on {surface}",
                    kind="leaf",
                    bug_class=vuln, surface=surface,
                    prior=p,
                    value=1.0,
                    estimate=CostEstimate(
                        requests=2, tokens=300.0, minutes=1.0,
                    ),
                )

    stats = tree.stats()
    _log.info(
        "planner.seed.tree_built",
        archetype=archetype_slug, surfaces=len(surfaces),
        leaves=stats["leaves"], total=stats["total"],
    )
    return tree
