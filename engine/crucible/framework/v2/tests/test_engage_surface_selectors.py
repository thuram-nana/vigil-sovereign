"""APEX PR-1 — the multi-agent SURFACE DECOMPOSITION selector + the GoalTree ``leaf_filter`` it rides.

Proves:
  * the classifier is deterministic and routes each surface to the right specialized domain (probe-leaves →
    recon; confirmed findings → their vuln domain; unknown → the injection fallback);
  * ``decompose`` partitions the open leaves by domain;
  * the ``SurfaceSelector`` ROUND-ROBINS across the domains that have an open leaf — so a cluster of high-prior
    injection leaves can no longer starve the auth / access-control surfaces (the whole point), while the
    GLOBAL greedy ``_select`` WOULD starve them (the control);
  * selection is deterministic (same tree → same pick sequence);
  * ``GoalTree.best_open_leaf`` / ``best_open_leaf_pathaware`` are BYTE-IDENTICAL with ``leaf_filter=None``
    and correctly scope to a subset when a filter is passed.

Pure/offline — no engagement, no traffic.
"""

from __future__ import annotations

from framework.v2 import engage_surface_selectors as ss
from framework.v2.planner.goal_tree import CostEstimate, GoalTree


# ---------------------------------------------------------------------------
# classifier
# ---------------------------------------------------------------------------


def test_probe_leaf_is_recon_regardless_of_bug_class():
    # a discovery probe leaf (label starts "probe ") is RECON even though its nominal class is xss
    assert ss.domain_for("probe xss @ http://x/a?q=1", "xss", "http://x/a?q=1") == ss.RECON
    assert ss.domain_for("PROBE sqli @ http://x/", "sqli", "http://x/") == ss.RECON


def test_reverify_leaf_routes_by_bug_class():
    cases = {
        ("reverify sqli @ /a", "sqli", "/a"): ss.INJECTION,
        ("reverify xss @ /a", "xss", "/a"): ss.INJECTION,
        ("reverify open_redirect @ /a", "open_redirect", "/a"): ss.INJECTION,
        ("reverify path_traversal @ /a", "path_traversal", "/a"): ss.INJECTION,
        ("reverify idor @ /a", "idor", "/a"): ss.ACCESS_CONTROL,
        ("reverify bola @ /a", "bola", "/a"): ss.ACCESS_CONTROL,
        ("reverify jwt @ /a", "jwt_forgery", "/a"): ss.AUTH,
        ("reverify session @ /a", "session_fixation", "/a"): ss.AUTH,
        ("reverify ssrf @ /a", "ssrf", "/a"): ss.SSRF_OOB,
        ("reverify xxe @ /a", "blind_xxe", "/a"): ss.SSRF_OOB,
        ("reverify race @ /a", "race_condition", "/a"): ss.BUSINESS_LOGIC,
        ("reverify logic @ /a", "business_logic", "/a"): ss.BUSINESS_LOGIC,
        ("reverify chain @ /a", "exploit_chain", "/a"): ss.EXPLOIT_CHAIN,
    }
    for (label, bc, sf), expected in cases.items():
        assert ss.domain_for(label, bc, sf) == expected, f"{bc} → {ss.domain_for(label, bc, sf)} != {expected}"


def test_unknown_class_falls_back_to_injection_and_never_raises():
    assert ss.domain_for("reverify weird @ /a", "totally_unknown_class", "/a") == ss.INJECTION
    # total / never raises on junk
    assert ss.domain_for(None, None, None) == ss.INJECTION
    assert ss.domain_for(123, object(), 4.5) in ss.DOMAINS


def test_domains_are_the_seven_specialized_surfaces():
    assert ss.DOMAINS == (
        "recon", "auth", "injection", "access-control", "business-logic", "ssrf-oob", "exploit-chain")


# ---------------------------------------------------------------------------
# decompose
# ---------------------------------------------------------------------------


def _tree_with(leaves: list[tuple[str, str, float]]) -> GoalTree:
    """A goal tree with one leaf per (bug_class, surface, prior). label mimics _build_goal_tree's reverify
    label so the classifier keys off bug_class (not a probe prefix)."""
    tree = GoalTree()
    root = tree.add(label="root", kind="root", prior=1.0, value=1.0)
    for bc, sf, prior in leaves:
        tree.add(parent_id=root, kind="leaf", label=f"reverify {bc} @ {sf}",
                 prior=prior, value=1.0, bug_class=bc, surface=sf, estimate=CostEstimate(requests=1))
    return tree


def test_decompose_partitions_open_leaves_by_domain():
    tree = _tree_with([("sqli", "/a", 0.9), ("idor", "/b", 0.5), ("jwt", "/c", 0.4), ("xss", "/d", 0.8)])
    groups = ss.decompose(tree)
    assert set(groups) == {ss.INJECTION, ss.ACCESS_CONTROL, ss.AUTH}
    assert len(groups[ss.INJECTION]) == 2    # sqli + xss
    assert len(groups[ss.ACCESS_CONTROL]) == 1
    assert len(groups[ss.AUTH]) == 1
    # ids are sorted within a domain (determinism)
    for ids in groups.values():
        assert ids == sorted(ids)


# ---------------------------------------------------------------------------
# SurfaceSelector round-robin — the anti-starvation property
# ---------------------------------------------------------------------------


def _drive(selector, tree, *, steps: int) -> list[str]:
    """Simulate the loop: pick a leaf, mark it claimed (so it leaves the open set), record its domain."""
    out: list[str] = []
    for _ in range(steps):
        leaf = selector(tree, None, [], None)
        if leaf is None:
            break
        out.append(ss.domain_for(leaf.label, leaf.bug_class, leaf.surface))
        tree.mark_status(leaf.id, "claimed")   # claimed leaves are not 'open' → leave the rotation
    return out


def test_round_robin_covers_every_domain_before_exhausting_one():
    # three injection leaves (high prior) + one auth + one access-control (low prior)
    tree = _tree_with([
        ("sqli", "/a", 0.95), ("xss", "/b", 0.93), ("open_redirect", "/c", 0.9),
        ("jwt", "/d", 0.2), ("idor", "/e", 0.1),
    ])
    picks = _drive(ss.SurfaceSelector(), tree, steps=5)
    # the FIRST three picks must cover the three DISTINCT present domains — no surface starved by the
    # high-prior injection cluster (the decomposition's whole purpose).
    assert set(picks[:3]) == {ss.INJECTION, ss.AUTH, ss.ACCESS_CONTROL}, picks


def test_global_greedy_starves_the_low_prior_surfaces_control():
    # CONTROL: the GLOBAL greedy pick drains the high-prior injection cluster FIRST, starving auth/access.
    tree = _tree_with([
        ("sqli", "/a", 0.95), ("xss", "/b", 0.93), ("open_redirect", "/c", 0.9),
        ("jwt", "/d", 0.2), ("idor", "/e", 0.1),
    ])
    picks: list[str] = []
    for _ in range(3):
        leaf = tree.best_open_leaf()
        picks.append(ss.domain_for(leaf.label, leaf.bug_class, leaf.surface))
        tree.mark_status(leaf.id, "claimed")
    assert picks == [ss.INJECTION, ss.INJECTION, ss.INJECTION], picks  # all three are injection — starved


def test_selector_is_deterministic():
    def run() -> list[str]:
        tree = _tree_with([("sqli", "/a", 0.9), ("idor", "/b", 0.5), ("jwt", "/c", 0.4)])
        return _drive(ss.SurfaceSelector(), tree, steps=3)
    assert run() == run()


def test_selector_returns_none_when_no_open_leaf():
    tree = GoalTree()
    tree.add(label="root", kind="root", prior=1.0, value=1.0)
    assert ss.SurfaceSelector()(tree, None, [], None) is None


# ---------------------------------------------------------------------------
# GoalTree.leaf_filter — byte-identical when None, scoping when set
# ---------------------------------------------------------------------------


def test_best_open_leaf_filter_none_is_byte_identical():
    tree = _tree_with([("sqli", "/a", 0.9), ("idor", "/b", 0.5), ("jwt", "/c", 0.4)])
    assert tree.best_open_leaf().id == tree.best_open_leaf(leaf_filter=None).id


def test_best_open_leaf_filter_scopes_to_subset():
    tree = _tree_with([("sqli", "/a", 0.95), ("idor", "/b", 0.5), ("jwt", "/c", 0.4)])
    groups = ss.decompose(tree)
    auth_ids = set(groups[ss.AUTH])
    picked = tree.best_open_leaf(leaf_filter=lambda n: n.id in auth_ids)
    assert picked is not None and picked.bug_class == "jwt", "the filter did not scope to the auth leaf"
    # and the UNfiltered pick is the highest-prior (injection) leaf — proving the filter changed the result
    assert tree.best_open_leaf().bug_class == "sqli"


def test_best_open_leaf_pathaware_filter_none_is_byte_identical():
    tree = _tree_with([("sqli", "/a", 0.9), ("idor", "/b", 0.5)])
    # world=None path degrades to best_open_leaf; with no filter it must match the unfiltered greedy pick
    a = tree.best_open_leaf_pathaware()
    b = tree.best_open_leaf_pathaware(leaf_filter=None)
    assert a.id == b.id == tree.best_open_leaf().id


def test_best_open_leaf_pathaware_filter_scopes_without_world():
    tree = _tree_with([("sqli", "/a", 0.95), ("idor", "/b", 0.5)])
    groups = ss.decompose(tree)
    ac_ids = set(groups[ss.ACCESS_CONTROL])
    picked = tree.best_open_leaf_pathaware(leaf_filter=lambda n: n.id in ac_ids)
    assert picked is not None and picked.bug_class == "idor"
