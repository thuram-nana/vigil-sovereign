"""
Wave 9 — expected-information-gain (value-of-information) leaf selection.

The planner can select the probe that most reduces uncertainty about a
consequential fact, instead of greedily chasing the highest prior. This is a
genuinely different objective (theatre guard): a max-entropy (prior~0.5) leaf
outranks a near-certain (prior~0.99) equal-value one that greedy would pick
first, and on a scripted world VOI reaches a crown-jewel-relevant leaf in fewer
probes than greedy.
"""

from __future__ import annotations

from framework.v2.planner.goal_tree import (
    GoalTree,
    _bernoulli_entropy,
    expected_information_gain,
)


def test_entropy_and_eig_are_real_computations() -> None:
    assert abs(_bernoulli_entropy(0.5) - 1.0) < 1e-9      # max entropy = 1 bit
    assert _bernoulli_entropy(0.0) == 0.0 and _bernoulli_entropy(1.0) == 0.0
    # a coin-flip belief yields more information than a near-certain one
    assert expected_information_gain(0.5) > expected_information_gain(0.99)
    assert expected_information_gain(0.5) > expected_information_gain(0.01)


def test_voi_diverges_from_greedy() -> None:
    # two equal value/cost leaves: one near-certain (greedy's pick), one a coin
    # flip (VOI's pick). The selectors must DISAGREE — proving VOI != greedy.
    tree = GoalTree()
    root = tree.add(label="root", kind="root")
    certain = tree.add(parent_id=root, kind="leaf", label="near-certain",
                       prior=0.99, value=1.0, surface="/certain")
    coinflip = tree.add(parent_id=root, kind="leaf", label="uncertain",
                        prior=0.5, value=1.0, surface="/uncertain")

    assert tree.best_open_leaf().id == certain          # greedy prefers high prior
    assert tree.best_open_leaf_voi().id == coinflip      # VOI prefers max uncertainty


def test_voi_still_weights_value() -> None:
    # among equally-uncertain leaves, the higher-value one wins
    tree = GoalTree()
    root = tree.add(label="root", kind="root")
    low = tree.add(parent_id=root, kind="leaf", label="low", prior=0.5, value=1.0)
    high = tree.add(parent_id=root, kind="leaf", label="high", prior=0.5, value=5.0)
    assert tree.best_open_leaf_voi().id == high


def test_voi_reaches_a_target_leaf_in_fewer_probes_than_greedy() -> None:
    # a decoy leaf has the highest prior (greedy chases it first and wastes a
    # probe); the consequential leaf is uncertain-but-valuable, so VOI probes it
    # first. Count probes to first-touch the consequential leaf.
    def _build() -> tuple[GoalTree, int]:
        # decoy: high prior -> higher GREEDY score (0.9*2=1.8 > 0.5*2=1.0), but
        # low entropy -> lower EIG. target: coin-flip -> max entropy -> higher EIG.
        t = GoalTree()
        r = t.add(label="root", kind="root")
        t.add(parent_id=r, kind="leaf", label="decoy", prior=0.9, value=2.0)
        target = t.add(parent_id=r, kind="leaf", label="target", prior=0.5, value=2.0)
        return t, target

    def _probes_until(tree: GoalTree, target_id: int, voi: bool) -> int:
        n = 0
        while True:
            leaf = tree.best_open_leaf_voi() if voi else tree.best_open_leaf()
            if leaf is None:
                return n + 1
            n += 1
            if leaf.id == target_id:
                return n
            tree.mark_status(leaf.id, "failed")  # exhaust it and move on

    t1, target1 = _build()
    t2, target2 = _build()
    greedy_probes = _probes_until(t1, target1, voi=False)
    voi_probes = _probes_until(t2, target2, voi=True)
    assert voi_probes < greedy_probes
