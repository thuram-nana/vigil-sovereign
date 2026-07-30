"""P5 — the ``engage --learn`` auto-loop closes the bandit half: ``--learn`` auto-persists the Thompson
effort-ranking bandit per target (warm-start at the next run's start, save at its end), so ranking learns
across engagements WITHOUT the operator managing ``--bandit-file``. Non-circular: the bandit only RE-RANKS
effort — it never promotes a finding, gates a surface out, or feeds an oracle input; a fired oracle stays the
sole authority for a FACT (the OutcomeLedger→calibrator half already auto-closes under --learn --autonomous)."""
from __future__ import annotations

from framework.v2.engage import _learn_bandit_path, _resolve_bandit_path
from framework.v2.scanner.learning import ContextualBandit


def test_resolve_bandit_path_rule():
    # an explicit --bandit-file always wins
    assert _resolve_bandit_path("/x/b.json", True, "acme") == "/x/b.json"
    assert _resolve_bandit_path("/x/b.json", False, "acme") == "/x/b.json"
    # --learn with no --bandit-file → a per-target persistent bandit
    p = _resolve_bandit_path(None, True, "acme")
    assert p and p.endswith("bandit.json") and "acme" in p
    assert p == _learn_bandit_path("acme")
    # neither (default / --ephemeral) → no persistence
    assert _resolve_bandit_path(None, False, "acme") is None


def test_bandit_persists_and_warm_starts_across_runs(tmp_path):
    path = tmp_path / "bandit.json"
    ctx, arms = "acme", ["sqli", "xss", "idor"]

    # run 1: learn that sqli pays off on this target-class, then save (what --learn does at run end)
    b1 = ContextualBandit()
    for _ in range(6):
        b1.update(ctx, "sqli", reward=True)
    for _ in range(6):
        b1.update(ctx, "xss", reward=False)
    b1.save(path)

    # run 2: warm-start from disk (what --learn does at the next run's start) — the learned preference survived
    b2 = ContextualBandit.load(path)
    assert b2.expected_value(ctx, "sqli") > b2.expected_value(ctx, "xss")

    # RE-RANKS, never drops an arm — every surface stays selectable (coverage / non-circular invariant)
    ranked = b2.rank(ctx, arms)
    assert set(ranked) == set(arms)
    assert ranked[0] == "sqli"
