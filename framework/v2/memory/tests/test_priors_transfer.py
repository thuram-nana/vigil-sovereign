"""
Tests for W1.3 cross-engagement TRANSFER: embedding-smoothed, similarity-weighted priors
(memory.priors.get_prior_smoothed / smoothed_priors_for / SmoothedPrior).

The exact prior is keyed on a single archetype, so a new/rarely-seen archetype starts
cold. Transfer blends in priors from LEXICALLY SIMILAR archetypes, weighted by
embedding cosine and discounted so borrowed evidence counts for less than direct — and
it is honest: borrowed values are labelled and an under-evidenced blend is withheld.

These prove:
  * a well-evidenced local prior is returned as-is (no transfer);
  * a sparse/absent local prior borrows from a SIMILAR archetype but NOT a dissimilar
    one, with the borrowed evidence discounted below the neighbour's raw counts;
  * the evidence-sufficiency honesty gate withholds an under-evidenced blend;
  * it is deterministic (pinned lexical embedder);
  * a SmoothedPrior drops into the bandit's seed_from_priors bridge unchanged.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.memory import priors
from framework.v2.memory.store import Store, open_store


@pytest.fixture()
def store(tmp_path: Path) -> Store:
    s = open_store(tmp_path / "store.sqlite")
    yield s
    s.close()


# Three archetypes: two lexically SIMILAR (share "laravel"/"commerce"), one DISSIMILAR.
_QUERY = "laravel commerce marketplace"
_SIMILAR = "laravel commerce shop"
_OTHER = "static wordpress blog site"


def _bump(store: Store, archetype: str, bug_class: str, *, successes: int, attempts: int,
          surface: str = "") -> None:
    for _ in range(successes):
        priors.bump_success(store, archetype, bug_class, surface)
    for _ in range(attempts - successes):
        priors.bump_attempt(store, archetype, bug_class, surface)


def test_well_evidenced_local_prior_is_not_transferred(store: Store) -> None:
    _bump(store, _QUERY, "reflected_xss", successes=6, attempts=10)
    sm = priors.get_prior_smoothed(store, _QUERY, "reflected_xss")
    assert sm is not None
    assert sm.is_transferred is False and sm.sources == []
    assert sm.successes == 6.0 and sm.attempts == 10.0
    assert abs(sm.mean - (6 + 1) / (10 + 2)) < 1e-9   # unchanged Laplace mean


def test_sparse_local_borrows_from_similar_not_dissimilar(store: Store) -> None:
    # The query archetype has NO boolean_sqli history; a SIMILAR archetype has a strong
    # one, a DISSIMILAR archetype also has one. Transfer must borrow only the similar.
    _bump(store, _SIMILAR, "boolean_sqli", successes=8, attempts=10)
    _bump(store, _OTHER, "boolean_sqli", successes=1, attempts=10)

    sm = priors.get_prior_smoothed(store, _QUERY, "boolean_sqli")
    assert sm is not None
    assert sm.is_transferred is True
    assert sm.sources == [_SIMILAR]                     # dissimilar archetype excluded
    assert _OTHER not in sm.sources
    # borrowed evidence is DISCOUNTED below the neighbour's raw 10 attempts...
    assert 0.0 < sm.attempts < 10.0
    # ...and the transferred success rate is high (the similar archetype was 8/10).
    assert sm.mean > 0.5


def test_evidence_gate_withholds_underevidenced_transfer(store: Store) -> None:
    # A similar archetype with only ONE attempt: after the similarity*weight discount the
    # blended effective attempts fall below the floor, so smoothed_priors_for drops it.
    _bump(store, _SIMILAR, "open_redirect", successes=1, attempts=1)
    sm = priors.get_prior_smoothed(store, _QUERY, "open_redirect")
    assert sm is not None and sm.is_transferred is True
    assert sm.evidence_sufficient() is False            # too little effective evidence
    # ...so it is NOT in the transfer set fed to a bandit.
    transfer = priors.smoothed_priors_for(store, _QUERY)
    assert all(p.bug_class != "open_redirect" for p in transfer)


def test_no_local_and_no_similar_neighbour_returns_none(store: Store) -> None:
    # Only a DISSIMILAR archetype has this class -> no borrow possible -> None.
    _bump(store, _OTHER, "xxe", successes=5, attempts=8)
    assert priors.get_prior_smoothed(store, _QUERY, "xxe") is None


def test_transfer_is_deterministic(store: Store) -> None:
    _bump(store, _SIMILAR, "boolean_sqli", successes=8, attempts=10)
    a = priors.get_prior_smoothed(store, _QUERY, "boolean_sqli")
    b = priors.get_prior_smoothed(store, _QUERY, "boolean_sqli")
    assert a is not None and b is not None
    assert (a.successes, a.attempts, a.sources) == (b.successes, b.attempts, b.sources)


def test_smoothed_priors_feed_the_bandit_bridge(store: Store) -> None:
    # The transfer set is Prior-shaped, so it warm-starts the check-ordering bandit via
    # the existing seed_from_priors bridge (no bandit change needed).
    from framework.v2.scanner.learning import ContextualBandit

    _bump(store, _SIMILAR, "boolean_sqli", successes=8, attempts=10)
    transfer = priors.smoothed_priors_for(store, _QUERY)
    assert transfer, "expected at least one evidence-sufficient transfer"

    bandit = ContextualBandit()
    seeded = bandit.seed_from_priors(transfer, lambda p: ("ctx", p.bug_class))
    assert seeded == len(transfer)
    # the seeded arm is now biased above the uniform 0.5 (the similar archetype paid off)
    assert bandit.expected_value("ctx", "boolean_sqli") > 0.5


def test_transfer_seeds_a_cold_arm_once_never_compounding(store: Store) -> None:
    # Review fix: _seed_transfer is a ONE-TIME cold start. Re-running it — as happens when a
    # persisted bandit is reloaded each session — must NOT re-inject the borrowed pseudo-counts,
    # or transfer would compound unboundedly and dilute real learning (borrowed < direct).
    from framework.v2.scanner.campaign import WebScanCampaign
    from framework.v2.scanner.learning import ContextualBandit

    _bump(store, _SIMILAR, "boolean_sqli", successes=8, attempts=10)
    transfer = priors.smoothed_priors_for(store, _QUERY)
    assert transfer

    camp = WebScanCampaign(lambda req: {"status": 200, "body": ""},
                           priors=transfer, bandit_context="ctx")
    bandit = ContextualBandit()

    camp._seed_transfer(bandit)
    once = bandit.observations("ctx", "boolean_sqli")
    assert once > 0.0                              # a cold arm IS warm-started

    camp._seed_transfer(bandit)                    # simulate a second run reloading the bandit
    assert bandit.observations("ctx", "boolean_sqli") == once   # idempotent — NOT compounded

    # a real disproof still moves the arm, and transfer never re-inflates it afterwards
    bandit.update("ctx", "boolean_sqli", False)
    camp._seed_transfer(bandit)
    assert bandit.observations("ctx", "boolean_sqli") == once + 1.0   # only the real miss counted
