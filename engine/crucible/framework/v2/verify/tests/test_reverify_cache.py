"""
Speed X1 — the re-verification memo is a PURE-FUNCTION cache: it must speed the hot path
(the same retained oracle_context is re-fired at up to ~5 grounding-assessment sites over
one finding) WITHOUT changing a single output byte.

These tests pin both halves of that contract:
  * correctness/determinism — a cache hit returns the identical verdict a cold re-fire would
    (same reproduced / confirmed_by / confidence / matches_claim / note), only the caller's
    ``finding_ref`` differs, and a caller may mutate the result without poisoning the memo;
  * the actual saving — a second re-verify of byte-identical evidence does NOT re-run the
    oracle; a caller-supplied verifier bypasses the memo (its verdict is not cache-shareable).
"""

from __future__ import annotations

import framework.v2.verify.reverify as reverify
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.verifier import OracleVerifier

_BASE = {"status": 200, "body": "No results found."}
_DIVERGENT = {
    "status": 200,
    "body": "id=1 name=alice role=user\nid=2 name=bob role=admin\nid=3 name=carol role=user",
}


def _ctx_dict() -> dict:
    return FindingContext.from_http_responses(
        _BASE, _DIVERGENT, bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]},
    ).model_dump(mode="json")


def test_cache_hit_is_byte_identical_to_a_cold_refire() -> None:
    reverify._reverify_cached.cache_clear()
    oc = _ctx_dict()
    cold = reverify.reverify_context(oc, bug_class="boolean_sqli", ref="a")
    warm = reverify.reverify_context(oc, bug_class="boolean_sqli", ref="a")
    # everything but the ref (there is no ref difference here) is identical, to the byte.
    assert cold.model_dump() == warm.model_dump()
    assert cold.reproduced and cold.ok and cold.confirmed_by == "differential_response"


def test_caller_ref_is_stamped_not_leaked_from_the_shared_entry() -> None:
    reverify._reverify_cached.cache_clear()
    oc = _ctx_dict()
    first = reverify.reverify_context(oc, bug_class="boolean_sqli", ref="finding-1")
    second = reverify.reverify_context(oc, bug_class="boolean_sqli", ref="finding-2")
    assert first.finding_ref == "finding-1"
    assert second.finding_ref == "finding-2"
    # same underlying verdict, independent objects (mutating one cannot affect the other/cache)
    assert first is not second
    first.note = "MUTATED"
    third = reverify.reverify_context(oc, bug_class="boolean_sqli", ref="finding-3")
    assert third.note != "MUTATED"


def test_second_reverify_does_not_refire_the_oracle(monkeypatch) -> None:
    reverify._reverify_cached.cache_clear()
    calls = {"n": 0}
    real = reverify.confirm_finding

    def _counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(reverify, "confirm_finding", _counting)
    oc = _ctx_dict()
    # five assessment sites re-verify the SAME evidence+claim (engage grounding, report
    # export, reporter agent, critic panel, evidence certify) — the oracle fires ONCE.
    for i in range(5):
        r = reverify.reverify_context(
            oc, bug_class="boolean_sqli",
            claimed_confirmed_by="differential_response", ref=f"site-{i}")
        assert r.ok
    assert calls["n"] == 1


def test_distinct_claims_key_separately(monkeypatch) -> None:
    reverify._reverify_cached.cache_clear()
    calls = {"n": 0}
    real = reverify.confirm_finding

    def _counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(reverify, "confirm_finding", _counting)
    oc = _ctx_dict()
    # a different claimed_confidence is a different tamper-check → its own cache entry.
    reverify.reverify_context(oc, bug_class="boolean_sqli", claimed_confidence=0.9)
    reverify.reverify_context(oc, bug_class="boolean_sqli", claimed_confidence=0.1)
    assert calls["n"] == 2


def test_custom_verifier_bypasses_the_shared_memo(monkeypatch) -> None:
    reverify._reverify_cached.cache_clear()
    calls = {"n": 0}
    real = reverify.confirm_finding

    def _counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(reverify, "confirm_finding", _counting)
    oc = _ctx_dict()
    v = OracleVerifier()
    reverify.reverify_context(oc, bug_class="boolean_sqli", verifier=v)
    reverify.reverify_context(oc, bug_class="boolean_sqli", verifier=v)
    # a supplied verifier is never cache-shared: each call re-executes.
    assert calls["n"] == 2
