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

# The DIFFERENTIAL_RESPONSE certificate these tests re-verify is the SOUND one: a Wave-4.2
# request-smuggling DESYNC (a UNIQUE high-entropy canary echoed in VIGIL's own second response on
# the conflict leg and ABSENT from the identical no-conflict control leg). It used to be a
# `boolean_sqli` benign-vs-payload differential, which is no longer confirmable at all: a bare
# differential has no attribution step, so it minted FACTs on a WAF block page and on strict input
# validation against targets with no database (see verify.verifier.DIFFERENTIAL_LEAD_ONLY_CLASSES).
# The plumbing under test is unchanged — a real DIFFERENTIAL_RESPONSE certificate, tamperable to a
# non-firing twin — it is now anchored to evidence that actually proves something.
_CANARY = "vgLK7tQ2mXb9Zp4WdR"
_BUG_CLASS = "request_smuggling"
_CHECK_ID = "smuggling-CL.TE"


def _desync_ctx(*, genuine: bool = True) -> FindingContext:
    """A re-verifiable desync certificate. ``genuine=False`` drops the canary from the conflict
    leg, so the oracle does NOT re-fire (the tampered / would-be-fabricated twin)."""
    return FindingContext.from_smuggling_desync(
        canary=_CANARY, technique="CL.TE",
        conflict_second={"channel": True, "status": 400,
                         "body": (f"HTTP/1.1 400 Bad Request: unrecognised method GET /{_CANARY}"
                                  if genuine else "HTTP/1.1 200 OK ordinary second response")},
        control_second={"channel": True, "status": 200,
                        "body": "HTTP/1.1 200 OK ordinary second response"},
        bug_class=_BUG_CLASS,
    )


def _ctx_dict() -> dict:
    return _desync_ctx().model_dump(mode="json")


def test_cache_hit_is_byte_identical_to_a_cold_refire() -> None:
    reverify._reverify_cached.cache_clear()
    oc = _ctx_dict()
    cold = reverify.reverify_context(oc, bug_class=_BUG_CLASS, ref="a")
    warm = reverify.reverify_context(oc, bug_class=_BUG_CLASS, ref="a")
    # everything but the ref (there is no ref difference here) is identical, to the byte.
    assert cold.model_dump() == warm.model_dump()
    assert cold.reproduced and cold.ok and cold.confirmed_by == "differential_response"


def test_caller_ref_is_stamped_not_leaked_from_the_shared_entry() -> None:
    reverify._reverify_cached.cache_clear()
    oc = _ctx_dict()
    first = reverify.reverify_context(oc, bug_class=_BUG_CLASS, ref="finding-1")
    second = reverify.reverify_context(oc, bug_class=_BUG_CLASS, ref="finding-2")
    assert first.finding_ref == "finding-1"
    assert second.finding_ref == "finding-2"
    # same underlying verdict, independent objects (mutating one cannot affect the other/cache)
    assert first is not second
    first.note = "MUTATED"
    third = reverify.reverify_context(oc, bug_class=_BUG_CLASS, ref="finding-3")
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
            oc, bug_class=_BUG_CLASS,
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
    reverify.reverify_context(oc, bug_class=_BUG_CLASS, claimed_confidence=0.9)
    reverify.reverify_context(oc, bug_class=_BUG_CLASS, claimed_confidence=0.1)
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
    reverify.reverify_context(oc, bug_class=_BUG_CLASS, verifier=v)
    reverify.reverify_context(oc, bug_class=_BUG_CLASS, verifier=v)
    # a supplied verifier is never cache-shared: each call re-executes.
    assert calls["n"] == 2
