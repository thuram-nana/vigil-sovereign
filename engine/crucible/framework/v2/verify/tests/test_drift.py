"""
Phase D1 — continuous drift over the confirmed-fact set.

Drift is a PURE set-diff over two sets of oracle-CONFIRMED fact identities. Two properties
carry the whole design: (1) determinism — the same two retained states always diff to the
same result, no wallclock/rng, total on garbage; (2) it cannot fabricate a regression — a
finding is a "confirmed fact" ONLY if its retained oracle_context still RE-FIRES, so a lead
or a tampered cert never enters the diff.
"""

from __future__ import annotations

import json

from framework.v2.verify import drift
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding

_BASE = {"status": 200, "body": "No results found."}
_DIVERGENT = {
    "status": 200,
    "body": "id=1 name=alice role=user\nid=2 name=bob role=admin\nid=3 name=carol role=user",
}


def _ctx(mutated: dict) -> FindingContext:
    return FindingContext.from_http_responses(
        _BASE, mutated, bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]},
    )


def _finding(endpoint: str, param: str, *, genuine: bool = True) -> dict:
    """An AuditFinding-shaped dict with a re-verifiable certificate. ``genuine`` False swaps in
    a non-divergent context so the oracle does NOT re-fire (a would-be fabricated fact)."""
    ctx = _ctx(_DIVERGENT)
    confirmed = confirm_finding(finding={"bug_class": "boolean_sqli"}, context=ctx)
    assert confirmed is not None
    return {
        "check_id": "boolean-sqli",
        "bug_class": "boolean_sqli",
        "insertion_point": f"query:{param}",
        "param": param,
        "endpoint": endpoint,
        "confirmed_by": confirmed.confirmed_by.value,
        "confidence": confirmed.confidence,
        "oracle_context": (ctx if genuine else _ctx(dict(_BASE))).model_dump(mode="json"),
    }


# ---- the pure diff ----------------------------------------------------------


def test_diff_confirmed_added_removed_unchanged() -> None:
    prev = {"a", "b", "c"}
    curr = {"b", "c", "d"}
    d = drift.diff_confirmed(prev, curr)
    assert d.added == ("d",)
    assert d.removed == ("a",)
    assert d.unchanged == ("b", "c")
    assert d.has_drift


def test_diff_confirmed_is_deterministic_and_sorted() -> None:
    prev = {"z", "m", "a"}
    curr = {"a", "q", "z"}
    d1 = drift.diff_confirmed(prev, curr)
    d2 = drift.diff_confirmed(set(prev), set(curr))
    assert d1 == d2                       # pure function of inputs
    assert list(d1.added) == sorted(d1.added)     # sorted tuples
    assert list(d1.unchanged) == sorted(d1.unchanged)


def test_diff_confirmed_no_drift_when_identical() -> None:
    d = drift.diff_confirmed({"x", "y"}, {"y", "x"})
    assert not d.has_drift and d.added == () and d.removed == ()
    assert d.unchanged == ("x", "y")


def test_diff_confirmed_total_on_garbage() -> None:
    # non-iterable, bare string, mapping, and mixed non-string elements — none raise, and
    # a non-string element is NEVER coerced into an identity.
    assert drift.diff_confirmed(None, 123) == drift.DriftDiff((), (), ())
    assert drift.diff_confirmed("abc", {"k": 1}) == drift.DriftDiff((), (), ())
    d = drift.diff_confirmed([1, 2, "keep"], ["keep", 3.0, True, "new"])
    assert d.added == ("new",) and d.removed == () and d.unchanged == ("keep",)


# ---- confirmed-fact identities (re-fire required) ---------------------------


def test_confirmed_fact_ids_only_reconfirming_certs() -> None:
    doc = {"active_findings": [
        _finding("http://t/a", "id"),                 # re-fires -> a fact
        _finding("http://t/b", "q", genuine=False),   # tampered -> NOT a fact
        {"bug_class": "xss", "endpoint": "http://t/c", "param": "x"},  # no cert -> NOT a fact
    ]}
    ids = drift.confirmed_fact_ids(doc)
    assert len(ids) == 1
    only = json.loads(next(iter(ids)))
    assert only["endpoint"] == "http://t/a" and only["bug_class"] == "boolean_sqli"


def test_confirmed_fact_ids_total_on_bad_doc() -> None:
    assert drift.confirmed_fact_ids(None) == frozenset()
    assert drift.confirmed_fact_ids({"active_findings": "not-a-list"}) == frozenset()
    assert drift.confirmed_fact_ids([{"bad": 1}, 7, "x"]) == frozenset()


# ---- end-to-end drift over two run docs -------------------------------------


def test_drift_surfaces_a_newly_appeared_fact() -> None:
    prev = {"active_findings": [_finding("http://t/a", "id")]}
    curr = {"active_findings": [_finding("http://t/a", "id"), _finding("http://t/b", "q")]}
    d = drift.diff_run_docs(prev, curr)
    assert len(d.added) == 1 and len(d.removed) == 0 and len(d.unchanged) == 1
    findings = drift.drift_findings(d)
    assert [f["drift_kind"] for f in findings] == ["appeared"]
    assert findings[0]["endpoint"] == "http://t/b"


def test_drift_surfaces_a_disappeared_fact() -> None:
    prev = {"active_findings": [_finding("http://t/a", "id"), _finding("http://t/b", "q")]}
    curr = {"active_findings": [_finding("http://t/a", "id")]}
    d = drift.diff_run_docs(prev, curr)
    assert len(d.removed) == 1 and len(d.added) == 0
    assert drift.drift_findings(d)[0]["drift_kind"] == "disappeared"


def test_drift_cannot_fabricate_a_regression_from_a_tampered_cert() -> None:
    # curr adds a finding whose cert does NOT re-fire; it must NOT count as a new fact.
    prev = {"active_findings": [_finding("http://t/a", "id")]}
    curr = {"active_findings": [_finding("http://t/a", "id"),
                                _finding("http://t/evil", "x", genuine=False)]}
    d = drift.diff_run_docs(prev, curr)
    assert d.added == () and not d.has_drift


# ---- run store + watch ------------------------------------------------------


def _write_run(base, run_id: str, findings: list, target: str = "http://127.0.0.1/") -> None:
    d = base / run_id
    d.mkdir(parents=True)
    (d / "reverifiable.json").write_text(json.dumps({"active_findings": findings}), encoding="utf-8")
    (d / "meta.json").write_text(json.dumps({"target": target}), encoding="utf-8")


def test_drift_over_store_picks_two_latest(tmp_path) -> None:
    _write_run(tmp_path, "20250101-000001-001", [_finding("http://t/a", "id")])
    _write_run(tmp_path, "20250101-000002-002",
               [_finding("http://t/a", "id"), _finding("http://t/b", "q")])
    rep = drift.drift_over_store(tmp_path)
    assert rep is not None
    assert rep.prev == "20250101-000001-001" and rep.curr == "20250101-000002-002"
    assert len(rep.diff.added) == 1

    # fewer than two comparable runs -> None
    assert drift.drift_over_store(tmp_path, target="http://nonexistent/") is None


def test_watch_cadence_is_deterministic_with_injected_sleep(tmp_path) -> None:
    slept: list[float] = []
    prev_doc = {"active_findings": [_finding("http://t/a", "id")]}
    curr_doc = {"active_findings": [_finding("http://t/a", "id"), _finding("http://t/b", "q")]}
    diffs = drift.watch(lambda: prev_doc, lambda: curr_doc,
                        cycles=2, interval=5.0, sleep=slept.append)
    assert len(diffs) == 2
    # cycle 0: baseline(prev) vs curr -> B appeared; cycle 1: curr vs curr -> no drift
    assert len(diffs[0].added) == 1
    assert not diffs[1].has_drift
    assert slept == [5.0]                 # slept once, between the two cycles (injected clock)
