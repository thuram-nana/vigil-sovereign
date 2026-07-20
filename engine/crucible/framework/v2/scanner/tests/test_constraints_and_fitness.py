"""
Wave 10 — membership-query constraint inference + GA oracle-proximity fitness.

The scanner learns a filter's predicate from black-box yes/no queries and
synthesizes an input that provably crosses it, and gives the genetic payload
synthesizer a real gradient to climb from a blocked/inert payload toward one that
fires an oracle — adaptive, target-specific, explainable, beyond a static list.
"""

from __future__ import annotations

import html as _html
import random

from framework.v2.scanner.adaptive import evolve
from framework.v2.scanner.constraints import infer_predicate
from framework.v2.scanner.fitness import differential_proximity, reflection_proximity, unblocked_gate


# --- constraint inference --------------------------------------------------


def test_recovers_keyword_blocklist_and_synthesizes_confirmed_bypass() -> None:
    # a filter that reaches the sink iff the input has a quote AND lacks 'UNION'
    def membership(s: str) -> bool:
        return "'" in s and "union" not in s.lower()

    result = infer_predicate(membership)
    assert result.constraint is not None
    assert "single_quote" in result.constraint.required
    assert "kw_union" in result.constraint.forbidden
    # it synthesized an input that the oracle actually confirms
    assert result.synthesized is not None and result.confirmed
    assert membership(result.synthesized)


def test_required_character_filter_is_recovered() -> None:
    # reaches the sink only when a single quote is present (classic injection point)
    def membership(s: str) -> bool:
        return "'" in s

    result = infer_predicate(membership)
    assert result.constraint is not None
    assert "single_quote" in result.constraint.required
    assert result.confirmed


def test_non_injectable_target_reports_failure_not_a_false_claim() -> None:
    # nothing reaches the sink -> honest "no constraint inferred", never invented
    result = infer_predicate(lambda s: False)
    assert result.constraint is None and not result.confirmed
    assert "no constraint" in result.note


def test_inference_is_query_bounded() -> None:
    result = infer_predicate(lambda s: "'" in s, max_queries=50)
    assert result.queries <= 50


# --- oracle-proximity fitness + GA -----------------------------------------


def test_reflection_proximity_is_monotone_in_true_proximity() -> None:
    m = "cruciblemark"
    assert reflection_proximity(m, "nothing here") == 0.0
    assert 0.0 < reflection_proximity(m, f"<p>{m}</p>") < 1.0        # inert text
    assert reflection_proximity(m, f"<x{m}>") == 1.0                  # executable tag


def test_differential_proximity_gradient() -> None:
    base = "no results"
    assert differential_proximity(base, base) == 0.0
    assert differential_proximity(base, "id=1\nid=2\nid=3 (rows)") > 0.3


def test_ga_climbs_to_a_waf_bypass() -> None:
    # a WAF that blocks the literal "<script" (case-sensitive) but a case-varied
    # or otherwise-mutated payload that still creates a live element gets through.
    marker = "cruciblexss"

    def respond(payload: str) -> str:
        if "<script" in payload:  # naive case-sensitive block
            return "Request Blocked by WAF"
        return f"<html>echo: {payload}</html>"  # reflected raw

    def fitness(payload: str) -> float:
        body = respond(payload)
        return unblocked_gate(body) * reflection_proximity(marker, body)

    # the canonical probe is blocked (fitness 0); evolution must find a variant
    canonical = f"<script>{marker}</script>"
    assert fitness(canonical) == 0.0

    result = evolve([canonical, f"\"'><x{marker}>", f"<img src=x onerror={marker}>"],
                    fitness, generations=30, population=30, rng=random.Random(0))
    assert result.fitness == 1.0                 # found an executable, unblocked payload
    assert fitness(result.best) == 1.0
    assert "<script" not in result.best          # it evaded the block
