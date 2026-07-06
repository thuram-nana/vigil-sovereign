"""
Wave 13 — stealth-aware planning + detection-gap / candidate-rule reporting.

Defensive only: the planner can prefer the quieter route (via the existing
detection-cost edge weight), and the gap report tells the blue team which
techniques the current ruleset misses and synthesizes a rule that would catch
them — without false-firing on benign traffic.
"""

from __future__ import annotations

from framework.v2.defender import ActionDescriptor, ActionKind, model_telemetry
from framework.v2.defender.gap_report import detection_gaps, synthesize_rule
from framework.v2.defender.rules import DetectionRuleset, default_ruleset
from framework.v2.scanner import detection_cost
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import Edge, EdgeKind, Node, NodeKind


# --- 13A: stealth-aware planning (reuse detection_cost.weight_fn) -----------


def test_stealth_weight_prefers_the_quieter_route() -> None:
    w = WorldModel()
    for nid in ("src", "loud", "quiet"):
        w.add_node(Node(id=nid, kind=NodeKind.HOST, provenance="t", first_seen=0, last_seen=0))
    # two one-hop routes to a HOST crown jewel: one edge is loud (many tells),
    # the other quiet. detection_cost.weight_fn reads edge.attrs.
    w.add_edge(Edge(src="src", dst="loud", kind=EdgeKind.REACHABLE_FROM, provenance="t",
                    attrs={"detection_signals": ["a", "b", "c", "d", "e"]}, first_seen=0, last_seen=0))
    w.add_edge(Edge(src="src", dst="quiet", kind=EdgeKind.REACHABLE_FROM, provenance="t",
                    attrs={"detection_signals": []}, first_seen=0, last_seen=0))

    from framework.v2.worldmodel import pathsearch
    paths = pathsearch.best_paths(w, "src", {NodeKind.HOST}, detection_cost.weight_fn, k=2)
    assert paths and paths[0].edges[-1].dst == "quiet"  # the stealthier route ranks first


# --- 13B: detection-gap + candidate-rule synthesis -------------------------


def _scan_below_threshold() -> ActionDescriptor:
    # a directory enumeration of only 10 distinct 404s — below R-WEB-DIRSCAN's
    # threshold of 20, so the default ruleset MISSES it
    return ActionDescriptor(
        kind=ActionKind.DIRECTORY_BRUTEFORCE, target_surface="/admin",
        attributes={"distinct_paths": "10"},
    )


def test_gap_is_flagged_and_a_synthesized_rule_closes_it() -> None:
    gaps = detection_gaps([_scan_below_threshold()], ruleset=default_ruleset())
    assert len(gaps) == 1
    gap = gaps[0]
    assert not gap.covered                       # the default ruleset missed it
    assert gap.candidate_rule is not None

    # the synthesized rule, added to the ruleset, now CATCHES the technique...
    augmented = DetectionRuleset(default_ruleset().rules + [gap.candidate_rule])
    scan_signals = model_telemetry(_scan_below_threshold())
    assert augmented.evaluate(scan_signals), "synthesized rule failed to catch the technique"

    # ...and does NOT fire on benign traffic (a plain 200 GET)
    benign = model_telemetry(ActionDescriptor(kind=ActionKind.HTTP_REQUEST, target_surface="/home"))
    fired_ids = {h.rule_id for h in augmented.evaluate(benign)}
    assert gap.candidate_rule.id not in fired_ids, "synthesized rule false-fires on benign traffic"


def test_covered_technique_is_not_flagged_as_a_gap() -> None:
    # an injection probe IS caught by the default WAF rule -> not a gap
    inj = ActionDescriptor(kind=ActionKind.INJECTION_PROBE, target_surface="/search",
                           attributes={"inj_class": "sql_injection"})
    gap = detection_gaps([inj])[0]
    assert gap.covered and "R-WAF-INJECTION" in gap.covered_by


def test_synthesize_rule_returns_none_for_generic_only_telemetry() -> None:
    # a plain request emits only generic fields -> no specific rule can be built
    benign = model_telemetry(ActionDescriptor(kind=ActionKind.HTTP_REQUEST, target_surface="/x"))
    assert synthesize_rule(benign) is None
