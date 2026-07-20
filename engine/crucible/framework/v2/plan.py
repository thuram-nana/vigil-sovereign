"""
framework.v2.plan — READ-ONLY planner projection over a prior engagement's world-model (W2.2c).

    python3 -m framework.v2 plan <slug>

Loads the world-model + confirmed findings that ``engage --spine <slug> <seed-url>`` persisted
(``targets/<slug>/plan-input.json``), reconstructs the goal tree and the planner's ORIENT context
(crown-jewel objectives + the attacker foothold), then PRINTS the crown-jewel routes and the
action the planner would pick next — one-step greedy AND depth-2 lookahead.

It is a PURE projection: it loads persisted state, reasons over the graph, and prints. It sends NO
traffic and drives NO tools (no ``invoke_tool``, no gated capability, no HTTP) — so it is safe to
run any time, on any engagement, with zero impact. It reuses the ORIENT helpers from
``engage_autonomous`` (``_build_goal_tree`` / ``_foothold`` / ``_objective_kinds`` / ``_select``),
so the projected plan matches what the autonomous loop would select over the same state AT THE
DEFAULT request budget (``_PLAN_LOOKAHEAD_BUDGET``); a run with a non-default ``--autonomous-budget``
can trade off differently, and the depth-2 line is labelled with the budget it assumes.
"""

from __future__ import annotations

import argparse
import json
from types import SimpleNamespace
from typing import Any

from .common.errors import CrucibleError

# The request budget the depth-2 lookahead projection assumes — the SAME default the autonomous loop
# uses (``engage --autonomous-budget`` default). A run with a non-default budget can trade off
# differently; the projection labels this so it never overstates the match.
_PLAN_LOOKAHEAD_BUDGET = 8


def _load_plan_input(slug: str) -> dict:
    """Load the projection input ``engage --spine`` persisted. Missing → a legible CrucibleError
    (which the CLI prints and exits non-zero on) telling the operator to run the --spine engagement
    that persists it."""
    from .common.paths import target_dir

    path = target_dir(slug) / "plan-input.json"
    if not path.is_file():
        raise CrucibleError(
            f"no plan input for {slug!r} at {path} — run "
            f"`python3 -m framework.v2 engage --spine {slug} <seed-url>` first "
            f"(a --spine engagement persists the world-model this reads).")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise CrucibleError(f"plan input at {path} is unreadable: {e}") from e
    if not isinstance(doc, dict):
        raise CrucibleError(f"plan input at {path} is not a JSON object")
    return doc


def _findings_from(doc: dict) -> list:
    """Reconstruct lightweight finding stand-ins (just the attributes ``_build_goal_tree`` reads:
    bug_class / endpoint / insertion_point / confidence) from the persisted goal-tree seeds. These
    are NOT AuditFindings and never re-verify anything — they are goal-tree scaffolding for the
    read-only projection."""
    out: list = []
    for f in doc.get("findings", []) or []:
        if not isinstance(f, dict):
            continue
        out.append(SimpleNamespace(
            bug_class=str(f.get("bug_class", "") or ""),
            insertion_point=str(f.get("insertion_point", "") or ""),
            param=str(f.get("param", "") or ""),
            endpoint=str(f.get("endpoint", "") or ""),
            # None-aware default: a valid 0.0 confidence must NOT become 0.5 (`0.0 or 0.5 == 0.5`),
            # which would change the leaf's goal-tree prior and the projected ordering.
            confidence=float(f["confidence"]) if isinstance(f.get("confidence"), (int, float)) else 0.5,
            # a marker only — the projection never re-executes a certificate.
            oracle_context=({"present": True} if f.get("has_oracle_context") else None)))
    return out


def _routes(world: Any, source: str | None, objectives: list) -> list:
    """The best crown-jewel routes from the foothold — read-only over the world graph. Empty when
    there is no world / foothold / reachable crown jewel."""
    if world is None or source is None or not objectives:
        return []
    try:
        from .worldmodel import pathsearch
        return pathsearch.best_paths(world, source, objectives, k=5)
    except Exception:
        return []


def _render(slug: str, doc: dict) -> list[str]:
    """Build the projection report lines (pure — no I/O, no traffic, no tools)."""
    from .engage_autonomous import (
        _build_goal_tree, _foothold, _objective_kinds, _select,
    )
    from .worldmodel import store as world_store

    try:
        world = world_store.from_dict(doc.get("world") or {})
    except Exception:
        world = None
    findings = _findings_from(doc)
    tree, _ = _build_goal_tree(findings)
    objectives = _objective_kinds()
    source = _foothold(world)
    open_leaves = list(tree.open_leaves())

    lines = [
        f"plan {slug}  {doc.get('target', '(unknown target)')}",
        "  (READ-ONLY projection over the persisted --spine world-model — no traffic, no tools)",
        f"  world-model       : {world.node_count if world is not None else 0} node(s)",
        f"  confirmed findings: {len(findings)} → {len(open_leaves)} goal-tree leaf/leaves",
        f"  objectives        : {', '.join(getattr(k, 'value', str(k)) for k in objectives) or 'none'}",
        f"  foothold source   : {source or '(none — greedy ordering only)'}",
    ]

    routes = _routes(world, source, objectives)
    if routes:
        lines.append(f"  crown-jewel routes: {len(routes)} (attacker → crown jewel)")
        for r in routes:
            chain = " -> ".join(getattr(r, "nodes", []) or [])
            lines.append(f"    [conf {getattr(r, 'min_confidence', 0.0):.2f}] {chain}")
    else:
        lines.append("  crown-jewel routes: 0 (no reachable crown jewel — planner orders greedily)")

    greedy = _select(tree, world, objectives, source)
    look = _select(tree, world, objectives, source, lookahead_depth=2, budget=_PLAN_LOOKAHEAD_BUDGET)
    lines.append(f"  next action       : greedy         → {greedy.label if greedy else '(none)'}")
    lines.append(f"                      lookahead d-2  → {look.label if look else '(none)'}"
                 f"  (assumes budget {_PLAN_LOOKAHEAD_BUDGET}; a non-default --autonomous-budget may differ)")

    ordered = sorted(open_leaves, key=lambda l: (-l.score(), l.id))
    if ordered:
        lines.append(f"  goal-tree frontier ({len(ordered)} open leaf/leaves, greedy order):")
        for l in ordered[:20]:
            lines.append(f"    [{l.score():.3f}] {l.label}")
    return lines


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 plan",
        description="READ-ONLY planner projection over a prior `engage --spine` engagement's "
                    "world-model. Prints the crown-jewel routes and the planner's next action "
                    "(one-step greedy AND depth-2 lookahead). Sends no traffic and drives no tools.")
    parser.add_argument("slug", help="Engagement slug (must have a prior `engage --spine` run).")
    args = parser.parse_args(argv)

    doc = _load_plan_input(args.slug)   # raises CrucibleError (CLI-handled) when absent
    for line in _render(args.slug, doc):
        print(line)
    return 0
