"""W10-1 (#473): the README's egress-allowlist claim must stay TRUE of the code.

WHY THIS TEST EXISTS. The runtime egress allowlist is gate 6 of the fail-closed safety stack
(`engine/crucible/README.md` §9.14). Before W10-1 no shipped caller installed it on the
target-traffic path, so the README's "6th gate fires on every target-touching request" was false for
target traffic — the allowlist was only ever set on the default-OFF live-intel collector. W10-1 wired
`egress_allowlist=build_engagement_allowlist(...)` onto `engage`'s scan + discovery executors and the
repeater's replay executor, and corrected the README to describe the allowlist's real, narrower reach
(refusal only under sovereign mode) alongside the two gates that ALWAYS hold for target traffic — the
protected-domain floor and the signed charter scope.

This guard fails four ways, each a real drift:

  * the corrected README no longer names both always-on target-traffic gates, or the sovereign-mode
    qualifier on the allowlist's refusal, or that it is installed on the engage/repeater executors;
  * a code fact the correction cites is no longer true in-tree — `engage.py` or `repeater/tool.py`
    stops passing `egress_allowlist=` to its `HttpExecutor`;
  * the invoker's UNCONDITIONAL allowlist check (`allow.permits(...)`, no transport/tier gate) is
    gone — the narrower-but-real reach the docs credit it with;
  * `build_engagement_allowlist` stops enforcing collector/target disjointness.

It reads files only — imports nothing, runs no tool, sends no packet — so it is correct to run in the
docs-only briefing-completeness CI job that installs only pytest.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

CRUCIBLE_README = REPO / "engine" / "crucible" / "README.md"
V2 = REPO / "engine" / "crucible" / "framework" / "v2"
ENGAGE = V2 / "engage.py"
REPEATER_TOOL = V2 / "repeater" / "tool.py"
INVOKER = V2 / "agents" / "tools" / "invoker.py"
EGRESS_GUARD = V2 / "agents" / "egress_guard.py"


def _collapsed(path: Path) -> str:
    """File text with every whitespace run collapsed to one space, so a phrase that wraps across
    lines still matches as a single needle."""
    assert path.is_file(), f"missing: {path}"
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))


def _count_egress_constructions(path: Path) -> int:
    """Count `HttpExecutor(...)` constructions in `path` that pass `egress_allowlist=` before the
    matching close paren. Coarse but file-only (the STRUCTURAL AST guard lives in the offense job,
    `agents/tests/test_egress_allowlist_wiring.py`); here we only need the doc's cited fact to hold."""
    text = path.read_text(encoding="utf-8")
    n = 0
    for m in re.finditer(r"HttpExecutor\(", text):
        depth = 0
        i = m.end() - 1
        seg_chars = []
        while i < len(text):
            c = text[i]
            seg_chars.append(c)
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if "egress_allowlist=" in "".join(seg_chars):
            n += 1
    return n


def test_readme_gate6_describes_the_real_reach_and_the_two_always_on_gates():
    readme = _collapsed(CRUCIBLE_README)
    # The allowlist's refusal is tier-scoped, not unconditional, and it IS installed on the real path.
    assert "SOVEREIGN MODE" in readme or "sovereign mode" in readme, \
        "README §9.14 must qualify the egress allowlist's refusal as sovereign-mode"
    assert "engage`/repeater executor" in readme or "engage/repeater executor" in readme, \
        "README §9.14 must state the allowlist is installed on the engage/repeater executors"
    # Both gates that ALWAYS hold for target traffic must be named next to the allowlist claim.
    assert "protected-domain floor" in readme, \
        "README §9.14 must name the protected-domain floor as an always-on target-traffic gate"
    assert "signed charter scope" in readme, \
        "README §9.14 must name the signed charter scope as an always-on target-traffic gate"


def test_readme_cited_code_facts_are_true_in_tree():
    # (a) engage wires BOTH executors; the repeater wires its replay executor.
    assert _count_egress_constructions(ENGAGE) >= 2, \
        "engage.py must pass egress_allowlist= on both the scan and discovery HttpExecutor sites"
    assert _count_egress_constructions(REPEATER_TOOL) >= 1, \
        "repeater/tool.py must pass egress_allowlist= on its replay HttpExecutor site"

    # (b) the invoker checks the allowlist UNCONDITIONALLY (no transport, no tier gate).
    invoker = _collapsed(INVOKER)
    assert "build_engagement_allowlist(slug=ctx.slug)" in invoker, \
        "invoker.py must build the engagement allowlist for a tool that declares egress hosts"
    assert "allow.permits(" in invoker, \
        "invoker.py must call allow.permits(...) directly — the unconditional allowlist check"

    # (c) collector/target disjointness is enforced when the allowlist is built.
    guard = _collapsed(EGRESS_GUARD)
    assert "collector_scope_conflicts(" in guard, \
        "egress_guard.build_engagement_allowlist must drop collector hosts that overlap target scope"
