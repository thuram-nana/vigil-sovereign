"""A tiny, self-contained source-mutation probe — the negative-control engine behind the mutation gate.

WHY THIS EXISTS (W11-3, issue #484). Full mutation testing (mutmut / cosmic-ray) cannot run on an
ordinary PR runner: it re-runs the whole suite once PER mutant and needs the tools installed. But the
one property that must be provable in a FAST, REQUIRED job is that the mutation gate has *sensitivity* —
that an adequate test KILLS a mutant while a deliberately-weak test lets it SURVIVE. If that were not
true, a green "mutation score" would be meaningless (a suite that kills nothing, or a harness that
reports everything killed, would look identical to a real one).

This module reduces the kill/survive contract to the standard library (``ast`` + ``inspect``): it
applies a known boundary mutation to a function's SOURCE, runs a caller-supplied test against the
mutated function, and returns ``KILLED`` (the test failed on the mutant) or ``SURVIVED`` (the test
passed on the mutant). It imports NO offense module and runs no tool, so it is safe in the sovereign
CI leg. It is intentionally NOT a general mutation engine — mutmut/cosmic-ray own that in the scheduled
job; this is the falsifiable *oracle* that proves those runs measure something real.
"""
from __future__ import annotations

import ast
import inspect
import textwrap
from typing import Any, Callable

KILLED = "KILLED"
SURVIVED = "SURVIVED"

# Boundary / relational operator swaps — the classic off-by-one and negation mutations a mutation
# tester applies. Each maps an AST comparator op to the neighbour a weak test cannot distinguish.
_COMPARE_SWAP: dict[type, type] = {
    ast.LtE: ast.Lt,
    ast.Lt: ast.LtE,
    ast.GtE: ast.Gt,
    ast.Gt: ast.GtE,
    ast.Eq: ast.NotEq,
    ast.NotEq: ast.Eq,
}


class _SwapNthComparator(ast.NodeTransformer):
    """Swap the ``index``-th mutable comparator op encountered in a left-to-right walk."""

    def __init__(self, index: int) -> None:
        self.index = index
        self.seen = 0
        self.applied = False

    def visit_Compare(self, node: ast.Compare) -> ast.AST:  # noqa: N802 (ast visitor name)
        self.generic_visit(node)
        new_ops: list[ast.cmpop] = []
        for op in node.ops:
            repl = _COMPARE_SWAP.get(type(op))
            if repl is not None:
                if self.seen == self.index and not self.applied:
                    new_ops.append(repl())
                    self.applied = True
                else:
                    new_ops.append(op)
                self.seen += 1
            else:
                new_ops.append(op)
        node.ops = new_ops
        return node


def _function_source(func: Callable[..., Any]) -> str:
    return textwrap.dedent(inspect.getsource(func))


def count_boundary_sites(func: Callable[..., Any]) -> int:
    """How many relational/equality comparator operators the function's source exposes to mutation."""
    tree = ast.parse(_function_source(func))
    n = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            n += sum(1 for op in node.ops if type(op) in _COMPARE_SWAP)
    return n


def mutate_boundary(func: Callable[..., Any], index: int = 0) -> tuple[str, bool]:
    """Return ``(mutated_source, applied)`` for the ``index``-th boundary comparator of ``func``.

    ``applied`` is False (and the source is returned unchanged) when the function exposes no mutable
    comparator at that index — the caller asserts on it, so a function that silently could not be
    mutated can never masquerade as a killed mutant.
    """
    src = _function_source(func)
    tree = ast.parse(src)
    tx = _SwapNthComparator(index)
    tx.visit(tree)
    if not tx.applied:
        return src, False
    ast.fix_missing_locations(tree)
    return ast.unparse(tree), True


def evaluate(source: str, func_name: str, namespace: dict[str, Any],
             test: Callable[[Callable[..., Any]], None]) -> str:
    """Compile ``source`` in a fresh namespace (seeded with ``namespace`` for the function's free
    variables), pull out ``func_name``, run ``test`` against it, and return the kill/survive verdict.

    A test is a callable that ASSERTS the function's behaviour and raises on a violation. If it raises,
    the mutant is ``KILLED``; if it returns cleanly, the mutant ``SURVIVED``. Any exception counts as a
    kill (an AssertionError, or a mutant that now raises where the original did not — both mean the test
    detected the change). This is exactly how a mutation tester scores a mutant against a test suite.
    """
    ns: dict[str, Any] = dict(namespace)
    exec(compile(source, filename="<mutant>", mode="exec"), ns)  # noqa: S102 (deliberate: probe engine)
    func = ns[func_name]
    try:
        test(func)
    except Exception:  # noqa: BLE001 — ANY failure is a kill, by design.
        return KILLED
    return SURVIVED
