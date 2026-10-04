"""M4.1 no-bypass structural guard — PROVE the AI gateway is the only model-egress path.

The runtime guard (``vigil_core.ai_gateway.assert_in_egress``) fails a direct provider call closed, but only
if control actually reaches it. This STATIC guard is what makes "the gateway is the only egress path" a
FALSIFIABLE claim rather than a hope: it walks the offense (``framework.v2``) + integration
(``vigil_integration``) trees and fails if ANY model-egress call site —

    * ``<x>.messages.create(...)``   (Anthropic SDK, blocking)
    * ``<x>.messages.stream(...)``   (Anthropic SDK, streaming)
    * a model-backend ``<x>.complete(...)``   (the kernel provider layer, cloud or loopback-local)

— sits in a function that does NOT assert the egress context. Such a call could reach a provider WITHOUT
routing through ``vigil_core.ai_gateway.egress`` (so without classify -> redact -> authorize -> model-route
-> provenance -> audit). Add a new raw provider call outside the chokepoint and this test reds.

How "egress-guarded" is defined (and why it is sound):
  * every raw provider round-trip lives in a function (an adapter's ``invoke`` closure, or a ``*_raw`` helper
    reached only from one) whose OWN body calls ``assert_in_egress`` — so when that function runs outside the
    egress context it fails closed. An ``assert_in_egress`` sitting in a NESTED function does NOT count for the
    outer function (a nested closure's guard protects the closure, not its parent's own calls).
  * the kernel backend DRIVERS (``framework/v2/kernel/backends/``) wrap the provider SDK and are reached ONLY
    through a backend ``.complete()`` call. This guard requires EVERY such ``.complete()`` call to be
    egress-guarded, so the drivers are governed transitively; they are the one allowed home for an unguarded
    ``messages.create`` (the SDK leaf), and the guard skips exactly that directory and nothing else.

Scope: the two planes where the M4.1 gateway contract applies and where the red-pen found the bypasses. The
sovereign plane (``apps/sigil``) has no direct provider egress and governs its own model access separately.

Pure stdlib (``ast`` only) + path reads — no framework/vigil_core import — so it runs in every CI leg.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_ROOTS = ("engine/crucible/framework/v2", "integration/vigil_integration")
# The provider-SDK driver leaves — reached only via a (guarded) backend.complete(); see the module docstring.
_DRIVER_LEAVES = ("engine/crucible/framework/v2/kernel/backends",)
_ASSERT = "assert_in_egress"
# Receivers that denote a MODEL BACKEND for a `.complete(...)` egress, calibrated to this codebase's naming
# (verified: the only model `.complete` receivers are these; `self.complete`/`ledger.complete` are unrelated).
# `messages.create`/`.stream` are matched structurally (they require a `.messages` parent) and need no list.
_BACKEND_RECEIVER_NAMES = frozenset({"backend", "primary", "cand"})
_BACKEND_RECEIVER_CALLS = frozenset({"get_backend"})


# ── the AST matchers ──────────────────────────────────────────────────────────────────────────────

def _is_messages_attr_call(func: ast.expr, attr: str) -> bool:
    """`func` is the attribute chain ``<x>.messages.<attr>``."""
    return (isinstance(func, ast.Attribute) and func.attr == attr
            and isinstance(func.value, ast.Attribute) and func.value.attr == "messages")


def _is_backend_complete(func: ast.expr) -> bool:
    """`func` is ``<backend-ish>.complete`` — a Name in the backend set, or a call to ``get_backend(...)``."""
    if not (isinstance(func, ast.Attribute) and func.attr == "complete"):
        return False
    recv = func.value
    if isinstance(recv, ast.Name) and recv.id in _BACKEND_RECEIVER_NAMES:
        return True
    if isinstance(recv, ast.Call):
        rf = recv.func
        if isinstance(rf, ast.Name) and rf.id in _BACKEND_RECEIVER_CALLS:
            return True
        if isinstance(rf, ast.Attribute) and rf.attr in _BACKEND_RECEIVER_CALLS:
            return True
    return False


def _egress_kind(node: ast.AST) -> str | None:
    """Return a label if `node` is a model-egress Call, else None."""
    if not isinstance(node, ast.Call):
        return None
    f = node.func
    if _is_messages_attr_call(f, "create"):
        return "messages.create"
    if _is_messages_attr_call(f, "stream"):
        return "messages.stream"
    if _is_backend_complete(f):
        return "backend.complete"
    return None


def _own_nodes(node: ast.AST):
    """Yield the descendants of `node` WITHOUT crossing into a nested function/lambda scope (so a guard in a
    nested closure is not mistaken for a guard of the enclosing function's own statements)."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        yield child
        yield from _own_nodes(child)


def _fn_directly_asserts(fn: ast.AST) -> bool:
    """True iff `fn`'s OWN body (excluding nested function/lambda scopes) calls ``assert_in_egress``."""
    for n in _own_nodes(fn):
        if isinstance(n, ast.Call):
            f = n.func
            if (isinstance(f, ast.Attribute) and f.attr == _ASSERT) or \
               (isinstance(f, ast.Name) and f.id == _ASSERT):
                return True
    return False


class _Scan(ast.NodeVisitor):
    """Collect every model-egress call paired with its NEAREST enclosing function def (None at module level)."""

    def __init__(self) -> None:
        self._stack: list[ast.AST] = []
        self.hits: list[tuple[str, int, ast.AST | None]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._stack.append(node)
        self.generic_visit(node)
        self._stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Call(self, node: ast.Call):
        kind = _egress_kind(node)
        if kind:
            self.hits.append((kind, node.lineno, self._stack[-1] if self._stack else None))
        self.generic_visit(node)


def _violations_in_source(src: str, label: str = "<src>") -> list[str]:
    """The reusable checker: unguarded model-egress sites in one source string (used by the real-tree scan
    AND the self-tests below, so the real test and its negative controls share ONE code path)."""
    tree = ast.parse(src, filename=label)
    scan = _Scan()
    scan.visit(tree)
    out: list[str] = []
    for kind, lineno, fn in scan.hits:
        if fn is None or not _fn_directly_asserts(fn):
            where = getattr(fn, "name", None) or "<module>"
            out.append(f"{label}:{lineno}: {kind} in {where}() does not assert_in_egress")
    return out


def _count_in_source(src: str) -> int:
    scan = _Scan()
    scan.visit(ast.parse(src))
    return len(scan.hits)


def _iter_product_py():
    for root in _ROOTS:
        base = _REPO / root
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*.py")):
            rel = p.relative_to(_REPO).as_posix()
            if "/tests/" in f"/{rel}" or p.name.startswith("test_"):
                continue
            if any(rel.startswith(d) for d in _DRIVER_LEAVES):
                continue
            if "/.scratch" in f"/{rel}":
                continue
            yield p, rel


# ── the real invariant ────────────────────────────────────────────────────────────────────────────

def test_no_model_egress_bypasses_the_gateway():
    """EVERY model-egress call in the offense + integration trees is egress-guarded (or a driver leaf)."""
    violations: list[str] = []
    total = 0
    scanned = 0
    for path, rel in _iter_product_py():
        scanned += 1
        src = path.read_text(encoding="utf-8", errors="replace")
        hits = _violations_in_source(src, label=rel)
        # count all egress sites (guarded or not) for the no-op tripwire below
        total += _count_in_source(src)
        violations.extend(hits)
    assert scanned > 50, f"the guard scanned only {scanned} files — root/layout drift?"
    # Tripwire: if the matchers ever stop MATCHING (a refactor renames the SDK surface), this catches the
    # silent no-op. We route >= 8 application sites plus the URK failover + the raw helpers.
    assert total >= 8, (f"the guard found only {total} model-egress sites — the matchers may have drifted "
                        f"and silently stopped seeing provider calls")
    assert not violations, (
        "model-egress call sites that can BYPASS the gateway chokepoint (route them through "
        "vigil_core.ai_gateway.egress, or guard the raw helper with assert_in_egress):\n  "
        + "\n  ".join(violations))


# ── negative controls: PROVE the checker catches a bypass and passes a guarded call ─────────────────

_BYPASS_CREATE = "def leak(client):\n    return client.messages.create(model='m', messages=[])\n"
_BYPASS_STREAM = ("def leak(client):\n    with client.messages.stream(x=1) as s:\n"
                  "        return s.get_final_message()\n")
_BYPASS_COMPLETE_NAME = "def leak(prompt):\n    return backend.complete(prompt)\n"
_BYPASS_COMPLETE_GETB = "def leak(prompt):\n    return get_backend().complete(prompt)\n"
_GUARDED_CREATE = ("def ok(client):\n    _gw.assert_in_egress('x')\n"
                   "    return client.messages.create(model='m', messages=[])\n")
_GUARDED_COMPLETE = "def ok(prompt):\n    assert_in_egress('x')\n    return backend.complete(prompt)\n"
# an assert in a NESTED function must NOT satisfy the OUTER function's own egress call
_NESTED_GUARD_WRONG = ("def outer(client):\n    def _inner():\n        _gw.assert_in_egress('x')\n"
                       "    return client.messages.create(model='m', messages=[])\n")
# a non-model `.complete` (a scheduler/ledger) must NOT be flagged (no false positive)
_UNRELATED_COMPLETE = "def tick(ledger, phase):\n    ledger.complete(phase)\n    self.complete(phase)\n"


@pytest.mark.parametrize("src", [_BYPASS_CREATE, _BYPASS_STREAM, _BYPASS_COMPLETE_NAME,
                                 _BYPASS_COMPLETE_GETB, _NESTED_GUARD_WRONG])
def test_guard_catches_a_bypass(src):
    assert _violations_in_source(src), f"GREEN-WASHED: the guard failed to flag a bypass:\n{src}"


@pytest.mark.parametrize("src", [_GUARDED_CREATE, _GUARDED_COMPLETE])
def test_guard_passes_a_properly_guarded_call(src):
    assert not _violations_in_source(src), f"the guard WRONGLY flagged a guarded call:\n{src}"


def test_guard_ignores_unrelated_complete_calls():
    # calibration: `.complete` on a non-backend receiver is not a model egress and must not be flagged
    assert _count_in_source(_UNRELATED_COMPLETE) == 0
    assert not _violations_in_source(_UNRELATED_COMPLETE)


def test_guard_matches_each_egress_shape():
    # the matchers actually SEE each of the three shapes (so a drift in any one is caught by the real test)
    assert _count_in_source(_BYPASS_CREATE) == 1
    assert _count_in_source(_BYPASS_STREAM) == 1
    assert _count_in_source(_BYPASS_COMPLETE_NAME) == 1
    assert _count_in_source(_BYPASS_COMPLETE_GETB) == 1
