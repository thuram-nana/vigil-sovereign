"""Every anthropic-SDK client VIGIL builds has a BOUNDED retry (a structural guard over the source).

The anthropic SDK 2.x honours any positive Retry-After inside its own retry loop (SDK 0.x honoured only (0, 60] s), so a
client built with the SDK's default retries can stall for hours on one 429. A client is bounded when it is built with
``http_client=bounded_http_client(...)`` (``vigil_core.sdk_retry``: an out-of-bound Retry-After is dropped) or with
``max_retries=0`` (VIGIL's own capped loop does the retrying — the engine's ``AnthropicBackend``). This guard parses
every non-test module of the engine, the integration package and the sovereign app (never imports them, so it needs no
SDK) and fails on any SDK client construction that is neither — including one added later.

Mutation-verify target: drop ``http_client=bounded_http_client()`` from any construction site -> this test reds.
"""
from __future__ import annotations

import ast
from pathlib import Path

_REPO = Path(__file__).resolve().parents[6]
_ROOTS = ("engine/crucible/framework/v2", "integration/vigil_integration", "apps/sigil/sigil")
_CLIENTS = frozenset({"Anthropic", "AsyncAnthropic", "AnthropicBedrock", "AsyncAnthropicBedrock", "AnthropicVertex",
                      "AsyncAnthropicVertex", "AnthropicFoundry", "AsyncAnthropicFoundry", "AnthropicAWS",
                      "AsyncAnthropicAWS"})


def _is_test(path: Path) -> bool:
    return "tests" in path.parts or path.name.startswith("test_") or path.name == "conftest.py"


def _callee(node: ast.Call) -> str:
    f = node.func
    return f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""


def _bounded(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "max_retries" and isinstance(kw.value, ast.Constant) and kw.value.value == 0:
            return True
        if kw.arg == "http_client" and isinstance(kw.value, ast.Call) and _callee(kw.value) == "bounded_http_client":
            return True
    return False


def _constructions() -> "list[tuple[str, bool]]":
    found = []
    for root in _ROOTS:
        for path in sorted((_REPO / root).rglob("*.py")):
            if _is_test(path.relative_to(_REPO)):
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and _callee(node) in _CLIENTS:
                    found.append((f"{path.relative_to(_REPO)}:{node.lineno}", _bounded(node)))
    return found


def test_every_sdk_client_has_a_bounded_retry():
    found = _constructions()
    unbounded = [where for where, ok in found if not ok]
    assert not unbounded, ("an anthropic-SDK client without a bounded retry (pass http_client=bounded_http_client() "
                           f"or max_retries=0): {unbounded}")


def test_the_guard_sees_the_known_construction_sites():
    # never a vacuous pass: the scan must find the clients this repo is known to build
    files = {where.rsplit(":", 1)[0] for where, _ok in _constructions()}
    for expected in ("engine/crucible/framework/v2/kernel/backends/anthropic.py",
                     "engine/crucible/framework/v2/kernel/backends/bedrock.py",
                     "engine/crucible/framework/v2/kernel/backends/vertex.py",
                     "engine/crucible/framework/v2/console/chat.py",
                     "engine/crucible/framework/v2/console/actions.py",
                     "integration/vigil_integration/live/think_claude.py"):
        assert expected in files, (expected, sorted(files))
