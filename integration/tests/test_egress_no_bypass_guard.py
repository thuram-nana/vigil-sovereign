"""M4.1 no-bypass structural guard — PROVE the AI gateway is the only model-egress path.

The runtime guard (``vigil_core.ai_gateway.assert_in_egress``) fails a direct provider call closed, but only
if control actually reaches it. This STATIC guard is what makes "the gateway is the only egress path" a
FALSIFIABLE claim rather than a hope: it walks the offense (``framework.v2``), integration
(``vigil_integration``) AND sovereign (``apps/sigil``) trees and fails if ANY model-egress call site sits in a
function that does NOT assert the egress context. Such a call could reach a provider WITHOUT routing through
``vigil_core.ai_gateway.egress`` (so without classify -> redact -> authorize -> model-route -> provenance ->
audit). Add a new provider call outside the chokepoint and this test reds.

What the matchers recognise (and why each is sound):
  * ``<x>.messages.create`` / ``<x>.messages.stream`` — the Anthropic SDK completion surface. Matched by a
    ``messages`` (or ``completions``) ANCESTOR in the attribute chain, so ``client.messages.create``,
    ``client.beta.messages.create``, ``client.messages.with_raw_response.create`` and the legacy
    ``client.completions.create`` all match.
  * a ``messages``/``completions`` VARIABLE ALIAS — ``m = client.messages`` then ``m.create(...)`` (a captured
    SDK sub-client). Tracked WITHIN a function: a name assigned from a ``.messages``/``.completions`` attribute
    chain, later called ``.create``/``.stream``, is an egress the direct-chain matcher alone would miss.
  * a model-backend ``<x>.complete(...)`` — the kernel provider layer, where ``<x>`` is a Name in
    ``_BACKEND_RECEIVER_NAMES`` or a call to ``get_backend(...)`` (verified: the only model ``.complete``
    receivers in this tree; ``self.complete``/``ledger.complete`` are unrelated and must NOT be flagged).
  * a RAW-HTTP model egress — ``urllib.request.urlopen`` / ``requests.post`` / ``httpx.post`` / ``.request``
    reaching a MODEL-COMPLETION endpoint, detected by a ``/v1/messages`` or ``/v1/chat/completions`` string
    literal in the SAME function's subtree. This is how the SIGIL sovereign plane reaches Anthropic (raw
    ``urllib``, no SDK), and it also catches a raw ``httpx``/``requests`` provider call on any plane. It is
    keyed on the COMPLETION endpoint literal on purpose, so the many target-scanning HTTP POSTs in the scanner
    / sensor / executor trees (which never carry that literal) are NOT touched — no false positive.

How "egress-guarded" is defined (and why it is sound):
  * every raw provider round-trip lives in a function (an adapter's ``invoke`` closure, or a ``*_raw`` helper
    reached only from one) whose OWN body calls ``assert_in_egress`` — so when that function runs outside the
    egress context it fails closed. An ``assert_in_egress`` sitting in a NESTED function does NOT count for the
    outer function (a nested closure's guard protects the closure, not its parent's own calls).
  * the kernel backend DRIVERS (``framework/v2/kernel/backends/``) wrap the provider SDK and are reached ONLY
    through a backend ``.complete()`` call. This guard requires EVERY such ``.complete()`` call to be
    egress-guarded, so the drivers are governed transitively; they are the one allowed home for an unguarded
    ``messages.create`` (the SDK leaf), and the guard skips exactly that directory and nothing else.

Scope: the THREE planes where the M4.1 gateway contract applies. The sovereign plane (``apps/sigil``) DOES
reach a cloud provider directly (frontier vision upload + cloud memory consolidation) — those two LLM egress
sites now route through the gateway, which this guard enforces by scanning ``apps/sigil``. The sovereign plane
ALSO has NON-LLM provider egress that this guard deliberately does NOT cover: its VOICE provider (ElevenLabs
TTS text / STT audio / voice-library lookup) and its credential-validation probes are governed by the SIGIL
sovereignty tier (``sigil.sovereignty.assert_endpoint_permitted``) but are not gateway-redacted — a different
egress class, registered as a documented limitation (``docs/limitations/inventory.json``:
``LIMIT-sigil-voice-probe-egress-not-gatewayed``). Honest residual matcher misses (not covered here, by
design — they are dynamic/rare and would cost precision): a fully dynamic ``getattr(client.messages,'create')``
call, an attribute-receiver backend ``self.backend.complete``, a backend captured in a renamed local, and a
raw provider URL assembled entirely from non-literal parts.

Pure stdlib (``ast`` only) + path reads — no framework/vigil_core import — so it runs in every CI leg.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
# The three planes under the M4.1 gateway contract (offense, integration, sovereign).
_ROOTS = ("engine/crucible/framework/v2", "integration/vigil_integration", "apps/sigil/sigil")
# The provider-SDK driver leaves — reached only via a (guarded) backend.complete(); see the module docstring.
_DRIVER_LEAVES = ("engine/crucible/framework/v2/kernel/backends",)
_ASSERT = "assert_in_egress"
# Receivers that denote a MODEL BACKEND for a `.complete(...)` egress, calibrated to this codebase's naming
# (verified: the only model `.complete` receivers are these; `self.complete`/`ledger.complete` are unrelated).
# `messages.create`/`.stream` are matched structurally (a `.messages`/`.completions` ancestor) and need no list.
_BACKEND_RECEIVER_NAMES = frozenset({"backend", "primary", "cand"})
_BACKEND_RECEIVER_CALLS = frozenset({"get_backend"})
# Attribute names whose presence in a create/stream chain marks it an SDK completion call.
_SDK_SUBCLIENT_ATTRS = frozenset({"messages", "completions"})
# A string literal containing one of these marks a MODEL-COMPLETION endpoint (vs /v1/models, /v1/user, a
# target URL, an Ollama /api/generate, ...). Raw HTTP reaching such an endpoint must route through the gateway.
_COMPLETION_ENDPOINT_MARKERS = ("/v1/messages", "/v1/chat/completions")
# The HTTP-send primitives (the actual round-trip, not request construction — `Request` is capitalised).
_HTTP_SEND_ATTRS = frozenset({"urlopen", "post", "request"})
_HTTP_SEND_NAMES = frozenset({"urlopen"})


# ── the AST matchers ──────────────────────────────────────────────────────────────────────────────

def _attr_chain_names(node: ast.expr):
    """Yield the attr names of an attribute chain, from the node's own attr downward (``a.b.c`` -> c, b)."""
    while isinstance(node, ast.Attribute):
        yield node.attr
        node = node.value


def _is_sdk_create_or_stream(func: ast.expr) -> str | None:
    """``<x>.create`` / ``<x>.stream`` with a ``messages``/``completions`` ANCESTOR in its chain — the SDK
    completion surface (covers ``messages.create``, ``beta.messages.create``, ``messages.with_raw_response.
    create``, ``completions.create``). Returns a label or None."""
    if not (isinstance(func, ast.Attribute) and func.attr in ("create", "stream")):
        return None
    if any(name in _SDK_SUBCLIENT_ATTRS for name in _attr_chain_names(func.value)):
        return f"messages.{func.attr}"
    return None


def _is_alias_create_or_stream(func: ast.expr, aliases: frozenset[str]) -> str | None:
    """``<name>.create`` / ``<name>.stream`` where ``<name>`` is a tracked ``messages``/``completions`` alias
    (``m = client.messages`` captured earlier in the same function)."""
    if (isinstance(func, ast.Attribute) and func.attr in ("create", "stream")
            and isinstance(func.value, ast.Name) and func.value.id in aliases):
        return f"messages-alias.{func.attr}"
    return None


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


def _egress_kind(node: ast.AST, aliases: frozenset[str] = frozenset()) -> str | None:
    """Return a label if `node` is a (non-raw-HTTP) model-egress Call, else None. Raw-HTTP egress is matched
    separately (it needs the enclosing function's completion-endpoint context)."""
    if not isinstance(node, ast.Call):
        return None
    f = node.func
    return (_is_sdk_create_or_stream(f)
            or _is_alias_create_or_stream(f, aliases)
            or ("backend.complete" if _is_backend_complete(f) else None))


def _is_http_send(func: ast.expr) -> bool:
    """`func` is an HTTP-send primitive: ``urlopen`` (Name/attr) or a ``.post``/``.request`` attribute call."""
    if isinstance(func, ast.Attribute) and func.attr in _HTTP_SEND_ATTRS:
        return True
    return isinstance(func, ast.Name) and func.id in _HTTP_SEND_NAMES


def _subtree_has_completion_literal(fn: ast.AST) -> bool:
    """True iff `fn`'s subtree contains a ``/v1/messages`` or ``/v1/chat/completions`` string literal — i.e.
    `fn` reaches a MODEL-COMPLETION endpoint (not /v1/models, a target URL, or an Ollama /api/generate)."""
    for node in ast.walk(fn):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if any(mk in node.value for mk in _COMPLETION_ENDPOINT_MARKERS):
                return True
    return False


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


def _messages_alias_names(fn: ast.AST) -> frozenset[str]:
    """Names assigned (in `fn`'s OWN body, not nested scopes) a value whose attribute chain contains
    ``messages``/``completions`` — a captured SDK sub-client (``m = client.messages``). A later
    ``m.create(...)`` is then an SDK egress the direct-chain matcher would miss."""
    names: set[str] = set()
    for node in _own_nodes(fn):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Attribute):
            if any(name in _SDK_SUBCLIENT_ATTRS for name in _attr_chain_names(node.value)):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        names.add(tgt.id)
    return frozenset(names)


class _Scan(ast.NodeVisitor):
    """Collect every model-egress call paired with its NEAREST enclosing function def (None at module level).
    Tracks a per-function alias set (for ``m = client.messages``) and, separately, raw-HTTP send sites."""

    def __init__(self) -> None:
        self._stack: list[ast.AST] = []
        self._alias_stack: list[frozenset[str]] = []
        self.hits: list[tuple[str, int, ast.AST | None]] = []
        self.http_hits: list[tuple[int, ast.AST | None]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._stack.append(node)
        self._alias_stack.append(_messages_alias_names(node))
        self.generic_visit(node)
        self._alias_stack.pop()
        self._stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Call(self, node: ast.Call):
        aliases = self._alias_stack[-1] if self._alias_stack else frozenset()
        kind = _egress_kind(node, aliases)
        if kind:
            self.hits.append((kind, node.lineno, self._stack[-1] if self._stack else None))
        if _is_http_send(node.func):
            self.http_hits.append((node.lineno, self._stack[-1] if self._stack else None))
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
    # raw-HTTP model egress: a send whose NEAREST enclosing function reaches a model-completion endpoint must
    # assert the egress context too.
    for lineno, fn in scan.http_hits:
        if fn is None or not _subtree_has_completion_literal(fn):
            continue
        if not _fn_directly_asserts(fn):
            where = getattr(fn, "name", None) or "<module>"
            out.append(f"{label}:{lineno}: raw-HTTP model egress in {where}() does not assert_in_egress")
    return out


def _count_in_source(src: str) -> int:
    """SDK/backend egress sites (guarded or not) — the drift tripwire for the non-raw matchers."""
    scan = _Scan()
    scan.visit(ast.parse(src))
    return len(scan.hits)


def _count_raw_http_sites(src: str) -> int:
    """RAW-HTTP model-completion egress sites (guarded or not) — the drift tripwire for the raw matcher."""
    scan = _Scan()
    scan.visit(ast.parse(src))
    return sum(1 for _ln, fn in scan.http_hits if fn is not None and _subtree_has_completion_literal(fn))


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
    """EVERY model-egress call in the offense + integration + sovereign trees is egress-guarded (or a driver
    leaf)."""
    violations: list[str] = []
    total = 0
    raw_total = 0
    scanned = 0
    for path, rel in _iter_product_py():
        scanned += 1
        src = path.read_text(encoding="utf-8", errors="replace")
        hits = _violations_in_source(src, label=rel)
        # count all egress sites (guarded or not) for the no-op tripwires below
        total += _count_in_source(src)
        raw_total += _count_raw_http_sites(src)
        violations.extend(hits)
    assert scanned > 50, f"the guard scanned only {scanned} files — root/layout drift?"
    # Tripwire: if the SDK/backend matchers ever stop MATCHING (a refactor renames the SDK surface), this
    # catches the silent no-op. We route >= 8 application sites plus the URK failover + the raw helpers.
    assert total >= 8, (f"the guard found only {total} SDK/backend model-egress sites — the matchers may have "
                        f"drifted and silently stopped seeing provider calls")
    # Tripwire: the raw-HTTP matcher must see the SIGIL sovereign-plane egress sites (frontier vision upload +
    # cloud memory consolidation). If routing is removed/moved this drops below 2 and reds.
    assert raw_total >= 2, (f"the raw-HTTP matcher found only {raw_total} model-completion egress sites — the "
                            f"sovereign-plane routing may have moved (expected >= 2: vision + consolidation)")
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
_BYPASS_COMPLETIONS = "def leak(client):\n    return client.completions.create(prompt='x')\n"
_BYPASS_WITH_RAW = ("def leak(client):\n"
                    "    return client.messages.with_raw_response.create(model='m', messages=[])\n")
_BYPASS_ALIAS = ("def leak(client):\n    m = client.messages\n    return m.create(model='m', messages=[])\n")
_BYPASS_BETA = "def leak(client):\n    return client.beta.messages.create(model='m', messages=[])\n"
_BYPASS_RAW_HTTPX = ("import httpx\ndef leak(body):\n"
                     "    return httpx.post('https://api.anthropic.com/v1/messages', json=body)\n")
_BYPASS_RAW_REQUESTS = ("import requests\ndef leak(body):\n"
                        "    return requests.post('https://api.anthropic.com/v1/messages', json=body)\n")
_BYPASS_RAW_OPENAI = ("def leak(client, body):\n"
                      "    return client.post('https://api.openai.com/v1/chat/completions', json=body)\n")
_BYPASS_RAW_URLOPEN = ("import urllib.request\ndef leak(req):\n"
                       "    url = 'https://api.anthropic.com/v1/messages'\n"
                       "    return urllib.request.urlopen(req)\n")
_GUARDED_CREATE = ("def ok(client):\n    _gw.assert_in_egress('x')\n"
                   "    return client.messages.create(model='m', messages=[])\n")
_GUARDED_COMPLETE = "def ok(prompt):\n    assert_in_egress('x')\n    return backend.complete(prompt)\n"
_GUARDED_RAW_HTTP = ("import urllib.request\ndef ok(req):\n    _gw.assert_in_egress('x')\n"
                     "    url = 'https://api.anthropic.com/v1/messages'\n"
                     "    return urllib.request.urlopen(req)\n")
# an assert in a NESTED function must NOT satisfy the OUTER function's own egress call
_NESTED_GUARD_WRONG = ("def outer(client):\n    def _inner():\n        _gw.assert_in_egress('x')\n"
                       "    return client.messages.create(model='m', messages=[])\n")
# a non-model `.complete` (a scheduler/ledger) must NOT be flagged (no false positive)
_UNRELATED_COMPLETE = "def tick(ledger, phase):\n    ledger.complete(phase)\n    self.complete(phase)\n"
# a RAW HTTP POST to a NON-model endpoint (a scanner hitting a target) must NOT be flagged — the guard keys
# on the model-completion endpoint literal, so target-scanning HTTP is never touched.
_UNRELATED_RAW_HTTP = ("import requests\ndef scan(target):\n"
                       "    return requests.post(target + '/login', data={'u': 'x'})\n")
# a LOCAL on-box model POST (Ollama /api/generate) carries no completion-endpoint literal → NOT flagged.
_LOCAL_OLLAMA = ("import urllib.request\ndef gen(req):\n"
                 "    url = 'http://127.0.0.1:11434/api/generate'\n"
                 "    return urllib.request.urlopen(req)\n")
# a plain `.create` on a non-SDK object (not a messages alias) must NOT be flagged (no false positive).
_UNRELATED_CREATE = "def build(factory):\n    return factory.create(name='widget')\n"


@pytest.mark.parametrize("src", [_BYPASS_CREATE, _BYPASS_STREAM, _BYPASS_COMPLETE_NAME,
                                 _BYPASS_COMPLETE_GETB, _BYPASS_BETA, _NESTED_GUARD_WRONG])
def test_guard_catches_a_bypass(src):
    assert _violations_in_source(src), f"GREEN-WASHED: the guard failed to flag a bypass:\n{src}"


@pytest.mark.parametrize("src", [_BYPASS_COMPLETIONS, _BYPASS_WITH_RAW, _BYPASS_ALIAS])
def test_guard_catches_the_broadened_sdk_shapes(src):
    # completions.create, messages.with_raw_response.create, and a `m = client.messages` alias — the shapes
    # the red-pen named as gaps. Each is now flagged.
    assert _violations_in_source(src), f"GREEN-WASHED: broadened SDK shape not flagged:\n{src}"


@pytest.mark.parametrize("src", [_BYPASS_RAW_HTTPX, _BYPASS_RAW_REQUESTS, _BYPASS_RAW_OPENAI,
                                 _BYPASS_RAW_URLOPEN])
def test_guard_catches_raw_http_model_egress(src):
    # a raw urllib/requests/httpx call to a model-COMPLETION endpoint, outside the egress context, is flagged.
    assert _violations_in_source(src), f"GREEN-WASHED: raw-HTTP model egress not flagged:\n{src}"


@pytest.mark.parametrize("src", [_GUARDED_CREATE, _GUARDED_COMPLETE, _GUARDED_RAW_HTTP])
def test_guard_passes_a_properly_guarded_call(src):
    assert not _violations_in_source(src), f"the guard WRONGLY flagged a guarded call:\n{src}"


@pytest.mark.parametrize("src", [_UNRELATED_COMPLETE, _UNRELATED_RAW_HTTP, _LOCAL_OLLAMA, _UNRELATED_CREATE])
def test_guard_ignores_unrelated_calls(src):
    # calibration: a non-backend `.complete`, a target-scanning HTTP POST, a LOCAL Ollama POST, and a plain
    # `.create` on a non-SDK object are not model egress and must not be flagged (no false positive).
    assert not _violations_in_source(src), f"FALSE POSITIVE: the guard wrongly flagged:\n{src}"


def test_guard_ignores_unrelated_complete_calls():
    # retained by name: `.complete` on a non-backend receiver is not a model egress and must not be flagged
    assert _count_in_source(_UNRELATED_COMPLETE) == 0
    assert not _violations_in_source(_UNRELATED_COMPLETE)


def test_guard_matches_each_egress_shape():
    # the matchers actually SEE each shape (so a drift in any one is caught by the real test)
    assert _count_in_source(_BYPASS_CREATE) == 1
    assert _count_in_source(_BYPASS_STREAM) == 1
    assert _count_in_source(_BYPASS_COMPLETE_NAME) == 1
    assert _count_in_source(_BYPASS_COMPLETE_GETB) == 1
    assert _count_in_source(_BYPASS_COMPLETIONS) == 1
    assert _count_in_source(_BYPASS_WITH_RAW) == 1
    assert _count_in_source(_BYPASS_ALIAS) == 1
    assert _count_raw_http_sites(_BYPASS_RAW_HTTPX) == 1
    assert _count_raw_http_sites(_BYPASS_RAW_OPENAI) == 1
    assert _count_raw_http_sites(_LOCAL_OLLAMA) == 0        # local Ollama is not a completion endpoint
    assert _count_raw_http_sites(_UNRELATED_RAW_HTTP) == 0  # target scan is not a completion endpoint
