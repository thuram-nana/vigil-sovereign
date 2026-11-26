"""
aegis.closure — a static import-CLOSURE analyzer + deny list for the AEGIS SaaS defense image.

AS-28 ("closure + image", D34) addresses the HIGH finding *"offense code in the defense runtime"*
(plan §1 defect #9; threats T-7 / K13 / SaaS-9): the AEGIS gateway is a public-facing DATA PLANE that
sits inline in front of a customer's app, yet its process used to import the offensive engine — OOB
servers, credential-capture primitives, active-recon, token forgers, the agent EXECUTOR layer. An
attacker with code execution in that unit should find NO offensive machinery already loaded to abuse.

This module is the proof mechanism. It walks the module-level import graph FROM the gateway serving
entrypoint — SOUNDLY: reaching a submodule ``a.b.c`` also runs every ancestor package ``__init__``
(``a``, ``a.b``), which is exactly how the eager ``verify/__init__`` used to drag the offense tree in,
so the ancestor ``__init__`` files are parsed too — and refuses (FAIL CLOSED) if any module on the DENY
LIST is reachable, or if a first-party module cannot be located/parsed (unknown reachable code = deny).

Two soundness holes the red-pen found, now closed (both in the analyzer, backed by the runtime probe):
  * PEP 562 LAZY RE-EXPORT. A package whose ``__init__`` defines a module-level ``__getattr__`` plus a
    static ``_LAZY_SYMBOLS`` / ``_SUBMODULES`` map (``verify/__init__`` is exactly this) resolves
    ``from pkg import Symbol`` to a submodule ON FIRST ACCESS — a real import-time edge when the symbol
    is imported at module scope. The walk now PARSES that map and follows the lazy edge (fail-closed on
    an unknown symbol / an unparseable shim), so ``from framework.v2.verify import OOBReceiver`` is seen
    to reach ``framework.v2.verify.oob`` and is denied.
  * LAZY OFFENSE IN THE SERVING CODE. A function-local offense import in a defense SERVING module does
    not run at import time (so the module-level walk, correctly modelling Python, leaves it out of the
    closure) — but it is still offense wired into the serve path. A conservative overlay now scans EVERY
    import (module scope AND function/method bodies, excluding ``if TYPE_CHECKING:``) of every reachable
    ``framework.v2.aegis`` serving module and FAILS on any denied target. It is as strong as the
    module-level walk — it resolves a LITERAL ``from ..verify.oob import X``, a PEP 562 lazy re-export
    (``from framework.v2.verify import OOBReceiver`` -> the denied ``verify.oob``; fail-closed on an opaque
    shim) AND a dynamic-string ``importlib.import_module("framework.v2.verify.oob")`` / ``__import__(...)`` —
    so none of those forms can smuggle a denied module into a serving function body past the gate. (It is
    deliberately scoped to the AEGIS-owned serving layer: the shared engine's ``verify``/``agents`` code
    legitimately reaches offense submodules at INVOKE time, which the runtime probe — not this static
    overlay — governs.)

Design invariants (constitution: determinism, fail-closed, no over-claim):
  * PURE + DETERMINISTIC. No imports are executed, no network, no wall-clock, no RNG. The result is a
    deterministic function of the on-disk source; outputs are sorted. (Executing the graph to observe it
    is self-defeating here — it would load the very offense code we are proving absent.)
  * FAIL CLOSED. A first-party module that cannot be resolved or whose AST will not parse — or a PEP 562
    lazy shim whose map cannot be statically read — is a violation, never a silent pass.
    ``check_saas_closure(...).ok`` is True only when the reachable set is clean, fully resolved, AND no
    serving module carries a lazy offense import.
  * MODULE-LEVEL for the CLOSURE. The reachable set follows only import-time edges (imports nested in a
    ``def``/``async def`` are LAZY and are NOT added to it); the serving-module lazy scan above is a
    SEPARATE conservative gate, not part of the closure.
  * NO OVER-CLAIM. The enforced deny list is the part AS-28 keeps green; the ``KNOWN_RESIDUAL`` set (the
    offense agent-EXECUTOR coupling still pulled via the eager ``intel`` → ``planner`` → ``agents``
    package ``__init__`` chain) is import-reachable TODAY, so it is tracked by a shrink-only ratchet and
    DISCLOSED (never claimed absent) — see the module notes, ``saas-closure.json`` and the public
    Dockerfile.saas / docker-compose banners.

The companion RUNTIME check (block ``anthropic`` / the agent SDKs via an import hook, import the
entrypoints, then assert NO ``is_denied`` module — first-party offense OR third-party SDK — is in
``sys.modules``) lives in the test; it is the robust backstop that catches any dynamic/transitive/eager
path this static pass does not model. The two together are the closure proof the plan calls for.
"""

from __future__ import annotations

import ast
import pathlib
from dataclasses import dataclass, field

# closure.py -> aegis -> v2 -> framework -> engine/crucible (the dir that CONTAINS the ``framework`` pkg).
_ENGINE_ROOT = pathlib.Path(__file__).resolve().parents[3]

# Top-level first-party package name -> the directory that contains it. ONLY these are walked; anything
# else (stdlib, pydantic, httpx, vigil_core, …) is an external LEAF — recorded, deny-checked by name, but
# never parsed (we neither can nor should parse site-packages, and the deny contract is about NAMES).
_FIRST_PARTY_ROOTS: dict[str, pathlib.Path] = {"framework": _ENGINE_ROOT}

# The AEGIS SaaS serving entrypoints. The deployed image runs ``python3 -m framework.v2 aegis gateway``;
# ``framework.v2.__main__`` dispatches that LAZILY (``_aegis`` imports the handler function-locally), so
# the honest runtime closure of the container is the aegis serve path: the ``cli`` the dispatch loads and
# the ``gateway`` it serves. Both are analysed (their union) so a lazy edge on one is covered by the other.
SAAS_ENTRYPOINTS: tuple[str, ...] = (
    "framework.v2.aegis.cli",
    "framework.v2.aegis.gateway",
)

# The defense-owned SERVING layer this slice authors and controls. A reachable module under this package
# must carry NO denied import anywhere in its source — module scope OR a function/method body — so a lazy
# offense import cannot be smuggled into the serve path past the module-level closure walk (see the
# ``_serving_lazy_denied`` conservative overlay). The shared engine packages (``verify``/``agents``/…) are
# intentionally OUT of this scope: they reach offense submodules only at INVOKE time, which the runtime
# probe governs, and the ``agents`` executor coupling they pull at import is the tracked KNOWN_RESIDUAL.
_SERVING_MODULE_PREFIX = "framework.v2.aegis"


# --------------------------------------------------------------------------------------------------
# THE DENY LIST — the authoritative contract: none of this may be import-reachable from the entrypoint.
# --------------------------------------------------------------------------------------------------

# (1) Third-party packages a DEFENSE image must never load. The LLM/agent SDKs are the offense engine's
#     reasoning layer; ``strix`` is the bolt-on offensive agent. A top-level name ``p`` denies ``p`` and
#     every ``p.*``. (The literal "also with ``anthropic`` blocked" deliverable is the head of this list.)
DENIED_THIRD_PARTY: frozenset[str] = frozenset({
    "anthropic", "openai", "agents",  # ``agents`` == the openai-agents SDK (top-level); NOT framework.v2.agents
    "litellm", "langchain", "langchain_core", "langchain_community", "langgraph",
    "autogen", "cohere", "strix",
})

# (2) First-party OFFENSE modules/packages that must never be import-reachable from the defense serve
#     path. A prefix ``m`` denies ``m`` and every ``m.*``.
#       - the offense engine's attack/exec subpackages (not reachable today; denied to keep it that way);
#       - the ACTIVE-OFFENSE verify submodules the AS-28 lazy-``verify/__init__`` change removed from the
#         closure: OOB servers, live recon, credential capture, token forgery, privilege-path, PoC gen.
DENIED_OFFENSE_PREFIXES: frozenset[str] = frozenset({
    # offense engine attack/execution surface
    "framework.v2.engage",
    "framework.v2.scanner",
    "framework.v2.exploit",
    "framework.v2.benchmark",
    "framework.v2.redteam",
    # active-offense verify submodules (removed from the defense closure by AS-28; kept out by this gate)
    "framework.v2.verify.oob",
    "framework.v2.verify.dns_collector",
    "framework.v2.verify.collaborator",
    "framework.v2.verify.collaborator_cli",
    "framework.v2.verify.reachability",
    "framework.v2.verify.reachability_cloud",
    "framework.v2.verify.tls",
    "framework.v2.verify.imds_capture",
    "framework.v2.verify.secret_capture",
    "framework.v2.verify.gcp_impersonation_capture",
    "framework.v2.verify.iam_escalation_capture",
    "framework.v2.verify.k8s_rbac_grant",
    "framework.v2.verify.jwt_forgery",
    "framework.v2.verify.saml_forgery",
    "framework.v2.verify.policy_path",
    "framework.v2.verify.poc_translate",
    "framework.v2.verify.replay_harness",
})

# (3) KNOWN RESIDUAL — tracked, NOT yet enforced (honest deferral). The offense AGENT-EXECUTOR layer is
#     still import-reachable from the gateway because the ``intel`` world-model it needs re-exports through
#     EAGER ``intel/__init__`` → ``planner/__init__`` → ``agents/__init__`` package inits. Closing that is
#     the SAME lazy-package move as AS-28's verify fix, but applied to offense-core packages OUTSIDE
#     AS-28's VERIFY token lane and requiring a ``make gate`` byte-identity re-baseline — so it is deferred
#     to the companion GW / engine-core decoupling. The test RATCHETS this set: it may SHRINK, never GROW.
KNOWN_RESIDUAL: frozenset[str] = frozenset({
    "framework.v2.agents",
    "framework.v2.agents.base",
    "framework.v2.agents.blackboard",
    "framework.v2.agents.coordinator",
    "framework.v2.agents.egress_guard",
    "framework.v2.agents.executor_proto",
    "framework.v2.agents.http_executor",
    "framework.v2.agents.models",
    "framework.v2.agents.realistic_executor",
    "framework.v2.agents.scope_gate",
    "framework.v2.agents.tools",
    "framework.v2.agents.tools.base",
    "framework.v2.agents.tools.builtin",
    "framework.v2.agents.tools.invoker",
})


def is_denied(module: str) -> str | None:
    """Return a human reason if ``module`` is on the deny list, else None. Matches a third-party top-level
    name (``p`` or ``p.*``) or a first-party offense prefix (``m`` or ``m.*``)."""
    top = module.split(".", 1)[0]
    if top in DENIED_THIRD_PARTY:
        return f"denied third-party package {top!r}"
    for pfx in DENIED_OFFENSE_PREFIXES:
        if module == pfx or module.startswith(pfx + "."):
            return f"denied offense module (prefix {pfx!r})"
    return None


# --------------------------------------------------------------------------------------------------
# Static import-graph walk.
# --------------------------------------------------------------------------------------------------

def _resolve_first_party_file(module: str) -> tuple[pathlib.Path | None, bool]:
    """Map a first-party module name to its source file. Returns (path, is_package). (None, False) when
    the module is EXTERNAL (top-level not first-party) or genuinely not found on disk."""
    parts = module.split(".")
    root = _FIRST_PARTY_ROOTS.get(parts[0])
    if root is None:
        return None, False
    pkg_init = root.joinpath(*parts, "__init__.py")
    if pkg_init.is_file():
        return pkg_init, True
    mod_file = root.joinpath(*parts).with_suffix(".py")
    if mod_file.is_file():
        return mod_file, False
    return None, False


def _ancestors(module: str) -> list[str]:
    """The ancestor PACKAGES Python imports (running each ``__init__``) before ``module`` itself —
    ``a.b.c`` -> [``a``, ``a.b``]. These are where eager package inits hide their offense pulls."""
    parts = module.split(".")
    return [".".join(parts[:i]) for i in range(1, len(parts))]


def _resolve_relative(current_pkg: str, level: int, module: str | None) -> str:
    """Resolve a relative import target to an absolute module name. ``current_pkg`` is the package the
    importing file lives in (the module itself if it is an ``__init__``, else its parent)."""
    parts = current_pkg.split(".") if current_pkg else []
    if level > 1:
        parts = parts[: len(parts) - (level - 1)]
    base = ".".join(parts)
    if module:
        return f"{base}.{module}" if base else module
    return base


class _ModuleLevelImports(ast.NodeVisitor):
    """Collect import targets that execute AT MODULE LOAD — i.e. NOT inside a function/lambda body. A
    class body DOES run at import, so imports directly under a class are included; imports under a ``def``
    are lazy and skipped. Also captures ``importlib.import_module("literal")`` / ``__import__("literal")``
    string-literal dynamic imports at module scope, so a statically-named denied package cannot hide."""

    def __init__(self, current_pkg: str, is_pkg: bool) -> None:
        self.current_pkg = current_pkg
        self.is_pkg = is_pkg
        # each entry: (absolute_base_module, tuple_of_from_names). from_names=() for plain ``import a.b``.
        self.raw: list[tuple[str, tuple[str, ...]]] = []
        self.dynamic: list[str] = []

    # ``if TYPE_CHECKING:`` / ``if typing.TYPE_CHECKING:`` bodies are PROVABLY DEAD at import time
    # (``typing.TYPE_CHECKING`` is always False at runtime), so their imports never execute — model the
    # runtime closure by taking only the ELSE branch. Any other ``if`` is followed on both branches.
    def visit_If(self, node: ast.If) -> None:  # noqa: N802
        test = node.test
        is_type_checking = (
            (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING")
            or (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")
        )
        branches = node.orelse if is_type_checking else [*node.body, *node.orelse]
        for stmt in branches:
            self.visit(stmt)

    # do NOT descend into function bodies — those imports are lazy.
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
        return

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            self.raw.append((alias.name, ()))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        if node.level:
            base = _resolve_relative(
                self.current_pkg if self.is_pkg else self.current_pkg,
                node.level,
                node.module,
            )
        else:
            base = node.module or ""
        if base:
            self.raw.append((base, tuple(a.name for a in node.names)))

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        fn = node.func
        is_dynamic_import = (
            (isinstance(fn, ast.Attribute) and fn.attr == "import_module")
            or (isinstance(fn, ast.Name) and fn.id == "__import__")
        )
        if is_dynamic_import and node.args:
            arg0 = node.args[0]
            if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str) and arg0.value:
                self.dynamic.append(arg0.value)
        self.generic_visit(node)


# --------------------------------------------------------------------------------------------------
# PEP 562 lazy-re-export (``__getattr__``) awareness. A package ``__init__`` that defines a module-level
# ``__getattr__`` plus a static ``_LAZY_SYMBOLS`` (symbol -> submodule) and/or ``_SUBMODULES`` (submodule
# names) map imports the mapped submodule ON FIRST ACCESS of the name. So ``from pkg import Sym`` at module
# scope is a REAL import-time edge to ``pkg.<submodule>`` even though ``__init__`` holds no such ``import``.
# ``verify/__init__`` is exactly this shim; the walk must follow it (and fail closed when it cannot read it).
# --------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class _Pep562Shim:
    """The statically-read lazy surface of a package ``__init__`` with a module-level ``__getattr__``.
    ``opaque`` is True when ``__getattr__`` is present but its lazy map could not be read as concrete string
    literals — then a ``from pkg import X`` whose ``X`` we cannot classify is treated as UNRESOLVED (fail
    closed), because we cannot prove which submodule (if any) it pulls."""

    lazy_symbols: dict[str, str]
    submodules: frozenset[str]
    opaque: bool


def _literal_str_dict(node: ast.AST | None) -> dict[str, str] | None:
    """A ``{str: str, ...}`` literal as a dict, or None if ``node`` is not a pure str->str literal."""
    if not isinstance(node, ast.Dict):
        return None
    out: dict[str, str] = {}
    for k, v in zip(node.keys, node.values):
        if (isinstance(k, ast.Constant) and isinstance(k.value, str)
                and isinstance(v, ast.Constant) and isinstance(v.value, str)):
            out[k.value] = v.value
        else:
            return None  # a non-literal entry -> cannot trust the map
    return out


def _literal_str_set(node: ast.AST | None) -> frozenset[str] | None:
    """A set/list/tuple of str literals (bare, or wrapped in ``frozenset(...)`` / ``set(...)``), else None."""
    target = node
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id in ("frozenset", "set")):
        if not node.args:
            return frozenset()
        target = node.args[0]
    if isinstance(target, (ast.Set, ast.List, ast.Tuple)):
        vals: list[str] = []
        for e in target.elts:
            if isinstance(e, ast.Constant) and isinstance(e.value, str):
                vals.append(e.value)
            else:
                return None
        return frozenset(vals)
    return None


def _parse_pep562_shim(tree: ast.Module) -> _Pep562Shim | None:
    """Read a package ``__init__`` AST for a PEP 562 lazy shim: a module-level ``def __getattr__`` plus the
    ``_LAZY_SYMBOLS`` / ``_SUBMODULES`` maps. Returns None when there is no ``__getattr__`` (not a shim)."""
    has_getattr = False
    lazy_symbols: dict[str, str] | None = None
    submodules: frozenset[str] | None = None
    lazy_marker = subs_marker = False
    for stmt in tree.body:
        if isinstance(stmt, ast.FunctionDef) and stmt.name == "__getattr__":
            has_getattr = True
            continue
        value: ast.AST | None = None
        names: list[str] = []
        if isinstance(stmt, ast.Assign):
            names = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
            value = stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            names = [stmt.target.id]
            value = stmt.value
        for nm in names:
            if nm == "_LAZY_SYMBOLS":
                lazy_marker = True
                lazy_symbols = _literal_str_dict(value)
            elif nm == "_SUBMODULES":
                subs_marker = True
                submodules = _literal_str_set(value)
    if not has_getattr:
        return None
    parseable = (lazy_symbols is not None) or (submodules is not None)
    unparseable_marker = (lazy_marker and lazy_symbols is None) or (subs_marker and submodules is None)
    return _Pep562Shim(
        lazy_symbols=lazy_symbols or {},
        submodules=submodules or frozenset(),
        opaque=(not parseable) or unparseable_marker,
    )


_SHIM_CACHE: dict[str, _Pep562Shim | None] = {}


def _shim_for_package(init_path: pathlib.Path) -> _Pep562Shim | None:
    """The lazy shim of the package whose ``__init__`` is ``init_path`` (cached; deterministic in the source)."""
    key = str(init_path)
    if key not in _SHIM_CACHE:
        try:
            _SHIM_CACHE[key] = _parse_pep562_shim(ast.parse(init_path.read_text(encoding="utf-8"), filename=key))
        except (OSError, SyntaxError):
            _SHIM_CACHE[key] = None
    return _SHIM_CACHE[key]


def _module_imports(module: str, path: pathlib.Path, is_pkg: bool) -> set[str]:
    """The set of ABSOLUTE module names ``module`` reaches at import time. For ``from base import a, b`` we
    add ``base`` (its ``__init__`` runs), each ``base.<name>`` that resolves to a real submodule (so
    ``from ..verify import oob`` is caught), and — when ``base`` is a PEP 562 lazy shim — the submodule each
    lazily-re-exported ``<name>`` resolves to (so ``from ..verify import OOBReceiver`` reaches
    ``verify.oob``), failing closed on an opaque shim. ``ast.parse`` failure propagates to a fail-closed
    error (the caller records it as unresolved)."""
    current_pkg = module if is_pkg else module.rpartition(".")[0]
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    visitor = _ModuleLevelImports(current_pkg, is_pkg)
    visitor.visit(tree)

    out: set[str] = set()
    for base, from_names in visitor.raw:
        out.add(base)
        base_path, base_is_pkg = _resolve_first_party_file(base)
        shim = _shim_for_package(base_path) if (base_is_pkg and base_path is not None) else None
        for name in from_names:
            if name == "*":
                continue
            candidate = f"{base}.{name}"
            cpath, _ = _resolve_first_party_file(candidate)
            if cpath is not None:  # ``name`` is a real submodule -> importing it runs it
                out.add(candidate)
                continue
            if shim is not None:
                sub = shim.lazy_symbols.get(name)
                if sub is None and name in shim.submodules:
                    sub = name
                if sub is not None:
                    out.add(f"{base}.{sub}")  # lazy re-export edge; missing submodule -> unresolved (fail closed)
                    continue
                if shim.opaque:
                    out.add(candidate)  # cannot read the shim's map -> enqueue; unresolvable => fail closed
                    continue
            # else: an EAGER re-export (its module is already followed by parsing ``base``'s ``__init__``)
            # or a plain re-exported value -> no extra import-time module to enqueue.
    out.update(visitor.dynamic)
    return out


class _AllImports(ast.NodeVisitor):
    """Collect EVERY import target — module scope AND inside function/method bodies — as (base, from_names,
    lineno), SKIPPING provably-dead ``if TYPE_CHECKING:`` branches (those imports never run). Also captures
    ``importlib.import_module("literal")`` / ``__import__("literal")`` string-literal dynamic imports as
    (literal, lineno) in ``dynamic`` — mirroring ``_ModuleLevelImports`` — so a statically-named denied
    package cannot hide behind the dynamic form in a serving function body. Used only by the conservative
    serving-module lazy-offense scan; it does NOT feed the import closure."""

    def __init__(self, current_pkg: str) -> None:
        self.current_pkg = current_pkg
        self.targets: list[tuple[str, tuple[str, ...], int]] = []
        self.dynamic: list[tuple[str, int]] = []  # (literal_module_name, lineno)

    def visit_If(self, node: ast.If) -> None:  # noqa: N802
        test = node.test
        is_type_checking = (
            (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING")
            or (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")
        )
        for stmt in (node.orelse if is_type_checking else [*node.body, *node.orelse]):
            self.visit(stmt)

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            self.targets.append((alias.name, (), node.lineno))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        base = _resolve_relative(self.current_pkg, node.level, node.module) if node.level else (node.module or "")
        if base:
            self.targets.append((base, tuple(a.name for a in node.names), node.lineno))

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        fn = node.func
        is_dynamic_import = (
            (isinstance(fn, ast.Attribute) and fn.attr == "import_module")
            or (isinstance(fn, ast.Name) and fn.id == "__import__")
        )
        if is_dynamic_import and node.args:
            arg0 = node.args[0]
            if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str) and arg0.value:
                self.dynamic.append((arg0.value, node.lineno))
        self.generic_visit(node)


def _serving_lazy_denied(reachable: frozenset[str]) -> tuple[tuple[str, str, int], ...]:
    """Every denied import target that appears ANYWHERE — module scope OR a function/method body, excluding
    ``if TYPE_CHECKING:`` — in a reachable AEGIS SERVING module (``_SERVING_MODULE_PREFIX``). The module-level
    closure already catches eager offense; this conservative overlay additionally forbids a LAZY/function-
    local offense import smuggled into the serve path. It is as strong as the module-level walk: besides a
    literal ``from a.b import c`` it also resolves PEP 562 lazy re-exports (``from framework.v2.verify import
    OOBReceiver`` -> the denied ``verify.oob``, fail-closed on an opaque shim) and captures
    ``importlib.import_module("literal")`` / ``__import__("literal")`` dynamic-string imports. Returns sorted
    ``(module, denied_target, lineno)``."""
    out: list[tuple[str, str, int]] = []
    for module in reachable:
        if not (module == _SERVING_MODULE_PREFIX or module.startswith(_SERVING_MODULE_PREFIX + ".")):
            continue
        path, is_pkg = _resolve_first_party_file(module)
        if path is None:
            continue  # unresolved serving module is a fail-closed violation via ``import_closure`` itself
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError):
            continue  # likewise handled (fail-closed) by ``import_closure``
        current_pkg = module if is_pkg else module.rpartition(".")[0]
        visitor = _AllImports(current_pkg)
        visitor.visit(tree)
        for base, names, lineno in visitor.targets:
            if is_denied(base) is not None:
                out.append((module, base, lineno))
                continue
            # PEP 562 shim of ``base`` (if it is a first-party package) — mirrors ``_module_imports`` so a
            # lazily re-exported from-name that pulls a denied submodule cannot hide behind a clean ``base``.
            base_path, base_is_pkg = _resolve_first_party_file(base)
            shim = _shim_for_package(base_path) if (base_is_pkg and base_path is not None) else None
            for name in names:
                if name == "*":
                    continue
                cand = f"{base}.{name}"
                cpath, _ = _resolve_first_party_file(cand)
                if cpath is not None:  # ``name`` is a real submodule -> importing it runs that module
                    if is_denied(cand) is not None:
                        out.append((module, cand, lineno))
                    continue
                if shim is not None:
                    sub = shim.lazy_symbols.get(name)
                    if sub is None and name in shim.submodules:
                        sub = name
                    if sub is not None:  # lazy re-export edge -> the real submodule it pulls
                        resolved = f"{base}.{sub}"
                        if is_denied(resolved) is not None:
                            out.append((module, resolved, lineno))
                        continue
                    if shim.opaque:  # cannot read the map -> cannot prove ``name`` is not denied -> fail closed
                        out.append((module, cand, lineno))
                        continue
                # else: a literal denied NAME with no real submodule/shim (e.g. a bare ``from a import b``
                # whose ``a.b`` is on the deny prefix) is still caught by name.
                if is_denied(cand) is not None:
                    out.append((module, cand, lineno))
        for literal, lineno in visitor.dynamic:
            if is_denied(literal) is not None:  # importlib.import_module("framework.v2.verify.oob") et al.
                out.append((module, literal, lineno))
    return tuple(sorted(out))


@dataclass(frozen=True)
class ClosureResult:
    """The import closure of one or more entrypoints. ``reachable`` is every module name that loads at
    import time (first-party + external leaves + ancestor packages). ``unresolved_first_party`` are
    first-party names under a known root that have no file or will not parse — fail-closed violations."""

    entrypoints: tuple[str, ...]
    reachable: frozenset[str]
    external: frozenset[str] = field(default_factory=frozenset)
    unresolved_first_party: frozenset[str] = field(default_factory=frozenset)


def import_closure(entrypoints: tuple[str, ...] | list[str]) -> ClosureResult:
    """Compute the module-level import closure of ``entrypoints`` (BFS), including every ancestor package
    (their ``__init__`` runs). First-party modules are parsed and followed; external modules are recorded
    leaves. A first-party module that will not resolve/parse is recorded as unresolved (fail-closed)."""
    reachable: set[str] = set()
    external: set[str] = set()
    unresolved: set[str] = set()
    worklist: list[str] = []
    seen: set[str] = set()

    def enqueue(name: str) -> None:
        if name and name not in seen:
            seen.add(name)
            worklist.append(name)

    for ep in entrypoints:
        for anc in _ancestors(ep):
            enqueue(anc)
        enqueue(ep)

    while worklist:
        module = worklist.pop()
        reachable.add(module)
        for anc in _ancestors(module):
            if anc not in reachable:
                enqueue(anc)
        path, is_pkg = _resolve_first_party_file(module)
        if path is None:
            if module.split(".", 1)[0] in _FIRST_PARTY_ROOTS:
                unresolved.add(module)  # first-party but no file on disk -> refuse
            else:
                external.add(module)  # stdlib / third-party leaf: recorded, not parsed
            continue
        try:
            targets = _module_imports(module, path, is_pkg)
        except SyntaxError:
            unresolved.add(module)  # first-party source will not parse -> refuse
            continue
        for t in targets:
            enqueue(t)

    return ClosureResult(
        entrypoints=tuple(entrypoints),
        reachable=frozenset(reachable),
        external=frozenset(external),
        unresolved_first_party=frozenset(unresolved),
    )


@dataclass(frozen=True)
class ClosureReport:
    """The verdict for the SaaS deny-list check over an entrypoint set."""

    result: ClosureResult
    denied: tuple[tuple[str, str], ...]  # (module, reason), sorted
    unresolved: tuple[str, ...]          # sorted; fail-closed violations
    residual: tuple[str, ...]            # KNOWN_RESIDUAL members actually reachable, sorted
    serving_lazy_denied: tuple[tuple[str, str, int], ...] = ()  # (serving module, denied target, lineno)

    @property
    def ok(self) -> bool:
        """Clean iff NOTHING denied is import-reachable, EVERY first-party module resolved, AND no reachable
        AEGIS serving module carries a lazy/function-local offense import. The residual is reported but does
        NOT fail the check (it is a tracked, ratcheted, DISCLOSED deferral — see KNOWN_RESIDUAL)."""
        return not self.denied and not self.unresolved and not self.serving_lazy_denied


def check_saas_closure(entrypoints: tuple[str, ...] | list[str] = SAAS_ENTRYPOINTS) -> ClosureReport:
    """Run the import-closure analysis over ``entrypoints`` and judge it against the deny list — plus the
    conservative serving-module lazy-offense scan (``_serving_lazy_denied``)."""
    result = import_closure(entrypoints)
    denied = sorted(
        (m, reason)
        for m in result.reachable
        if (reason := is_denied(m)) is not None
    )
    residual = tuple(sorted(result.reachable & KNOWN_RESIDUAL))
    return ClosureReport(
        result=result,
        denied=tuple(denied),
        unresolved=tuple(sorted(result.unresolved_first_party)),
        residual=residual,
        serving_lazy_denied=_serving_lazy_denied(result.reachable),
    )


def main(argv: list[str] | None = None) -> int:
    """Build-time / CI closure gate. Print the verdict and exit non-zero (FAIL CLOSED) if any denied
    module is reachable from the defense entrypoints or any first-party module is unresolvable.

    Run as ``python3 -m framework.v2.aegis.closure``. The AEGIS SaaS image invokes this at BUILD time so
    a layer that would ship a reachable offense import fails the build. The check is PURE STATIC source
    parsing — it never imports the offense code it is proving absent."""
    report = check_saas_closure()
    lines = [
        "AEGIS SaaS closure gate (AS-28)",
        f"  entrypoints          : {', '.join(report.result.entrypoints)}",
        f"  reachable modules    : {len(report.result.reachable)}",
        f"  denied reachable     : {len(report.denied)}",
        f"  unresolved (closed)  : {len(report.unresolved)}",
        f"  serving lazy offense : {len(report.serving_lazy_denied)}",
        f"  tracked residual     : {len(report.residual)} (DISCLOSED: eager intel->planner->agents executor layer)",
    ]
    for module, reason in report.denied:
        lines.append(f"  DENIED  {module}  ({reason})")
    for module in report.unresolved:
        lines.append(f"  UNRESOLVED  {module}")
    for module, target, lineno in report.serving_lazy_denied:
        lines.append(f"  LAZY-OFFENSE  {module}:{lineno}  imports  {target}")
    lines.append(f"  verdict              : {'CLEAN' if report.ok else 'REFUSED'}")
    print("\n".join(lines))
    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover - CLI/build-gate entry
    raise SystemExit(main())
