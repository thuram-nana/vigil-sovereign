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

Design invariants (constitution: determinism, fail-closed, no over-claim):
  * PURE + DETERMINISTIC. No imports are executed, no network, no wall-clock, no RNG. The result is a
    deterministic function of the on-disk source; outputs are sorted. (Executing the graph to observe it
    is self-defeating here — it would load the very offense code we are proving absent.)
  * FAIL CLOSED. A first-party module that cannot be resolved or whose AST will not parse is a
    violation, never a silent pass. ``check_saas_closure(...).ok`` is True only when the reachable set is
    clean AND fully resolved.
  * MODULE-LEVEL ONLY. Imports nested inside a ``def``/``async def`` are LAZY — they do not run at
    import time — so they are NOT followed (this mirrors Python's real import-time behaviour and is why
    the gateway's function-local ``from ..verify.oob import OOBReceiver`` is correctly out of closure).
  * NO OVER-CLAIM. The enforced deny list is the part AS-28 can honestly keep green in its lane; the
    ``KNOWN_RESIDUAL`` set (the offense-executor coupling still pulled via the eager ``intel`` → ``planner``
    → ``agents`` package ``__init__`` chain) is tracked by a ratchet, not hidden — see the module notes
    and ``aegis/tests/test_saas_closure.py``.

The companion RUNTIME check (block ``anthropic`` / the agent SDKs via an import hook, then import the
entrypoint and confirm it still loads) lives in the test; it catches dynamic/transitive paths this
static pass does not model. The two together are the closure proof the plan calls for.
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


def _module_imports(module: str, path: pathlib.Path, is_pkg: bool) -> set[str]:
    """The set of ABSOLUTE module names ``module`` reaches at import time. For ``from base import a, b``
    we add ``base`` (its ``__init__`` runs) and each ``base.<name>`` that resolves to a real submodule
    (so ``from ..verify import oob`` is caught). ``ast.parse`` failure propagates to a fail-closed error."""
    current_pkg = module if is_pkg else module.rpartition(".")[0]
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    visitor = _ModuleLevelImports(current_pkg, is_pkg)
    visitor.visit(tree)

    out: set[str] = set()
    for base, from_names in visitor.raw:
        out.add(base)
        for name in from_names:
            if name == "*":
                continue
            candidate = f"{base}.{name}"
            cpath, _ = _resolve_first_party_file(candidate)
            if cpath is not None:  # ``name`` is a real submodule -> importing it runs it
                out.add(candidate)
    out.update(visitor.dynamic)
    return out


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

    @property
    def ok(self) -> bool:
        """Clean iff nothing denied is reachable AND every first-party module resolved. The residual is
        reported but does NOT fail the check (it is a tracked, ratcheted deferral — see KNOWN_RESIDUAL)."""
        return not self.denied and not self.unresolved


def check_saas_closure(entrypoints: tuple[str, ...] | list[str] = SAAS_ENTRYPOINTS) -> ClosureReport:
    """Run the import-closure analysis over ``entrypoints`` and judge it against the deny list."""
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
        f"  entrypoints         : {', '.join(report.result.entrypoints)}",
        f"  reachable modules   : {len(report.result.reachable)}",
        f"  denied reachable    : {len(report.denied)}",
        f"  unresolved (closed) : {len(report.unresolved)}",
        f"  tracked residual    : {len(report.residual)} (deferred: intel/planner/agents decoupling)",
    ]
    for module, reason in report.denied:
        lines.append(f"  DENIED  {module}  ({reason})")
    for module in report.unresolved:
        lines.append(f"  UNRESOLVED  {module}")
    lines.append(f"  verdict             : {'CLEAN' if report.ok else 'REFUSED'}")
    print("\n".join(lines))
    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover - CLI/build-gate entry
    raise SystemExit(main())
