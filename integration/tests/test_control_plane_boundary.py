"""S8 — the whole-control-plane boundary regression guard.

The `vigil` super-CLI is ONE command over TWO isolated trust domains. This test locks in the routing
invariant across the ENTIRE control plane, so a future verb can never silently cross the boundary:

  * every passthrough verb resolves to a FIXED environment — the ONLY sovereign route is `vigil sigil …`;
    every other passthrough (crucible/aegis/strix/gateway) resolves to the offense venv, never the sovereign
    one (and vice-versa);
  * native verbs (parsed in-process, offense-side) and passthrough verbs are DISJOINT — a name collision
    would let a passthrough shadow a native verb (or leave a native verb unreachable);
  * the dispatcher is PURE STDLIB + exec-only — it imports neither `framework`/`strix` nor `sigil`, so a
    single interpreter never co-loads both trust domains (the FATAL-2 boundary).

Run: PYTHONPATH=integration pytest integration/tests/test_control_plane_boundary.py -q
"""
from __future__ import annotations

import argparse
import ast
from pathlib import Path

from vigil_integration import dispatch
from vigil_integration.cli import build_parser

# The one sovereign route. EVERYTHING else the control plane can reach must be offense-side.
SOVEREIGN_VERBS = {"sigil"}


def _native_verbs() -> set[str]:
    """The in-process (offense-side) `vigil` subcommands, read from the argparse subparsers."""
    parser = build_parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices)
    raise AssertionError("no subparsers found on the vigil parser")


def test_every_passthrough_verb_routes_to_a_fixed_env():
    for verb, (env_name, _script) in dispatch._ENV.items():
        assert env_name in ("sovereign", "offense"), f"{verb} has an unknown env {env_name!r}"
        if verb in SOVEREIGN_VERBS:
            assert env_name == "sovereign", f"sovereign verb {verb!r} must route to the sovereign venv"
        else:
            assert env_name == "offense", f"non-sovereign passthrough {verb!r} must route offense-side"


def test_exactly_one_sovereign_route():
    sovereign = {v for v, (env, _) in dispatch._ENV.items() if env == "sovereign"}
    assert sovereign == SOVEREIGN_VERBS, (
        f"the ONLY sovereign route must be `vigil sigil` — found {sovereign}")


def test_no_offense_verb_resolves_into_the_sovereign_venv(monkeypatch, tmp_path):
    # resolve() must place each verb under .venv-<its fixed env>/bin/<script> — an offense verb can NEVER
    # produce a path under .venv-sovereign.
    monkeypatch.setattr(dispatch, "_repo_root", lambda: tmp_path)
    for verb, (env_name, script) in dispatch._ENV.items():
        p = dispatch.resolve(verb)
        assert p == tmp_path / f".venv-{env_name}" / "bin" / script
        if verb not in SOVEREIGN_VERBS:
            assert ".venv-sovereign" not in str(p), f"offense verb {verb!r} resolved into the sovereign venv!"


def test_native_and_passthrough_verbs_are_disjoint():
    # a collision would make the passthrough intercept (which runs BEFORE argparse) shadow a native verb,
    # or leave a native verb unreachable — either way a routing ambiguity across the boundary.
    native = _native_verbs()
    passthrough = set(dispatch.PASSTHROUGH_VERBS)
    assert native.isdisjoint(passthrough), f"verb collision: {native & passthrough}"
    assert passthrough == set(dispatch._ENV)   # PASSTHROUGH_VERBS is exactly the routing table


def test_every_native_verb_is_offense_side_in_process():
    # Native verbs run in THIS (offense) process — none is a passthrough, so none can reach the sovereign
    # venv. The sovereign side is reachable ONLY via the single `vigil sigil` passthrough.
    native = _native_verbs()
    assert native  # non-empty (engage/ledger/verify/… exist)
    assert native.isdisjoint(SOVEREIGN_VERBS)


def test_dispatcher_is_pure_stdlib_exec_only():
    # AST-level guarantee (process-independent): the dispatcher's module imports are stdlib ONLY — it pulls
    # in neither framework/strix (offense engine) nor sigil (sovereign core), so exec-ing across venvs never
    # co-loads both trust domains in one interpreter.
    allowed = {"__future__", "os", "subprocess", "sys", "pathlib"}
    src = Path(dispatch.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    forbidden = imported - allowed
    assert not forbidden, f"dispatcher must import stdlib only; found {forbidden}"
    for banned in ("framework", "strix", "sigil", "vigil_integration"):
        assert banned not in imported, f"dispatcher must not import {banned!r}"


# ---- P1b: the `vigil up`/`down` code path must also stay boundary-clean --------------------------
# `vigil up` orchestrates the WHOLE UI by subprocess ONLY (spawns sigil/crucible in their own venvs);
# it must import neither framework/strix (offense engine) nor sigil (sovereign core), so a single
# interpreter never co-loads both trust domains — exactly like the dispatcher it delegates spawning to.
_UP_ALLOWED_STDLIB = {
    "__future__", "base64", "binascii", "http", "ipaddress", "json", "os", "re", "signal", "socket",
    "socketserver", "subprocess", "sys", "threading", "time", "pathlib", "queue", "typing", "urllib",
    "webbrowser",
}
_BANNED = ("framework", "strix", "sigil")


def _module_imports(src: str) -> tuple[set[str], set[str]]:
    """Return (absolute_roots, relative_names) for every import in `src`. `absolute_roots` is the set of
    top-level module names of ABSOLUTE imports; `relative_names` is the set of sibling names brought in by
    a package-relative import (``from . import X`` / ``from .X import ...``)."""
    tree = ast.parse(src)
    absolute_roots: set[str] = set()
    relative_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            absolute_roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:                     # relative
                if node.module:
                    relative_names.add(node.module.split(".")[0])  # from .uiproxy import ...
                else:
                    relative_names.update(alias.name for alias in node.names)  # from . import dispatch
            elif node.module:
                absolute_roots.add(node.module.split(".")[0])
    return absolute_roots, relative_names


def test_uiproxy_is_pure_stdlib():
    # The reverse-proxy module: stdlib only + the (pure-stdlib) sibling `dispatch`. Never framework/strix/sigil.
    from vigil_integration import uiproxy
    absolute_roots, relative_names = _module_imports(Path(uiproxy.__file__).read_text(encoding="utf-8"))
    stray = absolute_roots - _UP_ALLOWED_STDLIB
    assert not stray, f"uiproxy must import stdlib only; found {stray}"
    assert relative_names <= {"dispatch"}, f"uiproxy may only reach the sibling `dispatch`; found {relative_names}"
    for banned in _BANNED:
        assert banned not in absolute_roots and banned not in relative_names, \
            f"uiproxy must not import {banned!r}"


def test_up_down_verbs_import_no_trust_domain():
    # The `vigil up`/`vigil down` verb bodies in cli.py may lazily import ONLY the (pure-stdlib) `.uiproxy`
    # module — never framework/strix/sigil. Prove it at the AST level over just those two functions.
    from vigil_integration import cli
    tree = ast.parse(Path(cli.__file__).read_text(encoding="utf-8"))
    seen = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in ("_cmd_up", "_cmd_down"):
            seen.add(node.name)
            roots: set[str] = set()
            rels: set[str] = set()
            for child in ast.walk(node):
                if isinstance(child, ast.Import):
                    roots.update(a.name.split(".")[0] for a in child.names)
                elif isinstance(child, ast.ImportFrom):
                    if child.level and child.level > 0:
                        rels.add((child.module or "").split(".")[0])
                    elif child.module:
                        roots.add(child.module.split(".")[0])
            assert rels <= {"uiproxy"}, f"{node.name} may only import `.uiproxy`; found relative {rels}"
            for banned in _BANNED:
                assert banned not in roots and banned not in rels, \
                    f"{node.name} must not import {banned!r}"
    assert seen == {"_cmd_up", "_cmd_down"}, f"expected both up/down verbs in cli.py, found {seen}"
