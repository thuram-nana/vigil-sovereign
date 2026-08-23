"""The feature-wiring completeness audit is machine-checked: every feature carries a wiring status, each
status agrees with the code, and the enumerable CLI surface cannot drift out from under the registry
(W15-2 #394, feeding the W17 milestone).

WHY THIS TEST EXISTS. "Others run VIGIL" means a built-not-wired feature is either shipped or removed,
not left ambiguous. Until every feature can be stated as LIVE / OPT-IN / GATED / BUILT-NOT-WIRED /
ORPHANED, nobody can answer "is this actually wired?" per feature. `docs/features/wiring-status.json`
assigns each feature a status; this guard makes the status answer to the code and EXTENDS the existing
system-map drift invariant (`tools/system-map/generate.py`, which the audit confirms is genuinely
enforced) with the same set-equality discipline applied to the CLI surface:

  * a `cli-native-verb` feature's verb must be a real top-level `sub.add_parser(...)` verb AND its handler
    must resolve BY AST — and the SET of declared native verbs must EQUAL the set the parser registers, so
    a new verb with no registry entry, or a registry verb deleted from the parser, turns CI red;
  * a `cli-passthrough-verb` feature's verb must be a key of the dispatcher's hardcoded `_ENV` table, and
    the declared set must EQUAL that table;
  * a `ui-screen` feature's `screen` must be a real NAV id AND a real route() id in the shipped UI
    (`packages/vigil-ui/app.js`), and the declared ui-screen SET must EQUAL the NAV == route() set — the
    system-map drift invariant, re-derived here from app.js (via `tools/system-map/generate.py`'s own
    extraction) and pinned to the registry, so a screen added to the UI without a registry entry (or a
    registry screen removed from the UI) turns CI red;
  * a `symbol-exists` feature's anchored symbol must resolve BY AST — the subsystem seams (chat, fireteam,
    brain, the MCP tool-governance boundary, and the not-yet-wired MCP live-client seam) are pinned to a
    real symbol so a "phantom subsystem" claim is impossible; the MCP live-client BUILT-NOT-WIRED status is
    additionally enforced by `test_mcp_live_client_seam_is_still_unwired` (its config producer has zero
    runtime call-sites — wiring it forces the status off BUILT-NOT-WIRED);
  * a `stub-raises` feature's anchored function must actually `raise NotImplementedError` (so a status of
    BUILT-NOT-WIRED / GATED-on-a-stub cannot lie about a stub that has since been implemented);
  * a `scaffold-abc` feature's anchor must be an abstract (ABC / @abstractmethod) class — an interface,
    not a runtime.

A single `validate_feature` validator is exercised by both the real registry AND deliberately-broken
negative controls in the same run, so the gate is provably not a no-op.

SCOPE (honest). This audit covers the enumerable, machine-checkable surface: every `vigil` CLI verb
(native + subsystem passthrough), every unified-UI screen, the deferred-infra subsystems, and the chat /
fireteam / brain / MCP subsystem seams. Orphaned console read routes remain covered by the W17-14
orphan-route guard (a distinct required job); this audit references that rather than duplicating it. It
does NOT enumerate every sub-flag or every prose line of docs/FEATURES.md — it pins the enumerable SURFACES
(verbs, screens, subsystem entrypoints) whose drift is machine-detectable.

STDLIB ONLY. Runs in the required `the briefing explains every agent and capability` CI job (pytest only):
`json` + `ast` + `pathlib` (+ `importlib` to reuse the system-map extractor, `functools` to cache it),
imports neither trust domain, runs no tool.
"""
from __future__ import annotations

import ast
import functools
import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
WIRING = REPO / "docs" / "features" / "wiring-status.json"
CLAIMS_REGISTRY = REPO / "docs" / "claims" / "registry.json"
CLI = "integration/vigil_integration/cli.py"
DISPATCH = "integration/vigil_integration/dispatch.py"

STATUSES = {"LIVE", "OPT-IN", "GATED", "BUILT-NOT-WIRED", "ORPHANED"}
WIRED_STATUSES = {"LIVE", "OPT-IN", "GATED"}
CHECKS = {"cli-native-verb", "cli-passthrough-verb", "stub-raises", "scaffold-abc", "orphaned-route",
          "ui-screen", "symbol-exists"}
REQUIRED_FIELDS = ("id", "name", "surface", "status", "anchor", "check", "rationale")
APP_JS = "packages/vigil-ui/app.js"


# --------------------------------------------------------------------------------------------------
# Loading + AST facts about the code (no import).
# --------------------------------------------------------------------------------------------------
def _load() -> dict:
    assert WIRING.is_file(), f"wiring-status registry missing: {WIRING}"
    data = json.loads(WIRING.read_text(encoding="utf-8"))
    assert isinstance(data.get("features"), list) and data["features"], "registry has no features"
    return data


def _features() -> list[dict]:
    return _load()["features"]


def _tree(file_path: str):
    return ast.parse((REPO / file_path).read_text(encoding="utf-8"))


def registered_native_verbs() -> set[str]:
    """The set of top-level `sub.add_parser("verb")` verbs — the parser's own native-verb contract."""
    out = set()
    for node in ast.walk(_tree(CLI)):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_parser"
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "sub"
                and node.args and isinstance(node.args[0], ast.Constant)):
            out.add(node.args[0].value)
    return out


def passthrough_verbs() -> set[str]:
    """The keys of the dispatcher's hardcoded `_ENV` verb->environment table."""
    for node in ast.walk(_tree(DISPATCH)):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == "_ENV" and isinstance(node.value, ast.Dict):
                    return {k.value for k in node.value.keys if isinstance(k, ast.Constant)}
    return set()


@functools.lru_cache(maxsize=1)
def _system_map_gen():
    """Import tools/system-map/generate.py by path and reuse ITS NAV/route extraction, so the UI-screen
    coverage check literally extends the existing system-map drift invariant (same regexes, one source of
    truth). generate.py's module-level code is stdlib-only — its single `import yaml` is inside
    `_load_screens`, which we never call — so this stays valid in the pytest-only briefing CI job."""
    p = REPO / "tools" / "system-map" / "generate.py"
    spec = importlib.util.spec_from_file_location("_vigil_system_map_gen", p)
    assert spec and spec.loader, f"cannot load the system-map generator at {p}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@functools.lru_cache(maxsize=1)
def ui_nav_ids() -> frozenset[str]:
    """The set of top-level UI screen ids in the `const NAV = [...]` array of app.js."""
    gen = _system_map_gen()
    return frozenset(gen._nav_ids((REPO / APP_JS).read_text(encoding="utf-8"))[0])


@functools.lru_cache(maxsize=1)
def ui_route_ids() -> frozenset[str]:
    """The set of screen ids handled in app.js's `function route() {...}` (via `id === "x"`)."""
    gen = _system_map_gen()
    return frozenset(gen._route_ids((REPO / APP_JS).read_text(encoding="utf-8"))[0])


def _find_node(body: list, parts: list[str]):
    head, rest = parts[0], parts[1:]
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == head:
            if not rest:
                return node
            if isinstance(node, ast.ClassDef):
                return _find_node(node.body, rest)
            return None
        if not rest and isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == head:
                    return node
    return None


def symbol_node(file_path: str, dotted: str):
    p = REPO / file_path
    if not p.is_file():
        return None
    try:
        return _find_node(ast.parse(p.read_text(encoding="utf-8")).body, dotted.split("."))
    except SyntaxError:
        return None


def raises_not_implemented(node) -> bool:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    for sub in ast.walk(node):
        if isinstance(sub, ast.Raise) and sub.exc is not None:
            name = sub.exc.func if isinstance(sub.exc, ast.Call) else sub.exc
            if isinstance(name, ast.Name) and name.id == "NotImplementedError":
                return True
            if isinstance(name, ast.Attribute) and name.attr == "NotImplementedError":
                return True
    return False


def is_abstract_class(node) -> bool:
    """A class is a scaffold interface if it inherits ABC/ABCMeta or has an @abstractmethod method."""
    if not isinstance(node, ast.ClassDef):
        return False
    for base in node.bases:
        if isinstance(base, ast.Name) and base.id in ("ABC", "ABCMeta"):
            return True
    for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in item.decorator_list:
                dname = dec.attr if isinstance(dec, ast.Attribute) else (dec.id if isinstance(dec, ast.Name) else "")
                if dname == "abstractmethod":
                    return True
    return False


# --------------------------------------------------------------------------------------------------
# The per-feature validator — real registry and negatives both run through THIS one function.
# --------------------------------------------------------------------------------------------------
def validate_feature(entry: dict, native: set[str], passthrough: set[str]) -> list[str]:
    errs: list[str] = []
    for f in REQUIRED_FIELDS:
        if f not in entry:
            errs.append(f"missing field {f!r}")
    if errs:
        return errs
    fid = entry["id"]
    if entry["status"] not in STATUSES:
        errs.append(f"{fid}: bad status {entry['status']!r}")
    if entry["check"] not in CHECKS:
        errs.append(f"{fid}: bad check {entry['check']!r}")
        return errs
    anchor = entry["anchor"]
    if not isinstance(anchor, dict) or "file" not in anchor:
        errs.append(f"{fid}: anchor must be an object with a file")
        return errs

    check = entry["check"]
    if check == "cli-native-verb":
        verb = entry.get("verb")
        if verb not in native:
            errs.append(f"{fid}: declared native verb {verb!r} is not a registered sub.add_parser verb "
                        f"(status must then be BUILT-NOT-WIRED, not {entry['status']!r})")
        if not symbol_node(anchor["file"], anchor.get("symbol", "")):
            errs.append(f"{fid}: handler {anchor.get('symbol')!r} not defined in {anchor['file']}")
        if entry["status"] not in WIRED_STATUSES:
            errs.append(f"{fid}: a registered native verb must be a wired status {sorted(WIRED_STATUSES)}")
    elif check == "cli-passthrough-verb":
        verb = entry.get("verb")
        if verb not in passthrough:
            errs.append(f"{fid}: declared passthrough verb {verb!r} is not a key of dispatch._ENV")
        if not symbol_node(anchor["file"], anchor.get("symbol", "")):
            errs.append(f"{fid}: {anchor.get('symbol')!r} not defined in {anchor['file']}")
        if entry["status"] not in WIRED_STATUSES:
            errs.append(f"{fid}: a passthrough verb must be a wired status")
    elif check == "ui-screen":
        screen = entry.get("screen")
        if screen not in ui_nav_ids():
            errs.append(f"{fid}: declared UI screen {screen!r} is not a NAV id in {APP_JS} "
                        f"(a real screen must be a NAV entry)")
        if screen not in ui_route_ids():
            errs.append(f"{fid}: declared UI screen {screen!r} is not a route() destination in {APP_JS}")
        if entry["status"] not in WIRED_STATUSES:
            errs.append(f"{fid}: a reachable UI screen must be a wired status {sorted(WIRED_STATUSES)}")
    elif check == "symbol-exists":
        if not symbol_node(anchor["file"], anchor.get("symbol", "")):
            errs.append(f"{fid}: symbol {anchor.get('symbol')!r} not defined in {anchor['file']} "
                        f"(a subsystem seam must anchor a real symbol, not a phantom)")
        if entry["status"] not in (WIRED_STATUSES | {"BUILT-NOT-WIRED"}):
            errs.append(f"{fid}: a symbol-exists feature must be LIVE/OPT-IN/GATED/BUILT-NOT-WIRED, "
                        f"not {entry['status']!r}")
    elif check == "stub-raises":
        node = symbol_node(anchor["file"], anchor.get("symbol", ""))
        if node is None:
            errs.append(f"{fid}: symbol {anchor.get('symbol')!r} not found in {anchor['file']}")
        elif not raises_not_implemented(node):
            errs.append(f"{fid}: {anchor['file']}::{anchor.get('symbol')} does not raise NotImplementedError "
                        f"(is it now wired? update the status)")
        if entry["status"] not in {"BUILT-NOT-WIRED", "GATED"}:
            errs.append(f"{fid}: a stub-raises feature must be BUILT-NOT-WIRED or GATED, not {entry['status']!r}")
    elif check == "scaffold-abc":
        node = symbol_node(anchor["file"], anchor.get("symbol", ""))
        if not is_abstract_class(node):
            errs.append(f"{fid}: {anchor.get('symbol')!r} is not an abstract (ABC/@abstractmethod) class")
        if entry["status"] != "BUILT-NOT-WIRED":
            errs.append(f"{fid}: a scaffold-abc feature must be BUILT-NOT-WIRED, not {entry['status']!r}")
    elif check == "orphaned-route":
        if entry["status"] != "ORPHANED":
            errs.append(f"{fid}: an orphaned-route feature must be ORPHANED")
    return errs


# ==================================================================================================
# The real registry
# ==================================================================================================
def test_every_feature_is_valid():
    native, passthrough = registered_native_verbs(), passthrough_verbs()
    problems, ids = [], set()
    for entry in _features():
        problems += validate_feature(entry, native, passthrough)
        if entry.get("id") in ids:
            problems.append(f"duplicate feature id {entry.get('id')!r}")
        ids.add(entry.get("id"))
    assert not problems, "wiring-status problems:\n  - " + "\n  - ".join(problems)


def test_every_feature_has_a_status():
    for entry in _features():
        assert entry["status"] in STATUSES, entry["id"]


def test_native_verb_coverage_is_exactly_the_parser_contract():
    """The drift extension: the SET of declared native verbs equals the set the parser registers — a new
    verb without a registry entry, or a registry verb removed from the parser, turns CI red."""
    declared = {f["verb"] for f in _features() if f["check"] == "cli-native-verb"}
    registered = registered_native_verbs()
    assert declared == registered, (
        f"native-verb drift: only-in-registry={sorted(declared - registered)} "
        f"only-in-parser={sorted(registered - declared)}")


def test_passthrough_verb_coverage_is_exactly_the_dispatch_table():
    declared = {f["verb"] for f in _features() if f["check"] == "cli-passthrough-verb"}
    env = passthrough_verbs()
    assert declared == env, (
        f"passthrough drift: only-in-registry={sorted(declared - env)} only-in-_ENV={sorted(env - declared)}")


def test_ui_screen_coverage_equals_the_system_map():
    """The UI drift extension: the SET of declared ui-screen ids EQUALS the app.js NAV ids AND the app.js
    route() ids. A screen added to the UI without a registry entry, or a registry screen removed from the
    UI, turns CI red. This re-derives the system-map drift invariant (NAV == route()) and pins it here."""
    declared = {f["screen"] for f in _features() if f["check"] == "ui-screen"}
    nav, route = set(ui_nav_ids()), set(ui_route_ids())
    assert nav == route, (f"app.js NAV != route(): only-in-NAV={sorted(nav - route)} "
                          f"only-in-route={sorted(route - nav)}")
    assert declared == nav, (f"ui-screen drift: only-in-registry={sorted(declared - nav)} "
                             f"only-in-UI={sorted(nav - declared)}")


def test_posture_is_live_not_a_stale_unwired_report():
    """The audit refutes the 'vigil posture reportedly unwired' report: it is a wired native verb."""
    posture = next((f for f in _features() if f.get("verb") == "posture"), None)
    assert posture is not None and posture["status"] in WIRED_STATUSES
    assert "posture" in registered_native_verbs()


def _calls_to(name: str, *, under: str, exclude_files: set[str]) -> list[str]:
    """Every `name(...)` call-site (AST) under `under`, excluding `exclude_files` (repo-relative) and any
    file in a tests/ dir or named test_*. Pure AST — imports nothing."""
    root = REPO / under
    hits: list[str] = []
    for p in sorted(root.rglob("*.py")):
        rel = str(p.relative_to(REPO))
        if rel in exclude_files or "/tests/" in rel or p.name.startswith("test_"):
            continue
        try:
            tree = ast.parse(p.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                f = node.func
                fn = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")
                if fn == name:
                    hits.append(f"{rel}:{node.lineno}")
    return hits


def test_mcp_live_client_seam_is_still_unwired():
    """`mcp.server_client` is declared BUILT-NOT-WIRED because the manifest→transport-config producer
    `to_client_config` exists but NO runtime consumes it (the live MCP client is a later slice). This
    enforces that claim against the code: the moment a caller wires `to_client_config`, this test fails,
    forcing the status off BUILT-NOT-WIRED. It also proves the declared status is not stale today."""
    entry = next((f for f in _features() if f["id"] == "mcp.server_client"), None)
    assert entry is not None and entry["status"] == "BUILT-NOT-WIRED", "mcp.server_client entry drifted"
    callers = _calls_to("to_client_config", under="integration/vigil_integration",
                        exclude_files={"integration/vigil_integration/tools/mcp_registry.py"})
    assert callers == [], (f"to_client_config now has runtime call-sites {callers} — the live MCP client is "
                           f"wired; change mcp.server_client off BUILT-NOT-WIRED in wiring-status.json")


def test_registered_in_claims_registry():
    reg = json.loads(CLAIMS_REGISTRY.read_text(encoding="utf-8"))
    ids = {c["id"] for c in reg["claims"]}
    assert "W15-2" in ids, "claim W15-2 (feature-wiring audit) is not registered in docs/claims/registry.json"
    assert "W15-2b" in ids, ("claim W15-2b (UI-screen + subsystem-seam coverage) is not registered in "
                             "docs/claims/registry.json")


# ==================================================================================================
# Negative controls — the gate is provably not a no-op.
# ==================================================================================================
def _native() -> set[str]:
    return registered_native_verbs()


def _pass() -> set[str]:
    return passthrough_verbs()


def _good_native() -> dict:
    return {"id": "cli.doctor", "name": "vigil doctor", "surface": "cli-native", "status": "LIVE",
            "verb": "doctor", "anchor": {"file": CLI, "symbol": "_cmd_doctor"},
            "check": "cli-native-verb", "rationale": "r"}


def test_negative_control_good_native_validates():
    assert validate_feature(_good_native(), _native(), _pass()) == []


def test_negative_control_live_for_unregistered_verb_rejected():
    bad = _good_native()
    bad["verb"] = "no-such-verb"
    assert any("not a registered sub.add_parser verb" in e for e in validate_feature(bad, _native(), _pass()))


def test_negative_control_wired_status_for_missing_verb_is_wrong():
    """A verb the parser does not register may not be declared LIVE/GATED — it would have to be
    BUILT-NOT-WIRED. This is the core status-vs-code disagreement the AC requires be caught."""
    bad = _good_native()
    bad["verb"] = "ghost"
    errs = validate_feature(bad, _native(), _pass())
    assert errs, "a LIVE feature for a non-existent verb must be rejected"


def test_negative_control_stub_that_does_not_raise_rejected():
    bad = {"id": "x", "name": "x", "surface": "deferred-infra", "status": "BUILT-NOT-WIRED",
           "anchor": {"file": "engine/crucible/framework/v2/attest/provider.py",
                      "symbol": "SoftwareAttestationProvider.verify"},
           "check": "stub-raises", "rationale": "r"}
    assert any("does not raise NotImplementedError" in e for e in validate_feature(bad, _native(), _pass()))


def test_negative_control_status_check_mismatch_rejected():
    bad = _good_native()
    bad["status"] = "BUILT-NOT-WIRED"  # a registered native verb cannot be BUILT-NOT-WIRED
    assert any("wired status" in e for e in validate_feature(bad, _native(), _pass()))


def test_negative_control_scaffold_that_is_concrete_rejected():
    bad = {"id": "x", "name": "x", "surface": "deferred-infra", "status": "BUILT-NOT-WIRED",
           "anchor": {"file": CLI, "symbol": "_cmd_doctor"}, "check": "scaffold-abc", "rationale": "r"}
    assert any("not an abstract" in e for e in validate_feature(bad, _native(), _pass()))


def test_negative_control_orphaned_requires_orphaned_status():
    bad = {"id": "x", "name": "x", "surface": "console", "status": "LIVE",
           "anchor": {"file": CLI}, "check": "orphaned-route", "rationale": "r"}
    assert any("must be ORPHANED" in e for e in validate_feature(bad, _native(), _pass()))


def test_negative_control_coverage_detects_a_dropped_verb():
    """Simulate a parser that registers an extra verb the registry does not declare — the coverage check
    must flag it (proving the drift guard is live, not a tautology over the same source)."""
    declared = {f["verb"] for f in _features() if f["check"] == "cli-native-verb"}
    mutated_registered = registered_native_verbs() | {"newly-added-verb"}
    assert declared != mutated_registered


def test_negative_control_ui_screen_phantom_rejected():
    """A ui-screen whose id is not a real NAV entry in app.js must be rejected — the core status-vs-code
    disagreement for the UI surface (a screen claimed present that the UI does not route to)."""
    bad = {"id": "ui.ghost", "name": "UI screen — ghost", "surface": "ui-screen", "status": "LIVE",
           "screen": "no-such-screen", "anchor": {"file": APP_JS}, "check": "ui-screen", "rationale": "r"}
    errs = validate_feature(bad, _native(), _pass())
    assert any("not a NAV id" in e for e in errs), errs


def test_negative_control_ui_screen_coverage_detects_an_added_screen():
    """Simulate the UI gaining a NAV screen the registry does not declare — the coverage set-equality must
    flag it (proving the UI drift guard is live, not a tautology)."""
    declared = {f["screen"] for f in _features() if f["check"] == "ui-screen"}
    mutated_nav = set(ui_nav_ids()) | {"phantomScreen"}
    assert declared != mutated_nav


def test_negative_control_symbol_exists_phantom_rejected():
    """A symbol-exists subsystem seam anchored to a non-existent symbol must be rejected (no phantom
    subsystem can be declared LIVE)."""
    bad = {"id": "x", "name": "x", "surface": "subsystem", "status": "LIVE",
           "anchor": {"file": CLI, "symbol": "_totally_not_a_real_symbol"},
           "check": "symbol-exists", "rationale": "r"}
    assert any("not defined" in e for e in validate_feature(bad, _native(), _pass()))


def test_negative_control_symbol_exists_bad_status_rejected():
    """A symbol-exists feature may not carry ORPHANED — only LIVE/OPT-IN/GATED/BUILT-NOT-WIRED."""
    bad = {"id": "x", "name": "x", "surface": "subsystem", "status": "ORPHANED",
           "anchor": {"file": CLI, "symbol": "_cmd_doctor"}, "check": "symbol-exists", "rationale": "r"}
    assert any("must be LIVE/OPT-IN/GATED/BUILT-NOT-WIRED" in e for e in validate_feature(bad, _native(), _pass()))
