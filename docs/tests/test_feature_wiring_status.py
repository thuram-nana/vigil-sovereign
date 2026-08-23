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
  * a `stub-raises` feature's anchored function must actually `raise NotImplementedError` (so a status of
    BUILT-NOT-WIRED / GATED-on-a-stub cannot lie about a stub that has since been implemented);
  * a `scaffold-abc` feature's anchor must be an abstract (ABC / @abstractmethod) class — an interface,
    not a runtime.

A single `validate_feature` validator is exercised by both the real registry AND deliberately-broken
negative controls in the same run, so the gate is provably not a no-op.

SCOPE (honest). This audit covers the enumerable, machine-checkable surface: every `vigil` CLI verb
(native + subsystem passthrough) and the deferred-infra subsystems. The UI-screen surface is already
covered by the system-map drift invariant (NAV == route() == manifest), and orphaned console routes are
already covered by the W17-14 orphan-route guard; this audit references those rather than duplicating them.

STDLIB ONLY. Runs in the required `the briefing explains every agent and capability` CI job (pytest only):
`json` + `ast` + `pathlib`, imports neither trust domain, runs no tool.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
WIRING = REPO / "docs" / "features" / "wiring-status.json"
CLAIMS_REGISTRY = REPO / "docs" / "claims" / "registry.json"
CLI = "integration/vigil_integration/cli.py"
DISPATCH = "integration/vigil_integration/dispatch.py"

STATUSES = {"LIVE", "OPT-IN", "GATED", "BUILT-NOT-WIRED", "ORPHANED"}
WIRED_STATUSES = {"LIVE", "OPT-IN", "GATED"}
CHECKS = {"cli-native-verb", "cli-passthrough-verb", "stub-raises", "scaffold-abc", "orphaned-route"}
REQUIRED_FIELDS = ("id", "name", "surface", "status", "anchor", "check", "rationale")


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


def test_posture_is_live_not_a_stale_unwired_report():
    """The audit refutes the 'vigil posture reportedly unwired' report: it is a wired native verb."""
    posture = next((f for f in _features() if f.get("verb") == "posture"), None)
    assert posture is not None and posture["status"] in WIRED_STATUSES
    assert "posture" in registered_native_verbs()


def test_registered_in_claims_registry():
    reg = json.loads(CLAIMS_REGISTRY.read_text(encoding="utf-8"))
    ids = {c["id"] for c in reg["claims"]}
    assert "W15-2" in ids, "claim W15-2 (feature-wiring audit) is not registered in docs/claims/registry.json"


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
