"""Phase B1 — the unified ToolProfile + the tool-consciousness admission gate (tools/profile.py).

Proves: the join fuses the host roster + Strix CLI playbooks + typed argv builders + THE ENGINE'S OWN
DRIVERS (gated sensors / analysis backends / the scanner's headless browser) on the binary name; the gate
ADMITS a globally-recognised tool that has any of those control surfaces and REFUSES one that is either not
recognised or has no way to be driven AT ALL, with an honest reason; and every declared mirror set is pinned
to the REAL source by a drift guard, so a tool added to a builder / sensor / analyzer / the browser resolver
and forgotten in ``tools.profile`` fails the build instead of silently rotting.

The drift guards read SOURCE TEXT (``ast``), never importing the driver packages — ``tools.profile`` mirrors
them for exactly that reason (see its module docstring), and a test that imported them would prove nothing
about the mirror while dragging the whole observation/world-model stack into a metadata test.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

from framework.v2.tools import profile as P
from framework.v2.tools.registry import HOST_TOOLS

# framework/v2 — this file is framework/v2/console/tests/test_tool_profile.py
_V2 = pathlib.Path(__file__).resolve().parents[2]


def _by_name(profiles):
    return {p["name"]: p for p in profiles}


# ---------------------------------------------------------------------------------------------------
# the join + the gate
# ---------------------------------------------------------------------------------------------------

def test_build_profiles_shape_and_summary_are_honest():
    out = P.build_profiles()
    assert set(out) == {"profiles", "summary"}
    profs = out["profiles"]
    assert profs and all({"name", "admitted", "control_surface", "global_recognition",
                          "admit_reason", "install_hint", "has_skill_doc", "has_typed_builder",
                          "has_spec_builder", "has_sensor", "has_analyzer", "has_browser_driver"} <= set(p)
                         for p in profs)
    s = out["summary"]
    assert s["total"] == len(profs)
    assert s["admitted"] + s["refused"] == s["total"]


def test_typed_builder_tools_admit_even_without_a_skill_doc():
    # nmap + hydra have a typed argv builder → a CLI control surface regardless of Strix being importable →
    # (they are also globally recognised via the host roster) → ADMITTED.
    got = _by_name(P.build_profiles()["profiles"])
    for name in ("nmap", "hydra"):
        p = got[name]
        assert p["has_typed_builder"] and p["control_surface"] == "cli"
        assert p["global_recognition"] and p["admitted"] and p["admit_reason"].startswith("admitted")


def test_engine_driven_tools_admit_with_an_honest_surface_label():
    """The operator's complaint: tools the engine ALREADY SPAWNS were being refused for "no CLI-usage
    knowledge". These three are admitted now — and the label says HOW each is driven, because a tool run
    by a sensor is not a model reading a playbook and the screen must not blur the two. An engine driver
    is their ONLY surface, so the label is pinned exactly."""
    got = _by_name(P.build_profiles()["profiles"])
    expected = {
        # tool      surface      the flag that carries it
        "tshark":   ("sensor",   "has_sensor"),          # sensors/tshark.py:TsharkFlowSensor
        "joern":    ("analyzer", "has_analyzer"),        # analysis/analyzers/joern.py:JoernAnalyzer
        "chromium": ("browser",  "has_browser_driver"),  # scanner/browser.py:_BROWSERS
    }
    for name, (surface, flag) in expected.items():
        p = got[name]
        assert p[flag], f"{name}: the driver flag {flag} is not set"
        assert p["control_surface"] == surface, f"{name}: surface {p['control_surface']!r} != {surface!r}"
        assert p["admitted"] and p["admit_reason"] == f"admitted ({surface})"
        # the label is honest in BOTH directions: none of these is driven by a playbook or a typed builder
        assert not p["has_skill_doc"] and not p["has_typed_builder"]


def test_zap_is_reported_as_sensor_driven():
    """``sensors/web_scanner.py:ZapWebSensor`` resolves zap.sh|zap-cli|zaproxy and spawns it (registered in
    ``sensors.builtin``), so the sensor flag must be set and the tool admitted. Only the FLAG is pinned,
    not the top surface: if a typed argv builder is added for it, "cli" correctly takes precedence."""
    p = _by_name(P.build_profiles()["profiles"])["zaproxy"]
    assert p["has_sensor"] and p["admitted"]
    assert p["control_surface"] in ("sensor", "cli")


def test_cli_surface_still_wins_for_tools_that_have_both():
    """No regression: nmap/nuclei are ALSO sensor-driven, but a playbook/typed builder is the more direct
    surface, so they keep reporting "cli" exactly as before."""
    got = _by_name(P.build_profiles()["profiles"])
    for name in ("nmap", "nuclei"):
        p = got[name]
        assert p["has_sensor"] and p["has_typed_builder"]
        assert p["control_surface"] == "cli"


def test_r4_spec_builder_tools_are_admitted_as_cli_so_the_two_surfaces_agree():
    """H4b MEET-UP. masscan/rustscan/naabu/sslscan and the W1 batch-2 zmap/unicornscan are driven by a
    runner-owned ToolSpec builder (the R4 runner path), which is a real 'we build + gate the argv' CLI
    control. They must be ADMITTED here as 'cli' — so this tool-profile screen AGREES with ``capability_join``
    (which already treats the same set as a builder source and shows them EXECUTABLE-if-installed), instead of
    the pre-meet-up contradiction where this screen said REFUSED while the brain panel said runnable. sslscan
    is the sharp case: it is NOT in the host roster and has NO typed executor builder, so ONLY the spec-builder
    driver recognises + admits it."""
    got = _by_name(P.build_profiles()["profiles"])
    for name in ("masscan", "rustscan", "naabu", "sslscan", "zmap", "unicornscan"):
        p = got[name]
        assert p["has_spec_builder"], f"{name}: the R4 ToolSpec-builder flag is not set"
        assert p["control_surface"] == "cli", f"{name}: surface {p['control_surface']!r} != 'cli'"
        assert p["global_recognition"] and p["admitted"] and p["admit_reason"] == "admitted (cli)"
    # these port scanners are neither in the host roster nor typed executor builders here — their ONLY
    # drive surface is the spec builder, which is exactly what the meet-up recognises.
    for name in ("masscan", "rustscan", "naabu", "sslscan", "zmap", "unicornscan"):
        assert not got[name]["has_typed_builder"], f"{name}: must not be a governed-executor typed builder"


def test_admit_gate_unit():
    assert P._admit(False, "cli")[0] is False               # not recognised → refused
    assert "not a globally-recognised" in P._admit(False, "cli")[1]
    assert P._admit(True, "")[0] is False                   # recognised but no control surface → refused
    assert "no CLI-usage knowledge" in P._admit(True, "")[1]
    ok, why = P._admit(True, "cli")
    assert ok and why == "admitted (cli)"
    assert P._admit(True, "background")[0] is True          # background surface also admits
    for surface in ("sensor", "analyzer", "browser"):       # the engine's own drivers admit …
        ok, why = P._admit(True, surface)
        assert ok and why == f"admitted ({surface})"


def test_skill_doc_only_tool_admits_when_strix_is_present():
    pytest.importorskip("strix")
    got = _by_name(P.build_profiles()["profiles"])
    # semgrep is in the host roster + has a Strix tooling playbook but is NOT a typed builder → the CLI
    # control surface comes from the playbook alone → admitted.
    if "semgrep" in got:
        p = got["semgrep"]
        assert p["has_skill_doc"] and not p["has_typed_builder"]
        assert p["control_surface"] == "cli" and p["admitted"]


# ---------------------------------------------------------------------------------------------------
# the MUTATION CONTROLS — what stops "just admit everything"
# ---------------------------------------------------------------------------------------------------

def test_installed_roster_tool_with_no_drive_knowledge_is_refused_end_to_end(monkeypatch):
    """THE NEGATIVE CONTROL, through the real ``build_profiles`` path: a globally-recognised, INSTALLED
    roster tool that nothing can drive — no playbook, no typed builder, no sensor, no analyzer, no browser
    — is REFUSED, with the honest reason. Synthetic on purpose: it must keep testing the gate even after
    every tool in the shipped roster has acquired a driver, and it is what stops a future "just admit
    everything" change. If this fails, the fix is to BUILD a driver, never to widen the gate."""
    fake = {"name": "obsidian-undriveable-probe", "binary": "obsidian-undriveable-probe",
            "purpose": "synthetic negative control", "status": "ok", "installed": True,
            "path": "/usr/bin/obsidian-undriveable-probe", "install_hint": "n/a"}
    monkeypatch.setattr(P, "probe_tools", lambda: {"tools": [fake]})

    p = _by_name(P.build_profiles()["profiles"])[fake["name"]]
    assert p["in_host_roster"] and p["installed"] and p["global_recognition"]   # recognised + present …
    assert not any(p[f] for f in ("has_skill_doc", "has_typed_builder", "has_spec_builder", "has_sensor",
                                  "has_analyzer", "has_browser_driver"))
    assert p["control_surface"] == "" and not p["admitted"]                     # … but nothing drives it
    assert "no CLI-usage knowledge" in p["admit_reason"] and p["admit_reason"].startswith("refused:")


def test_a_driver_is_what_flips_the_synthetic_control(monkeypatch):
    """The positive half of the control — proof the fixture above is refused for the RIGHT reason (no
    drive-knowledge) and not because ``build_profiles`` refuses anything unfamiliar. The same synthetic
    tool, with one sensor driver declared, admits as "sensor"."""
    name = "obsidian-undriveable-probe"
    monkeypatch.setattr(P, "probe_tools", lambda: {"tools": [
        {"name": name, "binary": name, "status": "ok", "installed": True}]})
    monkeypatch.setattr(P, "_SENSOR_DRIVEN_TOOLS", frozenset({name}))

    p = _by_name(P.build_profiles()["profiles"])[name]
    assert p["has_sensor"] and p["control_surface"] == "sensor"
    assert p["admitted"] and p["admit_reason"] == "admitted (sensor)"


def test_no_drive_knowledge_yields_no_surface_and_an_unknown_surface_never_admits():
    """Unit-level mutation control, independent of what happens to be in the roster: nothing set ⇒ no
    surface ⇒ refused; and the surface allowlist is CLOSED, so inventing a label does not buy admission."""
    assert P._control_surface(has_skill_doc=False, has_typed_builder=False, has_spec_builder=False,
                              has_sensor=False, has_analyzer=False, has_browser_driver=False) == ""
    assert P._admit(True, "")[0] is False
    for bogus in ("adapter", "parser", "import", "eval", "CLI", "sensor ", "yes", "true"):
        ok, why = P._admit(True, bogus)
        assert ok is False, f"unknown surface {bogus!r} must not admit"
        assert why.startswith("refused:")


def test_every_admitted_tool_has_a_real_named_drive_surface():
    """The invariant the whole gate exists to protect: nothing is admitted without a control surface from
    the closed allowlist, and (for every surface this module can mint) without the flag that carries it.
    A future "admit everything" change cannot pass this."""
    carrier = {"cli": ("has_skill_doc", "has_typed_builder", "has_spec_builder"),
               "sensor": ("has_sensor",), "analyzer": ("has_analyzer",),
               "browser": ("has_browser_driver",)}
    flags = ("has_skill_doc", "has_typed_builder", "has_spec_builder", "has_sensor", "has_analyzer",
             "has_browser_driver")
    for p in P.build_profiles()["profiles"]:
        # a surface exists IFF some drive-knowledge does — no surface may be conjured from nothing, and
        # real drive-knowledge may never be silently dropped (the under-reporting this change fixed)
        assert bool(p["control_surface"]) is any(p[f] for f in flags), (
            f"{p['name']}: surface {p['control_surface']!r} does not match its drive flags")
        if not p["admitted"]:
            assert p["admit_reason"].startswith("refused:")
            continue
        surface = p["control_surface"]
        assert surface in P._ADMITTABLE_SURFACES and surface != ""
        assert p["global_recognition"]
        assert any(p[flag] for flag in carrier[surface]), (
            f"{p['name']}: admitted as {surface!r} with no flag proving it")


# ---------------------------------------------------------------------------------------------------
# the DRIFT GUARDS — every mirror set pinned to the source it mirrors
# ---------------------------------------------------------------------------------------------------

def _repo_root() -> pathlib.Path:
    for anc in pathlib.Path(__file__).resolve().parents:
        if (anc / "engine" / "crucible").is_dir() and (anc / "integration").is_dir():
            return anc
    raise AssertionError("repo root not found")


def _tree(path: pathlib.Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _module_consts(tree: ast.Module) -> dict:
    """Module-level ``NAME = <expr>`` bindings (so a ``_ZAP_BINARIES``-style constant resolves)."""
    consts: dict = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    consts[t.id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            consts[node.target.id] = node.value
    return consts


def _strings(node: ast.AST, consts: dict) -> set:
    """Every string literal reachable from ``node`` as a value or a container element."""
    if isinstance(node, ast.Constant):
        return {node.value} if isinstance(node.value, str) else set()
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return set().union(*[_strings(e, consts) for e in node.elts]) if node.elts else set()
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
            and node.func.id in ("frozenset", "set", "tuple", "list"):
        return set().union(*[_strings(a, consts) for a in node.args]) if node.args else set()
    if isinstance(node, ast.Name) and node.id in consts:
        return _strings(consts[node.id], consts)
    return set()


_SPAWN_CALLS = {("subprocess", "run"), ("subprocess", "Popen"), ("subprocess", "call"),
                ("subprocess", "check_call"), ("subprocess", "check_output"),
                ("os", "system"), ("os", "popen"), ("shutil", "which")}


def _spawn_sites(tree: ast.Module) -> set:
    """``mod.func`` names of every host-process call in the module (resolve-or-spawn)."""
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and isinstance(node.func.value, ast.Name):
            key = (node.func.value.id, node.func.attr)
            if key in _SPAWN_CALLS:
                out.add(".".join(key))
    return out


def _driven_binary_names(tree: ast.Module) -> set:
    """The BINARY names a driver module resolves, extracted from the two shapes the engine actually uses:
    a literal ``shutil.which("<name>")``, and the string default of a ``binary=`` / ``binaries=`` parameter
    (which is what ``self._binary`` / ``self._binaries`` resolve to at every call site).

    Honest limitation: a fully dynamic, default-less binary is invisible here — which is exactly why the
    companion assertion pins the SET OF DRIVER MODULES too, so a new driver has to be classified by a
    human rather than slipping past this extractor."""
    consts = _module_consts(tree)
    found: set = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "which" and isinstance(node.func.value, ast.Name) \
                and node.func.value.id == "shutil":
            for a in node.args:
                found |= _strings(a, consts)
        if isinstance(node, ast.FunctionDef):
            a = node.args
            pairs = list(zip(a.args[len(a.args) - len(a.defaults):], a.defaults))
            pairs += [(kw, d) for kw, d in zip(a.kwonlyargs, a.kw_defaults) if d is not None]
            for arg, default in pairs:
                if arg.arg in ("binary", "binaries"):
                    found |= _strings(default, consts)
    return found


def _roster_names_for(binaries: set) -> set:
    """Fold binary names onto their ROSTER KEY (the id ``tools.profile`` is keyed by), so ``zap.sh`` and
    ``chromium-browser`` land on ``zaproxy`` / ``chromium``. A driven binary with NO roster entry is an
    error, not a silent drop: the engine must not spawn a tool the curated arsenal has never heard of."""
    index: dict = {}
    for spec in HOST_TOOLS:
        if getattr(spec, "sandbox", False):
            continue
        index[spec.binary] = spec.name
        for alt in getattr(spec, "alt_binaries", ()) or ():
            index[alt] = spec.name
    unknown = sorted(b for b in binaries if b not in index)
    assert not unknown, (f"driver spawns binaries absent from the host roster: {unknown} — add a ToolSpec "
                         f"to tools/registry.py (a driven tool the arsenal cannot even name is a gap)")
    return {index[b] for b in binaries}


def _driver_scan(subdir: str) -> tuple[set, set]:
    """(module filenames that touch a host process, roster names those modules drive) for a driver package."""
    modules, binaries = set(), set()
    for path in sorted((_V2 / subdir).glob("*.py")):
        tree = _tree(path)
        if not _spawn_sites(tree):
            continue
        modules.add(path.name)
        binaries |= _driven_binary_names(tree)
    return modules, _roster_names_for(binaries)


def test_typed_builder_list_does_not_drift_from_the_live_executor():
    # profile._TYPED_BUILDER_TOOLS duplicates integration.live.executor._BUILDERS' keys to avoid a backwards
    # crucible→integration import; pin them equal by SOURCE TEXT (no cross-env import) so they can't drift.
    src = (_repo_root() / "integration/vigil_integration/live/executor.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    keys: set = set()
    for node in ast.walk(tree):
        target_names = []
        if isinstance(node, ast.Assign):
            target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target_names = [node.target.id]
        if "_BUILDERS" in target_names and isinstance(getattr(node, "value", None), ast.Dict):
            keys = {k.value for k in node.value.keys if isinstance(k, ast.Constant)}
            break
    assert keys, "could not extract _BUILDERS keys from the executor source"
    assert set(P._TYPED_BUILDER_TOOLS) == keys, (
        f"typed-builder drift: profile={set(P._TYPED_BUILDER_TOOLS)} executor={keys}")


def test_spec_builder_driven_set_does_not_drift_from_oracle_families():
    # profile._SPEC_BUILDER_DRIVEN_TOOLS duplicates the framework-free SSOT
    # integration.live.oracle_families.SPEC_BUILDER_TOOLS (the R4 runner ToolSpec builders) to avoid a
    # backwards crucible→integration import; pin them equal by SOURCE TEXT (no cross-env import) so the
    # tool-profile screen and capability_join can never disagree about which tools have a runner builder.
    src = (_repo_root() / "integration/vigil_integration/live/oracle_families.py").read_text(encoding="utf-8")
    consts = _module_consts(ast.parse(src))
    assert "SPEC_BUILDER_TOOLS" in consts, "oracle_families.py no longer defines SPEC_BUILDER_TOOLS"
    names = _strings(consts["SPEC_BUILDER_TOOLS"], consts)
    assert names, "could not extract SPEC_BUILDER_TOOLS from oracle_families.py"
    assert set(P._SPEC_BUILDER_DRIVEN_TOOLS) == names, (
        f"spec-builder-driven drift: profile={set(P._SPEC_BUILDER_DRIVEN_TOOLS)} "
        f"oracle_families.SPEC_BUILDER_TOOLS={names}")


# The sensor modules that touch a host process, each with WHAT it drives. Pinned so that a NEW sensor which
# spawns anything fails here until a human classifies it (the extractor names binaries; this names modules).
_AUDITED_SENSOR_MODULES = {
    "nmap.py":        "NmapServiceSensor  -> nmap",
    "tshark.py":      "TsharkFlowSensor   -> tshark",
    "web_scanner.py": "NucleiWeb/NucleiTemplateSensor -> nuclei; ZapWebSensor -> zap.sh|zap-cli|zaproxy",
    # spawns an OPERATOR-SUPPLIED fuzz harness under an allowlisted root — the operator's binary, not a
    # named host tool, so it contributes nothing to the arsenal.
    "fuzz.py":        "FuzzHarnessSensor  -> (operator-supplied harness, no host tool)",
}


def test_sensor_driven_set_does_not_drift_from_the_sensors_package():
    modules, names = _driver_scan("sensors")
    assert modules == set(_AUDITED_SENSOR_MODULES), (
        f"sensor driver modules changed: {sorted(modules ^ set(_AUDITED_SENSOR_MODULES))} — classify the "
        f"new/removed module and update _SENSOR_DRIVEN_TOOLS + _AUDITED_SENSOR_MODULES")
    assert set(P._SENSOR_DRIVEN_TOOLS) == names, (
        f"sensor-driven drift: profile={set(P._SENSOR_DRIVEN_TOOLS)} sensors={names}")


_AUDITED_ANALYZER_MODULES = {
    "external.py": "SemgrepAnalyzer -> semgrep; BanditAnalyzer -> bandit; "
                   "GitleaksAnalyzer -> gitleaks; TruffleHogAnalyzer -> trufflehog",
    "joern.py":    "JoernAnalyzer   -> joern (CRUCIBLE_JOERN_HOME or PATH)",
}


def test_analyzer_driven_set_does_not_drift_from_the_analyzers_package():
    modules, names = _driver_scan("analysis/analyzers")
    assert modules == set(_AUDITED_ANALYZER_MODULES), (
        f"analyzer driver modules changed: {sorted(modules ^ set(_AUDITED_ANALYZER_MODULES))} — classify "
        f"the new/removed module and update _ANALYZER_DRIVEN_TOOLS + _AUDITED_ANALYZER_MODULES")
    assert set(P._ANALYZER_DRIVEN_TOOLS) == names, (
        f"analyzer-driven drift: profile={set(P._ANALYZER_DRIVEN_TOOLS)} analyzers={names}")


def test_browser_driven_set_does_not_drift_from_the_scanner_browser_resolver():
    """``scanner/browser.py:_BROWSERS`` is the ONE browser resolver (cdp.py / browser_xss.py go through its
    ``find_browser``), so pin the mirror to that tuple — and assert the sole-resolver property holds, since
    a second resolver elsewhere would be a browser this set could not see."""
    browser_py = _V2 / "scanner/browser.py"
    consts = _module_consts(_tree(browser_py))
    assert "_BROWSERS" in consts, "scanner/browser.py no longer defines _BROWSERS"
    binaries = _strings(consts["_BROWSERS"], consts)
    assert binaries, "could not extract _BROWSERS from scanner/browser.py"
    assert set(P._BROWSER_DRIVEN_TOOLS) == _roster_names_for(binaries), (
        f"browser-driven drift: profile={set(P._BROWSER_DRIVEN_TOOLS)} "
        f"scanner/browser._BROWSERS={sorted(binaries)}")
    others = sorted(p.name for p in (_V2 / "scanner").glob("*.py")
                    if p.name != "browser.py" and "shutil.which" in _spawn_sites(_tree(p)))
    assert not others, (f"a scanner module other than browser.py resolves a binary itself: {others} — "
                        f"route it through browser.find_browser or extend _BROWSER_DRIVEN_TOOLS")
