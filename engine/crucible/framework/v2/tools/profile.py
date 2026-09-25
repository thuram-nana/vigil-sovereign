"""
tools.profile — the unified ToolProfile + the tool-consciousness admission gate (Phase B1).

Per-tool knowledge is split across disjoint sources. This JOINS them, on the host-tool BINARY NAME (the id
that ``tools.registry`` roster keys, the Strix ``skills/tooling/<name>.md`` playbook stems, and the typed
``executor._BUILDERS`` all share), into one profile the operator/agent can reason over:

  * install + live status + binary + version + install_hint  ← :func:`tools.registry.probe_tools`
  * CLI-usage knowledge ("already knows how to use it")       ← a Strix ``tooling/<name>.md`` skill playbook
  * a machine-checkable "we can drive its CLI ourselves"      ← a typed argv builder in the live executor,
                                                                 OR a runner-owned ToolSpec builder on the R4
                                                                 runner path (``live.external_tool``)
  * the engine's OWN drivers — the code that already spawns   ← a gated ``sensors`` sensor, an
    the binary as part of an engagement                          ``analysis.analyzers`` analyzer, or the
                                                                 ``scanner.browser`` headless-browser driver

THE ADMISSION GATE (the operator's rule — "only globally-recognised tools it can fully control via CLI or
background"): a tool is ADMITTED to the arsenal iff it is ``global_recognition`` AND has a ``control_surface``
in :data:`_ADMITTABLE_SURFACES`. A tool with a binary but no way to drive it at all (no skill playbook, no
typed builder, and no engine driver) is REFUSED with an honest reason — the system will not claim to control
a tool it has no way to drive. This is advisory metadata only: it ADVISES what may be adopted/run; every
actual execution still passes the WARDEN gate, and a finding is a FACT only via a fired oracle. Read-only +
pure (safe to call on every request).

WHAT IS *NOT* COUNTED AS A CONTROL SURFACE (the honest boundary, so the gate keeps its teeth):

  * A PARSER for a tool's report (``imports.parsers``, ``eval.adapters_ext.parse_*``) is not control —
    reading someone else's output proves nothing about being able to produce it.
  * The offline BENCHMARK harness (``eval.adapters`` / ``eval.benchmark_run``) does spawn incumbents
    (nikto / wapiti / sqlmap / …) to SCORE CRUCIBLE against them; that is a measurement rig, not the
    engagement pipeline — it is not WARDEN/scope-gated, is not exposed to the agent as a tool, and is
    skippable with ``--incumbent-free``. Counting it would let the screen claim an engagement capability
    that does not exist, so it is deliberately excluded and those tools stay REFUSED until a real driver
    (playbook / typed builder / sensor) is BUILT for them.

Two-env boundary: OFFENSE-side (imports the framework roster; the Strix catalog is imported LAZILY so this
module stays import-clean when Strix is absent — then skill-doc knowledge simply reads empty, honestly).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from .registry import probe_tools

# The tools the live executor can turn into a validated, gated argv itself (a STRONG "control via CLI"
# proof — VIGIL builds + gates the command). Duplicated from integration.live.executor._BUILDERS to avoid
# a backwards crucible→integration import; a drift-guard test asserts this stays equal to that source.
_TYPED_BUILDER_TOOLS = frozenset({"ffuf", "httpx", "hydra", "nikto", "nmap", "nuclei",
                                  "sqlmap", "wapiti", "zaproxy"})

# The tools VIGIL drives via a runner-owned ToolSpec builder on the R4 runner path
# (``integration.live.external_tool``, reached through ``brains.hexstrike_body._spec_for_kind``). Like a
# typed executor builder this is a "control via CLI" proof — VIGIL constructs + gates the argv ITSELF,
# server-side — but on the runner path, not the governed executor, so these are deliberately NOT in
# ``_TYPED_BUILDER_TOOLS`` (the governed executor would fail-close on them). Recognising them here is the
# tool-profile half of the H4b meet-up: ``integration.live.capability_join`` already folds this same set into
# its builder source, so the operator's tool-profile screen and the brain-proposal panel AGREE — a port
# scanner that is spawnable + FACT-capable via the R4 runner is "adapted (cli)", not "nothing drives it".
# Duplicated (same reason as ``_TYPED_BUILDER_TOOLS``) from the framework-free SSOT
# ``integration.live.oracle_families.SPEC_BUILDER_TOOLS``; a drift-guard test pins this equal to that source.
_SPEC_BUILDER_DRIVEN_TOOLS = frozenset({"masscan", "naabu", "nmap", "rustscan", "sslscan",
                                        "unicornscan", "zmap", "httpx", "ffuf"})

# Globally-recognised tools NOT in the host roster and without a Strix skill doc (net-new curated metadata;
# empty today — the curated host roster + the maintained skill playbooks already are the recognition list).
_EXTRA_RECOGNISED: frozenset = frozenset()

# ---------------------------------------------------------------------------------------------------
# the engine's OWN drivers — control surfaces that exist in code, not in a playbook
# ---------------------------------------------------------------------------------------------------
# A playbook and a typed builder are not the only ways this engine drives a binary: parts of CRUCIBLE
# resolve and spawn tools THEMSELVES. Those tools are genuinely controllable, and reporting them as
# "no CLI-usage knowledge" was a REPORTING defect (the operator saw six installed tools refused that
# the engine already runs). The sets below name them, in ROSTER-KEY space (``tools.registry`` names,
# so an alt binary like ``zap.sh`` / ``chromium-browser`` folds onto its one roster tool).
#
# Each is a small explicit MIRROR rather than an import, for the same reason ``_TYPED_BUILDER_TOOLS``
# mirrors the executor instead of importing it (that one avoids a backwards crucible→integration
# import): ``tools.profile`` is a pure, import-light, read-only metadata module called on every console
# request, and importing ``sensors`` / ``analysis`` / ``scanner`` here would drag the whole observation,
# world-model and subprocess stack — plus an import cycle risk — into a function that needs only NAMES.
# A drift-guard test per set parses the REAL source and asserts the mirror equals what that source
# actually drives (and that each name is in the host roster), so a tool added to a sensor/analyzer/the
# browser resolver and forgotten here FAILS THE BUILD instead of silently rotting.

# Mirrors: sensors/*.py — the binaries the gated sensors resolve + spawn (registered in
# ``sensors.builtin.register_builtin_sensors``; registration is not invocation — each still passes
# run_sensor's kill-switch/entitlement/scope/egress gate).
#   nmap     ← sensors/nmap.py:NmapServiceSensor           (shutil.which("nmap"))
#   nuclei   ← sensors/web_scanner.py:NucleiWebSensor / NucleiTemplateSensor (binary="nuclei")
#   tshark   ← sensors/tshark.py:TsharkFlowSensor          (shutil.which("tshark"))
#   zaproxy  ← sensors/web_scanner.py:ZapWebSensor         (_ZAP_BINARIES = zaproxy|zap.sh|zap-cli)
# NOT here: sensors/fuzz.py spawns an OPERATOR-SUPPLIED harness under an allowlisted root — that is
# the operator's binary, not a named host tool, so it names nothing in the arsenal.
_SENSOR_DRIVEN_TOOLS = frozenset({"nmap", "nuclei", "tshark", "zaproxy"})

# Mirrors: analysis/analyzers/*.py — the SAST backends the analysis orchestrator runs when present.
#   semgrep    ← analyzers/external.py:SemgrepAnalyzer     (shutil.which("semgrep"))
#   joern      ← analyzers/joern.py:JoernAnalyzer          (CRUCIBLE_JOERN_HOME or shutil.which("joern"))
#   bandit     ← analyzers/external.py:BanditAnalyzer      (shutil.which("bandit"))
#   gitleaks   ← analyzers/external.py:GitleaksAnalyzer    (shutil.which("gitleaks"))
#   trufflehog ← analyzers/external.py:TruffleHogAnalyzer  (shutil.which("trufflehog"))
# All five are SOURCE analyzers — they take a directory, not a host — which is why none of them is a
# typed argv builder: the live executor fail-closes without a network target to resolve.
_ANALYZER_DRIVEN_TOOLS = frozenset({"semgrep", "joern", "bandit", "gitleaks", "trufflehog"})

# Mirrors: scanner/browser.py:_BROWSERS — the headless browser the DOM-XSS confirmation launches
# (``scanner/browser.py`` is the sole resolver; ``scanner/cdp.py`` and ``scanner/browser_xss.py``
# both go through its ``find_browser``). All five alt binaries fold onto the roster's ``chromium``.
_BROWSER_DRIVEN_TOOLS = frozenset({"chromium"})

# How a tool is driven, most-direct first. "cli" keeps its original meaning EXACTLY — the model reads a
# CLI playbook, or the live executor builds a validated argv — so nothing that was "cli" changes. The
# engine-driver labels are deliberately distinct: a tool run by a sensor is NOT a model reading a
# playbook, and the operator deserves to see which of the two they have.
_SURFACE_CLI = "cli"
_SURFACE_SENSOR = "sensor"
_SURFACE_ANALYZER = "analyzer"
_SURFACE_BROWSER = "browser"

# The CLOSED allowlist of surfaces that admit. Closed on purpose: a future label that is not listed
# here refuses, so "give it a surface string" can never become "admit everything".
_ADMITTABLE_SURFACES = frozenset({_SURFACE_CLI, "background", _SURFACE_SENSOR, _SURFACE_ANALYZER,
                                  _SURFACE_BROWSER})


@dataclass(frozen=True)
class ToolProfile:
    """One tool's fused, operator-facing profile. ``admitted``/``admit_reason`` are the consciousness gate's
    verdict; everything else is joined evidence. All advisory — never a fact, never an authorization."""

    name: str
    binary: str = ""
    purpose: str = ""
    # live status (from the host probe; "" / not_in_roster for a Strix-sandbox-only tool)
    status: str = "not_in_roster"
    installed: bool = False
    path: str = ""
    version: str = ""
    install_hint: str = ""
    apt: str = ""
    pip: str = ""
    in_host_roster: bool = False
    # consciousness signals
    has_skill_doc: bool = False        # a Strix tooling/<name>.md CLI playbook exists ("knows how to use it")
    has_typed_builder: bool = False    # the live executor can build a validated, gated argv for it
    has_spec_builder: bool = False     # a runner-owned ToolSpec builds a validated, gated argv (R4 runner path)
    has_sensor: bool = False           # a gated sensor resolves + spawns it (sensors/*.py)
    has_analyzer: bool = False         # an analysis backend resolves + spawns it (analysis/analyzers/*.py)
    has_browser_driver: bool = False   # the scanner's headless-browser driver launches it (scanner/browser.py)
    # HOW it is driven — "cli" (playbook or typed argv) | "sensor" | "analyzer" | "browser" |
    # "background" | "" (nothing drives it → refused). See _ADMITTABLE_SURFACES.
    control_surface: str = ""
    global_recognition: bool = False
    admitted: bool = False
    admit_reason: str = ""


def _skill_tooling_names() -> set:
    """The Strix tooling skill-doc stems (the tools with a CLI playbook). Lazy + fail-open-to-empty so the
    framework never hard-depends on Strix; absent Strix ⇒ no skill knowledge (honest, not a crash)."""
    try:
        from strix.skills import get_available_skills
    except Exception:  # noqa: BLE001 — Strix not installed / import error ⇒ no skill docs, honestly
        return set()
    try:
        return {str(n).strip().lower() for n in (get_available_skills().get("tooling") or [])}
    except Exception:  # noqa: BLE001
        return set()


def _control_surface(*, has_skill_doc: bool, has_typed_builder: bool,
                     has_sensor: bool = False, has_analyzer: bool = False,
                     has_browser_driver: bool = False, has_spec_builder: bool = False) -> str:
    """How we can drive the tool, reported as the MOST DIRECT surface we have.

    "cli" is unchanged in MEANING: VIGIL can drive the tool's CLI — a CLI playbook (the model knows the CLI),
    a typed executor argv builder, OR a runner-owned ToolSpec builder (both build + gate the command; the
    latter on the R4 runner path). It keeps precedence, so every tool that reported "cli" before still does.
    Otherwise the engine's own driver is named honestly — a sensor / an analyzer / the headless browser is
    real control (that code resolves the binary and spawns it), but it is NOT a model reading a playbook, and
    the screen should say which. Nothing at all ⇒ "" (no way to drive it → refused)."""
    if has_skill_doc or has_typed_builder or has_spec_builder:
        return _SURFACE_CLI
    if has_sensor:
        return _SURFACE_SENSOR
    if has_analyzer:
        return _SURFACE_ANALYZER
    if has_browser_driver:
        return _SURFACE_BROWSER
    return ""


def _admit(global_recognition: bool, control_surface: str) -> tuple[bool, str]:
    """The gate: globally recognised AND a real control surface from the CLOSED _ADMITTABLE_SURFACES
    allowlist. Fail-closed + honest reason (an unknown surface label refuses, it does not admit)."""
    if not global_recognition:
        return False, "refused: not a globally-recognised tool (arsenal is curated, not arbitrary)"
    if control_surface not in _ADMITTABLE_SURFACES:
        return False, ("refused: no CLI-usage knowledge and nothing in the engine drives it — add a skill "
                       "playbook, a typed argv builder, or a sensor/analyzer driver before this tool can "
                       "be driven")
    return True, f"admitted ({control_surface})"


def build_profiles() -> dict:
    """Join every known tool into a ToolProfile and apply the admission gate. Deterministic (sorted by name),
    real-data-only, honest-empty. Returns {profiles:[...], summary:{...}}."""
    roster = {t["name"].strip().lower(): t for t in probe_tools().get("tools", [])}
    skill_docs = _skill_tooling_names()
    names = sorted(set(roster) | skill_docs | set(_TYPED_BUILDER_TOOLS)
                   | set(_SPEC_BUILDER_DRIVEN_TOOLS) | set(_EXTRA_RECOGNISED))

    profiles: list[dict] = []
    for name in names:
        t = roster.get(name, {})
        in_roster = name in roster
        has_skill = name in skill_docs
        has_builder = name in _TYPED_BUILDER_TOOLS
        has_spec_builder = name in _SPEC_BUILDER_DRIVEN_TOOLS
        has_sensor = name in _SENSOR_DRIVEN_TOOLS
        has_analyzer = name in _ANALYZER_DRIVEN_TOOLS
        has_browser = name in _BROWSER_DRIVEN_TOOLS
        surface = _control_surface(has_skill_doc=has_skill, has_typed_builder=has_builder,
                                   has_sensor=has_sensor, has_analyzer=has_analyzer,
                                   has_browser_driver=has_browser, has_spec_builder=has_spec_builder)
        # Recognition: the curated roster / playbook list, PLUS a runner-owned ToolSpec builder — a tool VIGIL
        # constructs + gates a validated argv for is in the curated arsenal by construction (it is not an
        # arbitrary binary; the drift guard pins the set to the committed SSOT). Every OTHER recognition source
        # is a roster/playbook entry, and the driver drift guards ASSERT a driven binary is in the roster, so
        # this does not widen "recognised" to anything undriveable.
        recognised = in_roster or has_skill or has_spec_builder or name in _EXTRA_RECOGNISED
        admitted, reason = _admit(recognised, surface)
        profiles.append(asdict(ToolProfile(
            name=name,
            binary=str(t.get("binary", "") or name),
            purpose=str(t.get("purpose", "") or ""),
            status=str(t.get("status", "not_in_roster")) if in_roster else "not_in_roster",
            installed=bool(t.get("installed", False)),
            path=str(t.get("path", "") or ""),
            version=str(t.get("version", "") or ""),
            install_hint=str(t.get("install_hint", "") or ""),
            apt=str(t.get("apt", "") or ""),
            pip=str(t.get("pip", "") or ""),
            in_host_roster=in_roster,
            has_skill_doc=has_skill,
            has_typed_builder=has_builder,
            has_spec_builder=has_spec_builder,
            has_sensor=has_sensor,
            has_analyzer=has_analyzer,
            has_browser_driver=has_browser,
            control_surface=surface,
            global_recognition=recognised,
            admitted=admitted,
            admit_reason=reason,
        )))

    summary = {
        "total": len(profiles),
        "admitted": sum(1 for p in profiles if p["admitted"]),
        "refused": sum(1 for p in profiles if not p["admitted"]),
        "installed": sum(1 for p in profiles if p["installed"]),
        "installable_missing": sum(1 for p in profiles
                                   if p["admitted"] and not p["installed"] and p["install_hint"]),
    }
    return {"profiles": profiles, "summary": summary}
