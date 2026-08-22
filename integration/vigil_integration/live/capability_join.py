"""H4 — one capability view, joined from the registries that never referenced each other.

THE DEFECT. What VIGIL knows about a tool is scattered across five places that share no key:

    brains/hexstrike_brain.py::_TOOL_DANGER     35 tools the PLANNER may propose, + danger class
    docs/capability-matrix/hexstrike.json       33 rows of licence/privilege/oracle_family/fact_capable
    live/executor.py::_BUILDERS                  9 tools with a typed argv builder — the only ones that
                                                   can actually be spawned; everything else is denied
                                                   fail-closed at execute()
    framework/v2/tools/registry.py::HOST_TOOLS  16 tools with a LIVE presence/version probe
    live/tool_manifest.py                       the validator over the catalogue's invariants

Nothing computed the intersection, so a tool the planner proposes but VIGIL cannot execute simply
DISAPPEARED at run time: the chain listed it, the executor denied it, and no surface said why. Measured on
the current tree, 29 of the 35 proposable tools have no argv builder and 20 are absent from the catalogue
entirely.

WHAT THIS PROVIDES. One row per tool carrying every fact, and a STATUS that is never silence:

    EXECUTABLE      proposable, adapted, and present on this host
    UNAVAILABLE     adapted but not installed here — or proposable with no adapter at all
    BLOCKED         deliberately refused (an excluded offense/credential-access tool)
    NOT_PROPOSABLE  known to VIGIL but outside the planner's curated set

Every non-EXECUTABLE row carries a human-readable ``reason``. The planner is expected to plan against
``known ∩ installed ∩ authorized ∩ adapted`` and to render the remainder with that reason attached, so a
tool is never silently missing from a plan.

``join()`` is PURE — it takes the five inputs as data, so it is fully testable without Docker, without a
host probe, and without importing the offense engine. ``resolve()` gathers the real inputs and is the thin,
side-effecting half.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional

EXECUTABLE = "EXECUTABLE"
UNAVAILABLE = "UNAVAILABLE"
BLOCKED = "BLOCKED"
NOT_PROPOSABLE = "NOT_PROPOSABLE"

#: Statuses a planner must render with their reason rather than dropping from the plan.
SURFACED = (UNAVAILABLE, BLOCKED)


@dataclass(frozen=True)
class ToolCapability:
    """Everything VIGIL knows about one tool, in one row."""

    name: str
    status: str
    reason: str = ""
    proposable: bool = False
    danger: str = ""
    catalogued: bool = False
    oracle_family: str = ""
    fact_capable: bool = False
    excluded: bool = False
    typed_builder: bool = False
    installed: Optional[bool] = None      # None ⇒ presence was not probed on this host
    version: str = ""

    @property
    def runnable(self) -> bool:
        return self.status == EXECUTABLE

    def to_row(self) -> dict:
        return {
            "name": self.name, "status": self.status, "reason": self.reason,
            "proposable": self.proposable, "danger": self.danger,
            "catalogued": self.catalogued, "oracle_family": self.oracle_family,
            "fact_capable": self.fact_capable, "excluded": self.excluded,
            "typed_builder": self.typed_builder, "installed": self.installed,
            "version": self.version,
        }


def _classify(*, proposable: bool, excluded: bool, typed_builder: bool,
              installed: Optional[bool], name: str) -> tuple[str, str]:
    """The status rules, in precedence order. Refusal reasons beat availability reasons."""
    if excluded:
        return BLOCKED, (
            f"{name} is an excluded class (offense / credential-access): VIGIL never treats its output as a "
            f"FACT (excluded ⇒ never fact-capable) and confirms this class with its own gated re-drive + "
            f"oracle. A brain-proposed step for it is surfaced BLOCKED for the operator and is never "
            f"auto-promoted"
        )
    if not proposable:
        return NOT_PROPOSABLE, (
            f"{name} is outside the planner's curated set, so no plan will contain it"
        )
    if not typed_builder:
        return UNAVAILABLE, (
            f"{name} has no typed argv builder, so the executor denies it fail-closed. Planning it would "
            f"produce a step that can never run"
        )
    if installed is False:
        return UNAVAILABLE, f"{name} has an adapter but is not installed on this host"
    if installed is None:
        return UNAVAILABLE, (
            f"{name} has an adapter but its presence was not probed, so it cannot be promised runnable"
        )
    return EXECUTABLE, ""


def join(*, brain_tools: Mapping[str, str], catalogue: Mapping[str, Mapping[str, Any]],
         builders: Iterable[str], installed: Optional[Mapping[str, Mapping[str, Any]]] = None,
         ) -> list[ToolCapability]:
    """Compute one capability row per tool known to ANY source. Pure.

    ``brain_tools``  name -> danger class (the planner's catalogue)
    ``catalogue``    name -> {oracle_family, fact_capable, excluded, ...} (the capability matrix)
    ``builders``     names with a typed argv builder (what can actually be spawned)
    ``installed``    name -> {installed: bool, version: str} from a live probe; None ⇒ not probed
    """
    builder_set = {str(b) for b in builders}
    probe: Mapping[str, Mapping[str, Any]] = installed or {}
    names = sorted(set(brain_tools) | set(catalogue) | builder_set | set(probe))

    rows: list[ToolCapability] = []
    for name in names:
        cat = dict(catalogue.get(name) or {})
        present: Optional[bool] = None
        version = ""
        if name in probe:
            present = bool(probe[name].get("installed"))
            version = str(probe[name].get("version") or "")
        status, reason = _classify(
            proposable=name in brain_tools,
            excluded=bool(cat.get("excluded")),
            typed_builder=name in builder_set,
            installed=present,
            name=name,
        )
        rows.append(ToolCapability(
            name=name, status=status, reason=reason,
            proposable=name in brain_tools, danger=str(brain_tools.get(name) or ""),
            catalogued=name in catalogue, oracle_family=str(cat.get("oracle_family") or ""),
            fact_capable=bool(cat.get("fact_capable")), excluded=bool(cat.get("excluded")),
            typed_builder=name in builder_set, installed=present, version=version,
        ))
    return rows


def plannable(rows: Iterable[ToolCapability]) -> list[str]:
    """The intersection a planner may actually schedule: known ∩ authorized ∩ adapted ∩ installed."""
    return [r.name for r in rows if r.runnable]


def surfaced(rows: Iterable[ToolCapability]) -> list[ToolCapability]:
    """Rows a planner must SHOW with their reason instead of dropping (the anti-silence rule)."""
    return [r for r in rows if r.status in SURFACED and r.proposable]


def resolve(*, probe_host: bool = False) -> list[ToolCapability]:
    """Gather the real inputs and join them. The only side-effecting entry point.

    ``probe_host`` runs the LIVE presence/version probe, which shells out to ``command -v`` and version
    banners; it is off by default so a caller that only wants the static picture pays nothing. Every
    import here is function-local so importing this module co-loads neither the planner nor the engine.
    """
    from ..brains.hexstrike_brain import _TOOL_DANGER
    from .executor import _BUILDERS

    brain_tools = {name: getattr(danger, "value", str(danger)) for name, danger in _TOOL_DANGER.items()}
    catalogue = _load_catalogue()
    installed = _probe_installed() if probe_host else None
    return join(brain_tools=brain_tools, catalogue=catalogue, builders=_BUILDERS, installed=installed)


def _load_catalogue() -> dict[str, dict]:
    """The committed capability matrix, keyed by tool name."""
    import json
    from pathlib import Path

    path = Path(__file__).resolve().parents[3] / "docs" / "capability-matrix" / "hexstrike.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — an unreadable matrix must not crash a status view
        return {}
    rows = raw.get("tools") if isinstance(raw, dict) else raw
    if isinstance(rows, dict):
        rows = list(rows.values())
    return {str(r.get("name")): r for r in (rows or []) if isinstance(r, dict) and r.get("name")}


def _probe_installed() -> dict[str, dict]:
    """Live presence/version, via the offense roster's own shadow-aware probe.

    ``probe_tools()`` returns ``{"platform":…, "tools":[{name, installed, shadowed, path, version}], …}`` —
    a dict, not a list. Iterating it directly yields the top-level KEYS, which silently produced an empty
    probe and made every adapted tool look "not installed". Read the ``tools`` list explicitly.

    A SHADOWED binary counts as NOT installed: the roster flags the case where the name resolves to a
    different program than intended (the Python ``httpx`` package shadowing the httpx CLI), and running
    that would execute something other than the tool the plan named.
    """
    try:
        from framework.v2.tools.registry import probe_tools
    except Exception:  # noqa: BLE001 — no offense engine on this path ⇒ presence simply unknown
        return {}
    out: dict[str, dict] = {}
    try:
        report = probe_tools() or {}
        for entry in (report.get("tools") or []):
            name = str(entry.get("name") or "")
            if not name:
                continue
            out[name] = {
                "installed": bool(entry.get("installed")) and not bool(entry.get("shadowed")),
                "version": str(entry.get("version") or ""),
                "shadowed": bool(entry.get("shadowed")),
            }
    except Exception:  # noqa: BLE001
        return {}
    return out
