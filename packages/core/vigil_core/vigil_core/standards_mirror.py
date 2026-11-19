"""vigil_core.standards_mirror — the INERT, namespace-pure MIRROR of the engine's standards + priority tables.

APEX PR-A. The sovereign consumer renders a finding's standards chips and orders its worst-first triage with
the SAME ``bug_class -> controls`` mapping and the SAME deterministic impact×effort priority the engine's
report uses — but WITHOUT importing the engine (FATAL-2, the two-env boundary). The data lives in the committed
``standards_mirror.json`` (GENERATED from ``framework.v2.report.standards`` / ``report.priority`` by
``tools/gen_standards_mirror.py``; a drift test asserts the mirror never diverges from the engine). This module
is the pure reader over that data.

PURE STDLIB, namespace-pure: imports nothing from ``framework`` / ``strix`` / ``sigil`` / ``vigil_integration``,
so it can be imported from either trust domain. It is a JSON load + a handful of table lookups. It asserts and
proves NOTHING on its own — a control mapping is DATA about what a weakness CLASS would implicate, never an
assertion that a control is covered, and it NEVER touches a FACT/oracle verdict.
"""
from __future__ import annotations

import json
import pathlib
from typing import Any, Optional

_DATA_PATH = pathlib.Path(__file__).resolve().parent / "standards_mirror.json"


def _load() -> dict:
    try:
        return json.loads(_DATA_PATH.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — a missing/garbled mirror degrades to an empty table, never a crash
        return {"controls": {}, "standard_versions": {}, "frameworks": [], "ocsf_class_names": {},
                "priority": {"severity_rank": {}, "severity_impact": {}, "effort_weight": {},
                             "effort_rules": [], "tier_labels": {}}}


_MIRROR = _load()
_CONTROLS: dict[str, dict] = _MIRROR.get("controls", {})
_VERSIONS: dict[str, str] = _MIRROR.get("standard_versions", {})
_FRAMEWORKS: tuple[str, ...] = tuple(_MIRROR.get("frameworks", []))
_OCSF: dict[str, str] = _MIRROR.get("ocsf_class_names", {})
_PRIORITY: dict = _MIRROR.get("priority", {})
_SEVERITY_RANK: dict[str, int] = _PRIORITY.get("severity_rank", {})
_SEVERITY_IMPACT: dict[str, float] = _PRIORITY.get("severity_impact", {})
_EFFORT_WEIGHT: dict[str, float] = _PRIORITY.get("effort_weight", {})
_EFFORT_RULES: list = _PRIORITY.get("effort_rules", [])
_TIER_LABELS: dict[str, str] = _PRIORITY.get("tier_labels", {})

# Human display labels for the framework keys (the ``standard_versions`` values already carry the full
# citation; these are the short chip titles). Keyed by the stable framework key the engine uses.
FRAMEWORK_LABELS: dict[str, str] = {
    "owasp": "OWASP Top 10",
    "cwe": "CWE",
    "pci_dss": "PCI DSS",
    "soc2": "SOC 2",
    "iso27001": "ISO 27001",
    "attack": "MITRE ATT&CK",
    "nist_csf": "NIST CSF",
    "d3fend": "MITRE D3FEND",
    "ocsf": "OCSF",
    "ssdf": "NIST SSDF",
}


def _strnorm(bug_class: str) -> str:
    """The pure-string normalisation the mirror is keyed on (the engine's ``normalize_bug_class`` MINUS the
    alias fold — aliases are PRE-RESOLVED into the mirror values, so no alias map is needed here)."""
    key = (bug_class or "").strip().lower().replace("-", "_").replace(" ", "_")
    while "__" in key:
        key = key.replace("__", "_")
    return key


def controls_for(bug_class: str) -> Optional[dict[str, Any]]:
    """The standards controls a ``bug_class`` implicates, as DATA — or ``None`` for a class the engine
    vocabulary does not map. Equals the engine's ``report.standards.controls_for`` for every input (the drift
    test proves it). NEVER a coverage assertion — only what a weakness of this class WOULD implicate."""
    hit = _CONTROLS.get(_strnorm(bug_class))
    return dict(hit) if isinstance(hit, dict) else None


def standard_versions() -> dict[str, str]:
    """The framework-key -> full-citation map (e.g. ``owasp`` -> ``OWASP Top 10:2021``)."""
    return dict(_VERSIONS)


def frameworks() -> tuple[str, ...]:
    """The canonical framework-key order for rendering chips."""
    return _FRAMEWORKS


def framework_label(key: str) -> str:
    """The short display title for a framework key (falls back to the key itself)."""
    return FRAMEWORK_LABELS.get(key, key)


def ocsf_class_name(code: str) -> str:
    """The OCSF class NAME for a numeric class code (falls back to the code)."""
    return _OCSF.get(str(code), str(code))


def standards_chips(controls: Optional[dict[str, Any]]) -> list[dict[str, Any]]:
    """Render ``controls`` (from :func:`controls_for` or a signed presentation block) into an ordered,
    display-ready chip list: ``[{framework, label, version, ids}]`` in the canonical framework order, skipping
    frameworks with no ids. Pure/deterministic; a non-dict input yields ``[]``."""
    if not isinstance(controls, dict):
        return []
    chips: list[dict[str, Any]] = []
    for key in _FRAMEWORKS:
        val = controls.get(key)
        if not val:
            continue
        ids = [val] if isinstance(val, str) else [str(v) for v in val]
        if not ids:
            continue
        chips.append({"framework": key, "label": framework_label(key),
                      "version": _VERSIONS.get(key, ""), "ids": ids})
    return chips


# --- the deterministic impact×effort priority (mirrors report.priority) ----------------------------------

SEVERITY_RANK: dict[str, int] = dict(_SEVERITY_RANK)   # engine-cased ("Critical"=0 .. "Info"=4)


def effort_size(bug_class: str) -> str:
    """Class-level fix-effort estimate ('S'|'M'|'L'|'XL'), mirroring ``report.priority.effort_size``:
    substring match against the normalised class, first rule hit wins, default 'M'. Deterministic."""
    b = (bug_class or "").strip().lower()
    if b:
        for keys, size in _EFFORT_RULES:
            if any(k in b for k in keys):
                return size
    return "M"


def impact_weight(severity: str) -> float:
    """Business-impact weight from a (engine-cased) severity; default 1.0 (Info)."""
    return _SEVERITY_IMPACT.get(severity, 1.0)


def priority_score(severity: str, bug_class: str) -> float:
    """impact / effort — higher sorts first (a quick win), rounded to 4 dp. Mirrors
    ``report.priority.priority_score``. ``severity`` is engine-cased ('Critical'…'Info')."""
    weight = _EFFORT_WEIGHT.get(effort_size(bug_class), 2.0)
    return round(impact_weight(severity) / weight, 4) if weight else 0.0


def tier(severity: str, size: str) -> int:
    """Remediation tier (0=stop-the-bleeding … 3=low/info), mirroring ``report.priority._tier``.
    ``severity`` is engine-cased."""
    if severity in ("Critical", "High") and size == "S":
        return 0
    if severity in ("Critical", "High"):
        return 1
    if severity == "Medium":
        return 2
    return 3


def tier_label(t: int) -> str:
    """The display label for a remediation tier."""
    return _TIER_LABELS.get(str(t), "")
