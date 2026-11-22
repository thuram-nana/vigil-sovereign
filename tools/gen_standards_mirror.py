#!/usr/bin/env python3
"""Generate the vigil_core standards MIRROR (``vigil_core/standards_mirror.json``) from the engine.

APEX PR-A. The sovereign consumer renders the per-finding standards chips + the deterministic impact×effort
priority WITHOUT importing the engine (FATAL-2 — the two-env boundary). To do that soundly it needs the SAME
``bug_class -> controls`` table and the SAME priority tables the engine uses, but as INERT DATA it can import
on the sovereign side. This committed generator reads the engine's ``report.standards`` / ``report.priority``
/ ``verify.verifier`` and writes that data verbatim into a JSON file vigil_core ships (exactly as it already
ships ``warden_golden.json``). A drift test (``report/tests/test_standards_mirror.py``) RE-RUNS this generator
in memory and asserts byte-equality with the committed file, so the mirror can never silently drift from the
engine table.

Run under the OFFENSE venv (which can import ``framework``):

    PYTHONPATH=engine/crucible:packages/core/vigil_core .venv-offense/bin/python tools/gen_standards_mirror.py

The ``controls`` map is keyed by the PURE-STRING normalisation of every KNOWN class spelling (canonical +
alias source spellings), with aliases PRE-RESOLVED (``controls_for`` folds them), so the consumer needs only
the string normalisation — never the alias map — to look a class up: ``controls.get(strnorm(bug_class))``
equals the engine's ``controls_for(bug_class)`` for every input (proven by the drift test)."""
from __future__ import annotations

import json
import pathlib


def _strnorm(bug_class: str) -> str:
    """The engine's ``normalize_bug_class`` MINUS the alias fold — the pure string shape the mirror keys on
    (aliases are pre-resolved into the values, so the consumer never needs the alias map)."""
    key = (bug_class or "").strip().lower().replace("-", "_").replace(" ", "_")
    while "__" in key:
        key = key.replace("__", "_")
    return key


def build_mirror() -> dict:
    """Build the mirror dict from the engine tables (deterministic; sorted). Importable so the drift test can
    compare it against the committed file without shelling out."""
    from framework.v2.report import priority as P
    from framework.v2.report import standards as S
    from framework.v2.verify.verifier import known_bug_classes

    controls: dict[str, dict] = {}
    for cls in sorted(known_bug_classes()):
        mapped = S.controls_for(cls)
        if mapped is None:
            continue
        key = _strnorm(cls)
        # Two spellings that normalise to the same key fold (via the alias map) to the same canonical class,
        # so they MUST agree; assert it so a future table edit that breaks the property is caught here.
        if key in controls and controls[key] != mapped:
            raise SystemExit(f"mirror collision: {key!r} maps to two different control sets")
        controls[key] = mapped

    return {
        "schema": 1,
        "generated_note": ("GENERATED from framework.v2.report.standards/priority by "
                           "tools/gen_standards_mirror.py — do not edit by hand; "
                           "report/tests/test_standards_mirror.py re-generates and asserts equality."),
        "controls": dict(sorted(controls.items())),
        "standard_versions": dict(sorted(S.STANDARD_VERSIONS.items())),
        "frameworks": list(S._FRAMEWORKS),
        "ocsf_class_names": dict(sorted(S.OCSF_CLASS_NAMES.items())),
        # PR-G (Area 6): the OWASP Top 10:2021 category names, so the consumer's compliance view names every category
        # (A01..A10) exactly as the engine's report does — display data only, never a coverage assertion.
        "owasp_names": dict(sorted(S.OWASP_2021_NAMES.items())),
        "priority": {
            "severity_rank": dict(P.SEVERITY_RANK),
            "severity_impact": dict(P._SEVERITY_IMPACT),
            "effort_weight": dict(P._EFFORT_WEIGHT),
            # tuple-of-(substrings, size) -> list-of-[sorted-list, size]; order PRESERVED (first hit wins).
            "effort_rules": [[list(keys), size] for keys, size in P._EFFORT_RULES],
            "tier_labels": {str(k): v for k, v in P._TIER_LABEL.items()},
        },
    }


def mirror_json(mirror: dict) -> str:
    """The canonical on-disk form (sorted keys, 2-space indent, trailing newline) — the drift test compares
    exactly this string."""
    return json.dumps(mirror, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def target_path() -> pathlib.Path:
    return (pathlib.Path(__file__).resolve().parents[1]
            / "packages" / "core" / "vigil_core" / "vigil_core" / "standards_mirror.json")


def main() -> int:
    out = target_path()
    out.write_text(mirror_json(build_mirror()), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
