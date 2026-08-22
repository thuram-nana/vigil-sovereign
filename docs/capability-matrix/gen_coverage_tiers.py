#!/usr/bin/env python3
"""Generate the evidence-tier coverage table from the ONE source of truth.

WHY THIS EXISTS. Two shipped documents once disagreed about the system's single most-quoted honesty
number — the split of detector kinds across evidence tiers. ``docs/plain-english/05-weakness-types.md``
said ``3 / 2 / 13 / 20`` (external / own-infrastructure / local / fixtures) while
``docs/plain-english/_inventory/E-today-and-catalogues.md`` said ``3 / 2 / 12 / 21``. A number a reader
quotes back to a national agency cannot be maintained by hand in two places and hope to stay equal.

THE DESIGN. The tier of each detector kind lives once, in ``docs/capability-matrix/coverage-tiers.json``,
keyed by ``OracleKind`` — the detector-kind registry in
``engine/crucible/framework/v2/verify/models.py``. This module renders a single fenced block from that
file and writes the SAME block into both documents, between HTML-comment markers. The drift guard
(``docs/tests/test_coverage_tiers_drift.py``) re-runs the render and fails if either document has drifted
or if the source of truth has itself come loose from the registry.

GROUNDING (``--check`` / :func:`validate`). The source of truth is not free to say anything: it must list
EXACTLY the ``OracleKind`` members (no phantom detector, no omission), every ``oracle_version`` used in
``evidence-branches.json`` must be one of those kinds, and every tier must be in the closed vocabulary.
Reading ``models.py`` is done by AST over its SOURCE TEXT — this module imports neither trust domain and
uses only the standard library, so it is safe in the reads-only ``briefing-completeness`` CI leg (which
installs only pytest) and cannot pull an offensive module into a sovereign process.

    python3 docs/capability-matrix/gen_coverage_tiers.py            # write the block into both docs
    python3 docs/capability-matrix/gen_coverage_tiers.py --check    # fail on any drift (no writes)
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent            # docs/capability-matrix
_REPO = _HERE.parents[1]                            # repo root
_SOURCE = _HERE / "coverage-tiers.json"
_BRANCHES = _HERE / "evidence-branches.json"
_MODELS = _REPO / "engine" / "crucible" / "framework" / "v2" / "verify" / "models.py"

# The two shipped documents that quote the number, and the assembled build product they feed.
_DOC_05 = _REPO / "docs" / "plain-english" / "05-weakness-types.md"
_DOC_E = _REPO / "docs" / "plain-english" / "_inventory" / "E-today-and-catalogues.md"
TARGET_DOCS = (_DOC_05, _DOC_E)

BEGIN = ("<!-- BEGIN GENERATED coverage-tiers (source: docs/capability-matrix/coverage-tiers.json; "
         "regenerate: python3 docs/capability-matrix/gen_coverage_tiers.py) -->")
END = "<!-- END GENERATED coverage-tiers -->"

# Canonical render order — strongest evidence first, matching 05-weakness-types.md's prose.
_ORDER = ("external", "own_infrastructure", "local", "fixtures")


class DriftError(Exception):
    """The source of truth or a document is out of step with the registry."""


def _oracle_kinds() -> set[str]:
    """The detector-kind registry: the string values of ``OracleKind``, read by AST (no import)."""
    tree = ast.parse(_MODELS.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "OracleKind":
            vals: set[str] = set()
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Constant) \
                        and isinstance(stmt.value.value, str):
                    vals.add(stmt.value.value)
            if not vals:
                raise DriftError("OracleKind defines no string members — parser or enum changed")
            return vals
    raise DriftError(f"OracleKind enum not found in {_MODELS}")


def load_source() -> dict:
    return json.loads(_SOURCE.read_text(encoding="utf-8"))


def validate(source: dict | None = None) -> dict[str, int]:
    """Ground the source of truth against the registry and return {tier: count}.

    Raises :class:`DriftError` on any mismatch. This is the load-bearing check: it is what makes the
    generated number trustworthy rather than merely self-consistent.
    """
    source = source if source is not None else load_source()
    tier_ids = {t["id"] for t in source["tiers"]}
    if list(tier_ids) and set(_ORDER) != tier_ids:
        raise DriftError(f"tier vocabulary {sorted(tier_ids)} != canonical {sorted(_ORDER)}")

    detectors = source["detectors"]
    kinds = [d["kind"] for d in detectors]
    if len(kinds) != len(set(kinds)):
        raise DriftError("coverage-tiers.json lists a detector kind twice")

    registry = _oracle_kinds()
    listed = set(kinds)
    missing = registry - listed
    extra = listed - registry
    if missing or extra:
        raise DriftError(
            "coverage-tiers.json is not grounded in the OracleKind registry: "
            f"missing {sorted(missing)}; not-a-detector {sorted(extra)}")

    # Every tier of every detector is in the closed vocabulary.
    for d in detectors:
        if d["tier"] not in tier_ids:
            raise DriftError(f"detector {d['kind']!r} has unknown tier {d['tier']!r}")

    # The ladder cannot name an oracle this table does not know about.
    branches = json.loads(_BRANCHES.read_text(encoding="utf-8"))["branches"]
    for b in branches:
        ov = b.get("oracle_version", "")
        if ov and ov not in registry:
            raise DriftError(f"evidence-branches.json branch {b['id']!r} names unknown oracle {ov!r}")

    return {tier: sum(1 for d in detectors if d["tier"] == tier) for tier in _ORDER}


def render_block(source: dict | None = None) -> str:
    """The exact fenced block, markers included, that both documents must contain verbatim."""
    source = source if source is not None else load_source()
    counts = validate(source)
    label = {t["id"]: t["label"] for t in source["tiers"]}
    meaning = {t["id"]: t["meaning"] for t in source["tiers"]}
    total = sum(counts.values())
    lines = [
        BEGIN,
        "| Evidence tier | Detector kinds |",
        "|---|---|",
    ]
    for tier in _ORDER:
        lines.append(f"| {label[tier]} — {meaning[tier].rstrip('.').lower()} | {counts[tier]} |")
    lines.append(f"| **Total detector kinds** | **{total}** |")
    lines.append(END)
    return "\n".join(lines)


def _extract_region(text: str, path: Path) -> str:
    i = text.find(BEGIN)
    j = text.find(END)
    if i == -1 or j == -1 or j < i:
        raise DriftError(f"{path}: coverage-tiers markers not found — cannot locate the generated block")
    return text[i:j + len(END)]


def _replace_region(text: str, block: str, path: Path) -> str:
    return text.replace(_extract_region(text, path), block)


def check() -> list[str]:
    """Return a list of drift messages; empty means everything is in sync."""
    problems: list[str] = []
    try:
        source = load_source()
        block = render_block(source)
    except DriftError as exc:
        return [str(exc)]
    for path in TARGET_DOCS:
        try:
            region = _extract_region(path.read_text(encoding="utf-8"), path)
        except DriftError as exc:
            problems.append(str(exc))
            continue
        if region != block:
            problems.append(f"{path.relative_to(_REPO)}: coverage-tiers block has drifted from the "
                            f"source of truth — run gen_coverage_tiers.py")
    return problems


def write() -> None:
    source = load_source()
    block = render_block(source)
    for path in TARGET_DOCS:
        text = path.read_text(encoding="utf-8")
        path.write_text(_replace_region(text, block, path), encoding="utf-8")
        print(f"updated {path.relative_to(_REPO)}")


def main(argv: list[str]) -> int:
    if "--check" in argv:
        problems = check()
        if problems:
            print("coverage-tiers DRIFT:", file=sys.stderr)
            for p in problems:
                print("  - " + p, file=sys.stderr)
            return 1
        print("coverage-tiers: source of truth and both documents are in sync.")
        return 0
    write()
    print("NOTE: 05-weakness-types.md is a chapter — re-run "
          "docs/plain-english/_assembly/assemble.py to refresh VIGIL-EXPLAINED.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
