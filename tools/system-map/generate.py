#!/usr/bin/env python3
"""
system-map generator (S1) — turn the human SSOT ``knowledge/system-map/screens.yaml`` into the
machine-readable ``knowledge/system-map/system-map.json`` that SIGIL reads to KNOW the system, and
DRIFT-CHECK it against the real UI so SIGIL's map can never silently diverge.

Read-only + deterministic. Two modes:
  * ``--write``  : (re)generate system-map.json from screens.yaml (byte-identical for the same input).
  * ``--check``  : fail (exit 1) if screens.yaml's ids != the UI's NAV ids != the UI's route() ids, if any
                   screen lacks a synonym, or if the committed system-map.json is stale. CI runs this.

The set-equality is the load-bearing invariant: every screen SIGIL can navigate to (manifest) must be a
real NAV entry AND a real route() destination in ``packages/vigil-ui/app.js`` — no phantom screens, no
unreachable-by-voice screens. Extraction is SCOPED to the ``const NAV = [...]`` array and the ``function
route()`` body (a whole-file grep would wrongly pick up scan-mode / wizard-target / provider ids).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_APP_JS = _ROOT / "packages" / "vigil-ui" / "app.js"
_SCREENS_YAML = _ROOT / "knowledge" / "system-map" / "screens.yaml"
_MANIFEST = _ROOT / "knowledge" / "system-map" / "system-map.json"

# An id in EITHER quote and a permissive charset (camelCase / hyphen / underscore), so an idiomatic
# `id: "cloudScan"` or `id: 'api-keys'` is EXTRACTED (and thus checked), never silently missed. The raw
# tokens `id:\s*["']` / `id === ["']` are counted separately so a duplicate or an entry whose id we cannot
# parse at all can't vanish (a raw count > the extracted-set size is drift). This closes the false-green
# hole where a NAV+route screen absent from screens.yaml would be invisible on all three sides at once.
_ID = r"""["']([A-Za-z][A-Za-z0-9_-]*)["']"""
_NAV_RAW = re.compile(r"""id:\s*["']""")
_ROUTE_RAW = re.compile(r"""id === ["']""")


def _nav_block(src: str) -> str:
    m = re.search(r"const NAV = \[(.*?)\n\s*\];", src, re.DOTALL)
    if not m:
        raise SystemExit("could not locate the `const NAV = [...]` array in app.js")
    return m.group(1)


def _route_block(src: str) -> str:
    m = re.search(r"function route\(\)\s*\{(.*?)\n\s*\}\n", src, re.DOTALL)
    if not m:
        raise SystemExit("could not locate `function route()` in app.js")
    return m.group(1)


def _nav_ids(src: str) -> tuple[set[str], int]:
    """(the ids inside ``const NAV = [...]``, the RAW count of ``id:`` tokens there). A raw count above the
    set size means a duplicate or an unparseable id — surfaced as drift, never silently dropped."""
    block = _nav_block(src)
    return set(re.findall(r"id:\s*" + _ID, block)), len(_NAV_RAW.findall(block))


def _route_ids(src: str) -> tuple[set[str], int]:
    """(the ids handled in ``function route() {...}`` via ``id === "x"``, the RAW count of such branches).
    ``it.id === id`` (no quote) is correctly excluded — the raw token requires an opening quote."""
    block = _route_block(src)
    return set(re.findall(r"id === " + _ID, block)), len(_ROUTE_RAW.findall(block))


def _load_screens() -> list[dict]:
    import yaml  # PyYAML
    data = yaml.safe_load(_SCREENS_YAML.read_text(encoding="utf-8")) or {}
    screens = data.get("screens") if isinstance(data, dict) else None
    if not isinstance(screens, list) or not screens:
        raise SystemExit("screens.yaml has no `screens:` list")
    return screens


def _build_manifest(screens: list[dict]) -> dict:
    """A deterministic manifest: screens sorted by id, plus a source_sha of screens.yaml (so a re-generate
    over the same SSOT is byte-identical). No wallclock — the sha IS the version."""
    norm = []
    for s in sorted(screens, key=lambda x: str(x.get("id", ""))):
        norm.append({
            "id": str(s.get("id", "")),
            "label": str(s.get("label", "")),
            "group": str(s.get("group", "")),
            "owner": bool(s.get("owner", False)),
            "plane": str(s.get("plane", "unified")),
            "description": str(s.get("description", "")),
            "synonyms": [str(x).lower() for x in (s.get("synonyms") or [])],
        })
    sha = hashlib.sha256(_SCREENS_YAML.read_bytes()).hexdigest()
    return {"schema": "vigil.system-map/1", "source_sha": sha, "screens": norm}


def _serialize(manifest: dict) -> str:
    return json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def _verify(screens: list[dict]) -> list[str]:
    """Return a list of drift/consistency problems (empty = clean). Checks id-SET equality
    (screens.yaml == NAV == route()), plus a CARDINALITY guard (no duplicate / unparseable id can vanish),
    plus a synonym-per-screen requirement. NB: it verifies the id SET, not that route branch ``x`` renders
    the screen named ``x`` (renderer-binding is out of scope; ids are the navigation contract)."""
    problems: list[str] = []
    src = _APP_JS.read_text(encoding="utf-8")
    nav, nav_raw = _nav_ids(src)
    route, route_raw = _route_ids(src)
    manifest_ids = {str(s.get("id", "")) for s in screens}
    # cardinality: a raw `id:`/`id === "` token that produced no extracted id (a bad charset), or a
    # duplicate id (set-dedup hides it), means the extractor undercounts — treat as drift, never silent.
    if nav_raw != len(nav):
        problems.append(f"NAV has {nav_raw} `id:` tokens but {len(nav)} distinct parseable ids — an id is "
                        f"duplicated or uses an unrecognised form (check for a duplicate or an odd id)")
    if route_raw != len(route):
        problems.append(f"route() has {route_raw} `id === \"…\"` branches but {len(route)} distinct parseable "
                        f"ids — a duplicate or an unrecognised id form")
    if nav != route:
        problems.append(f"NAV ids != route() ids: only-in-NAV={sorted(nav - route)} "
                        f"only-in-route={sorted(route - nav)}")
    if manifest_ids != nav:
        problems.append(f"screens.yaml ids != NAV ids: only-in-manifest={sorted(manifest_ids - nav)} "
                        f"only-in-NAV={sorted(nav - manifest_ids)}")
    for s in screens:
        if not (s.get("synonyms") or []):
            problems.append(f"screen {s.get('id')!r} has no synonyms (voice nav needs at least one)")
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="generate / drift-check the SIGIL system map")
    ap.add_argument("--write", action="store_true", help="(re)write system-map.json from screens.yaml")
    ap.add_argument("--check", action="store_true", help="fail on drift (ids mismatch / missing synonym / stale json)")
    args = ap.parse_args(argv)

    screens = _load_screens()
    manifest = _build_manifest(screens)
    rendered = _serialize(manifest)

    if args.write:
        _MANIFEST.write_text(rendered, encoding="utf-8")
        print(f"wrote {_MANIFEST.relative_to(_ROOT)} ({len(manifest['screens'])} screens)")

    if args.check:
        problems = _verify(screens)
        committed = _MANIFEST.read_text(encoding="utf-8") if _MANIFEST.is_file() else ""
        if committed != rendered:
            problems.append("system-map.json is STALE — run `python tools/system-map/generate.py --write` and commit")
        if problems:
            print("SYSTEM-MAP DRIFT:", file=sys.stderr)
            for p in problems:
                print("  - " + p, file=sys.stderr)
            return 1
        print(f"system map OK — {len(manifest['screens'])} screens, ids match NAV == route()")

    if not (args.write or args.check):
        ap.error("pass --write and/or --check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
