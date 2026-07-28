"""
S1 — the SIGIL system-map manifest must never drift from the real UI.

``knowledge/system-map/system-map.json`` (what SIGIL reads to KNOW the system) is generated from
``screens.yaml`` and must satisfy: manifest ids == the UI's NAV ids == the UI's route() ids, every screen
has a voice synonym, and the committed json is not stale. This test IS the CI gate; it also proves the
gate BITES (a phantom screen / a missing synonym is caught), so it can't silently pass.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[3]
_GEN = _ROOT / "tools" / "system-map" / "generate.py"

pytest.importorskip("yaml")   # PyYAML (installed in the sigil CI job); skip locally if absent


def _gen():
    spec = importlib.util.spec_from_file_location("system_map_generate", _GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_manifest_is_current_and_ids_match_nav_and_route():
    gen = _gen()
    screens = gen._load_screens()
    # no drift: manifest ids == NAV ids == route() ids, every screen has a synonym
    assert gen._verify(screens) == []
    # the committed json is exactly what the SSOT regenerates (not stale)
    assert gen._MANIFEST.read_text(encoding="utf-8") == gen._serialize(gen._build_manifest(screens))


def test_check_mode_exits_zero():
    assert _gen().main(["--check"]) == 0


def test_manifest_covers_the_fifteen_nav_screens():
    gen = _gen()
    src = gen._APP_JS.read_text(encoding="utf-8")
    nav, nav_raw = gen._nav_ids(src)
    assert nav_raw == len(nav)                              # no duplicate / unparseable NAV id
    manifest_ids = {s["id"] for s in gen._build_manifest(gen._load_screens())["screens"]}
    assert manifest_ids == nav and len(manifest_ids) >= 10   # every real screen mapped


# --- the silent-green hole the S1 red-pen found: an id the extractor can't parse must NOT vanish -------

def _synthetic_app_js(nav_items: str, route_branches: str) -> str:
    return ("  const NAV = [\n    { group: \"DO\", items: [\n" + nav_items
            + "\n    ]},\n  ];\n\n"
            "  function route() {\n    const id = current();\n" + route_branches
            + "\n    NAV.forEach(function (g) { g.items.forEach(function (it) { if (it.id === id) x=it; }); });\n"
            "  }\n")


@pytest.mark.parametrize("bad_id", ["cloudScan", "api-keys", "under_score"])
def test_camelcase_or_hyphen_screen_is_extracted_not_silently_dropped(tmp_path, monkeypatch, bad_id):
    # a real NAV+route screen with an idiomatic non-lowercase-alnum id, ABSENT from screens.yaml, must be
    # caught as drift (it used to pass silently green because the extractor couldn't see it).
    gen = _gen()
    app = _synthetic_app_js(
        f'      {{ id: "home", label: "H" }},\n      {{ id: "{bad_id}", label: "X" }},',
        f'    if (id === "home") return;\n    if (id === "{bad_id}") return;')
    p = tmp_path / "app.js"; p.write_text(app, encoding="utf-8")
    monkeypatch.setattr(gen, "_APP_JS", p)
    nav, raw = gen._nav_ids(app)
    assert bad_id in nav and raw == len(nav)                # EXTRACTED now, not missed
    # with only "home" in the (fake) manifest, the extra screen is flagged
    problems = gen._verify([{"id": "home", "synonyms": ["h"]}])
    assert any(bad_id in p for p in problems)


def test_cardinality_catches_a_duplicate_nav_id():
    gen = _gen()
    app = _synthetic_app_js(
        '      { id: "home", label: "H" },\n      { id: "home", label: "H2" },',
        '    if (id === "home") return;')
    nav, raw = gen._nav_ids(app)
    assert raw == 2 and len(nav) == 1                        # raw > set → the dup is visible as drift


def test_verify_bites_on_a_phantom_screen():
    gen = _gen()
    screens = gen._load_screens() + [{"id": "phantomscreen", "label": "x", "synonyms": ["x"]}]
    problems = gen._verify(screens)
    assert any("phantomscreen" in p for p in problems)       # an id not in NAV/route is caught


def test_verify_bites_on_a_missing_synonym():
    gen = _gen()
    screens = [dict(s) for s in gen._load_screens()]
    screens[0]["synonyms"] = []
    problems = gen._verify(screens)
    assert any("no synonyms" in p for p in problems)
