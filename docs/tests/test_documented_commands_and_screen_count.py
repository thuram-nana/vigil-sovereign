"""W17-13 / #547 — documented commands must EXIST, and the stated screen count must EQUAL the UI's NAV.

Two doc-truth defects this test locks shut:

  1. Non-existent commands. ``docs/AS-BUILT.md`` and ``docs/FEATURES.md`` documented ``vigil attack-paths``
     and ``vigil calibration report`` — but ``vigil`` has no such NATIVE verbs (see the sub-parsers in
     ``integration/vigil_integration/cli.py`` and the passthrough set in ``dispatch.py``). The real
     commands are ``vigil crucible attack-paths`` and ``vigil crucible calibration report``:
     ``attack-paths`` and ``calibration`` are CRUCIBLE subcommands, reached only through the ``crucible``
     passthrough verb (``engine/crucible/framework/v2/__main__.py`` ``_DISPATCH``). ``vigil attack-paths``
     / ``vigil calibration …`` run nothing.

  2. A drifted screen count. ``README.md``, ``packages/vigil-ui/README.md`` and ``docs/FEATURES.md`` stated
     28 / 21 screens while the UI's authoritative NAV allowlist (``packages/vigil-ui/app.js`` ``const NAV``)
     carries 31 — the same 31 the CI-gated canonical manifest (``knowledge/system-map/system-map.json``)
     holds.

The count is DERIVED from NAV here (never hard-coded), by the SAME scoped extraction the S1 system-map
gate uses (``tools/system-map/generate.py``): scope to the ``const NAV = [...]`` array, count ``id:``
tokens, and demand the raw token count equal the distinct-id count so a duplicate or an unparseable id
is surfaced as drift, never silently dropped. Change a screen in NAV and this test moves with it — the
doc cannot drift from the UI again without going red.

Files only. No import of either trust domain, no tool run, no packet — correct for the docs-only
``briefing-completeness`` required CI job (which installs only pytest and reads files).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APP_JS = REPO / "packages" / "vigil-ui" / "app.js"
SYSTEM_MAP = REPO / "knowledge" / "system-map" / "system-map.json"

AS_BUILT = REPO / "docs" / "AS-BUILT.md"
FEATURES = REPO / "docs" / "FEATURES.md"
README = REPO / "README.md"
VIGIL_UI_README = REPO / "packages" / "vigil-ui" / "README.md"

# --- the canonical NAV extraction, mirrored from tools/system-map/generate.py ------------------------
_NAV_BLOCK = re.compile(r"const NAV = \[(.*?)\n\s*\];", re.DOTALL)
_NAV_ID = re.compile(r"""id:\s*["']([A-Za-z][A-Za-z0-9_-]*)["']""")
_NAV_RAW = re.compile(r"""id:\s*["']""")
# a "<N> screens" TOTAL claim (a plural-noun count), e.g. "31 screens" / "all 31 screens"
_SCREEN_TOTAL = re.compile(r"(\d+)\s+screens\b")


def _nav_block(src: str) -> str:
    m = _NAV_BLOCK.search(src)
    assert m, "could not locate the `const NAV = [...]` array in app.js"
    return m.group(1)


def _extract(src: str) -> tuple[list[str], int]:
    """(the NAV screen ids, the RAW count of `id:` tokens in the NAV block). A raw count above the
    distinct-id count means a duplicate or an unparseable id — surfaced, never silently dropped."""
    block = _nav_block(src)
    return _NAV_ID.findall(block), len(_NAV_RAW.findall(block))


def nav_screen_count() -> int:
    ids, raw = _extract(APP_JS.read_text(encoding="utf-8"))
    assert raw == len(ids) == len(set(ids)), (
        f"NAV has a duplicate or unparseable id (raw={raw}, ids={ids})")
    return len(ids)


def _raw(path: Path) -> str:
    assert path.is_file(), f"doc missing: {path}"
    return path.read_text(encoding="utf-8")


def _collapsed(path: Path) -> str:
    """File text with every whitespace run collapsed to one space, so a claim that wraps across
    indented lines still matches as a single phrase."""
    return re.sub(r"\s+", " ", _raw(path))


# ---------------------------------------------------------------------------------------------------
# 1. Documented commands use the REAL `vigil crucible …` verb — the bad forms are gone.
# ---------------------------------------------------------------------------------------------------
# Checked against RAW text so collapsing lines can never bridge a "vigil" and a later word into a
# false hit; the corrected form always carries `crucible` between the two, so it never matches these.
FORBIDDEN_COMMANDS = [
    (AS_BUILT, "vigil attack-paths"),
    (AS_BUILT, "vigil calibration"),
    (FEATURES, "vigil attack-paths"),
    (FEATURES, "vigil calibration"),
]
# Checked against COLLAPSED text so a future re-wrap of the line still counts as present.
REQUIRED_COMMANDS = [
    (AS_BUILT, "vigil crucible attack-paths"),
    (AS_BUILT, "vigil crucible calibration"),
    (FEATURES, "vigil crucible attack-paths"),
    (FEATURES, "vigil crucible calibration"),
]


def test_documented_commands_use_the_real_crucible_verb():
    for path, bad in FORBIDDEN_COMMANDS:
        assert bad not in _raw(path), (
            f"{path.name} still documents non-existent command `{bad}` "
            f"(the real one is `vigil crucible {bad.split(' ', 1)[1]}`)")
    for path, good in REQUIRED_COMMANDS:
        assert good in _collapsed(path), f"{path.name} is missing the corrected command `{good}…`"


# ---------------------------------------------------------------------------------------------------
# 2. Every stated whole-UI screen TOTAL equals the count DERIVED from NAV.
# ---------------------------------------------------------------------------------------------------
COUNT_DOCS = [README, VIGIL_UI_README, FEATURES]


def test_screen_totals_in_docs_equal_the_nav_derived_count():
    n = nav_screen_count()
    for path in COUNT_DOCS:
        totals = _SCREEN_TOTAL.findall(_collapsed(path))
        assert totals, f"{path.name} states no `<N> screens` total to check against NAV"
        for t in totals:
            assert int(t) == n, (
                f"{path.name} says {t} screens but the UI's NAV (app.js `const NAV`) has {n}")


def test_canonical_manifest_screen_count_equals_nav():
    """The CI-gated manifest SIGIL reads is the same count — a second, machine-readable witness."""
    n = nav_screen_count()
    manifest = json.loads(_raw(SYSTEM_MAP))
    assert len(manifest["screens"]) == n, (
        f"system-map.json has {len(manifest['screens'])} screens; NAV has {n}")


# ===================================================================================================
# NEGATIVE CONTROLS — proof, in the same run, that each gate BITES (rejects a deliberately bad input).
# ===================================================================================================
def test_negative_control_command_gate_rejects_a_bad_command_and_accepts_the_fix():
    bad_doc = "run `vigil attack-paths acme` to see the paths"          # the exact defect
    good_doc = "run `vigil crucible attack-paths acme` to see the paths"  # the fix
    # the forbidden-substring gate FIRES on the bad doc ...
    assert "vigil attack-paths" in bad_doc
    # ... and does NOT false-positive on the corrected form (there is a `crucible` in between).
    assert "vigil attack-paths" not in good_doc
    assert "vigil calibration" not in "run `vigil crucible calibration report`"


def test_negative_control_count_gate_rejects_a_wrong_count():
    n = nav_screen_count()
    # the derivation must produce the REAL number, not an old hard-coded constant it could collapse onto.
    assert n not in (21, 22, 28, 29, 30), f"derived NAV count {n} landed on a known-stale constant"
    fake_doc = "the console now has 28 screens in total"
    found = [int(x) for x in _SCREEN_TOTAL.findall(fake_doc)]
    assert found == [28]                       # the extractor really reads the number out of prose ...
    assert all(v != n for v in found)          # ... and the gate WOULD reject this doc (28 != NAV).


def test_negative_control_nav_extractor_reads_nav_not_a_constant():
    # a synthetic NAV with a known size is counted as that size — not the real file's 31.
    fake = 'const NAV = [\n{ id: "a" },\n{ id: "b" },\n{ id: "c" },\n  ];\n'
    ids, raw = _extract(fake)
    assert ids == ["a", "b", "c"] and raw == 3
    assert nav_screen_count() != 3             # the real file differs, so the count is not fixed
    # a duplicate id is caught as drift (raw > distinct), never silently dropped.
    dup = 'const NAV = [\n{ id: "a" },\n{ id: "a" },\n  ];\n'
    dids, draw = _extract(dup)
    assert draw == 2 and len(set(dids)) == 1
