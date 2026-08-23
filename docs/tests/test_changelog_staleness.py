"""CHANGELOG.md cannot go stale relative to the product version or the release tags (W4-2, #442).

Acceptance criterion: "CHANGELOG is generated and CI fails when it is stale relative to the tag
range." This guard rides the already-required "the briefing explains every agent and capability" job
(``pytest docs/tests -q``), which installs only pytest and reads files — so this test is stdlib-only.

WHAT IT ENFORCES (all offline):
  * the repo-root ``VERSION`` (the single product version, W4-1) has a matching ``## [X.Y.Z]`` section
    in CHANGELOG.md — bump ``VERSION`` without adding its section and the build goes red;
  * every git release tag ``vX.Y.Z`` has a matching section — a tagged release with no changelog entry
    is stale, and CI says so;
  * the ``tools/release/changelog.py`` generator's rendering is honest: conventional commits group into
    Keep-a-Changelog sections and non-conventional / merge subjects are omitted (not fabricated).

FAILS WITHOUT THE FIX: on a tree with no CHANGELOG.md the first real-tree test errors on the missing
file. NEGATIVE CONTROLS run in the same process against the pure ``changelog_defects`` function so a
green pass means the guard rejects a stale changelog, not that it is asleep.
"""
from __future__ import annotations

import importlib.util
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CHANGELOG = REPO / "CHANGELOG.md"
VERSION_FILE = REPO / "VERSION"
GENERATOR = REPO / "tools" / "release" / "changelog.py"

_SECTION = re.compile(r"^## \[(?P<v>[^\]]+)\]", re.MULTILINE)
_TAG = re.compile(r"^v(?P<v>\d+\.\d+\.\d+([abrc]|rc|\.dev|\.post)?\d*)$")


# --- pure guard: data in as arguments so the negative control runs in-process ----------------


def changelog_versions(changelog_text: str) -> set[str]:
    """The version tokens of every ``## [X]`` section (``Unreleased`` included)."""
    return {m.group("v") for m in _SECTION.finditer(changelog_text)}


def changelog_defects(changelog_text: str, version: str, tags: list[str]) -> list[str]:
    """Return the staleness problems; empty == the changelog is current.

    ``version`` is the product VERSION; ``tags`` is the list of raw git tags."""
    have = changelog_versions(changelog_text)
    defects: list[str] = []
    if version not in have:
        defects.append(
            f"the product version {version!r} has no '## [{version}]' section in CHANGELOG.md "
            "(bump VERSION and its changelog section together)"
        )
    for tag in tags:
        m = _TAG.match(tag)
        if not m:
            continue  # non-release tags are not the changelog's concern
        tv = m.group("v")
        if tv not in have:
            defects.append(f"release tag {tag!r} has no '## [{tv}]' section in CHANGELOG.md (stale)")
    return defects


def _git_tags() -> list[str]:
    """Best-effort git tags; empty if git is unavailable (the negative control still exercises the
    tag branch with injected data, so the guard is proven regardless)."""
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO), "tag"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    return [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]


def _load_generator():
    spec = importlib.util.spec_from_file_location("vigil_changelog_gen", GENERATOR)
    assert spec and spec.loader, f"cannot load generator at {GENERATOR}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- real-tree assertions --------------------------------------------------------------------


def test_changelog_exists_and_has_unreleased_and_version_sections():
    assert CHANGELOG.is_file(), "CHANGELOG.md is missing (W4-2)"
    text = CHANGELOG.read_text(encoding="utf-8")
    have = changelog_versions(text)
    assert "Unreleased" in have, "CHANGELOG.md must carry an '## [Unreleased]' section"
    version = VERSION_FILE.read_text(encoding="utf-8").strip()
    assert version in have, f"CHANGELOG.md has no section for the current VERSION {version!r}"


def test_changelog_is_not_stale_relative_to_version_or_tags():
    text = CHANGELOG.read_text(encoding="utf-8")
    version = VERSION_FILE.read_text(encoding="utf-8").strip()
    defects = changelog_defects(text, version, _git_tags())
    assert not defects, "CHANGELOG is stale:\n  " + "\n  ".join(defects)


# --- negative controls: a stale changelog is rejected ----------------------------------------


def test_negative_control_missing_version_section_is_rejected():
    text = "# Changelog\n\n## [Unreleased]\n\n## [0.1.0] - x\n"
    defects = changelog_defects(text, "0.2.0", tags=[])
    assert any("0.2.0" in d for d in defects), defects


def test_negative_control_tag_without_section_is_rejected():
    text = "# Changelog\n\n## [Unreleased]\n\n## [0.1.0] - x\n"
    defects = changelog_defects(text, "0.1.0", tags=["v0.1.0", "v0.2.0"])
    assert any("v0.2.0" in d for d in defects), defects
    assert not any("v0.1.0" in d for d in defects), "v0.1.0 has a section and must not be flagged"


def test_negative_control_current_changelog_passes_when_aligned():
    text = "# Changelog\n\n## [Unreleased]\n\n## [1.0.0] - x\n"
    assert changelog_defects(text, "1.0.0", tags=["v1.0.0"]) == []


# --- the generator renders conventional commits honestly -------------------------------------


def test_generator_groups_conventional_commits_into_keepachangelog_sections():
    gen = _load_generator()
    section = gen.render_section(
        "0.2.0",
        "2026-01-01",
        [
            "feat(cli): add --version to every entry point",
            "fix: reject a dirty tree as clean",
            "docs: write the release runbook",
        ],
    )
    assert "## [0.2.0] - 2026-01-01" in section
    assert "### Added" in section and "add --version to every entry point" in section
    assert "### Fixed" in section and "reject a dirty tree as clean" in section
    assert "### Changed" in section  # docs -> Changed


def test_negative_control_generator_omits_non_conventional_and_merge_subjects():
    gen = _load_generator()
    assert gen.parse_commit("just a normal message") is None
    assert gen.parse_commit("Merge pull request #1 from x") is None
    section = gen.render_section("0.2.0", "2026-01-01", ["not conventional", "Merge branch 'x'"])
    assert "_No conventional-commit changes in this range._" in section


def test_generator_breaking_change_is_flagged():
    gen = _load_generator()
    section = gen.render_section("1.0.0", "2026-01-01", ["feat!: drop the legacy path"])
    assert "**BREAKING**" in section and "drop the legacy path" in section


def test_generator_extract_section_reads_a_version_body():
    gen = _load_generator()
    text = "# Changelog\n\n## [Unreleased]\n\nx\n\n## [0.1.0] - d\n\n### Added\n- a thing\n\n## [0.0.9] - e\n- old\n"
    body = gen.extract_section(text, "0.1.0")
    assert body is not None and "a thing" in body
    assert "old" not in body  # stops at the next header
    assert gen.extract_section(text, "9.9.9") is None
