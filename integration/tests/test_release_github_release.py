"""The release workflow PUBLISHES a GitHub Release for the tag (W4-2, #442) — asserted statically.

The W4-2 issue lists "no publish step" as a defect. `.github/workflows/release.yml` now closes it: after
signing + attesting the artifacts it runs `gh release create` for the tag, attaching the signed
wheel/sdist and their offline-verifiable side-cars, with the committed CHANGELOG section as the notes.

Like `test_release_provenance.py`, this rides the required "integration two-env boundary (P5)" job (it
lives under integration/tests and is not in that job's --ignore list) and asserts the tag-triggered
workflow's shape offline — the workflow itself never reports on the PR that adds it.

FAILS WITHOUT THE FIX: a release.yml with no publish step is caught by the first test.
NEGATIVE CONTROL: `test_the_publish_shape_check_is_load_bearing` feeds the SAME checker a workflow with
the publish/notes legs removed and asserts each removal is detected — a green pass means the legs are
present, not that the checker is asleep.

Pure stdlib + PyYAML + pytest.
"""
from __future__ import annotations

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
RELEASE = REPO / ".github" / "workflows" / "release.yml"


def _strip_comments(text: str) -> str:
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


#: Each publish leg, keyed by a human reason -> a substring that must survive comment-stripping.
_LEGS: dict[str, str] = {
    "creates a GitHub Release for the tag": "gh release create",
    "titles the release with the tag": '--title "${GITHUB_REF_NAME}"',
    "uses the changelog as the release notes": "release-notes.md",
    "derives the notes from CHANGELOG.md via the generator": "changelog.py notes",
    "attaches the signed wheel to the release": "dist/*.whl",
    "attaches the cosign bundles to the release": "dist/*.cosign.bundle",
}


def missing_publish_legs(text: str) -> list[str]:
    body = _strip_comments(text)
    return [f"{why} ({needle!r})" for why, needle in _LEGS.items() if needle not in body]


def test_release_workflow_publishes_a_github_release():
    assert RELEASE.is_file(), f"missing {RELEASE}"
    missing = missing_publish_legs(RELEASE.read_text(encoding="utf-8"))
    assert not missing, "release.yml no longer publishes a GitHub Release:\n  " + "\n  ".join(missing)


def test_release_workflow_grants_contents_write_for_the_release():
    yaml = pytest.importorskip("yaml")
    data = yaml.safe_load(RELEASE.read_text(encoding="utf-8"))
    jobs = data["jobs"]
    job = jobs["build-sign-attest"]
    perms = job.get("permissions", {})
    assert perms.get("contents") == "write", (
        "the build-sign-attest job must have `contents: write` to create a GitHub Release; "
        f"got {perms.get('contents')!r}"
    )


def test_the_publish_shape_check_is_load_bearing():
    real = RELEASE.read_text(encoding="utf-8")
    assert missing_publish_legs(real) == [], "precondition: the real workflow declares every publish leg"

    no_create = real.replace("gh release create", "echo skip")
    assert any("GitHub Release" in f for f in missing_publish_legs(no_create)), (
        "removing `gh release create` was not detected"
    )
    no_notes = real.replace("changelog.py notes", "true")
    assert any("CHANGELOG" in f for f in missing_publish_legs(no_notes)), (
        "removing the changelog-notes derivation was not detected"
    )
    # A commented-out create step must not satisfy the check.
    commented = real.replace("gh release create", "# gh release create")
    assert any("GitHub Release" in f for f in missing_publish_legs(commented)), (
        "a commented-out create step wrongly satisfied the check"
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
