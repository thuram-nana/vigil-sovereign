"""Guard: GitHub-read control files live at the repository ROOT, and only there.

GitHub reads a workflow, a CODEOWNERS, or a pull-request template from a *fixed* set of paths
relative to the repository root — `.github/workflows/`, `.github/pull_request_template.md`, and a
couple of siblings. A copy of any of those nested under a subdirectory (`apps/sigil/.github/…`,
`engine/crucible/.github/…`) is **inert**: GitHub never reads it, so it enforces nothing and
requests nothing. Such a file is the exact defect the root CODEOWNERS was created to fix — a file
that looks like a control and is not one (see .github/CODEOWNERS). This guard makes that whole class
loud, so a vendored engine or app can never silently reintroduce an inert control that the as-built
docs might then cite as a protection.

Two behaviours are pinned here, shared by [W1-8] #417 and [W12-1] #490:

  1. No `.github/workflows/` and no `pull_request_template.md` exists OUTSIDE the repository root
     (`nested_github_offenses`) — #417; and
  2. a pull-request template DOES exist at the one root path GitHub reads
     (`root_pr_template_defect`) — #490.

Vendored third-party trees under `vendor/` are exempt: we ship them as a faithful upstream snapshot
and do not rewrite them, and their `.github/` is just as inert (it changes nothing about how this
repository behaves). The exemption is deliberately *scoped* to `vendor/` — the negative control
below proves a non-vendored nested workflow is still flagged in the same run, so the exemption is
not a blanket no-op.

The guard is framework-free and sigil-free (pure stdlib file reads), so it runs in the required
`integration two-env boundary (P5)` CI job, which collects the whole `integration/tests` tree. Keep
it out of any `--ignore` there.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]

# Directory names pruned from the walk: VCS/build junk, plus vendored third-party trees whose own
# `.github/` is a faithful upstream snapshot we do not rewrite (and which is just as inert here).
_PRUNE = {".git", "node_modules", "vendor", "__pycache__", ".venv", ".venv-sovereign"}

_PR_TEMPLATE = "pull_request_template.md"


def nested_github_offenses(root: str | os.PathLike) -> list[str]:
    """Return the repo-relative POSIX paths of GitHub control files that live in a NESTED `.github/`
    (i.e. not the repository-root `.github/`) and are therefore inert.

    Two inert classes are reported — the ones GitHub reads only from the root and that most mislead:
      * anything under a nested `.github/workflows/`; and
      * a nested `.github/pull_request_template.md` (or a `.github/PULL_REQUEST_TEMPLATE/` directory).

    Vendored trees (a `vendor/` path component) and VCS/build junk are excluded. This is the single
    enforcing symbol for [W1-8] #417.
    """
    root = Path(root)
    offenses: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune junk and vendored trees from further descent (top-down walk).
        dirnames[:] = [d for d in dirnames if d not in _PRUNE]

        rel = Path(dirpath).relative_to(root)
        parts = rel.parts
        if ".github" not in parts:
            continue
        gi = parts.index(".github")
        if gi == 0:
            continue  # the repository-root `.github/` (or a path under it) — the one place GitHub reads.

        under = parts[gi + 1:]  # path components inside this nested `.github/`
        relposix = rel.as_posix()
        for fn in filenames:
            if under[:1] == ("workflows",):
                offenses.append(f"{relposix}/{fn}")
            elif fn.lower() == _PR_TEMPLATE or under[:1] == ("PULL_REQUEST_TEMPLATE",):
                offenses.append(f"{relposix}/{fn}")
    return sorted(offenses)


def root_pr_template_defect(root: str | os.PathLike) -> str:
    """Return a non-empty defect string if the repository-root pull-request template GitHub reads is
    missing or empty; the empty string when it is present and non-empty. Enforcing symbol for
    [W12-1] #490 — the root path is `.github/pull_request_template.md`.
    """
    root = Path(root)
    p = root / ".github" / _PR_TEMPLATE
    if not p.is_file():
        return f"missing root pull-request template at {p.relative_to(root).as_posix()} (GitHub reads it only from the root)"
    if not p.read_text(encoding="utf-8").strip():
        return f"root pull-request template {p.relative_to(root).as_posix()} is empty"
    return ""


# --------------------------------------------------------------------------------------------------
# Positive checks — TRUE of this repository's tree. Each FAILS on a tree without the fix: the pre-fix
# tree carried apps/sigil/.github/workflows/ci.yml and engine/crucible/.github/pull_request_template.md
# (nested, inert) and had NO root pull-request template at all.
# --------------------------------------------------------------------------------------------------
def test_no_nested_github_workflows_or_templates_outside_root():
    offenses = nested_github_offenses(_REPO)
    assert offenses == [], (
        "these GitHub control files live in a nested `.github/` where GitHub never reads them, so they "
        "enforce/request nothing — move them to the repository root or delete them (vendored trees are "
        f"exempt): {offenses}"
    )


def test_root_pull_request_template_exists():
    defect = root_pr_template_defect(_REPO)
    assert not defect, defect


def test_contributing_points_to_the_real_pr_template_path():
    """[W12-1] #490: CONTRIBUTING must direct contributors to the real, GitHub-read path, not to a
    template that only exists where GitHub never looks."""
    contributing = _REPO / "CONTRIBUTING.md"
    assert contributing.is_file(), "CONTRIBUTING.md is missing at the repository root"
    text = contributing.read_text(encoding="utf-8")
    assert ".github/pull_request_template.md" in text, (
        "CONTRIBUTING.md must reference the real pull-request template path "
        "`.github/pull_request_template.md` (the one GitHub actually reads)"
    )


# --------------------------------------------------------------------------------------------------
# Negative controls — the very functions the positives rely on are shown to REJECT bad input, and to
# NOT over-reject, in the same run. A broken scanner that always returned [] would fail these.
# --------------------------------------------------------------------------------------------------
def _make_root_with_root_template(tmp: Path) -> Path:
    (tmp / ".github").mkdir(parents=True, exist_ok=True)
    (tmp / ".github" / _PR_TEMPLATE).write_text("## What this changes\n", encoding="utf-8")
    (tmp / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (tmp / ".github" / "workflows" / "ci.yml").write_text("name: ci\n", encoding="utf-8")
    return tmp


def test_negative_control_scanner_flags_a_nested_workflow(tmp_path):
    root = _make_root_with_root_template(tmp_path)
    nested = root / "apps" / "sigil" / ".github" / "workflows"
    nested.mkdir(parents=True)
    (nested / "ci.yml").write_text("name: inert\n", encoding="utf-8")

    offenses = nested_github_offenses(root)
    assert "apps/sigil/.github/workflows/ci.yml" in offenses, (
        "the scanner must flag a nested `.github/workflows/` file"
    )
    # ... and must NOT flag the legitimate root workflow (proves it is not a blanket rejector):
    assert ".github/workflows/ci.yml" not in offenses


def test_negative_control_scanner_flags_a_nested_pr_template(tmp_path):
    root = _make_root_with_root_template(tmp_path)
    nested = root / "engine" / "crucible" / ".github"
    nested.mkdir(parents=True)
    (nested / _PR_TEMPLATE).write_text("<!-- inert -->\n", encoding="utf-8")
    # A nested CODEOWNERS sibling is intentionally NOT one of the two flagged classes:
    (nested / "CODEOWNERS").write_text("* @nobody\n", encoding="utf-8")

    offenses = nested_github_offenses(root)
    assert "engine/crucible/.github/pull_request_template.md" in offenses
    assert "engine/crucible/.github/CODEOWNERS" not in offenses


def test_negative_control_vendored_github_tree_is_exempt(tmp_path):
    """The `vendor/` exemption is scoped, not a blanket pass: a vendored nested workflow is exempt
    while a non-vendored one in the SAME tree is still flagged."""
    root = _make_root_with_root_template(tmp_path)
    vendored = root / "vendor" / "strix" / ".github" / "workflows"
    vendored.mkdir(parents=True)
    (vendored / "build-release.yml").write_text("name: upstream\n", encoding="utf-8")
    ours = root / "packages" / "widget" / ".github" / "workflows"
    ours.mkdir(parents=True)
    (ours / "ci.yml").write_text("name: inert\n", encoding="utf-8")

    offenses = nested_github_offenses(root)
    assert "packages/widget/.github/workflows/ci.yml" in offenses, "a non-vendored nested workflow must still be flagged"
    assert not any(o.startswith("vendor/") for o in offenses), "vendored trees must be exempt"


def test_negative_control_missing_root_template_is_rejected(tmp_path):
    # A tree with no root template is rejected...
    (tmp_path / ".github").mkdir()
    assert root_pr_template_defect(tmp_path), "a missing root PR template must be a defect"
    # ...an empty one is rejected...
    (tmp_path / ".github" / _PR_TEMPLATE).write_text("   \n", encoding="utf-8")
    assert root_pr_template_defect(tmp_path), "an empty root PR template must be a defect"
    # ...and a real one passes (proves the check is not a constant-fail no-op).
    (tmp_path / ".github" / _PR_TEMPLATE).write_text("## What this changes\n", encoding="utf-8")
    assert root_pr_template_defect(tmp_path) == ""
