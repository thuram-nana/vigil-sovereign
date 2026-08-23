"""The shared ``--version`` build identity is honest about the tree (W4-2, #442).

This is the pin behind the acceptance criterion "``--version`` on all four CLIs prints
product version, build id and git sha" and its negative control "a build from a dirty tree
reports a dirty/unknown build id rather than a clean sha". It runs in the required
"vigil_core — shared integrity substrate" job (``pytest packages/core/vigil_core/tests``).

FAILS WITHOUT THE FIX: on a tree with no ``vigil_core/build_info.py`` this module errors at
import/collection, so the failure is observed, not assumed.

NEGATIVE CONTROLS (in the same run):
  * ``compose_build_id`` is a pure function fed a dirty / unknown state directly — it must
    NOT emit a clean ``+g<sha>`` for either;
  * a REAL temporary git repository is made dirty and ``resolve`` must report ``.dirty``;
  * a directory with no git yields ``unknown`` — never a fabricated clean sha.

Stdlib + pytest only; the git repositories are created in ``tmp_path`` and never touch the
product's own working tree.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from vigil_core import build_info


# --- pure build-id composition: the dirty / unknown negative controls ------------------------


def test_clean_tree_build_id_is_version_plus_short_sha():
    bid = build_info.compose_build_id("0.1.0", "a" * 40, dirty=False)
    assert bid == "0.1.0+g" + "a" * 12
    assert not bid.endswith(".dirty")


def test_negative_control_dirty_tree_build_id_is_marked_dirty():
    """A dirty tree must NEVER report a clean sha — the build id carries ``.dirty``."""
    bid = build_info.compose_build_id("0.1.0", "a" * 40, dirty=True)
    assert bid == "0.1.0+g" + "a" * 12 + ".dirty"
    assert bid.endswith(".dirty")


def test_negative_control_unknown_sha_build_id_is_unknown_not_clean():
    """No git sha must report ``+unknown``, not a manufactured clean ``+g...`` id."""
    for missing in (None, "", "unknown"):
        bid = build_info.compose_build_id("0.1.0", missing, dirty=False)
        assert bid == "0.1.0+unknown"
        assert "+g" not in bid


# --- product version resolution --------------------------------------------------------------


def test_product_version_reads_the_version_file_at_the_given_root(tmp_path: Path):
    (tmp_path / "VERSION").write_text("9.9.9\n", encoding="utf-8")
    assert build_info.product_version(tmp_path) == "9.9.9"


def test_product_version_ignores_blank_lines_in_version_file(tmp_path: Path):
    (tmp_path / "VERSION").write_text("\n1.2.3\n\n", encoding="utf-8")
    assert build_info.product_version(tmp_path) == "1.2.3"


# --- git state against a REAL temporary repository -------------------------------------------


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "test")
    _git(repo, "config", "commit.gpgsign", "false")
    (repo / "VERSION").write_text("0.1.0\n", encoding="utf-8")
    _git(repo, "add", "VERSION")
    _git(repo, "commit", "-q", "-m", "seed")
    return repo


requires_git = pytest.mark.skipif(shutil.which("git") is None, reason="git binary not available")


@requires_git
def test_clean_repo_reports_a_real_sha_and_not_dirty(tmp_path: Path):
    repo = _make_repo(tmp_path)
    sha, dirty = build_info.git_state(repo)
    assert len(sha) == 40 and all(c in "0123456789abcdef" for c in sha)
    assert dirty is False
    info = build_info.resolve("vigil", root=repo)
    assert info.version == "0.1.0"
    assert info.git_sha == sha
    assert info.build_id == f"0.1.0+g{sha[:12]}"
    # The full line carries all three facts.
    line = info.line()
    assert line.startswith("vigil 0.1.0 ")
    assert sha in line and "build 0.1.0+g" in line


@requires_git
def test_negative_control_dirty_repo_reports_dirty_end_to_end(tmp_path: Path):
    """The real thing: an uncommitted change makes ``resolve`` report ``.dirty`` — the AC's
    'a build from a dirty tree reports a dirty build id rather than a clean sha'."""
    repo = _make_repo(tmp_path)
    (repo / "VERSION").write_text("0.1.0\nlocal-edit\n", encoding="utf-8")  # uncommitted change
    sha, dirty = build_info.git_state(repo)
    assert dirty is True, "a modified tracked file must be reported dirty"
    info = build_info.resolve("vigil", root=repo)
    assert info.build_id.endswith(".dirty")
    assert info.build_id == f"0.1.0+g{sha[:12]}.dirty"


@requires_git
def test_negative_control_untracked_file_also_counts_as_dirty(tmp_path: Path):
    repo = _make_repo(tmp_path)
    (repo / "scratch.txt").write_text("untracked", encoding="utf-8")
    _sha, dirty = build_info.git_state(repo)
    assert dirty is True, "an untracked file must be reported dirty (never a silent clean sha)"


def test_non_git_directory_reports_unknown_not_a_fake_sha(tmp_path: Path):
    plain = tmp_path / "notarepo"
    plain.mkdir()
    (plain / "VERSION").write_text("0.1.0\n", encoding="utf-8")
    sha, dirty = build_info.git_state(plain)
    assert sha == "unknown"
    assert dirty is False
    info = build_info.resolve("sigil", root=plain)
    assert info.build_id == "0.1.0+unknown"
    assert info.line() == "sigil 0.1.0 (build 0.1.0+unknown; git unknown)"


def test_version_line_shape_for_every_program_name():
    for prog in ("vigil", "vigil-gateway", "sigil", "framework.v2"):
        line = build_info.version_line(prog, root=Path("/nonexistent-root-zzz"))
        assert line.startswith(f"{prog} ")
        assert "build " in line and "git " in line
