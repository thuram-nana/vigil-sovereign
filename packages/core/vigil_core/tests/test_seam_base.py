"""E3a — the ONE seam-base resolver (vigil_core.seam_base).

Every plane (sovereign cockpit + drains, integration glue, the keyless offense engine) resolves the cross-plane
seam base through this leaf, so it pins: the precedence (explicit > $VIGIL_BASE_DIR > .vigil-live, empty =
unset), that the winner is ABSOLUTE and names the same directory the old CWD-relative copies did from the same
working directory, that it is total, and the strict money-process form that refuses contradictory settings.

Mutation-verify targets (each neuter reds a NAMED test here):
  * drop the abspath in ``_absolute``                       -> test_result_is_absolute_and_the_same_directory
  * drop the OSError fallback in ``_absolute``              -> test_total_when_the_working_directory_is_gone
  * drop the "%" refusal in ``require_seam_base``           -> test_require_refuses_an_unexpanded_specifier
  * drop the contradiction refusal in ``require_seam_base`` -> test_require_refuses_a_contradictory_legacy_alias,
                                                               test_require_refuses_explicit_vs_env
"""
from __future__ import annotations

import os

import pytest

from vigil_core import seam_base as sb


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv(sb.SEAM_BASE_ENV, raising=False)
    monkeypatch.delenv(sb.LEGACY_SETTLE_BASE_ENV, raising=False)


def test_precedence_explicit_then_env_then_default(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert sb.resolve_seam_base() == str(tmp_path / ".vigil-live")
    monkeypatch.setenv(sb.SEAM_BASE_ENV, str(tmp_path / "env"))
    assert sb.resolve_seam_base() == str(tmp_path / "env")
    assert sb.resolve_seam_base(str(tmp_path / "x")) == str(tmp_path / "x")


def test_empty_values_count_as_unset(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(sb.SEAM_BASE_ENV, "")
    assert sb.resolve_seam_base("") == str(tmp_path / ".vigil-live")
    monkeypatch.setenv(sb.SEAM_BASE_ENV, str(tmp_path / "env"))
    assert sb.resolve_seam_base("") == str(tmp_path / "env")          # an empty explicit falls through to the env


def test_result_is_absolute_and_the_same_directory(monkeypatch, tmp_path):
    """A relative value resolves against the CWD at resolution time — the directory the CWD-relative copies
    named — but as an absolute path, so a child process or another working directory reads the same tree."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "rel").mkdir()
    monkeypatch.setenv(sb.SEAM_BASE_ENV, "rel/seam")
    got = sb.resolve_seam_base()
    assert os.path.isabs(got) and got == str(tmp_path / "rel" / "seam")
    assert os.path.isabs(sb.resolve_seam_base(".vigil-live"))
    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.chdir(other)
    assert os.path.samefile(os.path.dirname(got), tmp_path / "rel")    # the path handed on still names that tree


def test_tilde_is_expanded(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv(sb.SEAM_BASE_ENV, "~/.sigil/credit-lease")
    assert sb.resolve_seam_base() == str(tmp_path / ".sigil" / "credit-lease")


def test_total_when_the_working_directory_is_gone(monkeypatch, tmp_path):
    gone = tmp_path / "gone"
    gone.mkdir()
    monkeypatch.chdir(gone)
    gone.rmdir()                                                       # os.getcwd() now raises
    assert sb.resolve_seam_base() == ".vigil-live"                    # the historical relative form, no raise
    assert sb.require_seam_base() == ".vigil-live"


# ---- the strict form for a MONEY process (the settle drain) -------------------------------------------

def test_require_with_nothing_set_is_the_default(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert sb.require_seam_base() == str(tmp_path / ".vigil-live")


def test_require_accepts_sources_that_name_the_same_directory(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(sb.SEAM_BASE_ENV, "seam")                       # relative, same dir as the absolute ones
    monkeypatch.setenv(sb.LEGACY_SETTLE_BASE_ENV, str(tmp_path / "seam"))
    assert sb.require_seam_base(str(tmp_path / "seam/")) == str(tmp_path / "seam")


def test_require_refuses_a_contradictory_legacy_alias(monkeypatch, tmp_path):
    monkeypatch.setenv(sb.SEAM_BASE_ENV, str(tmp_path / "seam"))
    monkeypatch.setenv(sb.LEGACY_SETTLE_BASE_ENV, str(tmp_path / "credit-lease"))
    with pytest.raises(sb.SeamBaseError, match="contradictory") as ei:
        sb.require_seam_base()
    assert "VIGIL_SETTLE_BASE_DIR" in str(ei.value) and "VIGIL_BASE_DIR" in str(ei.value)
    monkeypatch.delenv(sb.SEAM_BASE_ENV)                               # alias alone vs the default: still refused
    monkeypatch.chdir(tmp_path)
    with pytest.raises(sb.SeamBaseError, match="contradictory"):
        sb.require_seam_base()
    assert sb.resolve_seam_base() == str(tmp_path / ".vigil-live")    # the lenient resolver ignores the alias


def test_require_refuses_explicit_vs_env(monkeypatch, tmp_path):
    monkeypatch.setenv(sb.SEAM_BASE_ENV, str(tmp_path / "a"))
    with pytest.raises(sb.SeamBaseError, match="--base-dir"):
        sb.require_seam_base(str(tmp_path / "b"))


@pytest.mark.parametrize("where", ["explicit", "env", "alias"])
def test_require_refuses_an_unexpanded_specifier(monkeypatch, tmp_path, where):
    literal = "%h/.sigil/credit-lease"
    if where == "env":
        monkeypatch.setenv(sb.SEAM_BASE_ENV, literal)
    elif where == "alias":
        monkeypatch.setenv(sb.LEGACY_SETTLE_BASE_ENV, literal)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(sb.SeamBaseError, match="unexpanded systemd specifier"):
        sb.require_seam_base(literal if where == "explicit" else None)


def test_the_leaf_is_stdlib_only():
    import ast
    from pathlib import Path
    tree = ast.parse(Path(sb.__file__).read_text(encoding="utf-8"))
    mods = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    mods |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert mods <= {"__future__", "os", "typing"}, mods
