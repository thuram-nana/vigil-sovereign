"""W16-1 — crucible_root() must not mis-root to a stray CLAUDE.md under $HOME.

The console-script wrappers (`vigil` / `crucible`) are invoked with ``sys.argv[0]`` pointing into a venv
``bin/`` directory. Walking up from there can reach a directory that happens to hold an UNRELATED
``CLAUDE.md`` (e.g. one under $HOME) — and rooting there would send the governance key, kill-switch,
entitlement trust root, findings and captured evidence to the wrong tree. The fix tries this module's
(stable) package location BEFORE the invoking script's path, so the real repo root always wins; the
argv[0]/CWD candidates remain as fallbacks for a true site-packages install.

These tests fail against the pre-fix ordering (argv[0] first) and pass after it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from framework.v2.common import paths


def test_console_script_argv0_does_not_misroot_to_a_stray_claude_md(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A fake $HOME holding an unrelated CLAUDE.md, with the wrapper living in a venv bin/ under it.
    stray_home = tmp_path / "home"
    stray_home.mkdir()
    (stray_home / "CLAUDE.md").write_text("# unrelated stray sentinel\n", encoding="utf-8")
    fake_bin = stray_home / "venv" / "bin"
    fake_bin.mkdir(parents=True)
    fake_console_script = fake_bin / "crucible"  # only its .parent is walked; the file need not exist

    monkeypatch.delenv("CRUCIBLE_ROOT", raising=False)
    monkeypatch.setattr(sys, "argv", [str(fake_console_script), "verify-ledger"])
    # a neutral cwd whose ancestry has no CLAUDE.md, so CWD cannot rescue either ordering
    monkeypatch.chdir(tmp_path)

    paths._reset_cache()
    try:
        root = paths.crucible_root()
    finally:
        paths._reset_cache()

    # The stable package-location walk is the source of truth for the real repo root.
    real_root = paths._walk_up_for_sentinel(Path(paths.__file__).parent)
    assert real_root is not None
    assert root == real_root
    assert (root / "CLAUDE.md").is_file()
    # Load-bearing security assertion: it must NOT root at the stray $HOME.
    assert root != stray_home


def test_crucible_root_env_override_still_honored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Blast-radius guard: reordering the discovery candidates must not disturb the CRUCIBLE_ROOT override
    # (which feeds the kill-switch path, entitlement trust root, and charter location).
    explicit = tmp_path / "explicit-root"
    explicit.mkdir()
    (explicit / "CLAUDE.md").write_text("# explicit root\n", encoding="utf-8")
    monkeypatch.setenv("CRUCIBLE_ROOT", str(explicit))
    # even a hostile argv[0] pointing at a different sentinel must not override the env pin
    monkeypatch.setattr(sys, "argv", [str(tmp_path / "elsewhere" / "bin" / "crucible")])

    paths._reset_cache()
    try:
        assert paths.crucible_root() == explicit.resolve()
    finally:
        paths._reset_cache()
