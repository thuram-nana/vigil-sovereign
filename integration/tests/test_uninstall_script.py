"""W16-STD-6(e) — the uninstall path (uninstall.sh) removes what bootstrap.sh wired, and ONLY that.

bootstrap.sh installs machine-level WIRING outside the repo: ~/.local/bin launchers, the ~/.sigil/venv
symlink, and user systemd units. Before this change there was NO uninstall — the wiring lingered forever.
``uninstall.sh`` is the inverse; it honors $HOME/$SIGIL_HOME so it can be exercised against a scratch HOME.

The test drives the real script against a fake HOME that mimics a completed install, and asserts:
  * it REMOVES the launchers, the venv symlink, and the units bootstrap copies;
  * NEGATIVE CONTROL — it LEAVES unrelated files it did not create (a foreign launcher, a foreign unit),
    the operator's secrets (sigil.env), and engagement data (.vigil-live); it says so on stdout;
  * a launcher pointing OUTSIDE the repo is not clobbered (conservative ownership check);
  * --purge-config additionally removes the copied config env files.

Fails without the fix: uninstall.sh does not exist, so the subprocess run raises / errors.
Pure offense-leg: no framework/sigil import (FATAL-2 intact).
"""
from __future__ import annotations

import os
import pathlib
import subprocess

import pytest

_REPO = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _REPO / "uninstall.sh"


def _seed_install(home: pathlib.Path, sigil_home: pathlib.Path) -> dict:
    """Lay down what a completed bootstrap leaves behind, plus foreign files that must survive."""
    bindir = home / ".local" / "bin"
    unitdir = home / ".config" / "systemd" / "user"
    vigil_cfg = home / ".config" / "vigil"
    for d in (bindir, unitdir, vigil_cfg, sigil_home, home / ".vigil-live"):
        d.mkdir(parents=True, exist_ok=True)

    # launchers bootstrap creates — symlinks INTO this repo's venvs
    (bindir / "vigil").symlink_to(_REPO / ".venv-offense" / "bin" / "vigil")
    (bindir / "sigil").symlink_to(_REPO / ".venv-sovereign" / "bin" / "sigil")
    # a FOREIGN launcher that must be left alone (points outside the repo)
    (bindir / "other").symlink_to("/usr/bin/true")
    # a launcher named 'vigil' but pointing elsewhere would be foreign too — cover via 'other'

    # the ~/.sigil/venv symlink bootstrap creates
    (sigil_home / "venv").symlink_to(_REPO / ".venv-sovereign")

    # units bootstrap copies (one vigil-*, one sigil-*), plus a FOREIGN unit that must survive
    (unitdir / "vigil-backup.service").write_text("[Unit]\n")
    (unitdir / "sigil-cockpit.service").write_text("[Unit]\n")
    (unitdir / "unrelated.service").write_text("[Unit]\n")

    # config + data that must be LEFT (secrets / engagement history) by default
    (sigil_home / "sigil.env").write_text("SECRET=keepme\n")
    (vigil_cfg / "backup.env").write_text("VIGIL_BACKUP_PASSPHRASE=x\n")
    (home / ".vigil-live" / "findings.txt").write_text("a real finding\n")

    return {
        "vigil": bindir / "vigil", "sigil": bindir / "sigil", "other": bindir / "other",
        "venv": sigil_home / "venv",
        "u_vigil": unitdir / "vigil-backup.service", "u_sigil": unitdir / "sigil-cockpit.service",
        "u_foreign": unitdir / "unrelated.service",
        "sigil_env": sigil_home / "sigil.env", "backup_env": vigil_cfg / "backup.env",
        "finding": home / ".vigil-live" / "findings.txt",
    }


def _run(home: pathlib.Path, sigil_home: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["SIGIL_HOME"] = str(sigil_home)
    # PATH without systemctl keeps the test hermetic (the script guards on `command -v systemctl`)
    env["PATH"] = "/usr/bin:/bin"
    return subprocess.run(
        ["bash", str(_SCRIPT), "--yes", *args],
        env=env, cwd=str(_REPO), capture_output=True, text=True, timeout=60,
    )


def test_uninstall_removes_wiring_and_leaves_data(tmp_path):
    home = tmp_path / "home"
    sigil_home = home / ".sigil"
    f = _seed_install(home, sigil_home)

    r = _run(home, sigil_home)
    assert r.returncode == 0, r.stderr

    # REMOVED: launchers, venv symlink, the two units bootstrap installed
    assert not f["vigil"].exists() and not f["vigil"].is_symlink()
    assert not f["sigil"].exists() and not f["sigil"].is_symlink()
    assert not f["venv"].exists() and not f["venv"].is_symlink()
    assert not f["u_vigil"].exists()
    assert not f["u_sigil"].exists()

    # NEGATIVE CONTROL: foreign / data / secret files are UNTOUCHED
    assert f["other"].is_symlink(), "a launcher pointing outside the repo must not be clobbered"
    assert f["u_foreign"].exists(), "a unit bootstrap did not install must survive"
    assert f["sigil_env"].read_text() == "SECRET=keepme\n"
    assert f["finding"].read_text() == "a real finding\n"
    assert f["backup_env"].exists(), "config env is kept unless --purge-config"

    # it SAYS what it leaves
    out = r.stdout
    assert ".vigil-live" in out and "sigil.env" in out


def test_uninstall_is_idempotent(tmp_path):
    home = tmp_path / "home"
    sigil_home = home / ".sigil"
    _seed_install(home, sigil_home)
    assert _run(home, sigil_home).returncode == 0
    # second run over an already-clean tree must still succeed (no state to remove)
    assert _run(home, sigil_home).returncode == 0


def test_purge_config_removes_env_files(tmp_path):
    home = tmp_path / "home"
    sigil_home = home / ".sigil"
    f = _seed_install(home, sigil_home)
    r = _run(home, sigil_home, "--purge-config")
    assert r.returncode == 0, r.stderr
    assert not f["backup_env"].exists(), "--purge-config must remove the copied config env"
    # but secrets/data are STILL kept even with --purge-config
    assert f["sigil_env"].read_text() == "SECRET=keepme\n"
    assert f["finding"].exists()
