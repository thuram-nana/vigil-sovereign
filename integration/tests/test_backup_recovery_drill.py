"""SUB-PART 4 — the automated backup RECOVERY DRILL round-trips green.

``tools/backup/recovery_drill.sh`` takes a real ``vigil backup``, restores it into FRESH throwaway dirs, and
leans on the EXISTING restore re-verification (offense spine chain/signatures + segment view + evidence
bundles). A non-zero restore exit fails the drill. This test drives the script against a seeded offense home
(offense-only, so no sovereign venv is needed) and asserts a clean PASS.

Run in the offense leg:
    PYTHONPATH=integration:engine/crucible:gateway:packages/core/vigil_core:. .venv-offense/bin/python \
        -m pytest integration/tests/test_backup_recovery_drill.py -q
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.evidence.cli")

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DRILL = _REPO_ROOT / "tools" / "backup" / "recovery_drill.sh"

from tests.test_backup_roundtrip import PW, _seed_offense_home  # type: ignore  # noqa: E402


def _offense_pythonpath() -> str:
    parts = [
        _REPO_ROOT / "integration",
        _REPO_ROOT / "engine" / "crucible",
        _REPO_ROOT / "gateway",
        _REPO_ROOT / "packages" / "core" / "vigil_core",
        _REPO_ROOT,                                    # so `tools.backup` + the script's find are rooted here
    ]
    return os.pathsep.join(str(p) for p in parts)


def test_recovery_drill_round_trips_green(tmp_path):
    base = tmp_path / "src-base"
    _seed_offense_home(base)
    empty_croot = tmp_path / "empty-crucible"
    empty_croot.mkdir()

    env = dict(os.environ)
    env["PYTHONPATH"] = _offense_pythonpath()
    env["VIGIL_CMD"] = f"{sys.executable} -m vigil_integration.cli"    # drive the real CLI, no venv needed
    env["VIGIL_BASE_DIR"] = str(base)
    env["VIGIL_CRUCIBLE_ROOT"] = str(empty_croot)                     # hermetic: no real in-repo crucible tree
    env["VIGIL_DRILL_SCOPE"] = "--offense-only"                        # no sovereign venv in this worktree
    env["VIGIL_BACKUP_PASSPHRASE"] = PW
    env["VIGIL_WORK_DIR"] = str(tmp_path)

    proc = subprocess.run(["bash", str(_DRILL)], env=env, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, f"drill failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert "PASS" in proc.stdout, proc.stdout
    # the throwaway work dir is cleaned up by the script's EXIT trap.
    assert not list(tmp_path.glob("vigil-drill.*")), "the drill must clean up its throwaway work dir"


def test_recovery_drill_requires_a_passphrase(tmp_path):
    """The drill refuses to run without a passphrase (exit 2) rather than silently produce a useless run."""
    env = dict(os.environ)
    env.pop("VIGIL_BACKUP_PASSPHRASE", None)
    proc = subprocess.run(["bash", str(_DRILL)], env=env, capture_output=True, text=True, timeout=30)
    assert proc.returncode == 2, proc.stderr
    assert "VIGIL_BACKUP_PASSPHRASE is required" in proc.stderr
