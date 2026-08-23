"""W7-1 — the DR objectives (RPO/RTO) are DEFINED numerically and ASSERTED by the recovery drill.

Two halves, both proven here:

  * the pure objective gate ``tools.backup.objectives`` — RPO/RTO are concrete numbers, ``data_loss_seconds``
    reads a backup's age from its timestamp, and ``assert_within_objectives`` FAILS (fail-closed) when the
    measured recovery time exceeds the RTO or the measured data loss exceeds the RPO. Negative controls run in
    the SAME suite against the DEFAULT objectives, so the gate is proven not to be a no-op.
  * the drill enforces them end to end — ``tools/backup/recovery_drill.sh`` times the real restore and asserts
    the objectives. The NEGATIVE CONTROL the acceptance criteria demand: an artificially delayed restore step
    makes the drill FAIL (``VIGIL_DRILL_INJECT_DELAY_S`` + a tightened ``VIGIL_RTO_SECONDS``), proving the
    assertion is live rather than decorative.

"Fails without this change": ``tools.backup.objectives`` did not exist, and the drill enforced no objective —
the imports below and the injected-delay drill run both go RED on a pre-W7-1 tree.

Needs framework (the drill's restore re-verifies the spine/evidence) → runs in the offense leg:
    PYTHONPATH=integration:engine/crucible:gateway:packages/core/vigil_core:. .venv-offense/bin/python \
        -m pytest integration/tests/test_backup_dr_objectives.py -q
"""
from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.evidence.cli")

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.backup import objectives  # noqa: E402
from tools.backup.objectives import (  # noqa: E402
    RPO_SECONDS,
    RTO_SECONDS,
    ObjectiveError,
    assert_within_objectives,
    data_loss_seconds,
    parse_backup_timestamp,
)

from test_backup_roundtrip import PW, _seed_offense_home  # type: ignore  # noqa: E402

_DRILL = _REPO_ROOT / "tools" / "backup" / "recovery_drill.sh"


# --------------------------------------------------------------------------------------------------
# The stated objectives are concrete numbers.
# --------------------------------------------------------------------------------------------------
def test_objectives_are_stated_as_sane_numbers():
    assert isinstance(RPO_SECONDS, int) and RPO_SECONDS == 24 * 60 * 60          # 24h
    assert isinstance(RTO_SECONDS, int) and RTO_SECONDS == 30 * 60              # 30m
    # a recovery budget larger than the data-loss budget would be nonsensical for this pipeline.
    assert 0 < RTO_SECONDS < RPO_SECONDS
    s = objectives.objectives_summary()
    assert s["rpo_human"] == "24h" and s["rto_human"] == "30m"


# --------------------------------------------------------------------------------------------------
# data_loss_seconds — a backup's age is read from its timestamped name (fail-closed on a bad name).
# --------------------------------------------------------------------------------------------------
def test_data_loss_seconds_reads_the_backup_age_from_its_timestamp():
    now = datetime(2026, 1, 2, 12, 0, 0, tzinfo=timezone.utc)
    # a backup taken 2 hours ago → 7200s of data loss.
    assert data_loss_seconds("20260102-100000", now=now) == pytest.approx(7200.0)
    # a full path is accepted; the basename is what matters.
    assert data_loss_seconds("/off-host/20260102-100000", now=now) == pytest.approx(7200.0)
    # a backup dir "from the future" (clock skew) clamps to 0, never negative.
    assert data_loss_seconds("20260102-140000", now=now) == 0.0
    assert parse_backup_timestamp("not-a-timestamp") is None


def test_data_loss_seconds_fails_closed_on_an_unparseable_name():
    with pytest.raises(ObjectiveError, match="not a YYYYmmdd-HHMMSS timestamp"):
        data_loss_seconds("latest")


# --------------------------------------------------------------------------------------------------
# assert_within_objectives — the fail-closed gate, negative controls against the DEFAULT objectives.
# --------------------------------------------------------------------------------------------------
def test_assert_within_objectives_passes_within_budget():
    rep = assert_within_objectives(recovery_seconds=5.0, data_loss_seconds=3600.0)
    assert rep["met"] is True and rep["rto_seconds"] == RTO_SECONDS and rep["rpo_seconds"] == RPO_SECONDS


def test_assert_fails_when_recovery_exceeds_the_rto():
    # NEGATIVE CONTROL (default RTO): a restore just over 30 minutes is rejected.
    with pytest.raises(ObjectiveError, match="recovery time .* exceeds the RTO"):
        assert_within_objectives(recovery_seconds=RTO_SECONDS + 1, data_loss_seconds=0.0)


def test_assert_fails_when_data_loss_exceeds_the_rpo():
    # NEGATIVE CONTROL (default RPO): a backup older than 24h is rejected.
    with pytest.raises(ObjectiveError, match="data loss .* exceeds the RPO"):
        assert_within_objectives(recovery_seconds=1.0, data_loss_seconds=RPO_SECONDS + 1)


def test_assert_reports_both_misses_at_once():
    with pytest.raises(ObjectiveError) as ei:
        assert_within_objectives(recovery_seconds=RTO_SECONDS + 1, data_loss_seconds=RPO_SECONDS + 1)
    assert "RTO" in str(ei.value) and "RPO" in str(ei.value)


# --------------------------------------------------------------------------------------------------
# The objectives CLI (what the systemd drill invokes) — fail-closed on a stale backup.
# --------------------------------------------------------------------------------------------------
def _objectives_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(_REPO_ROOT / "tools" / "backup" / "objectives.py"), *args],
                          capture_output=True, text=True, timeout=30)


def test_objectives_cli_ok_within_budget():
    now = datetime.now(timezone.utc) - timedelta(hours=1)
    name = now.strftime("%Y%m%d-%H%M%S")
    p = _objectives_cli("check", "--recovery-seconds", "3", "--backup-name", name)
    assert p.returncode == 0, p.stderr
    assert "objectives check: OK" in p.stdout


def test_objectives_cli_fails_closed_on_a_stale_backup():
    # a backup 10 days old → data loss > RPO → exit 1 (the drill turns this into a FAIL).
    old = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y%m%d-%H%M%S")
    p = _objectives_cli("check", "--recovery-seconds", "1", "--backup-name", old)
    assert p.returncode == 1, p.stdout
    assert "exceeds the RPO" in p.stderr


# --------------------------------------------------------------------------------------------------
# The DRILL enforces the objectives end to end.
# --------------------------------------------------------------------------------------------------
def _drill_env(base: Path, croot: Path, work: Path) -> dict:
    parts = [_REPO_ROOT / "integration", _REPO_ROOT / "engine" / "crucible",
             _REPO_ROOT / "gateway", _REPO_ROOT / "packages" / "core" / "vigil_core", _REPO_ROOT]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(str(p) for p in parts)
    env["VIGIL_CMD"] = f"{sys.executable} -m vigil_integration.cli"
    env["VIGIL_PYTHON"] = sys.executable
    env["VIGIL_BASE_DIR"] = str(base)
    env["VIGIL_CRUCIBLE_ROOT"] = str(croot)
    env["VIGIL_DRILL_SCOPE"] = "--offense-only"
    env["VIGIL_BACKUP_PASSPHRASE"] = PW
    env["VIGIL_WORK_DIR"] = str(work)
    return env


def test_drill_passes_within_objectives_and_reports_them(tmp_path):
    base = tmp_path / "src-base"
    _seed_offense_home(base)
    croot = tmp_path / "empty-crucible"
    croot.mkdir()
    proc = subprocess.run(["bash", str(_DRILL)], env=_drill_env(base, croot, tmp_path),
                          capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, f"drill failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert "PASS" in proc.stdout
    assert "objectives check: OK" in proc.stdout          # the objective assertion actually ran


def test_drill_FAILS_when_the_restore_exceeds_the_rto(tmp_path):
    # THE ACCEPTANCE-CRITERIA NEGATIVE CONTROL: an artificially delayed restore step makes the drill fail,
    # proving the RTO assertion is live. A real 3s delay against a tightened 1s RTO → the drill exits non-zero.
    base = tmp_path / "src-base"
    _seed_offense_home(base)
    croot = tmp_path / "empty-crucible"
    croot.mkdir()
    env = _drill_env(base, croot, tmp_path)
    env["VIGIL_DRILL_INJECT_DELAY_S"] = "3"
    env["VIGIL_RTO_SECONDS"] = "1"
    proc = subprocess.run(["bash", str(_DRILL)], env=env, capture_output=True, text=True, timeout=180)
    assert proc.returncode != 0, f"a slow restore must FAIL the drill:\n{proc.stdout}\n{proc.stderr}"
    combined = proc.stdout + proc.stderr
    assert "exceeds the RTO" in combined and "did NOT meet the DR objectives" in combined
    # fail-closed did not leave a stray work dir behind (the EXIT trap still cleans up on failure).
    assert not list(tmp_path.glob("vigil-drill.*"))
