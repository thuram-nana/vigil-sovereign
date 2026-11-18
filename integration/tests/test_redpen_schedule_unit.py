"""Red-Pen R4 — the System-review scheduler is AUTOMATED by `vigil-redpen-schedule.{service,timer}` (one
`sigil redpen-schedule tick` pass an hour, in the `vigil-billing-drain` pattern). Structural invariants a systemd
smoke test cannot check on a PR runner: one oneshot pass of the SOVEREIGN venv's scheduler (it reserves credits —
never a job), the ONE shared seam base, a required explicit SIGIL_HOME, an allow-listed heartbeat hook, a bounded
pass, a timer whose cadence is the one the dead-man monitors, an env example that ships nothing live, and — installed
beside the cockpit and the settle drain — agreement on the seam (an override on the scheduler alone is a hard
`vigil doctor` issue). Framework-free: files only."""
from __future__ import annotations

import shutil
from pathlib import Path

from vigil_integration import doctor as _doc
from vigil_integration import unit_alerts as ua
from vigil_integration.seam_base_units import SEAM_UNITS, seam_base_agreement

_REPO = Path(__file__).resolve().parents[2]
_SYS = _REPO / "infra" / "systemd"
_UNIT, _TIMER, _ENV = (_SYS / "vigil-redpen-schedule.service", _SYS / "vigil-redpen-schedule.timer",
                       _SYS / "vigil-redpen-schedule.env.example")


def _directives(p: Path) -> list[str]:
    return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")]


def test_runs_one_sovereign_scheduler_pass():
    d = _directives(_UNIT)
    assert "Type=oneshot" in d and not any(ln.startswith("Restart=") for ln in d)
    assert [ln for ln in d if ln.startswith("ExecStart=")] == ["ExecStart=%h/.sigil/venv/bin/sigil redpen-schedule tick"]


def test_it_shares_the_one_seam_base_and_needs_an_explicit_sigil_home():
    d = _directives(_UNIT)
    assert "Environment=VIGIL_BASE_DIR=%h/.sigil/credit-lease" in d       # the cockpit's + the settle drain's seam
    assert "EnvironmentFile=-%h/.config/vigil/redpen-schedule.env" in d
    assert "WorkingDirectory=%h/.sigil" in d and "ReadWritePaths=%h/.sigil" in d
    env = _ENV.read_text(encoding="utf-8")
    assert "# SIGIL_HOME=" in env and "REQUIRED, ALWAYS" in env and "# VIGIL_REDPEN_ENABLED=1" in env


def test_the_env_example_ships_nothing_live():
    # every assignment is commented: copying the example never turns Red-Pen on or names a home by accident
    assert _directives(_ENV) == []


def test_the_heartbeat_hook_runs_with_an_allow_listed_environment():
    (post,) = [ln for ln in _directives(_UNIT) if ln.startswith("ExecStopPost=")]
    assert "/usr/bin/env -i" in post and "unit-heartbeat" in post and "%n" in post


def test_a_hung_pass_is_bounded():
    limit = [ln for ln in _directives(_UNIT) if ln.startswith("TimeoutStartSec=")]
    assert len(limit) == 1 and 1800 <= int(limit[0].split("=", 1)[1]) <= 3600, limit


def test_the_unit_is_not_network_locked_because_the_owner_key_may_be_kms_wrapped():
    # a deliberate, documented choice: PrivateNetwork would break unsealing a KMS-wrapped owner key (VIGIL_KEK_BACKEND
    # =kms), so the scheduler could never sign — the settle drain, which also signs, is not network-locked either
    assert "PrivateNetwork=yes" not in _directives(_UNIT)
    assert "KMS" in _UNIT.read_text(encoding="utf-8")


def test_the_timer_fires_the_service_at_the_cadence_the_dead_man_watches():
    d = _directives(_TIMER)
    assert "Unit=vigil-redpen-schedule.service" in d and "WantedBy=timers.target" in d
    assert "OnUnitActiveSec=3600" in d and not any(ln.startswith("RandomizedDelaySec=") for ln in d)
    (spec,) = [u for u in ua.registry() if u.unit == "vigil-redpen-schedule.service"]
    assert spec.timer == "vigil-redpen-schedule.timer" and spec.cadence_s == 3600 and spec.randomized_delay_s == 0
    assert spec.optional is True and spec.enable_env == "VIGIL_REDPEN_ENABLED"   # armed by the master flag


def test_the_scheduler_is_a_registered_seam_unit():
    assert ("vigil-redpen-schedule.service", "infra/systemd") in SEAM_UNITS


def _install(home: Path, *units: str) -> None:
    d = home / ".config" / "systemd" / "user"
    d.mkdir(parents=True, exist_ok=True)
    shipped = {u: _REPO / sub / u for u, sub in SEAM_UNITS}
    for u in units:
        shutil.copy(shipped[u], d / u)


def test_installed_beside_the_cockpit_and_settle_drain_it_agrees_on_the_seam(tmp_path):
    _install(tmp_path, "sigil-cockpit.service", "vigil-settle-drain.service", "vigil-redpen-schedule.service")
    sec, issues = seam_base_agreement(_REPO, tmp_path, parse_env=_doc._parse_env_file)
    assert issues == []
    assert sec["units"]["vigil-redpen-schedule.service"] == str(tmp_path / ".sigil" / "credit-lease")
    assert len(set(sec["units"].values())) == 1


def test_an_override_on_the_scheduler_alone_is_a_hard_doctor_issue(tmp_path):
    _install(tmp_path, "sigil-cockpit.service", "vigil-settle-drain.service", "vigil-redpen-schedule.service")
    env = tmp_path / ".config" / "vigil" / "redpen-schedule.env"
    env.parent.mkdir(parents=True, exist_ok=True)
    env.write_text(f"VIGIL_BASE_DIR={tmp_path / 'elsewhere'}\n", encoding="utf-8")
    _sec, issues = seam_base_agreement(_REPO, tmp_path, parse_env=_doc._parse_env_file)
    assert len(issues) == 1 and "vigil-redpen-schedule.service" in issues[0]
