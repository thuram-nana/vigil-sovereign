"""Front B — the money-IN drain is AUTOMATED: `vigil-billing-drain.{service,timer}` runs one `sigil billing-drain`
pass every 60s (mirrors vigil-settle-drain / vigil-finding-drain), so a paid customer's credit grant no longer waits
on an operator. Structural invariants a systemd smoke test cannot check on a PR runner, plus the hard rule that the
shipped env example carries NO secret value (the owner provisions the Flutterwave secrets; never git)."""
from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_SYS = _REPO / "infra" / "systemd"
_UNIT, _TIMER, _ENV = (_SYS / "vigil-billing-drain.service", _SYS / "vigil-billing-drain.timer",
                       _SYS / "vigil-billing-drain.env.example")


def _directives(p: Path) -> list[str]:
    return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")]


def test_runs_one_drain_pass_of_the_billing_spool():
    d = _directives(_UNIT)
    assert "Type=oneshot" in d and not any(ln.startswith("Restart=") for ln in d)
    exec_start = [ln for ln in d if ln.startswith("ExecStart=")]
    assert exec_start == ["ExecStart=%h/.sigil/venv/bin/sigil billing-drain drain --spool ${VIGIL_BILLING_SPOOL}"]


def test_the_spool_default_is_a_unit_directive_not_an_env_file_value():
    d = _directives(_UNIT)
    assert "Environment=VIGIL_BILLING_SPOOL=%h/.sigil/spool/billing" in d       # %h expands only here
    env = d.index("Environment=VIGIL_BILLING_SPOOL=%h/.sigil/spool/billing")
    envfile = d.index("EnvironmentFile=-%h/.config/vigil/billing-drain.env")
    assert env < envfile                                                         # the env file may override it


def test_heartbeat_and_hardening():
    d = _directives(_UNIT)
    assert any(ln.startswith("ExecStopPost=") and "unit-heartbeat %n" in ln for ln in d)
    assert "ReadWritePaths=%h/.sigil" in d and "ProtectSystem=strict" in d and "NoNewPrivileges=yes" in d
    assert "PrivateNetwork=yes" not in d       # the MANDATORY processor re-verify is an HTTPS call


def test_timer_fires_every_minute():
    d = _directives(_TIMER)
    assert "OnUnitActiveSec=60" in d and "OnBootSec=60" in d and "Unit=vigil-billing-drain.service" in d


def test_the_env_example_ships_no_secret_value():
    for key in ("VIGIL_BILLING_WEBHOOK_SECRET", "VIGIL_FLW_SECRET_KEY", "VIGIL_BILLING_DRAIN_ENABLED"):
        live = [ln for ln in _ENV.read_text().splitlines() if re.match(rf"\s*{key}\s*=", ln)]
        assert not live, f"{key} must ship commented-out (opt-in; owner-provisioned): {live}"
    for ln in _ENV.read_text().splitlines():
        m = re.match(r"\s*#\s*(VIGIL_[A-Z_]*(SECRET|KEY)[A-Z_]*)\s*=\s*(\S*)", ln)
        if m:
            assert m.group(3) == "", f"{m.group(1)} must carry NO value, even commented out"


def test_the_spool_must_match_the_proxy_and_is_documented():
    text = _ENV.read_text()
    assert "VIGIL_BILLING_WEBHOOK_SPOOL" in text and "MUST equal" in text
