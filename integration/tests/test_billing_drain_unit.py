"""Front B — the money-IN drain is AUTOMATED: `vigil-billing-drain.{service,timer}` runs one `sigil billing-drain`
pass every 60s (mirrors vigil-settle-drain / vigil-finding-drain), so a paid customer's credit grant no longer waits
on an operator. Structural invariants a systemd smoke test cannot check on a PR runner, plus the hard rule that the
shipped env example carries NO secret value (the owner provisions the Flutterwave secrets; never git)."""
from __future__ import annotations

import os
import re
import shlex
import subprocess
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
    assert exec_start == ["ExecStart=%h/.sigil/venv/bin/sigil billing-drain drain"]


def test_the_unit_names_no_spool_so_the_drain_derives_it_from_sigil_home():
    """A fixed %h/.sigil/billing-spool default is NOT $SIGIL_HOME/billing-spool once the GO-LIVE runbook moves
    SIGIL_HOME: the drain then read an empty directory and exited 0 while paid webhooks sat un-credited. The unit
    therefore names NO spool (the CLI derives it — apps/sigil/tests/test_cli_billing_drain.py); an operator's env
    file may still set one."""
    d = _directives(_UNIT)
    assert not any("billing-spool" in ln or "--spool" in ln for ln in d), d
    assert not any(ln.startswith("Environment=VIGIL_BILLING_SPOOL") for ln in d)
    assert "EnvironmentFile=-%h/.config/vigil/billing-drain.env" in d
    env = _ENV.read_text()
    assert re.search(r"^# SIGIL_HOME=", env, re.M) and "MOVED SIGIL_HOME" in env   # the moved-home step is documented


def test_a_hung_pass_is_bounded():
    """Type=oneshot has NO start timeout by default: a pass stuck in the processor call would hold the
    single-drainer lock (and the timer) forever."""
    d = _directives(_UNIT)
    limit = [ln for ln in d if ln.startswith("TimeoutStartSec=")]
    assert len(limit) == 1 and 60 < int(limit[0].split("=", 1)[1]) <= 900, limit


def test_the_heartbeat_hook_never_sees_the_payment_secrets(tmp_path):
    """The EnvironmentFile is unit-wide, so every Exec line inherits it — including the ExecStopPost heartbeat,
    which runs the OTHER venv's `vigil`. RUN the unit's real ExecStopPost command (specifiers expanded the way
    systemd would, `vigil` replaced by a recorder) with both secrets in the environment: the hook must not see
    them, and must still see what it needs."""
    post = [ln.split("=", 1)[1] for ln in _directives(_UNIT) if ln.startswith("ExecStopPost=")]
    assert len(post) == 1
    seen = tmp_path / "seen.env"
    fake_home = tmp_path / "h"
    recorder = fake_home / "vigil" / ".venv-offense" / "bin" / "vigil"
    recorder.parent.mkdir(parents=True)
    recorder.write_text(f'#!/bin/sh\necho "argv=$*" > {shlex.quote(str(seen))}\nenv >> {shlex.quote(str(seen))}\n')
    recorder.chmod(0o755)
    argv = shlex.split(post[0].replace("%h", str(fake_home)).replace("%n", "vigil-billing-drain.service"))
    env = dict(os.environ, VIGIL_BILLING_WEBHOOK_SECRET="dummy-webhook-hash", VIGIL_FLW_SECRET_KEY="dummy-flw-key",
               SERVICE_RESULT="success", VIGIL_ALERT_STATE_DIR=str(tmp_path / "hb"))
    subprocess.run(argv, env=env, check=True, timeout=30)
    got = seen.read_text()
    assert "argv=unit-heartbeat vigil-billing-drain.service" in got
    assert "SERVICE_RESULT=success" in got and "VIGIL_ALERT_STATE_DIR=" in got     # what the hook reads survives
    assert "VIGIL_BILLING_WEBHOOK_SECRET" not in got and "VIGIL_FLW_SECRET_KEY" not in got
    assert "dummy-webhook-hash" not in got and "dummy-flw-key" not in got


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
    runbook = (_REPO / "docs" / "runbooks" / "GO-LIVE-quickstart.md").read_text()
    assert "$SIGIL_HOME/billing-spool" in runbook                     # the derived default IS the runbook path
    assert "billing-drain.env" in runbook and "moved `SIGIL_HOME`" in runbook    # the moved-home step


def test_one_drainer_rule_is_stated_everywhere():
    for p in (_UNIT, _ENV, _REPO / "docs" / "runbooks" / "GO-LIVE-quickstart.md"):
        assert "never both" in p.read_text(), p
