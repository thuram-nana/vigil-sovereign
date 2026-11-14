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

import pytest

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
    # SIGIL_HOME is REQUIRED (moved or not): the drain never falls back to ~/.sigil (test_cli_billing_drain.py)
    assert re.search(r"^# SIGIL_HOME=", env, re.M) and "REQUIRED, ALWAYS" in env and "MOVED SIGIL_HOME" not in env


def _lock_wait_s() -> float:
    cli_src = (_REPO / "apps" / "sigil" / "sigil" / "cli.py").read_text(encoding="utf-8")
    return float(re.search(r"^_BILLING_LOCK_WAIT_S = ([0-9.]+)", cli_src, re.M).group(1))


def test_a_hung_pass_is_bounded():
    """Type=oneshot has NO start timeout by default: a WEDGED pass would hold the single-drainer lock (and the timer)
    forever. But the bound must not kill a legitimately slow pass: each pass is a fresh process whose every mint
    folds the spine from the start (a subscription webhook several times), so on a large spine one envelope can take
    minutes — a tight bound would kill that pass every time and the payment would never be credited. Detection of a
    stuck pass is the dead-man's job (no heartbeat within its ~2 min bound), not this timeout's."""
    d = _directives(_UNIT)
    limit = [ln for ln in d if ln.startswith("TimeoutStartSec=")]
    assert len(limit) == 1 and 1800 <= int(limit[0].split("=", 1)[1]) <= 3600, limit
    egress = (_REPO / "apps" / "sigil" / "sigil" / "governor" / "flutterwave_egress.py").read_text(encoding="utf-8")
    per_call = float(re.search(r"^_DEFAULT_TIMEOUT_S = ([0-9.]+)", egress, re.M).group(1))
    assert int(limit[0].split("=", 1)[1]) >= 10 * (_lock_wait_s() + 4 * per_call)


def test_the_shipped_lock_wait_outlasts_an_ordinary_overlapping_pass_and_is_the_documented_one():
    """The CLI's real lock wait (the single-drainer tests pin their own): a timer pass overlapping a manual pass
    must WAIT it out, not exit 1 at once — that would turn the unit FAILED and raise a false paid-not-credited
    MONEY-5 alarm with nothing wrong. At least one timer period, and the value the unit and GO-LIVE §9 state."""
    wait = _lock_wait_s()
    assert 60 <= wait
    stated = f"{int(wait)} s"
    assert stated in _UNIT.read_text() and stated in (_REPO / "docs" / "runbooks" / "GO-LIVE-quickstart.md").read_text()


def _run_exec_stop_post(tmp_path, program: str, **extra_env) -> None:
    """RUN the unit's real ExecStopPost command line, its specifiers and `$$` escapes expanded the way systemd
    expands them, with the offense venv's `vigil` replaced by `program`."""
    post = [ln.split("=", 1)[1] for ln in _directives(_UNIT) if ln.startswith("ExecStopPost=")]
    assert len(post) == 1
    fake_home = tmp_path / "h"
    exe = fake_home / "vigil" / ".venv-offense" / "bin" / "vigil"
    exe.parent.mkdir(parents=True)
    exe.write_text(program)
    exe.chmod(0o755)
    line = post[0].replace("%h", str(fake_home)).replace("%n", "vigil-billing-drain.service").replace("$$", "$")
    env = dict(os.environ, HOME=str(fake_home), VIGIL_ALERT_STATE_DIR=str(tmp_path / "hb"), **extra_env)
    subprocess.run(shlex.split(line), env=env, check=True, timeout=60)


def test_the_heartbeat_hook_never_sees_the_payment_secrets(tmp_path):
    """The EnvironmentFile is unit-wide, so every Exec line inherits it — including the ExecStopPost heartbeat,
    which runs the OTHER venv's `vigil`. It gets an ALLOW-listed environment: not the two payment secrets, not
    any other secret an operator put in the env file, and still exactly what the hook reads."""
    seen = tmp_path / "seen.env"
    _run_exec_stop_post(tmp_path, f'#!/bin/sh\necho "argv=$*" > {shlex.quote(str(seen))}\nenv >> {shlex.quote(str(seen))}\n',
                        VIGIL_BILLING_WEBHOOK_SECRET="dummy-webhook-hash", VIGIL_FLW_SECRET_KEY="dummy-flw-key",
                        SOME_OPERATOR_TOKEN="dummy-operator-token", SERVICE_RESULT="success")
    got = seen.read_text()
    assert "argv=unit-heartbeat vigil-billing-drain.service" in got
    names = {ln.split("=", 1)[0] for ln in got.splitlines()[1:] if "=" in ln}
    assert {"SERVICE_RESULT", "VIGIL_ALERT_STATE_DIR", "HOME"} <= names
    assert names <= {"SERVICE_RESULT", "VIGIL_ALERT_STATE_DIR", "HOME", "PWD", "SHLVL", "_"}, names
    assert "SERVICE_RESULT=success" in got
    for secret in ("dummy-webhook-hash", "dummy-flw-key", "dummy-operator-token"):
        assert secret not in got


@pytest.mark.parametrize("result,ok", [("exit-code", False), ("timeout", False), ("success", True)])
def test_the_allow_listed_heartbeat_still_records_the_result(tmp_path, result, ok):
    """The REAL `vigil unit-heartbeat` under the hook's allow-listed environment: a failed pass is recorded as
    FAILED (the dead-man's input), a successful one as ok — nothing it needs was dropped."""
    import json
    import sys
    paths = [str(_REPO / "integration"), str(_REPO / "packages" / "core" / "vigil_core")]
    program = (f"#!{sys.executable}\nimport sys\nsys.path[:0] = {paths!r}\n"
               f"from vigil_integration.cli import main\nsys.exit(main(sys.argv[1:]))\n")
    beat = tmp_path / "hb" / "vigil-billing-drain.service.hb.json"
    _run_exec_stop_post(tmp_path, program, SERVICE_RESULT=result, VIGIL_FLW_SECRET_KEY="dummy-flw-key")
    rec = json.loads(beat.read_text())
    assert rec["ok"] is ok and rec["result"] == result


def test_heartbeat_and_hardening():
    d = _directives(_UNIT)
    assert any(ln.startswith("ExecStopPost=") and "unit-heartbeat" in ln and ln.endswith(" %n") for ln in d)
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
    assert "**Set `SIGIL_HOME` in `~/.config/vigil/billing-drain.env`**" in runbook   # always, moved or not
    assert "never falls back to `~/.sigil`" in runbook


def test_one_drainer_rule_is_stated_everywhere():
    for p in (_UNIT, _ENV, _REPO / "docs" / "runbooks" / "GO-LIVE-quickstart.md"):
        assert "never both" in p.read_text(), p
