"""Stripe parity ST-10: the Stripe lane of the money-IN drain is automated and observable like the Flutterwave one.

Structural invariants of `vigil-billing-drain-stripe.{service,timer,env.example}` (a systemd smoke test cannot run
on a PR runner), the rule that the shipped env example carries no secret value, the runbook section, and the
doctor's MONEY gate naming the Stripe lane's own spool and command when its drain fails.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

import pytest

from vigil_integration import doctor as _doc
from vigil_integration import unit_alerts as _ua

_REPO = Path(__file__).resolve().parents[2]
_SYS = _REPO / "infra" / "systemd"
_UNIT, _TIMER, _ENV = (_SYS / "vigil-billing-drain-stripe.service", _SYS / "vigil-billing-drain-stripe.timer",
                       _SYS / "vigil-billing-drain-stripe.env.example")
_RUNBOOK = _REPO / "docs" / "runbooks" / "GO-LIVE-quickstart.md"


def _directives(p: Path) -> list[str]:
    return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")]


def test_runs_one_stripe_drain_pass_of_its_own_spool():
    d = _directives(_UNIT)
    assert "Type=oneshot" in d and not any(ln.startswith("Restart=") for ln in d)
    assert [ln for ln in d if ln.startswith("ExecStart=")] == [
        "ExecStart=%h/.sigil/venv/bin/sigil billing-drain drain --provider stripe --spool ${VIGIL_STRIPE_BILLING_SPOOL}"]
    default = "Environment=VIGIL_STRIPE_BILLING_SPOOL=%h/.sigil/stripe-billing-spool"
    assert default in d and d.index(default) < d.index("EnvironmentFile=-%h/.config/vigil/billing-drain-stripe.env")
    assert "billing-spool" not in default.split("stripe-")[0]          # never the Flutterwave spool by default


def test_heartbeat_hardening_and_timer():
    d = _directives(_UNIT)
    assert any(ln.startswith("ExecStopPost=") and "unit-heartbeat" in ln and ln.endswith(" %n") for ln in d)
    assert "ReadWritePaths=%h/.sigil" in d and "ProtectSystem=strict" in d and "NoNewPrivileges=yes" in d
    assert "PrivateNetwork=yes" not in d                               # the re-fetch is an HTTPS call
    t = _directives(_TIMER)
    assert "OnUnitActiveSec=60" in t and "OnBootSec=60" in t and "Unit=vigil-billing-drain-stripe.service" in t


def test_the_env_example_ships_no_secret_value_and_no_live_setting():
    lines = _ENV.read_text().splitlines()
    for ln in lines:
        assert not re.match(r"\s*VIGIL_[A-Z_]+\s*=", ln), f"every setting ships commented out: {ln}"
        m = re.match(r"\s*#\s*(VIGIL_[A-Z_]*(SECRET|KEY|VERSION)[A-Z_]*)\s*=\s*(\S*)", ln)
        if m:
            assert m.group(3) == "", f"{m.group(1)} must carry NO value, even commented out"
    text = _ENV.read_text()
    for key in ("VIGIL_STRIPE_BILLING_DRAIN_ENABLED", "VIGIL_BILLING_ENABLE_STRIPE", "VIGIL_STRIPE_WEBHOOK_SECRET",
                "VIGIL_STRIPE_SECRET_KEY", "VIGIL_STRIPE_API_VERSION", "VIGIL_STRIPE_WEBHOOK_SPOOL"):
        assert key in text, key


def test_one_drainer_rule_and_the_runbook_section():
    for p in (_UNIT, _ENV):
        assert "never both" in p.read_text(), p
    rb = _RUNBOOK.read_text()
    assert "## 9b." in rb and "/webhooks/stripe" in rb and "vigil-billing-drain-stripe" in rb
    for event in ("checkout.session.completed", "checkout.session.async_payment_succeeded",
                  "checkout.session.async_payment_failed", "invoice.paid", "invoice.payment_failed"):
        assert f"`{event}`" in rb, event
    assert "VIGIL_BILLING_PROVIDER=stripe" in rb and "Adaptive Pricing off" in rb


def test_the_stripe_drain_is_an_optional_money_unit_watched_by_its_own_flag():
    spec = next(s for s in _ua.registry() if s.unit == "vigil-billing-drain-stripe.service")
    assert spec.optional and spec.enable_env == "VIGIL_STRIPE_BILLING_DRAIN_ENABLED"
    assert spec.timer == "vigil-billing-drain-stripe.timer"


def test_doctor_reds_on_a_failed_stripe_drain_with_its_own_spool_and_command(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(_ua, "default_state_dir", lambda: tmp_path / "hb")
    (tmp_path / "hb").mkdir()
    _ua.write_unit_heartbeat(tmp_path / "hb", "vigil-billing-drain-stripe.service", ok=False, now=time.time(),
                             result="exit-code", detail="quarantine standing")
    report = _doc.collect(_REPO)
    hit = [i for i in report["issues"] if "MONEY/pipeline drain" in i and "vigil-billing-drain-stripe.service" in i]
    assert hit and report["ok"] is False, report["issues"]
    assert "PAID and has NOT been credited" in hit[0] and "~/.sigil/stripe-billing-spool" in hit[0]
    assert "--provider stripe" in hit[0]


# ---- the Flutterwave lane's operating guards hold on the Stripe twin (audit E2) ---------------------------------------
def _lock_wait_s() -> float:
    cli_src = (_REPO / "apps" / "sigil" / "sigil" / "cli.py").read_text(encoding="utf-8")
    return float(re.search(r"^_BILLING_LOCK_WAIT_S = ([0-9.]+)", cli_src, re.M).group(1))


def test_a_hung_stripe_pass_is_bounded_but_never_below_a_slow_legitimate_pass():
    """Type=oneshot has no start timeout by default: a WEDGED pass would hold the single-drainer lock (and the timer)
    for ever. The bound sits well above a slow pass (an O(spine) fold per mint plus bounded re-fetches)."""
    d = _directives(_UNIT)
    limit = [ln for ln in d if ln.startswith("TimeoutStartSec=")]
    assert len(limit) == 1 and 1800 <= int(limit[0].split("=", 1)[1]) <= 3600, limit
    egress = (_REPO / "apps" / "sigil" / "sigil" / "governor" / "stripe_egress.py").read_text(encoding="utf-8")
    per_call = float(re.search(r"^_DEFAULT_TIMEOUT_S = ([0-9.]+)", egress, re.M).group(1))
    assert int(limit[0].split("=", 1)[1]) >= 10 * (_lock_wait_s() + 4 * per_call)
    assert f"{int(_lock_wait_s())} s" in _UNIT.read_text()                    # the lock wait the unit states


def _run_exec_stop_post(tmp_path, program: str, **extra_env) -> None:
    """RUN the unit's real ExecStopPost command line (specifiers and `$$` expanded the way systemd does), with the
    offense venv's `vigil` replaced by `program`."""
    post = [ln.split("=", 1)[1] for ln in _directives(_UNIT) if ln.startswith("ExecStopPost=")]
    assert len(post) == 1
    fake_home = tmp_path / "h"
    exe = fake_home / "vigil" / ".venv-offense" / "bin" / "vigil"
    exe.parent.mkdir(parents=True)
    exe.write_text(program)
    exe.chmod(0o755)
    line = post[0].replace("%h", str(fake_home)).replace("%n", "vigil-billing-drain-stripe.service").replace("$$", "$")
    env = dict(os.environ, HOME=str(fake_home), VIGIL_ALERT_STATE_DIR=str(tmp_path / "hb"), **extra_env)
    subprocess.run(shlex.split(line), env=env, check=True, timeout=60)


def test_the_stripe_heartbeat_hook_never_sees_the_payment_secrets(tmp_path):
    seen = tmp_path / "seen.env"
    _run_exec_stop_post(tmp_path, f'#!/bin/sh\necho "argv=$*" > {shlex.quote(str(seen))}\n'
                                  f'env >> {shlex.quote(str(seen))}\n',
                        VIGIL_STRIPE_WEBHOOK_SECRET="dummy-stripe-whsec", VIGIL_STRIPE_SECRET_KEY="dummy-stripe-key",
                        SOME_OPERATOR_TOKEN="dummy-operator-token", SERVICE_RESULT="success")
    got = seen.read_text()
    assert "argv=unit-heartbeat vigil-billing-drain-stripe.service" in got
    names = {ln.split("=", 1)[0] for ln in got.splitlines()[1:] if "=" in ln}
    assert {"SERVICE_RESULT", "VIGIL_ALERT_STATE_DIR", "HOME"} <= names
    assert names <= {"SERVICE_RESULT", "VIGIL_ALERT_STATE_DIR", "HOME", "PWD", "SHLVL", "_"}, names
    for secret in ("dummy-stripe-whsec", "dummy-stripe-key", "dummy-operator-token"):
        assert secret not in got


@pytest.mark.parametrize("result,ok", [("exit-code", False), ("timeout", False), ("success", True)])
def test_the_allow_listed_stripe_heartbeat_still_records_the_result(tmp_path, result, ok):
    paths = [str(_REPO / "integration"), str(_REPO / "packages" / "core" / "vigil_core")]
    program = (f"#!{sys.executable}\nimport sys\nsys.path[:0] = {paths!r}\n"
               f"from vigil_integration.cli import main\nsys.exit(main(sys.argv[1:]))\n")
    beat = tmp_path / "hb" / "vigil-billing-drain-stripe.service.hb.json"
    _run_exec_stop_post(tmp_path, program, SERVICE_RESULT=result, VIGIL_STRIPE_SECRET_KEY="dummy-stripe-key")
    rec = json.loads(beat.read_text())
    assert rec["ok"] is ok and rec["result"] == result


def test_the_stripe_env_example_requires_sigil_home_and_names_the_spool_rules():
    env = _ENV.read_text()
    assert re.search(r"^# SIGIL_HOME=", env, re.M) and "REQUIRED, ALWAYS" in env
    assert "REQUIRED once SIGIL_HOME is moved" in env and "refuses (the unit goes FAILED) a spool" in env
    rb = _RUNBOOK.read_text()
    assert "**Set\n   `SIGIL_HOME` in `~/.config/vigil/billing-drain-stripe.env`**" in rb


def test_a_failed_stripe_drain_is_intake_safe_and_its_remedy_is_its_own_unit(tmp_path, monkeypatch):
    """The Stripe lane's drain alarm is under-credit only, like the Flutterwave one: listed under
    `intake_safe_issues` (a scripted bring-up keeps the proxy that spools /webhooks/stripe up), and its remediation
    names the Stripe unit, its timer and its journal — never the Flutterwave lane's."""
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(_ua, "default_state_dir", lambda: tmp_path / "hb")
    (tmp_path / "hb").mkdir()
    _ua.write_unit_heartbeat(tmp_path / "hb", "vigil-billing-drain-stripe.service", ok=False, now=time.time(),
                             result="exit-code", detail="quarantine standing")
    report = _doc.collect(_REPO)
    hit = [i for i in report["issues"] if "vigil-billing-drain-stripe.service" in i]
    assert len(hit) == 1 and report["intake_safe_issues"] == hit
    msg = hit[0]
    assert "systemctl --user start vigil-billing-drain-stripe.service" in msg
    assert "enable --now vigil-billing-drain-stripe.timer" in msg and "journalctl --user -u vigil-billing-drain-stripe -e" in msg
    assert "VIGIL_STRIPE_WEBHOOK_SPOOL" in msg and "Only the unit's own run" in msg and "Keep the proxy UP" in msg
    assert "vigil-billing-drain.timer" not in msg and "VIGIL_BILLING_WEBHOOK_SPOOL" not in msg
