"""The one-shot bring-up's doctor gate vs the reds that must not hold payment intake down.

`tools/oneshot-bringup/vigil-oneshot.sh` refused to start `vigil-command` (the proxy that serves
`/webhooks/billing`) on ANY red `vigil doctor`. A FAILED billing drain is a hard doctor issue — so the alarm that says
"a customer paid and is not credited yet" also blocked a scripted restart of payment INTAKE, where every webhook
that arrives while the proxy is down is simply lost; so did a recorded fold-cache MISMATCH, which only a RUNNING
cockpit ever rewrites. Accepting + durably spooling a webhook is always safe: the script must start the UI when every
red is one doctor lists as `intake_safe_issues`, and must still refuse everything that launches or spends after it —
and must still refuse the UI itself on any other red.

These EXECUTE the script's real functions (cut out of the shipped file, run under bash with the phases stubbed)
against a REAL `doctor.collect()` report — no re-implementation of the gate in the test.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from vigil_integration import doctor as _doc
from vigil_integration import unit_alerts as _ua
from vigil_integration.uiproxy import make_proxy_server

_REPO = Path(_doc.__file__).resolve().parents[2]
_SCRIPT = _REPO / "tools" / "oneshot-bringup" / "vigil-oneshot.sh"

# Stubs for everything but the code under test; every phase other than the doctor gate just records its name.
_HARNESS = r"""
set -euo pipefail
banner(){ :; }; info(){ :; }; step(){ :; }; ok(){ :; }
warn(){ echo "WARN: $*"; }
die(){ echo "DIE: $*"; exit 1; }
export_production_env(){ :; }
for p in preflight bootstrap controls service_env ui meridian acceptance summary; do
  eval "phase_$p(){ echo PHASE:$p; }"
done
MODE=full; REPO=/nonexistent; SERVICE_ENV=/nonexistent/.vigil-live/service.env
eval "$(sed -n '/^doctor_red_is_intake_safe_only(){/,/^}/p; /^billing_intake_up(){/,/^}/p; /^phase_doctor_gate(){/,/^}/p; /^main(){/,/^}/p' "$SCRIPT")"
main
"""


@pytest.fixture()
def intake(tmp_path, monkeypatch):
    """Start a REAL UI proxy whose payment intake is "up" (route mounted + secret), "no-secret" (mounted, every
    delivery refused 503), "unmounted" (no VIGIL_BILLING_WEBHOOK_SPOOL: the path falls through), or nothing at all
    ("down"); returns the port the script's probe talks to."""
    servers = []

    def start(state: str) -> int:
        if state == "down":
            with socket.socket() as sk:
                sk.bind(("127.0.0.1", 0))
                return sk.getsockname()[1]
        if state == "no-secret":
            monkeypatch.delenv("VIGIL_BILLING_WEBHOOK_SECRET", raising=False)
            monkeypatch.delenv("VIGIL_STRIPE_WEBHOOK_SECRET", raising=False)
        else:
            monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", "dummy-verif-hash")
            monkeypatch.setenv("VIGIL_STRIPE_WEBHOOK_SECRET", "whsec_" + "dummy")
        ui = tmp_path / f"ui-{state}"
        ui.mkdir()
        # "stripe-up": only the Stripe lane's /webhooks/stripe is mounted; "both-up": both lanes are
        srv = make_proxy_server("127.0.0.1", 0, ui, webhook_billing_spool_dir=(
            None if state in ("unmounted", "stripe-up") else str(tmp_path / f"spool-{state}")),
            webhook_stripe_spool_dir=(str(tmp_path / f"stripe-spool-{state}")
                                      if state in ("stripe-up", "both-up", "no-secret") else None))
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        servers.append(srv)
        return srv.server_address[1]

    yield start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def _report(tmp_path, monkeypatch, *units, mismatch: bool = False, posture: bool = False) -> dict:
    """A REAL doctor report on a host where exactly `units` have a fresh FAILED heartbeat (with `mismatch`, the
    cockpit's last fold-cache audit recorded a MISMATCH; with `posture`, the production gate is armed on this bare
    sandbox, so its controls are UNMET). The sandbox's own unrelated issues (no venvs built here, …) are dropped so
    the report is red on the cases under test only."""
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    if posture:
        monkeypatch.setenv("VIGIL_POSTURE", "production")
    else:
        monkeypatch.delenv("VIGIL_POSTURE", raising=False)
    monkeypatch.setenv("SIGIL_HOME", str(home))
    monkeypatch.setattr(_ua, "default_state_dir", lambda: tmp_path / "hb")
    (tmp_path / "hb").mkdir(exist_ok=True)
    for u in units:
        _ua.write_unit_heartbeat(tmp_path / "hb", u, ok=False, now=time.time(), result="exit-code",
                                 detail="quarantine standing")
    if mismatch:
        (home / "fold_cache_audit.json").write_text(json.dumps(
            {"ok": False, "ts": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()), "pid": 4242,
             "interval_s": 21600.0, "folds": [{"fold": "governor.wallet", "status": "MISMATCH", "seq": 7,
                                               "difference": "state.granted"}]}))
    report = _doc.collect(_REPO)
    report["issues"] = [i for i in report["issues"] if "MONEY/pipeline drain" in i or "fold cache MISMATCH" in i
                        or (posture and i.startswith("PRODUCTION posture"))]
    assert (len(report["issues"]) > len(units) + int(mismatch)) if posture else \
        (len(report["issues"]) == len(units) + int(mismatch))
    return report


def _oneshot(tmp_path, doctor_stdout: str, doctor_rc: int, ui_port: int = 9) -> "tuple[int, list[str], str]":
    out_file = tmp_path / "doctor.out"
    out_file.write_text(doctor_stdout + "\n", encoding="utf-8")
    vigil = tmp_path / "vigil"
    vigil.write_text(f'#!/bin/sh\ncat "{out_file}"\nexit {doctor_rc}\n')
    vigil.chmod(0o755)
    r = subprocess.run(["bash", "-c", _HARNESS], capture_output=True, text=True, timeout=120,
                       env={"PATH": "/usr/bin:/bin", "SCRIPT": str(_SCRIPT), "VIGIL": str(vigil),
                            "OFFPY": sys.executable, "UI_PORT": str(ui_port)})
    phases = [ln.split(":", 1)[1] for ln in r.stdout.splitlines() if ln.startswith("PHASE:")]
    return r.returncode, phases, r.stdout + r.stderr


def _starts_intake_and_refuses_the_rest(rc, phases, text):
    assert phases == ["preflight", "bootstrap", "controls", "service_env", "ui"], text   # the UI IS started …
    assert rc != 0 and "meridian" not in phases and "acceptance" not in phases           # … nothing launches
    assert "payment intake restored" in text and "NOT proven green" in text              # and it is not "green"


def test_a_money_in_only_red_still_starts_payment_intake_and_refuses_everything_after_it(tmp_path, monkeypatch,
                                                                                          intake):
    report = _report(tmp_path, monkeypatch, "vigil-billing-drain.service")
    _starts_intake_and_refuses_the_rest(*_oneshot(tmp_path, json.dumps(report), 1, intake("up")))


@pytest.mark.parametrize("state,routes", [("up", "/webhooks/billing"), ("stripe-up", "/webhooks/stripe"),
                                          ("both-up", "/webhooks/billing and /webhooks/stripe")])
@pytest.mark.parametrize("unit", ["vigil-billing-drain.service", "vigil-billing-drain-stripe.service"])
def test_either_lanes_drain_alarm_starts_intake_and_names_the_routes_really_served(tmp_path, monkeypatch, intake,
                                                                                  unit, state, routes):
    """The Stripe lane's money-IN drain alarm is intake-safe like the Flutterwave one, and the intake claim names
    exactly the payment-webhook routes the started proxy answers on (whichever processor lane is mounted)."""
    report = _report(tmp_path, monkeypatch, unit)
    assert report["intake_safe_issues"] == report["issues"]
    rc, phases, text = _oneshot(tmp_path, json.dumps(report), 1, intake(state))
    _starts_intake_and_refuses_the_rest(rc, phases, text)
    assert f"serves {routes} (payment intake restored)" in text, text


def test_a_fold_cache_mismatch_only_red_still_starts_payment_intake(tmp_path, monkeypatch, intake):
    """A recorded MISMATCH is rewritten only by a RUNNING cockpit's next audit, so refusing to start the UI on it held
    payment intake down until someone deleted the report — while a running cockpit keeps serving after one."""
    port = intake("up")
    report = _report(tmp_path / "alone", monkeypatch, mismatch=True)
    _starts_intake_and_refuses_the_rest(*_oneshot(tmp_path, json.dumps(report), 1, port))
    both = _report(tmp_path / "both", monkeypatch, "vigil-billing-drain.service", mismatch=True)
    _starts_intake_and_refuses_the_rest(*_oneshot(tmp_path, json.dumps(both), 1, port))


@pytest.mark.parametrize("state", ["unmounted", "no-secret", "down"])
def test_the_intake_safe_path_never_claims_intake_it_cannot_see(tmp_path, monkeypatch, intake, state):
    """The UI is started for payment intake's sake — but the claim "payment intake restored" is made only when the
    started proxy really ACCEPTS webhooks (its route answers with its own verif-hash refusal). A proxy without the
    route, one with no secret (every delivery refused), or none answering: the script says intake is NOT up."""
    report = _report(tmp_path, monkeypatch, "vigil-billing-drain.service")
    rc, phases, text = _oneshot(tmp_path, json.dumps(report), 1, intake(state))
    assert phases == ["preflight", "bootstrap", "controls", "service_env", "ui"] and rc != 0, text
    assert "payment intake is NOT up" in text and "restored" not in text and "NOT proven green" in text


def test_reseeding_service_env_keeps_the_operators_payment_intake_settings(tmp_path):
    """`phase_service_env` rebuilds the UI unit's env file from a fixed list on EVERY run. The proxy mounts
    /webhooks/billing only when VIGIL_BILLING_WEBHOOK_SPOOL (+ its secret) is in that environment, so a rebuild that
    dropped them took payment intake down at the very restart the intake-safe path exists for. They are carried
    over (and only they: the script's own keys are rewritten), the secret never printed."""
    live = tmp_path / ".vigil-live"
    live.mkdir()
    svc = live / "service.env"
    svc.write_text("VIGIL_POSTURE=dev\nSTALE_OPERATOR_KEY=1\nVIGIL_BILLING_WEBHOOK_SPOOL=/srv/spool\n"
                   "VIGIL_BILLING_WEBHOOK_SECRET=dummy-verif-hash\n# VIGIL_BILLING_WEBHOOK_SPOOL=/commented/out\n"
                   "VIGIL_STRIPE_WEBHOOK_SPOOL=/srv/stripe-spool\nVIGIL_STRIPE_WEBHOOK_SECRET=dummy-whsec\n")
    harness = r"""
set -euo pipefail
banner(){ :; }; ok(){ echo "OK: $*"; }
eval "$(sed -n '/^phase_service_env(){/,/^}/p' "$SCRIPT")"
phase_service_env
"""
    env = {"PATH": "/usr/bin:/bin", "SCRIPT": str(_SCRIPT), "REPO": str(tmp_path), "SERVICE_ENV": str(svc),
           "VIGIL": "/v/bin/vigil", "CRUCIBLE_ROOT": "/c", "SIGIL_HOME": "/h", "SOVEREIGNTY_TIER": "t",
           "SLUG": "s", "VIGIL_WITNESS_ROSTER": "r", "CRUCIBLE_ANTHROPIC_MODEL": "dummy", "ANTHROPIC_API_KEY": "x"}
    r = subprocess.run(["bash", "-c", harness], capture_output=True, text=True, timeout=60, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    lines = svc.read_text().splitlines()
    assert "VIGIL_BILLING_WEBHOOK_SPOOL=/srv/spool" in lines and "VIGIL_BILLING_WEBHOOK_SECRET=dummy-verif-hash" in lines
    assert "VIGIL_POSTURE=production" in lines and "VIGIL_POSTURE=dev" not in lines        # the script's keys rewritten
    assert "STALE_OPERATOR_KEY=1" not in lines and "# VIGIL_BILLING_WEBHOOK_SPOOL=/commented/out" not in lines
    assert sum(ln.startswith("VIGIL_BILLING_WEBHOOK_") for ln in lines) == 2
    # the Stripe lane's /webhooks/stripe settings are the operator's too: carried over the same way
    assert "VIGIL_STRIPE_WEBHOOK_SPOOL=/srv/stripe-spool" in lines and "VIGIL_STRIPE_WEBHOOK_SECRET=dummy-whsec" in lines
    assert sum(ln.startswith("VIGIL_STRIPE_WEBHOOK_") for ln in lines) == 2
    assert "dummy-verif-hash" not in r.stdout + r.stderr and "dummy-whsec" not in r.stdout + r.stderr
    assert oct(os.stat(svc).st_mode & 0o777) == "0o600"
    # a first run (no file yet) still seeds it, with no intake settings to carry
    svc.unlink()
    r = subprocess.run(["bash", "-c", harness], capture_output=True, text=True, timeout=60, env=env)
    assert r.returncode == 0 and not any(ln.startswith(("VIGIL_BILLING", "VIGIL_STRIPE"))
                                         for ln in svc.read_text().splitlines())


def test_any_other_red_still_refuses_to_start_the_ui(tmp_path, monkeypatch):
    # a money-OUT / results drain red (spend-side: completed paid runs not charged/refunded), alone or next to the
    # intake-safe reds — the UI (whose cockpit launches paid runs) is NOT started
    for n, (units, mismatch) in enumerate(((("vigil-settle-drain.service",), False),
                                           (("vigil-billing-drain.service", "vigil-finding-drain.service"), False),
                                           (("vigil-settle-drain.service",), True))):
        case = tmp_path / str(n)
        case.mkdir()
        report = _report(case, monkeypatch, *units, mismatch=mismatch)
        rc, phases, text = _oneshot(case, json.dumps(report), 1)
        assert rc != 0 and "ui" not in phases and "vigil doctor REFUSES" in text, (units, text)
    # a production-posture control UNMET (a REAL armed gate on this bare sandbox) next to the intake-safe reds
    report = _report(tmp_path / "posture", monkeypatch, "vigil-billing-drain.service", mismatch=True, posture=True)
    rc, phases, text = _oneshot(tmp_path / "posture", json.dumps(report), 1)
    assert rc != 0 and "ui" not in phases and "vigil doctor REFUSES" in text and "(none parsed)" not in text, text


def test_a_red_the_script_cannot_classify_refuses_to_start_the_ui(tmp_path, monkeypatch):
    report = _report(tmp_path, monkeypatch, "vigil-billing-drain.service")
    claimed_only = dict(report, issues=[])                          # exit 1 with no issue listed: not provably safe
    foreign = dict(report, intake_safe_issues=["some other text"])  # the issue is not one doctor classified
    as_text = dict(report, intake_safe_issues=" ".join(report["issues"]))   # not a list: no substring matching
    for stdout in ("not json at all", "", json.dumps(claimed_only), json.dumps(foreign), json.dumps(as_text),
                   json.dumps({k: v for k, v in report.items() if k != "intake_safe_issues"})):
        rc, phases, text = _oneshot(tmp_path, stdout, 1)
        assert rc != 0 and "ui" not in phases and "vigil doctor REFUSES" in text, (stdout[:40], text)


def test_a_green_doctor_runs_every_phase(tmp_path):
    rc, phases, text = _oneshot(tmp_path, json.dumps({"ok": True, "issues": []}), 0)
    assert rc == 0, text
    assert phases == ["preflight", "bootstrap", "controls", "service_env", "ui", "meridian", "acceptance",
                      "summary"]
