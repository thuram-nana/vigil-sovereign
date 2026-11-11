"""The one-shot bring-up's doctor gate vs a money-IN alarm.

`tools/oneshot-bringup/vigil-oneshot.sh` refuses to start `vigil-command` (the proxy that serves
`/webhooks/billing`) on a red `vigil doctor`. A FAILED billing drain is a hard doctor issue — so the alarm that says
"a customer paid and is not credited yet" also blocked a scripted restart of payment INTAKE, where every webhook
that arrives while the proxy is down is simply lost. Accepting + durably spooling a webhook is always safe; the
script must start the UI on a money-IN-only red, and must still refuse everything that launches or spends.

These EXECUTE the script's real functions (cut out of the shipped file, run under bash with the phases stubbed)
against a REAL `doctor.collect()` report — no re-implementation of the gate in the test.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

from vigil_integration import doctor as _doc
from vigil_integration import unit_alerts as _ua

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
MODE=full; REPO=/nonexistent
eval "$(sed -n '/^doctor_red_is_money_in_only(){/,/^}/p; /^phase_doctor_gate(){/,/^}/p; /^main(){/,/^}/p' "$SCRIPT")"
main
"""


def _report(tmp_path, monkeypatch, *units) -> dict:
    """A REAL doctor report on a host where exactly `units` have a fresh FAILED heartbeat. The sandbox's own
    unrelated issues (no venvs built here, …) are dropped so the report is red on the drains under test only."""
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(_ua, "default_state_dir", lambda: tmp_path / "hb")
    (tmp_path / "hb").mkdir(exist_ok=True)
    for u in units:
        _ua.write_unit_heartbeat(tmp_path / "hb", u, ok=False, now=time.time(), result="exit-code",
                                 detail="quarantine standing")
    report = _doc.collect(_REPO)
    report["issues"] = [i for i in report["issues"] if "MONEY/pipeline drain" in i]
    assert len(report["issues"]) == len(units)
    return report


def _oneshot(tmp_path, doctor_stdout: str, doctor_rc: int) -> "tuple[int, list[str], str]":
    out_file = tmp_path / "doctor.out"
    out_file.write_text(doctor_stdout + "\n", encoding="utf-8")
    vigil = tmp_path / "vigil"
    vigil.write_text(f'#!/bin/sh\ncat "{out_file}"\nexit {doctor_rc}\n')
    vigil.chmod(0o755)
    r = subprocess.run(["bash", "-c", _HARNESS], capture_output=True, text=True, timeout=120,
                       env={"PATH": "/usr/bin:/bin", "SCRIPT": str(_SCRIPT), "VIGIL": str(vigil),
                            "OFFPY": sys.executable})
    phases = [ln.split(":", 1)[1] for ln in r.stdout.splitlines() if ln.startswith("PHASE:")]
    return r.returncode, phases, r.stdout + r.stderr


def test_a_money_in_only_red_still_starts_payment_intake_and_refuses_everything_after_it(tmp_path, monkeypatch):
    report = _report(tmp_path, monkeypatch, "vigil-billing-drain.service")
    rc, phases, text = _oneshot(tmp_path, json.dumps(report), 1)
    assert phases == ["preflight", "bootstrap", "controls", "service_env", "ui"], text   # the UI IS started …
    assert rc != 0 and "meridian" not in phases and "acceptance" not in phases           # … nothing launches
    assert "payment intake restored" in text and "NOT proven green" in text              # and it is not "green"


def test_any_other_red_still_refuses_to_start_the_ui(tmp_path, monkeypatch):
    # money-OUT / results drain red (not a money-IN alarm), alone or next to a money-IN alarm
    for n, units in enumerate((("vigil-settle-drain.service",),
                               ("vigil-billing-drain.service", "vigil-finding-drain.service"))):
        case = tmp_path / str(n)
        case.mkdir()
        report = _report(case, monkeypatch, *units)
        rc, phases, text = _oneshot(case, json.dumps(report), 1)
        assert rc != 0 and "ui" not in phases and "vigil doctor REFUSES" in text, (units, text)


def test_a_red_the_script_cannot_classify_refuses_to_start_the_ui(tmp_path, monkeypatch):
    report = _report(tmp_path, monkeypatch, "vigil-billing-drain.service")
    claimed_only = dict(report, issues=[])                       # exit 1 with no issue listed: not provably safe
    foreign = dict(report, money_in_alarms=["some other text"])  # the issue is not one doctor classified
    for stdout in ("not json at all", "", json.dumps(claimed_only), json.dumps(foreign),
                   json.dumps({k: v for k, v in report.items() if k != "money_in_alarms"})):
        rc, phases, text = _oneshot(tmp_path, stdout, 1)
        assert rc != 0 and "ui" not in phases and "vigil doctor REFUSES" in text, (stdout[:40], text)


def test_a_green_doctor_runs_every_phase(tmp_path):
    rc, phases, text = _oneshot(tmp_path, json.dumps({"ok": True, "issues": []}), 0)
    assert rc == 0, text
    assert phases == ["preflight", "bootstrap", "controls", "service_env", "ui", "meridian", "acceptance",
                      "summary"]
