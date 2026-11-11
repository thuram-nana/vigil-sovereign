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
eval "$(sed -n '/^doctor_red_is_intake_safe_only(){/,/^}/p; /^phase_doctor_gate(){/,/^}/p; /^main(){/,/^}/p' "$SCRIPT")"
main
"""


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


def _starts_intake_and_refuses_the_rest(rc, phases, text):
    assert phases == ["preflight", "bootstrap", "controls", "service_env", "ui"], text   # the UI IS started …
    assert rc != 0 and "meridian" not in phases and "acceptance" not in phases           # … nothing launches
    assert "payment intake restored" in text and "NOT proven green" in text              # and it is not "green"


def test_a_money_in_only_red_still_starts_payment_intake_and_refuses_everything_after_it(tmp_path, monkeypatch):
    report = _report(tmp_path, monkeypatch, "vigil-billing-drain.service")
    _starts_intake_and_refuses_the_rest(*_oneshot(tmp_path, json.dumps(report), 1))


def test_a_fold_cache_mismatch_only_red_still_starts_payment_intake(tmp_path, monkeypatch):
    """A recorded MISMATCH is rewritten only by a RUNNING cockpit's next audit, so refusing to start the UI on it held
    payment intake down until someone deleted the report — while a running cockpit keeps serving after one."""
    report = _report(tmp_path / "alone", monkeypatch, mismatch=True)
    _starts_intake_and_refuses_the_rest(*_oneshot(tmp_path, json.dumps(report), 1))
    both = _report(tmp_path / "both", monkeypatch, "vigil-billing-drain.service", mismatch=True)
    _starts_intake_and_refuses_the_rest(*_oneshot(tmp_path, json.dumps(both), 1))


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
