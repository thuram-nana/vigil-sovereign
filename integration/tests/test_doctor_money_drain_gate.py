"""readiness #69 MONEY gate: `vigil doctor` goes RED when a WATCHED money/pipeline drain is unhealthy.

The settle drain (settle_launch charge/refund) and the finding drain (confirmed-FACT crossing) are OPTIONAL
dead-man units — watched only once enabled or firing. So a watched one whose last run FAILED (e.g. a standing
rejected/ quarantine made it exit non-zero — MONEY-4) or that went STALE is a real nothing-lost failure, and
`doctor.collect` must raise it as a HARD issue (flips ok -> False -> `vigil doctor` exits 1), not the advisory
note a non-money unit gets. A host that never ran the drain (not enabled) keeps the old calm all-ABSENT note.

Integration leg (vigil_integration.doctor + unit_alerts, both framework-free, import only vigil_core).
"""
from __future__ import annotations

import time
from pathlib import Path

from vigil_integration import doctor as _doc
from vigil_integration import unit_alerts as _ua

_REPO = Path(_doc.__file__).resolve().parents[2]


def _fresh_failed_beat(state_dir: Path, unit: str) -> None:
    # a FRESH heartbeat whose last run FAILED (ok=false) -> unit_status classifies it FAILED (not STALE/ABSENT)
    _ua.write_unit_heartbeat(state_dir, unit, ok=False, now=time.time(), result="exit-code",
                             detail="quarantine standing")


def test_doctor_reds_on_a_failed_settle_drain(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(_ua, "default_state_dir", lambda: tmp_path / "hb")
    (tmp_path / "hb").mkdir()
    _fresh_failed_beat(tmp_path / "hb", "vigil-settle-drain.service")

    report = _doc.collect(_REPO)
    money = [i for i in report["issues"] if "MONEY/pipeline drain" in i and "vigil-settle-drain.service" in i]
    assert money, f"expected a hard MONEY-drain issue; issues={report['issues']}"
    assert report["ok"] is False
    # it is a HARD issue, not merely an advisory note
    assert not any("vigil-settle-drain.service" in n for n in report["notes"])


def test_doctor_reds_on_a_failed_finding_drain(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(_ua, "default_state_dir", lambda: tmp_path / "hb")
    (tmp_path / "hb").mkdir()
    _fresh_failed_beat(tmp_path / "hb", "vigil-finding-drain.service")

    report = _doc.collect(_REPO)
    assert any("MONEY/pipeline drain" in i and "vigil-finding-drain.service" in i for i in report["issues"]), \
        report["issues"]


def test_doctor_does_not_red_on_a_nonmoney_unit_alarm(tmp_path, monkeypatch):
    # a non-money unit (backup) failing is advisory — `vigil alerts` owns the full dead-man, not the doctor gate
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(_ua, "default_state_dir", lambda: tmp_path / "hb")
    (tmp_path / "hb").mkdir()
    _fresh_failed_beat(tmp_path / "hb", "vigil-backup.service")

    report = _doc.collect(_REPO)
    assert not any("MONEY/pipeline drain" in i for i in report["issues"]), report["issues"]
    assert any("vigil-backup.service" in n for n in report["notes"]), report["notes"]


def test_doctor_money_drain_absent_on_a_cold_host_is_not_red(tmp_path, monkeypatch):
    # no heartbeats at all -> the money drains are not watched (optional, not enabled) -> no MONEY issue
    # (the all-ABSENT branch emits one calm "alerting not enabled" note, not a per-unit hard failure)
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(_ua, "default_state_dir", lambda: tmp_path / "hb")
    (tmp_path / "hb").mkdir()

    report = _doc.collect(_REPO)
    assert not any("MONEY/pipeline drain" in i for i in report["issues"]), report["issues"]


def test_doctor_reds_on_a_failed_billing_drain_and_names_the_customer_impact(tmp_path, monkeypatch):
    """MONEY-5: the money-IN billing drain (#1055) is a money drain too — a FAILED run means a paid webhook stands
    quarantined: a customer PAID and has NOT been credited until an operator acts."""
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(_ua, "default_state_dir", lambda: tmp_path / "hb")
    (tmp_path / "hb").mkdir()
    _fresh_failed_beat(tmp_path / "hb", "vigil-billing-drain.service")

    report = _doc.collect(_REPO)
    hit = [i for i in report["issues"] if "MONEY/pipeline drain" in i and "vigil-billing-drain.service" in i]
    assert hit and report["ok"] is False, report["issues"]
    assert "PAID and has NOT been credited" in hit[0] and "rejected/" in hit[0]
    assert "charged/refunded" not in hit[0]                       # the money-OUT wording is not reused for it
    assert not any("vigil-billing-drain.service" in n for n in report["notes"])


def test_the_billing_drain_remediation_is_one_an_operator_can_follow(tmp_path, monkeypatch):
    """The remediation used to name a fixed ~/.sigil/billing-spool (wrong once SIGIL_HOME is moved) and offer a
    manual `sigil billing-drain drain` as if it cleared the alarm — it cannot: only the UNIT's own run rewrites the
    heartbeat this alarm reads."""
    home = tmp_path / "moved" / ".sigil"
    monkeypatch.setenv("SIGIL_HOME", str(home))
    monkeypatch.setattr(_ua, "default_state_dir", lambda: tmp_path / "hb")
    (tmp_path / "hb").mkdir()
    _fresh_failed_beat(tmp_path / "hb", "vigil-billing-drain.service")
    msg = next(i for i in _doc.collect(_REPO)["issues"] if "vigil-billing-drain.service" in i)
    assert str(home / "billing-spool") in msg and "VIGIL_BILLING_WEBHOOK_SPOOL" in msg
    assert "~/.sigil/billing-spool" not in msg
    assert "systemctl --user start vigil-billing-drain.service" in msg and "Only the unit's own run" in msg
    assert "Keep the proxy UP" in msg


def test_a_billing_drain_alarm_is_classified_intake_safe_and_no_other_drain_is(tmp_path, monkeypatch):
    """`intake_safe_issues` is how a scripted bring-up tells the reds that must not hold payment intake down (here:
    a paid webhook not credited yet) from every other red. The billing drain's issue is listed there — a
    settle/finding drain failure (money OUT / results) is not — and a report without one does not carry the key."""
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(_ua, "default_state_dir", lambda: tmp_path / "hb")
    (tmp_path / "hb").mkdir()
    _fresh_failed_beat(tmp_path / "hb", "vigil-settle-drain.service")
    assert "intake_safe_issues" not in _doc.collect(_REPO)

    _fresh_failed_beat(tmp_path / "hb", "vigil-billing-drain.service")
    report = _doc.collect(_REPO)
    billing = [i for i in report["issues"] if "vigil-billing-drain.service" in i]
    assert len(billing) == 1 and report["intake_safe_issues"] == billing
    assert any("vigil-settle-drain.service" in i for i in report["issues"])       # still a hard issue, unlisted


def test_the_settle_and_finding_messages_are_unchanged(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(_ua, "default_state_dir", lambda: tmp_path / "hb")
    (tmp_path / "hb").mkdir()
    _fresh_failed_beat(tmp_path / "hb", "vigil-settle-drain.service")
    report = _doc.collect(_REPO)
    msg = next(i for i in report["issues"] if "vigil-settle-drain.service" in i)
    assert "completed paid runs are not being charged/refunded" in msg and "PAID and has NOT" not in msg


def test_billing_drain_not_enabled_is_not_red(tmp_path, monkeypatch):
    # an install that takes no payments: the billing drain is OPTIONAL and unwatched -> never a MONEY issue
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("VIGIL_BILLING_DRAIN_ENABLED", raising=False)
    monkeypatch.setattr(_ua, "default_state_dir", lambda: tmp_path / "hb")
    (tmp_path / "hb").mkdir()
    _ua.write_unit_heartbeat(tmp_path / "hb", "vigil-backup.service", ok=True, now=time.time(), result="success",
                             detail="")                          # alerting IS enabled on this host
    report = _doc.collect(_REPO)
    assert not any("vigil-billing-drain.service" in i for i in report["issues"]), report["issues"]
