"""Stripe parity ST-10: the Stripe lane of the money-IN drain is automated and observable like the Flutterwave one.

Structural invariants of `vigil-billing-drain-stripe.{service,timer,env.example}` (a systemd smoke test cannot run
on a PR runner), the rule that the shipped env example carries no secret value, the runbook section, and the
doctor's MONEY gate naming the Stripe lane's own spool and command when its drain fails.
"""
from __future__ import annotations

import re
import time
from pathlib import Path

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
    assert any(ln.startswith("ExecStopPost=") and "unit-heartbeat %n" in ln for ln in d)
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
