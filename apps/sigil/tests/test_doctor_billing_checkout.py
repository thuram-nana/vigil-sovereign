"""Follow-up #7 — the doctor preflight that closes the "checkout on, but the drain that credits those payments
isn't configured ⇒ a payment taken that can never be credited" footgun.

``cli._posture_billing_checkout`` reports:
  * OK when customer checkout is OFF (nothing takes a payment), or when it is ON AND the resolved processor is
    fully provisioned (every checkout precondition) AND its money-IN drain is enabled;
  * a LOUD (required) failure when checkout is ON but ``config.billing_provider()`` is None (bogus selector), a
    checkout precondition is unmet, or the crediting drain is off — the message NAMES the missing env var(s) and
    NEVER prints a secret value.

The processor is resolved ONLY through ``config.billing_provider()`` — the SAME resolver the checkout edge
(``provision._checkout_provider``) and the bare money-IN drain use — so doctor and checkout agree by construction.
A parity test cross-checks the posture's checkout-precondition verdict against the REAL provision predicate (no
drift). Pure-Python, offline; no secret is ever read beyond a presence check.
"""
from __future__ import annotations

import tempfile

import pytest

from sigil import cli, config

# the REAL provisioner the checkout edge uses — to cross-check the doctor against provision (no drift).
from test_customer_checkout import _provisioner

# Secret ENV VARs carry SENTINEL canaries: no message may ever echo one of these VALUES (only the var NAME).
_CANARY = {
    "VIGIL_STRIPE_WEBHOOK_SECRET": "whsec_" + "LEAKCANARYwh0001",
    "VIGIL_STRIPE_SECRET_KEY": "sk_test_" + "LEAKCANARYsk0002notreal",   # recognisable (sk_test_) ⇒ a valid mode
    "VIGIL_BILLING_WEBHOOK_SECRET": "flw-whsec-" + "LEAKCANARYfw0003",
    "VIGIL_FLW_SECRET_KEY": "FLWSECK_TEST-" + "LEAKCANARYfk0004",
}
_ALL_VARS = ("VIGIL_CUSTOMER_CHECKOUT_ENABLED", "VIGIL_BILLING_PROVIDER", "VIGIL_BILLING_ENABLE_STRIPE",
             "VIGIL_STRIPE_WEBHOOK_SECRET", "VIGIL_STRIPE_SECRET_KEY", "VIGIL_STRIPE_API_VERSION",
             "VIGIL_STRIPE_BILLING_DRAIN_ENABLED", "VIGIL_BILLING_WEBHOOK_SECRET", "VIGIL_FLW_SECRET_KEY",
             "VIGIL_BILLING_DRAIN_ENABLED")
_STRIPE_CHECKOUT_PRECONDITIONS = ("VIGIL_BILLING_ENABLE_STRIPE", "VIGIL_STRIPE_WEBHOOK_SECRET",
                                  "VIGIL_STRIPE_SECRET_KEY", "VIGIL_STRIPE_API_VERSION")


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    # a private tmp home for the catalog the provision predicate reads; a clean slate for every billing var.
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    for k in _ALL_VARS:
        monkeypatch.delenv(k, raising=False)


def _stripe_full(monkeypatch):
    """Checkout ON, Stripe selected, every checkout precondition met AND the Stripe drain enabled."""
    monkeypatch.setenv("VIGIL_CUSTOMER_CHECKOUT_ENABLED", "1")
    monkeypatch.setenv("VIGIL_BILLING_PROVIDER", "stripe")
    monkeypatch.setenv("VIGIL_BILLING_ENABLE_STRIPE", "1")
    monkeypatch.setenv("VIGIL_STRIPE_WEBHOOK_SECRET", _CANARY["VIGIL_STRIPE_WEBHOOK_SECRET"])
    monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", _CANARY["VIGIL_STRIPE_SECRET_KEY"])
    monkeypatch.setenv("VIGIL_STRIPE_API_VERSION", "2000-01-01")
    monkeypatch.setenv("VIGIL_STRIPE_BILLING_DRAIN_ENABLED", "1")


def _flw_full(monkeypatch):
    """Checkout ON, Flutterwave selected, every checkout precondition met AND the Flutterwave drain enabled."""
    monkeypatch.setenv("VIGIL_CUSTOMER_CHECKOUT_ENABLED", "1")
    monkeypatch.setenv("VIGIL_BILLING_PROVIDER", "flutterwave")
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", _CANARY["VIGIL_BILLING_WEBHOOK_SECRET"])
    monkeypatch.setenv("VIGIL_FLW_SECRET_KEY", _CANARY["VIGIL_FLW_SECRET_KEY"])
    monkeypatch.setenv("VIGIL_BILLING_DRAIN_ENABLED", "1")


# ---- checkout OFF — the default: a green line that reads no provider/secret env --------------------------------------
def test_checkout_off_is_a_green_off_line_reading_no_secret(monkeypatch):
    # even with a secret present in the environment, OFF short-circuits before any provider/secret is consulted.
    monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", _CANARY["VIGIL_STRIPE_SECRET_KEY"])
    ok, state, detail = cli._posture_billing_checkout()
    assert ok is True and state == "OFF"
    assert "VIGIL_CUSTOMER_CHECKOUT_ENABLED" in detail
    assert _CANARY["VIGIL_STRIPE_SECRET_KEY"] not in detail and "VIGIL_STRIPE_SECRET_KEY" not in detail


# ---- Stripe lane ----------------------------------------------------------------------------------------------------
def test_stripe_fully_provisioned_with_drain_on_is_ok(monkeypatch):
    _stripe_full(monkeypatch)
    ok, state, detail = cli._posture_billing_checkout()
    assert ok is True and state == "OK" and "stripe" in detail


@pytest.mark.parametrize("missing", _STRIPE_CHECKOUT_PRECONDITIONS)
def test_stripe_missing_a_checkout_precondition_is_a_loud_failure_naming_the_var(monkeypatch, missing):
    _stripe_full(monkeypatch)
    monkeypatch.delenv(missing, raising=False)
    ok, state, detail = cli._posture_billing_checkout()
    assert ok is False and state == "UNPROVISIONED"
    assert missing in detail                              # the operator is told EXACTLY which var to set


def test_stripe_with_an_unrecognisable_key_is_a_loud_failure(monkeypatch):
    _stripe_full(monkeypatch)
    monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", "dummy-not-a-stripe-key")   # set, but not sk_/rk_ live|test
    ok, state, detail = cli._posture_billing_checkout()
    assert ok is False and state == "UNPROVISIONED"
    assert "VIGIL_STRIPE_SECRET_KEY" in detail and "recognisable" in detail


def test_stripe_provisioned_but_drain_off_is_the_footgun_caught(monkeypatch):
    # THE gap this slice closes: checkout provisioning is complete (provision would hand checkout a live provider)
    # yet the money-IN drain that CREDITS the payment is off — a customer could pay and never be credited.
    _stripe_full(monkeypatch)
    monkeypatch.delenv("VIGIL_STRIPE_BILLING_DRAIN_ENABLED", raising=False)
    ok, state, detail = cli._posture_billing_checkout()
    assert ok is False and state == "UNPROVISIONED"
    assert "VIGIL_STRIPE_BILLING_DRAIN_ENABLED" in detail
    # cross-check: provision itself is satisfied here (the posture is STRICTLY stronger than checkout provisioning).
    p = _provisioner()[0]
    assert p._checkout_provider() is not None


# ---- Flutterwave lane -----------------------------------------------------------------------------------------------
def test_flutterwave_fully_provisioned_with_drain_on_is_ok(monkeypatch):
    _flw_full(monkeypatch)
    ok, state, detail = cli._posture_billing_checkout()
    assert ok is True and state == "OK" and "flutterwave" in detail


@pytest.mark.parametrize("missing", ("VIGIL_BILLING_WEBHOOK_SECRET", "VIGIL_FLW_SECRET_KEY",
                                     "VIGIL_BILLING_DRAIN_ENABLED"))
def test_flutterwave_missing_a_precondition_or_drain_is_a_loud_failure_naming_the_var(monkeypatch, missing):
    _flw_full(monkeypatch)
    monkeypatch.delenv(missing, raising=False)
    ok, state, detail = cli._posture_billing_checkout()
    assert ok is False and state == "UNPROVISIONED" and missing in detail


# ---- bogus selector -------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("value", ("paypal", "none", "square", "stripe;flutterwave"))
def test_a_bogus_provider_with_checkout_on_is_a_loud_misconfiguration(monkeypatch, value):
    monkeypatch.setenv("VIGIL_CUSTOMER_CHECKOUT_ENABLED", "1")
    monkeypatch.setenv("VIGIL_BILLING_PROVIDER", value)
    assert config.billing_provider() is None             # the shared resolver refuses it
    ok, state, detail = cli._posture_billing_checkout()
    assert ok is False and state == "MISCONFIGURED" and "VIGIL_BILLING_PROVIDER" in detail


# ---- the selection is config.billing_provider(), not a hardcoded lane ------------------------------------------------
def test_the_posture_resolves_through_billing_provider_not_a_hardcoded_lane(monkeypatch):
    # Flutterwave selected + fully provisioned, with NO Stripe secrets at all: a posture that hardcoded the Stripe
    # lane would wrongly report UNPROVISIONED. OK here proves it follows config.billing_provider().
    _flw_full(monkeypatch)
    assert config.billing_provider() == "flutterwave"
    ok, state, _detail = cli._posture_billing_checkout()
    assert ok is True and state == "OK"


# ---- no secret VALUE ever appears in any message --------------------------------------------------------------------
def test_no_secret_value_ever_appears_in_any_message(monkeypatch):
    seen: "list[str]" = []

    def _capture():
        _ok, state, detail = cli._posture_billing_checkout()
        seen.append(state + " " + detail)

    _stripe_full(monkeypatch); _capture()                       # OK
    for miss in (*_STRIPE_CHECKOUT_PRECONDITIONS, "VIGIL_STRIPE_BILLING_DRAIN_ENABLED"):
        _stripe_full(monkeypatch); monkeypatch.delenv(miss, raising=False); _capture()
    _stripe_full(monkeypatch); monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", "dummy-not-a-stripe-key"); _capture()
    _flw_full(monkeypatch); _capture()                          # OK
    for miss in ("VIGIL_BILLING_WEBHOOK_SECRET", "VIGIL_FLW_SECRET_KEY", "VIGIL_BILLING_DRAIN_ENABLED"):
        _flw_full(monkeypatch); monkeypatch.delenv(miss, raising=False); _capture()

    blob = "\n".join(seen)
    assert seen, "no messages captured"
    for var, value in _CANARY.items():
        assert value not in blob, f"the message leaked the VALUE of {var}"


# ---- parity with the REAL provision predicate (no drift) ------------------------------------------------------------
def test_posture_checkout_verdict_matches_provision_for_every_stripe_precondition(monkeypatch):
    # With the drain flag held ON (so only the CHECKOUT preconditions move), the posture is red for exactly the
    # env states in which provision._checkout_provider() returns None — the two can never drift.
    def _provision_ok() -> bool:
        return _provisioner()[0]._checkout_provider() is not None

    def _posture_ok() -> bool:
        return cli._posture_billing_checkout()[0]

    _stripe_full(monkeypatch)
    assert _provision_ok() is True and _posture_ok() is True
    for missing in _STRIPE_CHECKOUT_PRECONDITIONS:
        _stripe_full(monkeypatch)
        monkeypatch.delenv(missing, raising=False)
        assert _provision_ok() is False, f"provision still provisions without {missing}"
        assert _posture_ok() is False, f"the posture missed the missing {missing}"


# ---- wired into the shared doctor report as a REQUIRED check --------------------------------------------------------
def test_wired_into_sigil_doctor_report_as_a_required_check(monkeypatch):
    rep = cli.sigil_doctor_report()
    bc = next(c for c in rep["checks"] if c["id"] == "billing_checkout")
    assert bc["required"] is True and bc["ok"] is True and bc["state"] == "OFF"   # checkout off (default)
    # when checkout is on but the drain is off, the SAME wired check turns red (and, being required, would flip the
    # doctor's exit) and carries the posture's own message.
    _stripe_full(monkeypatch)
    monkeypatch.delenv("VIGIL_STRIPE_BILLING_DRAIN_ENABLED", raising=False)
    bc2 = next(c for c in cli.sigil_doctor_report()["checks"] if c["id"] == "billing_checkout")
    assert bc2["required"] is True and bc2["ok"] is False and bc2["state"] == "UNPROVISIONED"
