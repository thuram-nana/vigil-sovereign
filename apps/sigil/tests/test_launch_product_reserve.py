"""EC-7b — the purchasable link: launch_reserve maps a tiered PRODUCT choice to the owner catalog's units.

Money doctrine: the customer names a PRODUCT (``product_id``), NEVER an amount; the units it reserves come
from the OWNER CATALOG (``catalog.launch_product``), exactly as ``price_id`` maps to credits. An unknown /
not-offered product_id is refused FAIL-CLOSED; no product_id keeps the default units (byte-identical to
pre-EC-7b). These pin the units-resolution logic by capturing the ``units`` arg launch_reserve passes to
``LaunchGate.reserve_launch`` (the admit + full launch chain are exercised by their own tests).

Mutation-verify targets (each neuter reds a NAMED test):
  * drop the product->units mapping (always config.LAUNCH_UNITS)  -> test_deep_product_reserves_its_catalog_units
  * drop the unknown-product refusal (fall through to default)    -> test_unknown_product_is_refused_fail_closed
  * reach reserve with a product_id while EC-7 is OFF             -> test_product_while_flag_off_is_refused
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor.customers import CustomerRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import ProvisionDenied, Provisioner

OWNER = generate_keypair()
OP = OWNER.public_key_b64


def _prov(monkeypatch):
    """A real Provisioner with a member admin. admit_customer is forced True so the test exercises the
    UNITS-RESOLUTION branch specifically (the admit gate is pinned by test_customer_stepup)."""
    monkeypatch.delenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", raising=False)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    custs = CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    orgs = OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    clock = itertools.count(1)
    p = Provisioner(
        s, customers=custs, orgs=orgs, wallet=WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP),
        email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
        email_sender=NullEmailSender(), trial_credits=100, now_fn=lambda: float(next(clock)))
    admin, org = "cust_admin000000000000001", "org_p1"
    custs.create("admin@acme.com", issued_at=1.0, password="password-xyz", username=admin)
    orgs.create_org(org, "Acme", owner=admin, issued_at=2.0)
    orgs.grant_membership(org, admin, "org_admin", issued_at=3.0)
    monkeypatch.setattr(p.orgs, "admit_customer", lambda **kw: True)
    return p, admin, org


def _capture_reserve(monkeypatch):
    """Monkeypatch LaunchGate.reserve_launch to CAPTURE the units it is handed (and short-circuit the real
    owner-signed launch chain), so each test asserts exactly what units launch_reserve resolved."""
    seen: dict = {}

    def _cap(self, *, requester, org_id, host, units, now):
        seen["units"] = units
        return {"ok": True, "slug": "cust_x", "host": host, "units_reserved": units,
                "nonce": "n1", "not_before": 0.0, "not_after": 0.0, "lease": {}, "trust_root": {}}
    monkeypatch.setattr("sigil.ui.launch_gate.LaunchGate.reserve_launch", _cap)
    return seen


def test_no_product_reserves_the_default_units_byte_identical(monkeypatch):
    from sigil import config
    monkeypatch.delenv("VIGIL_TIERED_PRODUCTS", raising=False)
    p, admin, org = _prov(monkeypatch)
    seen = _capture_reserve(monkeypatch)
    out = p.launch_reserve(admin, org, "acme.example")
    assert seen["units"] == config.LAUNCH_UNITS          # the pre-EC-7b default amount
    assert "product_id" not in out                       # nothing echoed when no product was chosen


def test_deep_product_reserves_its_catalog_units(monkeypatch):
    monkeypatch.setenv("VIGIL_TIERED_PRODUCTS", "1")
    p, admin, org = _prov(monkeypatch)
    seen = _capture_reserve(monkeypatch)
    out = p.launch_reserve(admin, org, "acme.example", product_id="vigil_launch_deep")
    assert seen["units"] == 20                           # from the OWNER catalog, never a customer-supplied amount
    assert out["product_id"] == "vigil_launch_deep"


def test_quick_product_reserves_its_catalog_units(monkeypatch):
    monkeypatch.setenv("VIGIL_TIERED_PRODUCTS", "1")
    p, admin, org = _prov(monkeypatch)
    seen = _capture_reserve(monkeypatch)
    p.launch_reserve(admin, org, "acme.example", product_id="vigil_launch_quick")
    assert seen["units"] == 3


def test_unknown_product_is_refused_fail_closed(monkeypatch):
    monkeypatch.setenv("VIGIL_TIERED_PRODUCTS", "1")
    p, admin, org = _prov(monkeypatch)
    seen = _capture_reserve(monkeypatch)
    with pytest.raises(ProvisionDenied):
        p.launch_reserve(admin, org, "acme.example", product_id="vigil_launch_nope")
    assert "units" not in seen                           # never reached reserve_launch (no silent fallback)


def test_product_while_flag_off_is_refused(monkeypatch):
    # EC-7 OFF ⇒ catalog.launch_product() returns None for ANY id ⇒ a product_id is refused — never a silent
    # fallback to the default tier (fail-closed; the customer asked for a product that isn't offered).
    monkeypatch.delenv("VIGIL_TIERED_PRODUCTS", raising=False)
    p, admin, org = _prov(monkeypatch)
    seen = _capture_reserve(monkeypatch)
    with pytest.raises(ProvisionDenied):
        p.launch_reserve(admin, org, "acme.example", product_id="vigil_launch_deep")
    assert "units" not in seen


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
