"""W13-8 (#501) property 2 — the trust anchor is CUSTOMER-controlled; NO vendor kill switch.

Runs in the SOVEREIGN leg of the required "integration two-env boundary (P5)" CI job. Pins, per #501:

  * A deployment is OPERATIONAL iff the CUSTOMER's own bundle verifies under the CUSTOMER's own trust
    anchor — ``deployment_operational`` is a pure function of that result and takes NO vendor input.
  * NO vendor-held anchor can disable a deployment: contrasted against a straw-man ``customer_ok AND
    vendor_allows`` design, our decision stays operational when a hypothetical vendor says "disallow" (there
    is nowhere to feed such a signal), and an ambient "vendor kill" env var is ignored. ``vendor_key_is_
    powerless`` shows a vendor's key is disjoint from the operational authorities. An AST scan of the whole
    ``sovereign_deploy`` package finds no vendor-control / phone-home identifier.
  * NEGATIVE CONTROL (same run, proves the property is not vacuous): a deployment whose CUSTOMER bundle does
    NOT verify (tampered / signed by a non-customer key) is NOT operational — the customer's own keys really
    gate operation; and a vendor key that DID appear among the anchors would NOT be powerless (the guard
    fires).

FAILS WITHOUT THE FIX: imports ``vigil_integration.sovereign_deploy.trust`` at module scope.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path

from vigil_core.crypto import generate_keypair
from vigil_core.models import AuthorizerKey, TrustRoot
from vigil_integration.sovereign_deploy import bundle as B
from vigil_integration.sovereign_deploy.trust import (
    SOLE_OPERATIONAL_AUTHORITY,
    deployment_operational,
    operational_authorities,
    vendor_key_is_powerless,
)

_PKG = Path(__file__).resolve().parents[2] / "integration" / "vigil_integration" / "sovereign_deploy"


# ---------------------------------------------------------------------------------------------------------
# helpers — build + install a real customer bundle so operational status has a real input.
# ---------------------------------------------------------------------------------------------------------
def _customer_bundle(tmp_path: Path, *, tamper: bool = False, attacker_signed: bool = False):
    keys = [generate_keypair() for _ in range(3)]
    tr = TrustRoot(schema_version=1, threshold=2, authorizers=[
        AuthorizerKey(key_id=f"cust-{i}", name=f"Customer {i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    payload = tmp_path / "payload"
    payload.mkdir(parents=True)
    (payload / "app.bin").write_text("app bytes")
    specs = [{"name": "app", "kind": "file", "path": "payload/app.bin"}]
    if attacker_signed:
        att = generate_keypair()
        signers = [("attacker-1", att.private_key_b64)]
    else:
        signers = [(f"cust-{i}", keys[i].private_key_b64) for i in range(2)]
    B.assemble_bundle(bundle_root=tmp_path, product_version="2.0.0", artifact_specs=specs,
                      trust_root=tr, signers=signers)
    if tamper:
        (payload / "app.bin").write_text("TAMPERED")
    return B.install_bundle(tmp_path), tr


# a STRAW-MAN of what a vendor kill switch WOULD look like — lives only here, never in the shipped code.
def _vendor_gated_operational(customer_ok: bool, vendor_allows: bool) -> bool:
    return customer_ok and vendor_allows


# ---------------------------------------------------------------------------------------------------------
# THE PROPERTY
# ---------------------------------------------------------------------------------------------------------
def test_operational_iff_customer_bundle_verifies(tmp_path):
    res, _tr = _customer_bundle(tmp_path)
    status = deployment_operational(res)
    assert status.operational is True
    assert status.authority == SOLE_OPERATIONAL_AUTHORITY == "customer-trust-root"


def test_no_vendor_kill_switch_a_vendor_disallow_cannot_disable(tmp_path, monkeypatch):
    res, _tr = _customer_bundle(tmp_path)
    # A hypothetical vendor now wants to DISABLE this deployment. There is no parameter, env var, or call to
    # do it. Set the most brazen ambient "kill" signal we can and confirm operation is unaffected.
    monkeypatch.setenv("VIGIL_VENDOR_KILL", "1")
    monkeypatch.setenv("VIGIL_LICENSE_REVOKED", "true")
    status = deployment_operational(res)
    assert status.operational is True  # the vendor cannot disable a verified customer deployment

    # The contrast that makes it concrete: a vendor-gated design WOULD go dark on vendor_allows=False, while
    # our sovereign decision (which has no such input) stays operational.
    assert _vendor_gated_operational(customer_ok=True, vendor_allows=False) is False
    assert deployment_operational(res).operational is True


def test_vendor_key_is_powerless_against_a_customer_trust_root(tmp_path):
    _res, tr = _customer_bundle(tmp_path)
    vendor = generate_keypair()  # a key the VENDOR holds
    anchors = set(operational_authorities(tr))
    assert anchors == {"cust-0", "cust-1", "cust-2"}
    assert vendor_key_is_powerless(tr, ["vendor-root", "vendor-backup"]) is True
    # the vendor's key_id is not among the operational authorities, so it cannot participate in the m-of-n
    # that gates the deployment.
    assert "vendor-root" not in anchors


def test_no_vendor_control_identifier_anywhere_in_the_package():
    """AST scan of the whole sovereign_deploy package: no identifier / attribute / imported name normalises
    to a vendor-control, remote-disable, or phone-home fragment. (The customer's OWN local controls elsewhere
    in the repo are out of scope — this scan is the sovereign-deploy package only.)"""
    # Vendor/remote CONTROL verbs and phone-home service nouns — the shapes a kill switch would take. NOT
    # bare "vendorkey"/"vendoranchor": this package legitimately REASONS about vendor keys to prove they are
    # powerless (``vendor_key_is_powerless``), so the scan targets a vendor DISABLING something or the box
    # calling out to a vendor service, never the noun "vendor key".
    forbidden = (
        "vendorkill", "vendordisable", "vendorrevoke", "vendordeactivate",
        "remotekill", "remotedisable", "remoterevoke", "remotedeactivate",
        "phonehome", "callhome", "beacon",
        "licenseserver", "licensecheck", "entitlementserver", "activationserver", "heartbeatserver",
    )

    def _norm(s: str) -> str:
        return "".join(ch for ch in s.lower() if ch.isalnum())

    offenders: list[str] = []
    scanned = 0
    for py in _PKG.rglob("*.py"):
        scanned += 1
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.append(node.name)
            elif isinstance(node, ast.Name):
                names.append(node.id)
            elif isinstance(node, ast.Attribute):
                names.append(node.attr)
            elif isinstance(node, ast.arg):
                names.append(node.arg)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                names.extend(a.name for a in node.names)
                if isinstance(node, ast.ImportFrom) and node.module:
                    names.append(node.module)
            for nm in names:
                n = _norm(nm)
                if any(frag in n for frag in forbidden):
                    offenders.append(f"{py.name}: {nm!r}")
    assert scanned >= 4, f"scanned too few files ({scanned}); package layout may have changed"
    assert not offenders, f"vendor-control / phone-home identifier in sovereign_deploy: {offenders}"


# ---------------------------------------------------------------------------------------------------------
# NEGATIVE CONTROLS — the customer's own control is REAL (not a vacuous always-operational).
# ---------------------------------------------------------------------------------------------------------
def test_negative_control_tampered_customer_bundle_is_not_operational(tmp_path):
    res, _tr = _customer_bundle(tmp_path, tamper=True)
    status = deployment_operational(res)
    assert status.operational is False
    assert "does not verify" in status.reason


def test_negative_control_non_customer_signed_bundle_is_not_operational(tmp_path):
    res, _tr = _customer_bundle(tmp_path, attacker_signed=True)
    assert deployment_operational(res).operational is False


def test_negative_control_a_vendor_key_among_anchors_is_not_powerless():
    # If a vendor key DID appear among the customer trust root's authorisers, the guard must FIRE (return
    # False) — proving vendor_key_is_powerless is a real check, not a constant True.
    keys = [generate_keypair() for _ in range(2)]
    tr = TrustRoot(schema_version=1, threshold=1, authorizers=[
        AuthorizerKey(key_id="cust-0", name="Customer", public_key_b64=keys[0].public_key_b64),
        AuthorizerKey(key_id="vendor-root", name="Vendor", public_key_b64=keys[1].public_key_b64),
    ])
    assert vendor_key_is_powerless(tr, ["vendor-root"]) is False
