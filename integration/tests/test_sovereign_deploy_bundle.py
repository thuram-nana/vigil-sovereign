"""W13-8 (#501) property 1 — offline SIGNED deployment bundles install + verify with NO network.

Runs in the SOVEREIGN leg of the required "integration two-env boundary (P5)" CI job — framework is imported
NOWHERE. Pins, per the acceptance criteria of #501:

  * A customer-signed bundle assembled by ``sovereign_deploy.assemble_bundle`` INSTALLS on a fresh host:
    ``install_bundle`` returns VALID / installed, verifying every artifact against a manifest signed under the
    CUSTOMER trust root — and it does so with NO network (the verification runs inside ``no_network``, and this
    test additionally pins the whole install with the socket layer patched to RAISE, so a phone-home anywhere
    in the path would fail the test).
  * NEGATIVE CONTROLS (same run): a tampered artifact -> MODIFIED (not installed); a removed artifact ->
    MISSING; an unsigned manifest -> UNSIGNED_BUILD; a bundle signed by a NON-customer key and verified under
    the customer trust root -> UNKNOWN_BUILD. None is a false install, so "installs offline" is a real check.
  * ``no_network`` blocks every outbound socket primitive inside its block and restores them after.

FAILS WITHOUT THE FIX: this module imports ``vigil_integration.sovereign_deploy.bundle``; on a tree without
W13-8 that import ERRORs and the whole file fails at collection (observed — see the decision record).
"""
from __future__ import annotations

import socket
from pathlib import Path

import pytest

from vigil_core.crypto import generate_keypair
from vigil_core.models import AuthorizerKey, TrustRoot
from vigil_integration.sovereign_deploy.bundle import (
    NetworkAccessError,
    assemble_bundle,
    install_bundle,
    no_network,
)


# ---------------------------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------------------------
def _customer_trust_root(n: int = 3, threshold: int = 2):
    keys = [generate_keypair() for _ in range(n)]
    tr = TrustRoot(schema_version=1, threshold=threshold, authorizers=[
        AuthorizerKey(key_id=f"cust-{i}", name=f"Customer {i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    signers = [(f"cust-{i}", keys[i].private_key_b64) for i in range(n)]
    return tr, signers, keys


def _stage_payload(root: Path) -> None:
    payload = root / "payload"
    (payload / "sub").mkdir(parents=True)
    (payload / "app.bin").write_text("the sovereign application bytes")
    (payload / "sub" / "lib.py").write_text("print('hello')\n")


def _specs():
    return [
        {"name": "app", "kind": "file", "path": "payload/app.bin"},
        {"name": "libtree", "kind": "tree", "path": "payload/sub"},
    ]


def _assemble(root: Path, *, sign_count: int = 2, trust_root=None, signers=None):
    if trust_root is None:
        trust_root, signers, _ = _customer_trust_root()
    _stage_payload(root)
    assemble_bundle(bundle_root=root, product_version="1.0.0", artifact_specs=_specs(),
                    trust_root=trust_root, signers=signers[:sign_count])
    return trust_root, signers


# ---------------------------------------------------------------------------------------------------------
# THE PROPERTY — installs + verifies with NO network
# ---------------------------------------------------------------------------------------------------------
def test_offline_bundle_installs_and_verifies_with_no_network(tmp_path, monkeypatch):
    _assemble(tmp_path)

    # Belt-and-suspenders: patch the socket layer to RAISE for the whole install, so if any code in the
    # verify path tried to open a connection the install would fail here. It does not — the reused verifier
    # is pure filesystem + Ed25519.
    def _boom(*_a, **_k):
        raise AssertionError("the offline install touched the network")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    monkeypatch.setattr(socket, "getaddrinfo", _boom)

    res = install_bundle(tmp_path)  # offline=True by default
    assert res.installed is True and res.state == "VALID", res.detail
    assert res.offline_enforced is True
    assert res.build_id and res.product_version == "1.0.0"


def test_no_network_blocks_every_outbound_primitive_and_restores(tmp_path):
    with no_network():
        with pytest.raises(NetworkAccessError):
            socket.socket()
        with pytest.raises(NetworkAccessError):
            socket.create_connection(("127.0.0.1", 9))
        with pytest.raises(NetworkAccessError):
            socket.getaddrinfo("example.com", 80)
    # restored afterwards
    s = socket.socket()
    s.close()


def test_install_offline_flag_is_recorded_and_default_is_offline(tmp_path):
    # The air-gap posture is the DEFAULT: install_bundle() enforces no-network unless explicitly told not to.
    _assemble(tmp_path)
    default = install_bundle(tmp_path)
    assert default.installed and default.offline_enforced is True
    off = install_bundle(tmp_path, offline=False)
    assert off.installed and off.offline_enforced is False  # both verify; only the enforcement flag differs


# ---------------------------------------------------------------------------------------------------------
# NEGATIVE CONTROLS — the offline verify is not a no-op; each tamper is rejected fail-closed.
# ---------------------------------------------------------------------------------------------------------
def test_negative_control_tampered_artifact_is_rejected(tmp_path):
    _assemble(tmp_path)
    (tmp_path / "payload" / "app.bin").write_text("TAMPERED — not the shipped bytes")
    res = install_bundle(tmp_path)
    assert res.installed is False and res.state == "MODIFIED", res.to_dict()


def test_negative_control_missing_artifact_is_rejected(tmp_path):
    _assemble(tmp_path)
    (tmp_path / "payload" / "app.bin").unlink()
    res = install_bundle(tmp_path)
    assert res.installed is False and res.state == "MISSING", res.to_dict()


def test_negative_control_unsigned_manifest_is_rejected(tmp_path):
    # sign_count=0 -> a manifest with no signatures -> UNSIGNED_BUILD, never installed
    tr, signers, _ = _customer_trust_root()
    _stage_payload(tmp_path)
    assemble_bundle(bundle_root=tmp_path, product_version="1.0.0", artifact_specs=_specs(),
                    trust_root=tr, signers=[])
    res = install_bundle(tmp_path)
    assert res.installed is False and res.state == "UNSIGNED_BUILD", res.to_dict()


def test_negative_control_non_customer_signature_is_rejected(tmp_path):
    # Sign with an ATTACKER key, verify under the CUSTOMER trust root -> signatures do not satisfy it ->
    # UNKNOWN_BUILD (cannot authenticate). Proves the CUSTOMER's keys are what gate the install.
    customer_tr, _, _ = _customer_trust_root()
    attacker = generate_keypair()
    _stage_payload(tmp_path)
    # assemble writes the CUSTOMER trust root, but signs with the attacker key_id (unknown to that root).
    assemble_bundle(bundle_root=tmp_path, product_version="1.0.0", artifact_specs=_specs(),
                    trust_root=customer_tr, signers=[("attacker-1", attacker.private_key_b64)])
    res = install_bundle(tmp_path)
    assert res.installed is False and res.state == "UNKNOWN_BUILD", res.to_dict()


# ---------------------------------------------------------------------------------------------------------
# FATAL-2 — importing the whole deployment facade loads no offense/sovereign engine (isolated subprocess).
# ---------------------------------------------------------------------------------------------------------
def test_import_is_two_env_clean():
    import subprocess
    import sys

    repo = Path(__file__).resolve().parents[2]
    probe = (
        "import sys, vigil_integration.sovereign_deploy as m; "
        "assert 'framework' not in sys.modules, 'framework leaked'; "
        "assert 'strix' not in sys.modules, 'strix leaked'; "
        "assert 'sigil' not in sys.modules, 'sigil leaked'; "
        "assert hasattr(m, 'install_bundle'); print('CLEAN')"
    )
    env = {
        "PYTHONPATH": f"{repo / 'integration'}:{repo / 'gateway'}:{repo / 'packages' / 'core' / 'vigil_core'}",
        "PATH": __import__("os").environ.get("PATH", ""),
    }
    out = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, env=env, timeout=60)
    assert out.returncode == 0 and "CLEAN" in out.stdout, f"FATAL-2 probe failed: {out.stdout}\n{out.stderr}"
