"""VSCP-own registries + signed authorization issuance suite (runs in vscp-ci.yml)."""
from __future__ import annotations

import pytest

from vigil_core.chain import verify_chain
from vigil_core.crypto import generate_keypair

from vscp.authorization import PermissionRefused, issue_authorization
from vscp.config import VscpConfig
from vscp.registries import DeploymentRegistry, TrustAuthorityRegistry
from vscp.store import open_store


@pytest.fixture()
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("VSCP_HOME", str(tmp_path / "home"))
    c = VscpConfig.resolve()
    c.ensure_data_dir()
    return c


def test_store_applies_own_migrations(cfg):
    with open_store(cfg) as store:
        assert store.applied_migrations() == ["0001_initial.sql"]
        # its own tables exist
        names = {r[0] for r in store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert {"deployments", "trust_authorities", "authorizations"} <= names


def test_deployment_registry_gates_writes(cfg):
    with open_store(cfg) as store:
        reg = DeploymentRegistry(store)
        with pytest.raises(PermissionRefused):
            reg.register(role="viewer", id="d1", name="edge", environment="production")
        with pytest.raises(PermissionRefused):
            reg.register(role="analyst", id="d1", name="edge", environment="production")
        made = reg.register(role="operator", id="d1", name="edge", environment="production")
        assert made.environment == "production"
        assert reg.get("d1").name == "edge"
        assert [d.id for d in reg.list()] == ["d1"]


def test_trust_authority_registry_validates_key_and_gates_writes(cfg):
    kp = generate_keypair()
    with open_store(cfg) as store:
        reg = TrustAuthorityRegistry(store)
        with pytest.raises(PermissionRefused):
            reg.register(role="viewer", id="t1", name="root", public_key_b64=kp.public_key_b64)
        made = reg.register(role="owner", id="t1", name="root", public_key_b64=kp.public_key_b64)
        assert made.public_key_b64 == kp.public_key_b64
        with pytest.raises(ValueError):
            reg.register(role="owner", id="bad", name="x", public_key_b64="not-a-key")


def test_issue_authorization_signs_chains_and_refuses_reviewer(cfg):
    r0 = issue_authorization(role="operator", subject="unit-7", scope="fleet:edge", config=cfg)
    assert r0.effect == "allow" and r0.verify()
    r1 = issue_authorization(role="owner", subject="unit-8", scope="fleet:edge", config=cfg,
                             prior_entries=[r0.chain_entry])
    ok, msg = verify_chain([r0.chain_entry, r1.chain_entry])
    assert ok, msg
    # tamper: a flipped digest fails verification
    bad = r0.__class__(**{**r0.__dict__, "subject": "unit-EVIL"})
    assert bad.verify() is False
    # reviewer issuance signs nothing
    with pytest.raises(PermissionRefused):
        issue_authorization(role="viewer", subject="x", scope="y", config=cfg)
