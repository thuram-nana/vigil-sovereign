"""Red-Pen R2 — the flag-off golden: with VIGIL_REDPEN_ENABLED off the Red-Pen surfaces are absent / inert.

Master flag ``VIGIL_REDPEN_ENABLED`` is OFF by default. This pins that, off, every Red-Pen entry point fails closed
(no GitHub egress, no review reserve), and the two always-present additions are inert: the doctor's Red-Pen line is a
non-required OFF line that never fails the report, and the ``manage_code`` permission is unreachable by any role a
customer can grant (so a customer's effective authority is byte-identical to a build without Red-Pen).
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil import cli, config
from sigil.governor import github_app as ga
from sigil.governor.connected_repos import ConnectedRepoRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from vigil_core.rbac import PERMISSIONS, role_can

_iss = itertools.count(1)


@pytest.fixture(autouse=True)
def _off(monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    for k in ("VIGIL_REDPEN_ENABLED", "VIGIL_GITHUB_APP_ID", "VIGIL_GITHUB_APP_PRIVATE_KEY",
              "VIGIL_GH_WEBHOOK_SECRET"):
        monkeypatch.delenv(k, raising=False)


def test_the_master_flag_is_off_by_default():
    assert config.redpen_enabled() is False


def test_every_github_app_call_fails_closed_when_off(monkeypatch):
    monkeypatch.setenv("VIGIL_GITHUB_APP_ID", "1")
    monkeypatch.setenv("VIGIL_GITHUB_APP_PRIVATE_KEY", "pem")
    with pytest.raises(ga.GitHubAppError):
        ga.build_app_jwt(now=1)
    with pytest.raises(ga.GitHubAppError):
        ga.mint_installation_token(42, now=1, transport=lambda *a, **k: {"token": "x"})


def test_reserve_redpen_review_refuses_when_off():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    ensure_owner_keypair()
    orgs = OrgRegistry(s)
    orgs.create_org("org_a", "org_a", owner="u", issued_at=float(next(_iss)))
    WalletRegistry(s).grant("org_a", 1_000, "trial", entry_id="t", issued_at=float(next(_iss)))
    ConnectedRepoRegistry(s).connect("org_a", 42, "github.com/acme/widgets", issued_at=float(next(_iss)))
    before = WalletRegistry(s).available("org_a")
    r = LaunchGate(s).reserve_redpen_review(org_id="org_a", repo="github.com/acme/widgets", now=2000.0)
    assert r["ok"] is False and "Red-Pen is off" in r["error"]
    assert WalletRegistry(s).available("org_a") == before          # nothing debited


def test_the_doctor_redpen_line_is_a_non_required_off_line():
    rep = cli.sigil_doctor_report()
    rp = next(c for c in rep["checks"] if c["id"] == "redpen")
    assert rp["ok"] is True and rp["required"] is False and rp["state"] == "OFF"


def test_manage_code_is_unreachable_by_any_customer_grantable_role():
    from sigil.ui.provision import _CUSTOMER_GRANTABLE_ROLES
    for role in _CUSTOMER_GRANTABLE_ROLES:
        assert not role_can(role, "manage_code")
    # the permission exists only on the testing-domain roles the service owner grants
    assert {r for r in PERMISSIONS if "manage_code" in PERMISSIONS[r]} == {"operator", "owner", "founder"}
