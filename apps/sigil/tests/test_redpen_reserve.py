"""Red-Pen R2 — reserve_redpen_review mints a lease from the connected-repo record and reuses the W2 settle path.

Invariants pinned here:
  * the lease is minted from the VERIFIED owner-signed connected-repo record — NO host ownership proof / engagement
    authority is needed (decision O-3); it names the repo as its scope_host and the W2 slug (_customer_slug(org, repo));
  * an unconnected repo, a repo at its monthly limit, and an empty wallet each refuse with nothing debited;
  * the whole W2 settle path is reused verbatim: settle refunds exactly to metered consumption, idempotent per
    (slug, nonce);
  * behind VIGIL_REDPEN_ENABLED (off ⇒ refuse, nothing debited).
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil import config
from sigil import model_gateway as gw
from sigil.governor.connected_repos import ConnectedRepoRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.redpen_spend import RedPenSpendLedger
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import _customer_slug
from vigil_core import BlockThreshold, SignedCreditLaunchLease, model_metering as mm, verify_credit_launch_lease
from vigil_core import AuthorizerKey, TrustRoot
from vigil_core.credit_lease import LEASE_DEPTH_VERSION
from vigil_core.rate_card import DEFAULT_RATE_CARD, RATE_CARD_ENV

_iss = itertools.count(1)
ORG, REPO, NOW = "org_a", "github.com/acme/widgets", 2000.0


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("VIGIL_REDPEN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    monkeypatch.setenv(mm.MARGIN_ENV, "0.5")
    monkeypatch.setenv(mm.CANCEL_ENV, "metered")
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    for k in ("VIGIL_RUN_FLOOR_CREDITS", "VIGIL_MODEL_PRICES", "VIGIL_MODEL_GATEWAY_ENABLED",
              mm.ALLOWANCE_CHUNK_ENV, RATE_CARD_ENV, "VIGIL_TIERED_PRODUCTS", *mm.OBSOLETE_PRICING_ENVS):
        monkeypatch.delenv(k, raising=False)


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _setup(store, *, credits, limit=0, connect=True):
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(ORG, ORG, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(ORG, "u", "operator", issued_at=float(next(_iss)))
    if credits:
        WalletRegistry(store).grant(ORG, credits, "trial", entry_id=f"trial:{ORG}:{next(_iss)}",
                                    issued_at=float(next(_iss)))
    if connect:
        ConnectedRepoRegistry(store).connect(ORG, 42, REPO, block_threshold=BlockThreshold.CRITICAL_HIGH,
                                             monthly_limit_credits=limit, issued_at=float(next(_iss)))
    return LaunchGate(store)


def _avail(store):
    return WalletRegistry(store).available(ORG)


def test_a_review_is_reserved_from_the_connected_repo_record_with_no_host_proof():
    s = _store()
    g = _setup(s, credits=1_000)
    r = g.reserve_redpen_review(org_id=ORG, repo=REPO, now=NOW)
    assert r["ok"], r
    assert r["action"] == "redpen_review_reserved" and r["repo"] == REPO and r["installation_id"] == 42
    assert r["slug"] == _customer_slug(ORG, REPO)                 # the SAME W2 slug the settle/meter path keys on
    doc = r["lease"]["document"]
    assert doc["scope_host"] == REPO and doc["run_tier"] == "quick" and doc["version"] == LEASE_DEPTH_VERSION
    # the lease verifies under the owner trust root
    signed = SignedCreditLaunchLease.model_validate(r["lease"])
    root = TrustRoot(threshold=1, authorizers=[AuthorizerKey(
        key_id="owner", name="owner", public_key_b64=ensure_owner_keypair().public_key_b64)])
    assert verify_credit_launch_lease(signed, root)[0]
    assert _avail(s) == 1_000 - r["units_reserved"]              # the chunk is held from the wallet


def test_an_unconnected_repo_is_refused_with_nothing_debited():
    s = _store()
    g = _setup(s, credits=1_000, connect=False)
    before = _avail(s)
    r = g.reserve_redpen_review(org_id=ORG, repo=REPO, now=NOW)
    assert r["ok"] is False and "not connected" in r["error"] and "lease" not in r
    assert _avail(s) == before


def test_a_repo_at_its_monthly_limit_refuses_new_reviews():
    s = _store()
    g = _setup(s, credits=1_000, limit=50)
    RedPenSpendLedger(s).record_charge(ORG, REPO, 50, nonce="prev", now=NOW)
    before = _avail(s)
    r = g.reserve_redpen_review(org_id=ORG, repo=REPO, now=NOW)
    assert r["ok"] is False and "monthly" in r["error"]
    assert _avail(s) == before
    # under the limit it proceeds
    s2 = _store()
    g2 = _setup(s2, credits=1_000, limit=50)
    RedPenSpendLedger(s2).record_charge(ORG, REPO, 49, nonce="prev", now=NOW)
    assert g2.reserve_redpen_review(org_id=ORG, repo=REPO, now=NOW)["ok"]


def test_an_empty_wallet_is_refused_with_no_amount_quoted():
    s = _store()
    g = _setup(s, credits=7)                                      # below one useful model request
    r = g.reserve_redpen_review(org_id=ORG, repo=REPO, now=NOW)
    assert r["ok"] is False and "insufficient credits to start a review" in r["error"]
    assert not any(ch.isdigit() for ch in r["error"])            # no amount quoted (pricing design §0.9)
    assert _avail(s) == 7


def test_the_settle_path_is_reused_and_idempotent():
    s = _store()
    g = _setup(s, credits=1_000)
    r = g.reserve_redpen_review(org_id=ORG, repo=REPO, now=NOW)
    held = r["units_reserved"]
    assert g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    out = g.settle_launch(signed_lease=r["lease"], consumed_units=0, consumed_mc=2_000, now=NOW)
    assert out["ok"] and out["net_spend"] == 2                    # 2000 mc = 2 credits consumed, the rest refunded
    assert _avail(s) == 1_000 - 2
    # idempotent per (slug, nonce): a second settle moves nothing more
    again = g.settle_launch(signed_lease=r["lease"], consumed_units=0, consumed_mc=2_000, now=NOW)
    assert again["net_spend"] == 2 and _avail(s) == 1_000 - 2


def test_a_reused_nonce_does_not_double_reserve():
    s = _store()
    g = _setup(s, credits=1_000)
    r1 = g.reserve_redpen_review(org_id=ORG, repo=REPO, now=NOW, nonce="fixed")
    assert r1["ok"]
    after_first = _avail(s)
    r2 = g.reserve_redpen_review(org_id=ORG, repo=REPO, now=NOW, nonce="fixed")
    assert r2["ok"] is False and "did not apply" in r2["error"]
    assert _avail(s) == after_first                              # the reused nonce's debit no-ops; nothing extra held


def test_reserve_is_refused_when_red_pen_is_off(monkeypatch):
    monkeypatch.delenv("VIGIL_REDPEN_ENABLED", raising=False)
    s = _store()
    g = _setup(s, credits=1_000)
    before = _avail(s)
    r = g.reserve_redpen_review(org_id=ORG, repo=REPO, now=NOW)
    assert r["ok"] is False and "Red-Pen is off" in r["error"]
    assert _avail(s) == before
