"""ops_sweeps: abandoned credit reservations (report / --apply full refund via settle_launch, exactly-once,
idempotent re-run) and dangling Flutterwave tx_refs (report only)."""
from __future__ import annotations

import base64
import itertools
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from sigil import ops_sweeps
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_core import CreditLaunchLease, generate_keypair, sign_credit_launch_lease
from vigil_integration.live.credit_lease_broker import is_lease_settled, read_credit_lease, write_credit_lease

_iss = itertools.count(1)
ORG, HOST, NOW = "org_a", "apme.cm", 2000.0
HOUR = 3600.0


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())


def _reserve(units=30, credits=100):
    store = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(ORG, ORG, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(ORG, "u", "operator", issued_at=float(next(_iss)))
    WalletRegistry(store).grant(ORG, credits, "trial", entry_id=f"trial:{ORG}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(ORG, HOST, issued_at=float(next(_iss)))
    reg.verify_and_record(ORG, HOST, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
    assert add_customer_target(HOST, org_id=ORG, store=store, now=NOW)["ok"]
    g = LaunchGate(store)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=units, now=NOW, duration_hours=1)
    assert r["ok"], r
    assert g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    return store, g, r


def _avail(store):
    return WalletRegistry(store).available(ORG)


LATE = NOW + HOUR + 100.0   # past not_after (NOW + 1h) + ttl 50


def test_report_only_by_default_moves_nothing():
    s, g, r = _reserve()
    out = ops_sweeps.sweep_abandoned_reservations(g, now=LATE, ttl_s=50, apply=False)
    assert [i["status"] for i in out["items"]] == ["abandoned"]
    assert out["items"][0]["nonce"] == r["nonce"] and out["applied"] is False
    assert _avail(s) == 70
    assert not is_lease_settled(os.environ["VIGIL_BASE_DIR"], r["slug"], r["nonce"])


def test_within_ttl_is_not_abandoned():
    s, g, _ = _reserve()
    assert ops_sweeps.sweep_abandoned_reservations(g, now=NOW + HOUR + 10, ttl_s=50, apply=True, completion_spool=_spool())["items"] == []
    assert _avail(s) == 70


def test_apply_full_refund_exactly_once_and_idempotent_rerun():
    s, g, r = _reserve()
    out = ops_sweeps.sweep_abandoned_reservations(g, now=LATE, ttl_s=50, apply=True, completion_spool=_spool())
    assert out["items"][0]["status"] == "refunded" and out["items"][0]["refunded"] == 30
    assert _avail(s) == 100
    base = os.environ["VIGIL_BASE_DIR"]
    assert is_lease_settled(base, r["slug"], r["nonce"]) and read_credit_lease(base, r["slug"]) is None
    again = ops_sweeps.sweep_abandoned_reservations(g, now=LATE + 10, ttl_s=50, apply=True, completion_spool=_spool())
    assert again["items"] == []
    assert _avail(s) == 100


def test_settle_path_marker_blocks_double_refund_even_if_bundle_reappears():
    s, g, r = _reserve()
    ops_sweeps.sweep_abandoned_reservations(g, now=LATE, ttl_s=50, apply=True, completion_spool=_spool())
    # a stale copy of the bundle is resurrected on the seam: the settled marker keeps it from being swept again
    from vigil_core import SignedCreditLaunchLease
    signed = SignedCreditLaunchLease.model_validate(r["lease"])
    from vigil_core import TrustRoot
    write_credit_lease(os.environ["VIGIL_BASE_DIR"], r["slug"], signed, TrustRoot.model_validate(r["trust_root"]))
    assert ops_sweeps.sweep_abandoned_reservations(g, now=LATE, ttl_s=50, apply=True, completion_spool=_spool())["items"] == []
    # and even a direct re-settle through the existing path is a no-op
    assert g.settle_launch(signed_lease=r["lease"], consumed_units=0, now=LATE)["action"] == "launch_already_settled"
    assert _avail(s) == 100


def test_already_settled_lease_is_skipped():
    s, g, r = _reserve()
    assert g.settle_launch(signed_lease=r["lease"], consumed_units=30, now=NOW + 1)["ok"]
    assert ops_sweeps.sweep_abandoned_reservations(g, now=LATE, ttl_s=50, apply=True, completion_spool=_spool())["items"] == []
    assert _avail(s) == 70                                   # completed charge stays charged


def test_foreign_signed_lease_is_unverified_never_refunded():
    s, g, r = _reserve()
    from datetime import datetime, timedelta, timezone
    from vigil_core import AuthorizerKey, TrustRoot
    evil = generate_keypair()
    t = datetime.fromtimestamp(NOW, tz=timezone.utc)
    slug2 = "cust_forged"
    doc = CreditLaunchLease(engagement_slug=slug2, org_id=ORG, scope_host=HOST, units_reserved=999,
                            not_before=t, not_after=t + timedelta(hours=1), nonce="n1", issued_at=NOW)
    signed = sign_credit_launch_lease(doc, {"owner": evil.private_key_b64})
    root = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                             public_key_b64=evil.public_key_b64)])
    write_credit_lease(os.environ["VIGIL_BASE_DIR"], slug2, signed, root)
    out = ops_sweeps.sweep_abandoned_reservations(g, now=LATE, ttl_s=50, apply=True, completion_spool=_spool())
    st = {i["slug"]: i["status"] for i in out["items"]}
    assert st[slug2] == "unverified" and st[r["slug"]] == "refunded"
    assert _avail(s) == 100                                  # only the genuine 30 came back, never 999


def _env(body: dict) -> str:
    return json.dumps({"schema": "vigil.webhook.billing.v1",
                       "body_b64": base64.b64encode(json.dumps(body).encode()).decode()})


def test_dangling_tx_refs_report_only(tmp_path):
    spool = tmp_path / "spool"
    for d in ("processed", "rejected", "incoming"):
        (spool / d).mkdir(parents=True)
    (spool / "processed" / "a.json").write_text(_env({"event": "charge.completed",
                                                       "data": {"id": 1, "tx_ref": "vigil:org_a:paid"}}))
    (spool / "rejected" / "b.json").write_text(_env({"event": "charge.completed",
                                                      "data": {"id": 2, "tx_ref": "vigil:org_a:quar"}}))
    (spool / "processed" / "junk.json").write_text("not json")
    os.symlink("/etc/passwd", spool / "processed" / "link.json")
    co = tmp_path / "co.jsonl"
    co.write_text("\n".join(json.dumps(x) for x in [
        {"tx_ref": "vigil:org_a:paid", "created": 0}, {"tx_ref": "vigil:org_a:quar", "created": 0},
        {"tx_ref": "vigil:org_a:lost", "created": 0}, {"tx_ref": "vigil:org_a:fresh", "created": 990},
        {"tx_ref": "vigil:org_a:lost", "created": 0}]) + "\nbroken\n")
    before = sorted(p.name for p in spool.rglob("*"))
    out = ops_sweeps.sweep_dangling_tx_refs(ops_sweeps.load_checkouts(co), spool_dir=spool, now=1000, ttl_s=100)
    assert out == {"applied": False, "items": [
        {"tx_ref": "vigil:org_a:quar", "created": 0.0, "status": "quarantined"},
        {"tx_ref": "vigil:org_a:lost", "created": 0.0, "status": "no_webhook"}]}
    assert sorted(p.name for p in spool.rglob("*")) == before  # nothing moved


def test_dangling_tx_refs_read_stripe_bodies_with_the_stripe_provider(tmp_path):
    """Stripe parity: a Stripe event carries the reference as data.object.client_reference_id (a checkout) or
    data.object.metadata.tx_ref; the default (Flutterwave) reading never matches a Stripe body, and vice versa."""
    spool = tmp_path / "spool"
    for d in ("processed", "rejected", "retry"):
        (spool / d).mkdir(parents=True)

    def stripe(obj):
        return json.dumps({"schema": "vigil.webhook.stripe.v1", "stripe_signature": "t=1,v1=00", "received_at": 1,
                           "body_b64": base64.b64encode(json.dumps(
                               {"type": "checkout.session.completed", "data": {"object": obj}}).encode()).decode()})
    (spool / "processed" / "a.json").write_text(stripe({"id": "cs_test_1", "client_reference_id": "vigil:org_a:paid"}))
    (spool / "rejected" / "b.json").write_text(stripe({"id": "in_1", "metadata": {"tx_ref": "vigil:org_a:quar"}}))
    (spool / "retry" / "c.json").write_text(stripe({"id": "cs_test_2", "client_reference_id": "vigil:org_a:wait"}))
    (spool / "processed" / "f.json").write_text(_env({"event": "charge.completed",
                                                       "data": {"id": 3, "tx_ref": "vigil:org_a:flw"}}))
    checkouts = [{"tx_ref": f"vigil:org_a:{n}", "created": 0.0} for n in ("paid", "quar", "wait", "lost", "flw")]
    out = ops_sweeps.sweep_dangling_tx_refs(checkouts, spool_dir=spool, now=1000, ttl_s=100, provider="stripe")
    assert {(i["tx_ref"].rsplit(":", 1)[1], i["status"]) for i in out["items"]} == {
        ("quar", "quarantined"), ("wait", "retrying"), ("lost", "no_webhook"), ("flw", "no_webhook")}
    flw = ops_sweeps.sweep_dangling_tx_refs(checkouts, spool_dir=spool, now=1000, ttl_s=100)
    assert "vigil:org_a:paid" in {i["tx_ref"] for i in flw["items"]}       # a Stripe body is not a Flutterwave one
    with pytest.raises(ValueError):
        ops_sweeps.sweep_dangling_tx_refs(checkouts, spool_dir=spool, now=1000, ttl_s=100, provider="paypal")


def _cli(*args, env_extra=None):
    env = dict(os.environ, **(env_extra or {}))
    return subprocess.run([sys.executable, "-m", "sigil.cli", *args], capture_output=True, text=True, env=env,
                          cwd=str(Path(__file__).resolve().parents[1]))


def test_cli_apply_is_default_off():
    p = _cli("ops-sweep", "reservations", "--apply", env_extra={"VIGIL_OPS_SWEEP_APPLY_ENABLED": ""})
    assert p.returncode == 2 and "VIGIL_OPS_SWEEP_APPLY_ENABLED" in p.stderr


def test_cli_tx_refs_refuses_apply():
    p = _cli("ops-sweep", "tx-refs", "--apply", "--checkouts", "x", "--spool", "y")
    assert p.returncode == 2 and "report-only" in p.stderr


def _spool():
    # a REAL (initialized) completion spool: has the drain's incoming/ subdir but no pending completion, so an
    # abandoned (never-run) lease is legitimately refundable. A bare mkdtemp with no subdirs is a mis-pointed
    # spool and is (correctly) refused — see test_apply_refuses_mispointed_completion_spool.
    sp = tempfile.mkdtemp()
    (Path(sp) / "incoming").mkdir()
    return sp


def _pending(spool, slug, nonce, sub="incoming"):
    d = Path(spool) / sub
    d.mkdir(parents=True, exist_ok=True)
    (d / "c.json").write_text(json.dumps({"schema": "x", "signatures": [], "document": {
        "engagement_slug": slug, "nonce": nonce, "outcome": "completed"}}))


@pytest.mark.parametrize("sub", ["incoming", "working", "rejected"])
def test_apply_never_refunds_a_lease_with_a_pending_completion(sub):
    s, g, r = _reserve()
    sp = _spool()
    _pending(sp, r["slug"], r["nonce"], sub)
    out = ops_sweeps.sweep_abandoned_reservations(g, now=LATE, ttl_s=50, apply=True, completion_spool=sp)
    assert [i["status"] for i in out["items"]] == ["completion_pending"]
    assert _avail(s) == 70
    assert not is_lease_settled(os.environ["VIGIL_BASE_DIR"], r["slug"], r["nonce"])


def test_pending_completion_for_other_nonce_does_not_block():
    s, g, r = _reserve()
    sp = _spool()
    _pending(sp, r["slug"], "other-nonce")
    out = ops_sweeps.sweep_abandoned_reservations(g, now=LATE, ttl_s=50, apply=True, completion_spool=sp)
    assert out["items"][0]["status"] == "refunded" and _avail(s) == 100


def test_unreadable_pending_completion_blocks_all_refunds():
    s, g, r = _reserve()
    sp = _spool()
    (Path(sp) / "incoming").mkdir(exist_ok=True)
    (Path(sp) / "incoming" / "x.json").write_text("garbage")
    out = ops_sweeps.sweep_abandoned_reservations(g, now=LATE, ttl_s=50, apply=True, completion_spool=sp)
    assert out["items"][0]["status"] == "completion_unknown" and _avail(s) == 70


def test_apply_refuses_mispointed_completion_spool():
    """A mis-pointed / uninitialized --completion-spool (exists but has none of incoming/working/rejected, or
    does not exist at all) must NOT read as 'no pending completions' and green-light a refund of a run whose
    completion is sitting in the REAL spool: it is completion-UNKNOWN -> refuse (fail-closed)."""
    s, g, r = _reserve()
    bare = tempfile.mkdtemp()                                 # exists, but no drain subdirs = not a real spool
    out = ops_sweeps.sweep_abandoned_reservations(g, now=LATE, ttl_s=50, apply=True, completion_spool=bare)
    assert out["items"][0]["status"] == "completion_unknown" and _avail(s) == 70
    assert not is_lease_settled(os.environ["VIGIL_BASE_DIR"], r["slug"], r["nonce"])
    missing = os.path.join(tempfile.mkdtemp(), "nope")        # a path that does not exist at all
    out2 = ops_sweeps.sweep_abandoned_reservations(g, now=LATE, ttl_s=50, apply=True, completion_spool=missing)
    assert out2["items"][0]["status"] == "completion_unknown" and _avail(s) == 70


def test_apply_without_completion_spool_refused():
    s, g, _ = _reserve()
    with pytest.raises(ValueError):
        ops_sweeps.sweep_abandoned_reservations(g, now=LATE, ttl_s=50, apply=True)
    assert _avail(s) == 70


def test_cli_apply_requires_completion_spool():
    p = _cli("ops-sweep", "reservations", "--apply", env_extra={"VIGIL_OPS_SWEEP_APPLY_ENABLED": "1"})
    assert p.returncode == 2 and "--completion-spool" in p.stderr
