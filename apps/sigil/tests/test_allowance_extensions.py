"""Pricing design §0.4 W2b — a running metered launch's ALLOWANCE EXTENSIONS (the prepaid pay-as-you-go wallet).

An extension is one more owner-signed WALLET debit of the SAME launch (``reserve-wallet:{slug}:{nonce}:x{k}``), so the
launch's one exactly-once settle transaction refunds or keeps it with the rest of its reservation. Drives the REAL
reserve -> metered publish -> gateway meter -> completion drain -> settle path. Pins:
  * an extension debits the wallet and is indexed with its launch; the settle clamps the charge to everything the
    launch holds (lease + extensions) and refunds exactly the unused part (net spend == metered consumption);
  * an extension is refused — nothing debited — when the wallet cannot cover it (``insufficient``: the run pauses),
    when the launch's meter is closed (a settle has begun), for a launch published flat, and for a postpaid line;
  * indices are consecutive; two extensions racing for the last credits debit at most what the wallet holds;
  * a settle whose allowance changed after its decision was built retries with nothing written;
  * an extension whose amount left the live spine window (a hard prune) HOLDS the settle for the owner;
  * E7 never releases an extended launch; the paused-abandoned charge clamps to lease + extensions;
  * the wallet's per-entry reserve amounts read the same with the verified fold cache on and off.

Mutation-verify targets:
  * clamp the drained charge to the lease alone            -> test_the_settle_charges_extension_usage_and_refunds_the_rest
  * extend a closed meter                                   -> test_no_extension_once_the_meter_is_closed
  * skip the wallet balance check                           -> test_an_extension_the_wallet_cannot_cover_is_refused
  * drop the in-lock allowance re-check                     -> test_a_settle_whose_allowance_changed_retries
  * settle on a pruned extension                            -> test_a_pruned_extension_holds_the_settle
  * index an extension as its own launch / ignore it        -> test_an_extension_is_indexed_with_its_launch
"""
from __future__ import annotations

import itertools
import os
import tempfile
import threading

import pytest

from sigil import config
from sigil import model_gateway as gw
from sigil.governor import settle_hold
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.identity import delegate_offense_governance, ensure_owner_keypair
from sigil.governor.launch_reservations import _extension_of, extension_entry_id, scan_reservations
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.inbound.completion_spool import CompletionSpoolWatcher
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import PLAN_DEBIT_PRUNED, LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_core import AuthorizerKey, generate_keypair
from vigil_core import model_metering as mm
from vigil_core.model_grant import ModelGrant
from vigil_integration.jobs.completion_signal import emit_completion_signal

_iss = itertools.count(1)
ORG, HOST, NOW = "org_a", "apme.cm", 2000.0
TEST_MARGIN = "0.5"                              # a test fixture (markup 2), not a pricing decision
BIG = mm.Usage(output_tokens=300_000)            # $7.50 x 2 = 1,500 credits: more than the 900 the lease holds
BIG_COST = 7_500_000_000


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    for k in ("VIGIL_METERED_BILLING", mm.MARGIN_ENV, mm.CANCEL_ENV, "VIGIL_RUN_FLOOR_CREDITS", "VIGIL_MODEL_PRICES",
              "VIGIL_MODEL_GATEWAY_ENABLED", "VIGIL_RUN_MODEL", *mm.OBSOLETE_PRICING_ENVS):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    monkeypatch.setenv(mm.MARGIN_ENV, TEST_MARGIN)
    monkeypatch.setenv(mm.CANCEL_ENV, "metered")


def _reserve(store, *, units=900, credits=5_000, publish=True):
    owner = ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(ORG, ORG, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(ORG, "u", "operator", issued_at=float(next(_iss)))
    WalletRegistry(store).grant(ORG, credits, "trial", entry_id=f"trial:{ORG}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(ORG, HOST, issued_at=float(next(_iss)))
    reg.verify_and_record(ORG, HOST, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
    assert add_customer_target(HOST, org_id=ORG, store=store, now=NOW)["ok"]
    g = LaunchGate(store)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=units, now=NOW)
    assert r["ok"], r
    if publish:
        assert g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    return owner, r, g


def _spend(r, usage: mm.Usage, cost: int) -> None:
    m = gw.GrantMeter(config.MODEL_METER_DIR)
    g = ModelGrant(grant_id="0" * 32, org_id=ORG, engagement_slug=r["slug"], nonce=r["nonce"],
                   model="claude-opus-4-8", effort="high", cap_nano_usd=10 ** 13, not_after=NOW + 86_400,
                   issued_at=NOW - 60)
    rid, _res, why = m.reserve(g, 10 ** 6, 25_000, now=NOW)
    assert why == "", why
    m.commit(g, rid, usage, cost, request_id="r", now=NOW)


def _drain(store, owner, r, outcome="completed"):
    gov = generate_keypair()
    deleg = delegate_offense_governance(
        owner, authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=gov.public_key_b64)],
        threshold=1, scope=r["slug"], not_after=9_000_000_000)
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome=outcome,
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    return CompletionSpoolWatcher(store, spool_dir=spool, owner_pubkey=owner.public_key_b64, delegation=deleg,
                                  scope=r["slug"], base_dir=os.environ["VIGIL_BASE_DIR"],
                                  now_fn=lambda: NOW).drain()


def _avail(store):
    return WalletRegistry(store).available(ORG)


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def test_the_settle_charges_extension_usage_and_refunds_the_rest():
    s = _store()
    owner, r, g = _reserve(s)
    assert _avail(s) == 4_100                                            # 5,000 - the lease's 900
    e = g.extend_reservation(org_id=ORG, slug=r["slug"], nonce=r["nonce"], credits=1_000, now=NOW)
    assert e["ok"] and e["k"] == 1 and e["extended"] == 1_000 and _avail(s) == 3_100
    _spend(r, BIG, BIG_COST)                                             # 1,500 credits: past the lease, inside 1,900
    assert _drain(s, owner, r)["settled"] == 1
    assert _avail(s) == 5_000 - 1_500                                    # net spend == metered consumption


def test_an_extension_is_indexed_with_its_launch():
    s = _store()
    owner, r, g = _reserve(s)
    assert g.extend_reservation(org_id=ORG, slug=r["slug"], nonce=r["nonce"], credits=250, now=NOW)["ok"]
    assert g.extend_reservation(org_id=ORG, slug=r["slug"], nonce=r["nonce"], credits=100, now=NOW)["k"] == 2
    ix = scan_reservations(s, owner.public_key_b64, org_id=ORG)
    (res,) = ix.reservations.values()                                   # one launch, not three
    assert res.nonce == r["nonce"] and res.extensions == {1: 250, 2: 100} and res.reserved == 900 + 350
    assert g.extension_total(ORG, r["slug"], r["nonce"]) == (350, False)
    assert g.reserved_with_extensions(org_id=ORG, slug=r["slug"], nonce=r["nonce"], units_reserved=900) == 1_250


def test_an_extension_the_wallet_cannot_cover_is_refused():
    s = _store()
    _owner, r, g = _reserve(s, credits=1_000)                            # 100 left after the lease
    out = g.extend_reservation(org_id=ORG, slug=r["slug"], nonce=r["nonce"], credits=101, now=NOW)
    assert not out["ok"] and out["insufficient"] and _avail(s) == 100
    assert g.extend_reservation(org_id=ORG, slug=r["slug"], nonce=r["nonce"], credits=100, now=NOW)["ok"]
    assert _avail(s) == 0


def test_no_extension_once_the_meter_is_closed():
    s = _store()
    owner, r, g = _reserve(s)
    _spend(r, mm.Usage(output_tokens=1_000), 25_000_000)
    assert _drain(s, owner, r)["settled"] == 1                           # the settle closed the meter
    before = _avail(s)
    out = g.extend_reservation(org_id=ORG, slug=r["slug"], nonce=r["nonce"], credits=10, now=NOW)
    assert not out["ok"] and "closed" in out["error"] and _avail(s) == before


def test_a_flat_launch_is_not_extended(monkeypatch):
    monkeypatch.delenv("VIGIL_METERED_BILLING")
    s = _store()
    _owner, r, g = _reserve(s)                                           # published flat: no meter marker
    before = _avail(s)
    out = g.extend_reservation(org_id=ORG, slug=r["slug"], nonce=r["nonce"], credits=10, now=NOW)
    assert not out["ok"] and "metered" in out["error"] and _avail(s) == before


def test_a_postpaid_launch_is_not_extended_yet(monkeypatch):
    s = _store()
    _owner, r, g = _reserve(s)
    monkeypatch.setattr(g.arrears, "was_accrued", lambda oid, eid: True)
    before = _avail(s)
    out = g.extend_reservation(org_id=ORG, slug=r["slug"], nonce=r["nonce"], credits=10, now=NOW)
    assert not out["ok"] and out["insufficient"] and "postpaid" in out["error"] and _avail(s) == before


def test_racing_extensions_never_overdraw_the_wallet():
    s = _store()
    _owner, r, g = _reserve(s, credits=1_400)                            # 500 left: room for exactly one
    results: list = []

    def go():
        results.append(g.extend_reservation(org_id=ORG, slug=r["slug"], nonce=r["nonce"], credits=500, now=NOW))

    threads = [threading.Thread(target=go) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(1 for x in results if x["ok"]) == 1 and _avail(s) == 0
    assert g.extension_total(ORG, r["slug"], r["nonce"]) == (500, False)


def test_a_settle_whose_allowance_changed_retries(monkeypatch):
    s = _store()
    owner, r, g = _reserve(s)
    _spend(r, mm.Usage(output_tokens=1_000), 25_000_000)
    real = g.extension_total
    calls = {"n": 0}

    def drifting(oid, slug, nonce):
        calls["n"] += 1
        total, pruned = real(oid, slug, nonce)
        return (total + 1, pruned) if calls["n"] > 1 else (total, pruned)   # changes inside the critical section

    monkeypatch.setattr(g, "extension_total", drifting)
    before = _avail(s)
    out = g.settle_launch(signed_lease=r["lease"], consumed_units=5, now=NOW, expect_org_id=ORG)
    assert not out["ok"] and out["retry"] and "allowance changed" in out["error"]
    assert _avail(s) == before                                           # nothing written
    monkeypatch.setattr(g, "extension_total", real)
    assert g.settle_launch(signed_lease=r["lease"], consumed_units=5, now=NOW, expect_org_id=ORG)["ok"]
    assert _avail(s) == 5_000 - 5


def test_a_pruned_extension_holds_the_settle(monkeypatch):
    s = _store()
    _owner, r, g = _reserve(s)
    assert g.extend_reservation(org_id=ORG, slug=r["slug"], nonce=r["nonce"], credits=200, now=NOW)["ok"]
    monkeypatch.setattr(g.wallet, "reserve_debit", lambda oid, eid: None)   # the amount left the live window
    before = _avail(s)
    out = g.settle_launch(signed_lease=r["lease"], consumed_units=5, now=NOW, expect_org_id=ORG)
    assert not out["ok"] and out.get("refused") == PLAN_DEBIT_PRUNED and _avail(s) == before
    assert r["nonce"] in str(settle_hold.read_held())


def test_e7_never_releases_an_extended_launch():
    s = _store()
    owner, r, g = _reserve(s, publish=False)
    ix = scan_reservations(s, owner.public_key_b64, org_id=ORG)
    (res,) = ix.reservations.values()
    res.extensions[1] = 50
    assert g._release_refusal(ORG, r["slug"], res, ix, NOW + 10 ** 9, 0.0) == "metered"


def test_the_paused_abandoned_charge_clamps_to_lease_and_extensions():
    from sigil.ops_sweeps import _paused_metered_charge
    s = _store()
    _owner, r, g = _reserve(s)
    assert g.extend_reservation(org_id=ORG, slug=r["slug"], nonce=r["nonce"], credits=1_000, now=NOW)["ok"]
    _spend(r, BIG, BIG_COST)
    assert _paused_metered_charge(g, r["slug"], r["nonce"], 900, NOW, org_id=ORG) == 1_500


def test_extension_entry_ids_are_canonical():
    assert _extension_of(extension_entry_id("cust_x", "n1", 12)) == ("cust_x", "n1", 12)
    for bad in ("reserve-wallet:s:n:x0", "reserve-wallet:s:n:x01", "reserve-wallet:s:n:x-1", "reserve-wallet:s:n:x",
                "reserve-wallet:s:n:xa", "reserve-wallet:s:n:x1:z", "reserve-wallet:s:n", "reserve-plan:s:n:x1",
                "reserve-wallet::n:x1", "reserve-wallet:s::x1", "reserve-wallet:s:n:x١"):
        assert _extension_of(bad) is None, bad
    with pytest.raises(ValueError):
        extension_entry_id("s", "n", 0)


@pytest.mark.parametrize("cache", ["", "1"])
def test_reserve_debit_amounts_read_the_same_with_the_fold_cache(monkeypatch, cache):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", cache)
    s = _store()
    _owner, r, g = _reserve(s)
    assert g.extend_reservation(org_id=ORG, slug=r["slug"], nonce=r["nonce"], credits=77, now=NOW)["ok"]
    w = WalletRegistry(s)
    assert w.reserve_debit(ORG, extension_entry_id(r["slug"], r["nonce"], 1)) == 77
    assert w.reserve_debit(ORG, f"reserve-wallet:{r['slug']}:{r['nonce']}") == 900
    assert w.reserve_debit(ORG, extension_entry_id(r["slug"], r["nonce"], 2)) is None
    assert w.reserve_debit(ORG, f"trial:{ORG}") is None                 # not a reserve entry


def test_a_flat_launch_settle_never_reads_extensions(monkeypatch):
    monkeypatch.delenv("VIGIL_METERED_BILLING")
    s = _store()
    _owner, r, g = _reserve(s)

    def boom(*_a, **_k):
        raise AssertionError("a flat launch's settle must not look up extensions")

    monkeypatch.setattr(g, "extension_total", boom)
    assert g.settle_launch(signed_lease=r["lease"], consumed_units=900, now=NOW, expect_org_id=ORG)["ok"]
