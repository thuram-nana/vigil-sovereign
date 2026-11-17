"""W2c-2 (k) — ``ENVELOPE_TOKENS_PER_CREDIT`` is off every METERED path; FLAT mode is byte-identical.

The credit->token envelope ``E`` (``vigil_core.ENVELOPE_TOKENS_PER_CREDIT``) sells AI far below cost; a metered run is
bounded by the gateway allowance + the grant cap, never units x E. So:
  * the EC-5 cost-ledger reserve/settle writes (``LaunchGate._write_cost_reserve`` / ``_write_cost_settle``) write
    NOTHING on a metered launch and never read E (its real provider cost is on the gateway meter);
  * a FLAT launch still writes ``units * E`` / ``consumed * E`` exactly as before (byte-identical).

Mutation-verify targets (each neuter reds a NAMED test here):
  * drop the metered skip in _write_cost_reserve (write u*E on a metered launch) -> test_a_metered_launch_writes_no_cost_envelope_and_reads_no_E
  * drop the metered skip in _write_cost_settle (write consumed*E on a metered settle) -> test_a_metered_launch_writes_no_cost_envelope_and_reads_no_E
  * skip the cost write on a FLAT launch too                                     -> test_a_flat_launch_still_writes_the_cost_envelope
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil import config
from sigil import model_gateway as gw
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.cost_ledger import CostEnvelopeLedger
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_core import model_metering as mm
from vigil_core.model_grant import ModelGrant, meter_id

_iss = itertools.count(1)
ORG, HOST, NOW = "org_a", "apme.cm", 2000.0
U2502 = mm.Usage(output_tokens=400, cache_read_tokens=16)   # 2502 mc -> a metered settle keeps 2 whole credits


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    for k in ("VIGIL_METERED_BILLING", "VIGIL_COST_LEDGER_WRITE", "VIGIL_GLOBAL_POOL_TOKENS", mm.MARGIN_ENV,
              mm.CANCEL_ENV, "VIGIL_SETTLE_SPINE_RECORD", "VIGIL_RATE_CARD", *mm.OBSOLETE_PRICING_ENVS):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv(mm.MARGIN_ENV, "0.5")
    monkeypatch.setenv(mm.CANCEL_ENV, "metered")
    monkeypatch.setenv("VIGIL_COST_LEDGER_WRITE", "1")           # the EC-5 writes are ARMED for every test here


def _gate(store):
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(ORG, ORG, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(ORG, "u", "operator", issued_at=float(next(_iss)))
    WalletRegistry(store).grant(ORG, 100, "trial", entry_id=f"trial:{ORG}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(ORG, HOST, issued_at=float(next(_iss)))
    reg.verify_and_record(ORG, HOST, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
    assert add_customer_target(HOST, org_id=ORG, store=store, now=NOW)["ok"]
    return LaunchGate(store)


def _use(r, usage):
    m = gw.GrantMeter(config.MODEL_METER_DIR)
    g = ModelGrant(grant_id="0" * 32, org_id=ORG, engagement_slug=r["slug"], nonce=r["nonce"],
                   model="claude-opus-4-8", effort="high", cap_nano_usd=10 ** 13, not_after=NOW + 86_400,
                   issued_at=NOW - 60)
    rid, _res, why = m.reserve(g, 10 ** 6, 25_000, now=NOW)
    assert why == "", why
    m.commit(g, rid, usage, 1, request_id="r", now=NOW)


def _close_and_settle(g, r, *, consumed_mc):
    gw.GrantMeter(config.MODEL_METER_DIR).close(meter_id(r["slug"], r["nonce"]), now=NOW)
    return g.settle_launch(signed_lease=r["lease"], consumed_units=0, consumed_mc=consumed_mc, now=NOW,
                           basis="completion:completed")


def test_a_metered_launch_writes_no_cost_envelope_and_reads_no_E(monkeypatch):
    # A metered launch (depth named) with the EC-5 writes ARMED must write NO cost record, at reserve OR settle, and
    # never read ENVELOPE_TOKENS_PER_CREDIT — monkeypatched to a sentinel, so any read would leave a cost envelope.
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    monkeypatch.setattr("vigil_core.ENVELOPE_TOKENS_PER_CREDIT", 1000)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    g = _gate(s)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=10, now=NOW, depth="quick")
    assert r["ok"], r
    assert g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    cl = CostEnvelopeLedger(s)
    assert cl.reserved_total(ORG) == 0 and cl.in_flight_envelope(ORG) == 0        # NO reserve envelope (no u*E)
    _use(r, U2502)
    out = _close_and_settle(g, r, consumed_mc=2502)        # a metered settle keeps 2 whole credits (consumed>0)
    assert out["ok"], out
    assert cl.committed_cost(ORG) == 0 and cl.in_flight_envelope(ORG) == 0         # NO settle envelope (no consumed*E)
    assert cl.was_settled(ORG, f"settle-cost:{r['slug']}:{r['nonce']}") is False


def test_a_flat_launch_still_writes_the_cost_envelope(monkeypatch):
    # FLAT (metered billing OFF, depth None) is byte-identical to pre-W2c-2: units*E reserve, consumed*E settle.
    from vigil_core import ENVELOPE_TOKENS_PER_CREDIT as E
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    g = _gate(s)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=30, now=NOW)   # depth=None -> flat
    assert r["ok"], r
    cl = CostEnvelopeLedger(s)
    assert cl.in_flight_envelope(ORG) == 30 * E                 # the flat path DID write the reserve envelope
    out = g.settle_launch(signed_lease=r["lease"], consumed_units=10, now=NOW + 1000)
    assert out["ok"], out
    assert cl.committed_cost(ORG) == 10 * E                     # ...and the settle envelope
