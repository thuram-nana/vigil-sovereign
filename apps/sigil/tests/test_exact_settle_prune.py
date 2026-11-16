"""W2c-1 — the org's sub-credit remainder survives a REAL hard prune (``prune.commit_prune``; HANDOFF §15.2).

The remainder is derived from the lifetime sum of the org's v3 ``consumed_mc``, so a hard prune that archives the
decisions must carry that sum into the snapshot seed (``wallet_usage_mc``, schema 11): after the prune no decision is
in the live window, the remainder still reads 502 mc from the seed alone, and the next settle collects it. The prune
tripwire (``stranded_active_wallets``) refuses a seed that drops it. Run with the fold cache off and on, and with the
settle record on.

Mutation-verify targets:
  * the wallet seed ignores the carried usage     -> test_a_settle_after_a_hard_prune_collects_the_carried_remainder
  * the prune tripwire ignores the usage total    -> test_the_prune_tripwire_refuses_a_seed_that_drops_the_usage_total
"""
from __future__ import annotations

import itertools

import pytest

import sigil.config as cfg
import sigil.spine.checkpoint as _cp
import sigil.spine.floor as _fl
import sigil.spine.snapshot as _snap
import sigil.spine.tail as _tail
from sigil import model_gateway as gw
from sigil.governor import identity
from sigil.governor import launch_settlement as ls
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine import fold_cache, prune
from sigil.spine.manifest import read_manifest
from sigil.spine.snapshot import SnapshotState
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_core import model_metering as mm
from vigil_core.model_grant import ModelGrant, meter_id

_iss = itertools.count(1)
ORG, HOST, NOW = "org_a", "apme.cm", 2000.0
U2502 = mm.Usage(output_tokens=400, cache_read_tokens=16)       # 2,500 + 2 mc at the published default card
U499 = mm.Usage(output_tokens=79, input_tokens=4)                # 494 + 5 mc


@pytest.fixture(params=[("", ""), ("1", ""), ("", "1")], ids=["cache_off", "cache_on", "settle_record_on"])
def world(request, tmp_path, monkeypatch):
    """One spine with its own owner key, signed head, floor and prune archive (a prune needs all of them)."""
    keys = tmp_path / "keys"
    monkeypatch.setattr(cfg, "KEYS_DIR", keys, raising=False)
    monkeypatch.setattr(_cp, "KEYS_DIR", keys)
    for mod in (_cp, identity):
        monkeypatch.setattr(mod, "_PRIV", keys / "owner.priv")
        monkeypatch.setattr(mod, "_PUB", keys / "owner.pub")
    monkeypatch.setattr(identity, "_GENESIS_PUB", keys / "owner.genesis.pub")
    head = tmp_path / "head.json"
    for mod in (cfg, _cp, _snap, _tail):
        monkeypatch.setattr(mod, "HEAD_PATH", head, raising=False)
    monkeypatch.setattr(_fl, "FLOOR_PATH", tmp_path / "floor.json")
    monkeypatch.setenv("SIGIL_SPINE_ARCHIVE_DIR", str(tmp_path / "archive"))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "seam"))
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(cfg, "MODEL_METER_DIR", tmp_path / "model_meter")
    for k in ("VIGIL_LEASE_PLAN_SPLIT", "VIGIL_SETTLE_SPINE_RECORD", "VIGIL_ONE_LAUNCH_PER_HOST",
              "VIGIL_COST_LEDGER_WRITE", "VIGIL_RATE_CARD", *mm.OBSOLETE_PRICING_ENVS):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    monkeypatch.setenv(mm.MARGIN_ENV, "0.5")                       # a test fixture, not a pricing decision
    monkeypatch.setenv(mm.CANCEL_ENV, "metered")
    cache, record = request.param
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", cache)
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", record)
    fold_cache.clear_all()
    path = tmp_path / "spine.jsonl"
    SpineStore(path).migrate()
    identity.ensure_owner_keypair()
    yield path
    fold_cache.clear_all()


def _seat(store):
    orgs = OrgRegistry(store)
    orgs.create_org(ORG, ORG, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(ORG, "u", "operator", issued_at=float(next(_iss)))
    WalletRegistry(store).grant(ORG, 100, "trial", entry_id=f"trial:{ORG}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(ORG, HOST, issued_at=float(next(_iss)))
    reg.verify_and_record(ORG, HOST, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
    assert add_customer_target(HOST, org_id=ORG, store=store, now=NOW)["ok"]


def _run_and_settle(path, usage):
    """One metered launch that uses ``usage``, settled exactly (a FRESH store handle each time)."""
    g = LaunchGate(SpineStore(path))
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=10, now=NOW, duration_hours=1)
    assert r["ok"], r
    assert g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    m = gw.GrantMeter(cfg.MODEL_METER_DIR)
    grant = ModelGrant(grant_id="0" * 32, org_id=ORG, engagement_slug=r["slug"], nonce=r["nonce"],
                       model="claude-opus-4-8", effort="high", cap_nano_usd=10 ** 13, not_after=NOW + 86_400,
                       issued_at=NOW - 60)
    rid, _res, why = m.reserve(grant, 10 ** 6, 25_000, now=NOW)
    assert why == "", why
    m.commit(grant, rid, usage, 1, request_id="r", now=NOW)
    m.close(meter_id(r["slug"], r["nonce"]), now=NOW)
    out = g.settle_launch(signed_lease=r["lease"], consumed_units=0,
                          consumed_mc=g.metered_use_mc(r["slug"], r["nonce"]), now=NOW, basis="completion:completed")
    assert out["ok"] and out["action"] == "launch_settled", out
    return out


def _hard_prune_everything_so_far(path) -> int:
    """Seal every record so far below K, add a live window, sign the head and run the REAL cutover. Returns K."""
    s = SpineStore(path)
    s.rotate()
    k = s.next_seq
    for i in range(2):
        s.append(kind="event", source="t", actor="u", payload={"signal": "noise", "live": i})
    s.rotate()
    for i in range(3):
        s.append(kind="event", source="t", actor="u", payload={"signal": "noise", "tail": i})
    _cp.checkpoint(s)
    rep = prune.commit_prune(s, k, confirm=True)
    assert rep["base_seq"] == k
    fold_cache.clear_all()
    return k


def test_a_settle_after_a_hard_prune_collects_the_carried_remainder(world):
    _seat(SpineStore(world))
    assert _run_and_settle(world, U2502)["remainder_mc"] == 502
    _hard_prune_everything_so_far(world)
    s = SpineStore(world)
    assert not any(isinstance(x.payload, dict) and x.payload.get("signal") == ls.LAUNCH_SETTLED_SIGNAL
                   for x in s.iter_records())                     # the decision left the live window...
    assert SnapshotState.load(s).wallet_usage_map() == {ORG: 2502}   # ...its usage rides in the seed
    b = WalletRegistry(s).balance(ORG)
    assert (b.available, b.remainder_mc) == (98, 502)
    out = _run_and_settle(world, U499)                             # 502 + 499 = 1,001: one more credit, 1 carried
    assert (out["net_spend"], out["remainder_mc"]) == (1, 1)
    b = WalletRegistry(SpineStore(world)).balance(ORG)
    assert (b.available, b.remainder_mc, b.usage_mc) == (97, 1, 3001)


def test_the_prune_tripwire_refuses_a_seed_that_drops_the_usage_total(world, monkeypatch):
    _seat(SpineStore(world))
    _run_and_settle(world, U2502)
    s = SpineStore(world)
    s.rotate()
    k = s.next_seq
    s.append(kind="event", source="t", actor="u", payload={"signal": "noise"})
    s.rotate()                                                     # K is now a sealed-segment boundary
    archived = [seg for seg in read_manifest(s._layout).sealed_in_order()
                if seg.last_seq is not None and seg.last_seq < k]
    assert prune.stranded_active_wallets(s, archived, k) == []     # the real seed carries the usage
    real_build = prune.build

    def drop_usage(records, **kw):
        return real_build(records, **kw).model_copy(update={"wallet_usage_mc": []})

    monkeypatch.setattr(prune, "build", drop_usage)
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, k)
    assert ORG in str(e.value)
    assert prune.stranded_active_wallets(s, archived, k) == [ORG]
