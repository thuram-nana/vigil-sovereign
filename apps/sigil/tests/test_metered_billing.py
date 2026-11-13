"""PRICING M1c — metered billing on the sovereign side: the launch mints the run's model grant, the settle charges
the run's metered cost (design §4.3-§4.4, §5.1).

Drives the REAL path: reserve → publish (which, with ``VIGIL_METERED_BILLING`` on, mints + publishes the owner-signed
model grant BEFORE the lease) → usage on the run's gateway meter → a governance-signed completion →
``CompletionSpoolWatcher.drain()`` → ``settle_launch``. Pins:
  * metering OFF: no grant is minted and settle is the flat rule, whatever a meter holds (byte-identical), and a
    flat install with no meter gets no meter file;
  * the grant is bound to the VERIFIED lease (tenant, slug, nonce, the run model, the tier's effort, the cap the
    reservation buys, the lease's expiry), is signed by the owner, and is published 0600 with a loopback URL;
  * a pricing configuration the metering core refuses — including no target margin or no cancel-settlement
    policy — refuses the publish: no lease, no grant (a run never starts unmetered); a failed lease write removes
    the grant it published;
  * a completed run pays ``min(reservation, max(floor, ceil(confirmed cost x markup / $0.01)))``; a cancelled run
    pays that under the ``metered`` policy and 0 under ``refund``; a failed run pays 0; only confirmed spend is billed;
  * EVERY settle path (completion, customer cancel, abandoned-lease sweep) closes the meter — the gateway admits
    nothing after it — and removes the grant;
  * a request still in flight, or a pricing setting unset at settle time, DEFERS the settle (back to incoming/,
    retried next drain); a broken meter refuses it (quarantined) — nothing is refunded or charged on a guess;
  * the cockpit starts the gateway once from the environment, and not at all when it is disabled or has no key.

Mutation-verify targets (each neuter reds a NAMED test here):
  * mint the grant even with metering off                     -> test_metering_off_mints_nothing_and_settles_flat
  * cap the grant at the units instead of usd_cap(units)      -> test_the_grant_is_bound_to_the_verified_lease
  * publish the lease when the grant cannot be minted         -> test_a_refused_pricing_config_refuses_the_publish
  * publish without a cancel policy                           -> test_a_refused_pricing_config_refuses_the_publish
  * charge a failed run its usage                             -> test_each_outcome_settles_metered
  * ignore the refund cancel policy                           -> test_each_outcome_settles_metered
  * keep the meter open after settle                          -> test_each_outcome_settles_metered
  * skip the meter close on the cancel / sweep settle         -> test_every_settle_path_closes_the_meter
  * quarantine (or settle) a busy meter instead of deferring  -> test_a_request_in_flight_defers_the_settle
  * settle with the policy unset instead of deferring         -> test_an_unset_policy_at_settle_defers_it
  * bill unconfirmed spend                                    -> test_only_confirmed_spend_is_billed
  * ignore the reservation clamp                              -> test_the_floor_and_the_clamp_hold
  * settle on a corrupt meter                                 -> test_a_corrupt_meter_refuses_the_settle
"""
from __future__ import annotations

import itertools
import os
import tempfile
from fractions import Fraction

import pytest

from sigil import config
from sigil import model_gateway as gw
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.identity import delegate_offense_governance, ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.inbound.completion_spool import CompletionSpoolWatcher
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_core import AuthorizerKey, generate_keypair, run_tier
from vigil_core import model_metering as mm
from vigil_core.model_grant import MAX_GRANT_LIFETIME_S, ModelGrant, decode_token, meter_id
from vigil_integration.jobs.completion_signal import emit_completion_signal
from vigil_integration.live import credit_lease_broker
from vigil_integration.live.credit_lease_broker import read_credit_lease
from vigil_integration.live.model_grant_broker import grant_path, read_model_grant

_iss = itertools.count(1)
ORG, HOST, NOW = "org_a", "apme.cm", 2000.0
TEST_MARGIN = "0.5"                              # a test fixture (markup 2), not a pricing decision
USAGE = mm.Usage(output_tokens=10_650)
USAGE_COST = 266_250_000                         # $0.26625 x 2 = 53.25 -> 54 credits


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    for k in ("VIGIL_METERED_BILLING", mm.MARGIN_ENV, mm.CANCEL_ENV, "VIGIL_RUN_FLOOR_CREDITS", "VIGIL_MODEL_PRICES",
              "VIGIL_MODEL_GATEWAY_ENABLED", "VIGIL_MODEL_GATEWAY_PORT", "VIGIL_RUN_MODEL", *mm.OBSOLETE_PRICING_ENVS):
        monkeypatch.delenv(k, raising=False)


def _metered(monkeypatch, cancel="metered"):
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    monkeypatch.setenv(mm.MARGIN_ENV, TEST_MARGIN)
    if cancel is not None:
        monkeypatch.setenv(mm.CANCEL_ENV, cancel)


def _reserve(store, *, units=900, credits=1_000, publish=True):
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
    pub = g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG) if publish else None
    return owner, r, g, pub


def _watcher(store, owner, r, outcome):
    """A completion spool holding one governance-signed completion for ``r``, and its watcher."""
    gov = generate_keypair()
    deleg = delegate_offense_governance(
        owner, authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=gov.public_key_b64)],
        threshold=1, scope=r["slug"], not_after=9_000_000_000)
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome=outcome,
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    return CompletionSpoolWatcher(store, spool_dir=spool, owner_pubkey=owner.public_key_b64, delegation=deleg,
                                  scope=r["slug"], base_dir=os.environ["VIGIL_BASE_DIR"], now_fn=lambda: NOW)


def _settle(store, owner, r, outcome):
    return _watcher(store, owner, r, outcome).drain()


def _grant(r, gid="0"):
    return ModelGrant(grant_id=gid * 32, org_id=ORG, engagement_slug=r["slug"], nonce=r["nonce"],
                      model="claude-opus-4-8", effort="high", cap_nano_usd=10 ** 12, not_after=NOW + 86_400,
                      issued_at=NOW - 60)


def _spend(r, usage: mm.Usage, cost: int, *, held: int = 0, meter=None) -> None:
    """Record one request's usage on the run's gateway meter, as the gateway does for each forwarded response."""
    m = meter or gw.GrantMeter(config.MODEL_METER_DIR)
    g = _grant(r)
    rid, _reserved, reason = m.reserve(g, 10 ** 6, 25_000, now=NOW)
    assert reason == "", reason
    m.commit(g, rid, usage, cost, request_id="r", now=NOW, held_nano=held)


def _avail(store):
    return WalletRegistry(store).available(ORG)


def _closed(r):
    return (config.MODEL_METER_DIR / f"{meter_id(r['slug'], r['nonce'])}.closed").exists()


def test_metering_off_mints_nothing_and_settles_flat():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, _g, pub = _reserve(s)
    assert pub["ok"] and read_model_grant(os.environ["VIGIL_BASE_DIR"], r["slug"]) is None
    assert _settle(s, owner, r, "completed")["settled"] == 1
    assert _avail(s) == 100                           # flat: the full 900 reserved is consumed
    assert not config.MODEL_METER_DIR.exists()        # a flat install with no meter: no meter file is created


def test_a_launch_settles_by_the_mode_it_was_published_under(monkeypatch):
    # published metered, settled after the flag is turned off: still metered (and closed)
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, _g, _pub = _reserve(s)
    _spend(r, USAGE, USAGE_COST)
    monkeypatch.delenv("VIGIL_METERED_BILLING")
    assert _settle(s, owner, r, "canceled")["settled"] == 1
    assert _avail(s) == 1_000 - 54 and _closed(r)


def test_a_launch_published_flat_settles_flat_after_the_flag_is_on(monkeypatch):
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, _g, pub = _reserve(s)                    # published while metering is off: no grant, no marker
    assert pub["ok"]
    _metered(monkeypatch)                              # the owner turns metering on while it runs
    assert _settle(s, owner, r, "completed")["settled"] == 1
    assert _avail(s) == 100                            # the flat rule (the whole reservation), never the floor
    assert not config.MODEL_METER_DIR.exists()         # and no meter was opened for it


@pytest.mark.parametrize("units, effort", [(450, "xhigh"), (10, "high")])     # the deep tier and the quick tier
def test_the_grant_is_bound_to_the_verified_lease(monkeypatch, units, effort):
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, _g, pub = _reserve(s, units=units)
    assert pub["ok"], pub
    base = os.environ["VIGIL_BASE_DIR"]
    bundle = read_model_grant(base, r["slug"], expect_nonce=r["nonce"])
    assert bundle is not None and bundle.gateway_url == config.model_gateway_url()
    assert oct(grant_path(base, r["slug"]).stat().st_mode & 0o777) == "0o600"
    assert bundle.token not in repr(bundle)
    grant, reason = decode_token(bundle.token, owner.public_key_b64)
    assert reason == "" and grant is not None
    lease = read_credit_lease(base, r["slug"]).signed_lease.document
    assert (grant.org_id, grant.engagement_slug, grant.nonce) == (ORG, r["slug"], r["nonce"]) == (
        lease.org_id, lease.engagement_slug, lease.nonce)
    assert grant.model == "claude-opus-4-8"
    assert grant.effort == effort == run_tier.effort_for(run_tier.run_tier_for_units(units))
    assert grant.cap_nano_usd == mm.usd_cap_nano_for_credits(units, markup=Fraction(2)) == units * 5_000_000
    # valid from the lease's start for the longest grant lifetime: always past the lease window (at most a week),
    # so a run armed late in its window, or resumed after it, keeps its model access until its settle closes the meter
    assert (grant.issued_at, grant.not_after) == (lease.not_before.timestamp(),
                                                  lease.not_before.timestamp() + MAX_GRANT_LIFETIME_S)
    assert grant.not_after >= lease.not_after.timestamp() + 3_600
    assert grant.meter_id == meter_id(r["slug"], r["nonce"])
    # deterministic: re-publishing the same lease mints the identical grant (no clock, no randomness)
    assert _g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    assert read_model_grant(base, r["slug"], expect_nonce=r["nonce"]).token == bundle.token


@pytest.mark.parametrize("env", [{mm.MARGIN_ENV: "1.5"}, {mm.MARGIN_ENV: ""}, {mm.CANCEL_ENV: "free"},
                                 {"VIGIL_MARGIN_MULTIPLIER_K": "3"}, {"VIGIL_BILLING_MARKUP_K": ""}])
def test_a_refused_pricing_config_refuses_the_publish(monkeypatch, env):
    _metered(monkeypatch)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r, _g, pub = _reserve(s)
    assert pub["ok"] is False and "metered model grant" in pub["error"]
    base = os.environ["VIGIL_BASE_DIR"]
    assert read_credit_lease(base, r["slug"]) is None and read_model_grant(base, r["slug"]) is None


def test_a_failed_lease_write_removes_the_grant(monkeypatch):
    _metered(monkeypatch)

    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(credit_lease_broker, "write_credit_lease", boom)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r, _g, pub = _reserve(s)
    assert pub["ok"] is False
    assert read_model_grant(os.environ["VIGIL_BASE_DIR"], r["slug"]) is None


@pytest.mark.parametrize("outcome, cancel, charged", [
    ("completed", "metered", 54), ("completed", "refund", 54), ("canceled", "metered", 54),
    ("canceled", "refund", 0), ("failed", "metered", 0)])
def test_each_outcome_settles_metered(monkeypatch, outcome, cancel, charged):
    _metered(monkeypatch, cancel)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, _g, pub = _reserve(s)
    assert pub["ok"] and _avail(s) == 100                               # 900 reserved and held
    _spend(r, USAGE, USAGE_COST)
    assert _settle(s, owner, r, outcome)["settled"] == 1
    assert _avail(s) == 1_000 - charged
    assert _closed(r)                                                    # closed: nothing more can be spent
    assert read_model_grant(os.environ["VIGIL_BASE_DIR"], r["slug"]) is None
    assert gw.GrantMeter(config.MODEL_METER_DIR).reserve(_grant(r, "1"), 10 ** 6, 25_000, now=NOW)[2] == "closed"


def test_only_confirmed_spend_is_billed(monkeypatch):
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, _g, _pub = _reserve(s)
    _spend(r, USAGE, USAGE_COST, held=10 ** 9)            # $1 of a cut-off response VIGIL cannot prove: its cost
    assert _settle(s, owner, r, "completed")["settled"] == 1
    assert _avail(s) == 1_000 - 54


@pytest.mark.parametrize("flag_at_settle", [True, False])
def test_every_settle_path_closes_the_meter(monkeypatch, flag_at_settle):
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r, g, _pub = _reserve(s)
    assert read_model_grant(os.environ["VIGIL_BASE_DIR"], r["slug"]) is not None
    if not flag_at_settle:
        monkeypatch.delenv("VIGIL_METERED_BILLING")
    out = g.settle_launch(signed_lease=r["lease"], consumed_units=0, now=NOW, expect_org_id=ORG)   # a sweep refund
    assert out["ok"] and out["action"] == "launch_settled", out
    assert _closed(r) and read_model_grant(os.environ["VIGIL_BASE_DIR"], r["slug"]) is None
    assert gw.GrantMeter(config.MODEL_METER_DIR).reserve(_grant(r), 10 ** 6, 25_000, now=NOW)[2] == "closed"


def test_a_cancelled_reservation_that_never_started_opens_no_meter(monkeypatch):
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r, g, _pub = _reserve(s, publish=False)
    out = g.settle_launch(signed_lease=r["lease"], consumed_units=0, now=NOW, expect_org_id=ORG)
    assert out["ok"] and _avail(s) == 1_000 and not config.MODEL_METER_DIR.exists()


def test_a_grant_minted_before_metering_was_turned_off_is_still_closed(monkeypatch):
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r, g, _pub = _reserve(s)
    assert read_model_grant(os.environ["VIGIL_BASE_DIR"], r["slug"]) is not None and not _closed(r)
    monkeypatch.delenv("VIGIL_METERED_BILLING")
    assert g.settle_launch(signed_lease=r["lease"], consumed_units=0, now=NOW)["ok"]
    assert _closed(r) and read_model_grant(os.environ["VIGIL_BASE_DIR"], r["slug"]) is None


def test_settling_one_launch_never_touches_another_launchs_grant(monkeypatch):
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r1, g, _pub = _reserve(s)                                  # published: its grant is on the seam
    r2 = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=50, now=NOW)   # a re-lease of the same slug
    assert r2["ok"] and r2["slug"] == r1["slug"] and r2["nonce"] != r1["nonce"], r2
    monkeypatch.delenv("VIGIL_METERED_BILLING")
    assert g.settle_launch(signed_lease=r2["lease"], consumed_units=0, now=NOW)["ok"]
    assert read_model_grant(os.environ["VIGIL_BASE_DIR"], r1["slug"], expect_nonce=r1["nonce"]) is not None
    m2 = meter_id(r2["slug"], r2["nonce"])
    assert not [p for p in config.MODEL_METER_DIR.iterdir() if p.name.startswith(m2)]   # nor opened a meter for it


@pytest.mark.parametrize("second_metered", [True, False])
def test_one_launch_per_host_is_in_flight_while_metering_is_involved(monkeypatch, second_metered):
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r1, g, pub = _reserve(s)                                     # published metered, still running
    assert pub["ok"]
    if not second_metered:
        monkeypatch.delenv("VIGIL_METERED_BILLING")                     # the first one is metered all the same
    r2 = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=50, now=NOW)
    out = g.publish_lease(signed_lease=r2["lease"], expect_org_id=ORG)
    assert out["ok"] is False and "earlier launch on this host" in out["error"]
    base = os.environ["VIGIL_BASE_DIR"]
    assert read_credit_lease(base, r1["slug"]).signed_lease.document.nonce == r1["nonce"]   # the seam keeps the first
    assert g.publish_lease(signed_lease=r1["lease"], expect_org_id=ORG)["ok"]               # its own re-publish is fine
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    monkeypatch.setattr(credit_lease_broker, "tombstone_credit_lease", lambda *a, **k: None)  # its seam copy stays
    assert _settle(s, owner, r1, "completed")["settled"] == 1
    assert read_credit_lease(base, r1["slug"]) is not None
    assert g.publish_lease(signed_lease=r2["lease"], expect_org_id=ORG)["ok"]               # once it has settled


def test_two_flat_launches_on_one_host_are_unchanged():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, _r1, g, pub = _reserve(s)
    r2 = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=50, now=NOW)
    assert pub["ok"] and g.publish_lease(signed_lease=r2["lease"], expect_org_id=ORG)["ok"]


def test_a_failed_re_publish_keeps_the_live_grant(monkeypatch):
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r, g, pub = _reserve(s)
    assert pub["ok"]

    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(credit_lease_broker, "write_credit_lease", boom)
    assert g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"] is False      # a double-click, failing
    assert read_model_grant(os.environ["VIGIL_BASE_DIR"], r["slug"], expect_nonce=r["nonce"]) is not None


def test_a_launch_marked_metered_is_re_published_with_its_grant(monkeypatch):
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r, g, pub = _reserve(s)
    assert pub["ok"]
    base = os.environ["VIGIL_BASE_DIR"]
    from vigil_integration.live.model_grant_broker import remove_model_grant
    remove_model_grant(base, r["slug"], expect_nonce=r["nonce"])          # say a failed first publish left no grant
    monkeypatch.delenv("VIGIL_METERED_BILLING")                         # and the flag is off by the retry
    assert g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    assert read_model_grant(base, r["slug"], expect_nonce=r["nonce"]) is not None


def test_a_launch_started_flat_is_re_published_flat_after_the_flag_is_on(monkeypatch):
    # the billing mode is decided once, at the first publish: a double-click after the owner turns metering on must
    # never switch a run already under way unmetered to metered (it would settle at the floor)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, g, pub = _reserve(s)                                       # started flat
    assert pub["ok"]
    _metered(monkeypatch)
    again = g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)
    assert again["ok"] and again["action"] == "launch_published"
    assert read_model_grant(os.environ["VIGIL_BASE_DIR"], r["slug"]) is None
    assert not (config.MODEL_METER_DIR / f"{meter_id(r['slug'], r['nonce'])}.metered").exists()
    assert _settle(s, owner, r, "completed")["settled"] == 1
    assert _avail(s) == 100                                              # the flat charge, never the floor


def test_the_customer_start_retried_after_the_flag_is_on_keeps_the_run_flat(monkeypatch):
    from sigil.ui.provision import build_provisioner
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, _g, _ = _reserve(s, publish=False)
    p = build_provisioner(s)
    assert p.launch_start("u", ORG, r["lease"])["slug"] == r["slug"]      # started flat (metering off)
    _metered(monkeypatch)
    assert p.launch_start("u", ORG, r["lease"])["slug"] == r["slug"]      # the customer clicks start again
    assert _settle(s, owner, r, "completed")["settled"] == 1 and _avail(s) == 100


def test_a_new_launch_after_the_flag_is_on_is_metered(monkeypatch):
    # the decision is per launch: a first publish while the flag is on is metered (a flat launch on the seam earlier
    # does not make the next one flat)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r1, g, pub = _reserve(s)                                      # flat
    assert pub["ok"] and _settle(s, owner, r1, "completed")["settled"] == 1
    _metered(monkeypatch)
    r2 = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=50, now=NOW)
    assert g.publish_lease(signed_lease=r2["lease"], expect_org_id=ORG)["ok"]
    assert read_model_grant(os.environ["VIGIL_BASE_DIR"], r2["slug"], expect_nonce=r2["nonce"]) is not None


def test_a_new_launch_while_a_flat_one_runs_is_refused_once_metering_is_on(monkeypatch):
    # only the SAME launch keeps its flat mode: another launch published after the flag is on is metered, so the
    # one-launch-per-host rule applies and it never replaces the flat run still on the seam
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r1, g, pub = _reserve(s)                                     # flat, still running
    assert pub["ok"]
    _metered(monkeypatch)
    r2 = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=50, now=NOW)
    out = g.publish_lease(signed_lease=r2["lease"], expect_org_id=ORG)
    assert out["ok"] is False and "earlier launch on this host" in out["error"]
    assert read_credit_lease(os.environ["VIGIL_BASE_DIR"], r1["slug"]).signed_lease.document.nonce == r1["nonce"]


def test_concurrent_metered_publishes_on_one_host_let_one_through(monkeypatch):
    # the one-launch check, the grant and the lease write are one step per host: a second publish that starts while
    # the first is between its check and its lease write waits for it, then sees it and is refused
    import threading
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r1, g, _ = _reserve(s, publish=False)
    r2 = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=50, now=NOW)
    real = LaunchGate._publish_model_grant
    seen: dict = {}

    def other(out=seen):
        out["r2"] = LaunchGate(s).publish_lease(signed_lease=r2["lease"], expect_org_id=ORG)

    def interleaved(self, doc, kp):
        if str(doc.nonce) == r1["nonce"] and "t" not in seen:
            seen["t"] = threading.Thread(target=other)
            seen["t"].start()
            seen["t"].join(timeout=1.0)
            seen["waited"] = seen["t"].is_alive()                        # held off by the first publish's lock
        return real(self, doc, kp)
    monkeypatch.setattr(LaunchGate, "_publish_model_grant", interleaved)
    out1 = g.publish_lease(signed_lease=r1["lease"], expect_org_id=ORG)
    seen["t"].join(timeout=10)
    assert out1["ok"] and seen["waited"] is True
    assert seen["r2"]["ok"] is False and "earlier launch on this host" in seen["r2"]["error"]
    assert read_credit_lease(os.environ["VIGIL_BASE_DIR"], r1["slug"]).signed_lease.document.nonce == r1["nonce"]


def test_a_flat_publish_takes_no_lock(monkeypatch):
    def no_lock(*a, **k):
        raise AssertionError("a flat-only publish must not take the metering lock")
    monkeypatch.setattr(LaunchGate, "_publish_lock", staticmethod(no_lock))
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, _r, _g, pub = _reserve(s)
    assert pub["ok"] and not config.MODEL_METER_DIR.exists()


def test_a_run_armed_late_keeps_its_model_access_past_the_lease_window(monkeypatch):
    from sigil.governor.identity import owner_pubkey
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, _g, pub = _reserve(s)
    base = os.environ["VIGIL_BASE_DIR"]
    lease = read_credit_lease(base, r["slug"]).signed_lease.document
    token = read_model_grant(base, r["slug"], expect_nonce=r["nonce"]).token
    clock = {"t": lease.not_after.timestamp() - 60}                      # armed a minute before the window closes
    cfg = gw.GatewayConfig(api_key="sk-dummy", owner_pubkey=owner_pubkey(), meter_dir=config.MODEL_METER_DIR,
                           clock=lambda: clock["t"])
    gate = gw.ModelGateway(cfg)
    try:
        assert gate.authenticate({"x-api-key": token}).meter_id == meter_id(r["slug"], r["nonce"])
        clock["t"] = lease.not_after.timestamp() + 3_000                 # still running after the window
        assert gate.authenticate({"x-api-key": token}).meter_id == meter_id(r["slug"], r["nonce"])
        clock["t"] = lease.not_before.timestamp() + MAX_GRANT_LIFETIME_S # the grant itself is still bounded
        with pytest.raises(gw._Refusal):
            gate.authenticate({"x-api-key": token})
    finally:
        gate.stop()
        gate.meter.shutdown()


def _spool():
    spool = tempfile.mkdtemp()
    for sub in ("incoming", "working", "rejected"):
        os.makedirs(os.path.join(spool, sub))
    return spool


LATER = NOW + 8 * 3600 + 2 * 86400                                     # past the lease window + the sweep TTL


def test_the_abandoned_sweep_refunds_a_metered_launch_vigil_lost_and_reports_its_spend(monkeypatch):
    """No pause marker: the customer did not pause it, so the run was lost on VIGIL's side — refunded in full, with
    the meter's confirmed spend reported (the spend the refund leaves VIGIL paying)."""
    from sigil.ops_sweeps import sweep_abandoned_reservations
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r, g, pub = _reserve(s)
    assert pub["ok"]
    _spend(r, USAGE, USAGE_COST)
    spool = _spool()
    seen = sweep_abandoned_reservations(g, now=LATER, ttl_s=86400, completion_spool=spool)["items"]
    assert [(x["status"], x["paused"], x["metered_cost_nano"], x["metered_requests"]) for x in seen] == [
        ("abandoned", False, USAGE_COST, 1)]
    done = sweep_abandoned_reservations(g, now=LATER, ttl_s=86400, apply=True, completion_spool=spool)["items"]
    assert [(x["status"], x["refunded"], x["metered_cost_nano"]) for x in done] == [("refunded", 900, USAGE_COST)]
    assert _closed(r) and _avail(s) == 1_000


def test_a_metered_launch_the_customer_paused_and_never_resumed_is_charged_for_what_it_used(monkeypatch):
    """Owner decision 2026-11-13: paused and never resumed = charged for what it used (54 credits here), the rest of
    the reservation refunded; the meter is closed so nothing more can be spent."""
    from sigil.ops_sweeps import sweep_abandoned_reservations
    from vigil_integration.live.credit_lease_pause import record_lease_pause
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r, g, pub = _reserve(s)
    assert pub["ok"]
    _spend(r, USAGE, USAGE_COST)
    record_lease_pause(os.environ["VIGIL_BASE_DIR"], r["slug"], r["nonce"])
    spool = _spool()
    seen = sweep_abandoned_reservations(g, now=LATER, ttl_s=86400, completion_spool=spool)["items"]
    assert [(x["status"], x["paused"]) for x in seen] == [("abandoned", True)]
    done = sweep_abandoned_reservations(g, now=LATER, ttl_s=86400, apply=True, completion_spool=spool)["items"]
    assert [(x["status"], x["charged"], x["refunded"], x["metered_cost_nano"]) for x in done] == [
        ("charged_paused", 54, 846, USAGE_COST)]
    assert _closed(r) and _avail(s) == 1_000 - 54
    again = sweep_abandoned_reservations(g, now=LATER, ttl_s=86400, apply=True, completion_spool=spool)["items"]
    assert again == [] and _avail(s) == 1_000 - 54                     # settled exactly once


def test_a_paused_metered_launch_that_used_nothing_is_refunded(monkeypatch):
    """Charged for what it used: a paused launch with no model request and no confirmed spend (it may never have
    started, e.g. the worker was down) used nothing, so it is refunded; the floor covers a run's start-up only."""
    from sigil.ops_sweeps import sweep_abandoned_reservations
    from vigil_integration.live.credit_lease_pause import record_lease_pause
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r, g, _pub = _reserve(s)
    record_lease_pause(os.environ["VIGIL_BASE_DIR"], r["slug"], r["nonce"])
    done = sweep_abandoned_reservations(g, now=LATER, ttl_s=86400, apply=True, completion_spool=_spool())["items"]
    assert [(x["status"], x["refunded"]) for x in done] == [("refunded", 900)]
    assert _avail(s) == 1_000 and _closed(r)


def test_a_paused_launch_with_one_request_and_no_confirmed_spend_pays_the_floor(monkeypatch):
    """A request was made (the run started) but its spend was never confirmed: the run's start-up floor applies."""
    from sigil.ops_sweeps import sweep_abandoned_reservations
    from vigil_integration.live.credit_lease_pause import record_lease_pause
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r, g, _pub = _reserve(s)
    _spend(r, mm.Usage(), 0, held=10 ** 9)
    record_lease_pause(os.environ["VIGIL_BASE_DIR"], r["slug"], r["nonce"])
    done = sweep_abandoned_reservations(g, now=LATER, ttl_s=86400, apply=True, completion_spool=_spool())["items"]
    floor = mm.run_floor_credits()
    assert [(x["status"], x["charged"]) for x in done] == [("charged_paused", floor)]
    assert _avail(s) == 1_000 - floor


def test_a_paused_charge_bills_only_confirmed_spend(monkeypatch):
    from sigil.ops_sweeps import sweep_abandoned_reservations
    from vigil_integration.live.credit_lease_pause import record_lease_pause
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r, g, _pub = _reserve(s)
    _spend(r, USAGE, USAGE_COST, held=10 ** 9)            # $1 VIGIL cannot prove: never the customer's
    record_lease_pause(os.environ["VIGIL_BASE_DIR"], r["slug"], r["nonce"])
    done = sweep_abandoned_reservations(g, now=LATER, ttl_s=86400, apply=True, completion_spool=_spool())["items"]
    assert [(x["status"], x["charged"]) for x in done] == [("charged_paused", 54)]


def test_a_pause_held_by_another_launch_of_the_slug_is_not_this_launchs(monkeypatch):
    """The pause marker is per slug and holds nonces: a pause of an earlier launch on the same slug never makes this
    launch 'paused' (it is refunded as a run VIGIL lost)."""
    from sigil.ops_sweeps import sweep_abandoned_reservations
    from vigil_integration.live.credit_lease_pause import record_lease_pause
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r, g, _pub = _reserve(s)
    _spend(r, USAGE, USAGE_COST)
    record_lease_pause(os.environ["VIGIL_BASE_DIR"], r["slug"], "an-earlier-nonce")
    done = sweep_abandoned_reservations(g, now=LATER, ttl_s=86400, apply=True, completion_spool=_spool())["items"]
    assert [(x["status"], x["refunded"]) for x in done] == [("refunded", 900)]


def _late_resume(monkeypatch, *, spend=True):
    """A metered launch the customer paused inside its window and lifted only after the window closed."""
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, g, _pub = _reserve(s)
    if spend:
        _spend(r, USAGE, USAGE_COST)
    assert g.pause_launch(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    res = g.resume_launch(signed_lease=r["lease"], expect_org_id=ORG, now=NOW + 9 * 3600)
    assert res["ok"] and res.get("expired") is True
    return s, owner, r, g


def test_lifting_a_pause_after_the_window_closed_still_charges_what_was_used(monkeypatch):
    from sigil.ops_sweeps import sweep_abandoned_reservations
    from vigil_integration.live.credit_lease_pause import is_lease_paused
    s, _owner, r, g = _late_resume(monkeypatch)
    assert not is_lease_paused(os.environ["VIGIL_BASE_DIR"], r["slug"], r["nonce"])   # the halt is lifted
    done = sweep_abandoned_reservations(g, now=LATER, ttl_s=86400, apply=True, completion_spool=_spool())["items"]
    assert [(x["status"], x["charged"], x["refunded"]) for x in done] == [("charged_paused", 54, 846)]
    assert _avail(s) == 1_000 - 54


def test_a_late_lifted_pause_whose_re_drive_fails_is_charged_by_the_drain(monkeypatch):
    s, owner, r, _g = _late_resume(monkeypatch)
    assert _settle(s, owner, r, "failed")["settled"] == 1
    assert _avail(s) == 1_000 - 54 and _closed(r)


def test_a_late_lifted_pause_that_used_nothing_is_refunded_everywhere(monkeypatch):
    from sigil.ops_sweeps import sweep_abandoned_reservations
    s, owner, r, g = _late_resume(monkeypatch, spend=False)
    done = sweep_abandoned_reservations(g, now=LATER, ttl_s=86400, apply=True, completion_spool=_spool())["items"]
    assert [(x["status"], x["refunded"]) for x in done] == [("refunded", 900)] and _avail(s) == 1_000
    s2, owner2, r2, _g2 = _late_resume(monkeypatch, spend=False)
    assert _settle(s2, owner2, r2, "failed")["settled"] == 1 and _avail(s2) == 1_000


def test_a_pause_lifted_inside_the_window_leaves_no_charge_record(monkeypatch):
    """Resumed in time: the launch is runnable again, so nothing records it as held — a later loss is VIGIL's."""
    from sigil.ops_sweeps import sweep_abandoned_reservations
    from vigil_integration.live.credit_lease_pause import paused_past_expiry
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, g, _pub = _reserve(s)
    _spend(r, USAGE, USAGE_COST)
    assert g.pause_launch(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    res = g.resume_launch(signed_lease=r["lease"], expect_org_id=ORG, now=NOW + 60)
    assert res["ok"] and "expired" not in res
    assert paused_past_expiry(os.environ["VIGIL_BASE_DIR"], r["slug"], r["nonce"]) is False
    done = sweep_abandoned_reservations(g, now=LATER, ttl_s=86400, apply=True, completion_spool=_spool())["items"]
    assert [(x["status"], x["refunded"]) for x in done] == [("refunded", 900)]


def test_a_failure_after_a_pause_lifted_inside_the_window_is_free(monkeypatch):
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, g, _pub = _reserve(s)
    _spend(r, USAGE, USAGE_COST)
    assert g.pause_launch(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    assert g.resume_launch(signed_lease=r["lease"], expect_org_id=ORG, now=NOW + 60)["ok"]
    assert _settle(s, owner, r, "failed")["settled"] == 1
    assert _avail(s) == 1_000                                            # VIGIL's failure: free


def test_an_unreadable_late_resume_record_settles_nothing_and_refuses_the_resume(monkeypatch):
    from sigil.ops_sweeps import sweep_abandoned_reservations
    from vigil_integration.live import credit_lease_pause as clp
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, g, _pub = _reserve(s)
    _spend(r, USAGE, USAGE_COST)
    rec = clp._past_expiry_path(os.environ["VIGIL_BASE_DIR"], r["slug"])
    rec.parent.mkdir(parents=True, exist_ok=True)
    rec.write_text("{not json", encoding="utf-8")
    assert g.pause_launch(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    res = g.resume_launch(signed_lease=r["lease"], expect_org_id=ORG, now=NOW + 9 * 3600)
    assert not res["ok"]                                                  # never erase the evidence it cannot keep
    assert clp.is_lease_paused(os.environ["VIGIL_BASE_DIR"], r["slug"], r["nonce"])
    done = sweep_abandoned_reservations(g, now=LATER, ttl_s=86400, apply=True, completion_spool=_spool())["items"]
    assert [x["status"] for x in done] == ["charged_paused"]              # still paused: charged by the marker
    s2 = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner2, r2, g2, _pub2 = _reserve(s2)
    _spend(r2, USAGE, USAGE_COST)
    rec2 = clp._past_expiry_path(os.environ["VIGIL_BASE_DIR"], r2["slug"])
    rec2.parent.mkdir(parents=True, exist_ok=True)
    rec2.write_text("{not json", encoding="utf-8")
    done2 = sweep_abandoned_reservations(g2, now=LATER, ttl_s=86400, apply=True, completion_spool=_spool())["items"]
    assert [x["status"] for x in done2] == ["pause_unknown"]
    assert _settle(s2, owner2, r2, "failed")["settled"] == 0 and _avail(s2) == 100   # the drain defers too


def test_a_paused_charge_never_exceeds_the_reservation(monkeypatch):
    """Confirmed use worth more than the reservation is charged the reservation, never more (and reported so)."""
    from sigil.ops_sweeps import sweep_abandoned_reservations
    from vigil_integration.live.credit_lease_pause import record_lease_pause
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r, g, _pub = _reserve(s)
    _spend(r, USAGE, USAGE_COST * 20)                                    # ~1065 credits of use against 900 reserved
    record_lease_pause(os.environ["VIGIL_BASE_DIR"], r["slug"], r["nonce"])
    done = sweep_abandoned_reservations(g, now=LATER, ttl_s=86400, apply=True, completion_spool=_spool())["items"]
    assert [(x["status"], x["charged"], x["refunded"]) for x in done] == [("charged_paused", 900, 0)]
    assert _avail(s) == 1_000 - 900


def test_an_unreadable_pause_state_settles_nothing(monkeypatch):
    """Cannot tell whether the customer paused it: neither charge nor refund — reported for a human."""
    from sigil.ops_sweeps import sweep_abandoned_reservations
    from vigil_integration.live.credit_lease_pause import pause_path
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r, g, _pub = _reserve(s)
    _spend(r, USAGE, USAGE_COST)
    p = pause_path(os.environ["VIGIL_BASE_DIR"], r["slug"])
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{not json", encoding="utf-8")                          # a corrupt marker
    done = sweep_abandoned_reservations(g, now=LATER, ttl_s=86400, apply=True, completion_spool=_spool())["items"]
    assert [x["status"] for x in done] == ["pause_unknown"]
    assert _avail(s) == 100 and not _closed(r)                           # the 900 reservation is still held


def test_a_paused_charge_waits_on_its_pricing_configuration(monkeypatch):
    from sigil.ops_sweeps import sweep_abandoned_reservations
    from vigil_integration.live.credit_lease_pause import record_lease_pause
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r, g, _pub = _reserve(s)
    _spend(r, USAGE, USAGE_COST)
    record_lease_pause(os.environ["VIGIL_BASE_DIR"], r["slug"], r["nonce"])
    monkeypatch.delenv(mm.MARGIN_ENV)                                     # the margin is unset at sweep time
    done = sweep_abandoned_reservations(g, now=LATER, ttl_s=86400, apply=True, completion_spool=_spool())["items"]
    assert [x["status"] for x in done] == ["deferred_config"]
    assert _avail(s) == 100                                              # nothing settled; the next pass retries


def test_a_flat_launch_paused_and_abandoned_is_refunded(monkeypatch):
    """A flat launch has no meter, so what it used cannot be measured: refunded in full whatever its pause state."""
    from sigil.ops_sweeps import sweep_abandoned_reservations
    from vigil_integration.live.credit_lease_pause import record_lease_pause
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r, g, _pub = _reserve(s)
    record_lease_pause(os.environ["VIGIL_BASE_DIR"], r["slug"], r["nonce"])
    done = sweep_abandoned_reservations(g, now=LATER, ttl_s=86400, apply=True, completion_spool=_spool())["items"]
    assert [(x["status"], x["refunded"]) for x in done] == [("refunded", 900)]
    assert _avail(s) == 1_000


def test_the_abandoned_sweep_reports_no_metered_spend_for_a_flat_launch():
    from sigil.ops_sweeps import sweep_abandoned_reservations
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r, g, pub = _reserve(s)
    spool = tempfile.mkdtemp()
    for sub in ("incoming", "working", "rejected"):
        os.makedirs(os.path.join(spool, sub))
    items = sweep_abandoned_reservations(g, now=NOW + 8 * 3600 + 2 * 86400, ttl_s=86400,
                                         completion_spool=spool)["items"]
    assert [x["status"] for x in items] == ["abandoned"] and not any(k.startswith("metered") for k in items[0])
    assert not config.MODEL_METER_DIR.exists()


def test_an_unpriced_run_model_refuses_the_publish(monkeypatch):
    _metered(monkeypatch)
    monkeypatch.setenv("VIGIL_RUN_MODEL", "claude-unpriced-1")
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r, _g, pub = _reserve(s)
    assert pub["ok"] is False and read_model_grant(os.environ["VIGIL_BASE_DIR"], r["slug"]) is None


def test_a_retryable_settle_refusal_defers_the_completion(monkeypatch):
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, _g, _pub = _reserve(s)
    calls = []

    def busy_once(self, slug, nonce, now_ts):
        calls.append(1)
        return {"ok": False, "retry": True, "error": "in flight"} if len(calls) == 1 else None
    monkeypatch.setattr(LaunchGate, "_close_model_meter", busy_once)
    w = _watcher(s, owner, r, "completed")
    out = w.drain()
    assert (out["settled"], out["rejected"], out.get("deferred")) == (0, 0, 1) and _avail(s) == 100
    assert "deferred_config" not in out                                  # a transient wait is not an alarm
    assert w.drain()["settled"] == 1


def test_the_doctor_and_the_cockpit_read_the_flags_alike():
    from vigil_integration import doctor
    assert doctor._AFFIRMATIVE == config._OIDC_AFFIRMATIVE


@pytest.mark.parametrize("path", ["cancel", "sweep"])
def test_a_broken_meter_refuses_every_settle_path(monkeypatch, path):
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _owner, r, g, _pub = _reserve(s, publish=(path == "sweep"))
    _spend(r, USAGE, USAGE_COST)
    _spend(r, USAGE, USAGE_COST)
    p = config.MODEL_METER_DIR / f"{meter_id(r['slug'], r['nonce'])}.jsonl"
    p.write_text("\n".join(p.read_text().splitlines()[1:]) + "\n")
    out = g.settle_launch(signed_lease=r["lease"], consumed_units=0, now=NOW, expect_org_id=ORG)
    assert out["ok"] is False and "model meter" in out["error"] and _avail(s) == 100
    assert not out.get("retry")                                          # a broken meter needs a human, not a retry


def test_a_meter_that_cannot_be_written_defers_the_settle(monkeypatch):
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, _g, _pub = _reserve(s)

    def full(self, mid, *, now):
        raise OSError("no space left on device")
    monkeypatch.setattr(gw.GrantMeter, "close", full)
    out = _settle(s, owner, r, "completed")
    assert (out["settled"], out["rejected"], out.get("deferred")) == (0, 0, 1) and _avail(s) == 100
    direct = _g.settle_launch(signed_lease=r["lease"], consumed_units=0, now=NOW)        # a sweep: retryable too
    assert direct["ok"] is False and direct.get("retry") is True


def test_the_gateway_settings_parse(monkeypatch):
    assert (config.model_gateway_port(), config.model_gateway_url()) == (8742, "http://127.0.0.1:8742")
    for raw, port in (("9001", 9001), ("0", 8742), ("65536", 8742), ("x", 8742), (" 1 ", 1)):
        monkeypatch.setenv("VIGIL_MODEL_GATEWAY_PORT", raw)
        assert config.model_gateway_port() == port, raw
    monkeypatch.setenv("VIGIL_RUN_MODEL", " claude-x ")
    assert config.run_model() == "claude-x"


def test_a_request_in_flight_defers_the_settle(monkeypatch):
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, g, _pub = _reserve(s)
    live = gw.GrantMeter(config.MODEL_METER_DIR, gateway=True)          # the running gateway
    try:
        _spend(r, USAGE, USAGE_COST, meter=live)
        grant = _grant(r, "2")
        rid, _res, reason = live.reserve(grant, 10 ** 6, 25_000, now=NOW)  # a second request, still in flight
        assert reason == ""
        w = _watcher(s, owner, r, "completed")
        out = w.drain()
        assert (out["settled"], out["rejected"], out.get("deferred")) == (0, 0, 1), out
        assert len(list(w.incoming.glob("*.json"))) == 1 and _avail(s) == 100   # back in incoming; nothing moved
        assert live.reserve(grant, 10 ** 6, 25_000, now=NOW)[2] == "closed"      # but admission already stopped
        busy = g.settle_launch(signed_lease=r["lease"], consumed_units=0, now=NOW)  # nor can a sweep refund it
        assert busy["ok"] is False and busy.get("retry") is True and "in flight" in busy["error"]
        live.commit(grant, rid, USAGE, USAGE_COST, request_id="r2", now=NOW)
        out = w.drain()
        assert out["settled"] == 1 and "deferred" not in out, out
        assert _avail(s) == 1_000 - 107                                    # both responses: $0.5325 x 2 -> 107
    finally:
        live.shutdown()


def test_an_unset_cancel_policy_settles_a_cancel_metered(monkeypatch):
    """Owner decision 2026-11-13: unset means a cancelled run pays for what it used (54 credits here)."""
    _metered(monkeypatch, cancel=None)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, _g, pub = _reserve(s)
    assert pub["ok"]                                                     # an unset policy no longer refuses the publish
    _spend(r, USAGE, USAGE_COST)
    assert _settle(s, owner, r, "canceled")["settled"] == 1 and _avail(s) == 1_000 - 54


def test_a_mistyped_policy_at_settle_defers_it(monkeypatch):
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, _g, _pub = _reserve(s)
    _spend(r, USAGE, USAGE_COST)
    monkeypatch.setenv(mm.CANCEL_ENV, "free")                            # a typo never silently picks a policy
    w = _watcher(s, owner, r, "canceled")
    assert w.drain()["deferred"] == 1 and _avail(s) == 100
    monkeypatch.setenv(mm.CANCEL_ENV, "refund")
    assert w.drain()["settled"] == 1 and _avail(s) == 1_000


def test_an_unset_margin_at_settle_defers_a_charge_but_not_a_failure(monkeypatch):
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, _g, _pub = _reserve(s)
    _spend(r, USAGE, USAGE_COST)
    monkeypatch.delenv(mm.MARGIN_ENV)
    out = _settle(s, owner, r, "completed")
    assert out["deferred"] == 1 and out["deferred_config"] == 1 and _avail(s) == 100   # a configuration wait: alarm
    assert _settle(s, owner, r, "failed")["settled"] == 1 and _avail(s) == 1_000   # a failed run needs no price


def test_the_settle_drain_fails_its_unit_while_a_charge_waits_on_pricing(monkeypatch, tmp_path, capsys):
    # a charge waiting on the pricing configuration never clears by retrying: the unit fails (the dead-man alarms);
    # a transient wait (a request still in flight) alone exits 0
    import types
    from sigil import cli
    from sigil.inbound import completion_spool as cs
    owner = ensure_owner_keypair()
    gov = generate_keypair()
    deleg = delegate_offense_governance(
        owner, authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=gov.public_key_b64)],
        threshold=1, scope="*", not_after=9_000_000_000)
    dfile = tmp_path / "delegation.json"
    dfile.write_text(deleg.model_dump_json(), encoding="utf-8")
    results = iter([{"settled": 0, "noop": 0, "rejected": 0, "deduped": 0, "deferred": 1, "deferred_config": 1},
                    {"settled": 0, "noop": 0, "rejected": 0, "deduped": 0, "deferred": 1}])

    class _Watcher:
        def __init__(self, *a, **k):
            self.rejected = tmp_path / "rejected"

        def drain(self):
            return next(results)
    monkeypatch.setattr(cs, "CompletionSpoolWatcher", _Watcher)
    a = types.SimpleNamespace(spool=str(tmp_path), base_dir=str(tmp_path), delegation=str(dfile), scope="*",
                              settle_cmd="drain", interval=2.0)
    with pytest.raises(SystemExit) as ei:
        cli.cmd_settle_drain(a)
    assert ei.value.code == 1 and "wait on the pricing configuration" in capsys.readouterr().err
    cli.cmd_settle_drain(a)                                              # transient only: no exit


@pytest.mark.parametrize("name", ["VIGIL_BILLING_MARKUP_K", "VIGIL_MARGIN_MULTIPLIER_K"])
def test_flat_billing_ignores_a_retired_pricing_setting(monkeypatch, name):
    # the refusal guards metered pricing only: the default (flat) launch and settle never read a pricing setting
    monkeypatch.setenv(name, "2")
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, _g, pub = _reserve(s)
    assert pub["ok"] and read_model_grant(os.environ["VIGIL_BASE_DIR"], r["slug"]) is None
    assert _settle(s, owner, r, "completed")["settled"] == 1 and _avail(s) == 100
    assert not config.MODEL_METER_DIR.exists()


@pytest.mark.parametrize("name", ["VIGIL_BILLING_MARKUP_K", "VIGIL_MARGIN_MULTIPLIER_K"])
def test_a_retired_pricing_setting_at_settle_defers_a_charge(monkeypatch, name):
    # the margin is the only pricing input: a stale second knob refuses to price, so the charge waits (it is not
    # settled on a guess) until the setting is removed
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, _g, _pub = _reserve(s)
    _spend(r, USAGE, USAGE_COST)
    monkeypatch.setenv(name, "2")
    assert _settle(s, owner, r, "completed")["deferred"] == 1 and _avail(s) == 100
    monkeypatch.delenv(name)
    assert _settle(s, owner, r, "completed")["settled"] == 1


@pytest.mark.parametrize("usage, cost, charged", [
    (mm.Usage(), 0, 25),                                                 # nothing used: the floor
    (mm.Usage(output_tokens=10 ** 6), 25_000 * 10 ** 6, 900),            # $25 x 2 = 5,000 credits: the clamp
])
def test_the_floor_and_the_clamp_hold(monkeypatch, usage, cost, charged):
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, _g, _pub = _reserve(s)
    if cost:
        _spend(r, usage, cost)
    assert _settle(s, owner, r, "completed")["settled"] == 1
    assert _avail(s) == 1_000 - charged


def test_a_corrupt_meter_refuses_the_settle(monkeypatch):
    _metered(monkeypatch)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    owner, r, _g, _pub = _reserve(s)
    _spend(r, USAGE, USAGE_COST)
    _spend(r, USAGE, USAGE_COST)
    p = config.MODEL_METER_DIR / f"{meter_id(r['slug'], r['nonce'])}.jsonl"
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[1:]) + "\n")                           # the first line is gone
    out = _settle(s, owner, r, "completed")
    assert out["settled"] == 0 and out["rejected"] == 1
    assert _avail(s) == 100                                              # nothing refunded or charged on a guess


def _free_port():
    import socket
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        return sk.getsockname()[1]


def test_the_cockpit_starts_the_gateway_once_from_the_environment(monkeypatch, caplog):
    ensure_owner_keypair()
    monkeypatch.setenv("SIGIL_ANTHROPIC_API_KEY", "sk-ant-test")
    port = _free_port()
    monkeypatch.setenv("VIGIL_MODEL_GATEWAY_PORT", str(port))
    assert gw.start_from_env() is None                                   # disabled: nothing listens, key or not
    monkeypatch.setenv("VIGIL_MODEL_GATEWAY_ENABLED", "1")
    monkeypatch.delenv("SIGIL_ANTHROPIC_API_KEY")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert gw.start_from_env() is None and "provider key" in caplog.text  # no key: not started, logged
    monkeypatch.setenv("SIGIL_ANTHROPIC_API_KEY", "sk-ant-test")
    for name, bad in (("VIGIL_GATEWAY_TENANT_CONCURRENCY", "0"), ("VIGIL_GATEWAY_GLOBAL_CONCURRENCY", "x"),
                      ("VIGIL_GATEWAY_GLOBAL_CONCURRENCY", "+4"), ("VIGIL_GATEWAY_TENANT_CONCURRENCY", "4_0"),
                      ("VIGIL_GATEWAY_DAILY_LIMIT_USD", "-1"), ("VIGIL_GATEWAY_DAILY_LIMIT_USD", "nan")):
        monkeypatch.setenv(name, bad)
        assert gw.start_from_env() is None, (name, bad)                   # a refused limit: not started
        monkeypatch.delenv(name)
    monkeypatch.setenv("VIGIL_GATEWAY_TENANT_CONCURRENCY", "2")
    monkeypatch.setenv("VIGIL_GATEWAY_DAILY_LIMIT_USD", "250.50")
    server = gw.start_from_env()
    try:
        assert server is not None and server.server_address == ("127.0.0.1", port)
        cfg = server.gateway.config
        assert (cfg.tenant_concurrency, cfg.global_concurrency, cfg.daily_limit_nano) == (2, 32, 250_500_000_000)
        assert cfg.meter_dir == config.MODEL_METER_DIR and cfg.egress_check is not None
        assert cfg.api_key == "sk-ant-test"
        assert gw.start_from_env() is server                              # once per process and port
        monkeypatch.setenv("VIGIL_MODEL_GATEWAY_PORT", str(_free_port()))
        assert gw.start_from_env() is None and "already metering" in caplog.text   # one gateway per meter dir
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
            gw._RUNNING.clear()


def test_the_gateway_needs_the_owner_key_to_verify_grants(monkeypatch):
    from sigil.governor import identity
    monkeypatch.setenv("SIGIL_ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setattr(identity, "owner_pubkey", lambda: None)
    with pytest.raises(ValueError, match="owner public key"):
        gw.config_from_env()


def test_the_cockpit_survives_any_gateway_start_failure(monkeypatch, caplog):
    monkeypatch.setenv("VIGIL_MODEL_GATEWAY_ENABLED", "1")
    monkeypatch.setenv("VIGIL_MODEL_GATEWAY_PORT", str(_free_port()))

    def broken():
        raise TypeError("a meter line of the wrong shape")
    monkeypatch.setattr(gw, "config_from_env", broken)
    assert gw.start_from_env() is None and "not started" in caplog.text


def test_the_gateway_falls_back_to_the_plain_provider_key_name(monkeypatch):
    ensure_owner_keypair()
    monkeypatch.delenv("SIGIL_ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-plain")
    assert gw.config_from_env().api_key == "sk-ant-plain"


def test_the_meter_directory_is_in_every_backup():
    from sigil import backup
    assert "model_meter" in backup.CAPTURED_TOP_LEVEL and "model_meter" in backup._STATE_DIRS
