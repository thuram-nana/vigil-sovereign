"""Pricing design §0 W4 — worker-time and premium-API metering on the same meter as the AI units.

A metered run accrues two more kinds of charge beside its model responses, both priced from the PUBLISHED rate card
in milli-credits and settled into the SAME owner-signed exact milli-credit settlement (W2c-1):

  * WORKER TIME (1 credit/minute, billed per second), measured on the SOVEREIGN side: the run's keyless worker only
    PINGS the gateway; the gateway's own clock measures the interval between pings and bills it, each interval bounded
    by the slot it reserved — so a stalled worker, a clock jump or a late ping can never bill more than the slots it
    reserved, and the worker can never self-report time. The first ping only reserves (bills 0); a run that stops
    pinging leaves its last slot uncommitted — VIGIL's cost (I9), never billed (``worker_open`` / ``worker`` lines).
  * PREMIUM external API calls: priced from the card's own ``premium`` line (an unpriced API is refused, never
    metered free), reserved against the prepaid allowance before the sovereign proxy forwards (``premium`` lines).

Pins:
  * worker time is the real elapsed between pings, bounded by the reserved slot; a backward clock bills 0;
  * the first and any un-committed (lapsed) slot are never billed;
  * a worker slot is refused once the prepaid allowance cannot cover it (the W3 credit stop);
  * a premium call is priced from the card and refused when unpriced or unaffordable;
  * worker + premium fold into ``charged_mc`` / ``pending_mc`` and ``charge_records``; a replay equals the live totals;
  * ``metered_use_mc`` sums AI + worker + premium, and that is what ``settle_launch`` keeps (exact, with the
    remainder); the statement shows each as its own priced line with the rate RECORDED with it;
  * the metered worker/premium charge is the PURE rate-card sum — the retired ``ENVELOPE_TOKENS_PER_CREDIT`` is never
    read (W2c-2 invariant);
  * ``charge_records`` on an AI-only meter is byte-identical to ``usage_records`` (the AI read path is unchanged);
  * two orgs never mix.

Mutation-verify targets (each neuter reds a NAMED test here):
  * forget to clamp a committed slot to the reserved seconds   -> test_worker_time_is_measured_and_bounded_by_the_slot
  * bill the first / an un-committed slot                       -> test_the_first_and_lapsed_worker_slots_are_never_billed
  * drop the worker allowance gate                              -> test_a_worker_slot_is_refused_when_the_allowance_is_short
  * meter an unpriced premium API instead of refusing           -> test_premium_is_priced_from_the_card_or_refused
  * drop the premium allowance gate                             -> test_premium_is_refused_when_the_allowance_is_short
  * metered_use_mc ignores worker / premium charges             -> test_worker_and_premium_settle_into_the_exact_settlement
  * worker / premium not folded into charged_mc on replay       -> test_a_replay_gives_the_live_worker_and_premium_totals
"""
from __future__ import annotations

import itertools
import json
import tempfile
import urllib.error
import urllib.request

import pytest

from sigil import config
from sigil import model_gateway as gw
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui import billing as ui_billing
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_core import generate_keypair
from vigil_core import model_metering as mm
from vigil_core.model_grant import STOP_CREDITS_EXHAUSTED, ModelGrant, encode_token, meter_id
from vigil_core.rate_card import DEFAULT_RATE_CARD, RateCardError, _card, rate_card

NOW = 2_000.0
OWNER = generate_keypair()
RUN_MODEL = mm.DEFAULT_RUN_MODEL        # the one priced run model (the gateway refuses a grant for an unpriced one)
TEST_MARGIN = "0.5"                      # a test fixture (markup 2), not a pricing decision
_iss = itertools.count(1)
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))

#: the published AI rates (credits per million tokens / per search), restated so a test card can change one rate
_AI_RATES = {"input_tokens": "1250", "output_tokens": "6250", "cache_read_tokens": "125",
             "cache_write_5m_tokens": "1563", "cache_write_1h_tokens": "2500", "web_searches": "2.5"}


def _card_doc(*, worker: str = "1", intel: str = "5") -> dict:
    """A rate-card document: the published AI rates, ``worker`` credits per worker-minute and one premium external API
    (Threat-intel lookups at ``intel`` credits per call). A test fixture of the card's SHAPE, not a pricing decision."""
    return {"ai": dict(_AI_RATES), "worker_minute": worker,
            "premium": {"intel_lookup": {"credits": intel, "per": 1, "label": "Threat-intel lookups"}}}


PREMIUM_CARD = _card(_card_doc(), what="test premium card")


def _grant(slug: str = "cust_x", nonce: str = "n-1", org: str = "org_a", *,
           not_after: float = NOW + 86_400) -> ModelGrant:
    return ModelGrant(grant_id="0" * 32, org_id=org, engagement_slug=slug, nonce=nonce, model=RUN_MODEL,
                      effort="high", cap_nano_usd=10 ** 13, not_after=not_after, issued_at=NOW - 60)


def _kinds(m, g):
    return [r["kind"] for r in m.charge_records(g.meter_id)]


# ----------------------------------------------------------------------------- worker-time measurement (meter level)

def test_worker_time_is_measured_and_bounded_by_the_slot(tmp_path):
    m = gw.GrantMeter(tmp_path, rate_card=DEFAULT_RATE_CARD)
    g = _grant()
    # beat 1 at t=0: opens a 60 s slot, bills nothing
    assert m.worker_heartbeat(g, slot_s=60, allowance_mc=None, now=0.0) == {
        "ok": True, "billed_seconds": 0, "opened": True, "exhausted": False}
    assert m.totals(g.meter_id).charged_mc == 0
    # beat 2 at t=30: commits min(30, 60) = 30 s -> 500 mc, opens the next slot
    out = m.worker_heartbeat(g, slot_s=60, allowance_mc=None, now=30.0)
    assert out["billed_seconds"] == 30 and out["opened"]
    assert m.totals(g.meter_id).charged_mc == DEFAULT_RATE_CARD.worker_line(30).amount_mc == 500
    # beat 3 after a 200 s STALL: commits min(200, 60) = 60 s -> the slot bound, never the full stall
    out = m.worker_heartbeat(g, slot_s=60, allowance_mc=None, now=230.0)
    assert out["billed_seconds"] == 60
    assert m.totals(g.meter_id).charged_mc == 500 + 1_000
    worker = [r for r in m.charge_records(g.meter_id) if r["kind"] == "worker"]
    assert [r["seconds"] for r in worker] == [30, 60] and sum(r["charge_mc"] for r in worker) == 1_500


def test_the_first_and_lapsed_worker_slots_are_never_billed(tmp_path):
    m = gw.GrantMeter(tmp_path, rate_card=DEFAULT_RATE_CARD)
    g = _grant()
    m.worker_heartbeat(g, slot_s=60, allowance_mc=None, now=0.0)       # opens slot 1 (bills 0)
    # the run stops here: slot 1 lapses, never committed -> no worker CHARGE line, nothing billed
    assert _kinds(m, g) == []
    t = m.totals(g.meter_id)
    assert t.charged_mc == 0 and t.pending_mc == DEFAULT_RATE_CARD.worker_line(60).amount_mc == 1_000


def test_a_backward_clock_bills_zero_never_negative(tmp_path):
    m = gw.GrantMeter(tmp_path, rate_card=DEFAULT_RATE_CARD)
    g = _grant()
    m.worker_heartbeat(g, slot_s=60, allowance_mc=None, now=100.0)
    out = m.worker_heartbeat(g, slot_s=60, allowance_mc=None, now=50.0)   # the clock went backwards
    assert out["billed_seconds"] == 0 and m.totals(g.meter_id).charged_mc == 0


def test_a_worker_slot_is_refused_when_the_allowance_is_short(tmp_path):
    m = gw.GrantMeter(tmp_path, rate_card=DEFAULT_RATE_CARD)
    g = _grant()
    # allowance 1,500 mc: slot 1 (1,000) fits; commit 30 s (500) then slot 2 (1,000) still fits (500+1,000<=1,500);
    # commit 30 s again (now 1,000 charged) then slot 3 needs 1,000 but 1,000+1,000 > 1,500 -> exhausted
    assert m.worker_heartbeat(g, slot_s=60, allowance_mc=1_500, now=0.0)["opened"]
    assert m.worker_heartbeat(g, slot_s=60, allowance_mc=1_500, now=30.0)["opened"]
    out = m.worker_heartbeat(g, slot_s=60, allowance_mc=1_500, now=60.0)
    assert out["billed_seconds"] == 30 and out["opened"] is False and out["exhausted"] is True
    assert m.totals(g.meter_id).charged_mc == 1_000       # the two committed slots, the third never opened


def test_a_worker_slot_counts_the_ai_requests_in_flight(tmp_path):
    """The allowance is SHARED: a model request still in flight holds its worst-case charge, so a worker slot that
    fits only by ignoring it is refused (never over-commit the prepaid allowance, I1 / I9)."""
    m = gw.GrantMeter(tmp_path, rate_card=DEFAULT_RATE_CARD)
    g = _grant()
    _rid, _res, why = m.reserve(g, 40 * 25_000, 25_000, now=NOW,
                                worst_mc=lambda t: DEFAULT_RATE_CARD.request_worst_mc(2_000, 0, t))
    assert why == ""
    inflight = m.totals(g.meter_id).pending_mc
    slot = DEFAULT_RATE_CARD.worker_line(60).amount_mc
    assert inflight > 0
    out = m.worker_heartbeat(g, slot_s=60, allowance_mc=inflight + slot - 1, now=0.0)
    assert out["opened"] is False and out["exhausted"] is True
    assert m.worker_heartbeat(g, slot_s=60, allowance_mc=inflight + slot, now=0.0)["opened"]


def test_a_closed_meter_refuses_a_heartbeat(tmp_path):
    m = gw.GrantMeter(tmp_path, rate_card=DEFAULT_RATE_CARD)
    g = _grant()
    m.worker_heartbeat(g, slot_s=60, allowance_mc=None, now=0.0)
    m.close(g.meter_id, now=30.0)
    assert m.worker_heartbeat(g, slot_s=60, allowance_mc=None, now=60.0) == {"ok": False, "reason": "closed"}


# ----------------------------------------------------------------------------------------- premium APIs (meter level)

def test_premium_is_priced_from_the_card_or_refused(tmp_path):
    m = gw.GrantMeter(tmp_path, rate_card=PREMIUM_CARD)
    g = _grant()
    out = m.commit_premium(g, "intel_lookup", 2, allowance_mc=None, now=NOW)
    assert out["ok"] and out["charge_mc"] == PREMIUM_CARD.premium_line("intel_lookup", 2).amount_mc == 10_000
    assert m.totals(g.meter_id).charged_mc == 10_000
    # an unpriced API: refused BEFORE anything is written (never metered free), the meter unchanged
    with pytest.raises(RateCardError):
        m.commit_premium(g, "no-such-api", 1, allowance_mc=None, now=NOW)
    assert _kinds(m, g) == ["premium"]
    rec = m.charge_records(g.meter_id)[0]
    assert rec["api"] == "intel_lookup" and rec["label"] == "Threat-intel lookups" and rec["calls"] == 2


def test_premium_is_refused_when_the_allowance_is_short(tmp_path):
    m = gw.GrantMeter(tmp_path, rate_card=PREMIUM_CARD)
    g = _grant()
    out = m.commit_premium(g, "intel_lookup", 2, allowance_mc=5_000, now=NOW)   # 2 calls = 10,000 mc > 5,000
    assert out == {"ok": False, "reason": "allowance"}
    assert _kinds(m, g) == []                              # reserve-before-forward: nothing written


# ---------------------------------------------------------------------------------- read paths (charge_records, replay)

def test_charge_records_ai_only_equals_usage_records(tmp_path):
    """The AI read path is unchanged: with no worker / premium lines, ``charge_records`` (minus its ``kind`` tag)
    is exactly ``usage_records`` — so every AI-only statement and settle is byte-identical."""
    m = gw.GrantMeter(tmp_path, rate_card=DEFAULT_RATE_CARD)
    g = _grant()
    rid, _res, why = m.reserve(g, 10 ** 6, 25_000, now=NOW)
    assert why == ""
    m.commit(g, rid, mm.Usage(input_tokens=1_000, output_tokens=200), 123, request_id="r", now=NOW)
    charge = [{k: v for k, v in r.items() if k != "kind"} for r in m.charge_records(g.meter_id)]
    assert charge == m.usage_records(g.meter_id)
    assert [r["kind"] for r in m.charge_records(g.meter_id)] == ["ai"]


def test_a_replay_gives_the_live_worker_and_premium_totals(tmp_path):
    m = gw.GrantMeter(tmp_path, rate_card=PREMIUM_CARD)
    g = _grant()
    m.worker_heartbeat(g, slot_s=60, allowance_mc=None, now=0.0)
    m.worker_heartbeat(g, slot_s=60, allowance_mc=None, now=45.0)      # 45 s -> 750 mc
    m.commit_premium(g, "intel_lookup", 1, allowance_mc=None, now=50.0)  # 5,000 mc
    live = m.totals(g.meter_id)
    disk = gw.GrantMeter(tmp_path).verify(g.meter_id)
    assert live.charged_mc == disk.charged_mc == 750 + 5_000
    # a fresh read-only meter sums the same charges (worker 750 + premium 5,000)
    assert sum(r["charge_mc"] for r in gw.GrantMeter(tmp_path).charge_records(g.meter_id)) == 5_750


def test_a_card_change_never_reprices_recorded_worker_or_premium_usage(monkeypatch):
    """Each worker / premium line records the rate that applied: when the owner later changes the card, the settle
    (``metered_use_mc``) and the statement keep the recorded amount and rate — past usage is never re-priced."""
    m = gw.GrantMeter(config.MODEL_METER_DIR, rate_card=PREMIUM_CARD)
    g = _grant("cust_rc", "n-rc")
    m.worker_heartbeat(g, slot_s=60, allowance_mc=None, now=0.0)
    m.worker_heartbeat(g, slot_s=60, allowance_mc=None, now=60.0)        # 60 s at 1 credit/min = 1,000 mc
    m.commit_premium(g, "intel_lookup", 1, allowance_mc=None, now=61.0)   # 1 call at 5 credits = 5,000 mc
    monkeypatch.setenv("VIGIL_RATE_CARD", json.dumps(_card_doc(worker="2", intel="9")))   # the owner changes the card
    assert LaunchGate.metered_use_mc("cust_rc", "n-rc") == 6_000                         # not 2,000 + 9,000
    shown = [ui_billing._charge_display(rec, rate_card()) for rec in m.charge_records(g.meter_id)]
    assert [(op, amt, lines[0]["rate"], lines[0]["rate_per"], lines[0]["credits"]) for lines, amt, op in shown] == [
        ("Scan-worker time", 1_000, "1.000", 60, "1.000"), ("Threat-intel lookups", 5_000, "5.000", 1, "5.000")]


# ------------------------------------------------------------------------- end to end: settle + statement (real path)

def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _org(store, org, host, *, credits):
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(org, org, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(org, "u", "operator", issued_at=float(next(_iss)))
    WalletRegistry(store).grant(org, credits, "trial", entry_id=f"trial:{org}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
    assert add_customer_target(host, org_id=org, store=store, now=NOW)["ok"]
    return LaunchGate(store)


def _launch(g, org, host, *, units=100):
    r = g.reserve_launch(requester="u", org_id=org, host=host, units=units, now=NOW)
    assert r["ok"], r
    assert g.publish_lease(signed_lease=r["lease"], expect_org_id=org)["ok"]
    return r


def _meter_for(r, org, card):
    return gw.GrantMeter(config.MODEL_METER_DIR, rate_card=card), _grant(r["slug"], r["nonce"], org)


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    for k in ("VIGIL_RATE_CARD", mm.MARGIN_ENV, mm.CANCEL_ENV, "VIGIL_SETTLE_SPINE_RECORD", *mm.OBSOLETE_PRICING_ENVS):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    # a metered publish mints the run's model grant, whose ceiling refuses to be built without this setting (it has no
    # default); the same labelled fixture as test_exact_settle — never the owner's value, and no customer charge reads it
    monkeypatch.setenv(mm.MARGIN_ENV, TEST_MARGIN)


def test_worker_and_premium_settle_into_the_exact_settlement(monkeypatch):
    monkeypatch.setenv("VIGIL_RATE_CARD", json.dumps(_card_doc()))
    card = rate_card()
    s = _store()
    g = _org(s, "org_a", "apme.cm", credits=100)
    r = _launch(g, "org_a", "apme.cm")
    m, grant = _meter_for(r, "org_a", card)
    # one AI response (80 output tokens -> 500 mc), 45 s of worker time (750 mc) and 1 premium call (5,000 mc)
    rid, _res, why = m.reserve(grant, 10 ** 6, 25_000, now=NOW)
    assert why == ""
    m.commit(grant, rid, mm.Usage(output_tokens=80), 1, request_id="r", now=NOW)
    m.worker_heartbeat(grant, slot_s=60, allowance_mc=None, now=NOW)
    m.worker_heartbeat(grant, slot_s=60, allowance_mc=None, now=NOW + 45)
    assert m.commit_premium(grant, "intel_lookup", 1, allowance_mc=None, now=NOW + 50)["ok"]
    gw.GrantMeter(config.MODEL_METER_DIR).close(meter_id(r["slug"], r["nonce"]), now=NOW + 60)
    # metered_use_mc sums AI (500) + worker (750) + premium (5,000) = 6,250 mc
    used = g.metered_use_mc(r["slug"], r["nonce"])
    assert used == 500 + 750 + 5_000 == 6_250
    out = g.settle_launch(signed_lease=r["lease"], consumed_units=0, consumed_mc=used, now=NOW + 60,
                          basis="completion:completed")
    assert out["ok"] and out["consumed_mc"] == 6_250 and out["net_spend"] == 6 and out["remainder_mc"] == 250
    b = WalletRegistry(s).balance("org_a")
    assert (b.available, b.remainder_mc) == (94, 250)      # 100 credits less 6.25 used
    # the statement shows each kind as its own priced line, summing to the same total
    usage = ui_billing.billing_usage(s, "org_a", trusted_pubkey=ensure_owner_keypair().public_key_b64,
                                     meter_dir=config.MODEL_METER_DIR)
    assert usage["amount_mc"] == 6_250
    (scan,) = usage["scans"]
    assert scan["requests"] == 1 and scan["amount_mc"] == 6_250        # one MODEL request; worker / premium are lines
    ops = {c["operation"]: c for c in usage["charges"]}
    assert set(ops) == {"AI analysis", "Scan-worker time", "Threat-intel lookups"}
    assert ops["Scan-worker time"]["credits"] == "0.750" and ops["Scan-worker time"]["lines"][0]["quantity"] == 45
    assert ops["Threat-intel lookups"]["credits"] == "5.000" and ops["Threat-intel lookups"]["lines"][0]["quantity"] == 1
    text = json.dumps(usage).lower()
    assert "claude" not in text and "opus" not in text and "usd" not in text and "estimat" not in text


def test_the_metered_worker_and_premium_charge_is_the_pure_rate_card_sum(monkeypatch):
    """W2c-2 invariant: the metered charge is the published rate card applied to the usage, with NO envelope factor —
    the retired ``ENVELOPE_TOKENS_PER_CREDIT`` is never read on the worker / premium path. Poison it and the charge
    is unchanged (if it were read, the amount would differ)."""
    import vigil_core
    monkeypatch.setattr(vigil_core, "ENVELOPE_TOKENS_PER_CREDIT", 1, raising=False)
    s = _store()
    g = _org(s, "org_a", "apme.cm", credits=100)
    r = _launch(g, "org_a", "apme.cm")
    m, grant = _meter_for(r, "org_a", DEFAULT_RATE_CARD)
    m.worker_heartbeat(grant, slot_s=60, allowance_mc=None, now=NOW)
    m.worker_heartbeat(grant, slot_s=60, allowance_mc=None, now=NOW + 60)   # 60 s -> exactly 1,000 mc = 1 credit
    gw.GrantMeter(config.MODEL_METER_DIR).close(meter_id(r["slug"], r["nonce"]), now=NOW + 90)
    assert g.metered_use_mc(r["slug"], r["nonce"]) == DEFAULT_RATE_CARD.worker_line(60).amount_mc == 1_000


def test_the_statement_is_tenant_scoped_for_worker_and_premium(monkeypatch):
    monkeypatch.setenv("VIGIL_RATE_CARD", json.dumps(_card_doc()))
    card = rate_card()
    s = _store()
    ga = _org(s, "org_a", "apme.cm", credits=100)
    _org(s, "org_b", "bpme.cm", credits=100)
    ra = _launch(ga, "org_a", "apme.cm")
    rb = _launch(LaunchGate(s), "org_b", "bpme.cm")
    ma, grant_a = _meter_for(ra, "org_a", card)
    ma.worker_heartbeat(grant_a, slot_s=60, allowance_mc=None, now=NOW)
    ma.worker_heartbeat(grant_a, slot_s=60, allowance_mc=None, now=NOW + 60)
    mb, grant_b = _meter_for(rb, "org_b", card)
    mb.commit_premium(grant_b, "intel_lookup", 3, allowance_mc=None, now=NOW)
    a = ui_billing.billing_usage(s, "org_a", trusted_pubkey=ensure_owner_keypair().public_key_b64,
                                 meter_dir=config.MODEL_METER_DIR)
    assert [c["scan"] for c in a["charges"]] == [ra["slug"]] and a["amount_mc"] == 1_000   # only org_a's worker time
    assert all(c["operation"] == "Scan-worker time" for c in a["charges"])


def test_a_paused_abandoned_run_is_charged_its_worker_time():
    """Through the REAL completion drain: a metered run held paused past its window ends FAILED and settles by the
    paused-and-abandoned rule (owner decision 2026-11-13: charged what it used). Worker time is use (W4): a run that
    accrued worker time but made no model request is charged it — never refunded as if it used nothing."""
    import os

    from sigil.governor.identity import delegate_offense_governance
    from sigil.inbound.completion_spool import CompletionSpoolWatcher
    from vigil_core import AuthorizerKey
    from vigil_integration.jobs.completion_signal import emit_completion_signal
    from vigil_integration.live.credit_lease_pause import record_lease_pause

    s = _store()
    g = _org(s, "org_a", "apme.cm", credits=100)
    r = _launch(g, "org_a", "apme.cm")                                    # holds all 100 credits
    m, grant = _meter_for(r, "org_a", DEFAULT_RATE_CARD)
    m.worker_heartbeat(grant, slot_s=60, allowance_mc=None, now=NOW)
    m.worker_heartbeat(grant, slot_s=60, allowance_mc=None, now=NOW + 60)   # 60 s = 1 credit; no model request
    base = os.environ["VIGIL_BASE_DIR"]
    record_lease_pause(base, r["slug"], r["nonce"])
    assert g.resume_launch(signed_lease=r["lease"], expect_org_id="org_a", now=NOW + 8 * 3600 + 2 * 86400)["expired"]
    owner = ensure_owner_keypair()
    gov = generate_keypair()
    deleg = delegate_offense_governance(
        owner, authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=gov.public_key_b64)],
        threshold=1, scope=r["slug"], not_after=9_000_000_000)
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="failed",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    w = CompletionSpoolWatcher(s, spool_dir=spool, owner_pubkey=owner.public_key_b64, delegation=deleg,
                               scope=r["slug"], base_dir=base, now_fn=lambda: NOW)
    assert w.drain()["settled"] == 1
    b = WalletRegistry(s).balance("org_a")
    assert (b.available, b.remainder_mc) == (99, 0)                       # 1 credit kept, 99 refunded


# ------------------------------------------------------------------- the gateway: ensure-allowance + the HTTP endpoint

class _FakeAllowance:
    """A stand-in for ``ui.launch_gate.LaunchAllowance``: a fixed allowance that cannot be extended (an empty
    wallet)."""

    def __init__(self, allowance_mc: int):
        self._mc = allowance_mc

    def allowance_mc(self, grant):
        return self._mc

    def available_credits(self, grant):
        return 0

    def extend(self, grant, credits):
        return {"ok": False, "insufficient": True}


def _cfg(meter_dir, clock, **kw):
    return gw.GatewayConfig(api_key="sk-x", owner_pubkey=OWNER.public_key_b64, meter_dir=meter_dir,
                            upstream="http://127.0.0.1:1", opener=_NO_PROXY, clock=lambda: clock["now"],
                            rate_card=DEFAULT_RATE_CARD, worker_slot_s=60, **kw)


def test_the_gateway_pauses_a_run_whose_wallet_cannot_cover_the_next_slot(tmp_path):
    clock = {"now": NOW}
    g = gw.ModelGateway(_cfg(tmp_path / "m", clock, allowance=_FakeAllowance(0), allowance_required=True))
    try:
        grant = _grant()
        with pytest.raises(gw._Refusal) as ei:
            g.worker_heartbeat(grant, now=clock["now"])
        assert (ei.value.status, ei.value.stop) == (403, STOP_CREDITS_EXHAUSTED)   # the W3 credit stop
        assert gw.GrantMeter(tmp_path / "m").charge_records(grant.meter_id) == []  # no slot opened, nothing billed
    finally:
        g.stop()
        g.meter.shutdown()


def test_the_gateway_refuses_worker_time_with_no_allowance_source_when_metered(tmp_path):
    clock = {"now": NOW}
    g = gw.ModelGateway(_cfg(tmp_path / "m", clock, allowance=None, allowance_required=True))
    try:
        with pytest.raises(gw._Refusal) as ei:
            g.worker_heartbeat(_grant(), now=clock["now"])
        assert ei.value.status == 529                                   # cannot check credits: never meter blind
    finally:
        g.stop()
        g.meter.shutdown()


def _serve(cfg):
    server, t = gw.start(cfg)
    server.serve_thread = t
    server.url = f"http://127.0.0.1:{server.server_address[1]}"
    return server


def _stop(server):
    server.shutdown()
    server.server_close()


def _beat(server, token):
    req = urllib.request.Request(server.url + gw.WORKER_HEARTBEAT_PATH, data=b"",
                                 headers={"x-api-key": token, "content-type": "application/json"}, method="POST")
    try:
        with _NO_PROXY.open(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_the_http_worker_heartbeat_endpoint_meters_time(tmp_path):
    clock = {"now": NOW}
    server = _serve(_cfg(tmp_path / "m", clock))        # allowance None, not required: worker time metered, uncapped
    try:
        grant = _grant()
        token = encode_token(grant, OWNER.private_key_b64)
        st, body = _beat(server, token)
        assert st == 200 and body["billed_seconds"] == 0 and body["next_slot_s"] == 60     # the first beat only opens
        clock["now"] = NOW + 30
        st, body = _beat(server, token)
        assert st == 200 and body["billed_seconds"] == 30                                   # the second commits 30 s
        recs = gw.GrantMeter(tmp_path / "m").charge_records(grant.meter_id)
        assert [r["kind"] for r in recs] == ["worker"] and recs[0]["seconds"] == 30
    finally:
        _stop(server)


def test_the_worker_heartbeat_path_mirrors_the_gateway():
    """The keyless worker cannot import the sovereign constant (FATAL-2), so it hard-codes the path: pin the mirror."""
    from vigil_integration.jobs import engage_worker
    assert engage_worker._WORKER_HEARTBEAT_PATH == gw.WORKER_HEARTBEAT_PATH == "/v1/vigil/worker/heartbeat"


def test_the_http_heartbeat_refuses_an_expired_grant(tmp_path):
    clock = {"now": NOW}
    server = _serve(_cfg(tmp_path / "m", clock))
    try:
        expired = encode_token(_grant(not_after=NOW - 1), OWNER.private_key_b64)
        st, body = _beat(server, expired)                 # worker time is bounded to the grant's lifetime (lease window)
        assert st == 403 and body["error"]["type"] == "permission_error" and "expired" in body["error"]["message"]
        assert gw.GrantMeter(tmp_path / "m").charge_records(_grant().meter_id) == []   # nothing metered
    finally:
        _stop(server)
