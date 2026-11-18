"""W3 (HANDOFF §11.6) — pause an assessment on insufficient credit; resume it after a top-up.

A METERED run whose prepaid allowance can no longer cover one model request is PARKED — not failed, not settled. The
model gateway first records the SOVEREIGN credit pause (the pause time + reason ``insufficient_credits``, and the
reversible halt marker every later step refuses) and only THEN refuses the request with the terminal credit stop (the
Anthropic-shaped 403 ``permission_error`` + ``x-vigil-stop: credits_exhausted`` the engine maps to ``CreditPaused``,
M1c-2b). A pause that cannot be recorded is refused as RETRYABLE instead, so no launch parks unrecorded.

Resume after a top-up checks the wallet now covers a model request, continues the lease with a FRESH window when the
8-hour one (and the run's model grant) ran out — under the SAME nonce, so the SAME model meter, grant id, reservation
and single-use floor (``continue_of`` = the nonce, ``issued_at`` kept) — and takes the first post-top-up allowance and
un-parks the launch in ONE settle-locked step (idempotent; a W5 billing hold refuses it). A launch not resumed within
``VIGIL_CREDIT_PAUSE_TTL_S`` (default 7 days) counted from the PAUSE is closed by the settle-drain / ops sweep and
charged exactly what it used — never earlier by the lease-window rule.

Real spine, real owner key, real seam files, the REAL LaunchGate / LaunchAllowance / model gateway (fake upstream on
loopback) / settle-drain expiry pass / ops sweep / provisioner. No real AI call, no real payment.

Mutation-verify targets (each reds the NAMED test):
  * the gateway stops without recording the pause          -> test_a_run_that_hits_the_allowance_floor_is_parked_not_settled
  * the gateway stops terminally although the record failed -> test_the_terminal_stop_waits_for_a_recorded_pause
  * record_credit_pause skips the halt marker               -> test_a_run_that_hits_the_allowance_floor_is_parked_not_settled
  * record_credit_pause pauses a flat launch                -> test_a_flat_launch_never_pauses_for_credit
  * the first pause time is overwritten                     -> test_the_first_pause_time_wins
  * the 7-day close ignores the pause time (window rule)    -> test_the_close_waits_for_the_pause_anchored_grace_then_charges_what_was_used
  * ops-sweep closes a launch still waiting for credit      -> test_the_ops_sweep_waits_out_a_credit_pause
  * the resume extension refuses the still-set halt         -> test_a_top_up_resumes_the_launch_on_the_same_meter
  * the resume extension skips "still credit-paused"        -> test_concurrent_resumes_take_exactly_one_allowance
  * the resume extension skips the end-of-wait check        -> test_the_locked_resume_step_refuses_once_the_wait_has_ended
  * resume skips its end-of-wait pre-check                  -> test_a_resume_at_the_end_of_the_wait_is_refused_and_nothing_is_continued
  * resume skips the wallet pre-check                       -> test_a_resume_without_enough_credit_changes_nothing
  * the un-park leaves the record / the halt                -> test_a_top_up_resumes_the_launch_on_the_same_meter
  * no continuation when the window closed                  -> test_a_pause_outliving_the_lease_window_and_the_grant_still_resumes
  * the continuation gets a fresh issued_at / no continue_of -> test_a_pause_outliving_the_lease_window_and_the_grant_still_resumes
  * resume judges expiry by the original window only        -> test_a_pause_outliving_the_lease_window_and_the_grant_still_resumes
  * a W5 billing hold read as a credit shortfall            -> test_a_credit_pause_is_not_a_billing_hold_nor_an_operator_pause
  * the notice ignores the tenant / a settled launch        -> test_the_paused_notice_is_tenant_scoped_carries_no_amount_and_ends_with_the_pause
"""
from __future__ import annotations

import itertools
import json
import os
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from sigil import config
from sigil import model_gateway as gw
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.identity import delegate_offense_governance, ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.inbound.completion_spool import CompletionSpoolWatcher
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import _RESUMED_EXPIRED_DETAIL, LaunchAllowance, LaunchGate
from sigil.ui.target_authorization import add_customer_target
from test_model_gateway import (  # noqa: F401  (``upstream`` is the fake-provider fixture)
    BODY, NO_PROXY, PROVIDER_KEY, _Allowance, _call, _grant, _sent, _start, _stop, _tok, upstream,
)
from vigil_core import AuthorizerKey, SignedCreditLaunchLease, TrustRoot, generate_keypair
from vigil_core import model_metering as mm
from vigil_core.credit_lease import verify_credit_launch_lease
from vigil_core.model_grant import (MAX_GRANT_LIFETIME_S, STOP_CREDITS_EXHAUSTED, STOP_HEADER, ModelGrant, decode_token,
                                    meter_id)
from vigil_integration.jobs.completion_signal import emit_completion_signal
from vigil_integration.live import credit_lease_pause as clp
from vigil_integration.live.credit_lease_broker import is_lease_settled, read_credit_lease
from vigil_integration.live.credit_lease_expiry import settle_due_at
from vigil_integration.live.model_grant_broker import read_model_grant

ORG, HOST = "org_a", "apme.cm"
H, DAY = 3_600.0, 86_400.0
T0 = 2_000.0                                     # the launch's reserve time (simulated, like the W2 suites)
TTL = 7 * DAY                                    # the default VIGIL_CREDIT_PAUSE_TTL_S
GRACE = 86_400.0                                 # the default paused-expiry settle grace (the lease-window rule)
TEST_MARGIN = "0.5"                              # a test fixture (markup 2), not a pricing decision
USAGE = mm.Usage(output_tokens=8_640)            # exactly 54 credits at the published rate card (as the W2 suites)
USAGE_COST = 266_250_000                         # the provider cost the meter records for it (internal only)
_ENV = ("VIGIL_METERED_BILLING", mm.MARGIN_ENV, mm.CANCEL_ENV, "VIGIL_RUN_FLOOR_CREDITS", "VIGIL_MODEL_PRICES",
        "VIGIL_RUN_MODEL", "VIGIL_SETTLE_SPINE_RECORD", "VIGIL_CREDIT_PAUSE_TTL_S", "VIGIL_PAUSED_EXPIRY_SETTLE",
        "VIGIL_PAUSED_EXPIRY_SETTLE_GRACE_SECONDS", mm.ALLOWANCE_CHUNK_ENV, *mm.OBSOLETE_PRICING_ENVS)

_iss = itertools.count(1)


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    for k in _ENV:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    monkeypatch.setenv(mm.MARGIN_ENV, TEST_MARGIN)
    monkeypatch.setenv(mm.CANCEL_ENV, "metered")


def _base() -> str:
    return os.environ["VIGIL_BASE_DIR"]


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


class _Launch:
    """One seated tenant (an operator member, a current ownership proof, an owner-signed target) with a launch
    reserved at ``at`` for an ``hours`` window and published — metered (its model grant minted) while the flag is on."""

    def __init__(self, store, *, units=900, credits=900, at=T0, hours=8.0, org=ORG, host=HOST):
        self.store, self.org, self.host = store, org, host
        self.owner = ensure_owner_keypair()
        orgs = OrgRegistry(store)
        orgs.create_org(org, org, owner="u", issued_at=float(next(_iss)))
        orgs.grant_membership(org, "u", "operator", issued_at=float(next(_iss)))
        WalletRegistry(store).grant(org, credits, "trial", entry_id=f"trial:{org}", issued_at=float(next(_iss)))
        reg = AssetOwnershipRegistry(store)
        ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
        reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=at, ttl_seconds=1e12)
        assert add_customer_target(host, org_id=org, store=store, now=at)["ok"]
        self.gate = LaunchGate(store)
        r = self.gate.reserve_launch(requester="u", org_id=org, host=host, units=units, now=at, duration_hours=hours)
        assert r["ok"], r
        assert self.gate.publish_lease(signed_lease=r["lease"], expect_org_id=org)["ok"]
        self.lease, self.slug, self.nonce, self.units = r["lease"], r["slug"], r["nonce"], int(r["units_reserved"])
        self.not_after = at + hours * H

    # -- what the gateway, the customer and the drains do ----------------------------------------------------------
    def spend(self, at: float) -> None:
        """One confirmed model request on the run's meter, as the gateway records it."""
        g = ModelGrant(grant_id="0" * 32, org_id=self.org, engagement_slug=self.slug, nonce=self.nonce,
                       model="claude-opus-4-8", effort="high", cap_nano_usd=10 ** 13, not_after=at + DAY,
                       issued_at=at - 60)
        m = gw.GrantMeter(config.MODEL_METER_DIR)
        rid, _reserved, why = m.reserve(g, 10 ** 6, 25_000, now=at)
        assert why == "", why
        m.commit(g, rid, USAGE, USAGE_COST, request_id="r", now=at)

    def park(self, at: float) -> dict:
        """The sovereign record the gateway writes (through ``LaunchAllowance.note_credit_pause``) before its stop."""
        return self.gate.record_credit_pause(slug=self.slug, nonce=self.nonce, now=at)

    def top_up(self, credits: int, k: int = 1) -> None:
        """A verified purchase lands in the wallet (the owner-signed grant the billing drain writes)."""
        WalletRegistry(self.store).grant(self.org, credits, "topup", entry_id=f"topup:{self.org}:{k}",
                                         issued_at=float(next(_iss)))

    def resume(self, at: float) -> dict:
        return self.gate.resume_launch(signed_lease=self.lease, expect_org_id=self.org, now=at)

    def avail(self) -> int:
        return WalletRegistry(self.store).available(self.org)

    def extensions(self) -> "tuple[int, bool]":
        return self.gate.extension_total(self.org, self.slug, self.nonce)

    def paused_at(self):
        return clp.credit_pause_at(_base(), self.slug, self.nonce)

    def halted(self):
        return clp.lease_pause_state(_base(), self.slug, self.nonce)

    def settled(self) -> bool:
        return is_lease_settled(_base(), self.slug, self.nonce)

    def seam_doc(self):
        return read_credit_lease(_base(), self.slug).signed_lease.document

    def drain_completed(self, at: float) -> dict:
        """The worker's COMPLETED signal, drained by the settle-drain (charged to the metered use)."""
        gov = generate_keypair()
        deleg = delegate_offense_governance(
            self.owner, authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=gov.public_key_b64)],
            threshold=1, scope=self.slug, not_after=9_000_000_000)
        spool = tempfile.mkdtemp()
        emit_completion_signal(engagement_slug=self.slug, nonce=self.nonce, outcome="completed",
                               signers=[("gov", gov.private_key_b64)], spool_dir=spool)
        return CompletionSpoolWatcher(self.store, spool_dir=spool, owner_pubkey=self.owner.public_key_b64,
                                      delegation=deleg, scope=self.slug, base_dir=_base(),
                                      now_fn=lambda: at).drain()

    def spool(self) -> str:
        """An initialised, empty completion spool (what the sweeps re-check before they settle)."""
        gov = generate_keypair()
        deleg = delegate_offense_governance(
            self.owner, authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=gov.public_key_b64)],
            threshold=1, scope=self.slug, not_after=9_000_000_000)
        spool = tempfile.mkdtemp()
        CompletionSpoolWatcher(self.store, spool_dir=spool, owner_pubkey=self.owner.public_key_b64, delegation=deleg,
                               scope=self.slug, base_dir=_base(), now_fn=lambda: T0)
        return spool


def _close(L: _Launch, at: float) -> "list[dict]":
    """The settle-drain's expiry pass (``VIGIL_PAUSED_EXPIRY_SETTLE``) over ``L``'s seam at ``at``."""
    from sigil.paused_expiry_settle import settle_expired_paused_launches
    return settle_expired_paused_launches(L.gate, now=at, completion_spool=L.spool())


def _real_gateway(upstream_srv, L: _Launch, clock: dict):
    """The model gateway as the cockpit runs it: the REAL in-process allowance source over ``L``'s gate, the owner key
    that signed ``L``'s grant, the shared meter directory; a fake provider on loopback."""
    cfg = gw.GatewayConfig(api_key=PROVIDER_KEY, owner_pubkey=L.owner.public_key_b64, meter_dir=config.MODEL_METER_DIR,
                           upstream=f"http://127.0.0.1:{upstream_srv.server_address[1]}", opener=NO_PROXY,
                           clock=lambda: clock["now"], allowance=LaunchAllowance(L.gate), allowance_required=True)
    server, _t = gw.start(cfg)
    server.url = f"http://127.0.0.1:{server.server_address[1]}"
    return server


def _post(server, token: str):
    req = urllib.request.Request(server.url + "/v1/messages", data=json.dumps(BODY).encode(), method="POST",
                                 headers={"content-type": "application/json", "x-api-key": token,
                                          "anthropic-version": "2023-06-01"})
    try:
        with NO_PROXY.open(req, timeout=20) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


# ------------------------------------------------------------------------------------------------- the pause
def test_a_run_that_hits_the_allowance_floor_is_parked_not_settled(upstream):  # noqa: F811  (the imported ``upstream`` pytest fixture, reused by name)
    L = _Launch(_store(), units=1, credits=1)                 # one credit held, an empty wallet: no extension possible
    token = read_model_grant(_base(), L.slug, expect_nonce=L.nonce).token
    clock = {"now": T0 + 60}
    server = _real_gateway(upstream, L, clock)
    try:
        status, headers, body = _post(server, token)
        # the Anthropic-shaped, NON-retryable credit stop the engine maps to its held CreditPaused (M1c-2)
        assert status == 403 and headers.get(STOP_HEADER) == STOP_CREDITS_EXHAUSTED
        assert json.loads(body) == {"type": "error", "error": {"type": "permission_error",
                                                               "message": gw.CREDITS_EXHAUSTED}}
        assert "retry-after" not in headers
        assert _sent(upstream) == []                          # never forwarded past the refusal
        # PARKED: the sovereign record (the pause time + reason) and the halt marker are durable ...
        assert L.paused_at() == T0 + 60
        assert clp.credit_pause_reason(_base(), L.slug, L.nonce) == clp.CREDIT_PAUSE_REASON == "insufficient_credits"
        assert L.halted() is True
        # ... and nothing settled: the lease is held (on the seam, not marked settled), no money moved either way
        assert not L.settled() and read_credit_lease(_base(), L.slug) is not None
        assert L.avail() == 0 and L.extensions() == (0, False)
        # a later refusal of the same pause (a retry, a request in flight) keeps the FIRST pause time
        clock["now"] = T0 + 600
        assert _post(server, token)[0] == 403 and L.paused_at() == T0 + 60
    finally:
        _stop(server)


class _Recording(_Allowance):
    """The gateway-test allowance stand-in plus the W3 hook (``LaunchAllowance.note_credit_pause``)."""

    def __init__(self, *a, note=True, **kw):
        super().__init__(*a, **kw)
        self.note, self.notes = note, []

    def note_credit_pause(self, grant, now):
        self.notes.append((grant.meter_id, now))
        if isinstance(self.note, Exception):
            raise self.note
        return self.note


@pytest.mark.parametrize("note", [False, OSError("seam unwritable")], ids=["not-recorded", "hook-raised"])
def test_the_terminal_stop_waits_for_a_recorded_pause(upstream, tmp_path, note):  # noqa: F811  (the imported ``upstream`` pytest fixture, reused by name)
    src = _Recording(1_000, available=0, note=note)
    server = _start(upstream, tmp_path / "meter", allowance=src)
    try:
        status, headers, body = _call(server, BODY, _tok(_grant()))
        hl = {k.lower(): v for k, v in headers.items()}
        # an unrecorded pause is RETRYABLE (the run retries), never the terminal stop that would park it unseen
        assert status == 529 and json.loads(body)["error"]["type"] == "overloaded_error"
        assert STOP_HEADER not in hl and hl.get("retry-after") == "5"
        assert src.notes and _sent(upstream) == []
    finally:
        _stop(server)


def test_a_recorded_pause_gets_the_terminal_stop_and_names_the_run(upstream, tmp_path):  # noqa: F811  (the imported ``upstream`` pytest fixture, reused by name)
    src = _Recording(1_000, available=0, note=True)
    server = _start(upstream, tmp_path / "meter", allowance=src)
    try:
        g = _grant()
        status, headers, _b = _call(server, BODY, _tok(g))
        assert status == 403 and {k.lower(): v for k, v in headers.items()}.get(STOP_HEADER) == STOP_CREDITS_EXHAUSTED
        assert [mid for mid, _t in src.notes] == [g.meter_id]   # the pause is recorded for THIS run's meter
    finally:
        _stop(server)


def test_a_flat_launch_never_pauses_for_credit(monkeypatch):
    monkeypatch.delenv("VIGIL_METERED_BILLING")
    L = _Launch(_store(), units=30, credits=100)                  # published FLAT: no grant, no meter
    out = L.park(T0 + 60)
    assert not out["ok"] and "metered" in out["error"]
    assert L.paused_at() is None and L.halted() is False
    assert not (Path(_base()) / "credit-pauses").exists()


def test_a_settled_launch_is_not_paused():
    L = _Launch(_store(), units=900, credits=1_000)
    L.spend(T0 + H)
    assert L.drain_completed(T0 + 2 * H)["settled"] == 1
    out = L.park(T0 + 3 * H)
    assert not out["ok"] and L.paused_at() is None


def test_the_first_pause_time_wins():
    base = _base()
    clp.record_credit_pause(base, "cust_x", "n1", 100.0)
    clp.record_credit_pause(base, "cust_x", "n1", 900.0, reason="other")         # a re-record of the same pause
    clp.record_credit_pause(base, "cust_x", "n2", 500.0)
    assert clp.credit_pause_at(base, "cust_x", "n1") == 100.0
    assert clp.credit_pause_reason(base, "cust_x", "n1") == "insufficient_credits"
    assert clp.credit_paused_launches(base) == [("cust_x", ["n1", "n2"])]
    clp.clear_credit_pause(base, "cust_x", "n1")
    assert clp.credit_pause_at(base, "cust_x", "n1") is None and clp.credit_pause_at(base, "cust_x", "n2") == 500.0
    clp.record_credit_pause(base, "cust_x", "n1", 700.0)                         # a NEW pause after a resume
    assert clp.credit_pause_at(base, "cust_x", "n1") == 700.0


def test_the_credit_pause_record_fails_closed():
    base = _base()
    with pytest.raises(ValueError):
        clp.record_credit_pause(base, "../escape", "n1", 1.0)
    with pytest.raises(ValueError):
        clp.record_credit_pause(base, "cust_x", "n1", float("nan"))
    p = clp.credit_pause_path(base, "cust_y")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{corrupt", encoding="utf-8")                       # an unreadable record is never overwritten
    with pytest.raises(ValueError):
        clp.record_credit_pause(base, "cust_y", "n1", 1.0)
    with pytest.raises(ValueError):
        clp.clear_credit_pause(base, "cust_y", "n1")
    assert clp.credit_pause_at(base, "cust_y", "n1") is None and clp.credit_paused_launches(base) == []


@pytest.mark.parametrize("raw, want", [(None, 604_800.0), ("3600", 3_600.0), ("0", 604_800.0), ("-5", 604_800.0),
                                       ("nan", 604_800.0), ("inf", 604_800.0), ("x", 604_800.0)])
def test_the_credit_pause_grace_is_seven_days_unless_validly_set(monkeypatch, raw, want):
    if raw is not None:
        monkeypatch.setenv("VIGIL_CREDIT_PAUSE_TTL_S", raw)
    assert clp.credit_pause_ttl_s() == want


# ------------------------------------------------------------------------------------------------- the resume
def test_a_resume_without_enough_credit_changes_nothing():
    L = _Launch(_store())                                    # 900 held, wallet empty
    L.spend(T0 + H)
    assert L.park(T0 + H)["ok"]
    out = L.resume(T0 + 2 * H)
    assert not out["ok"] and out.get("insufficient") is True and "top up" in out["error"]
    # still parked, exactly as it was: the 7-day clock keeps its first pause time
    assert L.paused_at() == T0 + H and L.halted() is True and L.extensions() == (0, False) and L.avail() == 0


def test_a_top_up_resumes_the_launch_on_the_same_meter():
    L = _Launch(_store())                                    # 900 held, wallet empty
    L.spend(T0 + H)                                          # 54 credits used before the wallet ran dry
    assert L.park(T0 + H)["ok"]
    L.top_up(500)
    out = L.resume(T0 + 2 * H)
    assert out["ok"] and out["credit_resumed"] is True and "expired" not in out
    assert set(out) == {"ok", "action", "credit_resumed", "org_id", "slug", "nonce"}     # no amount in the reply
    # un-parked: the record and the halt are gone; ONE allowance (the chunk) was taken from the top-up
    assert L.paused_at() is None and L.halted() is False
    assert L.extensions() == (100, False) and L.avail() == 400
    # the run continues on the SAME meter (one meter per scan: the statement stays continuous)
    L.spend(T0 + 3 * H)
    mid = meter_id(L.slug, L.nonce)
    assert len(gw.GrantMeter(config.MODEL_METER_DIR).usage_records(mid)) == 2
    assert L.drain_completed(T0 + 4 * H)["settled"] == 1
    # net spend == the metered use of BOTH legs (54 + 54); everything held and unused came back
    assert L.avail() == 900 + 500 - 108 and L.settled()


def test_a_pause_outliving_the_lease_window_and_the_grant_still_resumes():
    L = _Launch(_store(), hours=8.0)
    original = SignedCreditLaunchLease.model_validate(L.lease).document
    old_token = read_model_grant(_base(), L.slug, expect_nonce=L.nonce).token
    L.spend(T0 + H)
    paused = T0 + 2 * H                                       # paused inside the window ...
    assert L.park(paused)["ok"]
    L.top_up(500)
    later = T0 + 7 * DAY + 1.5 * H                           # ... resumed after BOTH the window and the grant ended,
    assert later > original.not_after.timestamp()             # still inside the 7-day wait from the pause
    old_grant, _why = decode_token(old_token, L.owner.public_key_b64)
    assert old_grant.not_after < later < paused + TTL
    out = L.resume(later)
    assert out["ok"] and out["credit_resumed"] is True
    # the seam now holds the CONTINUATION: the same lease, a fresh window, continue_of = its own nonce, the same
    # issued_at (so the single-use floor still refuses a fresh arm), units and owner signature that verifies
    cont = L.seam_doc()
    assert cont.continue_of == cont.nonce == L.nonce
    assert (cont.not_before.timestamp(), cont.not_after.timestamp()) == (later, later + 8 * H)
    assert cont.model_dump(exclude={"not_before", "not_after", "continue_of"}) == original.model_dump(
        exclude={"not_before", "not_after", "continue_of"})
    root = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=L.owner.public_key_b64)])
    assert verify_credit_launch_lease(read_credit_lease(_base(), L.slug).signed_lease, root)[0]
    # its model grant was renewed from the new window's start, bound to the SAME meter
    grant, why = decode_token(read_model_grant(_base(), L.slug, expect_nonce=L.nonce).token, L.owner.public_key_b64)
    assert grant is not None, why
    assert grant.meter_id == meter_id(L.slug, L.nonce) and grant.issued_at == later
    assert grant.not_after == later + MAX_GRANT_LIFETIME_S
    # the run finishes on the same meter and settles both legs
    L.spend(later + H)
    assert L.drain_completed(later + 2 * H)["settled"] == 1
    assert L.avail() == 900 + 500 - 108


def test_a_second_resume_is_a_no_op_judged_by_the_continued_window():
    L = _Launch(_store(), hours=8.0)
    assert L.park(T0 + 2 * H)["ok"]
    L.top_up(500)
    later = T0 + 2 * DAY
    assert L.resume(later)["ok"]
    assert L.extensions() == (100, False)
    again = L.resume(later + 60)                              # the customer clicks Resume twice
    assert again == {"ok": True, "action": "launch_resumed", "org_id": ORG, "slug": L.slug, "nonce": L.nonce}
    assert L.extensions() == (100, False) and L.avail() == 400  # no second allowance, nothing re-charged


def test_concurrent_resumes_take_exactly_one_allowance():
    L = _Launch(_store())
    assert L.park(T0 + H)["ok"]
    L.top_up(500)
    outs: list = []
    gates = [LaunchGate(L.store), LaunchGate(L.store)]
    threads = [threading.Thread(target=lambda g=g: outs.append(g.resume_launch(
        signed_lease=L.lease, expect_org_id=ORG, now=T0 + 2 * H))) for g in gates]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert len(outs) == 2 and all(o["ok"] for o in outs)
    assert sum(1 for o in outs if o.get("credit_resumed")) == 1
    assert L.extensions() == (100, False) and L.avail() == 400 and L.halted() is False


def test_the_locked_resume_step_refuses_once_the_wait_has_ended():
    L = _Launch(_store())
    assert L.park(T0 + H)["ok"]
    L.top_up(500)
    out = L.gate.extend_reservation(org_id=ORG, slug=L.slug, nonce=L.nonce, credits=100, now=T0 + H + TTL,
                                    credit_resume=True)
    assert not out["ok"] and out.get("credit_pause_expired") is True
    assert L.extensions() == (0, False) and L.paused_at() == T0 + H and L.halted() is True


def test_a_resume_at_the_end_of_the_wait_is_refused_and_nothing_is_continued():
    L = _Launch(_store())
    L.spend(T0 + H)
    assert L.park(T0 + H)["ok"]
    L.top_up(500)
    out = L.resume(T0 + H + TTL)                              # the window is long closed: a continuation would be minted
    assert not out["ok"] and out.get("credit_pause_expired") is True
    assert L.seam_doc().continue_of is None                   # ... but the wait has ended: nothing was continued
    assert L.paused_at() == T0 + H and L.halted() is True and L.extensions() == (0, False)
    rows = _close(L, T0 + H + TTL)                           # the close charges it for what it used
    assert [(r["status"], r["charged"]) for r in rows] == [("charged_paused", 54)]


def test_a_credit_pause_is_not_a_billing_hold_nor_an_operator_pause(monkeypatch):
    # W5 (#1151, the interface as briefed): an extension for an org on a billing hold is refused with
    # {insufficient: True, billing_hold: True, reason: "billing_hold"} — a hold a credit top-up does not lift
    L = _Launch(_store())
    assert L.park(T0 + H)["ok"]
    L.top_up(500)
    held = {"ok": False, "insufficient": True, "billing_hold": True, "reason": "billing_hold",
            "error": "this org is on a billing hold"}
    with monkeypatch.context() as m:
        m.setattr(LaunchGate, "extend_reservation", lambda self, **kw: dict(held))
        out = L.resume(T0 + 2 * H)
    assert not out["ok"] and out.get("billing_hold") is True and "insufficient" not in out
    assert "hold" in out["error"] and "top up" not in out["error"]
    assert L.paused_at() == T0 + H and L.halted() is True     # still parked, still a CREDIT pause
    # an OPERATOR pause carries no credit-pause record: its resume is the ordinary one (no allowance, no continuation)
    O = _Launch(_store(), org="org_b")
    assert O.gate.pause_launch(signed_lease=O.lease, expect_org_id="org_b")["ok"]
    assert O.paused_at() is None
    r = O.gate.resume_launch(signed_lease=O.lease, expect_org_id="org_b", now=T0 + 2 * H)
    assert r == {"ok": True, "action": "launch_resumed", "org_id": "org_b", "slug": O.slug, "nonce": O.nonce}
    assert O.extensions() == (0, False)


# ------------------------------------------------------------------------------------------------- the 7-day close
def test_the_close_waits_for_the_pause_anchored_grace_then_charges_what_was_used():
    L = _Launch(_store(), units=900, credits=1_000)          # 100 left in the wallet
    L.spend(T0 + H)
    paused = T0 + 2 * H
    assert L.park(paused)["ok"]
    # the lease-window rule would close it at the window's end + the ops grace: a credit pause waits for ITS grace
    assert settle_due_at(_base(), L.slug, L.nonce, L.not_after) == paused + TTL
    assert _close(L, L.not_after + GRACE + 60) == [] and not L.settled()
    assert _close(L, paused + TTL - 1) == [] and not L.settled()
    rows = _close(L, paused + TTL)
    assert [(r["status"], r["charged"], r["refunded"]) for r in rows] == [("charged_paused", 54, 846)], rows
    assert L.avail() == 1_000 - 54 and L.settled()            # charged exactly what it used, once
    assert _close(L, paused + TTL + DAY) == [] and L.avail() == 1_000 - 54


def test_the_close_honours_a_shorter_owner_grace(monkeypatch):
    monkeypatch.setenv("VIGIL_CREDIT_PAUSE_TTL_S", str(2 * DAY))
    L = _Launch(_store(), units=900, credits=1_000)
    assert L.park(T0 + 2 * H)["ok"]
    assert _close(L, T0 + 2 * H + 2 * DAY - 1) == []
    rows = _close(L, T0 + 2 * H + 2 * DAY)
    assert [r["status"] for r in rows] == ["settled"] and L.avail() == 1_000    # used nothing: refunded in full


def test_the_ops_sweep_waits_out_a_credit_pause():
    from sigil.ops_sweeps import sweep_abandoned_reservations
    L = _Launch(_store(), units=900, credits=1_000)
    L.spend(T0 + H)
    paused = T0 + 2 * H
    assert L.park(paused)["ok"]
    spool = L.spool()
    early = sweep_abandoned_reservations(L.gate, now=L.not_after + DAY + 60, ttl_s=DAY, apply=True,
                                         completion_spool=spool)
    assert [i for i in early["items"] if i.get("nonce") == L.nonce] == [] and not L.settled()
    late = sweep_abandoned_reservations(L.gate, now=paused + TTL, ttl_s=DAY, apply=True, completion_spool=spool)
    (row,) = [i for i in late["items"] if i.get("nonce") == L.nonce]
    assert (row["status"], row["charged"]) == ("charged_paused", 54) and L.avail() == 1_000 - 54


# ------------------------------------------------------------------------------------------------- the notice
def _provisioner(store):
    from sigil.governor.customers import CustomerRegistry
    from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
    from sigil.ui.login_ratelimit import LoginRateLimiter
    from sigil.ui.provision import Provisioner
    owner = ensure_owner_keypair()
    return Provisioner(
        store, customers=CustomerRegistry(store, owner_key=owner), orgs=OrgRegistry(store, owner_key=owner),
        wallet=WalletRegistry(store, owner_key=owner),
        email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
        email_sender=NullEmailSender(), trial_credits=100, now_fn=lambda: T0)


def _notices(prov, org, user="u", at=T0 + 3 * H):
    return [n for n in prov.customer_notifications(user, org, now=at)["notifications"]
            if n["id"].startswith("credit_pause:")]


def test_the_paused_notice_is_tenant_scoped_carries_no_amount_and_ends_with_the_pause():
    s = _store()
    L = _Launch(s)
    B = _Launch(s, org="org_b", host="other.cm")             # another tenant, with nothing paused
    prov = _provisioner(s)
    assert _notices(prov, ORG) == [] and _notices(prov, "org_b") == []
    assert L.park(T0 + H)["ok"]
    (n,) = _notices(prov, ORG)
    assert n == {"id": f"credit_pause:{L.slug}:{L.nonce}", "kind": "assessment", "severity": "high",
                 "title": "Assessment paused: out of credits", "body": n["body"], "ts": T0 + H}
    assert "within 7 days" in n["body"] and "Top up" in n["body"] and "resume" in n["body"]
    for banned in ("$", "usd", HOST, "estimat", "claude", "anthropic", "opus", "strix", "nyx", "model"):
        assert banned not in n["body"].lower() and banned not in n["title"].lower()
    assert _notices(prov, "org_b") == []                     # never another tenant's (the same user is in both)
    assert _notices(prov, ORG, user="stranger") == []        # never a non-member's
    assert B.paused_at() is None
    L.top_up(500)
    assert L.resume(T0 + 2 * H)["ok"]
    assert _notices(prov, ORG) == []                          # resumed: no longer paused


def test_the_notice_ends_when_the_close_settles_the_launch():
    s = _store()
    L = _Launch(s, units=900, credits=1_000)
    prov = _provisioner(s)
    assert L.park(T0 + H)["ok"]
    assert len(_notices(prov, ORG)) == 1
    assert [r["status"] for r in _close(L, T0 + H + TTL)] == ["settled"]
    assert _notices(prov, ORG, at=T0 + H + TTL + 60) == []   # the stale record of a settled launch is not shown


# ------------------------------------------------------------------------------------------------- flag OFF
def test_metered_billing_off_is_byte_identical(monkeypatch):
    monkeypatch.delenv("VIGIL_METERED_BILLING")
    s = _store()
    L = _Launch(s, units=30, credits=100)                     # a FLAT launch: no grant, no meter, no allowance
    assert read_model_grant(_base(), L.slug, expect_nonce=L.nonce) is None
    # the operator pause / resume replies are exactly the pre-W3 ones (in and after the window)
    assert L.gate.pause_launch(signed_lease=L.lease, expect_org_id=ORG)["ok"]
    assert L.resume(T0 + H) == {"ok": True, "action": "launch_resumed", "org_id": ORG, "slug": L.slug,
                                "nonce": L.nonce}
    assert L.gate.pause_launch(signed_lease=L.lease, expect_org_id=ORG)["ok"]
    assert L.resume(L.not_after + H) == {"ok": True, "action": "launch_resumed", "org_id": ORG, "slug": L.slug,
                                         "nonce": L.nonce, "expired": True, "detail": _RESUMED_EXPIRED_DETAIL}
    # the paused-launch close keeps the lease-window rule
    assert L.gate.pause_launch(signed_lease=L.lease, expect_org_id=ORG)["ok"]
    due = settle_due_at(_base(), L.slug, L.nonce, L.not_after)
    assert due is not None and due >= L.not_after + GRACE
    # no extension of a flat launch, no credit pause, no record, no notice
    assert L.gate.extend_reservation(org_id=ORG, slug=L.slug, nonce=L.nonce, credits=1, now=T0 + H) == {
        "ok": False, "error": "only a metered launch's allowance is extended"}
    assert not L.park(T0 + H)["ok"]
    assert not (Path(_base()) / "credit-pauses").exists()
    assert _notices(_provisioner(s), ORG) == []
