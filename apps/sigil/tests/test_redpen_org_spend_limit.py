"""C6 §15.11 — the workspace-wide monthly auto-fix SPENDING LIMIT: the per-org cap config (get/set), its enforcement
where the automated fixing spends, and the Code screen control that drives it.

Separate from each repository's per-review limit (``test_redpen_spend_limit``): this is the ceiling the merge-blocking
AUTO-FIX (``redpen_fix_this``) may spend ACROSS the whole session org in a calendar month, so the automated fixing
never exceeds it. Invariants pinned here:

  * the org usage fold sums owner-signed charges across EVERY repository for (org, calendar-month), idempotent per
    (repo, nonce); a forged charge is inert;
  * the org limit is owner-signed, latest-wins, persists across months, and a forged / stale record cannot move it;
  * the org gate refuses NEW auto-fixes once charged >= limit (the boundary REACHED refuses), 0 = no limit, and it
    re-arms next calendar month;
  * get/set are manage_code-gated and scoped to the SESSION org (never a body org), the set steps up;
  * the cap actually GATES SPEND: with the Fix-it dispatch on, an auto-fix at/over the org limit is refused before it
    reserves or publishes anything (nothing dispatched), and an auto-fix under the limit is NOT refused by the cap;
  * the Code screen's control renders the pack picker + the limit + this month's usage and saves only the limit.
"""
from __future__ import annotations

import itertools
import json
import tempfile
import time
from datetime import datetime, timezone

import pytest

# Reuse the Code screen harness: the two-workspace provisioner, the direct connect, the audit reader and the node-UI
# screen runner (app.js extracted verbatim).
from test_customer_code_screen import (
    API_REPO,
    WEB_REPO,
    _audits,
    _connect,
    _prov,
    _screen,
)

from sigil.governor.redpen_spend import RedPenSpendLedger, month_key
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui.provision import ProvisionDenied, ProvisionError, ProvisionStepUpRequired

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()
_c = itertools.count(1)
JAN = datetime(2026, 1, 15, tzinfo=timezone.utc).timestamp()
FEB = datetime(2026, 2, 3, tzinfo=timezone.utc).timestamp()


@pytest.fixture(autouse=True)
def _redpen_env(tmp_path, monkeypatch):
    # Keep the PR-K auto-fix dispatch and the step-up requirement OFF by default (the relevant tests turn each on
    # explicitly); the per-test monkeypatch from _prov sets the Red-Pen master flag. Any Red-Pen action seam write
    # lands under tmp, never the shared SIGIL_HOME. Like test_redpen_provision (and unlike the full-stack customer
    # tests), this file provisions only through _prov's own ensure_owner_keypair() and leaves the shared owner key in
    # place — it never scrubs the shared home, so a sibling file collected right after it still finds a provisioned key.
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path))
    monkeypatch.delenv("VIGIL_CUSTOMER_FIX_IT", raising=False)
    monkeypatch.delenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", raising=False)


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _led(store, key=OWNER, pub=OP):
    return RedPenSpendLedger(store, owner_key=key, trusted_pubkey=pub)


def _n() -> str:
    return f"rev{next(_c)}"


# --- the owner-signed org fold + limit (sovereign primitive) -----------------------------------------------------------
def test_org_usage_sums_charges_across_every_repository():
    s = _store()
    led = _led(s)
    led.record_charge("acme", API_REPO, 10, nonce=_n(), now=JAN)
    led.record_charge("acme", WEB_REPO, 7, nonce=_n(), now=JAN)
    led.record_charge("acme", "github.com/acme/third", 3, nonce=_n(), now=JAN)
    assert led.org_charged("acme", now=JAN) == 20                 # summed across all three repos
    led.record_charge("beta", API_REPO, 99, nonce=_n(), now=JAN)  # another org is isolated
    assert led.org_charged("acme", now=JAN) == 20


def test_org_usage_is_idempotent_per_repo_nonce_and_re_arms_next_month():
    s = _store()
    led = _led(s)
    non = _n()
    led.record_charge("acme", API_REPO, 10, nonce=non, now=JAN)
    led.record_charge("acme", API_REPO, 10, nonce=non, now=JAN)   # a retried settle re-appends the same (repo, nonce)
    led.record_charge("acme", WEB_REPO, 10, nonce=non, now=JAN)   # same nonce, DIFFERENT repo: counted on its own
    assert led.org_charged("acme", now=JAN) == 20
    assert led.org_charged("acme", now=FEB) == 0                  # February starts fresh
    assert month_key(JAN) == "2026-01" and month_key(FEB) == "2026-02"


def test_the_org_limit_is_owner_signed_latest_wins_and_persists():
    s = _store()
    led = _led(s)
    assert led.org_monthly_limit("acme") == 0                     # unset -> no limit (fail-closed default)
    led.set_org_monthly_limit("acme", 500, issued_at=1.0)
    assert led.org_monthly_limit("acme") == 500
    led.set_org_monthly_limit("acme", 1000, issued_at=2.0)        # a later record wins
    assert led.org_monthly_limit("acme") == 1000
    led.set_org_monthly_limit("acme", 0, issued_at=3.0)           # back to no limit
    assert led.org_monthly_limit("acme") == 0
    assert led.org_monthly_limit("beta") == 0                     # another org is isolated


def test_a_forged_org_limit_or_charge_is_inert():
    s = _store()
    forger = RedPenSpendLedger(s, owner_key=ATTACKER, trusted_pubkey=OP)
    forger.set_org_monthly_limit("acme", 999, issued_at=1.0)      # signed by a non-owner
    forger.record_charge("acme", API_REPO, 999, nonce=_n(), now=JAN)
    assert _led(s).org_monthly_limit("acme") == 0 and _led(s).org_charged("acme", now=JAN) == 0


def test_the_org_gate_refuses_at_the_limit_and_re_arms():
    s = _store()
    led = _led(s)
    led.record_charge("acme", API_REPO, 30, nonce=_n(), now=JAN)
    led.record_charge("acme", WEB_REPO, 19, nonce=_n(), now=JAN)
    assert led.org_review_refusal("acme", monthly_limit_credits=50, now=JAN) is None   # 49 < 50 -> allow
    led.record_charge("acme", API_REPO, 1, nonce=_n(), now=JAN)                        # now 50 == limit
    refusal = led.org_review_refusal("acme", monthly_limit_credits=50, now=JAN)
    assert refusal is not None and refusal["refused"] and refusal["notify"] is True
    assert refusal["charged"] == 50 and refusal["limit"] == 50 and refusal["month"] == "2026-01"
    assert led.org_review_refusal("acme", monthly_limit_credits=0, now=JAN) is None    # 0 -> no limit
    assert led.org_review_refusal("acme", monthly_limit_credits=50, now=FEB) is None   # re-arms next month


def test_set_org_monthly_limit_requires_the_owner_key_and_validates():
    s = _store()
    with pytest.raises(ValueError, match="owner signing key"):
        RedPenSpendLedger(s, owner_key=None, trusted_pubkey=OP).set_org_monthly_limit("acme", 1, issued_at=1.0)
    with pytest.raises(ValueError):
        _led(s).set_org_monthly_limit("acme", -1, issued_at=1.0)
    with pytest.raises(ValueError):
        _led(s).set_org_monthly_limit("acme", True, issued_at=1.0)       # a bool is never a limit


# --- the provisioner get/set (manage_code, step-up, session-org-scoped) ------------------------------------------------
def test_set_and_read_the_org_spend_limit_round_trip(tmp_path, monkeypatch):
    p, s = _prov(tmp_path, monkeypatch)
    now = time.time()
    got = p.redpen_org_spend("cust_fo", "org_a", now=now)
    assert got["org_id"] == "org_a" and got["monthly_limit_credits"] == 0 and got["used_this_month"] == 0
    assert got["month"] == month_key(now) and got["packs"] == [100, 250, 500, 1000, 2500]
    out = p.redpen_set_org_spend("cust_fo", "org_a", monthly_limit_credits=500, now=now)
    assert out == {"org_id": "org_a", "monthly_limit_credits": 500, "used_this_month": 0, "month": month_key(now)}
    RedPenSpendLedger(s).record_charge("org_a", API_REPO, 120, nonce="u1", now=now)
    read = p.redpen_org_spend("cust_op", "org_a", now=now)            # an owner-granted operator reads it too
    assert read["monthly_limit_credits"] == 500 and read["used_this_month"] == 120
    p.redpen_set_org_spend("cust_fo", "org_a", monthly_limit_credits="0", now=now)   # a numeric string is accepted
    assert p.redpen_org_spend("cust_fo", "org_a", now=now)["monthly_limit_credits"] == 0


def test_the_org_spend_limit_is_scoped_to_the_session_org(tmp_path, monkeypatch):
    p, s = _prov(tmp_path, monkeypatch)
    now = time.time()
    p.redpen_set_org_spend("cust_fo", "org_a", monthly_limit_credits=300, now=now)
    assert p.redpen_org_spend("cust_bb", "org_b", now=now)["monthly_limit_credits"] == 0   # org_b untouched
    p.redpen_set_org_spend("cust_bb", "org_b", monthly_limit_credits=50, now=now)
    assert p.redpen_org_spend("cust_fo", "org_a", now=now)["monthly_limit_credits"] == 300


def test_only_manage_code_reads_or_sets_the_org_spend_limit(tmp_path, monkeypatch):
    p, s = _prov(tmp_path, monkeypatch)
    for who in ("cust_ad", "cust_an", "cust_vi", "cust_bb", "cust_nobody"):
        with pytest.raises(ProvisionDenied, match="may not manage code review"):
            p.redpen_org_spend(who, "org_a")
        with pytest.raises(ProvisionDenied, match="may not manage code review"):
            p.redpen_set_org_spend(who, "org_a", monthly_limit_credits=10)
    assert any(a["outcome"] == "denied" for a in _audits(s, "redpen_org_spend"))


def test_setting_the_org_spend_limit_needs_a_fresh_second_factor(tmp_path, monkeypatch):
    p, s = _prov(tmp_path, monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")
    with pytest.raises(ProvisionStepUpRequired):
        p.redpen_set_org_spend("cust_fo", "org_a", monthly_limit_credits=10)
    with pytest.raises(ProvisionDenied):                                   # authority first: never "step up"
        p.redpen_set_org_spend("cust_vi", "org_a", monthly_limit_credits=10)
    assert p.redpen_set_org_spend("cust_fo", "org_a", monthly_limit_credits=10,
                                  mfa_at=time.time())["monthly_limit_credits"] == 10
    assert p.redpen_org_spend("cust_fo", "org_a")["monthly_limit_credits"] == 10   # reading never asks for one


def test_the_org_spend_limit_rejects_a_bad_value(tmp_path, monkeypatch):
    p, s = _prov(tmp_path, monkeypatch)
    for bad in (None, -1, True, 2.5, "ten", "1e3", "2.5"):
        with pytest.raises(ProvisionError):
            p.redpen_set_org_spend("cust_fo", "org_a", monthly_limit_credits=bad)


# --- THE CAP ENFORCES: the auto-fix actually stops at the limit --------------------------------------------------------
def test_the_org_monthly_cap_stops_the_auto_fix_at_the_limit(tmp_path, monkeypatch):
    p, s = _prov(tmp_path, monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_FIX_IT", "1")        # PR-K: "Fix this" dispatches to the auto-fix (spends)
    now = time.time()
    _connect(p, "org_a", API_REPO)
    p.redpen_set_org_spend("cust_fo", "org_a", monthly_limit_credits=50, now=now)
    led = RedPenSpendLedger(s)
    led.record_charge("org_a", API_REPO, 49, nonce="c1", now=now)      # 49 < 50: under the workspace cap
    # under the limit the ORG cap does NOT refuse — the fix passes the cap and reaches the spend path (which refuses
    # here for its own reason: this test wires no wallet). The refusal, whatever it is, is NOT the org-cap reason.
    with pytest.raises(ProvisionDenied) as under:
        p.redpen_fix_this("cust_fo", "org_a", API_REPO, "f1", now=now)
    assert "monthly auto-fix spending limit" not in str(under.value)
    led.record_charge("org_a", API_REPO, 1, nonce="c2", now=now)       # now 50 == limit (boundary REACHED)
    before = sum(1 for _ in s.iter_records())
    with pytest.raises(ProvisionDenied, match="monthly auto-fix spending limit"):
        p.redpen_fix_this("cust_fo", "org_a", API_REPO, "f1", now=now)
    # the cap refuses BEFORE the spend path: nothing is reserved, charged or dispatched — only the refusal audit lands
    assert any(a["outcome"] == "org_limit_reached" for a in _audits(s, "redpen_fix_this"))
    assert sum(1 for _ in s.iter_records()) == before + 1              # just the one audit record, no lease/charge/marker


def test_the_org_cap_counts_spend_across_repositories(tmp_path, monkeypatch):
    p, s = _prov(tmp_path, monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_FIX_IT", "1")
    now = time.time()
    _connect(p, "org_a", API_REPO)
    _connect(p, "org_a", WEB_REPO)
    p.redpen_set_org_spend("cust_fo", "org_a", monthly_limit_credits=60, now=now)
    led = RedPenSpendLedger(s)
    led.record_charge("org_a", API_REPO, 40, nonce="a1", now=now)      # 40 on one repo ...
    led.record_charge("org_a", WEB_REPO, 20, nonce="w1", now=now)      # ... + 20 on another == 60, the workspace cap
    # a fix on EITHER repo is now refused by the workspace-wide cap, even though neither repo alone hit a per-repo limit
    with pytest.raises(ProvisionDenied, match="monthly auto-fix spending limit"):
        p.redpen_fix_this("cust_fo", "org_a", WEB_REPO, "f9", now=now)


def test_no_org_limit_means_the_cap_never_refuses(tmp_path, monkeypatch):
    p, s = _prov(tmp_path, monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_FIX_IT", "1")
    now = time.time()
    _connect(p, "org_a", API_REPO)
    RedPenSpendLedger(s).record_charge("org_a", API_REPO, 10_000, nonce="big", now=now)   # lots of spend, but no limit
    with pytest.raises(ProvisionDenied) as e:
        p.redpen_fix_this("cust_fo", "org_a", API_REPO, "f1", now=now)
    assert "monthly auto-fix spending limit" not in str(e.value)       # the cap is off (0) -> it never refuses


# --- the Code screen control (app.js under node) -----------------------------------------------------------------------
_SPEND = {"org_id": "org_a", "monthly_limit_credits": 500, "used_this_month": 120, "month": "2026-11",
          "packs": [100, 250, 500, 1000]}


def test_the_auto_fix_spending_control_renders():
    out = _screen(server={"GET api/customer/code/spend": {"data": _SPEND}}, then=r"""
const c = root.querySelector("div#code-spend").querySelector("div.card");
out.has = !!c;
out.heading = text(c.querySelector("h3"));
out.limit = c.querySelector("input").value;
out.packButtons = buttons(c).filter(b => b !== "Save");
out.text = text(c);
out.calls = calls.filter(x => x[1] === "api/customer/code/spend");
""")
    assert out["has"] and out["heading"] == "Auto-fix spending"
    assert out["limit"] == "500"
    assert out["packButtons"] == ["100 credits", "250 credits", "500 credits", "1000 credits"]
    assert "Used this month120 of 500 credits" in out["text"]
    assert out["calls"] == [["GET", "api/customer/code/spend"]]


def test_picking_a_pack_fills_the_limit_then_save_sends_only_the_limit():
    out = _screen(server={"GET api/customer/code/spend": {"data": _SPEND},
                          "POST api/customer/code/spend": {"data": {"ok": True}}}, then=r"""
const c = root.querySelector("div#code-spend");
button(c, "250 credits").click();
out.filled = c.querySelector("input").value;
button(c, "Save").click(); await flush();
out.posts = posts(); out.toasts = toasts; out.renders = renders;
""")
    assert out["filled"] == "250"
    assert out["posts"] == [["POST", "api/customer/code/spend", {"monthly_limit_credits": 250}]]
    assert out["toasts"] == ["Auto-fix spending limit saved."] and out["renders"] == 1


def test_the_control_shows_the_at_limit_state_and_refuses_a_bad_value():
    full = {**_SPEND, "monthly_limit_credits": 100, "used_this_month": 100}
    out = _screen(server={"GET api/customer/code/spend": {"data": full}}, then=r"""
out.text = text(root.querySelector("div#code-spend"));
""")
    assert "Used this month100 of 100 credits" in out["text"] and "reached its monthly auto-fix limit" in out["text"]
    for bad in ("", "-1", "2.5", "ten", "9999999999"):
        out = _screen(server={"GET api/customer/code/spend": {"data": _SPEND}}, then=f"""
const c = root.querySelector("div#code-spend");
c.querySelector("input").value = {json.dumps(bad)};
button(c, "Save").click(); await flush();
out.posts = posts(); out.errs = errs;
""")
        assert out["posts"] == [] and "whole number of credits" in out["errs"][0], bad


def test_the_control_stays_quiet_when_the_read_fails():
    # no stub for /code/spend -> the read 404s; the card shows no control (the main Code body states the error)
    out = _screen(then=r"""
const holder = root.querySelector("div#code-spend");
out.hasCard = !!(holder && holder.querySelector("div.card"));
out.spendCalls = calls.filter(x => x[1] === "api/customer/code/spend").length;
""")
    assert out["hasCard"] is False and out["spendCalls"] == 1
