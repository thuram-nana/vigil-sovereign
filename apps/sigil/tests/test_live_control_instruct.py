"""Live Control MISSION STEERING — the advisory instruction write path end-to-end through the sovereign
provisioner into the offense-local instruction queue the engine drains. Deterministic, NO-LLM, FATAL-2-clean.

The feature: a customer tells their OWN running engagement what to prioritise ("focus on auth") WHILE it runs,
without restarting it. Invariants a false-green would break:
  * tenant isolation — a customer can steer ONLY a host their org has ownership-proven; another tenant's
    engagement (and an unproven host) is structurally unreachable;
  * the instruction LANDS on the exact queue the engine's OODA loop drains (reuse, not a second store);
  * ADVISORY-only — it is the queue's own safety model (fires no tool, relaxes no scope, mints no fact);
  * idempotent on idem_key — a double-click / reconnect enqueues once;
  * flag-OFF => the action is refused (default-OFF surface stays inert);
  * empty text => refused (fail-closed).
"""
from __future__ import annotations

import itertools
import os
import tempfile

import pytest

_iss = itertools.count(1)


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("VIGIL_LIVE_DIR", tempfile.mkdtemp())        # the shared advisory-instruction store
    monkeypatch.setenv("VIGIL_CUSTOMER_LIVE_CONTROL", "1")


def _store():
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.spine.store import SpineStore
    ensure_owner_keypair()
    return SpineStore(os.path.join(tempfile.mkdtemp(), "spine.jsonl"))


def _prove(store, org, host):
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=1e9, ttl_seconds=1e12)


def _slug(org, host):
    from sigil.ui.target_authorization import _customer_slug
    return _customer_slug(org, host)


# --- the sovereign adapter: live_control.submit_instruction -------------------------------------------
def test_submit_lands_on_the_queue_for_the_proven_host():
    from vigil_integration.live import instructions

    from sigil.ui import live_control
    s = _store()
    _prove(s, "org_a", "api.example.com")
    r = live_control.submit_instruction(s, "org_a", "api.example.com", "focus on auth")
    assert r["ok"] and r["idempotent"] is False and r["slug"] == _slug("org_a", "api.example.com")
    # the engine drains EXACTLY this instruction from the SAME store (reuse of the existing queue). drain()
    # returns the instruction texts, newest since the last cursor.
    assert instructions.drain(r["slug"]) == ["focus on auth"]


def test_cannot_steer_a_host_the_org_never_proved():
    from sigil.ui import live_control
    s = _store()
    _prove(s, "org_a", "api.example.com")
    with pytest.raises(ValueError):
        live_control.submit_instruction(s, "org_a", "other.example.com", "focus on auth")   # host not proven
    # cross-tenant: org_b cannot steer org_a's proven host (the slug is resolved only for org_b's own proven set)
    with pytest.raises(ValueError):
        live_control.submit_instruction(s, "org_b", "api.example.com", "focus on auth")


def test_empty_text_is_refused():
    from sigil.ui import live_control
    s = _store()
    _prove(s, "org_a", "api.example.com")
    with pytest.raises(ValueError):
        live_control.submit_instruction(s, "org_a", "api.example.com", "   ")


def test_idempotent_on_idem_key():
    from vigil_integration.live import instructions

    from sigil.ui import live_control
    s = _store()
    _prove(s, "org_a", "api.example.com")
    r1 = live_control.submit_instruction(s, "org_a", "api.example.com", "focus on auth", idem_key="k1")
    r2 = live_control.submit_instruction(s, "org_a", "api.example.com", "again", idem_key="k1")
    assert r1["idempotent"] is False and r2["idempotent"] is True and r1["seq"] == r2["seq"]
    # only ONE instruction was enqueued despite two submits under the same key
    assert instructions.drain(_slug("org_a", "api.example.com")) == ["focus on auth"]


# --- the provisioner action: flag + admit_customer(run_engagement) + tenant-bind ----------------------
def _prov(store):
    from sigil.governor.customers import CustomerRegistry
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
    from sigil.ui.login_ratelimit import LoginRateLimiter
    from sigil.ui.provision import Provisioner
    orgs = OrgRegistry(store)
    if orgs.org("org_a") is None:
        orgs.create_org("org_a", "org_a", owner="alice", issued_at=float(next(_iss)))
    # `operator` is the per-org TESTING role that carries run_engagement (org_admin is billing/member-admin
    # only — billing-authz != testing-authz); a launching customer holds operator, so steering requires it.
    orgs.grant_membership("org_a", "alice", "operator", issued_at=float(next(_iss)))
    return Provisioner(store, customers=CustomerRegistry(store), orgs=orgs, wallet=WalletRegistry(store),
                       email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
                       rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=1000, window_s=1e4,
                                                     base_lock_s=1.0),
                       email_sender=NullEmailSender(), now_fn=lambda: float(next(_iss)))


def test_provisioner_instruct_accepts_for_admin_then_is_flag_gated(monkeypatch):
    from vigil_integration.live import instructions

    from sigil.ui.provision import ProvisionDenied
    s = _store()
    _prove(s, "org_a", "api.example.com")
    p = _prov(s)
    r = p.launch_instruct("alice", "org_a", host="api.example.com", text="focus on auth")
    assert r["slug"] == _slug("org_a", "api.example.com") and isinstance(r["seq"], int)
    assert instructions.drain(r["slug"]) == ["focus on auth"]
    # flag OFF -> the action is refused (the whole surface is inert by default)
    monkeypatch.delenv("VIGIL_CUSTOMER_LIVE_CONTROL")
    with pytest.raises(ProvisionDenied):
        p.launch_instruct("alice", "org_a", host="api.example.com", text="focus on auth")


def test_provisioner_instruct_denies_a_non_member_and_an_unproven_host(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    s = _store()
    _prove(s, "org_a", "api.example.com")
    p = _prov(s)
    # a requester not admitted for org_a cannot steer it (tenant isolation at admit)
    with pytest.raises(ProvisionDenied):
        p.launch_instruct("mallory", "org_a", host="api.example.com", text="x")
    # an admin steering a host the org never proved is refused (no engagement to steer)
    with pytest.raises(ProvisionDenied):
        p.launch_instruct("alice", "org_a", host="not-proven.example.com", text="x")


def test_instruction_text_is_bounded_but_accepted(monkeypatch):
    # a long instruction is length-bounded by the queue, never rejected for size, and still lands advisory-only
    from vigil_integration.live import instructions

    from sigil.ui import live_control
    s = _store()
    _prove(s, "org_a", "api.example.com")
    r = live_control.submit_instruction(s, "org_a", "api.example.com", "x" * 10000)
    (one,) = instructions.drain(r["slug"])
    assert 0 < len(one) <= 4000


def test_fatal2_live_control_imports_no_framework_or_offense():
    # FATAL-2: the sovereign Live Control adapter must not pull framework.*/strix.* into the customer plane.
    # Its offense-local queue crossing is a LAZY (function-level) import of the import-clean instructions module,
    # so importing the adapter itself stays clean.
    import subprocess
    import sys
    code = ("import sys; import sigil.ui.live_control as m; "
            "bad=[k for k in sys.modules if k=='framework' or k.startswith('framework.') or k.startswith('strix')]; "
            "assert not bad, bad; print('ok')")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)})
    assert r.returncode == 0 and r.stdout.strip() == "ok", (r.stdout, r.stderr)
