"""Route-via-sovereign: the cockpit signs an OFFENSE per-action approval in-process with the owner key,
and the KEYLESS offense broker verifies + consumes it.

Operator choices under test: key model = unify on the sovereign owner key; posture = sign in-process on
click. The private key never leaves the sovereign process; only a public-safe token crosses the shared
filesystem seam, and the offense broker independently verifies signature + key-pin + action-binding and
burns the single-use nonce — so nothing dropped in signed/ can authorize without a real owner signature.
"""
from __future__ import annotations

import os
import tempfile
import time

import pytest


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())      # the shared approvals dir
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())     # isolate the sigil owner vault/spine
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.delenv("VIGIL_APPROVAL_OWNER_KEY", raising=False)  # the cockpit key, not an env key
    monkeypatch.setenv("VIGIL_APPROVAL_WAIT_SECONDS", "2")        # bound any broker poll in the test


def _publish(tool="exec_command", target="strix:exec", digest=""):
    from vigil_integration.live.approval_broker import ApprovalBroker, approvals_root
    from vigil_integration.live.approval_token import ApprovalAction
    br = ApprovalBroker(approvals_root(os.environ["VIGIL_BASE_DIR"]))
    br.bind(ApprovalAction(tool_name=tool, target=target, action_digest=digest))
    return br, br.publish_current()


# --- authority binding -----------------------------------------------------------------------------
def test_bind_pins_the_owner_key_and_status_reflects_it():
    from sigil.ui import offense_approvals as oa
    assert oa.authority_status()["bound"] is False       # nothing pinned yet
    assert oa.bind_authority()["ok"] is True
    st = oa.authority_status()
    assert st["bound"] is True and st["owner_key_id"] == "owner"


def test_sign_refuses_until_the_authority_is_bound():
    from sigil.ui import offense_approvals as oa
    _, pend = _publish()
    out = oa.sign_pending(pend.request_id)
    assert out["ok"] is False and out.get("needs_bind") is True   # honest refusal, no token written


# --- the security-critical round trip --------------------------------------------------------------
def test_cockpit_signed_token_is_verified_and_consumed_by_the_offense_broker():
    from sigil.ui import offense_approvals as oa
    from vigil_integration.live.approval_broker import load_authority
    from vigil_integration.live.approval_token import consume_token
    from vigil_integration.live.nonce_ledger import NonceLedger
    br, pend = _publish()
    oa.bind_authority()
    assert oa.sign_pending(pend.request_id)["ok"] is True

    got = br.token_source()                               # the offense broker polls signed/
    assert got is not None, "the cockpit-signed token did not reach the offense broker"
    tok, act = got
    auth = load_authority(os.environ["VIGIL_BASE_DIR"])
    led = NonceLedger(os.path.join(os.environ["VIGIL_BASE_DIR"], "approval-nonces"))
    d = consume_token(tok, action=act, authority=auth, ledger=led, now=time.time())
    assert d.authorized is True                            # signature + key-pin + binding all pass
    # single-use: a replay is refused
    d2 = consume_token(tok, action=act, authority=auth, ledger=led, now=time.time())
    assert d2.authorized is False


def test_a_tampered_token_is_rejected_by_binding():
    from sigil.ui import offense_approvals as oa
    from vigil_integration.live.approval_broker import load_authority
    from vigil_integration.live.approval_token import consume_token
    from vigil_integration.live.nonce_ledger import NonceLedger
    br, pend = _publish()
    oa.bind_authority(); oa.sign_pending(pend.request_id)
    tok, act = br.token_source()
    bad = type(tok)(**{**tok.__dict__, "target": "evil-elsewhere"})   # flip the bound target
    auth = load_authority(os.environ["VIGIL_BASE_DIR"])
    led = NonceLedger(os.path.join(os.environ["VIGIL_BASE_DIR"], "approval-nonces"))
    assert consume_token(bad, action=act, authority=auth, ledger=led, now=time.time()).authorized is False


# --- refusals + deny -------------------------------------------------------------------------------
def test_sign_refuses_an_unknown_request_id():
    from sigil.ui import offense_approvals as oa
    oa.bind_authority()
    out = oa.sign_pending("deadbeefdeadbeef")
    assert out["ok"] is False and "no pending" in out["error"]


def test_deny_removes_the_pending_and_writes_no_token():
    from sigil.ui import offense_approvals as oa
    from vigil_integration.live.approval_broker import approvals_root
    _, pend = _publish()
    assert len(oa.list_offense_pending()["pending"]) == 1
    assert oa.deny_pending(pend.request_id)["removed"] is True
    assert oa.list_offense_pending()["pending"] == []
    signed = approvals_root(os.environ["VIGIL_BASE_DIR"]) / "signed"
    assert not signed.exists() or not list(signed.glob("*.json")), "deny must never write a token"


# --- dispatch + boundary ---------------------------------------------------------------------------
def test_do_action_routes_the_three_offense_actions():
    from sigil.ui import actions
    assert {"offense_bind_authority", "offense_approve", "offense_deny"} <= actions.ACTIONS
    assert actions.do_action("offense_bind_authority", {})["ok"] is True
    assert actions.do_action("offense_deny", {"request_id": "nope"})["ok"] is True   # clean no-op
    assert actions.do_action("offense_approve", {"request_id": "nope"})["ok"] is False


def test_offense_approvals_imports_no_offense_engine():
    # FATAL-2: the sovereign-side bridge must not pull framework/strix into the sigil process.
    import sys
    for m in [m for m in list(sys.modules) if m.startswith(("framework", "strix"))]:
        sys.modules.pop(m, None)
    from sigil.ui import offense_approvals  # noqa: F401
    assert not any(m == "framework" or m.startswith("framework.") or m == "strix" or m.startswith("strix.")
                   for m in sys.modules), "offense_approvals dragged the offense engine into the sovereign process"
