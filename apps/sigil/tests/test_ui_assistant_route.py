"""PR-J route wiring — the flag-gated dispatch (byte-identical when OFF), the provisioner gate + per-turn grant mint,
and a provisioner-level END-TO-END through the REAL model gateway (a fake model behind it — never a real provider).

Byte-identical when off: with ``VIGIL_CUSTOMER_ASSISTANT`` unset, dispatching ``assistant_ask`` returns None (handled
as an unknown action → 404), exactly as before this feature existed. Nothing is minted, no grant, no model request.
"""
from __future__ import annotations

import glob
import json
import tempfile
import time

import pytest

from sigil import config
from sigil import model_gateway as gw
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.spine.store import SpineStore
from sigil.ui.provision import ProvisionDenied, Provisioner
from sigil.ui.server import Handler
from sigil.ui.target_authorization import _customer_slug
from vigil_core.model_grant import decode_token

from test_model_gateway import NO_PROXY, OPUS, PROVIDER_KEY, _Upstream, _serve  # noqa: E402
from test_ui_assistant import _finding  # noqa: E402  (reuse the synthetic finding writer)


def _seed(member=("alice", "operator")):
    """A spine with acme (a proven host + two findings) and a member who may view_assessments; returns the path."""
    path = tempfile.mktemp(suffix=".jsonl")
    SpineStore(path).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    owner = ensure_owner_keypair()
    store = SpineStore(path)
    orgs = OrgRegistry(store, owner_key=owner)
    it = iter(range(1, 10_000))
    orgs.create_org("acme", "Acme Corp", owner="owner", issued_at=float(next(it)))
    if member:
        orgs.grant_membership("acme", member[0], member[1], issued_at=float(next(it)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge("acme", "acme.example", issued_at=float(next(it)))
    reg.verify_and_record("acme", "acme.example", method=METHOD_DNS_TXT, observed=[ch.marker], now=10.0, ttl_seconds=1e12)
    slug = _customer_slug("acme", "acme.example")
    _finding(store, slug, "F1")
    _finding(store, slug, "F2", bug_class="sqli")
    return path


class _P:
    """A minimal Provisioner double carrying ONLY what ``customer_assistant_ask`` touches (``store``/``orgs``), with the
    REAL methods bound — so the method's own gate, validation and grant mint are exercised, not a reimplementation."""

    def __init__(self, store, orgs):
        self.store, self.orgs = store, orgs

    customer_assistant_ask = Provisioner.customer_assistant_ask
    _mint_assistant_grant = Provisioner._mint_assistant_grant


# =============================================================================== byte-identical when the flag is off ==

class _RecP:
    def __init__(self):
        self.calls = []

    def customer_assistant_ask(self, requester, org_id, question, *, ip=""):
        self.calls.append((requester, org_id, question, ip))
        return {"kind": "assistant_advice", "is_advice": True, "answer": "ok", "grounded_in": [], "finding_count": 0}


def test_dispatch_is_absent_when_the_flag_is_off(monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_ASSISTANT", raising=False)
    p = _RecP()
    body = {"org_id": "acme", "question": "hi", "ip": "1.2.3.4"}
    # unbound call with a bare self (the method uses self only for the redpen_ branch, never reached here)
    out = Handler._provision_dispatch(object(), p, "assistant_ask", "alice", body)
    assert out is None and p.calls == []                               # unknown action -> None -> 404; nothing called


def test_dispatch_relays_when_the_flag_is_on(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_ASSISTANT", "1")
    p = _RecP()
    body = {"org_id": "acme", "question": "what first?", "ip": "9.9.9.9"}
    out = Handler._provision_dispatch(object(), p, "assistant_ask", "alice", body)
    assert out["kind"] == "assistant_advice"
    assert p.calls == [("alice", "acme", "what first?", "9.9.9.9")]    # org + question relayed; requester is the hop's


def test_edge_flag_helper_tracks_the_config(monkeypatch):
    from sigil.ui.custui import _assistant_on
    monkeypatch.delenv("VIGIL_CUSTOMER_ASSISTANT", raising=False)
    assert _assistant_on() is False
    monkeypatch.setenv("VIGIL_CUSTOMER_ASSISTANT", "1")
    assert _assistant_on() is True


# ================================================================================= the provisioner gate + validation ==

def test_a_non_member_is_denied(monkeypatch):
    monkeypatch.delenv("VIGIL_METERED_BILLING", raising=False)
    store = SpineStore(_seed())
    p = _P(store, OrgRegistry(store, owner_key=ensure_owner_keypair()))
    with pytest.raises(ProvisionDenied):                              # bob holds no membership in acme
        p.customer_assistant_ask("bob", "acme", "am I vulnerable?", ip="1.2.3.4")


def test_an_empty_question_is_denied(monkeypatch):
    monkeypatch.delenv("VIGIL_METERED_BILLING", raising=False)
    store = SpineStore(_seed())
    p = _P(store, OrgRegistry(store, owner_key=ensure_owner_keypair()))
    with pytest.raises(ProvisionDenied):
        p.customer_assistant_ask("alice", "acme", "   ", ip="1.2.3.4")


def test_metered_billing_fails_closed_for_now(monkeypatch):
    """The HONEST TODO made a hard gate: while metered billing is ON the assistant grant has no wallet allowance, so
    the gateway would refuse it — the method fails closed rather than mint a grant that cannot be admitted."""
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    store = SpineStore(_seed())
    p = _P(store, OrgRegistry(store, owner_key=ensure_owner_keypair()))
    with pytest.raises(ProvisionDenied):
        p.customer_assistant_ask("alice", "acme", "what should I fix first?", ip="1.2.3.4")


def test_mint_assistant_grant_is_owner_signed_and_well_formed():
    """The per-turn grant verifies under the owner key and binds exactly the org / model / cheapest effort / small cap
    / short life the config names — so the gateway admits it and a leaked token can spend no more than the cap."""
    owner = ensure_owner_keypair()
    store = SpineStore(_seed())
    p = _P(store, OrgRegistry(store, owner_key=owner))
    now = time.time()
    token = p._mint_assistant_grant("acme", owner, now=now)
    grant, reason = decode_token(token, owner.public_key_b64)
    assert grant is not None, reason
    assert grant.org_id == "acme" and grant.model == config.assistant_model() and grant.effort == "high"
    assert grant.cap_nano_usd == config.assistant_cap_nano_usd()
    assert grant.engagement_slug.startswith("assistant:")
    assert 0 < grant.not_after - grant.issued_at <= 301
    # a DIFFERENT owner key must NOT verify it (it is unforgeable)
    from vigil_core import generate_keypair
    assert decode_token(token, generate_keypair().public_key_b64)[0] is None
    # two turns get distinct nonces -> distinct meters (spend never collides onto one meter)
    assert p._mint_assistant_grant("acme", owner, now=now) != token


# ===================================================================== provisioner END-TO-END through a real gateway ==

@pytest.fixture()
def live_gateway(tmp_path, monkeypatch):
    """A REAL model gateway started with the COCKPIT owner key (so a provisioner-minted grant verifies), a fake model
    behind it, reachable at ``config.model_gateway_url()``. Proxy env scrubbed so the loopback dial goes direct."""
    for v in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    monkeypatch.delenv("VIGIL_METERED_BILLING", raising=False)
    owner = ensure_owner_keypair()
    up = _serve(_Upstream)
    meter_dir = tmp_path / "meter"
    cfg = gw.GatewayConfig(api_key=PROVIDER_KEY, owner_pubkey=owner.public_key_b64, meter_dir=meter_dir,
                           upstream=f"http://127.0.0.1:{up.server_address[1]}", opener=NO_PROXY)
    server, _t = gw.start(cfg)
    monkeypatch.setenv("VIGIL_MODEL_GATEWAY_PORT", str(server.server_address[1]))
    monkeypatch.setenv("VIGIL_ASSISTANT_MODEL", OPUS)                  # a priced model the gateway will accept
    yield server, up, meter_dir
    server.shutdown()
    server.server_close()
    up.shutdown()
    up.server_close()


def test_provisioner_answers_through_the_gateway_metered_and_without_minting(live_gateway):
    server, up, meter_dir = live_gateway
    path = _seed()
    store = SpineStore(path)
    p = _P(store, OrgRegistry(store, owner_key=ensure_owner_keypair()))
    before = len(list(SpineStore(path).iter_records()))
    out = p.customer_assistant_ask("alice", "acme", "what should I fix first?", ip="1.2.3.4")
    assert out["kind"] == "assistant_advice" and out["is_advice"] is True and out["answer"] == "ok"
    assert set(out["grounded_in"]) == {"F1", "F2"} and out["finding_count"] == 2
    # the fake provider saw exactly ONE model request — the turn really went through the metered gateway
    assert len([x for x in up.seen if x["path"].startswith("/v1/messages")]) == 1
    # a meter file exists with the write-ahead open + the metered usage (the turn was METERED)
    files = glob.glob(str(meter_dir / "*.jsonl"))
    assert files, "no meter file written — the turn was not metered"
    kinds = [json.loads(ln)["kind"] for ln in open(files[0]).read().splitlines()]
    assert "open" in kinds and ("usage" in kinds or "release" in kinds), kinds
    assert len(list(SpineStore(path).iter_records())) == before        # answered without minting a finding
