"""The onboarding tour's SERVER-SIDE state: has this customer finished or skipped it? Behind
VIGIL_CUSTOMER_ONBOARDING (default OFF), account-level, for the SESSION's account only.

The customer app opens the tour after a person's first sign-in and keeps opening it — on any device — until they
finish or skip it. That answer is kept by the provisioner, per account, so it follows the account, not the browser:

  * ui/onboarding_store keeps one hashed-name 0600 file per account in a 0700 directory under customer/; anything
    missing, unreadable, malformed, oversized or symlinked reads "pending" (the tour shows once more), never an error;
    only "done" and "skipped" are ever written;
  * Provisioner.onboarding_state / onboarding_record serve an ACTIVE customer only, record only "done"/"skipped",
    write nothing for an unchanged answer, and audit only the FIRST close (one row per account — a customer cannot
    grow the signed spine by re-posting);
  * the cockpit's provision dispatch is absent (unknown action -> 404) unless the flag is on, and acts for the hop
    principal, never a body field;
  * the edge route GET/POST api/customer/onboarding is absent (404) unless the flag is on, needs a session (401), and
    reads/records for the session's account only — a body naming another account changes nothing for it.

Mutation-verify targets (each neuter reds a NAMED test here):
  * read_state ignores the file (always "pending")            -> test_the_store_round_trips_per_account
  * write_state accepts any state                              -> test_the_store_records_only_done_or_skipped
  * read_state follows a symlink                               -> test_the_store_reads_anything_odd_as_pending
  * the provisioner skips the active-customer check            -> test_the_provisioner_serves_active_customers_only
  * the cockpit dispatch ignores the flag                      -> test_the_cockpit_dispatch_exists_only_with_the_flag
  * the cockpit dispatch takes the account from the body       -> test_the_cockpit_dispatch_exists_only_with_the_flag
  * the provisioner records without an audit row              -> test_the_provisioner_serves_active_customers_only
  * every re-post is written and audited (unbounded spine)     -> test_re_posting_the_answer_cannot_grow_the_spine
  * the edge route ignores the flag                            -> test_the_edge_route_is_absent_with_the_flag_off
  * the edge takes the account from the body                   -> test_the_edge_relays_for_the_session_account_only,
                                                                  test_the_edge_reads_and_records_for_the_session_account
"""
from __future__ import annotations

import json
import re
import shutil
import stat
import tempfile

import pytest

from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _get, _opener, _post, _stack

from sigil import config
from sigil.governor.customers import CustomerRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui import onboarding_store as store
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import ProvisionDenied, ProvisionError, Provisioner

OWNER = generate_keypair()
OP = OWNER.public_key_b64


@pytest.fixture
def home(tmp_path, monkeypatch):
    d = tmp_path / "customer" / "onboarding"
    monkeypatch.setattr(config, "CUSTOMER_ONBOARDING_DIR", d)
    return d


# --- the store ------------------------------------------------------------------------------------------------------
def test_the_store_round_trips_per_account(home):
    assert config.CUSTOMER_ONBOARDING_DIR == home
    assert store.read_state("ana") == "pending" and not home.exists()      # reading never creates anything
    assert store.write_state("ana", "skipped", now=5.0) == "skipped"
    assert store.read_state("ana") == "skipped" and store.read_state("ben") == "pending"
    store.write_state("ana", "done", now=6.0)                    # a replayed tour records again: the latest stands
    assert store.read_state("ana") == "done"
    store.write_state("ben", "skipped", now=7.0)
    assert store.read_state("ben") == "skipped" and store.read_state("ana") == "done"
    files = sorted(home.iterdir())
    assert len(files) == 2
    for f in files:                                              # no username in a path; one 0600 file each
        assert re.fullmatch(r"[0-9a-f]{64}\.json", f.name) and "ana" not in f.name and "ben" not in f.name
        assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert stat.S_IMODE(home.stat().st_mode) == 0o700
    assert {json.loads(f.read_text())["state"] for f in files} == {"done", "skipped"}


def test_the_store_records_only_done_or_skipped(home):
    for bad in ("", "pending", "DONE", "done ", "yes", "skipped\n", "true"):
        with pytest.raises(ValueError):
            store.write_state("ana", bad, now=1.0)
    with pytest.raises(ValueError):
        store.write_state("", "done", now=1.0)                  # never a record without an account
    assert not home.exists() or not any(home.iterdir())
    assert store.read_state("") == "pending"
    assert store.STATES == ("done", "skipped") and store.PENDING == "pending"


def test_the_store_reads_anything_odd_as_pending(home, tmp_path):
    store.write_state("ana", "done", now=1.0)
    f = next(home.iterdir())
    for raw in (b"", b"not json", b"[]", b"null", b'{"state": "pending"}', b'{"state": "DONE"}', b'{"state": 1}',
                b"\xff\xfe", json.dumps({"state": "done", "pad": "x" * 5000}).encode(),
                b'{"state": "done"}' + b" " * 5000):          # oversized, though its first 4 KiB parse: still pending
        f.write_bytes(raw)
        assert store.read_state("ana") == "pending", raw[:24]
    # a symlink planted where the account's file goes is never followed ...
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text(json.dumps({"state": "done"}))
    f.unlink()
    f.symlink_to(elsewhere)
    assert store.read_state("ana") == "pending"
    # ... and a record replaces the link itself, never writing through it
    store.write_state("ana", "skipped", now=2.0)
    assert not f.is_symlink() and store.read_state("ana") == "skipped"
    assert json.loads(elsewhere.read_text()) == {"state": "done"}
    shutil.rmtree(home)                                          # the directory gone: pending, no error
    assert store.read_state("ana") == "pending"


def test_the_directory_is_customer_plane_state_outside_backups():
    from sigil import backup
    assert config.CUSTOMER_ONBOARDING_DIR.parent == config.CUSTOMER_SESSIONS_DIR.parent        # SIGIL_HOME/customer
    assert config.CUSTOMER_ONBOARDING_DIR.parent.name == "customer"
    assert "onboarding tour" in backup._EXCLUSION_REASONS["customer"]


# --- the provisioner ------------------------------------------------------------------------------------------------
def _prov(now_fn=lambda: 1234.0):
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    custs = CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    p = Provisioner(
        s, customers=custs, orgs=OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP),
        wallet=WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP),
        email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
        email_sender=NullEmailSender(), trial_credits=100, now_fn=now_fn)
    return p, s, custs


def _audits(s):
    return [r.payload for r in s.iter_records()
            if r.kind == "event" and isinstance(r.payload, dict) and r.payload.get("signal") == "provision.audit"
            and r.payload.get("action") == "onboarding_record"]


def test_the_provisioner_serves_active_customers_only(home):
    p, s, custs = _prov()
    custs.create("ana@acme.io", issued_at=1.0, password="password-xyz", username="cust_ana")
    custs.create("ben@acme.io", issued_at=1.0, password="password-xyz", username="cust_ben")
    assert p.onboarding_state("cust_ana") == {"ok": True, "state": "pending"}
    assert p.onboarding_record("cust_ana", "skipped") == {"ok": True, "state": "skipped"}
    assert p.onboarding_state("cust_ana") == {"ok": True, "state": "skipped"}
    assert p.onboarding_state("cust_ben") == {"ok": True, "state": "pending"}     # per account
    assert json.loads(next(home.iterdir()).read_text())["at"] == 1234.0          # the provisioner's clock
    for who in ("", "cust_nobody", "owner"):                                       # not an active customer
        with pytest.raises(ProvisionDenied):
            p.onboarding_state(who)
        with pytest.raises(ProvisionDenied):
            p.onboarding_record(who, "done")
    custs.revoke("cust_ben")
    with pytest.raises(ProvisionDenied):
        p.onboarding_record("cust_ben", "done")
    with pytest.raises(ProvisionDenied):
        p.onboarding_state("cust_ben")
    assert store.read_state("cust_ben") == "pending"
    for bad in ("", "pending", "DONE", "reset"):
        with pytest.raises(ProvisionError):
            p.onboarding_record("cust_ana", bad)
    assert p.onboarding_state("cust_ana")["state"] == "skipped"                   # a refused record changes nothing
    a = _audits(s)
    assert [(x["requester"], x["target"], x["outcome"]) for x in a] == [("cust_ana", "cust_ana", "skipped")]


def test_re_posting_the_answer_cannot_grow_the_spine(home):
    """Bounded: the same answer again writes nothing; only the FIRST close is audited (one row per account), so a
    customer re-posting the state in a loop adds nothing to the signed spine."""
    clock = iter(range(1000, 2000))
    p, s, custs = _prov(now_fn=lambda: float(next(clock)))           # a write would stamp a new time
    custs.create("ana@acme.io", issued_at=1.0, password="password-xyz", username="cust_ana")
    p.onboarding_record("cust_ana", "skipped")
    f = next(home.iterdir())
    first, ino = f.read_bytes(), f.stat().st_ino
    n = s.count()
    for _ in range(25):
        assert p.onboarding_record("cust_ana", "skipped") == {"ok": True, "state": "skipped"}
    assert f.read_bytes() == first and f.stat().st_ino == ino        # unchanged answer: no write at all
    assert s.count() == n                                             # and nothing appended to the spine
    for state in ("done", "skipped", "done"):                         # a replayed tour updates the answer ...
        assert p.onboarding_record("cust_ana", state)["state"] == state
    assert store.read_state("cust_ana") == "done"
    assert len(_audits(s)) == 1                                       # ... but only the first close was audited


def test_a_store_that_cannot_be_written_is_a_clean_refusal(home, monkeypatch):
    p, s, custs = _prov()
    custs.create("ana@acme.io", issued_at=1.0, password="password-xyz", username="cust_ana")

    def boom(*a, **k):
        raise PermissionError("read-only")

    monkeypatch.setattr(store, "write_state", boom)
    with pytest.raises(ProvisionError, match="could not be saved: PermissionError"):
        p.onboarding_record("cust_ana", "done")
    assert _audits(s) == []                                        # nothing recorded, nothing audited


# --- the cockpit's provision dispatch ---------------------------------------------------------------------------------
class _P:
    def __init__(self):
        self.calls: list = []

    def __getattr__(self, name):
        def f(*a, **k):
            self.calls.append((name, a, k))
            return {"ok": True}
        return f


def test_the_cockpit_dispatch_exists_only_with_the_flag(monkeypatch):
    from sigil.ui.server import Handler
    monkeypatch.delenv("VIGIL_CUSTOMER_ONBOARDING", raising=False)
    for a in ("onboarding_get", "onboarding_set"):
        p = _P()
        assert Handler._provision_dispatch(None, p, a, "cust_ana", {"state": "done"}) is None   # -> 404
        assert p.calls == []
    monkeypatch.setenv("VIGIL_CUSTOMER_ONBOARDING", "1")
    p = _P()
    Handler._provision_dispatch(None, p, "onboarding_get", "cust_ana", {"username": "cust_eve", "ip": "1.2.3.4"})
    Handler._provision_dispatch(None, p, "onboarding_set", "cust_ana",
                                {"state": "skipped", "username": "cust_eve", "requester": "cust_eve"})
    # the account is the hop principal — a body field naming someone else is never used
    assert p.calls == [("onboarding_state", ("cust_ana",), {}), ("onboarding_record", ("cust_ana", "skipped"), {})]


# --- the edge -----------------------------------------------------------------------------------------------------------
def _edge_stub(session):
    """A customer-edge handler with its session and its hop to the provisioner stubbed: what does it relay?"""
    from sigil.ui.custui import CustomerHandler
    h = object.__new__(CustomerHandler)
    sent: dict = {}
    h._session = lambda: session
    h._ip = lambda: "1.2.3.4"
    h._provision = lambda action, principal, body: (sent.update(action=action, principal=principal, body=body)
                                                    or (200, {"ok": True, "state": "pending"}))
    h._json = lambda obj, code=200: sent.update(code=code, out=obj)
    h._deny = lambda code=403, msg="forbidden": sent.update(code=code, out={"error": msg})
    return h, sent


def test_the_edge_relays_for_the_session_account_only(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_ONBOARDING", "1")
    h, sent = _edge_stub({"username": "cust_ana", "org_id": "org_a"})
    h.path = "/api/customer/onboarding?username=cust_eve"
    h.do_GET()
    assert sent == {"action": "onboarding_get", "principal": "cust_ana", "body": {"ip": "1.2.3.4"},
                    "code": 200, "out": {"ok": True, "state": "pending"}}
    h, sent = _edge_stub({"username": "cust_ana"})
    h._dispatch("onboarding", {"state": "done", "username": "cust_eve", "requester": "cust_eve"})
    assert sent["action"] == "onboarding_set" and sent["principal"] == "cust_ana"
    assert sent["body"] == {"state": "done", "ip": "1.2.3.4"}                  # only the state travels
    for session in (None, {}, {"username": ""}):                               # no signed-in account: 401, no hop
        h, sent = _edge_stub(session)
        h._dispatch("onboarding", {"state": "done"})
        assert sent["code"] == 401 and "action" not in sent, session
        h, sent = _edge_stub(session)
        h.path = "/api/customer/onboarding"
        h.do_GET()
        assert sent["code"] == 401 and "action" not in sent, session


def test_the_edge_route_is_absent_with_the_flag_off(monkeypatch):
    """The edge's own gate (the cockpit has its own too): with the flag off the route is exactly an unknown route."""
    monkeypatch.delenv("VIGIL_CUSTOMER_ONBOARDING", raising=False)
    h, sent = _edge_stub({"username": "cust_ana"})
    h.path = "/api/customer/onboarding"
    h.do_GET()
    h2, unknown = _edge_stub({"username": "cust_ana"})
    h2.path = "/api/customer/nope"
    h2.do_GET()
    assert sent == unknown == {"code": 404, "out": {"error": "not found"}}
    h, sent = _edge_stub({"username": "cust_ana"})
    h._dispatch("onboarding", {"state": "done"})
    h2, unknown = _edge_stub({"username": "cust_ana"})
    h2._dispatch("no/such/route", {})
    assert sent == unknown == {"code": 404, "out": {"error": "unknown action"}}


# --- the edge, over the real hop ----------------------------------------------------------------------------------------
def _signed_up(tmp_path, monkeypatch, email):
    sov, edge, ep, sp = _stack(tmp_path, monkeypatch)
    op = _opener()
    t = _post(op, ep, "/api/customer/signup/request", {"email": email})[1]["dev_token"]
    conf = _post(op, ep, "/api/customer/signup/confirm", {"token": t, "password": "customer-pw-1", "org_name": "Acme"})
    assert conf[0] == 200, conf
    return sov, edge, ep, op, conf[1]["username"]


def _sign_in(ep, email):
    op = _opener()
    c, r = _post(op, ep, "/api/customer/login", {"email": email, "password": "customer-pw-1"})
    assert c == 200, (c, r)
    return op, r["username"]


def test_with_the_flag_off_nothing_is_served_or_recorded(tmp_path, monkeypatch, home):
    monkeypatch.delenv("VIGIL_CUSTOMER_ONBOARDING", raising=False)
    sov, edge, ep, op, user = _signed_up(tmp_path, monkeypatch, "off@acme.io")
    try:
        assert _get(op, ep, "/api/customer/onboarding")[0] == 404
        assert _post(op, ep, "/api/customer/onboarding", {"state": "done"})[0] == 404
        assert not home.exists()                                                  # nothing was recorded
    finally:
        sov.shutdown()
        edge.shutdown()


def test_the_edge_reads_and_records_for_the_session_account(tmp_path, monkeypatch, home):
    monkeypatch.setenv("VIGIL_CUSTOMER_ONBOARDING", "1")
    sov, edge, ep, op, ana = _signed_up(tmp_path, monkeypatch, "ana@acme.io")
    try:
        anon = _opener()
        assert _get(anon, ep, "/api/customer/onboarding")[0] == 401                     # no session
        assert _post(anon, ep, "/api/customer/onboarding", {"state": "done"})[0] == 401
        assert not home.exists()
        assert _post(op, ep, "/api/customer/onboarding", {"state": "done"},
                     origin="https://evil.example")[0] == 403                           # a cross-origin write
        # a first sign-in: the tour is ahead of this account
        assert _get(op, ep, "/api/customer/onboarding") == (200, {"ok": True, "state": "pending"})
        # the tour was skipped — recorded for the SESSION's account, whatever the body names
        c, r = _post(op, ep, "/api/customer/onboarding", {"state": "skipped", "username": "cust_eve"})
        assert (c, r) == (200, {"ok": True, "state": "skipped"})
        assert store.read_state(ana) == "skipped" and store.read_state("cust_eve") == "pending"
        # a sign-in on another device (a new session) sees the same answer: the tour does not open there
        op2, again = _sign_in(ep, "ana@acme.io")
        assert again == ana and _get(op2, ep, "/api/customer/onboarding") == (200, {"ok": True, "state": "skipped"})
        # only "done" / "skipped" are recorded; anything else is refused and changes nothing
        for bad in ({"state": "pending"}, {"state": "nope"}, {}, {"state": ["done"]}):
            assert _post(op2, ep, "/api/customer/onboarding", bad)[0] == 400, bad
        assert store.read_state(ana) == "skipped"
        assert _post(op2, ep, "/api/customer/onboarding", {"state": "done"}) == (200, {"ok": True, "state": "done"})
        # another account of the same deployment still has its tour ahead of it
        sov2_t = _post(_opener(), ep, "/api/customer/signup/request", {"email": "ben@other.io"})[1]["dev_token"]
        opb = _opener()
        assert _post(opb, ep, "/api/customer/signup/confirm",
                     {"token": sov2_t, "password": "customer-pw-1", "org_name": "Other"})[0] == 200
        assert _get(opb, ep, "/api/customer/onboarding") == (200, {"ok": True, "state": "pending"})
        assert _get(op, ep, "/api/customer/onboarding") == (200, {"ok": True, "state": "done"})
    finally:
        sov.shutdown()
        edge.shutdown()
