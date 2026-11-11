"""Slice E1 — SessionLedger org-binding: a CUSTOMER session carries a server-bound active org, while an
operator session is byte-identical to before (no org_id key). org_id is read-time context only."""
import tempfile

from sigil.ui.sessions import SessionLedger


def test_customer_session_carries_server_bound_org_id():
    led = SessionLedger(tempfile.mkdtemp())
    sid = led.create("cust_x", "org_admin", org_id="org_abc", now=100.0)
    rec = led.resolve(sid, now=101.0)
    assert rec is not None and rec.get("org_id") == "org_abc"


def test_operator_session_record_shape_unchanged():
    led = SessionLedger(tempfile.mkdtemp())
    sid = led.create("alice", "operator", now=100.0)          # no org_id ⇒ operator session
    rec = led.resolve(sid, now=101.0)
    assert rec is not None and "org_id" not in rec            # byte-identical operator record shape
    assert rec["username"] == "alice" and rec["role"] == "operator" and rec["is_owner"] is False


def test_org_id_is_read_time_only_does_not_affect_expiry():
    led = SessionLedger(tempfile.mkdtemp(), idle_ttl=10.0, absolute_ttl=100.0)
    sid = led.create("cust_y", "viewer", org_id="org_q", now=0.0)
    assert led.resolve(sid, now=5.0).get("org_id") == "org_q"  # live, org bound
    assert led.resolve(sid, now=50.0) is None                  # idle-expired (no request for >idle_ttl)
