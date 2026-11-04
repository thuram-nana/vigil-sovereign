"""Slice E1 — the OFF-by-default email sender + purpose-bound verification/recovery tokens.

Load-bearing invariants (a false-green here is an account-takeover / trial-farming path):
  * the default sender sends NOTHING and says so (no silent dependency on an external relay);
  * a token is SINGLE-USE (a replay returns None), TTL-bounded (expired → None), and PURPOSE-bound
    (a verify token is refused on the recover path and vice-versa) — AND a wrong-purpose probe does NOT
    burn a still-valid token;
  * a malformed/absent token and an unknown purpose fail closed.
"""
from __future__ import annotations

import tempfile

import pytest

from sigil.ui.email_channel import (PURPOSE_RECOVER, PURPOSE_VERIFY, EmailTokenLedger,
                                     NullEmailSender, SmtpEmailSender)


def test_null_sender_is_off_by_default():
    assert NullEmailSender().send("a@x.com", "hi", "body") is False


def test_smtp_sender_fails_soft_on_unreachable_host():
    # connecting to a closed port must NOT raise into the auth path — it returns False (not delivered).
    s = SmtpEmailSender("127.0.0.1", 1, from_addr="noreply@x.com", timeout=1.0)
    assert s.send("a@x.com", "hi", "body") is False


def _led():
    return EmailTokenLedger(tempfile.mkdtemp(), ttl_s=100.0)


def test_issue_then_consume_once():
    led = _led()
    tok = led.issue("a@x.com", PURPOSE_VERIFY, now=0.0)
    assert isinstance(tok, str) and tok
    assert led.consume(tok, PURPOSE_VERIFY, now=1.0) == "a@x.com"   # first consume returns the email
    assert led.consume(tok, PURPOSE_VERIFY, now=2.0) is None        # single-use: replay refused


def test_expired_token_refused():
    led = _led()
    tok = led.issue("a@x.com", PURPOSE_VERIFY, now=0.0)
    assert led.consume(tok, PURPOSE_VERIFY, now=101.0) is None      # past the 100s TTL


def test_wrong_purpose_refused_without_consuming():
    led = _led()
    tok = led.issue("a@x.com", PURPOSE_VERIFY, now=0.0)
    # a verify token probed on the recover path is refused...
    assert led.consume(tok, PURPOSE_RECOVER, now=1.0) is None
    # ...and is NOT burned — it still works for its real purpose (no cross-purpose DoS)
    assert led.consume(tok, PURPOSE_VERIFY, now=2.0) == "a@x.com"


def test_malformed_or_absent_token_is_none():
    led = _led()
    assert led.consume("", PURPOSE_VERIFY, now=0.0) is None
    assert led.consume("never-issued", PURPOSE_VERIFY, now=0.0) is None


def test_unknown_purpose_raises():
    led = _led()
    with pytest.raises(ValueError):
        led.issue("a@x.com", "login", now=0.0)
    assert led.consume("x", "login", now=0.0) is None              # consume fail-closed on bad purpose


def test_revoke_for_email_clears_outstanding():
    led = _led()
    t1 = led.issue("a@x.com", PURPOSE_VERIFY, now=0.0)
    t2 = led.issue("a@x.com", PURPOSE_RECOVER, now=0.0)
    led.issue("b@x.com", PURPOSE_VERIFY, now=0.0)                   # a different email survives
    assert led.revoke_for_email("a@x.com") == 2
    assert led.consume(t1, PURPOSE_VERIFY, now=1.0) is None
    assert led.consume(t2, PURPOSE_RECOVER, now=1.0) is None
