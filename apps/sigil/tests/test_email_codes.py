"""The 6-digit code in the sign-up and password-reset emails (email_channel.EmailCodeLedger + the provisioner + the
edge + the app's screens), so a person in the installed app can type it instead of following the email into a
browser.

Pinned here:
  * the ledger: bound to the email AND the purpose, single use, 10 minutes, the 5th wrong code destroys it, a new
    email replaces the previous code, raw code never on disk (hash-named, salted scrypt), bounded, exactly one winner
    under concurrency;
  * the provisioner: OFF by default (the emails and answers exactly as before, the code confirmations refused);
    ON, the emails carry the code beside the token, the code completes the SAME sign-up the token would (same
    username and org), either path ends the other, wrong codes are limited per email+purpose ACROSS re-sent codes
    and per IP, a reset by code sets the password and asks the edge to sever sessions, the answers never reveal
    whether an address has an account;
  * over the real edge -> cockpit hop: sign-up and reset by code; the reset severs a live session;
  * the app: "Enter the 6-digit code from your email", the code goes with the email address, a reset screen.
"""
from __future__ import annotations

import itertools
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest

from sigil.governor.customers import CustomerRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui.email_channel import (PURPOSE_RECOVER, PURPOSE_VERIFY, CodeGone, CodeOk, CodeWrong, EmailCodeLedger,
                                    EmailSender, EmailTokenLedger, format_code, normalize_code)
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import (ProvisionDenied, ProvisionError, ProvisionRateLimited, Provisioner,
                                _signup_org_id, _signup_username)

OWNER = generate_keypair()
OP = OWNER.public_key_b64
APP_JS = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app" / "app.js"


# ================================================================================================================
# the ledger
# ================================================================================================================
def test_a_code_is_bound_to_the_email_and_the_purpose_and_used_once(tmp_path):
    led = EmailCodeLedger(tmp_path)
    code = led.issue("a@acme.com", PURPOSE_VERIFY, bind={"u": "cust_x"}, now=100.0)
    assert len(code) == 6 and code.isdigit()
    assert led.check("b@acme.com", PURPOSE_VERIFY, code, now=101.0) == CodeGone()          # another address
    assert led.check("a@acme.com", PURPOSE_RECOVER, code, now=101.0) == CodeGone()         # another purpose
    assert led.check("a@acme.com", PURPOSE_VERIFY, format_code(code), now=101.0) == CodeOk({"u": "cust_x"})
    assert led.check("a@acme.com", PURPOSE_VERIFY, code, consume=True, now=101.0) == CodeOk({"u": "cust_x"})
    assert led.check("a@acme.com", PURPOSE_VERIFY, code, now=101.0) == CodeGone()          # used once


def test_a_code_lives_ten_minutes(tmp_path):
    led = EmailCodeLedger(tmp_path)
    code = led.issue("a@acme.com", PURPOSE_RECOVER, now=100.0)
    assert led.check("a@acme.com", PURPOSE_RECOVER, code, now=699.0) == CodeOk({})
    assert led.check("a@acme.com", PURPOSE_RECOVER, code, now=700.0) == CodeGone()


def test_the_fifth_wrong_code_destroys_it(tmp_path):
    led = EmailCodeLedger(tmp_path)
    code = led.issue("a@acme.com", PURPOSE_VERIFY, now=100.0)
    wrong = f"{(int(code) + 1) % 1_000_000:06d}"
    assert [led.check("a@acme.com", PURPOSE_VERIFY, wrong, now=101.0) for _ in range(5)] == \
        [CodeWrong(4), CodeWrong(3), CodeWrong(2), CodeWrong(1), CodeWrong(0)]
    assert led.check("a@acme.com", PURPOSE_VERIFY, code, now=101.0) == CodeGone()
    assert [p for p in tmp_path.iterdir() if not p.name.startswith(".")] == []


@pytest.mark.parametrize("typed", ["", "12345", "1234567", "abcdef", "١٢٣٤٥٦"])
def test_a_malformed_code_counts_as_wrong(tmp_path, typed):
    led = EmailCodeLedger(tmp_path)
    led.issue("a@acme.com", PURPOSE_VERIFY, now=100.0)
    assert led.check("a@acme.com", PURPOSE_VERIFY, typed, now=101.0) == CodeWrong(4)


def test_a_new_email_replaces_the_previous_code(tmp_path):
    led = EmailCodeLedger(tmp_path)
    first = led.issue("a@acme.com", PURPOSE_VERIFY, now=100.0)
    second = led.issue("a@acme.com", PURPOSE_VERIFY, now=101.0)
    if first != second:
        assert led.check("a@acme.com", PURPOSE_VERIFY, first, now=102.0) == CodeWrong(4)
    assert led.check("a@acme.com", PURPOSE_VERIFY, second, now=102.0) == CodeOk({})


def test_the_raw_code_and_the_email_are_never_on_disk(tmp_path):
    led = EmailCodeLedger(tmp_path)
    code = led.issue("alice@acme.com", PURPOSE_VERIFY, bind={"u": "cust_1", "o": "org_1"}, now=100.0)
    files = [p for p in tmp_path.iterdir() if not p.name.startswith(".")]
    assert len(files) == 1 and len(files[0].name) == 64 and set(files[0].name) <= set("0123456789abcdef")
    assert oct(files[0].stat().st_mode & 0o777) == "0o600"
    blob = files[0].read_text()
    assert code not in blob and format_code(code) not in blob and "alice@acme.com" not in blob
    rec = json.loads(blob)
    assert set(rec) == {"exp", "salt", "hash", "attempts", "bind"}
    # the stored hash is the salted scrypt of the code, bound to the purpose and the address
    assert EmailCodeLedger._hash(code, rec["salt"], "alice@acme.com", PURPOSE_VERIFY) == rec["hash"]
    assert EmailCodeLedger._hash(code, rec["salt"], "alice@acme.com", PURPOSE_RECOVER) != rec["hash"]
    assert EmailCodeLedger._hash(code, rec["salt"], "bob@acme.com", PURPOSE_VERIFY) != rec["hash"]


def test_revoke_for_email_ends_both_purposes(tmp_path):
    led = EmailCodeLedger(tmp_path)
    v = led.issue("a@acme.com", PURPOSE_VERIFY, now=100.0)
    r = led.issue("a@acme.com", PURPOSE_RECOVER, now=100.0)
    other = led.issue("b@acme.com", PURPOSE_VERIFY, now=100.0)
    assert led.revoke_for_email("a@acme.com") == 2
    assert led.check("a@acme.com", PURPOSE_VERIFY, v, now=101.0) == CodeGone()
    assert led.check("a@acme.com", PURPOSE_RECOVER, r, now=101.0) == CodeGone()
    assert led.check("b@acme.com", PURPOSE_VERIFY, other, now=101.0) == CodeOk({})


def test_the_ledger_is_bounded(tmp_path):
    led = EmailCodeLedger(tmp_path, max_records=2)
    assert led.issue("a@x.com", PURPOSE_VERIFY, now=100.0) and led.issue("b@x.com", PURPOSE_VERIFY, now=100.0)
    assert led.issue("c@x.com", PURPOSE_VERIFY, now=101.0) is None
    assert led.issue("a@x.com", PURPOSE_VERIFY, now=101.0)              # a replacement is not a new record
    assert led.issue("c@x.com", PURPOSE_VERIFY, now=800.0)              # the expired ones were swept


def test_concurrent_checks_consume_exactly_once(tmp_path):
    led = EmailCodeLedger(tmp_path)
    code = led.issue("a@acme.com", PURPOSE_RECOVER)
    out, barrier = [], threading.Barrier(8)

    def go():
        barrier.wait()
        out.append(EmailCodeLedger(tmp_path).check("a@acme.com", PURPOSE_RECOVER, code, consume=True))

    ts = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sum(isinstance(r, CodeOk) for r in out) == 1


class _SlowReads(EmailCodeLedger):
    """Every read of a record takes a while: concurrent checks then overlap inside the read-check-write, which only
    the ledger's lock can keep apart (lost wrong-code counts, two winners)."""

    def _read(self, p):
        rec = super()._read(p)
        time.sleep(0.05)
        return rec


def test_concurrent_wrong_codes_all_count_even_when_they_overlap(tmp_path):
    code = _SlowReads(tmp_path).issue("a@acme.com", PURPOSE_VERIFY)
    wrong = f"{(int(code) + 3) % 1_000_000:06d}"
    out, barrier = [], threading.Barrier(4)

    def go():
        barrier.wait()
        out.append(_SlowReads(tmp_path).check("a@acme.com", PURPOSE_VERIFY, wrong))

    ts = [threading.Thread(target=go) for _ in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(r.remaining for r in out) == [1, 2, 3, 4]               # no count lost
    assert EmailCodeLedger(tmp_path).check("a@acme.com", PURPOSE_VERIFY, wrong) == CodeWrong(0)


def test_concurrent_right_codes_consume_once_even_when_they_overlap(tmp_path):
    code = _SlowReads(tmp_path).issue("a@acme.com", PURPOSE_RECOVER)
    out, barrier = [], threading.Barrier(4)

    def go():
        barrier.wait()
        out.append(_SlowReads(tmp_path).check("a@acme.com", PURPOSE_RECOVER, code, consume=True))

    ts = [threading.Thread(target=go) for _ in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sum(isinstance(r, CodeOk) for r in out) == 1


def test_normalize_code():
    assert normalize_code(" 123 456 ") == "123456" and normalize_code("000000") == "000000"
    for bad in ("12345", "1234567", "12a456", "１２３４５６", None):
        assert normalize_code(bad) == ""


# ================================================================================================================
# the provisioner
# ================================================================================================================
class _Mail(EmailSender):
    def __init__(self):
        self.sent = []

    def send(self, to, subject, body):
        self.sent.append((to, subject, body))
        return False                     # "not delivered", so the dev token / code are exposed to the test


def _prov(*, codes=True, ip_fails=50, code_limiter=True):
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    custs = CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    orgs = OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    wallet = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    mail = _Mail()
    clock = itertools.count(1)
    p = Provisioner(s, customers=custs, orgs=orgs, wallet=wallet,
                    email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=10_000.0),
                    rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=ip_fails, window_s=10_000.0,
                                                  base_lock_s=50.0),
                    email_codes=EmailCodeLedger(tempfile.mkdtemp()) if codes else None,
                    email_code_limiter=(LoginRateLimiter(tempfile.mkdtemp(), max_fails=5, window_s=3600.0,
                                                         base_lock_s=3600.0, max_lock_s=86400.0)
                                        if codes and code_limiter else None),
                    email_sender=mail, trial_credits=100, expose_dev_tokens=True,
                    now_fn=lambda: float(next(clock)))
    return p, custs, orgs, mail


def test_codes_off_by_default_change_nothing():
    p, custs, _orgs, mail = _prov(codes=False)
    r = p.request_signup("a@acme.com", ip="1.1.1.1", now=100.0)
    assert set(r) == {"status", "dev_token"} and mail.sent[-1][2] == f"Confirm: token {r['dev_token']}"
    with pytest.raises(ProvisionError, match="not enabled"):
        p.confirm_signup_code("a@acme.com", "123456", password="pw-123456", org_name="A", now=100.0)
    p.confirm_signup(r["dev_token"], password="pw-123456", org_name="A", now=100.0)
    rr = p.request_recover("a@acme.com", ip="1.1.1.1", now=100.0)
    assert set(rr) == {"status", "dev_token"} and mail.sent[-1][2] == f"Reset: token {rr['dev_token']}"
    with pytest.raises(ProvisionError, match="not enabled"):
        p.confirm_recover_code("a@acme.com", "123456", new_password="pw-2", now=100.0)


def test_the_signup_email_carries_the_code_beside_the_token():
    p, _c, _o, mail = _prov()
    r = p.request_signup("a@acme.com", ip="1.1.1.1", now=100.0)
    assert r["code"] is True and len(r["dev_code"]) == 6
    to, subject, body = mail.sent[-1]
    assert to == "a@acme.com" and subject == "Verify your VIGIL email"
    assert format_code(r["dev_code"]) in body and r["dev_token"] in body
    assert "within 10 minutes" in body and "valid for 1 hour" in body


def test_the_code_completes_the_same_signup_the_token_would_and_ends_the_token():
    p, custs, orgs, _mail = _prov()
    r = p.request_signup("A@Acme.com", ip="1.1.1.1", now=100.0)
    out = p.confirm_signup_code(" a@acme.com ", r["dev_code"], password="pw-123456", org_name="Acme", now=101.0)
    assert out["username"] == _signup_username(r["dev_token"]) and out["org_id"] == _signup_org_id(r["dev_token"])
    assert custs.by_email("a@acme.com").username == out["username"]
    assert orgs.membership_role(out["username"], out["org_id"]) == "org_admin"
    with pytest.raises(ProvisionDenied):                                  # the token died with the sign-up
        p.confirm_signup(r["dev_token"], password="pw-2", org_name="X", now=102.0)
    with pytest.raises(ProvisionDenied):                                  # and the code is used once
        p.confirm_signup_code("a@acme.com", r["dev_code"], password="pw-2", org_name="X", now=102.0)


def test_the_token_path_ends_the_code():
    p, _c, _o, _m = _prov()
    r = p.request_signup("a@acme.com", ip="1.1.1.1", now=100.0)
    p.confirm_signup(r["dev_token"], password="pw-123456", org_name="Acme", now=101.0)
    with pytest.raises(ProvisionDenied):
        p.confirm_signup_code("a@acme.com", r["dev_code"], password="pw-2", org_name="X", now=102.0)


def test_a_bad_workspace_name_does_not_burn_the_code():
    p, _c, _o, _m = _prov()
    r = p.request_signup("a@acme.com", ip="1.1.1.1", now=100.0)
    with pytest.raises(ValueError):
        p.confirm_signup_code("a@acme.com", r["dev_code"], password="pw-123456", org_name="x" * 1000, now=101.0)
    assert p.confirm_signup_code("a@acme.com", r["dev_code"], password="pw-123456", org_name="Acme",
                                 now=102.0)["username"]


def test_wrong_codes_are_limited_per_email_across_resent_codes():
    p, _c, _o, _m = _prov()
    r = p.request_signup("a@acme.com", ip="1.1.1.1", now=100.0)
    wrong = f"{(int(r['dev_code']) + 1) % 1_000_000:06d}"
    for k in range(5):                                                    # five addresses, so not the IP leg
        with pytest.raises(ProvisionDenied, match="invalid or expired code"):
            p.confirm_signup_code("a@acme.com", wrong, password="pw-123456", org_name="A", ip=f"9.9.9.{k}",
                                  now=101.0)
    # the code is destroyed — and a freshly sent code is refused too while this email+purpose is locked
    fresh = p.request_signup("a@acme.com", ip="1.1.1.2", now=102.0)["dev_code"]
    with pytest.raises(ProvisionRateLimited):
        p.confirm_signup_code("a@acme.com", fresh, password="pw-123456", org_name="A", ip="9.9.9.9", now=103.0)
    # the lock is per email+purpose: another address, and the same address's reset, are untouched
    other = p.request_signup("b@acme.com", ip="1.1.1.3", now=104.0)["dev_code"]
    assert p.confirm_signup_code("b@acme.com", other, password="pw-123456", org_name="B", ip="9.9.9.9",
                                 now=105.0)["username"]


def test_without_the_cross_resend_limiter_each_code_still_dies_at_its_fifth_wrong_code():
    p, _c, _o, _m = _prov(code_limiter=False)
    r = p.request_signup("a@acme.com", ip="1.1.1.1", now=100.0)
    wrong = f"{(int(r['dev_code']) + 1) % 1_000_000:06d}"
    for k in range(5):
        with pytest.raises(ProvisionDenied):
            p.confirm_signup_code("a@acme.com", wrong, password="pw-123456", org_name="A", ip=f"9.9.9.{k}",
                                  now=101.0)
    with pytest.raises(ProvisionDenied):
        p.confirm_signup_code("a@acme.com", r["dev_code"], password="pw-123456", org_name="A", ip="9.9.9.9",
                              now=102.0)


def test_wrong_codes_are_limited_per_ip():
    p, _c, _o, _m = _prov(ip_fails=3)
    for k in range(3):                                                    # three addresses, one IP
        with pytest.raises(ProvisionDenied):
            p.confirm_signup_code(f"x{k}@acme.com", "000000", password="pw", org_name="X", ip="7.7.7.7", now=100.0)
    r = p.request_signup("a@acme.com", ip="1.1.1.1", now=101.0)
    with pytest.raises(ProvisionRateLimited):                             # even a right code, from that IP
        p.confirm_signup_code("a@acme.com", r["dev_code"], password="pw-123456", org_name="A", ip="7.7.7.7",
                              now=102.0)


def test_reset_by_code_sets_the_password_once_and_asks_the_edge_to_sever_sessions():
    p, custs, _o, mail = _prov()
    t = p.request_signup("a@acme.com", ip="1.1.1.1", now=100.0)["dev_token"]
    p.confirm_signup(t, password="old-password-1", org_name="Acme", now=100.0)
    rr = p.request_recover("a@acme.com", ip="1.1.1.1", now=101.0)
    assert rr["code"] is True and format_code(rr["dev_code"]) in mail.sent[-1][2]
    assert mail.sent[-1][1] == "Reset your VIGIL password" and rr["dev_token"] in mail.sent[-1][2]
    out = p.confirm_recover_code("a@acme.com", rr["dev_code"], new_password="new-password-2", ip="2.2.2.2",
                                 now=102.0)
    assert out == {"username": custs.by_email("a@acme.com").username, "sessions_must_revoke": True}
    assert p.login("a@acme.com", "new-password-2", ip="3.3.3.3", now=103.0)["username"] == out["username"]
    with pytest.raises(ProvisionDenied):                                  # used once
        p.confirm_recover_code("a@acme.com", rr["dev_code"], new_password="x-password-3", now=104.0)
    with pytest.raises(ProvisionDenied):                                  # and the token died with it
        p.confirm_recover(rr["dev_token"], new_password="x-password-3", now=104.0)


def test_two_concurrent_resets_with_one_code_set_one_password():
    """The reset code is consumed by its check, before the password is set: two requests racing with the same code
    yield ONE reset. (Without that, both would pass the check before either finished, and both would reset.)"""
    p, custs, _o, _m = _prov()
    t = p.request_signup("a@acme.com", ip="1.1.1.1", now=100.0)["dev_token"]
    p.confirm_signup(t, password="old-password-1", org_name="Acme", now=100.0)
    code = p.request_recover("a@acme.com", ip="1.1.1.1", now=101.0)["dev_code"]
    both = threading.Barrier(2)
    real_commit = p._recover_commit

    def commit(email, new_password):
        try:
            both.wait(timeout=1.0)                     # both checks passed: both requests are about to reset
        except threading.BrokenBarrierError:
            pass
        return real_commit(email, new_password)

    p._recover_commit = commit
    out, start = [], threading.Barrier(2)

    def go(pw):
        start.wait()
        try:
            out.append(p.confirm_recover_code("a@acme.com", code, new_password=pw, ip="2.2.2.2", now=102.0))
        except ProvisionDenied:
            out.append(None)

    ts = [threading.Thread(target=go, args=(pw,)) for pw in ("new-password-A", "new-password-B")]
    [x.start() for x in ts]
    [x.join() for x in ts]
    assert sum(r is not None for r in out) == 1


def test_a_reset_by_token_ends_the_reset_code():
    p, _c, _o, _m = _prov()
    t = p.request_signup("a@acme.com", ip="1.1.1.1", now=100.0)["dev_token"]
    p.confirm_signup(t, password="old-password-1", org_name="Acme", now=100.0)
    rr = p.request_recover("a@acme.com", ip="1.1.1.1", now=101.0)
    p.confirm_recover(rr["dev_token"], new_password="new-password-2", now=102.0)
    with pytest.raises(ProvisionDenied):
        p.confirm_recover_code("a@acme.com", rr["dev_code"], new_password="x-password-3", now=103.0)


def test_a_signup_code_is_not_a_reset_code_and_unknown_addresses_look_the_same():
    p, _c, _o, _m = _prov()
    t = p.request_signup("a@acme.com", ip="1.1.1.1", now=100.0)["dev_token"]
    p.confirm_signup(t, password="old-password-1", org_name="Acme", now=100.0)
    v = p.request_signup("a@acme.com", ip="1.1.1.1", now=101.0)["dev_code"]   # a verify code for that address
    with pytest.raises(ProvisionDenied, match="invalid or expired code"):
        p.confirm_recover_code("a@acme.com", v, new_password="new-password-2", now=102.0)
    # an address without an account: the same answer at request, the same refusal at confirm
    known, unknown = p.request_recover("a@acme.com", now=103.0), p.request_recover("ghost@acme.com", now=103.0)
    assert {k: known[k] for k in ("status", "code")} == {k: unknown[k] for k in ("status", "code")}
    assert "dev_code" not in unknown
    with pytest.raises(ProvisionDenied, match="invalid or expired code"):
        p.confirm_recover_code("ghost@acme.com", "123456", new_password="new-password-2", now=104.0)


def test_build_provisioner_wires_codes_only_with_the_flag(tmp_path, monkeypatch):
    from sigil import config
    from sigil.ui.provision import build_provisioner
    for attr in ("EMAIL_TOKENS_DIR", "EMAIL_CODES_DIR", "EMAIL_CODE_RATELIMIT_DIR", "LOGIN_RATELIMIT_DIR",
                 "SIGNUP_CAP_DIR", "MEMBER_RATELIMIT_DIR", "CHECKOUT_RATELIMIT_DIR", "PENDING_PLAN_CHECKOUT_DIR"):
        monkeypatch.setattr(config, attr, tmp_path / attr.lower())
    from sigil.governor.identity import ensure_owner_keypair
    ensure_owner_keypair()
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    monkeypatch.delenv("VIGIL_CUSTOMER_EMAIL_CODE", raising=False)
    p = build_provisioner(store)
    assert p.email_codes is None and p.email_code_limiter is None
    monkeypatch.setenv("VIGIL_CUSTOMER_EMAIL_CODE", "1")
    p = build_provisioner(store)
    assert isinstance(p.email_codes, EmailCodeLedger) and p.email_codes.dir == tmp_path / "email_codes_dir"
    assert p.email_codes.ttl_s == 600.0 and p.email_codes.max_attempts == 5
    lim = p.email_code_limiter
    assert (lim.max_fails, lim.window_s, lim.base_lock_s, lim.max_lock_s) == (5, 3600.0, 3600.0, 86400.0)


def test_the_flag_is_off_unless_affirmative(monkeypatch):
    from sigil import config
    monkeypatch.delenv("VIGIL_CUSTOMER_EMAIL_CODE", raising=False)
    assert config.customer_email_code_enabled() is False
    for v in ("0", "", "off"):
        monkeypatch.setenv("VIGIL_CUSTOMER_EMAIL_CODE", v)
        assert config.customer_email_code_enabled() is False
    monkeypatch.setenv("VIGIL_CUSTOMER_EMAIL_CODE", "1")
    assert config.customer_email_code_enabled() is True


# ================================================================================================================
# over the real edge -> cockpit hop
# ================================================================================================================
def test_signup_and_reset_by_code_over_the_edge(tmp_path, monkeypatch):
    from sigil import config
    from test_custui import _get, _opener, _post, _stack
    monkeypatch.setenv("VIGIL_CUSTOMER_EMAIL_CODE", "1")
    for attr in ("EMAIL_CODES_DIR", "EMAIL_CODE_RATELIMIT_DIR"):
        monkeypatch.setattr(config, attr, tmp_path / attr.lower())
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        c, r = _post(op, ep, "/api/customer/signup/request", {"email": "c@acme.com"})
        assert c == 200 and r["code"] is True and len(r["dev_code"]) == 6
        c, out = _post(op, ep, "/api/customer/signup/confirm",
                       {"email": "c@acme.com", "code": format_code(r["dev_code"]), "password": "customer-pw-1",
                        "org_name": "Cee"})
        assert c == 200 and out["username"], (c, out)
        who = _get(op, ep, "/api/customer/whoami")[1]
        assert who["authenticated"] is True and who["username"] == out["username"]   # signed in by the code
        # reset by code from another device: the first session is severed
        other = _opener()
        rr = _post(other, ep, "/api/customer/recover/request", {"email": "c@acme.com"})[1]
        c, res = _post(other, ep, "/api/customer/recover/confirm",
                       {"email": "c@acme.com", "code": rr["dev_code"], "new_password": "customer-pw-2"})
        assert c == 200 and res["username"] == out["username"], (c, res)
        assert _get(op, ep, "/api/customer/whoami")[1]["authenticated"] is False
        c, li = _post(_opener(), ep, "/api/customer/login", {"email": "c@acme.com", "password": "customer-pw-2"})
        assert c == 200 and li["username"] == out["username"]
        # a wrong code is one refusal, never a session
        rr = _post(other, ep, "/api/customer/recover/request", {"email": "c@acme.com"})[1]
        bad = f"{(int(rr['dev_code']) + 1) % 1_000_000:06d}"
        c, res = _post(other, ep, "/api/customer/recover/confirm",
                       {"email": "c@acme.com", "code": bad, "new_password": "customer-pw-3"})
        assert c == 403 and "invalid or expired code" in res["error"]
    finally:
        sov.shutdown(); edge.shutdown()


# ================================================================================================================
# the app
# ================================================================================================================
def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _fn(src: str, name: str) -> str:
    i = src.index(f"function {name}(")
    i = src.rindex("\n", 0, i) + 1
    return src[i:src.index("\n  }\n", i) + 4]


def test_the_screens_ask_for_the_code_and_offer_a_reset():
    js = _js()
    assert '"Enter the 6-digit code from your email."' in _fn(js, "proofSwitch")
    assert '"#/recover": function () { return authed() ? viewDashboard() : viewRecover(); }' in js
    assert 'nav("#/recover")' in _fn(js, "viewLogin")
    assert 'VUI.postJSON(API + "/recover/confirm", proof)' in _fn(js, "doRecoverConfirm")
    assert 'VUI.postJSON(API + "/signup/confirm", proof)' in _fn(js, "doSignupConfirm")


_HARNESS = r"""
const vm = require("vm");
const [PROOF, CFG] = process.argv.slice(-2);
const cfg = JSON.parse(CFG);
const errors = [];
const ctx = { VUI: { $: (sel) => (sel === "#su-proof" ? { dataset: { mode: cfg.mode } } : null) },
  val: (id) => (cfg.values[id] || "").trim(), err: (m) => errors.push(m) };
vm.createContext(ctx);
vm.runInContext(PROOF + "\nthis.proofBody = proofBody;", ctx);
console.log(JSON.stringify({ body: ctx.proofBody("su", "su-email"), errors }));
"""


def _proof(mode, values):
    r = subprocess.run(["node", "-e", _HARNESS, _fn(_js(), "proofBody"), json.dumps({"mode": mode,
                                                                                     "values": values})],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_the_code_goes_with_the_address_it_was_sent_to():
    out = _proof("code", {"su-email": "a@acme.com", "su-code": "123 456", "su-token": "tok"})
    assert out == {"body": {"email": "a@acme.com", "code": "123456"}, "errors": []}
    assert _proof("token", {"su-email": "a@acme.com", "su-token": "tok"})["body"] == {"token": "tok"}
    assert _proof("code", {"su-email": "a@acme.com", "su-code": "12345"}) == \
        {"body": None, "errors": ["Enter the 6-digit code from your email."]}
    assert _proof("code", {"su-code": "123456"})["body"] is None


_ = os
