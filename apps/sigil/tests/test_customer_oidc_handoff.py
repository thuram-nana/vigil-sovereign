"""Google sign-in that completes inside an INSTALLED customer app — the app hand-off (ui/oidc_handoff.py + custui).

An app on an iPhone Home Screen runs standalone and iOS finishes Google sign-in in a separate browser with its own
cookies, so the sid-cookie binding of the normal flow cannot hold there. The hand-off binds the login to the app's
challenge = base64url(sha256(verifier)) instead; the callback stores the verified sign-in with a 6-digit pairing code
shown only where the Google sign-in happened; the app redeems verifier + code for its session.

Pinned here:
  * the store: single use, ~2 minute TTL, 5 wrong codes then gone, first completion wins, bounded, raw challenge /
    verifier / code never on disk, exactly one winner under concurrency, PKCE S256 shape (RFC 7636 vector);
  * the edge, over the real edge -> cockpit hop with a fake Google: the hand-off login sets no cookie and binds the
    challenge; the callback sets no session cookie, shows the code page (strict CSP, no-store); the redeem mints the
    session in the redeeming client's jar from the provisioner's answer (a body username/org is ignored); everything
    is 404 unless Google sign-in AND the hand-off are on; the redeem is Origin-gated and limited per IP;
  * THE ATTACK: an attacker starts a hand-off on their own device and gets a victim to finish Google sign-in — the
    attacker holds the verifier but never sees the code, so a wrong-code brute force is cut off after 5 guesses and
    the record is destroyed (the right code no longer works either); the attacker never gets a session;
  * THE RELAY: the victim is talked into typing the code into a look-alike "VIGIL app" whose server holds the
    verifier. Every step of a hand-off is bound to ONE network (client_net: IPv4 /24, IPv6 /56): a callback on
    another network than the login start is refused before Google's answer is used (no code exchanged, no account),
    and a redeem from another network than the callback removes the record unchecked — the relayed code mints
    nothing. Google is asked for its account chooser (prompt=select_account) and the code page names the Google
    account and says to close the page unless the person just started this in the VIGIL app on this phone;
  * one Google account (3) or one network (16) cannot fill the store of waiting sign-ins for everybody;
  * the normal (non-hand-off) flow keeps its sid binding unchanged with the hand-off on.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import secrets
import shutil
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

import pytest
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _edge_raw, _get, _MiniIdP, _oidc_login, _opener, _stack_oidc

from sigil.ui.custui import CUSTOMER_COOKIE, build_customer_server
from sigil.ui.oidc_handoff import (Elsewhere, Gone, HandoffBusy, HandoffExists, HandoffStore, HandoffTooMany,
                                   Redeemed, WrongCode, challenge_of, client_net, format_code, normalize_code)

APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"


def _verifier() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


_NET = "198.51.100.0/24"                       # the network every store test finishes and redeems on


# ================================================================================================================
# the store
# ================================================================================================================
def test_challenge_is_pkce_s256_rfc7636_vector():
    # RFC 7636 Appendix B
    assert challenge_of("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_complete_then_redeem_once(tmp_path):
    st = HandoffStore(tmp_path)
    v = _verifier()
    code = st.complete(challenge_of(v), "cust_alice", "org_a", net=_NET, now=100.0)
    assert len(code) == 6 and code.isdigit()
    assert st.redeem(v, format_code(code), net=_NET, now=101.0) == Redeemed("cust_alice", "org_a")   # "123 456" accepted
    assert st.redeem(v, code, net=_NET, now=101.0) == Gone()                                           # single use


def test_raw_values_are_never_on_disk(tmp_path):
    st = HandoffStore(tmp_path)
    v = _verifier()
    ch = challenge_of(v)
    code = st.complete(ch, "cust_alice", "org_a", net=_NET, now=100.0)
    files = [p for p in tmp_path.iterdir() if p.name != ".handoff.lock"]
    assert len(files) == 1 and len(files[0].name) == 64 and all(c in "0123456789abcdef" for c in files[0].name)
    assert oct(files[0].stat().st_mode & 0o777) == "0o600"
    blob = files[0].read_text()
    for raw in (v, ch, code, format_code(code)):
        assert raw not in blob and raw not in files[0].name
    # and the stored MAC does not let a reader of the directory test codes without the challenge
    rec = json.loads(blob)
    assert set(rec) == {"exp", "username", "org_id", "net", "salt", "mac", "attempts"}


def test_the_stored_code_check_is_keyed_by_the_challenge(tmp_path):
    # the MAC on disk can only be checked by someone who has the challenge (a reader of the directory has only its
    # sha256): the same salt and code under any other key give another MAC
    st = HandoffStore(tmp_path)
    v = _verifier()
    code = st.complete(challenge_of(v), "cust_alice", "org_a", net=_NET, now=100.0)
    rec = json.loads(next(p for p in tmp_path.iterdir() if p.name != ".handoff.lock").read_text())
    assert HandoffStore._mac(challenge_of(v), rec["salt"], code) == rec["mac"]
    assert HandoffStore._mac(challenge_of(_verifier()), rec["salt"], code) != rec["mac"]
    assert HandoffStore._mac(challenge_of(v), "0" * 32, code) != rec["mac"]


def test_five_wrong_codes_destroy_the_record(tmp_path):
    st = HandoffStore(tmp_path)
    v = _verifier()
    code = st.complete(challenge_of(v), "cust_alice", "org_a", net=_NET, now=100.0)
    wrong = f"{(int(code) + 1) % 1_000_000:06d}"
    assert [st.redeem(v, wrong, net=_NET, now=101.0) for _ in range(4)] == [WrongCode(4), WrongCode(3), WrongCode(2),
                                                                   WrongCode(1)]
    assert st.redeem(v, wrong, net=_NET, now=101.0) == WrongCode(0)                 # the 5th wrong code removes it
    assert st.redeem(v, code, net=_NET, now=101.0) == Gone()                        # the right code no longer works
    assert [p for p in tmp_path.iterdir() if p.name != ".handoff.lock"] == []


@pytest.mark.parametrize("typed", ["", "12345", "1234567", "abcdef", "12 34 5"])
def test_a_malformed_code_counts_as_wrong(tmp_path, typed):
    st = HandoffStore(tmp_path)
    v = _verifier()
    st.complete(challenge_of(v), "cust_alice", None, net=_NET, now=100.0)
    assert st.redeem(v, typed, net=_NET, now=101.0) == WrongCode(4)


def test_expired_unknown_and_wrong_verifier_are_gone(tmp_path):
    st = HandoffStore(tmp_path, ttl_s=120.0)
    v = _verifier()
    code = st.complete(challenge_of(v), "cust_alice", "org_a", net=_NET, now=100.0)
    assert st.redeem(_verifier(), code, net=_NET, now=101.0) == Gone()              # another verifier: no record
    assert st.redeem("not-a-verifier", code, net=_NET, now=101.0) == Gone()
    assert st.redeem(v + "A", code, net=_NET, now=101.0) == Gone()
    assert st.redeem(v, code, net=_NET, now=220.0) == Gone()                       # 120 s later: expired
    assert [p for p in tmp_path.iterdir() if p.name != ".handoff.lock"] == []


def test_first_completion_wins(tmp_path):
    st = HandoffStore(tmp_path)
    v = _verifier()
    code = st.complete(challenge_of(v), "cust_alice", "org_a", net=_NET, now=100.0)
    with pytest.raises(HandoffExists):
        st.complete(challenge_of(v), "cust_mallory", "org_m", net=_NET, now=101.0)
    assert st.redeem(v, code, net=_NET, now=102.0) == Redeemed("cust_alice", "org_a")


def test_the_store_is_bounded(tmp_path):
    st = HandoffStore(tmp_path, max_records=2, ttl_s=120.0)
    st.complete(challenge_of(_verifier()), "a", None, net=_NET, now=100.0)
    st.complete(challenge_of(_verifier()), "b", None, net=_NET, now=100.0)
    with pytest.raises(HandoffBusy):
        st.complete(challenge_of(_verifier()), "c", None, net=_NET, now=101.0)
    st.complete(challenge_of(_verifier()), "c", None, net=_NET, now=300.0)           # the expired two were swept


def test_complete_refuses_a_malformed_challenge_or_no_username(tmp_path):
    st = HandoffStore(tmp_path)
    for bad in ("", "x" * 42, "x" * 44, "../" + "x" * 40, "x" * 42 + "="):
        with pytest.raises(ValueError):
            st.complete(bad, "cust_alice", None, net=_NET)
    with pytest.raises(ValueError):
        st.complete(challenge_of(_verifier()), "", None, net=_NET)


def test_concurrent_redeems_yield_exactly_one_session(tmp_path):
    st = HandoffStore(tmp_path)
    v = _verifier()
    code = st.complete(challenge_of(v), "cust_alice", "org_a", net=_NET)
    results, barrier = [], threading.Barrier(16)

    def go():
        barrier.wait()
        results.append(HandoffStore(tmp_path).redeem(v, code, net=_NET))

    ts = [threading.Thread(target=go) for _ in range(16)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sum(isinstance(r, Redeemed) for r in results) == 1 and results.count(Gone()) == 15


def test_concurrent_wrong_codes_all_count(tmp_path):
    st = HandoffStore(tmp_path)
    v = _verifier()
    code = st.complete(challenge_of(v), "cust_alice", "org_a", net=_NET)
    wrong = f"{(int(code) + 7) % 1_000_000:06d}"
    barrier = threading.Barrier(5)
    out = []

    def go():
        barrier.wait()
        out.append(HandoffStore(tmp_path).redeem(v, wrong, net=_NET))

    ts = [threading.Thread(target=go) for _ in range(5)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(r.remaining for r in out) == [0, 1, 2, 3, 4]           # none lost: the 5th removed it
    assert st.redeem(v, code, net=_NET) == Gone()


def test_a_redeem_from_another_network_removes_the_record_without_checking_the_code(tmp_path):
    st = HandoffStore(tmp_path)
    v = _verifier()
    code = st.complete(challenge_of(v), "cust_alice", "org_a", net=_NET, now=100.0)
    assert st.redeem(v, code, net="203.0.113.0/24", now=101.0) == Elsewhere()   # the RIGHT code, elsewhere
    assert st.redeem(v, code, net=_NET, now=101.0) == Gone()                     # removed: nothing to redeem
    for other in ("", None, "203.0.113.0/24"):
        v = _verifier()
        code = st.complete(challenge_of(v), "cust_alice", "org_a", net=_NET, now=100.0)
        assert st.redeem(v, code, net=other, now=101.0) == Elsewhere()          # no network is not a network
        assert st.redeem(v, code, net=_NET, now=101.0) == Gone()


def test_a_record_without_a_network_redeems_nowhere(tmp_path):
    # a record written without one (an edge from before the network rule) never redeems
    st = HandoffStore(tmp_path)
    v = _verifier()
    code = st.complete(challenge_of(v), "cust_alice", "org_a", net=_NET, now=100.0)
    rec_path = next(p for p in tmp_path.iterdir() if p.name != ".handoff.lock")
    rec = json.loads(rec_path.read_text())
    del rec["net"]
    rec_path.write_text(json.dumps(rec))
    assert st.redeem(v, code, net=_NET, now=101.0) == Elsewhere()


def test_complete_needs_the_network(tmp_path):
    with pytest.raises(ValueError):
        HandoffStore(tmp_path).complete(challenge_of(_verifier()), "cust_alice", None, net="")


def test_one_account_or_one_network_cannot_fill_the_store(tmp_path):
    st = HandoffStore(tmp_path, max_per_user=3, max_per_net=4, ttl_s=120.0)
    for _ in range(3):
        st.complete(challenge_of(_verifier()), "cust_busy", None, net=_NET, now=100.0)
    with pytest.raises(HandoffTooMany):
        st.complete(challenge_of(_verifier()), "cust_busy", None, net="203.0.113.0/24", now=100.0)
    st.complete(challenge_of(_verifier()), "cust_other", None, net=_NET, now=100.0)       # 4 from _NET now
    with pytest.raises(HandoffTooMany):
        st.complete(challenge_of(_verifier()), "cust_third", None, net=_NET, now=100.0)
    st.complete(challenge_of(_verifier()), "cust_third", None, net="203.0.113.0/24", now=100.0)
    st.complete(challenge_of(_verifier()), "cust_busy", None, net=_NET, now=300.0)        # the old ones expired
    assert issubclass(HandoffTooMany, HandoffBusy)


def test_the_store_defaults_bound_one_account_and_one_network():
    st = HandoffStore("/nonexistent")
    assert (st.max_per_user, st.max_per_net, st.max_records, st.ttl_s) == (3, 16, 4096, 120.0)


@pytest.mark.parametrize("ip,net", [
    ("203.0.113.77", "203.0.113.0/24"), (" 203.0.113.1 ", "203.0.113.0/24"),
    ("::ffff:203.0.113.9", "203.0.113.0/24"),                                  # IPv4-mapped counts as IPv4
    ("2001:db8:1200:a1::5", "2001:db8:1200::/56"), ("2001:db8:1200:ff:ffff::1", "2001:db8:1200::/56"),
    ("2001:db8:1200:100::1", "2001:db8:1200:100::/56"),                       # the next /56 is another network
    ("fe80::1%eth0", "fe80::/56"), ("127.0.0.1", "127.0.0.0/24"),
    ("", ""), (None, ""), ("unknown", ""), ("203.0.113.0/24", ""), ("1.2.3.4, 5.6.7.8", ""),
])
def test_client_net(ip, net):
    assert client_net(ip) == net


def test_normalize_code():
    assert normalize_code(" 123 456 ") == "123456" and normalize_code("123456") == "123456"
    for bad in ("12345", "1234567", "12a456", None, ""):
        assert normalize_code(bad) == ""


# ================================================================================================================
# the edge, over the real hop, with a fake Google
# ================================================================================================================
def _on(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_OIDC_HANDOFF", "1")


def _get_from(ep, path, *, ip=None, cookie=None):
    """A no-redirect GET to the edge, as the proxy forwards it from client `ip` (X-Real-IP) — or, with no `ip`, as
    a loopback client (the edge's peer address)."""
    if ip is None:
        return _edge_raw(ep, path, cookie=cookie)
    conn = http.client.HTTPConnection("127.0.0.1", ep, timeout=5)
    h = {"Host": f"127.0.0.1:{ep}", "X-Real-IP": ip}
    if cookie:
        h["Cookie"] = cookie
    conn.request("GET", path, headers=h)
    r = conn.getresponse()
    out = (r.status, dict(r.getheaders()), r.read())
    conn.close()
    return out


def _handoff_login(ep, challenge, *, ip=None):
    return _get_from(ep, f"/api/customer/oidc/login?handoff={quote(challenge)}", ip=ip)


def _callback(ep, state, *, cookie=None, ip=None):
    return _get_from(ep, f"/api/customer/oidc/callback?code=auth-1&state={state}", ip=ip, cookie=cookie)


def _redeem(ep, body, *, origin=None, ip=None):
    conn = http.client.HTTPConnection("127.0.0.1", ep, timeout=5)
    h = {"Host": f"127.0.0.1:{ep}", "Content-Type": "application/json",
         "Origin": origin if origin is not None else f"http://127.0.0.1:{ep}"}
    if ip:
        h["X-Real-IP"] = ip
    conn.request("POST", "/api/customer/oidc/handoff", body=json.dumps(body).encode(), headers=h)
    r = conn.getresponse()
    raw = r.read()
    out = (r.status, dict(r.getheaders()), json.loads(raw) if raw else None)
    conn.close()
    return out


def _code_from(page: bytes) -> str:
    text = page.decode()
    i = text.index('class="cust-handoff-code"')
    shown = text[text.index(">", i) + 1:text.index("</p>", i)]
    return shown.replace(" ", "")


def _whoami(ep, set_cookie):
    session = http.cookies.SimpleCookie(set_cookie)[CUSTOMER_COOKIE].value
    return _get(_opener(), ep, "/api/customer/whoami", cookie=f"{CUSTOMER_COOKIE}={session}")[1]


import http.cookies  # noqa: E402  (used by _whoami)


def _app_finishes_google(ep, idp, *, sub="g-sub-1", email="founder@gmail.com", ip=None):
    """An installed app starts a hand-off; the person finishes Google sign-in in another browser (no cookies) on the
    same phone, so from the same client address `ip`."""
    v = _verifier()
    st, hdr, _ = _handoff_login(ep, challenge_of(v), ip=ip)
    assert st == 302, (st, hdr)
    q = parse_qs(urlparse(hdr["Location"]).query)
    idp.next_id_token = idp.mint(nonce=q["nonce"][0], sub=sub, email=email)
    st, hdr, page = _callback(ep, q["state"][0], ip=ip)
    return v, st, hdr, page


class _CountingIdP(_MiniIdP):
    """The fake Google, counting the authorization codes exchanged at its token endpoint."""

    def __init__(self):
        super().__init__()
        self.exchanges = 0

    def http_post(self, url, form):
        self.exchanges += 1
        return super().http_post(url, form)


def test_the_handoff_is_404_unless_google_and_the_handoff_are_on(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack_oidc(tmp_path, monkeypatch, _MiniIdP())
    try:
        monkeypatch.delenv("VIGIL_CUSTOMER_OIDC_HANDOFF", raising=False)
        assert _handoff_login(ep, challenge_of(_verifier()))[0] == 404
        assert _redeem(ep, {"verifier": _verifier(), "code": "123456"})[0] == 404
        assert _edge_raw(ep, "/api/customer/oidc/login")[0] == 302              # the normal flow is untouched
        _on(monkeypatch)
        monkeypatch.delenv("VIGIL_CUSTOMER_OIDC_ENABLED", raising=False)        # the hand-off alone is nothing
        assert _handoff_login(ep, challenge_of(_verifier()))[0] == 404
        assert _redeem(ep, {"verifier": _verifier(), "code": "123456"})[0] == 404
    finally:
        sov.shutdown(); edge.shutdown()


def test_the_handoff_login_binds_the_challenge_and_sets_no_cookie(tmp_path, monkeypatch):
    _on(monkeypatch)
    sov, edge, ep, _ = _stack_oidc(tmp_path, monkeypatch, _MiniIdP())
    try:
        st, hdr, _ = _handoff_login(ep, challenge_of(_verifier()))
        assert st == 302 and hdr["Location"].startswith("https://accounts.google.com/o/oauth2/v2/auth?")
        assert "Set-Cookie" not in hdr                                       # nothing to bind in this jar
        assert hdr.get("Cache-Control") == "no-store"
        for bad in ("", "x" * 42, "x" * 44, "%2E%2E%2F" + "x" * 40):
            assert _handoff_login(ep, bad)[0] == 400, bad
        assert _edge_raw(ep, "/api/customer/oidc/login?handoff=" + "a" * 43 + "&handoff=" + "b" * 43)[0] == 400
    finally:
        sov.shutdown(); edge.shutdown()


def test_full_handoff_round_trip_mints_the_session_in_the_redeeming_jar(tmp_path, monkeypatch):
    _on(monkeypatch)
    idp = _MiniIdP()
    sov, edge, ep, sp = _stack_oidc(tmp_path, monkeypatch, idp)
    try:
        v, st, hdr, page = _app_finishes_google(ep, idp)
        # the browser where Google sign-in finished gets the code page — and NO session cookie
        assert st == 200 and hdr["Content-Type"].startswith("text/html")
        assert CUSTOMER_COOKIE not in (hdr.get("Set-Cookie") or "")
        assert hdr.get("Cache-Control") == "no-store" and "default-src 'self'" in hdr["Content-Security-Policy"]
        text = page.decode()
        for line in ("Signed in.", "Go back to the VIGIL app and enter this code:",
                     "Only enter it in the VIGIL app on this phone — VIGIL will never ask you for it anywhere else."):
            assert line in text, line
        assert "<script>" not in text and "style=" not in text               # strict CSP: nothing inline
        code = _code_from(page)
        assert len(code) == 6 and code.isdigit()
        # the installed app redeems verifier + code: the session cookie lands in ITS jar, from the provisioner's
        # answer — a body username/org is ignored
        st, hdr, body = _redeem(ep, {"verifier": v, "code": code[:3] + " " + code[3:],
                                     "username": "cust_attacker", "org_id": "org_attacker"})
        assert st == 200 and body["ok"] is True, (st, body)
        who = _whoami(ep, hdr["Set-Cookie"])
        assert who["authenticated"] is True and who["username"] == body["username"]
        assert who["username"].startswith("cust_") and who["username"] != "cust_attacker"
        assert who["org_id"] == body["active_org"] and who["org_id"] != "org_attacker"
        # used once
        st, _, body = _redeem(ep, {"verifier": v, "code": code})
        assert st == 401 and body["retry"] is False
    finally:
        sov.shutdown(); edge.shutdown()


def test_attacker_with_the_verifier_cannot_redeem_a_victims_sign_in_without_the_code(tmp_path, monkeypatch):
    """The attack the pairing code exists for: the ATTACKER starts a hand-off on their own device (they hold the
    verifier), sends the Google link to a VICTIM, and the victim finishes Google sign-in. The callback runs in the
    victim's browser, so only the victim sees the code. Here the attacker is on the victim's own network (the same
    Wi-Fi: from anywhere else the callback is refused, see the relay tests below), so only the code stands in the
    way: the wrong-code brute force is cut off after 5 guesses — the record is destroyed, so even the right code no
    longer works — and no session is ever minted."""
    _on(monkeypatch)
    idp = _MiniIdP()
    sov, edge, ep, _ = _stack_oidc(tmp_path, monkeypatch, idp)
    try:
        attacker_v = _verifier()
        st, hdr, _ = _handoff_login(ep, challenge_of(attacker_v), ip="192.0.2.7")   # the attacker's device
        q = parse_qs(urlparse(hdr["Location"]).query)
        # the victim opens the attacker's Google link and signs in as THEMSELVES; their browser hits the callback
        idp.next_id_token = idp.mint(nonce=q["nonce"][0], sub="victim-sub", email="victim@gmail.com")
        st, vhdr, page = _callback(ep, q["state"][0], ip="192.0.2.50")
        assert st == 200 and CUSTOMER_COOKIE not in (vhdr.get("Set-Cookie") or "")
        victims_code = _code_from(page)                                    # shown ONLY in the victim's browser
        # the attacker has the verifier but not the code: guesses (from 5 addresses on that network, so the per-IP
        # limit is not what stops them) — every one refused, and no session cookie
        guesses = [f"{(int(victims_code) + k) % 1_000_000:06d}" for k in range(1, 6)]
        answers = [_redeem(ep, {"verifier": attacker_v, "code": g}, ip=f"192.0.2.{k}")
                   for k, g in enumerate(guesses)]
        assert [a[0] for a in answers] == [401] * 5
        assert [a[2]["retry"] for a in answers] == [True, True, True, True, False]
        assert not any(CUSTOMER_COOKIE in (a[1].get("Set-Cookie") or "") for a in answers)
        # the record is destroyed: even the victim's real code (were it phished later) redeems nothing
        st, hdr, body = _redeem(ep, {"verifier": attacker_v, "code": victims_code}, ip="192.0.2.99")
        assert st == 401 and body["retry"] is False and CUSTOMER_COOKIE not in (hdr.get("Set-Cookie") or "")
        # and a fresh verifier with the right code redeems nothing either (the record is keyed by the challenge)
        assert _redeem(ep, {"verifier": _verifier(), "code": victims_code}, ip="192.0.2.98")[0] == 401
    finally:
        sov.shutdown(); edge.shutdown()


def test_a_relayed_code_redeemed_from_another_network_mints_nothing(tmp_path, monkeypatch):
    """THE RELAY (the review's account-takeover path): the attacker's server holds a verifier and gets the victim to
    open the GENUINE login link for its challenge (so the login starts on the victim's network). The victim signs
    in to Google, the genuine page shows the code, and the victim types it into a look-alike "VIGIL app"; the
    attacker's server redeems {verifier, code} from its own address. The redeem is refused, the record is removed
    unchecked, no session cookie is set — and the victim's code is dead even on the victim's own network."""
    _on(monkeypatch)
    idp = _MiniIdP()
    sov, edge, ep, _ = _stack_oidc(tmp_path, monkeypatch, idp)
    try:
        attacker_v = _verifier()
        st, hdr, _ = _handoff_login(ep, challenge_of(attacker_v), ip="198.51.100.23")        # the victim's browser
        q = parse_qs(urlparse(hdr["Location"]).query)
        idp.next_id_token = idp.mint(nonce=q["nonce"][0], sub="victim-sub", email="victim@gmail.com")
        st, _vh, page = _callback(ep, q["state"][0], ip="198.51.100.23")
        assert st == 200
        code = _code_from(page)
        st, hdr, body = _redeem(ep, {"verifier": attacker_v, "code": code}, ip="203.0.113.250")   # the attacker
        assert st == 401 and body["retry"] is False and "another network" in body["error"]
        assert CUSTOMER_COOKIE not in (hdr.get("Set-Cookie") or "")
        st, hdr, body = _redeem(ep, {"verifier": attacker_v, "code": code}, ip="198.51.100.40")
        assert st == 401 and body["retry"] is False and CUSTOMER_COOKIE not in (hdr.get("Set-Cookie") or "")
    finally:
        sov.shutdown(); edge.shutdown()


def test_a_sign_in_finished_on_another_network_than_it_started_is_refused_before_google_is_asked(tmp_path,
                                                                                                  monkeypatch):
    """The other relay: the attacker's server starts the hand-off itself and sends the victim straight to the Google
    URL it got back. The callback arrives from the victim's network, not the one the login started on: it is
    refused BEFORE the authorization code is exchanged — no code page, no session, no account created."""
    _on(monkeypatch)
    idp = _CountingIdP()
    sov, edge, ep, _ = _stack_oidc(tmp_path, monkeypatch, idp)
    try:
        attacker_v = _verifier()
        st, hdr, _ = _handoff_login(ep, challenge_of(attacker_v), ip="203.0.113.250")        # the attacker's server
        q = parse_qs(urlparse(hdr["Location"]).query)
        idp.next_id_token = idp.mint(nonce=q["nonce"][0], sub="victim-sub", email="victim@gmail.com")
        st, vhdr, page = _callback(ep, q["state"][0], ip="198.51.100.23")                   # the victim's browser
        assert st == 403 and b"cust-handoff-code" not in page and b"started on another network" in page
        assert CUSTOMER_COOKIE not in (vhdr.get("Set-Cookie") or "")
        assert idp.exchanges == 0                                           # Google's answer was never used
        assert [p for p in (tmp_path / "customer-oidc-handoff").glob("*") if p.name != ".handoff.lock"] == []
        assert _callback(ep, q["state"][0], ip="203.0.113.250")[0] == 401  # and the state is spent
        # the same login from one network (an IPv6 phone moving between addresses of its own /56) completes
        v = _verifier()
        st, hdr, _ = _handoff_login(ep, challenge_of(v), ip="2001:db8:1200:a1::5")
        q = parse_qs(urlparse(hdr["Location"]).query)
        idp.next_id_token = idp.mint(nonce=q["nonce"][0])
        st, _h, page = _callback(ep, q["state"][0], ip="2001:db8:1200:b7::9")
        assert st == 200 and idp.exchanges == 1
        assert _redeem(ep, {"verifier": v, "code": _code_from(page)}, ip="2001:db8:1200:c3::1")[0] == 200
    finally:
        sov.shutdown(); edge.shutdown()


def test_a_handoff_state_without_a_network_completes_nothing(tmp_path, monkeypatch):
    # a login state written without the starting network (an edge from before the network rule, still running
    # while the new one takes over) is refused at the callback, before Google's answer is used
    from sigil.ui.oidc import OidcStateStore
    _on(monkeypatch)
    idp = _CountingIdP()
    sov, edge, ep, _ = _stack_oidc(tmp_path, monkeypatch, idp)
    try:
        v = _verifier()
        OidcStateStore(tmp_path / "customer-oidc-state").issue("old-edge-state", "old-nonce", verifier="pkce-v" * 8,
                                                               handoff=challenge_of(v))
        idp.next_id_token = idp.mint(nonce="old-nonce")
        st, hdr, page = _callback(ep, "old-edge-state")
        assert st == 403 and b"cust-handoff-code" not in page and idp.exchanges == 0
        assert CUSTOMER_COOKIE not in (hdr.get("Set-Cookie") or "")
    finally:
        sov.shutdown(); edge.shutdown()


def test_a_handoff_from_a_client_whose_address_cannot_be_read_does_not_start(tmp_path, monkeypatch):
    _on(monkeypatch)
    sov, edge, ep, _ = _stack_oidc(tmp_path, monkeypatch, _MiniIdP())
    try:
        for bad in ("unknown", "203.0.113.0/24", "not an address"):
            st, hdr, body = _handoff_login(ep, challenge_of(_verifier()), ip=bad)
            assert st == 400 and b"client address" in body and "Location" not in hdr
        assert list((tmp_path / "customer-oidc-state").glob("*")) == []          # no login state was issued
    finally:
        sov.shutdown(); edge.shutdown()


def test_the_authorize_url_takes_only_a_known_prompt():
    from sigil.ui import oidc as _oidc
    cfg = _oidc.OidcConfig.from_settings({"issuer": "https://accounts.google.com", "client_id": "c",
                                          "redirect_uri": "https://app.example/cb",
                                          "authorize_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
                                          "token_endpoint": "https://oauth2.googleapis.com/token",
                                          "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
                                          "signing_algs": ["RS256"]})
    url = _oidc.build_authorize_url(cfg, "s", "n", code_challenge="x" * 43, prompt="select_account")
    assert parse_qs(urlparse(url).query)["prompt"] == ["select_account"]
    assert "prompt" not in parse_qs(urlparse(_oidc.build_authorize_url(cfg, "s", "n", code_challenge="x" * 43)).query)
    with pytest.raises(_oidc.OidcError):
        _oidc.build_authorize_url(cfg, "s", "n", code_challenge="x" * 43, prompt="select_account consent&x=1")


def test_the_handoff_asks_google_for_the_account_chooser_and_the_page_names_the_account(tmp_path, monkeypatch):
    _on(monkeypatch)
    idp = _MiniIdP()
    sov, edge, ep, _ = _stack_oidc(tmp_path, monkeypatch, idp)
    try:
        st, hdr, _ = _handoff_login(ep, challenge_of(_verifier()))
        assert parse_qs(urlparse(hdr["Location"]).query)["prompt"] == ["select_account"]
        st, hdr, _ = _edge_raw(ep, "/api/customer/oidc/login")                # the normal flow: unchanged
        assert st == 302 and "prompt=" not in hdr["Location"]
        _v, st, _h, page = _app_finishes_google(ep, idp, email="o'brien+<x>@gmail.com")
        text = page.decode()
        assert st == 200 and "You signed in to Google as" in text
        assert "o&#x27;brien+&lt;x&gt;@gmail.com" in text and "<x>" not in text    # escaped, never markup
        assert ("If you did not just tap Continue with Google in the VIGIL app installed on this phone, close this "
                "page and do not enter the code anywhere.") in text
    finally:
        sov.shutdown(); edge.shutdown()


def test_one_google_account_cannot_fill_the_store_of_waiting_sign_ins(tmp_path, monkeypatch):
    _on(monkeypatch)
    idp = _MiniIdP()
    sov, edge, ep, _ = _stack_oidc(tmp_path, monkeypatch, idp)
    try:
        for _ in range(3):                                                  # three waiting at once: fine
            assert _app_finishes_google(ep, idp, sub="busy-sub", email="busy@gmail.com")[1] == 200
        _v, st, hdr, page = _app_finishes_google(ep, idp, sub="busy-sub", email="busy@gmail.com")
        assert st == 429 and b"cust-handoff-code" not in page and b"Too many Google sign-ins" in page
        assert CUSTOMER_COOKIE not in (hdr.get("Set-Cookie") or "")
        assert _app_finishes_google(ep, idp, sub="other-sub", email="other@gmail.com")[1] == 200   # others unaffected
    finally:
        sov.shutdown(); edge.shutdown()


def test_the_victim_cannot_be_logged_into_the_attackers_account_by_a_crafted_callback(tmp_path, monkeypatch):
    """Login CSRF against the hand-off: the attacker finishes Google sign-in as THEMSELVES for a hand-off they
    started and makes the victim's browser load the callback. The victim's browser gets a code page and no session
    cookie; nothing redeems without the attacker's verifier, which never leaves the attacker's app."""
    _on(monkeypatch)
    idp = _MiniIdP()
    sov, edge, ep, _ = _stack_oidc(tmp_path, monkeypatch, idp)
    try:
        _v, st, hdr, _page = _app_finishes_google(ep, idp, sub="attacker-sub", email="attacker@gmail.com")
        assert st == 200 and CUSTOMER_COOKIE not in (hdr.get("Set-Cookie") or "")
    finally:
        sov.shutdown(); edge.shutdown()


def test_the_redeem_is_origin_gated_and_limited_per_ip(tmp_path, monkeypatch):
    _on(monkeypatch)
    idp = _MiniIdP()
    sov, edge, ep, _ = _stack_oidc(tmp_path, monkeypatch, idp)
    try:
        v, _st, _h, page = _app_finishes_google(ep, idp, ip="198.51.100.20")
        code = _code_from(page)
        assert _redeem(ep, {"verifier": v, "code": code}, origin="https://evil.example")[0] == 403   # CSRF
        # one IP: 10 failed redemptions (unknown verifiers) in 15 minutes, then 429 — even with the right pair
        for _ in range(10):
            assert _redeem(ep, {"verifier": _verifier(), "code": "000000"}, ip="198.51.100.7")[0] == 401
        st, hdr, _ = _redeem(ep, {"verifier": v, "code": code}, ip="198.51.100.7")
        assert st == 429 and int(hdr["Retry-After"]) >= 1
        # another address on that network still redeems (the per-IP leg is best effort; the per-record limit is the
        # bound)
        st, _h, body = _redeem(ep, {"verifier": v, "code": code}, ip="198.51.100.8")
        assert st == 200 and body["ok"] is True
    finally:
        sov.shutdown(); edge.shutdown()


def test_a_refused_google_sign_in_shows_a_page_and_stores_nothing(tmp_path, monkeypatch):
    _on(monkeypatch)
    idp = _MiniIdP()
    sov, edge, ep, _ = _stack_oidc(tmp_path, monkeypatch, idp)
    try:
        v = _verifier()
        st, hdr, _ = _handoff_login(ep, challenge_of(v))
        q = parse_qs(urlparse(hdr["Location"]).query)
        idp.next_id_token = idp.mint(nonce=q["nonce"][0], email_verified=False)   # the provisioner refuses
        st, hdr, page = _callback(ep, q["state"][0])
        assert st == 401 and b"Sign-in did not complete." in page and b"cust-handoff-code" not in page
        assert CUSTOMER_COOKIE not in (hdr.get("Set-Cookie") or "")
        assert [p for p in (tmp_path / "customer-oidc-handoff").glob("*") if p.name != ".handoff.lock"] == []
        # a replayed callback finds its state spent
        assert _callback(ep, q["state"][0])[0] == 401
    finally:
        sov.shutdown(); edge.shutdown()


def test_the_normal_flow_keeps_its_sid_binding_with_the_handoff_on(tmp_path, monkeypatch):
    _on(monkeypatch)
    idp = _MiniIdP()
    sov, edge, ep, _ = _stack_oidc(tmp_path, monkeypatch, idp)
    try:
        state, nonce, sid, _ = _oidc_login(ep)                               # sets the sid cookie as before
        idp.next_id_token = idp.mint(nonce=nonce)
        st, hdr, _ = _callback(ep, state)                                    # no sid cookie: refused
        assert st == 401 and CUSTOMER_COOKIE not in (hdr.get("Set-Cookie") or "")
        state, nonce, sid, _ = _oidc_login(ep)
        idp.next_id_token = idp.mint(nonce=nonce)
        st, hdr, _ = _callback(ep, state, cookie=f"vigil_customer_oidc_sid={sid}")
        assert st == 302 and hdr["Location"] == "/" and CUSTOMER_COOKIE in hdr.get("Set-Cookie", "")
    finally:
        sov.shutdown(); edge.shutdown()


def test_a_handoff_started_then_switched_off_completes_nothing(tmp_path, monkeypatch):
    _on(monkeypatch)
    idp = _MiniIdP()
    sov, edge, ep, _ = _stack_oidc(tmp_path, monkeypatch, idp)
    try:
        v = _verifier()
        st, hdr, _ = _handoff_login(ep, challenge_of(v))
        q = parse_qs(urlparse(hdr["Location"]).query)
        idp.next_id_token = idp.mint(nonce=q["nonce"][0])
        monkeypatch.delenv("VIGIL_CUSTOMER_OIDC_HANDOFF")
        st, hdr, page = _callback(ep, q["state"][0])
        assert st == 404 and b"cust-handoff-code" not in page and CUSTOMER_COOKIE not in (hdr.get("Set-Cookie") or "")
    finally:
        sov.shutdown(); edge.shutdown()


# ================================================================================================================
# the page flag, and the app's side under node
# ================================================================================================================
def _page(tmp_path):
    srv = build_customer_server(host="127.0.0.1", port=0, hop_key="k", provision_base="http://127.0.0.1:1",
                                sessions_dir=str(tmp_path / "s"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
        c.request("GET", "/", headers={"Host": f"127.0.0.1:{srv.server_address[1]}"})
        r = c.getresponse()
        return r.read().decode(), r.getheader("X-Vigil-Build")
    finally:
        srv.shutdown()
        srv.server_close()


def test_the_page_flag_needs_google_and_the_handoff(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_OIDC_CLIENT_ID", "client-123")
    monkeypatch.setenv("VIGIL_CUSTOMER_OIDC_REDIRECT_URI", "https://app.example/api/customer/oidc/callback")
    monkeypatch.delenv("VIGIL_CUSTOMER_OIDC_ENABLED", raising=False)
    monkeypatch.setenv("VIGIL_CUSTOMER_OIDC_HANDOFF", "1")
    page, b1 = _page(tmp_path / "a")
    assert 'data-oidc-handoff="0"' in page                                   # hand-off without Google: nothing
    monkeypatch.setenv("VIGIL_CUSTOMER_OIDC_ENABLED", "1")
    page, b2 = _page(tmp_path / "b")
    assert 'data-oidc-handoff="1"' in page and "__VIGIL_OIDC_HANDOFF__" not in page
    monkeypatch.delenv("VIGIL_CUSTOMER_OIDC_HANDOFF")
    page, b3 = _page(tmp_path / "c")
    assert 'data-oidc-handoff="0"' in page
    assert len({b1, b2, b3}) == 3                                            # each is its own build


def test_the_flag_is_off_unless_affirmative(monkeypatch):
    from sigil import config
    monkeypatch.delenv("VIGIL_CUSTOMER_OIDC_HANDOFF", raising=False)
    assert config.customer_oidc_handoff_enabled() is False
    for v in ("0", "", "no", "off"):
        monkeypatch.setenv("VIGIL_CUSTOMER_OIDC_HANDOFF", v)
        assert config.customer_oidc_handoff_enabled() is False, v
    for v in ("1", "true", "on"):
        monkeypatch.setenv("VIGIL_CUSTOMER_OIDC_HANDOFF", v)
        assert config.customer_oidc_handoff_enabled() is True, v


_APP_HARNESS = r"""
const vm = require("vm"), fs = require("fs");
const [APPJS, CFG] = process.argv.slice(-2);
const cfg = JSON.parse(CFG);
const src = fs.readFileSync(APPJS, "utf8");
const a = src.indexOf("  function pageFlag("), b = src.indexOf("\n  }\n", a) + 4;
const c = src.indexOf("  // ---- Continue with Google"), d = src.indexOf("  async function doHandoff(");
const e = src.indexOf("\n  }\n", d) + 4;
const out = { assigned: [], navs: [], errors: [], cookie: "" };
const ss = {};
const ctx = { console, Promise, JSON, String, Uint8Array, TextEncoder, btoa, crypto: globalThis.crypto,
  Date, setTimeout,
  document: { body: { dataset: cfg.dataset }, get cookie() { return out.cookie; },
              set cookie(v) { out.cookie = v; } },
  navigator: { standalone: !!cfg.standalone }, window: { matchMedia: () => ({ matches: false }) },
  sessionStorage: { getItem: k => (k in ss ? ss[k] : null), setItem: (k, v) => { ss[k] = String(v); },
                    removeItem: k => { delete ss[k]; } },
  location: { hash: "", assign: u => out.assigned.push(u) },
  API: "api/customer", clearErr() {}, err: m => out.errors.push(m), nav: h => out.navs.push(h),
  h() { return {}; }, authed: () => false, here: () => "#/login", render() {}, refreshWho: async () => ({}),
  shell: x => x, val: () => "", VUI: {} };
vm.createContext(ctx);
vm.runInContext(src.slice(a, b) + "\n" + src.slice(c, e) +
  "\nthis.startGoogle = startGoogle; this.handoffOn = handoffOn; this.pendingLoad = pendingLoad;", ctx);
(async () => {
  out.handoffOn = ctx.handoffOn();
  ctx.startGoogle();
  for (let i = 0; i < 20 && !out.assigned.length; i++) await new Promise(r => setTimeout(r, 10));
  out.stored = ss;
  const rec = await ctx.pendingLoad();
  out.loaded = rec ? rec.verifier : null;
  console.log(JSON.stringify(out));
})();
"""


def _app(dataset, standalone):
    r = subprocess.run(["node", "-e", _APP_HARNESS, str(APP / "app.js"),
                        json.dumps({"dataset": dataset, "standalone": standalone})],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_the_installed_app_starts_the_handoff_with_the_challenge_of_a_verifier_it_keeps():
    out = _app({"googleSignin": "1", "oidcHandoff": "1"}, True)
    assert out["handoffOn"] is True and len(out["assigned"]) == 1
    url = out["assigned"][0]
    assert url.startswith("api/customer/oidc/login?handoff=")
    verifier = out["loaded"]
    assert verifier and len(verifier) == 43
    assert url == "api/customer/oidc/login?handoff=" + challenge_of(verifier)   # same S256 as the edge
    assert verifier not in url and out["cookie"] == ""                           # never in a URL or a cookie
    assert out["navs"] == ["#/google-code"]                                      # the code box is waiting
    assert json.loads(out["stored"]["vigil.oidc.handoff"])["verifier"] == verifier   # (no IndexedDB here)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("dataset,standalone", [({"googleSignin": "1", "oidcHandoff": "1"}, False),
                                                ({"googleSignin": "1", "oidcHandoff": "0"}, True),
                                                ({"googleSignin": "0", "oidcHandoff": "1"}, True)])
def test_outside_a_standalone_app_with_the_handoff_on_the_normal_flow_is_used(dataset, standalone):
    out = _app(dataset, standalone)
    assert out["handoffOn"] is False and out["assigned"] == ["api/customer/oidc/login"]
    assert out["stored"] == {} and out["navs"] == []


def test_the_code_page_script_only_reveals_a_link_back_into_the_app():
    js = (APP / "handoff.js").read_text(encoding="utf-8")
    assert "fetch(" not in js and "Storage" not in js and "cookie" not in js
    assert 'getElementById("handoff-continue")' in js and "el.hidden = false" in js


def test_store_dirs_are_siblings_of_the_session_ledger(tmp_path):
    srv = build_customer_server(host="127.0.0.1", port=0, hop_key="k", provision_base="http://127.0.0.1:1",
                                sessions_dir=str(tmp_path / "sessions"))
    try:
        assert srv.oidc_handoff_dir == tmp_path / "customer-oidc-handoff"
        assert srv.oidc_handoff_limit_dir == tmp_path / "customer-oidc-handoff-limit"
    finally:
        srv.server_close()


def test_handoff_records_expire_in_about_two_minutes():
    assert HandoffStore(".").ttl_s == 120.0 and HandoffStore(".").max_attempts == 5


_ = (hashlib, os, time)
