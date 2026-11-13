"""Anonymous requests to the cockpit cost bounded work and write bounded audit.

  * A presented token that cannot be a per-user bearer (the shape `AccountsRegistry.create` enforces) is refused
    BEFORE the account fold; the legacy owner token is compared first, whatever its shape.
  * A well-shaped token that just FAILED to resolve is remembered (bounded, short TTL) so repeating it costs no
    second fold; a success is never remembered, so a revocation takes effect on the very next request.
  * A logout that ends no session and has no principal (a made-up cookie included) appends nothing.
  * Failed logins are coalesced per (client, method, reason[, a username a first factor proved]) and window: the
    first is recorded at once with its client (the peer address — forwarded headers are not trusted), the rest
    are counted into one summary record, written when the window ends (on the next request, by a background
    flush, or at shutdown) and retried if the spine refuses it — an attack is never invisible on the spine.

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=packages/core/vigil_core:apps/sigil:integration \
     .venv-sovereign/bin/python -m pytest -q apps/sigil/tests/test_anonymous_cost.py
"""
from __future__ import annotations

import json
import secrets
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

from sigil.governor import accounts as acc
from sigil.governor.identity import ensure_owner_keypair
from sigil.ui import server as srvmod
from sigil.ui.authn_audit import FailedAuthnCoalescer
from sigil.ui.server import FailedTokenCache, bearer_shape_ok, build_server

TOKEN = "owner-shared-token-anon-cost"


class _Clock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def _serve():
    ensure_owner_keypair()
    s = build_server(token=TOKEN, port=0, spine_path=tempfile.mktemp(suffix=".jsonl"))
    clock = _Clock()
    s.failed_tokens.clock = clock
    s.authn_failures.clock = clock
    threading.Thread(target=s.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return s, s.server_address[1], clock


def _req(port, path, *, method="GET", body=None, token=None, headers=None):
    h = {"Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}", **(headers or {})}
    if token is not None:
        h["X-SIGIL-Token"] = token
    data = None
    if body is not None:
        h["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:  # noqa: BLE001
            return e.code, {}


def _authn(server):
    return [r.payload for r in server.store().iter_records() if getattr(r, "source", None) == "authn"]


@pytest.fixture
def folds(monkeypatch):
    """Count account folds (`AccountsRegistry.resolve`) and, separately, every spine read (`iter_records`)."""
    from sigil.spine.store import SpineStore
    calls = {"n": 0, "reads": 0}
    real = acc.AccountsRegistry.resolve
    real_iter = SpineStore.iter_records

    def spy(self, *a, **k):
        calls["n"] += 1
        return real(self, *a, **k)

    def spy_iter(self, *a, **k):
        calls["reads"] += 1
        return real_iter(self, *a, **k)

    monkeypatch.setattr(acc.AccountsRegistry, "resolve", spy)
    monkeypatch.setattr(SpineStore, "iter_records", spy_iter)
    return calls


# ======================================================================================================
# 1. a token that cannot be a bearer never reaches the account fold
# ======================================================================================================
@pytest.mark.parametrize("tok", ["short", "x" * 15, "x" * 513, "spaced token value!!", "tab\tseparated-token",
                                 "nön-ascii-tokenvalue", "ctrl\x01-token-value-xx", "new\nline-token-value"])
def test_a_token_that_cannot_be_a_bearer_is_refused_without_a_fold(folds, tok):
    s, port, _clock = _serve()
    q = urllib.parse.quote(tok, safe="")                  # the query carrier (a header cannot hold every byte)
    try:
        assert bearer_shape_ok(tok) is False
        assert _req(port, f"/api/whoami?token={q}")[1].get("authenticated") is False
        assert _req(port, f"/api/accounts?token={q}")[0] == 401
        assert folds["n"] == 0 and folds["reads"] == 0, "the spine was read for a token that cannot be a bearer"
    finally:
        s.shutdown()


def test_the_bearers_the_cockpit_mints_and_the_creation_minimum_have_a_valid_shape():
    assert bearer_shape_ok(secrets.token_urlsafe(32))
    assert bearer_shape_ok("x" * 16) and bearer_shape_ok("x" * 512)
    assert bearer_shape_ok("!#$%&()*+,-./:;<=>?@[]^_`{|}~0123456789")


@pytest.mark.parametrize("bad", ["x" * 15, "x" * 513, "spaced token value!!", "nön-ascii-tokenvalue",
                                 "ctrl\x01-token-value-xx", "del\x7f-token-value-xxx"])
def test_account_creation_refuses_a_bearer_the_cockpit_would_never_resolve(bad):
    ensure_owner_keypair()
    from sigil.spine.store import SpineStore
    reg = acc.AccountsRegistry(SpineStore(tempfile.mktemp(suffix=".jsonl")), owner_key=ensure_owner_keypair())
    with pytest.raises(ValueError, match="printable, non-space ASCII"):
        reg.create("tim", "operator", bearer_token=bad, issued_at=1.0)


def test_the_owner_token_is_compared_first_whatever_its_shape(folds):
    s, port, _clock = _serve()
    try:
        s.token = "short"                                 # an operator-chosen owner token need not be bearer-shaped
        code, who = _req(port, "/api/whoami", token="short")
        assert code == 200 and who["authenticated"] and who["role"] == "owner"
        assert folds["n"] == 0
    finally:
        s.shutdown()


# ======================================================================================================
# 2. failures are remembered briefly; successes never are
# ======================================================================================================
def test_a_repeated_failed_token_folds_once_per_ttl(folds):
    s, port, clock = _serve()
    bogus = secrets.token_urlsafe(32)
    try:
        for _ in range(5):
            assert _req(port, "/api/accounts", token=bogus)[0] == 401
        assert folds["n"] == 1
        clock.t += s.failed_tokens.ttl_s - 0.001
        _req(port, "/api/accounts", token=bogus)
        assert folds["n"] == 1
        clock.t += 0.001                                  # the TTL has passed: resolved again
        _req(port, "/api/accounts", token=bogus)
        assert folds["n"] == 2
        other = secrets.token_urlsafe(32)                 # a different token is its own entry
        _req(port, "/api/accounts", token=other)
        assert folds["n"] == 3
    finally:
        s.shutdown()


def test_a_success_is_never_remembered_so_a_revocation_takes_effect_at_once(folds):
    s, port, _clock = _serve()
    try:
        code, out = _req(port, "/api/action", method="POST", token=TOKEN,
                         body={"action": "create_account", "username": "tim", "role": "operator"})
        assert code == 200
        bearer = out.get("bearer_token")
        assert bearer, out
        assert _req(port, "/api/whoami", token=bearer)[1]["authenticated"] is True
        n = folds["n"]
        assert _req(port, "/api/whoami", token=bearer)[1]["authenticated"] is True
        assert folds["n"] == n + 1, "a successful resolution was answered from memory"
        acc.AccountsRegistry(s.store(), owner_key=ensure_owner_keypair()).revoke("tim")
        assert _req(port, "/api/whoami", token=bearer)[1].get("authenticated") is False
    finally:
        s.shutdown()


def test_a_resolution_that_raised_is_not_remembered(folds, monkeypatch):
    s, port, _clock = _serve()
    bogus = secrets.token_urlsafe(32)
    try:
        def broken(self, *a, **k):
            folds["n"] += 1
            raise OSError("spine unreadable")

        monkeypatch.setattr(acc.AccountsRegistry, "resolve", broken)
        _req(port, "/api/accounts", token=bogus)
        _req(port, "/api/accounts", token=bogus)
        assert folds["n"] == 2, "a spine error (not the token) was remembered as the token's failure"
    finally:
        s.shutdown()


def test_the_failed_token_memory_is_bounded_and_expires():
    clock = _Clock()
    c = FailedTokenCache(ttl_s=5.0, max_entries=3, clock=clock)
    for d in "abcd":
        c.add(d)
    assert not c.hit("a") and c.hit("b") and c.hit("c") and c.hit("d")    # the oldest was evicted
    c.add("b")                                                            # re-adding refreshes, never duplicates
    c.add("e")
    assert c.hit("b") and not c.hit("c") and c.hit("e")
    clock.t += 5.0
    assert not c.hit("b") and not c.hit("e")


# ======================================================================================================
# 3. a logout by nobody appends nothing
# ======================================================================================================
def test_a_logout_that_ends_no_session_appends_nothing_and_a_real_logout_is_still_audited():
    from pathlib import Path

    from sigil.ui.sessions import SessionLedger
    s, port, _clock = _serve()
    try:
        before = len(_authn(s))
        for cookie in (None, "sigil_session=an-old-session-id", "sigil_session=" + secrets.token_urlsafe(32)):
            h = {"Cookie": cookie} if cookie else None
            assert _req(port, "/api/logout", method="POST", body={}, headers=h)[0] == 200
        assert len(_authn(s)) == before, "a logout that ended nothing was audited"
        assert _req(port, "/api/logout", method="POST", body={}, token=TOKEN)[0] == 200
        assert [e["event"] for e in _authn(s)[before:]] == ["authn.logout"]
        base = Path(s.spine_path)
        sid = SessionLedger(base.parent / (base.name + ".sessions")).create("owner", "owner", is_owner=True)
        assert sid
        assert _req(port, "/api/logout", method="POST", body={}, headers={"Cookie": f"sigil_session={sid}"})[0] == 200
        assert [e["event"] for e in _authn(s)[before:]] == ["authn.logout", "authn.logout"]
        ghost = SessionLedger(base.parent / (base.name + ".sessions")).create("ghost", "operator")
        assert ghost                                     # a live session whose account resolves to no principal
        assert _req(port, "/api/logout", method="POST", body={}, headers={"Cookie": f"sigil_session={ghost}"})[0] == 200
        assert [e["event"] for e in _authn(s)[before:]] == ["authn.logout"] * 3, "ending a session was not audited"
    finally:
        s.shutdown()


# ======================================================================================================
# 4. failed logins are coalesced, never invisible
# ======================================================================================================
def _fail_login(port, *, forwarded=None, username=None):
    body = {"token": secrets.token_urlsafe(32)} if username is None else {"username": username,
                                                                          "password": "wrong-password"}
    h = {"X-Forwarded-For": forwarded, "X-Real-IP": forwarded} if forwarded else None
    return _req(port, "/api/login", method="POST", body=body, headers=h)[0]


def _fails(s):
    return [e for e in _authn(s) if e["event"] == "authn.login.failure"]


def test_a_burst_of_failed_logins_records_the_first_at_once_and_counts_the_rest():
    s, port, clock = _serve()
    try:
        for i in range(20):                                  # a forwarded address the client chose splits nothing
            assert _fail_login(port, forwarded=f"203.0.113.{i}") == 401
        fails = _fails(s)
        assert len(fails) == 1 and fails[0]["client"] == "127.0.0.1" and "coalesced" not in fails[0]
        clock.t += s.authn_failures.window_s
        _req(port, "/healthz")                            # any request flushes a window that has ended
        fails = _fails(s)
        assert len(fails) == 2
        summary = fails[1]
        assert summary["coalesced"] == 19 and summary["client"] == "127.0.0.1" and summary["method"] == "bearer"
        assert summary["window_s"] == s.authn_failures.window_s and summary["reason"] == "invalid_token"
        assert summary["username"] == "(coalesced)" and summary["since"].endswith("+00:00")
        _req(port, "/healthz")
        assert len(_fails(s)) == 2, "a summary written twice"
        assert _fail_login(port) == 401                    # a new window: recorded at once
        assert len(_fails(s)) == 3
    finally:
        s.shutdown()


def test_methods_are_their_own_groups_and_claimed_usernames_do_not_split_one():
    s, port, _clock = _serve()
    try:
        _fail_login(port)
        _fail_login(port)
        for i in range(5):                                 # varying the claimed username does not open new groups
            _fail_login(port, username=f"user{i}")
        assert [(e["client"], e["method"], e["reason"]) for e in _fails(s)] == [
            ("127.0.0.1", "bearer", "invalid_token"), ("127.0.0.1", "password", "bad_credentials")]
    finally:
        s.shutdown()


def test_every_failed_login_goes_through_the_coalescer():
    """No login path appends its own failure record: each one calls `_authn_failure`, and every second-factor
    failure (the username a first factor proved) is marked proven."""
    import inspect
    src = inspect.getsource(srvmod)
    assert src.count('"authn.login.failure"') == 1 and "def _authn_failure" in src
    assert src.count('reason="totp", proven=True)') == 3 and src.count('reason="totp")') == 0


def test_the_handler_passes_a_proven_username_through_to_the_coalescer():
    seen: list = []

    class _C:
        def record(self, store, event, **kw):
            seen.append(kw)

    class _H:
        client_address = ("127.0.0.1", 0)
        server = type("S", (), {"authn_failures": _C()})()
        _client_source = srvmod.Handler._client_source

    srvmod.Handler._authn_failure(_H(), None, username="tim", method="password", reason="totp", proven=True)
    srvmod.Handler._authn_failure(_H(), None, username="eve", method="password", reason="bad_credentials")
    assert [(k["username"], k["proven"]) for k in seen] == [("tim", True), ("eve", False)]


class _Rec:
    def __init__(self, fail_first: int = 0):
        self.written: list = []
        self.fail = fail_first

    def append(self, **kw):
        if self.fail:
            self.fail -= 1
            raise OSError("spine busy")
        self.written.append(kw["payload"])


def _coalescer(**kw):
    clock = _Clock()
    return FailedAuthnCoalescer(window_s=60.0, clock=clock, **kw), clock


def test_client_method_reason_and_a_proven_username_each_split_a_group():
    c, clock = _coalescer()
    st = _Rec()
    for src, method, reason, user, proven in [
            ("198.51.100.1", "password", "bad_credentials", "a", False),
            ("198.51.100.1", "password", "bad_credentials", "b", False),   # a claimed username: same group
            ("198.51.100.2", "password", "bad_credentials", "a", False),   # another client
            ("198.51.100.1", "bearer", "bad_credentials", "", False),      # another method
            ("198.51.100.1", "password", "totp", "tim", True),             # another reason, a proven username
            ("198.51.100.1", "password", "totp", "ann", True),             # another proven username
            ("198.51.100.1", "password", "totp", "tim", True)]:            # counted
        c.record(st, "authn.login.failure", source=src, username=user, method=method, reason=reason, proven=proven)
    assert [(p["client"], p["method"], p.get("reason"), p["username"]) for p in st.written] == [
        ("198.51.100.1", "password", "bad_credentials", "a"), ("198.51.100.2", "password", "bad_credentials", "a"),
        ("198.51.100.1", "bearer", "bad_credentials", "anonymous"), ("198.51.100.1", "password", "totp", "tim"),
        ("198.51.100.1", "password", "totp", "ann")]
    clock.t += 60.0
    c.flush(lambda: st)
    assert [(p["username"], p["coalesced"]) for p in st.written[5:]] == [("(coalesced)", 1), ("tim", 1)]


def test_the_next_failure_after_a_window_ends_writes_its_summary():
    c, clock = _coalescer()
    st = _Rec()
    for _ in range(4):
        c.record(st, "authn.login.failure", source="203.0.113.1", method="bearer", reason="invalid_token")
    clock.t += 60.0
    c.record(st, "authn.login.failure", source="203.0.113.2", method="bearer", reason="invalid_token")
    assert [(p["client"], p.get("coalesced")) for p in st.written] == [
        ("203.0.113.1", None), ("203.0.113.1", 3), ("203.0.113.2", None)]


def test_a_summary_the_spine_refuses_stays_owed_and_is_written_later():
    c, clock = _coalescer()
    st = _Rec()
    for _ in range(3):
        c.record(st, "authn.login.failure", source="203.0.113.1", method="bearer", reason="invalid_token")
    clock.t += 60.0
    st.fail = 1
    c.flush(lambda: st)                                  # the spine refuses the summary write
    c.flush(lambda: (_ for _ in ()).throw(OSError("no spine")))   # and then cannot even be opened
    assert [p.get("coalesced") for p in st.written] == [None]
    for _ in range(2):                    # the next failure writes the owed summary, then opens a new window
        c.record(st, "authn.login.failure", source="203.0.113.1", method="bearer", reason="invalid_token")
    clock.t += 60.0
    c.flush(lambda: st)
    assert [p.get("coalesced") for p in st.written] == [None, 2, None, 1], "an owed count was lost"


def test_an_owed_summary_merges_with_failures_counted_meanwhile_and_is_retried_first():
    c, clock = _coalescer()
    st = _Rec()
    for _ in range(3):                                   # group A: first + 2 counted
        c.record(st, "authn.login.failure", source="203.0.113.1", method="bearer", reason="invalid_token")
    clock.t += 50.0
    c.record(st, "authn.login.failure", source="203.0.113.9", method="bearer", reason="invalid_token")   # group B
    clock.t += 10.0                                      # A's window has ended; B's has not

    def busy_spine():
        for _ in range(3):                               # group A fails again while its summary is being written
            c.record(st, "authn.login.failure", source="203.0.113.1", method="bearer", reason="invalid_token")
        raise OSError("spine busy")

    c.flush(busy_spine)
    assert [p.get("coalesced") for p in st.written] == [None, None, None]
    c.flush(lambda: st)                                  # the owed (ended) group A is first in line, ahead of B
    assert [(p["client"], p.get("coalesced")) for p in st.written[3:]] == [("203.0.113.1", 4)]


def test_a_first_record_the_spine_refuses_is_counted_into_the_summary():
    c, clock = _coalescer()
    st = _Rec(fail_first=1)
    c.record(st, "authn.login.failure", source="203.0.113.1", method="bearer", reason="invalid_token")
    c.record(st, "authn.login.failure", source="203.0.113.1", method="bearer", reason="invalid_token")
    clock.t += 60.0
    c.flush(lambda: st)
    assert [p.get("coalesced") for p in st.written] == [2]


def test_close_writes_every_pending_count_and_server_close_calls_it():
    st = _Rec()
    c, _clock = _coalescer(store_factory=lambda: st)
    for _ in range(3):
        c.record(st, "authn.login.failure", source="203.0.113.1", method="bearer", reason="invalid_token")
    c.close()                                            # the window has NOT ended
    assert [p.get("coalesced") for p in st.written] == [None, 2]
    s, port, _clock = _serve()
    try:
        for _ in range(3):
            _fail_login(port)
    finally:
        s.shutdown()
        s.server_close()
    assert [e.get("coalesced") for e in _fails(s)] == [None, 2]


def test_an_idle_server_still_writes_the_count_when_each_window_ends():
    from sigil.spine.store import SpineStore
    p = tempfile.mktemp(suffix=".jsonl")
    c = FailedAuthnCoalescer(window_s=0.3, store_factory=lambda: SpineStore(p))
    st = SpineStore(p)
    for _ in range(4):
        c.record(st, "authn.login.failure", source="203.0.113.1", method="bearer", reason="invalid_token")
    time.sleep(0.15)
    for _ in range(2):                                   # a second group, ending later than the first
        c.record(st, "authn.login.failure", source="203.0.113.2", method="bearer", reason="invalid_token")
    want = [("203.0.113.1", None), ("203.0.113.2", None), ("203.0.113.1", 3), ("203.0.113.2", 1)]
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        got = [(r.payload.get("client"), r.payload.get("coalesced")) for r in SpineStore(p).iter_records()]
        if got == want:
            break
        time.sleep(0.05)
    assert got == want, "a summary was not written without a further request"


def test_past_the_group_bound_proven_usernames_share_the_aggregate_group():
    c, _clock = _coalescer(max_keys=1)
    st = _Rec()
    for user in ("tim", "ann", "bob", "eve"):
        c.record(st, "authn.login.failure", source="203.0.113.1", username=user, method="password",
                 reason="totp", proven=True)
    assert [(p["client"], p["username"]) for p in st.written] == [("203.0.113.1", "tim"), ("*", "ann")]


def test_the_bounds_are_the_documented_ones():
    t, a = FailedTokenCache(), FailedAuthnCoalescer()
    assert (t.ttl_s, t.max_entries) == (5.0, 4096) and (a.window_s, a.max_keys) == (60.0, 1024)


def test_a_flood_of_distinct_clients_still_leaves_a_record_and_a_count():
    clock = _Clock()
    c = FailedAuthnCoalescer(window_s=60.0, max_keys=2, clock=clock)
    st = _Rec()
    for i in range(10):
        c.record(st, "authn.login.failure", source=f"198.51.100.{i}", method="bearer", reason="invalid_token")
    assert [p["client"] for p in st.written] == ["198.51.100.0", "198.51.100.1", "*"]
    clock.t += 60.0
    c.flush(lambda: st)
    summary = st.written[-1]
    assert summary["client"] == "*" and summary["coalesced"] == 7


def test_a_summary_is_written_even_if_the_attack_stops_and_only_probes_arrive():
    s, port, clock = _serve()
    try:
        for _ in range(3):
            _fail_login(port)
        clock.t += s.authn_failures.window_s + 5
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5) as r:   # a scraper
            assert r.status == 200
        assert [e.get("coalesced") for e in _fails(s)] == [None, 2]
    finally:
        s.shutdown()


# ======================================================================================================
# 5. the client a failure is attributed to
# ======================================================================================================
def test_the_client_is_the_peer_and_forwarded_headers_are_ignored():
    class _H:
        def __init__(self, peer, headers):
            self.client_address, self.headers = (peer, 0), headers

    src = srvmod.Handler._client_source
    for peer in ("127.0.0.1", "::1", "10.0.0.5"):
        assert src(_H(peer, {"X-Forwarded-For": "203.0.113.1, 198.51.100.2", "X-Real-IP": "203.0.113.3"})) == peer


def test_the_api_ask_owner_token_check_compares_bytes():
    class _H:
        def __init__(self, tok):
            self.headers = {"X-SIGIL-Token": tok}
            self.server = type("S", (), {"token": TOKEN})()

        def _query(self):
            return {}

    ok = srvmod.Handler._token_ok
    assert ok(_H(TOKEN)) is True
    assert ok(_H("nön-ascii-owner-token")) is False and ok(_H("\udc80" + TOKEN[1:])) is False


def test_a_lone_surrogate_token_in_a_json_body_is_a_plain_refusal():
    s, port, _clock = _serve()
    try:
        raw = json.dumps({"token": "\udc80-lone-surrogate-token-xx"}).encode("ascii")   # the JSON escape
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/login", data=raw, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"})
        try:
            urllib.request.urlopen(req, timeout=5)
            raise AssertionError("accepted")
        except urllib.error.HTTPError as e:
            assert e.code == 401
    finally:
        s.shutdown()


@pytest.mark.parametrize("tok", ["nön-ascii-owner-token", "\udc80-lone-surrogate-token-xx"])
def test_a_non_ascii_token_is_refused_never_a_crash(tok):
    """`hmac.compare_digest` raises on a non-ASCII str: the owner-token compare runs on bytes, so a presented token
    like that is a plain 401, never a dropped connection."""
    s, port, _clock = _serve()
    q = urllib.parse.quote(tok.encode("utf-8", "surrogatepass"), safe="")
    try:
        assert _req(port, f"/api/accounts?token={q}")[0] == 401
        assert _req(port, f"/api/whoami?token={q}")[0] == 200
        assert srvmod._token_equal(tok, tok) is True and srvmod._token_equal(tok, TOKEN) is False
    finally:
        s.shutdown()


def test_a_lone_failure_writes_no_summary_and_a_window_ends_exactly_on_time():
    clock = _Clock()
    c = FailedAuthnCoalescer(window_s=60.0, clock=clock)
    written: list = []

    class _Store:
        def append(self, **kw):
            written.append(kw["payload"])

    st = _Store()
    c.record(st, "authn.login.failure", source="203.0.113.5", method="bearer", reason="invalid_token")
    clock.t += 59.999
    assert c.due() is False
    c.record(st, "authn.login.failure", source="203.0.113.5", method="bearer", reason="invalid_token")
    assert len(written) == 1                           # still inside the window: counted
    clock.t += 0.001                                   # exactly one window after it opened
    assert c.due() is True
    c.flush(lambda: st)
    assert [p.get("coalesced") for p in written] == [None, 1]
    c.record(st, "authn.login.failure", source="203.0.113.5", method="bearer", reason="invalid_token")
    clock.t += 60.0
    c.flush(lambda: st)
    assert [p.get("coalesced") for p in written] == [None, 1, None], "a window that counted nothing wrote a summary"
