"""
Authenticated scanning — cookie jar, login sequence, logout-detection + re-auth,
and a full crawl+scan of a login-gated vulnerability.

A stateful loopback app tracks valid sessions: /login mints one, /account is
401 without it and (when authenticated) is boolean-SQLi-vulnerable on `filter`.
The tests pin: login captures the cookie; the audit engine finds the SQLi ONLY
through the authenticated send; and when the server invalidates the session mid
scan, the AuthSession detects the logout and re-authenticates transparently.
"""

from __future__ import annotations

import contextlib
import re
import secrets
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from framework.v2.scanner.engine import AuditEngine
from framework.v2.scanner.insertion import HttpRequest, InsertionKind
from framework.v2.scanner.session import AuthSession, CookieJar, LoginSequence


class _AuthServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler) -> None:
        super().__init__(addr, handler)
        self.sessions: set[str] = set()


class _AuthHandler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        return

    def _token(self) -> str | None:
        m = re.search(r"session=([^;]+)", self.headers.get("Cookie", ""))
        return m.group(1) if m else None

    def _reply(self, status: int, body: bytes, extra: list[tuple[str, str]] = ()) -> None:
        self.send_response(status)
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0) or 0)
        params = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
        if urllib.parse.urlsplit(self.path).path == "/login" \
                and params.get("user") == ["admin"] and params.get("password") == ["secret"]:
            token = secrets.token_hex(8)
            self.server.sessions.add(token)  # type: ignore[attr-defined]
            self._reply(200, b"welcome admin", [("Set-Cookie", f"session={token}; Path=/")])
        else:
            self._reply(401, b"bad credentials")

    def do_GET(self) -> None:  # noqa: N802
        sp = urllib.parse.urlsplit(self.path)
        token = self._token()
        authed = token in self.server.sessions  # type: ignore[attr-defined]
        if sp.path == "/account":
            if not authed:
                self._reply(401, b"please log in")
                return
            q = urllib.parse.parse_qs(sp.query).get("filter", [""])[0]
            if "'1'='1" in q or "1=1" in q:  # tautology dumps the table
                rows = "\n".join(f"id={i} user{i} role={'admin' if i == 2 else 'user'}"
                                 for i in range(1, 9))
            else:
                rows = "no results"
            self._reply(200, f"account [{q}]:\n{rows}".encode())
        elif sp.path == "/":
            self._reply(200, b'<a href="/account?filter=x">acct</a>')
        else:
            self._reply(404, b"nope")


@contextlib.contextmanager
def _server() -> Iterator[tuple[str, _AuthServer]]:
    srv = _AuthServer(("127.0.0.1", 0), _AuthHandler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}", srv
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def _raw_send(req: HttpRequest) -> dict:
    r = urllib.request.Request(req.url, method=req.method, headers=dict(req.headers))
    if req.body is not None:
        r.data = req.body.encode("utf-8")
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:  # noqa: S310 (loopback)
            return {"status": resp.status, "headers": list(resp.headers.items()),
                    "body": resp.read().decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:  # 401 is a normal response here, not an error
        return {"status": e.code, "headers": list(e.headers.items()),
                "body": e.read().decode("utf-8", "replace")}


def _login(base: str) -> LoginSequence:
    return LoginSequence(url=f"{base}/login", body="user=admin&password=secret",
                         logged_out_markers=("please log in",))


def test_cookie_jar_capture_and_render() -> None:
    jar = CookieJar()
    jar.update_from_headers([("Set-Cookie", "session=abc123; Path=/; HttpOnly"),
                             ("Set-Cookie", "theme=dark; Path=/")])
    assert "session" in jar and jar.header() == "session=abc123; theme=dark"
    jar.update_from_headers([("Set-Cookie", "session=deleted; Max-Age=0")])
    assert "session" not in jar


def test_login_captures_session_and_authenticated_access_works() -> None:
    with _server() as (base, _srv):
        auth = AuthSession(_raw_send, _login(base))
        assert auth.authenticate() is True
        assert "session" in auth.jar
        resp = auth.send(HttpRequest(method="GET", url=f"{base}/account?filter=x"))
        assert resp["status"] == 200 and "account" in resp["body"]


def test_sqli_behind_login_found_only_when_authenticated() -> None:
    with _server() as (base, _srv):
        req = HttpRequest(method="GET", url=f"{base}/account?filter=x")

        # unauthenticated: /account is 401 for both probes -> no differential
        unauth = AuditEngine(_raw_send).audit(req, insertion_kinds=(InsertionKind.QUERY_VALUE,))
        assert unauth == [], "found a finding without authenticating (impossible here)"

        # authenticated: the boolean-SQLi differential fires
        auth = AuthSession(_raw_send, _login(base))
        findings = AuditEngine(auth.send).audit(req, insertion_kinds=(InsertionKind.QUERY_VALUE,))
        sqli = [f for f in findings if f.bug_class == "boolean_sqli" and f.param == "filter"]
        assert sqli and sqli[0].confirmed_by == "differential_response"


def test_reauth_on_session_expiry() -> None:
    with _server() as (base, srv):
        auth = AuthSession(_raw_send, _login(base))
        assert auth.send(HttpRequest(url=f"{base}/account")).get("status") == 200
        relogins_before = auth.relogins

        srv.sessions.clear()  # server invalidates every session mid-scan
        resp = auth.send(HttpRequest(url=f"{base}/account"))
        assert resp["status"] == 200, "session expiry was not transparently recovered"
        assert auth.relogins > relogins_before, "no re-authentication happened"
