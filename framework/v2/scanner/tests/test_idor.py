"""
IDOR / BOLA producer — a two-identity, oracle-confirmed unauthorized read.

A two-user app serves documents. Acting as alice, the check requests bob's
document. On the VULNERABLE app the response reveals bob's content (cross-tenant
read) and the achieved-state oracle confirms it; on the SECURE app the request is
403'd and nothing is confirmed. Authorization is proven by what was actually
read, not by a numeric id's presence.
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

from framework.v2.scanner.checks import IdorCheck
from framework.v2.scanner.engine import AuditEngine
from framework.v2.scanner.insertion import HttpRequest, InsertionKind
from framework.v2.scanner.session import AuthSession, LoginSequence

# doc id -> (owner, secret content)
_DOCS = {"1": ("alice", "alice-tax-return"), "2": ("bob", "bob-medical-record")}
_CREDS = {"alice": "pw-alice", "bob": "pw-bob"}


def _make_handler(enforce_owner: bool) -> type[BaseHTTPRequestHandler]:
    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a: object) -> None:
            return

        def _user(self) -> str | None:
            m = re.search(r"session=([^;]+)", self.headers.get("Cookie", ""))
            tok = m.group(1) if m else None
            return self.server.tokens.get(tok) if tok else None  # type: ignore[attr-defined]

        def _reply(self, status: int, body: bytes, extra=()) -> None:
            self.send_response(status)
            for k, v in extra:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            n = int(self.headers.get("Content-Length", 0) or 0)
            p = urllib.parse.parse_qs(self.rfile.read(n).decode())
            user, pw = p.get("user", [""])[0], p.get("password", [""])[0]
            if _CREDS.get(user) == pw:
                tok = secrets.token_hex(8)
                self.server.tokens[tok] = user  # type: ignore[attr-defined]
                self._reply(200, b"ok", [("Set-Cookie", f"session={tok}; Path=/")])
            else:
                self._reply(401, b"bad creds")

        def do_GET(self) -> None:  # noqa: N802
            sp = urllib.parse.urlsplit(self.path)
            user = self._user()
            if sp.path != "/document" or user is None:
                self._reply(401, b"please log in")
                return
            doc_id = urllib.parse.parse_qs(sp.query).get("id", [""])[0]
            doc = _DOCS.get(doc_id)
            if doc is None:
                self._reply(404, b"no such doc")
                return
            owner, secret = doc
            if enforce_owner and owner != user:
                self._reply(403, b"forbidden")  # secure: object-level authz
                return
            # vulnerable path (or the owner): returns the object content
            self._reply(200, f"doc {doc_id} owner={owner} secret={secret}".encode())

    return _H


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler) -> None:
        super().__init__(addr, handler)
        self.tokens: dict[str, str] = {}


@contextlib.contextmanager
def _app(enforce_owner: bool) -> Iterator[str]:
    srv = _Server(("127.0.0.1", 0), _make_handler(enforce_owner))
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
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
    except urllib.error.HTTPError as e:
        return {"status": e.code, "headers": list(e.headers.items()),
                "body": e.read().decode("utf-8", "replace")}


def _session(base: str, user: str) -> AuthSession:
    return AuthSession(_raw_send, LoginSequence(
        url=f"{base}/login", body=f"user={user}&password={_CREDS[user]}",
        logged_out_markers=("please log in", "forbidden")))


def _idor_check(base: str) -> IdorCheck:
    # attacker is the auditor's session (alice); victim is bob, ref = bob's doc "2"
    bob = _session(base, "bob")
    return IdorCheck(id="idor-doc", ref_param="id", victim_ref="2", victim_send=bob.send)


def test_idor_confirmed_on_vulnerable_app() -> None:
    with _app(enforce_owner=False) as base:
        alice = _session(base, "alice")
        req = HttpRequest(method="GET", url=f"{base}/document?id=1")  # alice's own doc as the seed
        findings = AuditEngine(alice.send).audit(
            req, checks=(_idor_check(base),), insertion_kinds=(InsertionKind.QUERY_VALUE,))
        idor = [f for f in findings if f.bug_class == "idor"]
        assert idor, "cross-tenant read was not confirmed on the vulnerable app"
        assert idor[0].confirmed_by == "achieved_state" and idor[0].param == "id"


def test_idor_not_confirmed_when_authz_enforced() -> None:
    with _app(enforce_owner=True) as base:
        alice = _session(base, "alice")
        req = HttpRequest(method="GET", url=f"{base}/document?id=1")
        findings = AuditEngine(alice.send).audit(
            req, checks=(_idor_check(base),), insertion_kinds=(InsertionKind.QUERY_VALUE,))
        assert findings == [], "IDOR falsely confirmed against an app that enforces object authz"
