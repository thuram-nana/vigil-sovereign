"""
JWT attacks — codec round-trips, HMAC secret cracking, and a live alg:none bypass
confirmed only when the server specifically trusts unsigned tokens.
"""

from __future__ import annotations

import contextlib
import hmac as _hmac
import http.client
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from framework.v2.scanner import jwt
from framework.v2.scanner.checks import Send
from framework.v2.scanner.engine import AuditEngine
from framework.v2.scanner.insertion import HttpRequest

_SECRET = b"s3cr3t"


def _valid_token() -> str:
    return jwt.encode_hs256({"typ": "JWT"}, {"sub": "alice", "role": "user"}, _SECRET)


# --- codec + crack ----------------------------------------------------------


def test_codec_roundtrip_and_none() -> None:
    tok = _valid_token()
    header, payload, _ = jwt.decode(tok)
    assert header["alg"] == "HS256" and payload["sub"] == "alice"
    none = jwt.encode_none(header, payload)
    h2, p2, _ = jwt.decode(none + "x")  # trailing empty sig segment handled by split
    assert h2["alg"] == "none" and p2 == payload


def test_crack_hs256_finds_weak_secret() -> None:
    tok = _valid_token()
    assert jwt.crack_hs256(tok, ["wrong", "password", "s3cr3t", "admin"]) == "s3cr3t"
    assert jwt.crack_hs256(tok, ["nope", "wrong"]) is None


# --- live alg:none bypass ---------------------------------------------------


def _make(secure: bool) -> type[BaseHTTPRequestHandler]:
    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a: object) -> None:
            return

        def _verify(self, token: str) -> bool:
            parts = token.split(".")
            if len(parts) != 3:
                return False
            try:
                header = json.loads(jwt.b64url_decode(parts[0]))
            except Exception:
                return False
            alg = header.get("alg")
            if alg == "none":
                return not secure          # vulnerable server trusts unsigned tokens
            if alg == "HS256":
                expected = jwt.b64url_encode(
                    _hmac.new(_SECRET, f"{parts[0]}.{parts[1]}".encode("ascii"), __import__("hashlib").sha256).digest())
                return _hmac.compare_digest(parts[2], expected)
            return False

        def do_GET(self) -> None:  # noqa: N802
            auth = self.headers.get("Authorization", "")
            token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            ok = self._verify(token)
            body = b"welcome" if ok else b"unauthorized"
            self.send_response(200 if ok else 401)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return _H


class _Srv(ThreadingHTTPServer):
    daemon_threads = True


@contextlib.contextmanager
def _server(secure: bool) -> Iterator[tuple[str, int]]:
    srv = _Srv(("127.0.0.1", 0), _make(secure))
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield "127.0.0.1", srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def _send(host: str, port: int) -> Send:
    def send(req: HttpRequest) -> dict:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        try:
            conn.request(req.method, "/me", headers=dict(req.headers))
            resp = conn.getresponse()
            return {"status": resp.status, "body": resp.read().decode("utf-8", "replace")}
        finally:
            conn.close()
    return send


def test_alg_none_bypass_confirmed_on_vulnerable_server() -> None:
    with _server(secure=False) as (h, p):
        req = HttpRequest(method="GET", url=f"http://{h}:{p}/me",
                          headers=[("Authorization", f"Bearer {_valid_token()}")])
        f = AuditEngine(_send(h, p)).audit(req, checks=(), request_checks=(jwt.JwtNoneCheck(),))
        assert [x for x in f if x.bug_class == "jwt"], "alg:none acceptance not confirmed"
        assert f[0].confirmed_by == "achieved_state"


def test_alg_none_not_confirmed_on_secure_server() -> None:
    with _server(secure=True) as (h, p):
        req = HttpRequest(method="GET", url=f"http://{h}:{p}/me",
                          headers=[("Authorization", f"Bearer {_valid_token()}")])
        f = AuditEngine(_send(h, p)).audit(req, checks=(), request_checks=(jwt.JwtNoneCheck(),))
        assert f == [], "a server that verifies signatures must not be flagged for alg:none"
