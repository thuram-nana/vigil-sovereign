"""repo-connect Slice 2 — the INBOUND GitHub webhook route on the pure-stdlib reverse proxy.

Drives the REAL `make_proxy_server` over loopback HTTP. The route lives in the probe-safe band (pre-auth,
pre-routing, Host-ungated) because a GitHub server-to-server POST carries no session bearer / no
X-Requested-With / an unrelated Origin — the X-Hub-Signature-256 HMAC is the SOLE authenticator. Pins:
  * a valid signed PR delivery → 202 AND one inert envelope spooled to <spool>/incoming/ with the
    normalized coordinates (schema/delivery_id/repo/commit/pr_number);
  * fail-closed on a bad/missing signature (401), an unset secret (503), a missing delivery id (400), a
    non-POST (405) — and NOTHING is spooled in any of those;
  * the ping handshake (and any repo-less event) → 202 with spooled:false;
  * content-addressed idempotency (the identical delivery spools exactly one file);
  * the route is ABSENT (404) when no spool dir is configured;
  * a verified delivery is 202 (spool-only) and NEVER forwarded/spawned — there is no backend, so a forward
    attempt would surface as 502; a 202 proves the handler never left the probe band.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import vigil_integration.uiproxy as uiproxy
from vigil_integration.uiproxy import make_proxy_server

_SECRET = "It's a Secret to Everybody"
_SECRET_ENV = "VIGIL_GH_WEBHOOK_SECRET"


def _serve(tmp_path: Path, *, enabled: bool = True):
    serve_dir = tmp_path / "ui"
    serve_dir.mkdir(parents=True, exist_ok=True)
    spool = tmp_path / "spool"
    srv = make_proxy_server("127.0.0.1", 0, serve_dir,
                            webhook_spool_dir=str(spool) if enabled else None)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    time.sleep(0.05)
    return srv, srv.server_address[1], spool


def _sign(body: bytes, secret: str = _SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _post(port: int, body: bytes, headers: dict) -> tuple[int, dict]:
    req = urllib.request.Request(f"http://127.0.0.1:{port}/webhooks/github", data=body,
                                 method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except ValueError:
            return e.code, {}


def _pr_payload():
    return json.dumps({
        "action": "opened",
        "number": 7,
        "pull_request": {"number": 7, "head": {"sha": "c0ffee1234"}},
        "repository": {"full_name": "acme/widget"},
    }).encode("utf-8")


def _spooled(spool: Path) -> list[dict]:
    incoming = spool / "incoming"
    if not incoming.is_dir():
        return []
    return [json.loads(p.read_text()) for p in incoming.glob("*.json")]


def _hdrs(body: bytes, *, sign: bool = True, delivery: str = "d-1", event: str = "pull_request",
          secret: str = _SECRET) -> dict:
    h = {"Content-Type": "application/json", "X-GitHub-Event": event, "X-GitHub-Delivery": delivery}
    if sign:
        h["X-Hub-Signature-256"] = _sign(body, secret)
    return h


def test_valid_pr_delivery_spools_one_inert_envelope_and_202s(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, spool = _serve(tmp_path)
    try:
        body = _pr_payload()
        status, resp = _post(port, body, _hdrs(body, delivery="D-100"))
        assert status == 202 and resp.get("spooled") is True and resp.get("delivery_id") == "D-100"
        envs = _spooled(spool)
        assert len(envs) == 1
        e = envs[0]
        assert e["schema"] == "vigil.webhook.github.v1"
        assert e["delivery_id"] == "D-100" and e["event"] == "pull_request"
        assert e["repo"] == "github.com/acme/widget" and e["commit"] == "c0ffee1234" and e["pr_number"] == 7
    finally:
        srv.shutdown()


def test_bad_signature_is_401_and_spools_nothing(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, spool = _serve(tmp_path)
    try:
        body = _pr_payload()
        h = _hdrs(body)
        h["X-Hub-Signature-256"] = "sha256=" + "0" * 64          # well-formed but wrong
        status, _ = _post(port, body, h)
        assert status == 401 and _spooled(spool) == []
        # a totally missing signature header is also refused
        h2 = _hdrs(body, sign=False)
        status2, _ = _post(port, body, h2)
        assert status2 == 401 and _spooled(spool) == []
    finally:
        srv.shutdown()


def test_unset_secret_fails_closed_503(monkeypatch, tmp_path):
    monkeypatch.delenv(_SECRET_ENV, raising=False)               # route enabled but NO secret provisioned
    srv, port, spool = _serve(tmp_path)
    try:
        body = _pr_payload()
        status, _ = _post(port, body, _hdrs(body))
        assert status == 503 and _spooled(spool) == []
    finally:
        srv.shutdown()


def test_missing_delivery_id_is_400(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, spool = _serve(tmp_path)
    try:
        body = _pr_payload()
        h = _hdrs(body)
        del h["X-GitHub-Delivery"]                               # signed, but no exactly-once key
        status, _ = _post(port, body, h)
        assert status == 400 and _spooled(spool) == []
    finally:
        srv.shutdown()


def test_ping_event_acks_202_without_spooling(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, spool = _serve(tmp_path)
    try:
        body = json.dumps({"zen": "Keep it logically awesome.", "hook_id": 1}).encode()
        status, resp = _post(port, body, _hdrs(body, event="ping", delivery="ping-1"))
        assert status == 202 and resp.get("spooled") is False and _spooled(spool) == []
    finally:
        srv.shutdown()


def test_non_post_is_405(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, spool = _serve(tmp_path)
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/webhooks/github", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310
                status = r.status
        except urllib.error.HTTPError as e:
            status = e.code
        assert status == 405 and _spooled(spool) == []
    finally:
        srv.shutdown()


def test_identical_delivery_is_idempotent_content_addressed(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, spool = _serve(tmp_path)
    try:
        body = _pr_payload()
        h = _hdrs(body, delivery="D-dup")
        assert _post(port, body, h)[0] == 202
        assert _post(port, body, h)[0] == 202                   # same bytes → same sha256 name
        assert len(_spooled(spool)) == 1                        # spooled exactly once
    finally:
        srv.shutdown()


def test_route_absent_when_not_configured_is_404(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, _spool = _serve(tmp_path, enabled=False)         # no webhook_spool_dir → route not mounted
    try:
        body = _pr_payload()
        status, _ = _post(port, body, _hdrs(body))
        assert status == 404                                    # falls through to static 404, never handled
    finally:
        srv.shutdown()


# ---- red-pen hardening regressions (Slice-2a) ---------------------------------------------------------

def test_non_finite_number_is_422_not_502(monkeypatch, tmp_path):
    # a signed payload with Infinity/NaN (GitHub never sends these) is a protocol error → 422, NOT a 502
    # (the old int(float('inf')) OverflowError), and nothing is spooled.
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, spool = _serve(tmp_path)
    try:
        body = b'{"repository":{"full_name":"a/b"},"pull_request":{"number":Infinity,"head":{"sha":"x"}}}'
        status, _ = _post(port, body, _hdrs(body, delivery="D-inf"))
        assert status == 422 and _spooled(spool) == []
    finally:
        srv.shutdown()


def test_lone_surrogate_in_full_name_is_sanitized_not_502(monkeypatch, tmp_path):
    # a signed payload whose repo full_name carries a lone UTF-16 surrogate must NOT 502 (the old
    # envelope-encode crash); it is sanitized and spooled.
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, spool = _serve(tmp_path)
    try:
        payload = {"repository": {"full_name": "acme/wi\ud800dget"},
                   "pull_request": {"number": 7, "head": {"sha": "c0ffee"}}}
        body = json.dumps(payload).encode("ascii")              # ensure_ascii default → the surrogate is \uXXXX-escaped
        status, resp = _post(port, body, _hdrs(body, delivery="D-surr"))
        assert status == 202 and resp.get("spooled") is True
        envs = _spooled(spool)
        assert len(envs) == 1 and envs[0]["repo"].startswith("github.com/acme/wi")  # sanitized, no crash
    finally:
        srv.shutdown()


def test_branch_delete_push_null_sha_acks_without_spooling(monkeypatch, tmp_path):
    # a push whose `after` is the null SHA (a branch delete) has nothing to scan → 202 spooled:false
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, spool = _serve(tmp_path)
    try:
        body = json.dumps({"repository": {"full_name": "a/b"}, "after": "0" * 40,
                           "deleted": True}).encode()
        status, resp = _post(port, body, _hdrs(body, event="push", delivery="D-del"))
        assert status == 202 and resp.get("spooled") is False and _spooled(spool) == []
    finally:
        srv.shutdown()


def test_slow_incomplete_body_times_out_408(monkeypatch, tmp_path):
    # a slow/incomplete body (promises 1000 bytes, sends 7) must hit the read deadline → 408, never pin the
    # thread indefinitely; nothing is spooled. Uses a short per-test timeout + a raw socket.
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    monkeypatch.setattr(uiproxy, "_WEBHOOK_READ_TIMEOUT_S", 0.5)
    srv, port, spool = _serve(tmp_path)
    try:
        c = socket.create_connection(("127.0.0.1", port), timeout=5)
        c.sendall(b"POST /webhooks/github HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n"
                  b"X-GitHub-Delivery: d\r\nX-Hub-Signature-256: sha256=deadbeef\r\n\r\npartial")
        c.settimeout(5)
        resp = b""
        try:
            while True:
                chunk = c.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except (socket.timeout, OSError):
            pass
        c.close()
        assert b" 408 " in resp.split(b"\r\n", 1)[0], resp[:120]
        assert _spooled(spool) == []
    finally:
        srv.shutdown()
