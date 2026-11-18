"""R3 — the Red-Pen GitHub App webhook route (/webhooks/github-app) on the pure-stdlib reverse proxy.

Drives the REAL `make_proxy_server` over loopback HTTP, like ``test_uiproxy_webhook.py``. Pins:
  * flag ON: a signed App ``pull_request`` delivery → 202 and ONE inert Red-Pen envelope in <spool>/redpen/incoming/
    (schema / delivery_id / event / action / kind / repo / commit / pr_number — coordinates only, no payload body,
    no secret), and NOTHING in the repo-connect <spool>/incoming/;
  * flag ON: ``installation`` / ``installation_repositories`` → an inert connect/disconnect SYNC envelope
    (installation_id + repos); the App's ping and a bare push ack 202 WITHOUT spooling;
  * the App route keeps every fail-closed refusal of the repo-connect route (bad signature 401, unset secret 503);
  * flag OFF: /webhooks/github-app is ABSENT (404) and nothing is spooled anywhere; no spool dir ⇒ 404 even with the
    flag on;
  * BYTE-IDENTICAL: /webhooks/github spools the same bytes and answers the same body with the flag on or off, and
    never writes under redpen/ — enabling Red-Pen never changes what the repo-connect drain receives.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from vigil_integration.uiproxy import make_proxy_server

_SECRET = "It's a Secret to Everybody"
_SECRET_ENV = "VIGIL_GH_WEBHOOK_SECRET"
_FLAG = "VIGIL_REDPEN_ENABLED"
_APP = "/webhooks/github-app"


def _serve(tmp_path: Path, *, enabled: bool = True):
    serve_dir = tmp_path / "ui"
    serve_dir.mkdir(parents=True, exist_ok=True)
    spool = tmp_path / "spool"
    srv = make_proxy_server("127.0.0.1", 0, serve_dir, webhook_spool_dir=str(spool) if enabled else None)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    time.sleep(0.05)
    return srv, srv.server_address[1], spool


def _sign(body: bytes, secret: str = _SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _post(port: int, path: str, body: bytes, headers: dict) -> "tuple[int, dict]":
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except ValueError:
            return e.code, {}


def _hdrs(body: bytes, *, delivery: str = "d-1", event: str = "pull_request", sign: bool = True) -> dict:
    h = {"Content-Type": "application/json", "X-GitHub-Event": event, "X-GitHub-Delivery": delivery}
    if sign:
        h["X-Hub-Signature-256"] = _sign(body)
    return h


def _pr_body(action: str = "opened") -> bytes:
    return json.dumps({"action": action, "number": 7, "installation": {"id": 42},
                       "pull_request": {"number": 7, "head": {"sha": "c0ffee1234"}},
                       "repository": {"full_name": "acme/widget"}}).encode("utf-8")


def _files(d: Path) -> "list[dict]":
    return [json.loads(p.read_text()) for p in sorted(d.glob("*.json"))] if d.is_dir() else []


def _redpen(spool: Path) -> "list[dict]":
    return _files(spool / "redpen" / "incoming")


def _repo_connect(spool: Path) -> "list[dict]":
    return _files(spool / "incoming")


# ---- flag ON: the App route spools inert Red-Pen envelopes ---------------------------------------------

def test_flag_on_app_pr_delivery_spools_one_inert_redpen_envelope_only(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    monkeypatch.setenv(_FLAG, "1")
    srv, port, spool = _serve(tmp_path)
    try:
        body = _pr_body("synchronize")
        status, resp = _post(port, _APP, body, _hdrs(body, delivery="D-100"))
        assert status == 202 and resp.get("spooled") is True and resp.get("kind") == "pr"
        envs = _redpen(spool)
        assert len(envs) == 1
        assert envs[0] == {"schema": "vigil.webhook.github.redpen.v1", "delivery_id": "D-100",
                           "event": "pull_request", "action": "synchronize", "kind": "pr",
                           "repo": "github.com/acme/widget", "commit": "c0ffee1234", "pr_number": 7}
        assert _repo_connect(spool) == []                       # the repo-connect drain never sees an App event
    finally:
        srv.shutdown()


def test_flag_on_installation_event_spools_a_connect_sync_signal(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    monkeypatch.setenv(_FLAG, "true")
    srv, port, spool = _serve(tmp_path)
    try:
        body = json.dumps({"action": "created", "installation": {"id": 4242},
                           "repositories": [{"full_name": "acme/widget"}, {"full_name": "acme/gadget"}]}).encode()
        status, resp = _post(port, _APP, body, _hdrs(body, delivery="I-1", event="installation"))
        assert status == 202 and resp.get("kind") == "installation"
        (env,) = _redpen(spool)
        assert env["kind"] == "installation" and env["action"] == "created" and env["installation_id"] == 4242
        assert env["repos"] == ["github.com/acme/widget", "github.com/acme/gadget"]
        assert "repo" not in env and "pr_number" not in env       # a sync signal is never a review job
    finally:
        srv.shutdown()


def test_flag_on_installation_repositories_removed_spools_a_disconnect_sync_signal(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    monkeypatch.setenv(_FLAG, "on")
    srv, port, spool = _serve(tmp_path)
    try:
        body = json.dumps({"action": "removed", "installation": {"id": 7},
                           "repositories_added": [], "repositories_removed": [{"full_name": "acme/widget"}]}).encode()
        status, _ = _post(port, _APP, body, _hdrs(body, delivery="I-2", event="installation_repositories"))
        assert status == 202
        (env,) = _redpen(spool)
        assert env["action"] == "removed" and env["repos"] == ["github.com/acme/widget"]
    finally:
        srv.shutdown()


def test_flag_on_app_ping_and_bare_push_ack_without_spooling(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    monkeypatch.setenv(_FLAG, "1")
    srv, port, spool = _serve(tmp_path)
    try:
        ping = json.dumps({"zen": "Keep it logically awesome.", "hook_id": 1}).encode()
        assert _post(port, _APP, ping, _hdrs(ping, delivery="p", event="ping")) == \
            (202, {"ok": True, "spooled": False, "event": "ping"})
        push = json.dumps({"repository": {"full_name": "acme/widget"}, "after": "ab" * 20}).encode()
        status, resp = _post(port, _APP, push, _hdrs(push, delivery="u", event="push"))
        assert status == 202 and resp.get("spooled") is False    # a bare push is not a Red-Pen PR trigger
        assert _redpen(spool) == [] and _repo_connect(spool) == []
    finally:
        srv.shutdown()


def test_flag_on_app_route_keeps_every_fail_closed_refusal(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    monkeypatch.setenv(_FLAG, "1")
    srv, port, spool = _serve(tmp_path)
    try:
        body = _pr_body()
        bad = _hdrs(body)
        bad["X-Hub-Signature-256"] = "sha256=" + "0" * 64          # well-formed but wrong
        assert _post(port, _APP, body, bad)[0] == 401
        assert _post(port, _APP, body, _hdrs(body, sign=False))[0] == 401
        no_delivery = _hdrs(body)
        del no_delivery["X-GitHub-Delivery"]
        assert _post(port, _APP, body, no_delivery)[0] == 400
        monkeypatch.delenv(_SECRET_ENV)                             # route mounted, no secret provisioned
        assert _post(port, _APP, body, _hdrs(body))[0] == 503
        assert _redpen(spool) == []
    finally:
        srv.shutdown()


def test_identical_app_delivery_is_idempotent(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    monkeypatch.setenv(_FLAG, "1")
    srv, port, spool = _serve(tmp_path)
    try:
        body = _pr_body()
        h = _hdrs(body, delivery="D-dup")
        assert _post(port, _APP, body, h)[0] == 202
        assert _post(port, _APP, body, h)[0] == 202
        assert len(_redpen(spool)) == 1                             # content-addressed: spooled exactly once
    finally:
        srv.shutdown()


# ---- flag OFF: the App route is absent; /webhooks/github is byte-identical -----------------------------

def test_flag_off_app_route_is_absent_404_and_spools_nothing(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    monkeypatch.delenv(_FLAG, raising=False)
    srv, port, spool = _serve(tmp_path)
    try:
        body = _pr_body()
        status, _ = _post(port, _APP, body, _hdrs(body))
        assert status == 404                                        # not mounted: the usual 404, as before Red-Pen
        assert _redpen(spool) == [] and _repo_connect(spool) == []
        # a non-affirmative value is OFF too
        monkeypatch.setenv(_FLAG, "0")
        assert _post(port, _APP, body, _hdrs(body))[0] == 404
    finally:
        srv.shutdown()


def _raw_post(port: int, path: str, body: bytes, headers: dict) -> "tuple[int, str, bytes]":
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, r.headers.get("Content-Type", ""), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", ""), e.read()


def test_flag_off_the_app_path_is_indistinguishable_from_a_never_mounted_path(monkeypatch, tmp_path):
    # ABSENT, not merely refused: with the flag off the request never enters the webhook handler — status,
    # content type and body are exactly those of a path that was never mounted (the pre-Red-Pen proxy).
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    monkeypatch.delenv(_FLAG, raising=False)
    srv, port, spool = _serve(tmp_path)
    try:
        body = _pr_body()
        app = _raw_post(port, _APP, body, _hdrs(body))
        never = _raw_post(port, "/webhooks/never-mounted", body, _hdrs(body))
        assert app[0] == 404 and app == never
        assert _redpen(spool) == [] and _repo_connect(spool) == []
    finally:
        srv.shutdown()


def test_a_flag_flipped_off_between_dispatch_and_spool_writes_nothing(monkeypatch, tmp_path):
    # the handler RE-CHECKS the flag before spooling (defence in depth): the mount saw it ON, the re-check sees it
    # OFF (an operator flipped it mid-request) ⇒ 404 and nothing is written under redpen/.
    import vigil_integration.uiproxy as uiproxy
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    answers = iter([True, False])
    monkeypatch.setattr(uiproxy, "_redpen_webhook_enabled", lambda: next(answers, False))
    srv, port, spool = _serve(tmp_path)
    try:
        body = _pr_body()
        status, _ = _post(port, _APP, body, _hdrs(body))
        assert status == 404 and _redpen(spool) == [] and _repo_connect(spool) == []
    finally:
        srv.shutdown()


def test_app_route_absent_404_without_a_spool_dir_even_with_the_flag_on(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    monkeypatch.setenv(_FLAG, "1")
    srv, port, _spool = _serve(tmp_path, enabled=False)
    try:
        body = _pr_body()
        assert _post(port, _APP, body, _hdrs(body))[0] == 404
    finally:
        srv.shutdown()


def _repo_connect_exchange(monkeypatch, tmp_path: Path, flag: "str | None") -> "tuple[int, dict, bytes, list]":
    """One signed PR delivery to the REPO-CONNECT route; returns (status, response, spooled bytes, redpen files)."""
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    if flag is None:
        monkeypatch.delenv(_FLAG, raising=False)
    else:
        monkeypatch.setenv(_FLAG, flag)
    srv, port, spool = _serve(tmp_path)
    try:
        body = _pr_body()
        status, resp = _post(port, "/webhooks/github", body, _hdrs(body, delivery="D-same"))
        (f,) = sorted((spool / "incoming").glob("*.json"))
        return status, resp, f.read_bytes(), _redpen(spool)
    finally:
        srv.shutdown()


def test_the_repo_connect_route_is_byte_identical_with_the_flag_on_or_off(monkeypatch, tmp_path):
    off = _repo_connect_exchange(monkeypatch, tmp_path / "off", None)
    on = _repo_connect_exchange(monkeypatch, tmp_path / "on", "1")
    assert off[0] == on[0] == 202 and off[1] == on[1]               # same status + same response body
    assert off[2] == on[2]                                           # the SAME spooled bytes
    assert set(json.loads(on[2])) == {"schema", "delivery_id", "event", "repo", "commit", "pr_number"}
    assert off[3] == on[3] == []                                     # never anything under redpen/
