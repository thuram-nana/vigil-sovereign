"""W4 — the customer-launch worker PINGS the model gateway while a METERED run executes; the gateway bills the time.

The keyless worker never reports a number: it only sends empty, grant-authenticated pings to the loopback gateway's
worker-time endpoint, and the SOVEREIGN gateway measures the time between them (``sigil.model_gateway``). Pins:
  * a FLAT run (no model grant) never pings — no thread, no network (byte-identical);
  * a metered run pings at START (opens the first slot) and once at the END (commits the last slot), and
    periodically in between, always to its grant's gateway with its grant as the key;
  * a TERMINAL refusal (a bad / closed / exhausted grant, or a gateway without the endpoint) stops the pings — the
    run itself carries on and pauses through the model path (W3); a transient error never stops them;
  * the real ping is an EMPTY POST to ``/v1/vigil/worker/heartbeat`` with the grant in ``x-api-key``, through no proxy.

Mutation-verify targets (each neuter reds a NAMED test here):
  * ping a flat run                          -> test_the_heartbeat_scope_is_a_no_op_for_a_flat_run
  * drop the final (commit) ping             -> test_a_metered_run_pings_at_start_and_at_the_end
  * keep pinging after a terminal refusal    -> test_a_terminal_mid_run_refusal_stops_the_pings
  * let a transient error stop the pings     -> test_a_transient_error_never_stops_the_heartbeat
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from vigil_integration.jobs import engage_worker as ew

GATEWAY = "http://127.0.0.1:8742"
TOKEN = "vmg1.grant-token"


class _Bundle:
    token = TOKEN
    gateway_url = GATEWAY


class _Recorder:
    """A fake ``post``: records each ping and answers from ``codes`` (then 200)."""

    def __init__(self, codes=(), *, raise_on=()):
        self.calls: list = []
        self._codes = list(codes)
        self._raise_on = set(raise_on)
        self.lock = threading.Lock()
        self.event = threading.Event()
        self.want = 0

    def __call__(self, gateway, token):
        with self.lock:
            self.calls.append((gateway, token))
            n = len(self.calls)
            if self.want and n >= self.want:
                self.event.set()
            if n in self._raise_on:
                raise OSError("connection reset")
            return self._codes.pop(0) if self._codes else 200


# ------------------------------------------------------------------------------------------------- the scope (unit)

def test_the_heartbeat_scope_is_a_no_op_for_a_flat_run():
    rec = _Recorder()
    ran = []
    with ew._worker_heartbeat_scope(None, post=rec, interval_s=0.01):
        ran.append(True)
    assert ran == [True] and rec.calls == []


def test_a_malformed_bundle_never_pings():
    class _NoToken:
        token = ""
        gateway_url = GATEWAY

    rec = _Recorder()
    with ew._worker_heartbeat_scope(_NoToken(), post=rec, interval_s=0.01):
        pass
    assert rec.calls == []


def test_a_metered_run_pings_at_start_and_at_the_end():
    rec = _Recorder()
    with ew._worker_heartbeat_scope(_Bundle(), post=rec, interval_s=3_600):   # no periodic ping in this short run
        assert rec.calls == [(GATEWAY, TOKEN)]                                  # the start ping opened the first slot
    assert rec.calls == [(GATEWAY, TOKEN), (GATEWAY, TOKEN)]                    # the end ping committed the last slot


def test_the_heartbeat_pings_periodically_while_running():
    rec = _Recorder()
    rec.want = 3                                       # the start ping + at least two periodic ones
    with ew._worker_heartbeat_scope(_Bundle(), post=rec, interval_s=0.01):
        assert rec.event.wait(10.0), "the heartbeat never pinged periodically"
    assert len(rec.calls) >= 4 and set(rec.calls) == {(GATEWAY, TOKEN)}      # ... and the final ping


def test_a_terminal_first_refusal_stops_the_heartbeat_but_not_the_run():
    rec = _Recorder(codes=[403])
    ran = []
    with ew._worker_heartbeat_scope(_Bundle(), post=rec, interval_s=0.01):
        ran.append(True)
    assert ran == [True] and rec.calls == [(GATEWAY, TOKEN)]                   # no thread, no final ping


@pytest.mark.parametrize("code", sorted(ew._HEARTBEAT_STOP_CODES))
def test_a_terminal_mid_run_refusal_stops_the_pings(code):
    rec = _Recorder(codes=[200, code])                 # the start ping is fine; the first periodic one is refused
    rec.want = 2
    with ew._worker_heartbeat_scope(_Bundle(), post=rec, interval_s=0.01):
        assert rec.event.wait(10.0)
        threading.Event().wait(0.1)                    # many intervals: a heartbeat that kept going would ping again
    assert len(rec.calls) == 2                         # start + the refused one; no more, and no final ping


def test_a_transient_error_never_stops_the_heartbeat():
    rec = _Recorder(codes=[200, 0, 529, 429], raise_on={5})   # a connection error, busy answers, then an exception
    rec.want = 7
    with ew._worker_heartbeat_scope(_Bundle(), post=rec, interval_s=0.01):
        assert rec.event.wait(10.0), "a transient error stopped the heartbeat"
    assert len(rec.calls) >= 8                         # it kept pinging through all of them, then the final ping


def test_the_interval_setting(monkeypatch):
    monkeypatch.delenv(ew._WORKER_HEARTBEAT_INTERVAL_ENV, raising=False)
    assert ew._worker_heartbeat_interval_s() == 30.0
    for raw, want in (("5", 5.0), ("0.5", 30.0), ("abc", 30.0), ("", 30.0)):
        monkeypatch.setenv(ew._WORKER_HEARTBEAT_INTERVAL_ENV, raw)
        assert ew._worker_heartbeat_interval_s() == want, raw


# ------------------------------------------------------------------------------- the real ping (loopback server only)

class _Gw(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("content-length") or 0)
        self.server.seen.append({"path": self.path, "key": self.headers.get("x-api-key"),
                                 "body": self.rfile.read(n) if n else b""})
        raw = json.dumps({"ok": True}).encode()
        self.send_response(self.server.code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def _serve(code):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Gw)
    srv.seen, srv.code = [], code
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.mark.parametrize("code", [200, 403])
def test_the_real_ping_is_an_empty_grant_authenticated_post(code):
    srv = _serve(code)
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}"
        assert ew._post_heartbeat(url, TOKEN) == code
        (seen,) = srv.seen
        assert seen == {"path": "/v1/vigil/worker/heartbeat", "key": TOKEN, "body": b""}   # no number is sent
    finally:
        srv.shutdown()
        srv.server_close()


def test_the_real_ping_reports_an_unreachable_gateway_as_transient():
    srv = _serve(200)
    port = srv.server_address[1]
    srv.shutdown()
    srv.server_close()                                  # nothing listens on the port any more
    assert ew._post_heartbeat(f"http://127.0.0.1:{port}", TOKEN, timeout=2.0) == 0


# --------------------------------------------------------------------------------- the worker (needs the offense leg)

def test_the_worker_pings_for_a_metered_run_and_never_for_a_flat_one(monkeypatch):
    pytest.importorskip("framework.v2.authority.store", reason="framework (offense) not importable in this leg")
    import datetime as _dt
    import tempfile
    from datetime import timezone

    from framework.v2.authority import store as authz_store
    from framework.v2.authority.models import EngagementAuthority
    from vigil_core import (AuthorizerKey, CreditLaunchLease, TrustRoot, generate_keypair,
                            sign_credit_launch_lease)
    from vigil_core.model_grant import ModelGrant, encode_token
    from vigil_integration.jobs.launch_trigger import launch_delivery_id
    from vigil_integration.jobs.model import SecurityJob
    from vigil_integration.live.credit_lease_broker import write_credit_lease
    from vigil_integration.live.model_grant_broker import write_model_grant
    from vigil_core.model_metering import DEFAULT_RUN_MODEL

    slug, host, org = "cust_w4hb", "apme.cm", "org_a"
    owner = generate_keypair()
    root = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)])
    t = _dt.datetime.fromtimestamp(1000.0, tz=timezone.utc)

    def _base(*, metered):
        base = tempfile.mkdtemp()
        doc = CreditLaunchLease(engagement_slug=slug, org_id=org, scope_host=host, units_reserved=10,
                                not_before=t - _dt.timedelta(hours=1), not_after=t + _dt.timedelta(hours=8),
                                nonce="n1", issued_at=1000.0)
        write_credit_lease(base, slug, sign_credit_launch_lease(doc, {"owner": owner.private_key_b64}), root)
        if metered:
            g = ModelGrant(grant_id="0" * 32, org_id=org, engagement_slug=slug, nonce="n1", model=DEFAULT_RUN_MODEL,
                           effort="high", cap_nano_usd=1_000_000, not_after=4600.0, issued_at=1000.0)
            write_model_grant(base, slug, "n1", encode_token(g, owner.private_key_b64), GATEWAY)
        return base

    monkeypatch.setattr(authz_store, "load_authority_root", lambda path=None: root)
    monkeypatch.setattr(authz_store, "load_verified_authority", lambda s, r, path=None: EngagementAuthority(
        engagement_slug=s, environment="twin", scope=[host], issued_by="customer:org_a",
        not_before=t - _dt.timedelta(hours=1), not_after=t + _dt.timedelta(hours=8)))
    monkeypatch.setattr("vigil_integration.jobs.completion_signal.emit_completion_signal", lambda **kw: None)
    job = SecurityJob.normalize(source="api", repo=host, engagement_slug=slug, tenant_id=org, commit="n1",
                                delivery_id=launch_delivery_id(slug, "n1"),
                                extra={"seed_url": f"https://{host}", "host": host, "nonce": "n1", "org_id": org})
    for metered in (True, False):
        rec = _Recorder()
        w = ew.make_engage_worker(trust_root=root, base_dir=_base(metered=metered), run=lambda **kw: {"facts": 0},
                                  signers=[("k", "v")], heartbeat_post=rec, heartbeat_interval_s=3_600)
        w(job)
        if metered:
            assert len(rec.calls) == 2 and {c[0] for c in rec.calls} == {GATEWAY}   # start + end, to its gateway
            assert all(c[1].startswith("vmg1.") for c in rec.calls)                 # with its grant as the key
        else:
            assert rec.calls == []                                                   # a flat run never pings
