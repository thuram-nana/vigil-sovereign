"""PRICING G1 — the model gateway at scale, through the real HTTP gateway against FAKE upstreams only (no network):
capacity sized from the provider's rate-limit response headers, the provider-account pool with health + failover
(and no failover of a customer's credit stop), the loss alarm refusing new reservations, the flag-off golden, and a
small deterministic concurrent throughput/fairness load test.
"""
from __future__ import annotations

import datetime as dt
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from vigil_core import generate_keypair
from vigil_core import model_metering as mm
from vigil_core.model_grant import ModelGrant, encode_token, new_grant_id

from sigil import gateway_capacity as gc
from sigil import gateway_loss as gl
from sigil import model_gateway as gw

OWNER = generate_keypair()
OPUS = "claude-opus-4-8"
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))
NOW = float((int(time.time()) // 86_400) * 86_400 + 43_200)
USAGE = {"input_tokens": 1_000, "output_tokens": 500}
BODY = {"model": OPUS, "max_tokens": 1_024, "messages": [{"role": "user", "content": "hi"}]}


def _reset(now, offset):
    return dt.datetime.fromtimestamp(now + offset, dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _rl_headers(now, requests_remaining=1000, tokens_remaining=1_000_000):
    return [("anthropic-ratelimit-requests-limit", "1000"),
            ("anthropic-ratelimit-requests-remaining", str(requests_remaining)),
            ("anthropic-ratelimit-requests-reset", _reset(now, 60)),
            ("anthropic-ratelimit-tokens-limit", "1000000"),
            ("anthropic-ratelimit-tokens-remaining", str(tokens_remaining)),
            ("anthropic-ratelimit-tokens-reset", _reset(now, 60)),
            ("anthropic-ratelimit-input-tokens-limit", "1000000"),
            ("anthropic-ratelimit-input-tokens-remaining", str(tokens_remaining)),
            ("anthropic-ratelimit-input-tokens-reset", _reset(now, 60)),
            ("anthropic-ratelimit-output-tokens-limit", "1000000"),
            ("anthropic-ratelimit-output-tokens-remaining", str(tokens_remaining)),
            ("anthropic-ratelimit-output-tokens-reset", _reset(now, 60)),
            ("anthropic-workspace-id", "wrk_fake"), ("request-id", "req_1")]


class _Up(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        return

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("content-length") or 0)
        self.rfile.read(n)
        srv = self.server
        srv.seen.append({"key": self.headers.get("x-api-key")})
        if self.path.startswith("/v1/messages/count_tokens"):
            return self._send(200, {"input_tokens": 10}, [])
        mode = srv.mode
        if mode in (429, 500, 503):
            extra = [("retry-after", str(srv.retry_after))] if srv.retry_after else []
            return self._send(mode, {"type": "error", "error": {"type": "api_error", "message": "x"}}, extra)
        doc = {"id": "m", "type": "message", "role": "assistant", "model": OPUS, "stop_reason": "end_turn",
               "content": [{"type": "text", "text": "ok"}], "usage": USAGE}
        return self._send(200, doc, _rl_headers(NOW, srv.req_remaining, srv.tok_remaining))

    def _send(self, status, doc, headers):
        raw = json.dumps(doc).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def _serve():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Up)
    srv.daemon_threads = True
    srv.seen, srv.mode, srv.retry_after = [], 200, 0
    srv.req_remaining, srv.tok_remaining = 1000, 1_000_000
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    return srv


def _url(srv):
    return f"http://127.0.0.1:{srv.server_address[1]}"


def _account(aid, srv):
    return gc.ProviderAccount(account_id=aid, api_key=f"sk-{aid}", workspace_id=aid, upstream=_url(srv))


def _grant(**kw):
    base = dict(grant_id=new_grant_id(), org_id="org_a", engagement_slug="cust_a", nonce="n-1", model=OPUS,
                effort="max", cap_nano_usd=10_000_000_000, not_after=NOW + 86_400, issued_at=NOW - 3_600)
    base.update(kw)
    return ModelGrant(**base)


def _tok(g=None, **kw):
    return encode_token(g if g is not None else _grant(**kw), OWNER.private_key_b64)


def _start(tmp_path, accounts=None, *, g1=True, allowance=None, upstream=None, clock=None, **kw):
    clock = clock or {"now": NOW}
    loss_file = tmp_path / "alarms" / gl.LOSS_ALARM_NAME
    cfg = gw.GatewayConfig(api_key="sk-default", owner_pubkey=OWNER.public_key_b64, meter_dir=tmp_path / "meter",
                           upstream=upstream or "http://127.0.0.1:1", opener=NO_PROXY, clock=lambda: clock["now"],
                           g1=g1, accounts=accounts or (), loss_alarm_file=loss_file if g1 else None,
                           allowance=allowance, health_interval_s=0, **kw)
    server, _t = gw.start(cfg)
    server.url = f"http://127.0.0.1:{server.server_address[1]}"
    server.clock = clock
    return server


def _call(server, token, body=None, path="/v1/messages"):
    raw = json.dumps(body or BODY).encode()
    req = urllib.request.Request(server.url + path, data=raw,
                                 headers={"content-type": "application/json", "x-api-key": token,
                                          "anthropic-version": "2023-06-01"}, method="POST")
    try:
        with NO_PROXY.open(req, timeout=20) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _stop(server):
    server.shutdown()
    server.server_close()


# --------------------------------------------------------------------------- flag-off golden
def test_flag_off_builds_no_pool_no_loss_and_works(tmp_path):
    up = _serve()
    try:
        server = _start(tmp_path, g1=False, upstream=_url(up))
        assert server.gateway._pool is None and server.gateway._loss is None   # nothing G1 is built
        assert server.gateway.meter._loss is None
        try:
            assert _call(server, _tok())[0] == 200
            # the meter lines are exactly open+usage, with NO account_id (byte-identical to pre-G1)
            lines = [json.loads(x) for x in (tmp_path / "meter" / f"{_grant().meter_id}.jsonl").read_text().splitlines()]
            assert [ln["kind"] for ln in lines] == ["open", "usage"]
            assert "account_id" not in lines[1]
        finally:
            _stop(server)
    finally:
        up.shutdown(); up.server_close()


# --------------------------------------------------------------------------- capacity from the headers
def test_capacity_is_sized_from_the_response_headers(tmp_path):
    up = _serve()
    up.req_remaining, up.tok_remaining = 5, 1_000_000
    try:
        acc = _account("ws0", up)
        server = _start(tmp_path, [acc], upstream=_url(up))
        try:
            assert _call(server, _tok())[0] == 200
            lane = server.gateway._pool.lane("ws0", gc.model_class(OPUS))
            assert lane.known() and lane.limits()["requests"] == 1000     # sized from the header
        finally:
            _stop(server)
    finally:
        up.shutdown(); up.server_close()


def test_a_request_is_refused_when_the_provider_has_no_requests_left(tmp_path):
    up = _serve()
    try:
        acc = _account("ws0", up)
        server = _start(tmp_path, [acc], upstream=_url(up))
        try:
            assert _call(server, _tok())[0] == 200                       # first request sizes the lane
            # now the provider reports zero requests remaining on the next response headers
            lane = server.gateway._pool.lane("ws0", gc.model_class(OPUS))
            # force the lane empty (as a zero-remaining snapshot would) and confirm a new request is refused
            h = {"anthropic-ratelimit-requests-limit": "1000", "anthropic-ratelimit-requests-remaining": "0",
                 "anthropic-ratelimit-requests-reset": _reset(NOW, 60)}
            lane.observe(gc.parse_rate_limit_headers(h, NOW), NOW)
            status, _h, _b = _call(server, _tok(nonce="n-2"))
            assert status in (429, 529)                                   # no capacity on the only account
        finally:
            _stop(server)
    finally:
        up.shutdown(); up.server_close()


# --------------------------------------------------------------------------- the pool: failover + health
def test_failover_on_a_provider_error_reaches_a_healthy_account(tmp_path):
    bad, good = _serve(), _serve()
    bad.mode = 500
    try:
        server = _start(tmp_path, [_account("bad", bad), _account("good", good)],
                        upstream=_url(bad))
        try:
            # every request succeeds by failing over to the good account; the bad one ends up marked down
            for i in range(4):
                assert _call(server, _tok(nonce=f"n-{i}"))[0] == 200
            assert good.seen                                             # the good account served them
            assert "bad" in server.gateway._pool.down_ids(NOW)          # the bad account was failed over and downed
        finally:
            _stop(server)
    finally:
        for s in (bad, good):
            s.shutdown(); s.server_close()


def test_a_5xx_with_no_healthy_account_left_relays_the_error(tmp_path):
    bad = _serve()
    bad.mode = 503
    try:
        server = _start(tmp_path, [_account("only", bad)], upstream=_url(bad))
        try:
            status, _h, _b = _call(server, _tok())
            assert status == 503                                        # one account, down: the provider error relays
        finally:
            _stop(server)
    finally:
        bad.shutdown(); bad.server_close()


def _until_down(server, aid):
    """Fire requests (round-robin eventually reaches the bad account) until ``aid`` is failed over and down."""
    for i in range(8):
        _call(server, _tok(nonce=f"dn-{i}"))
        if aid in server.gateway._pool.down_ids(NOW):
            return True
    return aid in server.gateway._pool.down_ids(NOW)


def test_the_health_probe_restores_a_recovered_account(tmp_path):
    bad, good = _serve(), _serve()
    bad.mode = 500
    try:
        server = _start(tmp_path, [_account("bad", bad), _account("good", good)], upstream=_url(bad))
        try:
            assert _until_down(server, "bad")                          # it failed over and was marked down
            bad.mode = 200                                              # the account recovers
            server.gateway._probe_down_accounts()                      # the health thread's work, run directly
            assert "bad" not in server.gateway._pool.down_ids(NOW)     # restored to the pool
        finally:
            _stop(server)
    finally:
        for s in (bad, good):
            s.shutdown(); s.server_close()


def test_a_retry_after_on_a_429_paces_the_account(tmp_path):
    up = _serve()
    up.mode, up.retry_after = 429, 30
    other = _serve()
    try:
        # the default down window is short (5s) so only the 30s retry-after can hold the account out past it
        server = _start(tmp_path, [_account("busy", up), _account("spare", other)], upstream=_url(up),
                        account_down_s=5.0)
        try:
            assert _until_down(server, "busy")                          # a 429 fails it over to the spare
            # the retry-after (30s), not the 5s default, sets how long it stays out
            assert "busy" in server.gateway._pool.down_ids(NOW + 29)
            assert "busy" not in server.gateway._pool.down_ids(NOW + 31)
        finally:
            _stop(server)
    finally:
        for s in (up, other):
            s.shutdown(); s.server_close()


# --------------------------------------------------------------------------- the credit stop is terminal
class _Exhausted:
    def allowance_mc(self, grant):
        return 1_000

    def available_credits(self, grant):
        return 0

    def extend(self, grant, credits):
        return {"ok": False, "insufficient": True}


def test_a_credit_stop_is_never_failed_over(tmp_path):
    up0, up1 = _serve(), _serve()
    try:
        server = _start(tmp_path, [_account("ws0", up0), _account("ws1", up1)], upstream=_url(up0),
                        allowance=_Exhausted(), allowance_required=True)
        try:
            from vigil_core.model_grant import STOP_CREDITS_EXHAUSTED, STOP_HEADER
            status, headers, body = _call(server, _tok())
            assert status == 403 and json.loads(body)["error"]["message"] == gw.CREDITS_EXHAUSTED
            assert {k.lower(): v for k, v in headers.items()}.get(STOP_HEADER) == STOP_CREDITS_EXHAUSTED
            assert up0.seen == [] and up1.seen == []                    # nothing reached any provider account
        finally:
            _stop(server)
    finally:
        for s in (up0, up1):
            s.shutdown(); s.server_close()


# --------------------------------------------------------------------------- the loss alarm
def _orphan(meter, g, input_cost):
    """Write a big orphan (pure unconfirmed spend) for launch ``g``, as a dead gateway's leftover would become."""
    out_price = mm.DEFAULT_PRICES[OPUS].output
    rid, reserved, why = meter.reserve(g, 1_024 * out_price, out_price, now=NOW, input_cost=input_cost)
    assert reserved and not why
    st = meter._state(g.meter_id)
    with st.cond:
        with meter._locked(g.meter_id) as fd:
            meter._orphan(fd, st, [rid], now=NOW)
    return reserved


def test_the_loss_alarm_refuses_new_reservations(tmp_path):
    up = _serve()
    try:
        server = _start(tmp_path, [_account("ws0", up)], upstream=_url(up))
        meter = server.gateway.meter
        try:
            assert _call(server, _tok())[0] == 200                     # some CONFIRMED provider spend
            confirmed, _unconf = meter.day_split(NOW)
            # a big crash leftover (orphan) is pure UNCONFIRMED spend, well past 2% of the day's confirmed spend
            _orphan(meter, _grant(nonce="orphan"), input_cost=max(1, confirmed) + 1_000_000)
            assert server.gateway._loss.tripped(NOW)                   # the meter's own day split breaches 2%
            before = len(up.seen)
            status, _h, _b = _call(server, _tok(nonce="n-2"))
            assert status == 529                                       # new reservations refused
            assert len(up.seen) == before                             # nothing new reached the provider
            assert gl.read_alarm(tmp_path)["tripped"] is True         # the durable alarm file is present for doctor
            # acknowledging it (once reconciled) resumes runs for the day
            server.gateway._loss.acknowledge("owner", now=NOW)
            assert _call(server, _tok(nonce="n-3"))[0] == 200
            assert gl.read_alarm(tmp_path) is None                    # the alarm file is cleared
        finally:
            _stop(server)
    finally:
        up.shutdown(); up.server_close()


def test_an_orphan_grows_the_days_unconfirmed_spend_in_the_loss_ledger(tmp_path):
    # a crash leftover (an orphan) is pure unconfirmed spend: it must move the loss ledger's unconfirmed total
    up = _serve()
    try:
        server = _start(tmp_path, [_account("ws0", up)], upstream=_url(up))
        try:
            g = _grant()
            meter = server.gateway.meter
            # write an open line as a DEAD process would, then load the launch so the startup/orphan path records it
            rid, reserved, why = meter.reserve(g, 1_024 * mm.DEFAULT_PRICES[OPUS].output, mm.DEFAULT_PRICES[OPUS].output,
                                               now=NOW, input_cost=5_000)
            assert reserved and not why
            conf0, unconf0 = meter.day_split(NOW)
            # orphan it (its reservation becomes unconfirmed spend)
            st = meter._state(g.meter_id)
            with st.cond:
                with meter._locked(g.meter_id) as fd:
                    meter._orphan(fd, st, [rid], now=NOW)
            conf1, unconf1 = meter.day_split(NOW)
            assert unconf1 == unconf0 + reserved and conf1 == conf0
        finally:
            _stop(server)
    finally:
        up.shutdown(); up.server_close()


# --------------------------------------------------------------------------- config_from_env wiring
def test_config_from_env_builds_the_pool_and_loss_file(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_GATEWAY_G1", "1")
    monkeypatch.setenv("SIGIL_ANTHROPIC_API_KEY", "sk-default")
    monkeypatch.setenv("VIGIL_GATEWAY_POOL", json.dumps([{"id": "a", "key_env": "KA"}, {"id": "b", "key_env": "KB"}]))
    monkeypatch.setenv("KA", "sk-a")
    monkeypatch.setenv("KB", "sk-b")
    from sigil.governor import identity as _id
    monkeypatch.setattr(_id, "owner_pubkey", lambda: OWNER.public_key_b64)
    cfg = gw.config_from_env()
    assert cfg.g1 is True
    assert [a.account_id for a in cfg.accounts] == ["a", "b"]
    assert cfg.accounts[0].api_key == "sk-a" and cfg.accounts[1].api_key == "sk-b"
    assert cfg.loss_alarm_file is not None and cfg.loss_alarm_file.name == gl.LOSS_ALARM_NAME


def test_config_from_env_g1_off_has_no_pool(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_GATEWAY_G1", raising=False)
    monkeypatch.setenv("SIGIL_ANTHROPIC_API_KEY", "sk-default")
    from sigil.governor import identity as _id
    monkeypatch.setattr(_id, "owner_pubkey", lambda: OWNER.public_key_b64)
    cfg = gw.config_from_env()
    assert cfg.g1 is False and tuple(cfg.accounts) == () and cfg.loss_alarm_file is None


# --------------------------------------------------------------------------- a small concurrent load test (fakes only)
def test_concurrent_requests_across_tenants_all_complete(tmp_path):
    up0, up1 = _serve(), _serve()
    try:
        server = _start(tmp_path, [_account("ws0", up0), _account("ws1", up1)], upstream=_url(up0),
                        tenant_concurrency=8, global_concurrency=16)
        try:
            results: list = []
            lock = threading.Lock()

            def fire(org, i):
                s = _call(server, _tok(org_id=org, engagement_slug=f"cust_{org}", nonce=f"n-{org}-{i}"))[0]
                with lock:
                    results.append(s)

            threads = [threading.Thread(target=fire, args=(org, i))
                       for org in ("t1", "t2", "t3") for i in range(6)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(20)
            assert len(results) == 18 and all(s == 200 for s in results)
            assert len(up0.seen) + len(up1.seen) >= 18        # served across the pool
        finally:
            _stop(server)
    finally:
        for s in (up0, up1):
            s.shutdown(); s.server_close()
