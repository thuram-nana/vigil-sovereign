"""PRICING M1b — the sovereign model gateway (``sigil.model_gateway``), against a fake Anthropic upstream.

What it proves (design §5.1), against a caller that sends whatever it likes:
  * the grant is the only credential: a bad / foreign / expired / settled grant is refused before anything is
    forwarded; the provider key is added by the gateway, never follows a redirect, never travels over plain http
    to a non-loopback host; the client's token never reaches the provider;
  * the request is an ALLOWLIST: the grant's model only; unknown fields, server-executed tools (web search, code
    execution, the advisor, MCP), tools naming a model, compaction, PDFs and file references are refused; unknown
    betas are dropped; effort = the grant's; thinking adaptive; sampling, fast mode, US-only inference, the priority
    tier and 1-hour cache writes can never reach the provider; each tenant gets its own prompt-cache prefix;
  * the budget is enforced BEFORE spending: the request's input (a byte bound, or the provider's count when the
    byte bound does not fit) and its output are reserved; ``max_tokens`` is lowered; a spent cap is a 403, a cap
    held by requests in flight is a retryable 429; concurrent reservations cannot jointly pass the cap;
  * the meter is exact for a JSON body and for a stream (cumulative ``message_delta`` usage), including a stream
    whose client disconnects or stops reading; an unreadable 200 (or one reporting unpriced server-side steps) is
    charged its reservation; a cut-off stream is held as unconfirmed spend; a stream that never started is free;
  * the meter file is write-ahead and hash-chained: a crash between the call and its record leaves an orphan that
    counts against the cap; a torn line is repaired; tampering is detected; an unwritable meter refuses the
    request; a close from another process stops the run and waits for requests in flight.

Mutation-verify targets: the runner's list lives with the PR (each guard above is broken in turn and a NAMED test
here goes red).
"""
from __future__ import annotations

import fcntl
import http.client
import json
import os
import socket
import struct
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from vigil_core import generate_keypair
from vigil_core import model_metering as mm
from vigil_core.model_grant import ModelGrant, encode_token, new_grant_id

from sigil import model_gateway as gw

OWNER = generate_keypair()
OTHER = generate_keypair()
OPUS = "claude-opus-4-8"
PROVIDER_KEY = "sk-ant-provider-secret"
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))

USAGE = {"input_tokens": 1_000, "output_tokens": 2_000, "cache_read_input_tokens": 10_000,
         "cache_creation_input_tokens": 4_000,
         "cache_creation": {"ephemeral_5m_input_tokens": 3_000, "ephemeral_1h_input_tokens": 1_000}}
USAGE_COST = 88_750_000                       # the hand-worked cost in test_model_metering
# noon UTC today: the daily ceiling seeds a restarted gateway from meter files by their modification day, which is
# real wall-clock time, so the test clock must share the real day (in production both are the same clock)
NOW = float((int(time.time()) // 86_400) * 86_400 + 43_200)


ROW = mm.DEFAULT_PRICES[OPUS]
OUT = ROW.output
RATE = max(ROW.input, ROW.cache_write_5m)     # what one reserved input token costs


def _in(body) -> int:
    """The input reservation the gateway takes for ``body`` sent by :func:`_call` (the byte bound)."""
    return (len(json.dumps(body).encode()) + 1_000) * RATE


# ---------------------------------------------------------------------------------------------------------------
# A fake Anthropic
# ---------------------------------------------------------------------------------------------------------------

def _sse(events):
    out = b""
    for e in events:
        out += f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode()
    return out


STREAM_EVENTS = [
    {"type": "message_start", "message": {"id": "msg_s", "type": "message", "role": "assistant", "content": [],
                                          "model": OPUS, "usage": {**USAGE, "output_tokens": 1}}},
    {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
    {"type": "ping"},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "hello"}},
    {"type": "message_delta", "delta": {"stop_reason": None}, "usage": {"output_tokens": 900}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": " world"}},
    {"type": "content_block_stop", "index": 0},
    # the documented final delta: cumulative counts, the cache-write TOTAL without its TTL split
    {"type": "message_delta", "delta": {"stop_reason": "end_turn"},
     "usage": {"output_tokens": 2_000, "cache_creation_input_tokens": 4_000}},
    {"type": "message_stop"},
]


class _Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        return

    def _json(self, status, doc, headers=()):
        raw = json.dumps(doc).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802 — only ever reached by a FOLLOWED redirect, which must never happen
        self.server.seen.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                                 "body": None})
        self._json(200, {"leaked": True})

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("content-length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        srv = self.server
        srv.seen.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
        mode = srv.mode
        if self.path.startswith("/v1/messages/count_tokens"):
            if srv.count is None:
                return self._json(500, {"type": "error", "error": {"type": "api_error", "message": "no count"}})
            return self._json(200, {"input_tokens": srv.count})
        if mode == "error":
            if srv.delay:
                time.sleep(srv.delay)
            return self._json(429, {"type": "error", "error": {"type": "rate_limit_error", "message": "slow down"}},
                              [("retry-after", "7")])
        if mode == "redirect":
            self.send_response(302)
            self.send_header("location", srv.redirect_to)
            self.send_header("content-length", "0")
            self.end_headers()
            return None
        if body.get("stream"):
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("request-id", "req_stream")
            self.send_header("connection", "close")
            self.end_headers()
            try:
                for e in srv.events:
                    self.wfile.write(_sse([e]) if isinstance(e, dict) else e)
                    self.wfile.flush()
                    if srv.delay:
                        time.sleep(srv.delay)
            finally:
                srv.stream_done.set()
            return None
        if srv.delay:
            time.sleep(srv.delay)
        doc = {"id": "msg_1", "type": "message", "role": "assistant", "model": OPUS, "stop_reason": "end_turn",
               "content": [{"type": "text", "text": "ok"}]}
        if mode == "json":
            doc["usage"] = USAGE
        elif mode == "deep":                  # valid JSON nested past any parser's recursion limit
            raw = b'{"id":"m","usage":' + b"[" * 200_000 + b"]" * 200_000 + b"}"
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return None
        elif mode == "iterations":            # a server-side step (an advisor, a compaction pass) billed on top
            doc["usage"] = {**USAGE, "iterations": [{"type": "message", **USAGE},
                                                    {"type": "advisor_message", "model": "claude-fable-5-2",
                                                     "input_tokens": 500_000, "output_tokens": 20_000}]}
        return self._json(200, doc, [("request-id", "req_json")])


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    srv.seen, srv.mode, srv.delay, srv.stream_done = [], "json", 0.0, threading.Event()
    srv.events, srv.count, srv.redirect_to = STREAM_EVENTS, None, ""
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    return srv


@pytest.fixture()
def upstream():
    srv = _serve(_Upstream)
    yield srv
    srv.shutdown()
    srv.server_close()


def _start(upstream, meter_dir, clock=None, **kw):
    clock = clock if clock is not None else {"now": NOW}
    cfg = gw.GatewayConfig(api_key=PROVIDER_KEY, owner_pubkey=OWNER.public_key_b64, meter_dir=meter_dir,
                           upstream=f"http://127.0.0.1:{upstream.server_address[1]}", opener=NO_PROXY,
                           clock=lambda: clock["now"], **kw)
    server, _t = gw.start(cfg)
    server.clock = clock
    server.url = f"http://127.0.0.1:{server.server_address[1]}"
    return server


def _stop(server):
    server.shutdown()
    server.server_close()


@pytest.fixture()
def gateway(upstream, tmp_path):
    server = _start(upstream, tmp_path / "meter")
    yield server
    _stop(server)


def _grant(**kw) -> ModelGrant:
    base = dict(grant_id=new_grant_id(), org_id="org_acme", engagement_slug="cust_abc", nonce="n-1", model=OPUS,
                effort="max", cap_nano_usd=10_000_000_000, not_after=NOW + 86_400, issued_at=NOW - 3_600)
    base.update(kw)
    return ModelGrant(**base)


def _tok(g=None, **kw) -> str:
    return encode_token(g if g is not None else _grant(**kw), OWNER.private_key_b64)


def _call(server, body, token, *, path="/v1/messages", headers=None):
    raw = json.dumps(body).encode() if not isinstance(body, bytes) else body
    h = {"content-type": "application/json", "x-api-key": token, "anthropic-version": "2023-06-01", **(headers or {})}
    req = urllib.request.Request(server.url + path, data=raw, headers=h, method="POST")
    try:
        with NO_PROXY.open(req, timeout=20) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _raw_post(server, token, raw, extra=b""):
    """Open a socket and send a POST by hand; returns the socket (the caller reads or abandons it)."""
    sock = socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=10)
    sock.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\ncontent-type: application/json\r\n"
                 + f"x-api-key: {token}\r\n".encode() + extra + f"content-length: {len(raw)}\r\n\r\n".encode() + raw)
    return sock


def _err(raw):
    doc = json.loads(raw)
    assert doc["type"] == "error"
    return doc["error"]["type"], doc["error"]["message"]


def _wait(cond, seconds=10.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return bool(cond())


def _sent(upstream):
    """The model requests the provider saw (not the gateway's own count_tokens look-ups)."""
    return [x for x in upstream.seen if x["path"].partition("?")[0] == "/v1/messages"]


def _lines(meter_dir, g):
    return [json.loads(x) for x in (meter_dir / f"{g.meter_id}.jsonl").read_text().splitlines()]


BODY = {"model": OPUS, "max_tokens": 4_096, "messages": [{"role": "user", "content": "hi"}]}


# ---------------------------------------------------------------------------------------------------------------
# Authentication, pinning, the allowlist
# ---------------------------------------------------------------------------------------------------------------

def test_a_metered_json_call_is_pinned_and_priced(gateway, upstream, tmp_path):
    g = _grant()
    token = _tok(g)
    body = {**BODY, "temperature": 0.2, "top_p": 0.9, "top_k": 5, "speed": "fast", "inference_geo": "us",
            "service_tier": "auto", "system": "be careful",
            "thinking": {"type": "enabled", "budget_tokens": 9_000}, "output_config": {"effort": "low", "format": {"x": 1}}}
    status, headers, raw = _call(gateway, body, token, headers={
        "anthropic-beta": "FAST-MODE-2026-02-01, context-1m-2025-08-07, advisor-tool-2026-03-01, compact-2026-01-12"})
    assert status == 200 and json.loads(raw)["usage"] == USAGE and headers.get("request-id") == "req_json"
    sent = upstream.seen[-1]
    assert sent["path"] == "/v1/messages"
    assert sent["headers"]["x-api-key"] == PROVIDER_KEY and token not in json.dumps(sent)
    assert "authorization" not in sent["headers"]
    assert sent["headers"]["anthropic-beta"] == "context-1m-2025-08-07"      # every other beta is dropped
    b = sent["body"]
    assert b["thinking"] == {"type": "adaptive"} and b["output_config"] == {"effort": "max", "format": {"x": 1}}
    assert b["service_tier"] == "standard_only"
    assert not {"temperature", "top_p", "top_k", "speed"} & set(b)
    assert b["inference_geo"] == "global"                               # pinned: never the US-only premium
    assert b["max_tokens"] == 4_096
    assert b["system"][1:] == [{"type": "text", "text": "be careful"}] and b["system"][0]["type"] == "text"
    t = gateway.gateway.meter.totals(g.meter_id)
    assert (t.cost_nano, t.requests, t.closed, t.unconfirmed_nano, t.open_requests) == (USAGE_COST, 1, False, 0, 0)
    assert t.usage == mm.Usage(1_000, 2_000, 10_000, 3_000, 1_000)
    kinds = [(ln["kind"], ln["n"]) for ln in _lines(tmp_path / "meter", g)]
    assert kinds == [("open", 1), ("usage", 2)]                        # write-ahead, then the metered response
    # Authorization: Bearer works too
    status, _h, _raw = _call(gateway, BODY, "", headers={"x-api-key": "", "authorization": f"Bearer {token}"})
    assert status == 200 and gateway.gateway.meter.totals(g.meter_id).requests == 2


@pytest.mark.parametrize("make_token, status, kind", [
    (lambda g: "nope", 401, "authentication_error"),
    (lambda g: encode_token(g, OTHER.private_key_b64), 401, "authentication_error"),
    (lambda g: encode_token(g.model_copy(update={"not_after": NOW}), OWNER.private_key_b64),
     403, "permission_error"),                                         # expires AT now: already expired
    (lambda g: encode_token(g.model_copy(update={"model": "claude-opus-4-7"}), OWNER.private_key_b64),
     403, "permission_error"),
])
def test_a_bad_grant_is_refused_before_anything_is_forwarded(gateway, upstream, make_token, status, kind):
    s, _h, raw = _call(gateway, BODY, make_token(_grant()))
    assert s == status and _err(raw)[0] == kind and upstream.seen == []


_PDF = {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": "JVBERi0="}}


@pytest.mark.parametrize("body, path, status", [
    ({**BODY, "model": "claude-sonnet-5"}, "/v1/messages", 400),
    ({**BODY, "max_tokens": 0}, "/v1/messages", 400),
    ({**BODY, "max_tokens": True}, "/v1/messages", 400),
    ({**BODY, "output_config": "max"}, "/v1/messages", 400),
    ({**BODY, "output_config": {"effort": "max", "surprise": 1}}, "/v1/messages", 400),
    ({**BODY, "stream": "yes"}, "/v1/messages", 400),
    ({**BODY, "messages": "hi"}, "/v1/messages", 400),
    ({**BODY, "system": 7}, "/v1/messages", 400),
    # anything Anthropic would bill outside the price table
    ({**BODY, "tools": [{"type": "code_execution_20250825", "name": "code_execution"}]}, "/v1/messages", 400),
    ({**BODY, "tools": [{"type": "code_execution_20260521", "name": "code_execution"}]}, "/v1/messages", 400),
    ({**BODY, "tools": [{"type": "advisor_20260301", "name": "advisor", "model": "claude-fable-5-2"}]},
     "/v1/messages", 400),
    ({**BODY, "tools": [{"type": "web_search_20260209", "name": "web_search"}]}, "/v1/messages", 400),
    ({**BODY, "tools": [{"type": "web_fetch_20260209", "name": "web_fetch"}]}, "/v1/messages", 400),
    ({**BODY, "tools": [{"type": "mcp_toolset", "mcp_server_name": "x"}]}, "/v1/messages", 400),
    ({**BODY, "tools": [{"name": "x", "input_schema": {"type": "object"}, "model": "claude-fable-5-2"}]},
     "/v1/messages", 400),
    ({**BODY, "tools": ["web_search"]}, "/v1/messages", 400),
    ({**BODY, "tools": {"name": "x"}}, "/v1/messages", 400),
    ({**BODY, "mcp_servers": [{"type": "url", "url": "https://evil.example/mcp", "name": "x"}]}, "/v1/messages", 400),
    ({**BODY, "container": {"skills": []}}, "/v1/messages", 400),
    ({**BODY, "fallbacks": [{"model": "claude-fable-5-2"}]}, "/v1/messages", 400),
    ({**BODY, "context_management": {"edits": [{"type": "compact_20260112"}]}}, "/v1/messages", 400),
    ({**BODY, "context_management": {"edits": [{"type": "clear_tool_uses_20250919"}], "more": 1}}, "/v1/messages", 400),
    ({**BODY, "messages": [{"role": "user", "content": [_PDF]}]}, "/v1/messages", 400),
    ({**BODY, "messages": [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t", "content": [_PDF]}]}]}, "/v1/messages", 400),
    ({**BODY, "messages": [{"role": "user", "content": [
        {"type": "image", "source": {"type": "file", "file_id": "file_1"}}]}]}, "/v1/messages", 400),
    ({**BODY, "messages": [{"role": "user", "content": [
        {"type": "image", "source": {"type": "url", "url": "https://attacker.example/a.png"}}]}]}, "/v1/messages", 400),
    # a server-tool block in history: a PDF nested in a web_fetch result is still a PDF
    ({**BODY, "messages": [{"role": "assistant", "content": [
        {"type": "server_tool_use", "id": "s1", "name": "web_fetch", "input": {"url": "https://x.example"}},
        {"type": "web_fetch_tool_result", "tool_use_id": "s1", "content": {"type": "web_fetch_result",
         "url": "https://x.example", "content": _PDF}}]}]}, "/v1/messages", 400),
    ({**BODY, "messages": [{"role": "user", "content": [{"type": "container_upload", "file_id": "f"}]}]},
     "/v1/messages", 400),
    ({**BODY, "messages": [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t", "content": [
        {"type": "image", "source": {"type": "url", "url": "https://attacker.example/a.png"}}]}]}]}, "/v1/messages", 400),
    ({**BODY, "messages": [{"role": "user", "content": [{"type": "search_result", "source": "s", "title": "t",
                                                         "content": [_PDF]}]}]}, "/v1/messages", 400),
    ({**BODY, "messages": [{"role": "user", "content": "hi", "output_config": {"effort": "max"}}]}, "/v1/messages", 400),
    ({**BODY, "messages": ["hi"]}, "/v1/messages", 400),
    ({**BODY, "messages": [{"role": "user", "content": 7}]}, "/v1/messages", 400),
    ({**BODY, "system": [{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "x"}}]},
     "/v1/messages", 400),
    # only exact, client-executed tool types
    ({**BODY, "tools": [{"type": "computer_20251124", "name": "computer"}]}, "/v1/messages", 400),
    ({**BODY, "tools": [{"type": "computer_toolset_20260801", "name": "computer"}]}, "/v1/messages", 400),
    ({**BODY, "tools": [{"type": "memory_20250818", "name": "memory"}]}, "/v1/messages", 400),
    ({**BODY, "tools": [{"type": "bash_20991231", "name": "bash"}]}, "/v1/messages", 400),
    ({**BODY, "tools": [{"type": "web_search_20260209", "name": "web_search"}]}, "/v1/messages/count_tokens", 400),
    (b"{not json", "/v1/messages", 400),
    (["a", "list"], "/v1/messages", 400),
    (BODY, "/v1/complete", 404),
    (BODY, "/v1/messages/batches", 404),
    (BODY, "/v1/files", 404),
])
def test_a_bad_request_is_refused_before_anything_is_forwarded(gateway, upstream, body, path, status):
    g = _grant()
    s, _h, raw = _call(gateway, body, _tok(g), path=path)
    assert s == status and _err(raw) and upstream.seen == []
    assert gateway.gateway.meter.pending(g.meter_id) == 0              # and nothing stays reserved


def test_what_the_runners_legitimately_send_is_forwarded(gateway, upstream):
    body = {**BODY, "stop_sequences": ["X"], "metadata": {"user_id": "u"},
            "cache_control": {"type": "ephemeral", "ttl": "1h"},
            "context_management": {"edits": [{"type": "clear_tool_uses_20250919"}]},
            "system": [{"type": "text", "text": "sys", "cache_control": {"type": "ephemeral", "ttl": "1h"}}],
            "tools": [{"name": "run", "input_schema": {"type": "object"}, "cache_control": {"type": "ephemeral", "ttl": "1h"}},
                      {"type": "custom", "name": "c", "input_schema": {"type": "object"}},
                      {"type": "bash_20250124", "name": "bash"},
                      {"type": "text_editor_20250728", "name": "str_replace_based_edit_tool"}],
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "look", "cache_control": {"type": "ephemeral", "ttl": "1h"}},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}},
                {"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": "notes"}},
                {"type": "tool_result", "tool_use_id": "t", "content": [
                    {"type": "text", "text": "out", "cache_control": {"type": "ephemeral", "ttl": "1h"}}]}]}]}
    assert _call(gateway, body, _tok())[0] == 200
    sent = upstream.seen[-1]["body"]
    assert '"ttl"' not in json.dumps(sent)                             # every cache write is a 5-minute one
    assert json.dumps(sent).count('"cache_control"') == 4               # ...and no breakpoint on a tool (below)
    assert not any("cache_control" in t for t in sent["tools"])
    assert sent["context_management"] == body["context_management"] and len(sent["tools"]) == 4


def test_each_tenant_gets_its_own_prompt_cache_prefix(gateway, upstream):
    def first_block(**kw):
        assert _call(gateway, {**BODY, "system": "the shared VIGIL system prompt"}, _tok(**kw))[0] == 200
        system = upstream.seen[-1]["body"]["system"]
        assert system[1] == {"type": "text", "text": "the shared VIGIL system prompt"}
        return system[0]["text"]
    acme, acme_again = first_block(org_id="org_acme"), first_block(org_id="org_acme", nonce="n-2")
    other = first_block(org_id="org_other", engagement_slug="cust_other")
    assert acme == acme_again and acme != other and "org_acme" not in acme
    assert _call(gateway, BODY, _tok())[0] == 200                      # no system prompt at all: still separated
    assert upstream.seen[-1]["body"]["system"] == [{"type": "text", "text": acme}]


def test_an_oversized_body_a_get_and_a_body_without_a_length_are_refused(gateway, upstream):
    gateway.gateway.config.max_body_bytes = 100
    token = _tok()
    s, _h, raw = _call(gateway, {**BODY, "messages": [{"role": "user", "content": "x" * 500}]}, token)
    assert s == 413 and _err(raw)[0] == "request_too_large"
    with pytest.raises(urllib.error.HTTPError) as e:
        NO_PROXY.open(gateway.url + "/v1/messages", timeout=5)
    assert e.value.code == 404
    for head in (b"transfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", b"\r\n", b"content-length: -5\r\n\r\n",
                 b"content-length: abc\r\n\r\n"):
        sock = socket.create_connection(("127.0.0.1", gateway.server_address[1]), timeout=10)
        sock.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\n" + f"x-api-key: {token}\r\n".encode() + head)
        assert sock.recv(64).startswith(b"HTTP/1.1 411")
        sock.close()
    assert upstream.seen == []


def test_count_tokens_is_forwarded_unmetered_but_validated_and_bounded(gateway, upstream):
    upstream.count = 1234
    g = _grant()
    s, _h, raw = _call(gateway, {"model": OPUS, "messages": BODY["messages"], "temperature": 1, "max_tokens": 10,
                                 "output_config": {"effort": "high", "task_budget": {"type": "tokens", "total": 9}}},
                       _tok(g), path="/v1/messages/count_tokens?beta=true")
    assert s == 200 and json.loads(raw) == {"input_tokens": 1234}
    sent = upstream.seen[-1]
    assert sent["path"] == "/v1/messages/count_tokens?beta=true"
    assert "temperature" not in sent["body"] and "max_tokens" not in sent["body"]
    assert sent["body"]["output_config"] == {"effort": g.effort}       # pinned, and only what the count endpoint takes
    assert "service_tier" not in sent["body"]
    assert gateway.gateway.meter.totals(g.meter_id).requests == 0
    # it shares the account's rate limits: bounded apart from the model slots
    gw_ = gateway.gateway
    gw_.config.concurrency_wait_s = 0.1
    held = [gw_.acquire_count_slot(f"org_{i}") for i in range(gw_.config.global_concurrency)]
    s, h, raw = _call(gateway, {"model": OPUS, "messages": BODY["messages"]}, _tok(g), path="/v1/messages/count_tokens")
    assert s == 429 and h.get("retry-after") == "5"
    for give_back in held:
        give_back()
    assert _call(gateway, BODY, _tok(g))[0] == 200                     # the model slots were never touched
    # a settled run's grant is no longer a credential, for counting either
    gw.GrantMeter(gw_.config.meter_dir).close(g.meter_id, now=NOW)
    n = len(upstream.seen)
    s, _h, raw = _call(gateway, {"model": OPUS, "messages": BODY["messages"]}, _tok(g), path="/v1/messages/count_tokens")
    assert s == 403 and "closed" in _err(raw)[1] and len(upstream.seen) == n


def test_a_forced_tool_choice_carries_no_thinking(gateway, upstream):
    body = {**BODY, "thinking": {"type": "adaptive"}, "tool_choice": {"type": "tool", "name": "x"},
            "tools": [{"name": "x", "input_schema": {"type": "object"}}]}
    assert _call(gateway, body, _tok(effort="high"))[0] == 200
    sent = upstream.seen[-1]["body"]
    assert "thinking" not in sent and sent["output_config"] == {"effort": "high"}


# ---------------------------------------------------------------------------------------------------------------
# Streams
# ---------------------------------------------------------------------------------------------------------------

def test_a_stream_is_relayed_unchanged_and_metered(gateway, upstream):
    g = _grant()
    s, h, raw = _call(gateway, {**BODY, "stream": True}, _tok(g))
    assert s == 200 and h.get("content-type") == "text/event-stream" and h.get("request-id") == "req_stream"
    assert raw == _sse(STREAM_EVENTS)                                  # byte-identical relay
    assert upstream.seen[-1]["headers"]["accept"] == "text/event-stream"
    t = gateway.gateway.meter.totals(g.meter_id)
    # the final delta repeats the cache-write total without its split: the 1-hour writes stay 1-hour writes
    assert t.usage == mm.Usage(1_000, 2_000, 10_000, 3_000, 1_000) and t.cost_nano == USAGE_COST
    assert t.unconfirmed_nano == 0


def test_a_stream_is_metered_after_its_client_disconnects(gateway, upstream):
    upstream.delay = 0.05
    g = _grant()
    sock = _raw_post(gateway, _tok(g), json.dumps({**BODY, "stream": True}).encode())
    assert sock.recv(64).startswith(b"HTTP/1.1 200")
    sock.close()                                                       # the client goes away mid-stream
    assert upstream.stream_done.wait(10)
    assert _wait(lambda: gateway.gateway.meter.totals(g.meter_id).requests)
    t = gateway.gateway.meter.totals(g.meter_id)
    assert t.requests == 1 and t.usage.output_tokens == 2_000 and t.cost_nano == USAGE_COST


def test_a_client_that_stops_reading_cannot_hold_the_request_open(upstream, tmp_path):
    # a stream far larger than the socket buffers, and a client that never reads it
    pad = {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "x" * 65_536}}
    upstream.events = STREAM_EVENTS[:3] + [pad] * 200 + STREAM_EVENTS[3:]
    server = _start(upstream, tmp_path / "meter", client_timeout_s=0.5, tenant_concurrency=1, concurrency_wait_s=0.2)
    try:
        g = _grant()
        sock = _raw_post(server, _tok(g), json.dumps({**BODY, "stream": True}).encode())
        assert upstream.stream_done.wait(20)                           # the gateway kept draining the provider
        assert _wait(lambda: server.gateway.meter.totals(g.meter_id).requests)
        t = server.gateway.meter.totals(g.meter_id)
        assert (t.requests, t.cost_nano, t.unconfirmed_nano) == (1, USAGE_COST, 0)     # metered in full
        assert server.gateway.meter.pending(g.meter_id) == 0
        upstream.events = STREAM_EVENTS
        assert _call(server, BODY, _tok(g))[0] == 200                  # and its one tenant slot came back
        sock.close()
    finally:
        _stop(server)


def test_a_stream_cut_off_before_its_final_usage_is_held_not_free(gateway, upstream):
    upstream.events = STREAM_EVENTS[:6]                                # message_start ... then the provider drops
    g = _grant()
    body = {**BODY, "stream": True}
    assert _call(gateway, body, _tok(g))[0] == 200
    t = gateway.gateway.meter.totals(g.meter_id)
    reserved = _in(body) + 4_096 * OUT
    assert t.requests == 1 and t.cost_nano < USAGE_COST                # only what the stream reported is charged
    assert t.cost_nano + t.unconfirmed_nano == reserved                # the rest of the reservation stays held
    assert gateway.gateway.budget(g)["spent_nano_usd"] == reserved
    assert gateway.gateway.meter._daily == {gw._utc_day(NOW): reserved}        # and counts toward the daily ceiling
    again = gw.GrantMeter(gateway.gateway.config.meter_dir).verify(g.meter_id)  # and it is on disk, not only in memory
    assert (again.cost_nano, again.unconfirmed_nano) == (t.cost_nano, t.unconfirmed_nano)


def test_a_stream_that_never_started_is_released(gateway, upstream):
    upstream.events = [{"type": "error", "error": {"type": "overloaded_error", "message": "busy"}}]
    g = _grant()
    assert _call(gateway, {**BODY, "stream": True}, _tok(g))[0] == 200
    t = gateway.gateway.meter.totals(g.meter_id)
    assert (t.requests, t.cost_nano, t.unconfirmed_nano) == (0, 0, 0) and gateway.gateway.meter.pending(g.meter_id) == 0


def test_a_stream_that_stops_without_starting_is_held_never_free(gateway, upstream):
    upstream.events = [{"type": "message_stop"}]                        # an end, but no message: what ran is unknown
    g = _grant()
    assert _call(gateway, {**BODY, "stream": True}, _tok(g))[0] == 200
    t = gateway.gateway.meter.totals(g.meter_id)
    reserved = _lines(gateway.gateway.config.meter_dir, g)[0]["reserved"]
    assert (t.cost_nano, t.unconfirmed_nano) == (0, reserved) and gateway.gateway.meter.pending(g.meter_id) == 0


@pytest.mark.parametrize("bad", [
    b"data: " + b"[" * 200_000 + b"]" * 200_000 + b"\n\n",                            # nested too deep to parse
    b"data: {not json\n\n",                                                            # unparseable
    b'data: {"type":"message_delta","usage":{"output_tokens":-5}}\n\n',                # a count the meter refuses
    _sse([{"type": "message_delta", "delta": {}, "usage": {                            # an unpriced server-side step
        "output_tokens": 5, "iterations": [{"type": "message"}, {"type": "compaction"}]}}]),
])
def test_an_unreadable_stream_is_charged_at_least_its_reservation(gateway, upstream, bad):
    upstream.events = STREAM_EVENTS[:5] + [bad] + STREAM_EVENTS[5:]
    g = _grant()
    body = {**BODY, "stream": True, "max_tokens": 64_000}
    assert _call(gateway, body, _tok(g))[0] == 200
    t = gateway.gateway.meter.totals(g.meter_id)
    assert t.requests == 1 and t.cost_nano == _in(body) + 64_000 * OUT > USAGE_COST


# ---------------------------------------------------------------------------------------------------------------
# The budget
# ---------------------------------------------------------------------------------------------------------------

def test_max_tokens_is_lowered_to_what_the_cap_allows_and_a_spent_cap_is_refused(gateway, upstream):
    body = {**BODY, "max_tokens": 64_000}
    cap = USAGE_COST + _in(body) + 3_000 * OUT          # room for one call, then one request with 3,000 output tokens
    g = _grant(cap_nano_usd=cap)
    token = _tok(g)
    assert _call(gateway, body, token)[0] == 200
    assert upstream.seen[-1]["body"]["max_tokens"] == (cap - _in(body)) // OUT
    assert _call(gateway, body, token)[0] == 200
    assert upstream.seen[-1]["body"]["max_tokens"] == 3_000            # what is left after the first call
    s, _h, raw = _call(gateway, BODY, token)                           # now nothing useful is left
    assert s == 403 and "budget is reached" in _err(raw)[1] and len(_sent(upstream)) == 2


def test_the_floor_is_a_useful_amount_of_output(gateway, upstream):
    upstream.count = len(json.dumps(BODY).encode())                    # the provider's count is no tighter here
    g = _grant(cap_nano_usd=_in(BODY) + 1_023 * OUT)                   # one token short of the 1,024 floor
    s, _h, raw = _call(gateway, BODY, _tok(g))
    assert s == 403 and "budget is reached" in _err(raw)[1] and _sent(upstream) == []
    g = _grant(cap_nano_usd=_in(BODY) + 1_024 * OUT, nonce="n-2")
    assert _call(gateway, BODY, _tok(g))[0] == 200 and upstream.seen[-1]["body"]["max_tokens"] == 1_024


def test_the_input_of_a_request_is_reserved_before_it_is_sent(gateway, upstream):
    # a Quick-sized cap ($0.75) and a request whose INPUT alone could cost more: it never reaches the provider
    big = {**BODY, "messages": [{"role": "user", "content": "A" * 400_000}]}
    upstream.count = 400_000
    g = _grant(cap_nano_usd=750_000_000)
    assert _in(big) > g.cap_nano_usd
    s, _h, raw = _call(gateway, big, _tok(g))
    assert s == 403 and "budget is reached" in _err(raw)[1]
    assert [x["path"] for x in upstream.seen] == ["/v1/messages/count_tokens"]     # it asked for the tight bound
    assert gateway.gateway.meter.pending(g.meter_id) == 0
    # an image is not billed by its bytes: each one carries an allowance
    pic = {**BODY, "messages": [{"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}}] * 3}]}
    g2 = _grant(nonce="n-2")
    assert _call(gateway, pic, _tok(g2))[0] == 200
    assert _lines(gateway.gateway.config.meter_dir, g2)[0]["reserved"] == _in(pic) + 3 * 6_000 * RATE + 4_096 * OUT
    # ... including an image nested inside an inline document's content
    nested = {**BODY, "messages": [{"role": "user", "content": [{"type": "document", "source": {"type": "content",
        "content": [{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}}]}}]}]}
    g3 = _grant(nonce="n-3")
    assert _call(gateway, nested, _tok(g3))[0] == 200
    assert _lines(gateway.gateway.config.meter_dir, g3)[0]["reserved"] == _in(nested) + 6_000 * RATE + 4_096 * OUT


def test_the_providers_count_replaces_a_byte_bound_that_does_not_fit(gateway, upstream):
    # 400 kB of text is at most 400k tokens by its bytes, but the provider counts 100k: with $1.50 left the byte
    # bound ($2.50) would refuse a request the run can afford
    big = {**BODY, "messages": [{"role": "user", "content": "A" * 400_000}]}
    upstream.count = 100_000
    g = _grant(cap_nano_usd=1_500_000_000)
    assert _call(gateway, big, _tok(g))[0] == 200
    assert [x["path"] for x in upstream.seen] == ["/v1/messages/count_tokens", "/v1/messages"]
    counted = upstream.seen[0]
    assert counted["headers"]["x-api-key"] == PROVIDER_KEY and "max_tokens" not in counted["body"]
    reserved_input = (100_000 * 105 // 100 + 1_000) * RATE             # the count is an estimate: 5% over it
    assert _lines(gateway.gateway.config.meter_dir, g)[0]["reserved"] == reserved_input + 4_096 * OUT
    # a junk count is no count, and an unsized request that may well fit is a RETRY, never "budget is reached"
    for nonce, count in (("n-3", "many"), ("n-4", True), ("n-5", -4), ("n-6", None)):
        upstream.count = count
        g2 = _grant(cap_nano_usd=_in(big) + 500 * OUT, nonce=nonce)    # the byte bound leaves no useful output
        s, h, raw = _call(gateway, big, _tok(g2))
        assert s == 529 and h.get("retry-after") == "5" and "cannot size" in _err(raw)[1]
        assert gateway.gateway.meter.pending(g2.meter_id) == 0
    # with no count and a budget that really is spent, it is the terminal refusal
    upstream.count = None
    spent = _grant(cap_nano_usd=1_000 * OUT, nonce="n-7")
    s, _h, raw = _call(gateway, big, _tok(spent))
    assert s == 403 and "budget is reached" in _err(raw)[1]


def test_concurrent_reservations_cannot_jointly_pass_the_cap(tmp_path):
    meter = gw.GrantMeter(tmp_path)
    g = _grant(cap_nano_usd=10_000 * OUT)
    got = []
    barrier = threading.Barrier(8)

    def take():
        barrier.wait()
        got.append(meter.reserve(g, 4_000 * OUT, OUT, now=NOW))

    ts = [threading.Thread(target=take) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sum(r for _rid, r, _why in got) <= 10_000 * OUT
    assert sorted(r // OUT for _rid, r, _why in got if r) == [2_000, 4_000, 4_000]
    assert {why for _rid, r, why in got if not r} == {"held"}          # the cap is held, not spent: retryable
    for rid, r, _why in got:
        if r:
            meter.release(g, rid, now=NOW)
    assert meter.reserve(g, 10_000 * OUT, OUT, now=NOW)[1:] == (10_000 * OUT, "")   # every reservation came back


def test_a_cap_held_by_a_request_in_flight_is_a_retry_not_the_end(gateway, upstream):
    upstream.delay = 0.6
    body = {**BODY, "max_tokens": 64_000}
    g = _grant(cap_nano_usd=_in(body) + 20_000 * OUT)                  # one request reserves the whole cap
    token = _tok(g)
    gateway.gateway.config.concurrency_wait_s = 0.1
    first = threading.Thread(target=_call, args=(gateway, body, token), daemon=True)
    first.start()
    assert _wait(lambda: gateway.gateway.meter.pending(g.meter_id) > 0)
    s, h, raw = _call(gateway, body, token)                            # while the first is in flight
    assert s == 429 and h.get("retry-after") == "5" and "in flight" in _err(raw)[1]
    b = gateway.gateway.budget(g)
    assert b["fraction_used"] == 1.0 and b["fraction_spent"] == 0.0    # held is not spent
    gateway.gateway.config.concurrency_wait_s = 10
    s, _h, _raw = _call(gateway, body, token)                          # a caller that waits is admitted when it ends
    first.join(10)
    assert s == 200


def test_an_upstream_error_is_relayed_and_releases_the_reservation(gateway, upstream, tmp_path):
    upstream.mode = "error"
    body = {**BODY, "max_tokens": 5_000}
    g = _grant(cap_nano_usd=_in(body) + 5_000 * OUT)
    for _ in range(3):                                                 # a leaked reservation would refuse the 2nd
        s, h, raw = _call(gateway, body, _tok(g))
        assert s == 429 and h.get("retry-after") == "7" and _err(raw)[0] == "rate_limit_error"
        assert upstream.seen[-1]["body"]["max_tokens"] == 5_000
    t = gateway.gateway.meter.totals(g.meter_id)
    assert (t.requests, t.cost_nano, t.unconfirmed_nano) == (0, 0, 0)
    assert [ln["kind"] for ln in _lines(tmp_path / "meter", g)] == ["open", "release"] * 3


def test_an_unreachable_upstream_is_a_502_and_releases(gateway, tmp_path):
    gateway.gateway.config.upstream = "http://127.0.0.1:9"              # nothing listens on the discard port
    g = _grant()
    s, _h, raw = _call(gateway, BODY, _tok(g))
    assert s == 502 and _err(raw)[0] == "api_error"
    assert gateway.gateway.meter.pending(g.meter_id) == 0 and gateway.gateway.budget(g)["spent_nano_usd"] == 0


class _Mute(BaseHTTPRequestHandler):
    """An upstream that takes the request and then says nothing, or half an answer."""

    def log_message(self, *a):
        return

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("content-length") or 0))
        if self.server.mode == "half":
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", "5000")
            self.end_headers()
            self.wfile.write(b'{"id":')
            self.wfile.flush()
        else:
            time.sleep(1.5)
        self.close_connection = True


@pytest.mark.parametrize("mode", ["silent", "half"])
def test_a_request_that_was_sent_but_not_answered_is_held_not_free(tmp_path, mode):
    mute = _serve(_Mute)
    mute.mode = mode
    server = _start(mute, tmp_path / "meter", upstream_timeout_s=0.4)
    try:
        g = _grant()
        s, _h, raw = _call(server, BODY, _tok(g))
        assert s in (502, 504) and _err(raw)[0] == "api_error"
        t = server.gateway.meter.totals(g.meter_id)
        # the provider may have run and billed it: the whole reservation is unconfirmed spend, none of it charged
        assert (t.cost_nano, t.unconfirmed_nano) == (0, _in(BODY) + 4_096 * OUT)
        assert server.gateway.meter.pending(g.meter_id) == 0
    finally:
        _stop(server)
        mute.shutdown()
        mute.server_close()


@pytest.mark.parametrize("mode", ["nousage", "iterations"])
def test_an_unreadable_200_is_charged_its_reservation(gateway, upstream, mode):
    upstream.mode = mode
    g = _grant()
    body = {**BODY, "max_tokens": 2_000}
    assert _call(gateway, body, _tok(g))[0] == 200
    t = gateway.gateway.meter.totals(g.meter_id)
    assert t.requests == 1 and t.cost_nano == _in(body) + 2_000 * OUT


def test_the_sovereignty_tier_can_refuse_egress(gateway, upstream):
    def refuse(url):
        raise RuntimeError("cloud egress is not permitted at this tier")
    gateway.gateway.config.egress_check = refuse
    g = _grant()
    s, _h, raw = _call(gateway, BODY, _tok(g))
    assert s == 403 and "sovereignty" in _err(raw)[1] and upstream.seen == []
    assert gateway.gateway.meter.pending(g.meter_id) == 0              # released


# ---------------------------------------------------------------------------------------------------------------
# Key custody
# ---------------------------------------------------------------------------------------------------------------

def test_the_provider_key_never_follows_a_redirect(upstream, tmp_path):
    elsewhere = _serve(_Upstream)
    cfg = gw.GatewayConfig(api_key=PROVIDER_KEY, owner_pubkey=OWNER.public_key_b64, meter_dir=tmp_path / "meter",
                           upstream=f"http://127.0.0.1:{upstream.server_address[1]}", clock=lambda: NOW)
    assert cfg.opener is None                                          # the gateway's OWN opener is under test
    server, _t = gw.start(cfg)
    server.url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        upstream.mode, upstream.redirect_to = "redirect", f"http://127.0.0.1:{elsewhere.server_address[1]}/steal"
        g = _grant()
        s, h, raw = _call(server, BODY, _tok(g))
        assert s == 502 and _err(raw)[0] == "api_error" and "location" not in {k.lower() for k in h}
        assert elsewhere.seen == [] and PROVIDER_KEY not in raw.decode()
        assert server.gateway.meter.pending(g.meter_id) == 0
    finally:
        _stop(server)
        elsewhere.shutdown()
        elsewhere.server_close()


def test_the_key_only_travels_over_tls_and_is_never_shown(tmp_path):
    def cfg(**kw):
        base = dict(api_key=PROVIDER_KEY, owner_pubkey=OWNER.public_key_b64, meter_dir=tmp_path / "m")
        base.update(kw)
        return gw.GatewayConfig(**base)
    for bad in ("http://api.anthropic.com", "http://10.0.0.5:8080", "ftp://127.0.0.1", "api.anthropic.com", ""):
        with pytest.raises(ValueError, match="https"):
            gw.ModelGateway(cfg(upstream=bad))
    for bad_key in ("", "sk-ant\nx-evil: 1", "sk ant", "sk-änt", "sk-ant-x\n", "sk-ant-x\r\n", "sk-ant-\tx"):
        with pytest.raises(ValueError) as e:
            gw.ModelGateway(cfg(api_key=bad_key))
        assert "sk-" not in str(e.value) and (not bad_key or bad_key not in str(e.value))
    assert PROVIDER_KEY not in repr(cfg())
    ok = gw.ModelGateway(cfg(upstream="https://api.anthropic.com"))
    ok.meter.shutdown()


def test_the_gateway_listens_on_loopback_only_and_alone(upstream, tmp_path):
    cfg = gw.GatewayConfig(api_key="k", owner_pubkey=OWNER.public_key_b64, meter_dir=tmp_path / "a")
    for host in ("0.0.0.0", "localhost", "::1", "192.168.1.5", ""):
        with pytest.raises(ValueError, match="loopback"):
            gw.start(cfg, host=host)
    with pytest.raises(ValueError):
        gw.ModelGateway(gw.GatewayConfig(api_key="k", owner_pubkey="", meter_dir=tmp_path / "a"))
    # ONE gateway meters a directory: a second on the same one refuses to start, until the first has stopped
    first = _start(upstream, tmp_path / "meter")
    with pytest.raises(RuntimeError, match="already metering"):
        _start(upstream, tmp_path / "meter")
    _stop(first)
    _stop(_start(upstream, tmp_path / "meter"))


# ---------------------------------------------------------------------------------------------------------------
# The meter file: write-ahead, crash, close
# ---------------------------------------------------------------------------------------------------------------

def test_a_close_from_another_process_stops_the_run(gateway, upstream, tmp_path):
    g = _grant()
    token = _tok(g)
    assert _call(gateway, BODY, token)[0] == 200
    other = gw.GrantMeter(tmp_path / "meter")                          # the settle step's own instance
    totals = other.close(g.meter_id, now=1_800_000_100.0)
    assert (totals.requests, totals.cost_nano, totals.closed, totals.open_requests) == (1, USAGE_COST, True, 0)
    # the gateway has this launch in memory as open: it learns of the close under the file lock, before it admits
    assert gateway.gateway.meter.reserve(g, OUT * 2_000, OUT, now=NOW)[2] == "closed"
    n = len(upstream.seen)
    s, _h, raw = _call(gateway, BODY, token)
    assert s == 403 and "closed" in _err(raw)[1] and len(upstream.seen) == n
    assert other.close(g.meter_id, now=1_800_000_300.0).requests == 1   # idempotent
    assert [ln["kind"] for ln in _lines(tmp_path / "meter", g)] == ["open", "usage", "close"]


def test_a_close_waits_for_the_requests_in_flight(gateway, upstream, tmp_path):
    upstream.delay = 0.5
    g = _grant()
    token = _tok(g)
    flying = threading.Thread(target=_call, args=(gateway, BODY, token), daemon=True)
    flying.start()
    assert _wait(lambda: gateway.gateway.meter.pending(g.meter_id) > 0)
    settle = gw.GrantMeter(tmp_path / "meter")
    with pytest.raises(gw.MeterBusy):
        settle.close(g.meter_id, now=NOW)                              # its total would miss the response in flight
    n = len(upstream.seen)
    assert _call(gateway, BODY, token)[0] == 403 and len(upstream.seen) == n       # but admission stopped at once
    flying.join(10)
    totals = settle.close(g.meter_id, now=NOW)                         # the retry, once the response is metered
    assert (totals.requests, totals.cost_nano, totals.closed) == (1, USAGE_COST, True)
    assert _lines(tmp_path / "meter", g)[-1]["kind"] == "close"         # the close line is always the last


def test_a_crash_between_the_call_and_its_record_is_never_free(upstream, tmp_path):
    d = tmp_path / "meter"
    crashed = gw.GrantMeter(d, gateway=True)
    g = _grant(cap_nano_usd=10_000 * OUT)
    _rid, reserved, _why = crashed.reserve(g, 6_000 * OUT, OUT, now=NOW)       # admitted, forwarded ... and gone
    crashed.shutdown()
    # a settle step with no gateway alive: the unmatched open is a crash's leftover
    assert gw.GrantMeter(d).verify(g.meter_id).open_requests == 1
    server = _start(upstream, d)                                       # the restarted gateway
    try:
        t = server.gateway.meter.totals(g.meter_id)
        assert (t.cost_nano, t.unconfirmed_nano, t.open_requests) == (0, reserved, 0)
        assert server.gateway.budget(g)["remaining_nano_usd"] == 4_000 * OUT       # it counts against the cap
        rid, r, _why = server.gateway.meter.reserve(g, 9_000 * OUT, OUT, now=NOW)
        assert r == 4_000 * OUT                                        # ... at admission, not only in the read
        server.gateway.meter.release(g, rid, now=NOW)
        assert [ln["kind"] for ln in _lines(d, g)] == ["open", "orphan", "open", "release"]
        totals = gw.GrantMeter(d).close(g.meter_id, now=NOW)
        assert (totals.cost_nano, totals.unconfirmed_nano, totals.closed) == (0, reserved, True)   # never billed
    finally:
        _stop(server)
    # and with no gateway ever coming back, the settle step records the orphan itself
    g2 = _grant(nonce="n-2")
    crashed = gw.GrantMeter(d, gateway=True)
    _rid, reserved2, _why = crashed.reserve(g2, 6_000 * OUT, OUT, now=NOW)
    crashed.shutdown()
    totals = gw.GrantMeter(d).close(g2.meter_id, now=NOW)
    assert (totals.unconfirmed_nano, totals.open_requests, totals.closed) == (reserved2, 0, True)
    assert [ln["kind"] for ln in _lines(d, g2)] == ["open", "orphan", "close"]


def test_the_meter_survives_a_restart_and_detects_tampering(gateway, upstream, tmp_path):
    g = _grant()
    token = _tok(g)
    for _ in range(3):
        assert _call(gateway, BODY, token)[0] == 200
    d = tmp_path / "meter"
    assert gw.GrantMeter(d).totals(g.meter_id).cost_nano == 3 * USAGE_COST
    p = d / f"{g.meter_id}.jsonl"
    assert oct(p.stat().st_mode & 0o777) == "0o600" and oct(d.stat().st_mode & 0o777) == "0o700"
    lines = p.read_text().splitlines()
    assert len(lines) == 6

    def broken(new_lines):
        p.write_text("\n".join(new_lines) + "\n")
        with pytest.raises(ValueError, match="hash chain"):
            gw.GrantMeter(d).verify(g.meter_id)

    edited = json.loads(lines[1])
    edited["cost_nano"] = 1
    broken([lines[0], json.dumps(edited, sort_keys=True, separators=(",", ":"))] + lines[2:])
    broken(lines[:2] + lines[4:])                                      # a dropped pair breaks the chain
    broken(lines[2:])                                                  # so does a file whose head was cut off
    broken([lines[0], lines[1], lines[3], lines[2]] + lines[4:])       # and a reordered one
    p.write_text("\n".join(lines) + "\n")
    assert gw.GrantMeter(d).verify(g.meter_id).requests == 3


def test_a_torn_final_line_is_repaired_not_fatal(gateway, upstream, tmp_path):
    g = _grant()
    token = _tok(g)
    assert _call(gateway, BODY, token)[0] == 200
    p = tmp_path / "meter" / f"{g.meter_id}.jsonl"
    with open(p, "ab") as f:
        f.write(b'{"kind":"usage","cost_nano":123')                    # a write cut short by a crash: no newline
    assert gw.GrantMeter(tmp_path / "meter").verify(g.meter_id).cost_nano == USAGE_COST    # readable as it is
    assert _call(gateway, BODY, token)[0] == 200                       # and the next append repairs it
    assert p.read_bytes().endswith(b"\n") and b'"cost_nano":123' not in p.read_bytes()
    t = gw.GrantMeter(tmp_path / "meter").verify(g.meter_id)
    assert (t.requests, t.cost_nano) == (2, 2 * USAGE_COST)


def test_a_meter_that_cannot_be_written_refuses_the_request(gateway, upstream, tmp_path, monkeypatch):
    g = _grant()

    def full(self, fd, line):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(gw.GrantMeter, "_write", full)
    s, _h, raw = _call(gateway, BODY, _tok(g))
    assert s == 529 and _err(raw)[0] == "overloaded_error" and upstream.seen == []   # nothing ran unrecorded
    assert gateway.gateway.meter.pending(g.meter_id) == 0
    # a meter file that is corrupt refuses too (the gateway never appends onto a broken chain)
    monkeypatch.undo()
    g2 = _grant(nonce="n-2")
    (tmp_path / "meter" / f"{g2.meter_id}.jsonl").write_text("not a meter line\n")
    assert _call(gateway, BODY, _tok(g2))[0] == 529 and upstream.seen == []


def test_a_response_that_cannot_be_recorded_still_counts_and_stops_the_launch(gateway, upstream, tmp_path, monkeypatch):
    body = dict(BODY)
    g = _grant()
    real = gw.GrantMeter._write

    def fails_after_the_call(self, fd, line):
        if line["kind"] != "open":
            raise OSError(5, "Input/output error")
        return real(self, fd, line)
    monkeypatch.setattr(gw.GrantMeter, "_write", fails_after_the_call)
    assert _call(gateway, body, _tok(g))[0] == 200                     # the provider answered and billed
    m = gateway.gateway.meter
    t = m.totals(g.meter_id)
    reserved = _in(body) + 4_096 * OUT
    assert t.cost_nano == USAGE_COST and t.cost_nano + t.unconfirmed_nano == reserved      # never less than reserved
    assert m.pending(g.meter_id) == 0
    n = len(upstream.seen)
    assert _call(gateway, body, _tok(g))[0] == 529 and len(upstream.seen) == n     # the launch is stopped
    monkeypatch.undo()
    assert _call(gateway, body, _tok(g))[0] == 529                     # ... for this gateway's lifetime
    # the open left on disk is unmatched, so the settle step waits, and a restarted gateway counts it
    assert gw.GrantMeter(tmp_path / "meter").verify(g.meter_id).open_requests == 1
    with pytest.raises(gw.MeterBusy):
        gw.GrantMeter(tmp_path / "meter").close(g.meter_id, now=NOW)


def test_a_ticket_settles_exactly_once(tmp_path):
    meter = gw.GrantMeter(tmp_path)
    g = _grant(cap_nano_usd=4_000 * OUT)
    rid1, r1, _ = meter.reserve(g, 2_000 * OUT, OUT, now=NOW)
    _rid2, _r2, _ = meter.reserve(g, 2_000 * OUT, OUT, now=NOW)
    t1 = gw._Ticket(meter, g, rid1, r1, lambda: NOW)
    t1.commit(mm.Usage(output_tokens=100), 100 * OUT, request_id="a")
    t1.release()                                                       # after a commit: a no-op
    t1.hold()
    t1.commit(mm.Usage(output_tokens=100), 100 * OUT, request_id="a")
    t = meter.totals(g.meter_id)
    assert (t.requests, t.cost_nano, t.unconfirmed_nano) == (1, 100 * OUT, 0)
    # the second reservation is still pending: only the 1,900 output tokens the first did not use are free again
    assert meter.reserve(g, 4_000 * OUT, OUT, now=NOW)[1:] == ((4_000 - 100 - 2_000) * OUT, "")


# ---------------------------------------------------------------------------------------------------------------
# One key, many tenants (design §5)
# ---------------------------------------------------------------------------------------------------------------

def _hold_a_slot(gateway, upstream, token):
    """Start a slow stream that occupies one tenant slot and one account slot until it finishes."""
    upstream.delay = 0.15
    n = len(upstream.seen)
    t = threading.Thread(target=_call, args=(gateway, {**BODY, "stream": True}, token), daemon=True)
    t.start()
    assert _wait(lambda: len(upstream.seen) > n)
    return t


def test_one_tenant_cannot_take_every_slot(upstream, tmp_path):
    server = _start(upstream, tmp_path / "meter", tenant_concurrency=1, concurrency_wait_s=0.2)
    try:
        busy = _hold_a_slot(server, upstream, _tok(org_id="org_acme"))
        s, h, raw = _call(server, BODY, _tok(org_id="org_acme", nonce="n-2"))
        assert s == 429 and h.get("retry-after") == "5" and _err(raw)[0] == "rate_limit_error"
        assert _call(server, BODY, _tok(org_id="org_other", engagement_slug="cust_other"))[0] == 200
        busy.join(10)
        assert _call(server, BODY, _tok(org_id="org_acme", nonce="n-3"))[0] == 200
    finally:
        _stop(server)


def test_all_tenants_together_stay_inside_the_account_limit(upstream, tmp_path):
    server = _start(upstream, tmp_path / "meter", tenant_concurrency=1, global_concurrency=1, concurrency_wait_s=0.2)
    try:
        busy = _hold_a_slot(server, upstream, _tok(org_id="org_a"))
        b = _tok(org_id="org_b", engagement_slug="cust_b")
        s, _h, raw = _call(server, BODY, b)
        assert s == 429 and "busy" in _err(raw)[1]
        busy.join(10)
        # the tenant slot B took while it waited for the account slot came back with the refusal
        assert _call(server, BODY, b)[0] == 200
    finally:
        _stop(server)
    for bad in ({"tenant_concurrency": 0}, {"global_concurrency": 0}, {"max_connections": 0}):
        with pytest.raises(ValueError):
            gw.ModelGateway(gw.GatewayConfig(api_key="k", owner_pubkey=OWNER.public_key_b64, meter_dir=tmp_path, **bad))


def test_open_connections_are_bounded_and_idle_ones_are_dropped(upstream, tmp_path):
    server = _start(upstream, tmp_path / "meter", max_connections=2, client_timeout_s=30, header_deadline_s=30)
    port = server.server_address[1]
    try:
        # idle connections cannot lock a runner out: a new one takes the place of the oldest that has not started
        idle = [socket.create_connection(("127.0.0.1", port), timeout=5) for _ in range(2)]
        time.sleep(0.2)
        assert _call(server, BODY, _tok())[0] == 200
        assert idle[0].recv(64) == b""                                 # the oldest idle one was cut
        for sk in idle:
            sk.close()
        # ... but connections busy with a request keep their places: over the bound, a new one is closed unanswered
        upstream.delay = 1.5
        busy = [threading.Thread(target=_call, args=(server, BODY, _tok())) for _ in range(2)]
        for t in busy:
            t.start()
        assert _wait(lambda: server._in_flight == 2 and not server._waiting, 5)
        extra = socket.create_connection(("127.0.0.1", port), timeout=5)
        extra.sendall(b"GET /v1/vigil/budget HTTP/1.1\r\nHost: x\r\n\r\n")
        assert extra.recv(64) == b""
        extra.close()
        for t in busy:
            t.join(10)
    finally:
        _stop(server)


def test_a_connection_that_does_not_send_its_headers_soon_is_cut(upstream, tmp_path):
    server = _start(upstream, tmp_path / "meter", header_deadline_s=0.3, client_timeout_s=30)
    try:
        sk = socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=5)
        sk.sendall(b"POST /v1/messages HTTP/1.1\r\n")                # a request line, then nothing
        started = time.monotonic()
        assert sk.recv(64) == b"" and time.monotonic() - started < 3   # cut at the header deadline, not at 30 s
        sk.close()
        assert _call(server, BODY, _tok())[0] == 200                   # a prompt runner is not affected ...
        upstream.delay = 1.0
        assert _call(server, BODY, _tok())[0] == 200                   # ... even when its answer outlasts the deadline
    finally:
        upstream.delay = 0
        _stop(server)


def test_the_daily_ceiling_protects_the_account_and_survives_a_restart(upstream, tmp_path):
    big = {**BODY, "max_tokens": 8_000}
    limit = USAGE_COST + _in(big) + 5_000 * OUT
    server = _start(upstream, tmp_path / "meter", daily_limit_nano=limit)
    try:
        token = _tok()
        assert _call(server, BODY, token)[0] == 200                    # spends USAGE_COST
        s, _h, raw = _call(server, big, token)                         # 8,000 output tokens would pass the ceiling
        assert s == 529 and _err(raw)[0] == "overloaded_error"
        other = _tok(org_id="org_other", engagement_slug="cust_other")
        assert _call(server, big, other)[0] == 529                     # account-wide, not per tenant
        assert server.gateway.meter._daily == {gw._utc_day(NOW): USAGE_COST}       # counted once, not twice
    finally:
        _stop(server)
    # a restarted gateway seeds the day from the meter files
    fresh = gw.GrantMeter(tmp_path / "meter")
    g2 = _grant(nonce="n-fresh")
    assert fresh.reserve(g2, 8_000 * OUT, OUT, now=NOW, input_cost=_in(big), daily_limit_nano=limit)[2] == "capacity"
    # reservations in flight count against the ceiling too
    rid, r, why = fresh.reserve(g2, 4_000 * OUT, OUT, now=NOW, daily_limit_nano=limit)
    assert r and fresh.reserve(_grant(nonce="n-3"), 4_000 * OUT, OUT, now=NOW, daily_limit_nano=limit)[2] == "capacity"
    fresh.release(g2, rid, now=NOW)
    # the next UTC day starts from zero, and its first response is counted once
    tomorrow = NOW + 86_400
    rid, r, why = fresh.reserve(g2, 8_000 * OUT, OUT, now=tomorrow, daily_limit_nano=limit)
    assert (r, why) == (8_000 * OUT, "")
    fresh.commit(g2, rid, mm.Usage(output_tokens=1_000), 1_000 * OUT, request_id="r", now=tomorrow)
    assert fresh._daily == {gw._utc_day(tomorrow): 1_000 * OUT}
    # a gateway with no ceiling configured still seeds the day before its first response lands on disk
    again = gw.GrantMeter(tmp_path / "meter")
    rid, r, why = again.reserve(g2, 2_000 * OUT, OUT, now=NOW)
    again.commit(g2, rid, mm.Usage(output_tokens=500), 500 * OUT, request_id="r2", now=NOW)
    assert again._daily == {gw._utc_day(NOW): USAGE_COST + 500 * OUT}  # the earlier spend, and this one once


def test_grants_for_one_launch_share_its_meter_and_launches_stay_apart(gateway, upstream, tmp_path):
    cap = USAGE_COST + _in(BODY) + 2_000 * OUT
    first = _grant(cap_nano_usd=cap)
    again = _grant(cap_nano_usd=cap)                                    # re-minted for the SAME launch
    assert first.grant_id != again.grant_id and first.meter_id == again.meter_id
    assert _call(gateway, BODY, _tok(first))[0] == 200
    s, _h, raw = _call(gateway, BODY, _tok(again))
    assert s == 200 and upstream.seen[-1]["body"]["max_tokens"] == 2_000   # a new grant cannot reset the budget
    other = _grant(org_id="org_other", engagement_slug="cust_other")
    assert other.meter_id != first.meter_id and _grant(nonce="n-relaunch").meter_id != first.meter_id
    assert _call(gateway, BODY, _tok(other))[0] == 200
    m = gateway.gateway.meter
    assert m.totals(first.meter_id).requests == 2 and m.totals(other.meter_id).requests == 1
    assert {ln["org_id"] for ln in _lines(tmp_path / "meter", other)} == {"org_other"}
    # every line says which grant spent
    assert [ln["grant_id"] for ln in _lines(tmp_path / "meter", first)] == [first.grant_id] * 2 + [again.grant_id] * 2


def test_the_engine_can_read_its_own_budget(gateway, upstream):
    g = _grant(cap_nano_usd=4 * USAGE_COST)
    token = _tok(g)
    assert _call(gateway, BODY, token)[0] == 200

    def budget(tok):
        req = urllib.request.Request(gateway.url + "/v1/vigil/budget", headers={"x-api-key": tok})
        try:
            with NO_PROXY.open(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    s, b = budget(token)
    assert s == 200 and b["spent_nano_usd"] == USAGE_COST and b["remaining_nano_usd"] == 3 * USAGE_COST
    assert b["fraction_used"] == b["fraction_spent"] == 0.25 and b["requests"] == 1 and b["closed"] is False
    # an in-flight request's reservation counts as used (the engine must not plan on money already committed),
    # but not as spent (the 90% wrap-up follows what is really gone)
    rid, held, _why = gateway.gateway.meter.reserve(g, USAGE_COST, 1, now=NOW)
    s, b = budget(token)
    assert b["pending_nano_usd"] == held == USAGE_COST and b["remaining_nano_usd"] == 2 * USAGE_COST
    assert b["fraction_used"] == 0.5 and b["fraction_spent"] == 0.25
    gateway.gateway.meter.release(g, rid, now=NOW)
    assert budget("nope")[0] == 401
    gateway.clock["now"] = 1_950_000_000.0                             # an expired grant can still read its meter
    assert budget(token)[0] == 200
    gw.GrantMeter(gateway.gateway.config.meter_dir).close(g.meter_id, now=NOW)
    assert budget(token)[1]["closed"] is True and len(upstream.seen) == 1


# ---------------------------------------------------------------------------------------------------------------
# Round-2 review folds
# ---------------------------------------------------------------------------------------------------------------

def test_stopping_the_gateway_waits_for_requests_in_flight(upstream, tmp_path):
    d = tmp_path / "meter"
    server = _start(upstream, d, shutdown_drain_s=5)
    upstream.delay = 1.0
    g = _grant()
    flying = threading.Thread(target=_call, args=(server, BODY, _tok(g)), daemon=True)
    flying.start()
    assert _wait(lambda: server.gateway.meter.pending(g.meter_id) > 0)
    server.shutdown()
    closer = threading.Thread(target=server.server_close, daemon=True)
    closer.start()
    time.sleep(0.2)
    assert closer.is_alive()                                           # still draining the request in flight
    with pytest.raises(gw.MeterBusy):                                  # and the settle cannot mistake it for dead
        gw.GrantMeter(d).close(g.meter_id, now=NOW)
    flying.join(10)
    closer.join(10)
    assert not closer.is_alive() and gw.GrantMeter(d)._live_boot() is None   # drained, then the lock let go
    t = gw.GrantMeter(d).close(g.meter_id, now=NOW)                    # now the gateway is gone and nothing is open
    assert (t.cost_nano, t.unconfirmed_nano, t.closed) == (USAGE_COST, 0, True)
    assert [ln["kind"] for ln in _lines(d, g)] == ["open", "usage", "close"]


def test_a_crashed_gateways_leftovers_never_block_a_settle(upstream, tmp_path, monkeypatch):
    d = tmp_path / "meter"
    dead = gw.GrantMeter(d, gateway=True)
    g = _grant(cap_nano_usd=10_000 * OUT)
    _rid, reserved, _why = dead.reserve(g, 6_000 * OUT, OUT, now=NOW)        # admitted ... and the process died
    dead.shutdown()
    # the restarted gateway records the leftover as it starts: nobody needs to touch the launch for it to settle
    server = _start(upstream, d)
    try:
        assert [ln["kind"] for ln in _lines(d, g)] == ["open", "orphan"]
        assert server.gateway.meter._daily.get(gw._utc_day(NOW), 0) >= reserved     # and the day counts it
        t = gw.GrantMeter(d).close(g.meter_id, now=NOW)                 # a live gateway, yet no MeterBusy
        assert (t.cost_nano, t.unconfirmed_nano, t.closed) == (0, reserved, True)
    finally:
        _stop(server)
    # ... and the settle tells a live gateway's requests from a dead one's by the boot id on each open line, even
    # for a leftover the new gateway has not swept
    g2 = _grant(nonce="n-2")
    dead = gw.GrantMeter(d, gateway=True)
    dead.reserve(g2, 2_000 * OUT, OUT, now=NOW)
    dead.shutdown()
    monkeypatch.setattr(gw.GrantMeter, "_orphan_dead_opens", lambda self: None)
    live = gw.GrantMeter(d, gateway=True)
    try:
        t = gw.GrantMeter(d).close(g2.meter_id, now=NOW)
        assert (t.unconfirmed_nano, t.closed) == (2_000 * OUT, True)
        live_rid, _r, _w = live.reserve(_grant(nonce="n-3"), 2_000 * OUT, OUT, now=NOW)
        with pytest.raises(gw.MeterBusy):                               # the live gateway's own open: in flight
            gw.GrantMeter(d).close(_grant(nonce="n-3").meter_id, now=NOW)
    finally:
        live.shutdown()


def test_a_leftover_the_startup_sweep_missed_is_orphaned_when_its_launch_is_loaded(tmp_path, monkeypatch):
    d = tmp_path / "meter"
    g = _grant(cap_nano_usd=10_000 * OUT)
    dead = gw.GrantMeter(d, gateway=True)
    _rid, reserved, _why = dead.reserve(g, 6_000 * OUT, OUT, now=NOW)        # admitted ... and the process died
    dead.shutdown()
    monkeypatch.setattr(gw.GrantMeter, "_orphan_dead_opens", lambda self: None)  # the sweep could not read it
    live = gw.GrantMeter(d, gateway=True)
    try:
        # loading the launch records the leftover: its reservation still counts against the run's cap
        assert live.headroom(g) == g.cap_nano_usd - reserved
        assert [ln["kind"] for ln in _lines(d, g)] == ["open", "orphan"]
    finally:
        live.shutdown()


def test_the_https_upstream_never_follows_a_redirect(tmp_path):
    # a redirect would replay the provider key to wherever the upstream points; the https opener refuses it
    g = gw.ModelGateway(gw.GatewayConfig(api_key="sk-ant-test", owner_pubkey=OWNER.public_key_b64,
                                         meter_dir=tmp_path / "meter"))
    try:
        assert any(isinstance(h, gw._NoRedirect) for h in g._opener.handlers)
        assert not any(type(h) is urllib.request.HTTPRedirectHandler for h in g._opener.handlers)
    finally:
        g.stop()
        g.meter.shutdown()


def test_the_count_body_keeps_only_what_the_count_endpoint_takes():
    shaped = {"model": "m", "messages": [], "max_tokens": 10, "system": "s", "tools": [], "stream": True,
              "output_config": {"effort": "high", "format": {"type": "json_schema"}, "task_budget": {"x": 1}}}
    body = gw.ModelGateway.count_body(shaped)
    assert body["output_config"] == {"effort": "high", "format": {"type": "json_schema"}}
    assert "max_tokens" not in body and "stream" not in body
    assert "output_config" not in gw.ModelGateway.count_body({"model": "m", "messages": [],
                                                              "output_config": {"task_budget": {"x": 1}}})


def test_a_record_that_failed_to_write_is_written_later_and_the_launch_settles(gateway, upstream, tmp_path,
                                                                             monkeypatch):
    g = _grant()
    real = gw.GrantMeter._write

    def fails_after_the_call(self, fd, line):
        if line["kind"] != "open":
            raise OSError(5, "Input/output error")
        return real(self, fd, line)
    monkeypatch.setattr(gw.GrantMeter, "_write", fails_after_the_call)
    assert _call(gateway, BODY, _tok(g))[0] == 200
    m = gateway.gateway.meter
    assert _call(gateway, BODY, _tok(g))[0] == 529                      # owed a record: the launch is refused
    assert m.flush_unwritten() == 0                                     # the disk is still failing
    monkeypatch.undo()
    assert m.flush_unwritten() == 1                                     # the disk is back: the record is written
    t = m.totals(g.meter_id)
    assert (t.cost_nano, t.unconfirmed_nano) == (USAGE_COST, 0)         # and it says what the request really cost
    assert _call(gateway, BODY, _tok(g))[0] == 200                      # the launch is admitted again
    # a settle that comes while a record is owed waits for it (it never signs a total missing a response)
    monkeypatch.setattr(gw.GrantMeter, "_write", fails_after_the_call)
    assert _call(gateway, BODY, _tok(g))[0] == 200
    with pytest.raises(gw.MeterBusy):
        gw.GrantMeter(tmp_path / "meter").close(g.meter_id, now=NOW)
    monkeypatch.undo()
    assert m.flush_unwritten() == 1
    t = gw.GrantMeter(tmp_path / "meter").close(g.meter_id, now=NOW)
    assert (t.cost_nano, t.requests, t.unconfirmed_nano, t.closed) == (3 * USAGE_COST, 3, 0, True)
    kinds = [ln["kind"] for ln in _lines(tmp_path / "meter", g)]
    assert kinds == ["open", "usage", "open", "usage", "open", "usage", "close"]


@pytest.mark.parametrize("sent", [b"", b"POST /v1/messages HTTP/1.1\r\nHost: x\r\n"])
def test_a_connection_that_has_not_started_its_request_is_cut_at_shutdown(upstream, tmp_path, sent):
    d = tmp_path / "meter"
    server = _start(upstream, d, header_deadline_s=30)                 # only the shutdown can cut it quickly
    g = _grant()
    sk = socket.create_connection(("127.0.0.1", server.server_address[1]))
    try:
        sk.sendall(sent)                                               # accepted, but no request yet
        time.sleep(0.2)
        server.shutdown()
        started = time.monotonic()
        server.server_close()
        assert time.monotonic() - started < 5                          # cut, not waited on
        body = json.dumps(BODY).encode()
        rest = (b"" if sent else b"POST /v1/messages HTTP/1.1\r\nHost: x\r\n") + (
            f"x-api-key: {_tok(g)}\r\ncontent-type: application/json\r\n"
            f"content-length: {len(body)}\r\n\r\n").encode() + body
        try:
            sk.sendall(rest)
            answer = sk.recv(4096)
        except OSError:
            answer = b""
        assert not answer.startswith(b"HTTP/1.1 200") and upstream.seen == []   # never forwarded
    finally:
        sk.close()
    t = gw.GrantMeter(d).close(g.meter_id, now=NOW)
    assert (t.cost_nano, t.unconfirmed_nano, t.requests) == (0, 0, 0)
    assert [ln["kind"] for ln in _lines(d, g)] == ["close"]


def test_a_request_that_starts_while_the_gateway_stops_is_refused(gateway, upstream):
    gateway._stopping = True
    s, _h, raw = _call(gateway, BODY, _tok())
    assert s == 529 and "stopping" in _err(raw)[1] and upstream.seen == []
    gateway._stopping = False


def test_a_failed_start_lets_go_of_the_meter_directory(tmp_path, monkeypatch):
    d = tmp_path / "meter"
    real = os.pwrite

    def full(fd, data, offset):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(gw.os, "pwrite", full)
    with pytest.raises(OSError):
        gw.GrantMeter(d, gateway=True)
    monkeypatch.setattr(gw.os, "pwrite", real)
    assert gw.GrantMeter(d)._live_boot() is None                         # the lock was not kept ...
    m = gw.GrantMeter(d, gateway=True)                                   # ... so the gateway can start again
    try:
        assert (d / ".gateway.lock").read_text() == m.boot and len(m.boot) == 16
    finally:
        m.shutdown()


def test_a_busy_port_is_an_os_error_and_gives_the_directory_back(tmp_path):
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        sk.listen()
        cfg = gw.GatewayConfig(api_key=PROVIDER_KEY, owner_pubkey=OWNER.public_key_b64, meter_dir=tmp_path / "meter")
        with pytest.raises(OSError):
            gw.start(cfg, port=sk.getsockname()[1])
    assert gw.GrantMeter(tmp_path / "meter")._live_boot() is None


@pytest.mark.parametrize("line", ["[]", '{"kind": "usage"}', '{"h": "x"}', '"text"'])
def test_a_malformed_record_is_corruption_never_a_crash(tmp_path, line):
    d = tmp_path / "meter"
    d.mkdir()
    g = _grant()
    (d / f"{g.meter_id}.jsonl").write_text(line + "\n")
    for read in (lambda m: m.verify(g.meter_id), lambda m: m.close(g.meter_id, now=NOW)):
        with pytest.raises(ValueError):
            read(gw.GrantMeter(d))
    m = gw.GrantMeter(d, gateway=True)                                   # a gateway still starts beside it ...
    try:
        assert m._day_spend(gw._utc_day(NOW)) == 0                        # ... and its daily ceiling still seeds
    finally:
        m.shutdown()


def test_request_bodies_in_memory_are_bounded_per_tenant_and_overall(upstream, tmp_path):
    raw = json.dumps(BODY).encode()
    server = _start(upstream, tmp_path / "meter", tenant_body_bytes=len(raw) + 10, global_body_bytes=3 * len(raw))
    try:
        assert _call(server, BODY, _tok())[0] == 200
        assert _call(server, BODY, _tok())[0] == 200                   # the first one's bytes were given back
        upstream.delay = 1.5
        first = threading.Thread(target=_call, args=(server, BODY, _tok()))
        first.start()
        assert _wait(lambda: server.gateway._body_total == len(raw), 5)
        s, h, raw2 = _call(server, BODY, _tok())                       # the same tenant, while its first is in flight
        assert s == 429 and h.get("retry-after") == "5" and "in flight" in _err(raw2)[1]
        others = [_tok(org_id=f"org_{i}", engagement_slug=f"cust_{i}") for i in range(3)]
        results = []
        threads = [threading.Thread(target=lambda t=t: results.append(_call(server, BODY, t)[0])) for t in others]
        for t in threads:
            t.start()
        for t in threads + [first]:
            t.join(10)
        assert sorted(results) == [200, 200, 429]                       # three bodies fit the account's budget
        assert server.gateway._body_total == 0 and server.gateway._tenant_body == {}
    finally:
        upstream.delay = 0
        _stop(server)


def test_a_cache_marker_is_rebuilt_and_citations_are_refused(gateway, upstream):
    body = {**BODY, "cache_control": {"type": "ephemeral", "scope": "global", "ttl": "1h"}, "system": [
        {"type": "text", "text": "s", "cache_control": {"type": "ephemeral", "anything": 1}}]}
    assert _call(gateway, body, _tok(), headers={"anthropic-beta": "prompt-caching-scope-2026-01-05"})[0] == 200
    sent = upstream.seen[-1]
    assert sent["body"]["cache_control"] == {"type": "ephemeral"}
    assert sent["body"]["system"][-1]["cache_control"] == {"type": "ephemeral"}
    assert "prompt-caching-scope" not in sent["headers"].get("anthropic-beta", "")
    doc = {"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": "a. b."}}
    for bad in ({**BODY, "cache_control": "ephemeral"}, {**BODY, "cache_control": {"type": "persistent"}},
                {**BODY, "messages": [{"role": "user", "content": [{**doc, "citations": {"enabled": True}}]}]},
                {**BODY, "messages": [{"role": "user", "content": [{**doc, "citations": True}]}]},
                {**BODY, "messages": [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t",
                    "content": [{"type": "search_result", "source": "s", "title": "t", "citations": {"enabled": True},
                                 "content": [{"type": "text", "text": "x"}]}]}]}]}):
        assert _call(gateway, bad, _tok())[0] == 400, bad
    ok = {**BODY, "messages": [{"role": "user", "content": [{**doc, "citations": {"enabled": False}}]}]}
    assert _call(gateway, ok, _tok())[0] == 200


def test_a_stopped_meter_admits_nothing(tmp_path):
    m = gw.GrantMeter(tmp_path / "meter", gateway=True)
    m.shutdown()
    g = _grant()
    assert m.reserve(g, 1_000 * OUT, OUT, now=NOW) == ("", 0, "meter")
    assert not (tmp_path / "meter" / f"{g.meter_id}.jsonl").exists() or _lines(tmp_path / "meter", g) == []


def test_shutdown_keeps_the_meter_until_every_owed_record_is_written(upstream, tmp_path, monkeypatch):
    d = tmp_path / "meter"
    server = _start(upstream, d, shutdown_drain_s=1.0)
    g = _grant()
    real = gw.GrantMeter._write

    def fails_after_the_call(self, fd, line):
        if line["kind"] != "open":
            raise OSError(28, "No space left on device")
        return real(self, fd, line)
    monkeypatch.setattr(gw.GrantMeter, "_write", fails_after_the_call)
    assert _call(server, BODY, _tok(g))[0] == 200                     # answered, but its record is owed
    server.shutdown()
    server.server_close()                                              # the disk is still full at the deadline
    assert gw.GrantMeter(d)._live_boot() == server.gateway.meter.boot  # so the lock is kept ...
    with pytest.raises(gw.MeterBusy):
        gw.GrantMeter(d).close(g.meter_id, now=NOW)                    # ... and the settle waits
    monkeypatch.undo()                                                 # the disk recovers: the flusher writes it
    deadline = time.monotonic() + 15
    while server.gateway.meter.owed() and time.monotonic() < deadline:
        time.sleep(0.2)
    t = gw.GrantMeter(d).close(g.meter_id, now=NOW)
    assert (t.cost_nano, t.unconfirmed_nano, t.requests) == (USAGE_COST, 0, 1)
    assert [ln["kind"] for ln in _lines(d, g)] == ["open", "usage", "close"]
    server.gateway.stop()
    server.gateway.meter.shutdown()
    # and a clean stop with a record owed, whose disk recovers within the drain, writes it before letting go
    d2 = tmp_path / "meter2"
    server = _start(upstream, d2, shutdown_drain_s=10.0)
    monkeypatch.setattr(gw.GrantMeter, "_write", fails_after_the_call)
    assert _call(server, BODY, _tok(g))[0] == 200
    threading.Timer(0.5, monkeypatch.undo).start()
    server.shutdown()
    server.server_close()
    assert server.gateway.meter.owed() == 0 and gw.GrantMeter(d2)._live_boot() is None
    assert [ln["kind"] for ln in _lines(d2, g)] == ["open", "usage"]


def test_a_settle_probe_does_not_stop_a_gateway_from_starting(tmp_path):
    d = tmp_path / "meter"
    d.mkdir(mode=0o700)
    fd = os.open(d / ".gateway.lock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_SH)                                      # a settle step's probe, mid-check
    assert gw.GrantMeter(d)._live_boot() is None                        # two settles' probes never see each other
    threading.Timer(0.3, lambda: os.close(fd)).start()
    m = gw.GrantMeter(d, gateway=True)                                  # waits it out instead of refusing
    try:
        assert gw.GrantMeter(d)._live_boot() == m.boot != ""
    finally:
        m.shutdown()
    assert gw.GrantMeter(d)._live_boot() is None


@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded, use of fork:DeprecationWarning")
def test_a_forked_child_does_not_keep_the_gateway_lock(tmp_path):
    d = tmp_path / "meter"
    m = gw.GrantMeter(d, gateway=True)
    pid = os.fork()
    if pid == 0:                                                        # the child outlives the gateway a while
        time.sleep(1.5)
        os._exit(0)
    try:
        m.shutdown()                                                    # the gateway process stops
        again = gw.GrantMeter(d, gateway=True, lock_wait_s=0.3)         # the child holds no copy of the lock
        again.shutdown()
    finally:
        os.waitpid(pid, 0)


@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded, use of fork:DeprecationWarning")
def test_a_forked_child_does_not_keep_a_launch_file_locked(tmp_path):
    d = tmp_path / "meter"
    m = gw.GrantMeter(d)
    g = _grant()
    entered, leave = threading.Event(), threading.Event()

    def writer():
        with m._locked(g.meter_id):                                     # a thread mid-write when the fork happens
            entered.set()
            leave.wait(10)
    t = threading.Thread(target=writer)
    t.start()
    assert entered.wait(10)
    pid = os.fork()
    if pid == 0:                                                        # the child outlives the write a while
        time.sleep(3)
        os._exit(0)
    try:
        leave.set()
        t.join(10)
        done = threading.Event()
        threading.Thread(target=lambda: (gw.GrantMeter(d).close(g.meter_id, now=NOW), done.set()),
                         daemon=True).start()
        assert done.wait(1.5)                                           # the child holds no copy of that lock
    finally:
        os.waitpid(pid, 0)


def test_anthropic_defined_tools_are_reserved_for_their_definitions(gateway, upstream, tmp_path):
    body = {**BODY, "tools": [{"type": "bash_20250124", "name": "bash"},
                              {"type": "text_editor_20250728", "name": "str_replace_based_edit_tool"}]}
    g = _grant()
    assert _call(gateway, body, _tok(g))[0] == 200
    reserved = _lines(tmp_path / "meter", g)[0]["reserved"]
    assert reserved == _in(body) + (400 + 1_100 + 500) * RATE + 4_096 * OUT


def test_a_cached_prefix_the_request_re_sends_is_reserved_at_the_read_rate(gateway, upstream, tmp_path):
    first = {**BODY, "cache_control": {"type": "ephemeral"},
             "messages": [{"role": "user", "content": "A" * 50_000}]}
    g = _grant()
    token = _tok(g)
    assert _call(gateway, first, token)[0] == 200                       # usage: 10,000 read + 4,000 written
    cached = 14_000
    longer = {**first, "messages": first["messages"] + [{"role": "assistant", "content": "ok"},
                                                          {"role": "user", "content": "more"}]}

    def reserved_for(body, grant=g, tok=token):
        assert _call(gateway, body, tok)[0] == 200
        return _lines(tmp_path / "meter", grant)[-2]["reserved"]

    bound = len(json.dumps(longer).encode()) + 1_000
    assert reserved_for(longer) == cached * ROW.cache_read + (bound - cached) * RATE + 4_096 * OUT
    # no discount when the prefix differs, the request asks for no caching, the entry has expired, or another
    # launch sent it
    changed = {**longer, "messages": [{"role": "user", "content": "B" * 50_000}] + longer["messages"][1:]}
    assert reserved_for(changed) == _in(changed) + 4_096 * OUT
    plain = {k: v for k, v in longer.items() if k != "cache_control"}
    assert reserved_for(plain) == _in(plain) + 4_096 * OUT
    other = _grant(nonce="n-other")
    assert reserved_for(longer, other, _tok(other)) == _in(longer) + 4_096 * OUT
    gateway.clock["now"] = NOW + 225
    assert reserved_for(longer) < _in(longer) + 4_096 * OUT              # live, with its admission delay allowed for
    gateway.clock["now"] = NOW + 225 + 235
    assert reserved_for(longer) == _in(longer) + 4_096 * OUT              # 300 s less the worst delay (60 s) and 10 s


def test_a_change_to_what_the_provider_renders_is_never_discounted(gateway, upstream, tmp_path):
    tools = [{"name": "run", "input_schema": {"type": "object"}}]
    first = {**BODY, "cache_control": {"type": "ephemeral"}, "tools": tools, "tool_choice": {"type": "auto"},
             "messages": [{"role": "user", "content": "A" * 50_000}]}
    g = _grant()
    token = _tok(g)
    assert _call(gateway, first, token)[0] == 200
    longer = {**first, "messages": first["messages"] + [{"role": "assistant", "content": "ok"},
                                                          {"role": "user", "content": "more"}]}

    def reserved_for(body, headers=None):
        assert _call(gateway, body, token, headers=headers)[0] == 200
        return _lines(tmp_path / "meter", g)[-2]["reserved"]
    assert reserved_for(longer) < _in(longer) + 4_096 * OUT              # the same render: discounted
    pic = {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}}
    for changed, headers in (
            ({**longer, "tool_choice": {"type": "any"}}, None),          # a forced tool (and so no thinking)
            ({**longer, "context_management": {"edits": [{"type": "clear_thinking_20251015"}]}}, None),
            ({**longer, "messages": longer["messages"][:-1] + [{"role": "user", "content": [
                {"type": "text", "text": "more"}, pic]}]}, None),         # an image changes the message blocks
            (longer, {"anthropic-beta": "context-1m-2025-08-07"})):      # another forwarded beta
        images = json.dumps(changed["messages"]).count('"image"')
        want = _in(changed) + (500 + 6_000 * images) * RATE + 4_096 * OUT   # the tools' preamble, each image
        assert reserved_for(changed, headers) == want, (changed.keys(), headers)
    # context edits on EVERY request (a constant runner setting): the provider clears part of the prefix the client
    # re-sends, so the same request is never discounted either
    edits = {"edits": [{"type": "clear_thinking_20251015"}]}
    g2 = _grant(nonce="n-edits")
    assert _call(gateway, {**first, "context_management": edits}, _tok(g2))[0] == 200
    again = {**longer, "context_management": edits}
    assert _call(gateway, again, _tok(g2))[0] == 200
    assert _lines(tmp_path / "meter", g2)[-2]["reserved"] == _in(again) + 500 * RATE + 4_096 * OUT


def test_the_discount_needs_a_breakpoint_that_can_read_the_entry(gateway, upstream, tmp_path):
    # automatic (top-level) caching: the entry sits at the previous request's last block, and the provider looks back
    # at most 20 blocks from this request's last block to find it
    first = {**BODY, "cache_control": {"type": "ephemeral"}, "messages": [{"role": "user", "content": "A" * 50_000}]}
    tail = [{"role": "assistant", "content": "ok"}]

    def reserved_for(g, body):
        assert _call(gateway, body, _tok(g))[0] == 200
        return _lines(tmp_path / "meter", g)[-2]["reserved"]
    near = {**first, "messages": first["messages"] + tail + [{"role": "user", "content": "more"}]}
    g = _grant(cap_nano_usd=10 ** 12)
    reserved_for(g, first)
    assert reserved_for(g, near) < _in(near) + 4_096 * OUT              # 2 blocks on: within the lookback
    far = {**first, "messages": first["messages"] + tail + [{"role": "user", "content": [
        {"type": "text", "text": f"b{i}"} for i in range(25)]}]}
    g2 = _grant(nonce="n-far", cap_nano_usd=10 ** 12)
    reserved_for(g2, first)
    assert reserved_for(g2, far) == _in(far) + 4_096 * OUT               # 26 blocks on: out of reach, no discount
    # ... even with an earlier explicit marker (the system prompt's), which reaches only its own short entry
    sysb = [{"type": "text", "text": "sys", "cache_control": {"type": "ephemeral"}}]
    g4 = _grant(nonce="n-sys", cap_nano_usd=10 ** 12)
    reserved_for(g4, {**first, "system": sysb})
    assert reserved_for(g4, {**far, "system": sysb}) == _in({**far, "system": sysb}) + 4_096 * OUT
    # an explicit marker kept where the entry was written reads it, however far the request runs past it
    marked = {**BODY, "messages": [{"role": "user", "content": [
        {"type": "text", "text": "A" * 50_000, "cache_control": {"type": "ephemeral"}}]}]}
    g3 = _grant(nonce="n-marked", cap_nano_usd=10 ** 12)
    reserved_for(g3, marked)
    far_marked = {**marked, "messages": marked["messages"] + far["messages"][1:]}
    assert reserved_for(g3, far_marked) < _in(far_marked) + 4_096 * OUT
    assert gw.ModelGateway.breakpoints(far) == [26] and gw.ModelGateway.breakpoints(far_marked) == [0]
    assert gw.ModelGateway.breakpoints({**BODY, "tools": [{"name": "t"}], "system": "s", "messages": [
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "x", "content": [
            {"type": "text", "text": "o", "cache_control": {"type": "ephemeral"}}]}]}]}) == [2]


def test_a_provider_error_the_client_never_receives_is_still_free(gateway, upstream, tmp_path):
    upstream.mode, upstream.delay = "error", 0.5
    g = _grant()
    sock = _raw_post(gateway, _tok(g), json.dumps(BODY).encode())
    assert _wait(lambda: gateway.gateway.meter.pending(g.meter_id) > 0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    sock.close()                                                        # a reset: relaying the 429 will fail
    assert _wait(lambda: gateway.gateway.meter.pending(g.meter_id) == 0)
    t = gateway.gateway.meter.totals(g.meter_id)
    assert (t.cost_nano, t.unconfirmed_nano) == (0, 0)                  # the provider billed nothing
    assert [ln["kind"] for ln in _lines(tmp_path / "meter", g)] == ["open", "release"]


def test_only_the_known_query_string_reaches_the_provider(gateway, upstream):
    for qs, want in (("?beta=true", "/v1/messages?beta=true"), ("?beta=true&x=1", "/v1/messages"),
                     ("?anything", "/v1/messages"), ("?%00", "/v1/messages")):
        assert _call(gateway, BODY, _tok(), path="/v1/messages" + qs)[0] == 200
        assert upstream.seen[-1]["path"] == want


def test_a_response_nested_too_deep_to_parse_is_charged_its_reservation(gateway, upstream):
    upstream.mode = "deep"
    g = _grant()
    assert _call(gateway, BODY, _tok(g))[0] == 200
    t = gateway.gateway.meter.totals(g.meter_id)
    assert (t.requests, t.cost_nano) == (1, _in(BODY) + 4_096 * OUT)


class _Broken(BaseHTTPRequestHandler):
    """An upstream that starts a stream and then sends a malformed chunk, before any event."""

    def log_message(self, *a):
        return

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("content-length") or 0))
        self.wfile.write(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n"
                         b"\r\nZZ\r\n")
        self.wfile.flush()
        self.close_connection = True


def test_a_stream_that_breaks_before_its_first_event_is_held_not_free(tmp_path):
    broken = _serve(_Broken)
    server = _start(broken, tmp_path / "meter")
    try:
        g = _grant()
        _call(server, {**BODY, "stream": True}, _tok(g))
        t = server.gateway.meter.totals(g.meter_id)
        assert (t.cost_nano, t.unconfirmed_nano) == (0, _in({**BODY, "stream": True}) + 4_096 * OUT)
        assert server.gateway.meter.pending(g.meter_id) == 0
    finally:
        _stop(server)
        broken.shutdown()
        broken.server_close()


def test_a_trickled_request_is_cut_off_at_its_deadline(upstream, tmp_path):
    server = _start(upstream, tmp_path / "meter", request_deadline_s=0.5, client_timeout_s=5,
                    tenant_concurrency=1, concurrency_wait_s=0.2)
    try:
        port = server.server_address[1]
        heads = socket.create_connection(("127.0.0.1", port), timeout=5)
        heads.sendall(b"POST /v1/messages HTTP/1.1\r\n")
        body = socket.create_connection(("127.0.0.1", port), timeout=5)
        body.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\ncontent-type: application/json\r\n"
                     + f"x-api-key: {_tok()}\r\ncontent-length: 1000\r\n\r\n".encode())
        start = time.monotonic()
        cut = set()
        while time.monotonic() - start < 3 and len(cut) < 2:
            for name, sock in (("heads", heads), ("body", body)):
                if name in cut:
                    continue
                try:
                    sock.sendall(b"x")                                  # one byte, well inside the idle timeout
                except OSError:
                    cut.add(name)
            time.sleep(0.1)
        assert cut == {"heads", "body"} and time.monotonic() - start < 2.5
        assert _call(server, BODY, _tok())[0] == 200                    # the trickler's tenant slot came back
        upstream.delay = 1.0                                            # the deadline covers the REQUEST only:
        assert _call(server, BODY, _tok())[0] == 200                    # a slow answer still reaches the client
        heads.close()
        body.close()
    finally:
        _stop(server)


def test_count_tokens_is_bounded_per_tenant(upstream, tmp_path):
    upstream.count = 7
    server = _start(upstream, tmp_path / "meter", tenant_concurrency=1, concurrency_wait_s=0.1)
    try:
        give_back = server.gateway.acquire_count_slot("org_acme")
        count = {"model": OPUS, "messages": BODY["messages"]}
        assert _call(server, count, _tok(), path="/v1/messages/count_tokens")[0] == 429
        assert _call(server, count, _tok(org_id="org_other", engagement_slug="cust_other"),
                     path="/v1/messages/count_tokens")[0] == 200       # another tenant is not starved
        give_back()
        assert _call(server, count, _tok(), path="/v1/messages/count_tokens")[0] == 200
    finally:
        _stop(server)


def test_a_failed_write_leaves_the_file_unchanged_and_releases_the_account(tmp_path, monkeypatch):
    d = tmp_path / "meter"
    meter = gw.GrantMeter(d)
    g = _grant(cap_nano_usd=10_000 * OUT)
    rid, _r, _w = meter.reserve(g, 1_000 * OUT, OUT, now=NOW)
    meter.commit(g, rid, mm.Usage(output_tokens=10), 10 * OUT, request_id="r", now=NOW)
    before = (d / f"{g.meter_id}.jsonl").read_bytes()
    monkeypatch.setattr(gw.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError(28, "No space left on device")))
    assert meter.reserve(g, 1_000 * OUT, OUT, now=NOW, daily_limit_nano=10 ** 15)[2] == "meter"
    assert (d / f"{g.meter_id}.jsonl").read_bytes() == before           # the half-written line was taken back
    assert meter._global_pending == 0                                   # ... and so was the account's commitment
    monkeypatch.undo()
    gw.GrantMeter(d).close(g.meter_id, now=NOW)
    assert meter.reserve(g, 1_000 * OUT, OUT, now=NOW, daily_limit_nano=10 ** 15)[2] == "closed"
    assert meter._global_pending == 0


def test_a_loopback_http_upstream_is_never_reached_through_a_proxy(upstream, tmp_path, monkeypatch):
    proxy = _serve(_Upstream)
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy.server_address[1]}")
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{proxy.server_address[1]}")
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    cfg = gw.GatewayConfig(api_key=PROVIDER_KEY, owner_pubkey=OWNER.public_key_b64, meter_dir=tmp_path / "meter",
                           upstream=f"http://127.0.0.1:{upstream.server_address[1]}", clock=lambda: NOW)
    server, _t = gw.start(cfg)                                          # the gateway's OWN default opener
    server.url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        assert _call(server, BODY, _tok())[0] == 200
        assert proxy.seen == [] and upstream.seen[-1]["headers"]["x-api-key"] == PROVIDER_KEY
    finally:
        _stop(server)
        proxy.shutdown()
        proxy.server_close()
    with pytest.raises(ValueError, match="https"):                      # a name is not a loopback guarantee
        gw.ModelGateway(gw.GatewayConfig(api_key=PROVIDER_KEY, owner_pubkey=OWNER.public_key_b64,
                                         meter_dir=tmp_path / "m2", upstream="http://localhost:9"))


def test_a_grant_issued_in_the_future_is_refused(gateway, upstream):
    s, _h, raw = _call(gateway, BODY, _tok(issued_at=NOW + 3_600, not_after=NOW + 7_200))
    assert s == 403 and "not valid yet" in _err(raw)[1] and upstream.seen == []
    assert _call(gateway, BODY, _tok(issued_at=NOW + 60, not_after=NOW + 7_200))[0] == 200     # clock skew is fine


def test_a_record_that_lands_after_its_orphan_counts_the_request_once(tmp_path):
    d = tmp_path / "meter"
    old = gw.GrantMeter(d, gateway=True)
    g = _grant(cap_nano_usd=10_000 * OUT)
    rid, reserved, _w = old.reserve(g, 4_000 * OUT, OUT, now=NOW)
    old.shutdown()                                                      # the lock is lost with the request in flight
    new = gw.GrantMeter(d, gateway=True)                                # ... and a new gateway orphans it
    new.shutdown()
    old.commit(g, rid, mm.Usage(output_tokens=100), 100 * OUT, request_id="late", now=NOW)   # its record lands late
    t = gw.GrantMeter(d).verify(g.meter_id)
    assert [ln["kind"] for ln in _lines(d, g)] == ["open", "orphan", "usage"]
    assert (t.cost_nano, t.unconfirmed_nano) == (100 * OUT, 0)          # what it really cost, counted once
