"""
AEGIS Gateway — passive OOB belief elevation (opt-in, canary-based, belief-only).

The most doctrine-delicate slice. These tests pin every hard line:

  * TRANSLATOR-not-generator: enabling the feature NEVER mutates an inbound request or its forwarded
    copy — the upstream receives byte-identical bytes whether OOB is on or off, and nothing (no token,
    no callback, no canary) is planted into traffic.
  * BELIEF-ONLY: a correlated canary hit ELEVATES the actor's Beta belief toward the EXISTING
    graduated challenge/throttle (soft, retryable 429) but NEVER yields action=="block" /
    decision=="confirmed" (prove-don't-guess: a hard block still rides only a fired oracle cert).
  * DEFAULT-OFF is byte-identical: no --oob-canary → no receiver, behaviour unchanged.
  * FAIL-OPEN: a receiver/correlator error forwards traffic, never blocks.
  * NEAR-ZERO-FP: a benign inbound hit that does not correlate to any actor's SSRF/XXE payload
    elevates nobody; a hit that predates any probe never retro-correlates.
"""

from __future__ import annotations

import http.client
import http.server
import socketserver
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator

import pytest

from framework.v2.aegis.gateway import serve_gateway
from framework.v2.aegis.models import AegisConfig, Verdict
from framework.v2.aegis.oob_correlator import OOBCorrelator, referenced_hosts
from framework.v2.verify.oob import OOBReceiver

# An operator-planted INTERNAL canary: referencing it trips AEGIS's SSRF lead (RFC1918 host) AND the
# host tunnels back to the loopback receiver. Its unique path segment is the receiver poll key.
CANARY = "http://10.77.88.99/oob-canary-xyz"
CANARY_HOST = "10.77.88.99"
CANARY_SEG = "oob-canary-xyz"


# =========================================================================== correlator unit tests

def test_referenced_hosts_extracts_from_raw_and_percent_encoded():
    enc = urllib.parse.quote(CANARY, safe="")
    assert CANARY_HOST in referenced_hosts(CANARY)
    assert CANARY_HOST in referenced_hosts("/fetch?url=" + enc)          # single-encoded
    assert CANARY_HOST in referenced_hosts("/fetch?url=" + urllib.parse.quote(enc, safe=""))  # double
    assert referenced_hosts("just some text, no url") == set()


def test_note_lead_records_only_when_canary_referenced():
    c = OOBCorrelator(CANARY)
    enc = urllib.parse.quote(CANARY, safe="")
    assert c.note_lead("1.2.3.4", path="/fetch?url=" + enc, body=None, attack_class="ssrf") is True
    # a DIFFERENT host (even an internal SSRF probe) is NOT the canary → no pending record.
    other = urllib.parse.quote("http://169.254.169.254/latest/", safe="")
    assert c.note_lead("1.2.3.4", path="/fetch?url=" + other, body=None, attack_class="ssrf") is False


def _fire_hit(receiver: OOBReceiver, path: str, host: str | None = None) -> None:
    """Send one real HTTP GET to the LOOPBACK receiver so it records an OOBHit (simulates the app
    dereferencing the canary). Optionally sets the Host header (the tunnel would preserve it)."""
    conn = http.client.HTTPConnection("127.0.0.1", receiver.port, timeout=5)
    try:
        headers = {"Host": host} if host else {}
        conn.request("GET", path, headers=headers)
        conn.getresponse().read()
    finally:
        conn.close()


def test_poll_correlates_matching_hit_to_pending_actor():
    c = OOBCorrelator(CANARY)
    with OOBReceiver() as recv:
        enc = urllib.parse.quote(CANARY, safe="")
        c.note_lead("9.9.9.9", path="/fetch?url=" + enc, body=None, attack_class="ssrf")
        _fire_hit(recv, "/" + CANARY_SEG, host=CANARY_HOST)
        elevations = c.poll_elevations(recv)
        assert len(elevations) == 1
        assert elevations[0].actor_key == "9.9.9.9"
        assert elevations[0].attack_class == "ssrf"
        assert elevations[0].referenced_host == CANARY_HOST


def test_poll_dedupes_same_hit_across_polls():
    c = OOBCorrelator(CANARY)
    with OOBReceiver() as recv:
        c.note_lead("9.9.9.9", path="/fetch?url=" + urllib.parse.quote(CANARY, safe=""),
                    body=None, attack_class="ssrf")
        _fire_hit(recv, "/" + CANARY_SEG, host=CANARY_HOST)
        assert len(c.poll_elevations(recv)) == 1   # first poll correlates
        assert c.poll_elevations(recv) == []        # same hit is not re-correlated


def test_one_elevation_per_actor_per_hit():
    # an actor who probes the canary 5 times is elevated ONCE per inbound hit (not 5x).
    c = OOBCorrelator(CANARY)
    with OOBReceiver() as recv:
        for _ in range(5):
            c.note_lead("7.7.7.7", path="/fetch?url=" + urllib.parse.quote(CANARY, safe=""),
                        body=None, attack_class="ssrf")
        _fire_hit(recv, "/" + CANARY_SEG, host=CANARY_HOST)
        assert len(c.poll_elevations(recv)) == 1


def test_benign_hit_with_no_pending_never_elevates():
    # NEAR-ZERO-FP: an inbound hit on the canary with NO actor having targeted it elevates nobody.
    c = OOBCorrelator(CANARY)
    with OOBReceiver() as recv:
        _fire_hit(recv, "/" + CANARY_SEG, host=CANARY_HOST)
        assert c.poll_elevations(recv) == []


def test_hit_before_pending_does_not_retro_correlate():
    # NEAR-ZERO-FP: a canary hit that arrives BEFORE any probe must not retro-correlate to a LATER
    # probe (a real correlation's hit always lands after its pending was recorded).
    c = OOBCorrelator(CANARY)
    with OOBReceiver() as recv:
        _fire_hit(recv, "/" + CANARY_SEG, host=CANARY_HOST)
        assert c.poll_elevations(recv) == []     # marks the early hit seen
        c.note_lead("5.5.5.5", path="/fetch?url=" + urllib.parse.quote(CANARY, safe=""),
                    body=None, attack_class="ssrf")
        assert c.poll_elevations(recv) == []     # the old hit does not resurrect


def test_xxe_external_canary_correlates():
    # For XXE the lead fires on ANY external SYSTEM/PUBLIC entity, so an EXTERNAL canary host works.
    ext = "http://canary.oob.example/xxe-beacon"
    c = OOBCorrelator(ext)
    body = f'<!DOCTYPE r [ <!ENTITY e SYSTEM "{ext}"> ]><r>&e;</r>'
    with OOBReceiver() as recv:
        assert c.note_lead("3.3.3.3", path="/upload", body=body, attack_class="xxe") is True
        _fire_hit(recv, "/xxe-beacon", host="canary.oob.example")
        els = c.poll_elevations(recv)
        assert len(els) == 1 and els[0].attack_class == "xxe"


# =========================================================================== end-to-end gateway

class _Echo(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a):
        return

    def do_GET(self):
        body = b"UP"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET


class _Capture(http.server.BaseHTTPRequestHandler):
    """An upstream that RECORDS the exact request it receives (for the no-injection proof)."""

    captured: list[dict] = []

    def log_message(self, *_a):
        return

    def _handle(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        type(self).captured.append(
            {"command": self.command, "path": self.path,
             "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
        out = b"UP"
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = _handle
    do_POST = _handle


@pytest.fixture()
def upstream() -> Iterator[int]:
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Echo)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def _gw(upstream_port: int, *, mode: str = "enforce", oob_canary: str | None = None,
        sink: list | None = None):
    gw = serve_gateway(f"http://127.0.0.1:{upstream_port}",
                       config=AegisConfig(deployment_secret="k", mode=mode, oob_canary=oob_canary),
                       host="127.0.0.1", port=0,
                       on_verdict=(sink.append if sink is not None else None))
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    return gw, gw.server_address[1]


_SSRF_ENC = urllib.parse.quote(CANARY + "/probe", safe="")


def _get(port: int, path: str):
    try:
        r = urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5)
        return r.status, r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.headers


def test_correlated_canary_hit_elevates_to_429_never_blocks(upstream):
    """A single SSRF probe alone does NOT escalate; correlated canary hits ELEVATE the actor's belief
    to a soft 429 (challenge/throttle). NEVER a 403, never a confirmed/block verdict."""
    sink: list[Verdict] = []
    gw, port = _gw(upstream, oob_canary=CANARY, sink=sink)
    try:
        assert gw.settings.oob_receiver is not None   # feature active (entitlement available in tests)
        recv = gw.settings.oob_receiver

        # 1 SSRF probe → relayed (a lead never blocks) and records a pending correlation. Alone, a
        # single hit never escalates (MIN_SUSTAINED_OBS + LCB).
        s0, _ = _get(port, "/fetch?url=" + _SSRF_ENC)
        assert s0 == 200

        # the vulnerable app dereferences the canary several times → unsolicited inbound hits.
        for _ in range(6):
            _fire_hit(recv, "/" + CANARY_SEG, host=CANARY_HOST)

        # subsequent requests DRAIN the hits, fold OOB elevations into the actor's belief, and cross
        # the graduated threshold → a soft, retryable 429 (never a hard block).
        codes = [_get(port, "/home") for _ in range(3)]
        statuses = [c for c, _ in codes]
        assert 429 in statuses, statuses
        assert 403 not in statuses
        first_429 = next(h for s, h in codes if s == 429)
        assert first_429.get("X-Aegis-Action") in ("challenge", "throttle")
        assert first_429.get("Retry-After") is not None

        # the OOB correlation fired (belief-only telemetry) …
        assert any(v.provenance == "intel:aegis:oob_correlation" for v in sink)
        # … and NOTHING the feature produced is a block / confirmed verdict.
        assert all(v.decision != "confirmed" for v in sink)
        assert all(v.action != "block" for v in sink)
    finally:
        gw.settings.stop_oob()
        gw.shutdown()


def test_no_injection_forwarded_request_is_byte_identical():
    """TRANSLATOR-not-generator: the request the upstream receives is byte-identical whether OOB is on
    or off — the feature plants NOTHING (no token, no callback, no canary) into forwarded traffic."""
    _Capture.captured = []
    up = socketserver.TCPServer(("127.0.0.1", 0), _Capture)
    up.daemon_threads = True
    threading.Thread(target=up.serve_forever, daemon=True).start()
    try:
        up_port = up.server_address[1]
        client_path = "/fetch?url=" + _SSRF_ENC
        gw_off, p_off = _gw(up_port, oob_canary=None)
        gw_on, p_on = _gw(up_port, oob_canary=CANARY)
        try:
            assert _get(p_off, client_path)[0] == 200
            assert _get(p_on, client_path)[0] == 200
        finally:
            gw_on.settings.stop_oob()
            gw_off.shutdown()
            gw_on.shutdown()

        assert len(_Capture.captured) == 2
        off, on = _Capture.captured
        # the forwarded request is IDENTICAL with OOB on vs off (path, body, headers).
        assert on["command"] == off["command"]
        assert on["path"] == off["path"] == client_path      # attacker's own bytes, verbatim
        assert on["body"] == off["body"] == b""
        assert on["headers"] == off["headers"]
        # and NO forwarded header carries the canary the client never put in a header (only the url
        # query param the client itself sent references the canary host).
        for name, val in on["headers"].items():
            if name in ("host", "x-forwarded-for"):
                continue
            assert CANARY_HOST not in val, (name, val)
    finally:
        up.shutdown()
        up.server_close()


def test_default_off_is_byte_identical_no_receiver(upstream):
    """No --oob-canary → no receiver, no correlator; an SSRF probe relays exactly as before."""
    gw, port = _gw(upstream, oob_canary=None)
    try:
        assert gw.settings.oob_receiver is None
        assert gw.settings.oob_correlator is None
        assert _get(port, "/fetch?url=" + _SSRF_ENC)[0] == 200   # lead relays (unchanged)
    finally:
        gw.shutdown()


def test_fail_open_on_correlator_error(upstream):
    """A raising correlator (poll/note) must forward traffic, never block."""
    class _Boom:
        canary_host = CANARY_HOST

        def poll_elevations(self, _recv):
            raise RuntimeError("boom")

        def note_lead(self, *_a, **_k):
            raise RuntimeError("boom")

    gw, port = _gw(upstream, oob_canary=CANARY)
    try:
        gw.settings.oob_correlator = _Boom()   # force errors on both OOB paths
        s, _ = _get(port, "/fetch?url=" + _SSRF_ENC)
        assert s == 200                         # forwarded despite the error (fail-open)
        assert _get(port, "/home")[0] == 200
    finally:
        gw.settings.stop_oob()
        gw.shutdown()


def test_benign_inbound_hit_does_not_elevate_anyone(upstream):
    """NEAR-ZERO-FP end-to-end: an unsolicited canary hit with NO actor having sent an SSRF payload
    elevates nobody, so subsequent benign requests are never challenged."""
    gw, port = _gw(upstream, oob_canary=CANARY)
    try:
        recv = gw.settings.oob_receiver
        assert recv is not None
        # a hit lands, but no actor ever targeted the canary → no pending, no elevation.
        for _ in range(6):
            _fire_hit(recv, "/" + CANARY_SEG, host=CANARY_HOST)
        codes = [_get(port, "/home")[0] for _ in range(4)]
        assert all(c == 200 for c in codes), codes
        assert gw.settings.actor_graph.belief("session:127.0.0.1") is None  # never tracked
    finally:
        gw.settings.stop_oob()
        gw.shutdown()
