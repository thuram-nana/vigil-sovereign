"""Log injection on the bridge denial audit line (CodeQL py/log-injection, `bridge/server.py::_deny`).

`_deny` logs the request PATH of a peer that has not authenticated yet (the 404s run before the envelope
and rebind gates). The stdlib refuses whitespace in a request target, but ESC / NUL / DEL / BS arrive
intact and there was no length cap, so an unauthenticated peer could write terminal escape sequences
(erase the previous audit line, clear the screen) or a 64 KiB line into the WARNING log, which goes to
stderr by default. The escape is injective (the backslash itself is escaped), so a real ESC and a typed
backslash sequence cannot log identically, and a request the static handler cannot even resolve (an
embedded NUL) is refused AND recorded rather than dropped. These tests drive the REAL server over a raw
socket and assert on the emitted record; the JSON response body is deliberately left unchanged."""
import logging
import socket
import tempfile
import threading
import time

from sigil.bridge import server as bridge_server
from sigil.bridge.server import build_server
from sigil.reuse import generate_keypair

OWNER = generate_keypair()
_LOGGER = "sigil.bridge.server"


def _serve():
    srv = build_server(addr="127.0.0.1", port=0, spine_path=tempfile.mktemp(suffix=".jsonl"),
                       trusted_pubkey=OWNER.public_key_b64)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, srv.server_address[1]


def _raw(port, request_line: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as c:
        c.sendall(request_line + b" HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n" % port)
        out = b""
        while True:
            chunk = c.recv(65536)
            if not chunk:
                break
            out += chunk
    return out


def _denials(caplog):
    return [r.getMessage() for r in caplog.records if r.name == _LOGGER and "bridge denied" in r.getMessage()]


def _assert_inert(line: str):
    bad = [hex(ord(ch)) for ch in line if not ch.isprintable()]
    assert not bad, f"non-printable characters reached the audit log: {bad} in {line!r}"


def test_escape_sequences_in_the_path_are_escaped_in_the_denial_log(caplog):
    srv, port = _serve()
    try:
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            resp = _raw(port, b"GET /x\x1b[1A\x1b[2K")           # CSI cursor-up + erase-line
            assert resp.startswith(b"HTTP/1.0 404") or resp.startswith(b"HTTP/1.1 404")
        lines = _denials(caplog)
        assert len(lines) == 1, lines
        _assert_inert(lines[0])
        # the evidence is kept, visibly escaped — not silently dropped.
        assert lines[0] == "bridge denied: GET /x\\x1b[1A\\x1b[2K -> 404 (not found)"
    finally:
        srv.shutdown()
        srv.server_close()


def test_nul_del_backspace_in_the_path_are_escaped(caplog):
    srv, port = _serve()
    try:
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            _raw(port, b"POST /y\x00\x7f\x08\x08")
        lines = _denials(caplog)
        assert len(lines) == 1, lines
        _assert_inert(lines[0])
        assert "/y\\x00\\x7f\\x08\\x08 -> 404" in lines[0]
    finally:
        srv.shutdown()
        srv.server_close()


def test_an_oversized_path_is_capped_in_the_denial_log(caplog):
    srv, port = _serve()
    try:
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            _raw(port, b"GET /" + b"A" * 60000)
        lines = _denials(caplog)
        assert len(lines) == 1, lines
        assert len(lines[0]) < 400, f"a 60 kB path was logged as a {len(lines[0])}-character line"
        assert "A" * 150 in lines[0] and "-> 404 (not found)" in lines[0]     # prefix kept, record intact
    finally:
        srv.shutdown()
        srv.server_close()


def test_a_legitimate_denial_line_is_unchanged(caplog):
    srv, port = _serve()
    try:
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            resp = _raw(port, b"GET /no/such-route_1.txt")
        assert _denials(caplog) == ["bridge denied: GET /no/such-route_1.txt -> 404 (not found)"]
        assert resp.endswith(b'{"error":"not found"}') or b'"not found"' in resp   # body untouched
    finally:
        srv.shutdown()
        srv.server_close()


def test_a_real_escape_and_a_typed_backslash_sequence_log_differently(caplog):
    srv, port = _serve()
    try:
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            _raw(port, b"GET /x\x1bB")                                # a real ESC byte
            _raw(port, b"GET /x\\x1bB")                               # the 7 printable characters
        assert _denials(caplog) == ["bridge denied: GET /x\\x1bB -> 404 (not found)",
                                    "bridge denied: GET /x\\x5cx1bB -> 404 (not found)"]
    finally:
        srv.shutdown()
        srv.server_close()


def test_an_unresolvable_static_path_is_refused_and_recorded_not_dropped(caplog):
    # an embedded NUL used to raise inside Path.resolve(): the connection dropped and NO denial was logged.
    srv, port = _serve()
    try:
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            resp = _raw(port, b"GET /static/\x00\x1b[2J")
        assert resp.startswith(b"HTTP/1.0 404") or resp.startswith(b"HTTP/1.1 404"), resp
        assert _denials(caplog) == ["bridge denied: GET /static/\\x00\\x1b[2J -> 404 (not found)"]
    finally:
        srv.shutdown()
        srv.server_close()


class _Stub:
    """Just enough of the handler for `_deny`: the logged copy vs. the response body."""
    command = "GET"

    def __init__(self, path):
        self.path = path
        self.sent = None

    def _json(self, obj, code=200):
        self.sent = (obj, code)


def test_the_reason_is_escaped_in_the_log_but_the_response_body_is_not_rewritten(caplog):
    stub = _Stub("/api/action")
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        bridge_server.Handler._deny(stub, 400, "bad request: x\r\nFORGED\x1b[2J")
    lines = _denials(caplog)
    assert len(lines) == 1, lines
    _assert_inert(lines[0])
    assert lines[0] == "bridge denied: GET /api/action -> 400 (bad request: x\\x0d\\x0aFORGED\\x1b[2J)"
    assert stub.sent == ({"error": "bad request: x\r\nFORGED\x1b[2J"}, 400)   # the LOGGED copy only


def test_log_safe_escapes_every_non_printable_not_just_cr_lf():
    f = bridge_server._log_safe
    # every character `str.splitlines` breaks on, plus ESC / NUL / DEL and the bidi/zero-width formats.
    hostile = "a\rb\nc\x0bd\x0ce\x1cf\x1dg\x1eh\x85i\u2028j\u2029k\x1bl\x00m\x7fn\u202eo\u200bp\U000e0001q"
    out = f(hostile)
    assert out.isprintable() and len(out.splitlines()) == 1
    assert out == ("a\\x0db\\x0ac\\x0bd\\x0ce\\x1cf\\x1dg\\x1eh\\x85i\\u2028j\\u2029k\\x1bl\\x00m\\x7fn"
                   "\\u202eo\\u200bp\\U000e0001q")
    assert f("\ud800") == "\\ud800"                              # a lone surrogate cannot break a handler
    # printable text — including spaces and non-ASCII letters — is returned unchanged.
    for ok in ("/api/pending", "stale request (timestamp outside freshness window)", "Zoë 山田", ""):
        assert f(ok) == ok
    assert f(None) == "None" and f(404) == "404"                  # never raises on a non-string
    # injective: the backslash is escaped too, so escaped "evidence" cannot be typed in by a peer.
    assert f("\\") == "\\x5c" and f("/x\x1bB") != f("/x\\x1bB")
    capped = f("B" * 5000)
    assert len(capped) < 240 and capped.startswith("B" * 200) and "4800" in capped
    assert f("C" * 200) == "C" * 200                             # exactly at the cap: untouched
