"""Log injection on the gated API's attribution audit line (CodeQL py/log-injection,
`api/server.py::_log_attribution`).

The attribution log exists to name WHO was authorized or refused. It interpolated the claimed
`X-VIGIL-Principal` / `X-VIGIL-Role` headers and the request path raw. A header value may be obs-folded
(`\\r\\n` + whitespace), and the stdlib keeps the fold inside the value, so a caller with NO valid hop
signature could append a second physical line reading `api action authorized: principal=owner ...` to the
record of its own refusal. VT / FF / 0x1c / 0x85 / ESC arrive the same way, and ESC also arrives in the path.

The same caller could also forge with PRINTABLE text alone: a claimed principal of
`alice INFO crucible.api.authz api action authorized: principal=owner role=owner via=hop ...` sat inside the
REFUSED record verbatim, so a search for `api action authorized: principal=owner` matched a refusal, and a
claimed `owner role=owner via=hop` made a first-occurrence key=value reader see a verified owner. So the
`key=value` fields and the path are logged as ONE token each (space, `=` and `"` escaped too), and the
backslash is escaped everywhere so the encoding is injective.

These tests drive the REAL handler over a raw socket (urllib refuses to send such headers) and assert on
the emitted record. The 403 response body is deliberately unchanged."""
from __future__ import annotations

import json
import logging
import socket
import threading
import time
from contextlib import contextmanager

from framework.v2.api import server

_LOGGER = "crucible.api.authz"
_FORGED = "INFO crucible.api.authz api action authorized: principal=owner role=owner via=hop POST /api/v1/run"


@contextmanager
def _running(hop_key: str = ""):
    httpd = server.serve(host="127.0.0.1", port=0, registry=None, hop_key=hop_key,
                         import_store_factory=lambda: None)
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()
        th.join(timeout=5)


def _raw_post(port: int, target: bytes, headers: bytes) -> tuple[int, dict]:
    req = (b"POST " + target + b" HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Requested-With: fetch\r\n" % port
           + b"Connection: close\r\nContent-Length: 2\r\n" + headers + b"\r\n{}")
    with socket.create_connection(("127.0.0.1", port), timeout=5) as c:
        c.sendall(req)
        out = b""
        while True:
            chunk = c.recv(65536)
            if not chunk:
                break
            out += chunk
    head, _, body = out.partition(b"\r\n\r\n")
    return int(head.split()[1]), json.loads(body)


def _lines(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == _LOGGER]


def _assert_one_inert_line(lines: list[str]) -> str:
    assert len(lines) == 1, lines
    line = lines[0]
    bad = [hex(ord(ch)) for ch in line if not ch.isprintable()]
    assert not bad, f"non-printable characters reached the attribution log: {bad} in {line!r}"
    assert len(line.splitlines()) == 1
    return line


def _fields(line: str) -> dict:
    """Parse a record the way a log pipeline would: split on spaces; every `k=v` token before the method is
    a field. Returns the fields plus the method and path, and fails if a key repeats (a spoofed field)."""
    toks = line.split(" ")
    assert toks[:2] == ["api", "action"] and toks[2] in ("authorized:", "REFUSED:"), toks[:3]
    out: dict = {"verb": toks[2]}
    i = 3
    while "=" in toks[i]:
        k, _, v = toks[i].partition("=")
        assert k not in out, f"field {k!r} appears twice in {line!r}"
        out[k] = v
        i += 1
    out["method"], out["path"] = toks[i], toks[i + 1]
    return out


def test_obs_folded_principal_cannot_forge_an_authorized_line(caplog):
    with _running() as port, caplog.at_level(logging.INFO, logger=_LOGGER):
        st, body = _raw_post(port, b"/api/v1/x", b"X-VIGIL-Role: viewer\r\n"
                             b"X-VIGIL-Principal: alice\r\n\t" + _FORGED.encode() + b"\r\n")
    assert st == 403
    line = _assert_one_inert_line(_lines(caplog))
    # ONE record, and it is the refusal; the injected text survives only as visibly-escaped data inside it.
    assert line.startswith("api action REFUSED: principal=alice\\x0d\\x0a\\x09INFO\\x20crucible.api.authz")
    assert " via=hop-unverified POST /api/v1/x (unverified role assertion" in line
    assert "api action authorized" not in line and "principal=owner" not in line
    assert _fields(line)["via"] == "hop-unverified" and _fields(line)["role"] == "viewer"
    # the response still carries the claimed value verbatim — only the LOGGED copy is escaped.
    assert body["principal"] == "alice\r\n\t" + _FORGED and body["role"] == "viewer"


def test_obs_folded_role_cannot_forge_a_line(caplog):
    with _running() as port, caplog.at_level(logging.INFO, logger=_LOGGER):
        st, body = _raw_post(port, b"/api/v1/x", b"X-VIGIL-Role: viewer\r\n FORGED-ROLE-LINE\r\n")
    assert st == 403
    line = _assert_one_inert_line(_lines(caplog))
    assert "principal=(unnamed) role=viewer\\x0d\\x0a\\x20FORGED-ROLE-LINE via=hop-unverified" in line
    assert body["role"] == "viewer\r\n FORGED-ROLE-LINE"


def test_other_line_breakers_and_escape_in_a_header_are_escaped(caplog):
    # VT, FF, NEL (0x85), FS (0x1c) all split a line for `str.splitlines`-style viewers; ESC drives a terminal.
    with _running() as port, caplog.at_level(logging.INFO, logger=_LOGGER):
        st, _ = _raw_post(port, b"/api/v1/x", b"X-VIGIL-Role: v\r\n"
                          b"X-VIGIL-Principal: a\x0bb\x0cc\x85d\x1ce\x1b[2Jf\r\n")
    assert st == 403
    line = _assert_one_inert_line(_lines(caplog))
    assert "principal=a\\x0bb\\x0cc\\x85d\\x1ce\\x1b[2Jf role=v " in line


def test_escape_sequences_in_the_path_are_escaped(caplog):
    with _running() as port, caplog.at_level(logging.INFO, logger=_LOGGER):
        st, _ = _raw_post(port, b"/api/v1/x\x1b[1A\x1b[2K", b"X-VIGIL-Role: v\r\n")
    assert st == 403
    line = _assert_one_inert_line(_lines(caplog))
    assert " POST /api/v1/x\\x1b[1A\\x1b[2K (unverified role assertion" in line


def test_an_oversized_path_and_principal_are_capped(caplog):
    with _running() as port, caplog.at_level(logging.INFO, logger=_LOGGER):
        st, _ = _raw_post(port, b"/api/v1/" + b"A" * 30000,
                          b"X-VIGIL-Role: v\r\nX-VIGIL-Principal: " + b"P" * 30000 + b"\r\n")
    assert st == 403
    line = _assert_one_inert_line(_lines(caplog))
    assert len(line) < 1000, f"a 60 kB request was logged as a {len(line)}-character line"
    assert "P" * 150 in line and "A" * 150 in line and "unverified role assertion" in line


def test_a_legitimate_attribution_line_is_unchanged(caplog):
    with _running() as port, caplog.at_level(logging.INFO, logger=_LOGGER):
        st, _ = _raw_post(port, b"/api/v1/does-not-exist", b"")          # direct credential-holder
        st2, _ = _raw_post(port, b"/api/v1/x", b"X-VIGIL-Role: viewer\r\nX-VIGIL-Principal: Zo\xeb.Smith-2\r\n")
    assert st2 == 403
    assert _lines(caplog) == [
        "api action authorized: principal=on-host-operator role=owner via=direct-credential "
        "POST /api/v1/does-not-exist",
        "api action REFUSED: principal=Zoë.Smith-2 role=viewer via=hop-unverified POST /api/v1/x "
        "(unverified role assertion (bad/expired hop signature))",
    ]


def test_a_printable_only_forged_authorized_entry_is_not_reproduced(caplog):
    # no control character, no fold — just spaces: the whole forged entry is ONE escaped principal token.
    forged = b"alice " + _FORGED.encode()
    with _running() as port, caplog.at_level(logging.INFO, logger=_LOGGER):
        st, body = _raw_post(port, b"/api/v1/x", b"X-VIGIL-Role: viewer\r\nX-VIGIL-Principal: " + forged + b"\r\n")
    assert st == 403
    line = _assert_one_inert_line(_lines(caplog))
    assert line.startswith("api action REFUSED: principal=alice\\x20INFO\\x20crucible.api.authz\\x20api")
    assert "api action authorized" not in line and "principal=owner" not in line and "via=hop " not in line
    f = _fields(line)
    assert (f["verb"], f["role"], f["via"], f["method"], f["path"]) == (
        "REFUSED:", "viewer", "hop-unverified", "POST", "/api/v1/x")
    assert body["principal"] == forged.decode()                      # the response is not rewritten


def test_a_claimed_principal_and_role_cannot_spoof_the_via_or_role_fields(caplog):
    with _running() as port, caplog.at_level(logging.INFO, logger=_LOGGER):
        st, _ = _raw_post(port, b"/api/v1/x", b"X-VIGIL-Role: owner via=hop\r\n"
                          b"X-VIGIL-Principal: owner role=owner via=hop\r\n")
    assert st == 403
    line = _assert_one_inert_line(_lines(caplog))
    f = _fields(line)                                 # each key exactly once — no first/last-occurrence game
    assert f["principal"] == "owner\\x20role\\x3downer\\x20via\\x3dhop"
    assert f["role"] == "owner\\x20via\\x3dhop"
    assert f["via"] == "hop-unverified"


def test_a_quote_or_equals_in_the_path_is_one_token(caplog):
    with _running() as port, caplog.at_level(logging.INFO, logger=_LOGGER):
        st, _ = _raw_post(port, b'/api/v1/x;via=hop"', b"X-VIGIL-Role: v\r\n")
    assert st == 403
    line = _assert_one_inert_line(_lines(caplog))
    assert _fields(line)["path"] == "/api/v1/x;via\\x3dhop\\x22"


def test_a_real_escape_and_a_typed_backslash_sequence_log_differently(caplog):
    with _running() as port, caplog.at_level(logging.INFO, logger=_LOGGER):
        _raw_post(port, b"/api/v1/x", b"X-VIGIL-Role: v\r\nX-VIGIL-Principal: A\x1bB\r\n")
        _raw_post(port, b"/api/v1/x", b"X-VIGIL-Role: v\r\nX-VIGIL-Principal: A\\x1bB\r\n")
    real, typed = _lines(caplog)
    assert real != typed
    assert _fields(real)["principal"] == "A\\x1bB" and _fields(typed)["principal"] == "A\\x5cx1bB"


def test_a_non_ascii_hop_signature_is_an_attributed_refusal_not_a_dropped_request(caplog):
    # with a hop key configured, a non-ASCII X-VIGIL-Role-Sig used to raise inside the verifier, so the
    # connection dropped and NO refusal was recorded. It must be an ordinary, attributed 403.
    ts = str(int(time.time())).encode()
    with _running(hop_key="k" * 32) as port, caplog.at_level(logging.INFO, logger=_LOGGER):
        st, body = _raw_post(port, b"/api/v1/tool/invoke", b"X-VIGIL-Principal: mallory\r\nX-VIGIL-Role: owner\r\n"
                             b"X-VIGIL-Role-Ts: " + ts + b"\r\nX-VIGIL-Role-Sig: \xe9\r\n")
    assert st == 403 and body["principal"] == "mallory"
    line = _assert_one_inert_line(_lines(caplog))
    assert line.startswith("api action REFUSED: principal=mallory role=owner via=hop-unverified "
                           "POST /api/v1/tool/invoke (unverified role assertion")


class _Stub:
    command = "POST"


def test_via_and_reason_are_escaped_too(caplog):
    actor = {"principal": "p", "role": "r", "via": "hop\nX"}
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        server.ApiHandler._log_attribution(_Stub(), "/api/v1/x", actor, False, "why\u2028FORGED\x1b[2J")
    line = _assert_one_inert_line(_lines(caplog))
    assert line == "api action REFUSED: principal=p role=r via=hop\\x0aX POST /api/v1/x (why\\u2028FORGED\\x1b[2J)"


def test_every_key_value_field_is_one_token(caplog):
    actor = {"principal": "p q", "role": "r=s", "via": 'v "w'}
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        server.ApiHandler._log_attribution(_Stub(), "/api/v1/x", actor, False, "a reason with spaces")
    line = _assert_one_inert_line(_lines(caplog))
    assert line == ("api action REFUSED: principal=p\\x20q role=r\\x3ds via=v\\x20\\x22w POST /api/v1/x "
                    "(a reason with spaces)")


def test_log_safe_escapes_every_non_printable_not_just_cr_lf():
    f = server._log_safe
    hostile = "a\rb\nc\x0bd\x0ce\x1cf\x1dg\x1eh\x85i\u2028j\u2029k\x1bl\x00m\x7fn\u202eo\u200bp\U000e0001q"
    out = f(hostile)
    assert out.isprintable() and len(out.splitlines()) == 1
    assert out == ("a\\x0db\\x0ac\\x0bd\\x0ce\\x1cf\\x1dg\\x1eh\\x85i\\u2028j\\u2029k\\x1bl\\x00m\\x7fn"
                   "\\u202eo\\u200bp\\U000e0001q")
    assert f("\ud800") == "\\ud800"
    for ok in ("/api/v1/tool/invoke", "on-host-operator", "Zoë 山田", "(unnamed)", ""):
        assert f(ok) == ok
    assert f(None) == "None" and f(7) == "7"
    capped = f("B" * 5000)
    assert len(capped) < 240 and capped.startswith("B" * 200) and "4800" in capped
    assert f("C" * 200) == "C" * 200


def test_log_safe_is_injective_and_token_mode_escapes_the_record_syntax():
    f = server._log_safe
    assert f("\\") == "\\x5c" and f("A\x1bB") != f("A\\x1bB")               # backslash escaped: injective
    assert f('a b=c"d') == 'a b=c"d'                                     # default mode (the reason): readable
    assert f('a b=c"d', token=True) == "a\\x20b\\x3dc\\x22d"              # token mode: one token
    for ok in ("on-host-operator", "owner", "hop-unverified", "(unnamed)", "alice.smith-2", "/api/v1/run"):
        assert f(ok, token=True) == ok                                 # every real field value is unchanged
    # a value cannot fake the truncation marker in token mode: the marker's space would be escaped.
    fake = f("P...[+4800 chars]", token=True)
    real = f("P" * 5000, token=True)
    assert fake == "P...[+4800\\x20chars]" and real.endswith("...[+4800 chars]")
