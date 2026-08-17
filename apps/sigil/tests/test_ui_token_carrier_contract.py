"""Producer-side contract pin (DEFECT-1 red-pen A2): the sovereign cockpit exposes the owner session
token ONLY via the HTML `data-token` carrier — NEVER in a non-HTML body, a response header, or Set-Cookie.

WHY THIS EXISTS. The unified-proxy owner-token scrub
(`integration/vigil_integration/uiproxy.py` `_scrub_html_tokens`) is, by design, HTML-`data-token`-only:
it blanks `data-token="..."` (and `__*_TOKEN__` placeholders) in a relayed `text/html` body so a viewer's
`GET /sovereign/` can never receive the cockpit's embedded owner token — including the `--proxy-only` case
where the cockpit is a REMOTE backend minting its own token the proxy never holds. That scrub is SOUND only
while this producer-side invariant holds: the cockpit must not leak the owner token through any OTHER
channel (a JSON body, a response header, a Set-Cookie), because the proxy would relay those verbatim. This
test pins the invariant so a future cockpit change that starts returning the token elsewhere fails HERE,
rather than silently slipping past the body-only scrub and re-opening the viewer->owner escalation.
Analogous to the SSE whoami-contract pin on the proxy side.

Run: PYTHONPATH=apps/sigil pytest apps/sigil/tests/test_ui_token_carrier_contract.py -q
"""
from __future__ import annotations

import http.client
import json
import re
import tempfile
import threading
import time

from sigil.spine.store import SpineStore
from sigil.ui.server import build_server

TOKEN = "owner-carrier-contract-tok-QQQQQQQQQQQQ"   # the cockpit's shared owner token (self.server.token)
DOMAIN = "cockpit.example.com"
ORIGIN = "https://cockpit.example.com"


def _spine():
    p = tempfile.mktemp(suffix=".jsonl")
    SpineStore(p).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    return p


def _serve():
    srv = build_server(token=TOKEN, port=0, spine_path=_spine(),
                       allowed_hosts=(DOMAIN,), allowed_origins=(ORIGIN,))
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, port


def _req(port, method, path, *, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {"X-SIGIL-Token": TOKEN, "Host": DOMAIN, "Origin": ORIGIN}
    if body is not None:
        h["Content-Type"] = "application/json"
    try:
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        raw = r.read()
        return r.status, r.getheader("Content-Type", "") or "", r.getheaders(), raw
    finally:
        conn.close()


# A representative slice of the owner-token-authenticated read/action surface a browser (or the relaying
# proxy) can reach — every one resolves the owner token to OWNER_PRINCIPAL, so if any of them echoed the
# token it would be a real leak the HTML-only scrub could not stop. Plus GET / (the KNOWN html carrier).
_ROUTES = [
    ("GET", "/", None),
    ("GET", "/index.html", None),
    ("GET", "/api/whoami", None),
    ("GET", "/api/settings", None),
    ("GET", "/api/accounts", None),
    ("GET", "/api/snapshot", None),
    ("GET", "/api/graph", None),
    ("POST", "/api/login", json.dumps({"token": TOKEN}).encode()),
]


def test_html_index_is_the_only_place_the_owner_token_appears():
    """Positive control (anti-vacuous): the token DOES appear at GET / — and ONLY inside a `data-token`
    attribute (the carrier the proxy scrubs). Proves the harness token is real, so the negative assertions
    below can actually detect a leak, and that the cockpit has no SECOND in-HTML token placement."""
    srv, port = _serve()
    try:
        st, ctype, _hdrs, raw = _req(port, "GET", "/")
        assert st == 200 and "text/html" in ctype
        body = raw.decode("utf-8", "replace")
        assert TOKEN in body, "the cockpit index must embed the token (else this producer test is vacuous)"
        # blank every data-token="..."/'...' occurrence; the token must not survive anywhere else in the HTML
        stripped = re.sub(r'data-token\s*=\s*"[^"]*"', 'data-token=""', body)
        stripped = re.sub(r"data-token\s*=\s*'[^']*'", "data-token=''", stripped)
        assert TOKEN not in stripped, "the owner token leaked OUTSIDE the data-token carrier in the HTML index"
    finally:
        srv.shutdown()
        srv.server_close()


def test_no_nonhtml_body_and_no_response_header_returns_the_owner_token():
    """The producer invariant the HTML-only scrub depends on: on EVERY route, no response header (incl.
    Set-Cookie) carries the owner token, and no NON-HTML body contains it. A future cockpit change that
    returns the token in a JSON body / header / cookie fails HERE (the scrub is body-and-HTML-only)."""
    srv, port = _serve()
    try:
        for method, path, body in _ROUTES:
            st, ctype, hdrs, raw = _req(port, method, path, body=body)
            for hk, hv in hdrs:
                assert TOKEN not in (hv or ""), f"{method} {path}: owner token leaked in response header {hk!r}"
            assert "set-cookie" not in {k.lower() for k, _ in hdrs}, (
                f"{method} {path}: unexpected Set-Cookie (a token-bearing cookie would bypass the body scrub)")
            if "text/html" not in ctype:
                assert TOKEN.encode() not in raw, (
                    f"{method} {path} ({ctype or 'no-ctype'}, HTTP {st}): a NON-HTML body returned the owner "
                    "token — the proxy's HTML-`data-token`-only scrub would relay it verbatim (viewer->owner).")
    finally:
        srv.shutdown()
        srv.server_close()
