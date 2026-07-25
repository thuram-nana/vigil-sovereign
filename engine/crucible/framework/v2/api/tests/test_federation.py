"""
API federation guards (VIGIL COMMAND P1) — the gated api plane behind the unified reverse
proxy. Mirrors the console federation test on the api side (which the console does NOT share
code with — api/guard.check_same_origin is only used here, so it needs its own coverage):

  1. A CSP header is present on api responses.
  2. The Host/Origin allowlist is DEFAULT-EMPTY = loopback-only (unchanged); an explicit
     allowlist admits ONLY the exact configured proxy domain (a substring/suffix/subdomain/
     wrong-port/wrong-scheme is refused), and never relaxes the anti-CSRF custom-header proof.

The api still BINDS loopback (the proxy is the only public listener).
Run: PYTHONPATH=engine/crucible pytest framework/v2/api/tests/test_federation.py -q
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

from framework.v2.api import server


@contextmanager
def _running(**serve_kw):
    httpd = server.serve(host="127.0.0.1", port=0, **serve_kw)
    port = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{port}/api/v1"
    finally:
        httpd.shutdown()
        httpd.server_close()
        th.join(timeout=5)


def _post(url, *, headers=None, csrf=True):
    req = urllib.request.Request(url, method="POST", data=json.dumps({"tool": "x"}).encode())
    if csrf:
        req.add_header("X-Requested-With", "fetch")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)


def test_api_csp_header_present():
    with _running() as base:
        with urllib.request.urlopen(base + "/status", timeout=5) as r:  # noqa: S310
            assert "default-src 'self'" in r.headers.get("Content-Security-Policy", "")
            assert r.headers.get("X-Content-Type-Options") == "nosniff"


def test_api_default_is_loopback_only():
    with _running() as base:
        st, _ = _post(base + "/tool/invoke",
                      headers={"Host": "vigil.example.com", "Origin": "https://vigil.example.com",
                               "Sec-Fetch-Site": "same-origin"})
        assert st == 403  # no allowlist configured → foreign proxy Host refused (unchanged)


def test_api_allowlisted_domain_accepted_others_refused():
    with _running(allowed_hosts=["vigil.example.com"],
                  allowed_origins=["https://vigil.example.com"]) as base:
        # the exact configured domain passes the guard (reaches the gated action → not 403)
        st, _ = _post(base + "/tool/invoke",
                      headers={"Host": "vigil.example.com", "Origin": "https://vigil.example.com",
                               "Sec-Fetch-Site": "same-origin"})
        assert st != 403
        # HOST exactness: substring/suffix/subdomain/wrong-port refused. Origin is OMITTED here so the
        # HOST check is what's exercised — otherwise a still-exact Origin check would mask a Host regression
        # (this is the exact→substring mutation the guard must defeat; verified load-bearing by mutation).
        for host in ("evil.example.com", "vigil.example.com.attacker.com", "evilvigil.example.com",
                     "a.vigil.example.com", "vigil.example.com:8443"):
            stx, _ = _post(base + "/tool/invoke", headers={"Host": host, "Sec-Fetch-Site": "same-origin"})
            assert stx == 403, f"host exactness: {host!r} must be refused, got {stx}"
        # ORIGIN exactness: allowlisted-exact Host, but a substring/suffix/foreign Origin → refused.
        for origin in ("https://vigil.example.com.attacker.com", "https://evilvigil.example.com",
                       "https://evil.example.com"):
            sto, _ = _post(base + "/tool/invoke",
                           headers={"Host": "vigil.example.com", "Origin": origin,
                                    "Sec-Fetch-Site": "same-origin"})
            assert sto == 403, f"origin exactness: {origin!r} must be refused, got {sto}"


def test_api_allowlist_does_not_relax_custom_header():
    with _running(allowed_hosts=["vigil.example.com"]) as base:
        st, _ = _post(base + "/tool/invoke",
                      headers={"Host": "vigil.example.com", "Sec-Fetch-Site": "same-origin"}, csrf=False)
        assert st == 403  # no X-Requested-With → refused regardless of the allowlist
