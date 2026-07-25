"""
Console federation guards (VIGIL COMMAND P1) — the offense console behind the unified
reverse proxy. Pins two properties:

  1. A strict `'self'` CSP (+ nosniff + no-referrer) is on EVERY response (reads/actions),
     so the offense plane matches the sovereign posture under one origin.
  2. The Host/Origin allowlist is DEFAULT-EMPTY = loopback-only (byte-identical to before);
     an explicit operator allowlist admits ONLY the exact configured proxy domain, and every
     other Host/Origin is still refused. The custom-header + Sec-Fetch proofs still apply.

The console still BINDS loopback (the proxy is the only public listener).
Run: PYTHONPATH=engine/crucible pytest framework/v2/console/tests/test_federation.py -q
"""
from __future__ import annotations

import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

from framework.v2.console import server


@contextmanager
def _running(**serve_kw):
    httpd = server.serve(host="127.0.0.1", port=0, **serve_kw)
    port = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{port}", port
    finally:
        httpd.shutdown()
        httpd.server_close()
        th.join(timeout=5)


def _post(url, *, headers=None):
    req = urllib.request.Request(url, method="POST", data=b"{}")
    req.add_header("X-Requested-With", "vigil-ui")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as r:  # noqa: S310 (loopback test)
        return r.status, dict(r.headers)


def test_csp_on_reads_and_actions():
    with _running() as (base, _port):
        _st, hdrs = _get(base + "/api/status")
        assert "default-src 'self'" in hdrs.get("Content-Security-Policy", "")
        assert hdrs.get("X-Content-Type-Options") == "nosniff"
        # a refused POST still carries the CSP header
        _st, phdrs = _post(base + "/api/launch/scan", headers={"Host": "evil.example"})
        assert "default-src 'self'" in phdrs.get("Content-Security-Policy", "")


def test_default_is_loopback_only_foreign_host_refused():
    # no allowlist configured → today's behaviour: a foreign proxy Host is refused.
    with _running() as (base, _port):
        st, _ = _post(base + "/api/launch/scan",
                      headers={"Host": "vigil.example.com", "Origin": "https://vigil.example.com",
                               "Sec-Fetch-Site": "same-origin"})
        assert st == 403


def test_allowlisted_domain_is_accepted_others_still_refused():
    with _running(allowed_hosts=["vigil.example.com"],
                  allowed_origins=["https://vigil.example.com"]) as (base, _port):
        # the EXACT configured proxy Host+Origin passes the guard (reaches the router → not 403)
        st, _ = _post(base + "/api/launch/scan",
                      headers={"Host": "vigil.example.com", "Origin": "https://vigil.example.com",
                               "Sec-Fetch-Site": "same-origin"})
        assert st != 403, "an allowlisted proxy domain must pass the CSRF/rebind guard"
        # a DIFFERENT domain is still refused even with the allowlist configured
        st2, _ = _post(base + "/api/launch/scan",
                       headers={"Host": "evil.example.com", "Origin": "https://evil.example.com",
                                "Sec-Fetch-Site": "same-origin"})
        assert st2 == 403
        # EXACTNESS: a substring/suffix/subdomain of the allowed host must NOT slip through (this is the
        # exact→substring/suffix regression the match must defeat — the production match is frozenset
        # membership, i.e. exact). All of these are refused:
        for bad in ("vigil.example.com.attacker.com",  # allowed host is a substring/prefix
                    "evilvigil.example.com",             # allowed host is a suffix
                    "a.vigil.example.com",               # subdomain
                    "vigil.example.com:8443"):           # wrong port
            stx, _ = _post(base + "/api/launch/scan",
                           headers={"Host": bad, "Sec-Fetch-Site": "same-origin"})
            assert stx == 403, f"exactness: Host {bad!r} must be refused, got {stx}"
        # right Host but wrong Origin → still refused (exact match, no rebinding)
        st3, _ = _post(base + "/api/launch/scan",
                       headers={"Host": "vigil.example.com", "Origin": "https://evil.example.com"})
        assert st3 == 403
        # loopback still works too (the allowlist is additive, not a replacement)
        st4, _ = _post(base + "/api/launch/scan", headers={"Sec-Fetch-Site": "same-origin"})
        assert st4 != 403


def test_allowlist_does_not_relax_the_custom_header_requirement():
    # even an allowlisted domain must still present the custom header (a cross-site form cannot).
    with _running(allowed_hosts=["vigil.example.com"]) as (base, _port):
        req = urllib.request.Request(base + "/api/launch/scan", method="POST", data=b"{}")
        req.add_header("Host", "vigil.example.com")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        assert code == 403  # no X-Requested-With → refused regardless of the allowlist
