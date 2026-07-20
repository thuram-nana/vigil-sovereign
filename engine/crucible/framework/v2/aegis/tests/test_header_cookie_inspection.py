"""
AEGIS — header / cookie injection surface (candidate_values extension).

The request-side parse-proof oracles (sqli_attempt / command_injection_attempt) now also cover a
CURATED set of free-text request headers and decoded Cookie values. The contract:

  * a SQL string-literal break-out / shell command construct in a Cookie or a curated header
    (X-Forwarded-For, Referer, ...) is a CONFIRMED block, with a re-runnable certificate,
  * NORMAL header/cookie traffic — a real User-Agent, a `tool/version` UA, an XFF IP list, a session
    cookie, a benign Referer — never trips (the near-zero-FP guarantee the review pinned),
  * structured / hop-by-hop / credential headers (Host, Content-Type, Authorization, ...) are NOT
    inspected (not in the curated allowlist),
  * cookie values are percent-decoded so an encoded payload is visible.
"""

from __future__ import annotations

import urllib.parse

from framework.v2.aegis.inspect import candidate_values, inspect_request


def _req(headers, *, path="/", body=None):
    return inspect_request("GET", path, headers, body, enforce=True)


# --------------------------------------------------------------------------- candidate extraction

def test_cookie_and_curated_headers_become_candidates():
    headers = [("Cookie", "sid=abc123; theme=dark"),
               ("User-Agent", "Mozilla/5.0"),
               ("X-Forwarded-For", "203.0.113.7"),
               ("Host", "example.com"),                 # excluded (structured)
               ("Authorization", "Bearer secrettoken"),  # excluded (credential)
               ("Accept", "text/html")]                  # excluded (negotiation)
    got = dict(candidate_values("/", headers, None))
    assert got.get("cookie:sid") == "abc123"
    assert got.get("cookie:theme") == "dark"
    assert got.get("header:user-agent") == "Mozilla/5.0"
    assert got.get("header:x-forwarded-for") == "203.0.113.7"
    # excluded surfaces must NOT appear
    assert not any(n.startswith("header:host") for n in got)
    assert not any(n.startswith("header:authorization") for n in got)
    assert not any(n.startswith("header:accept") for n in got)


def test_cookie_value_is_percent_decoded():
    got = dict(candidate_values("/", [("Cookie", "q=a%27b")], None))
    assert got.get("cookie:q") == "a'b"   # %27 -> '


# --------------------------------------------------------------------------- confirmed blocks

def test_sqli_in_cookie_is_confirmed_with_certificate():
    # a URL-encoded SQL breakout in a cookie -> decoded -> confirmed sqli_attempt.
    v = _req([("Cookie", "tracking=" + urllib.parse.quote("x' OR '1'='1", safe=""))])
    assert v is not None and v.decision == "confirmed" and v.attack_class == "sqli_attempt"
    assert v.certificate is not None and v.certificate.reverify() is True
    assert v.contributing == ["cookie:tracking"]


def test_command_injection_in_xff_header_is_confirmed():
    v = _req([("X-Forwarded-For", "127.0.0.1; cat /etc/passwd")])
    assert v is not None and v.decision == "confirmed"
    assert v.attack_class == "command_injection_attempt"
    assert v.certificate is not None and v.certificate.reverify() is True


def test_sqli_in_referer_header_is_confirmed():
    v = _req([("Referer", "https://x/p?q=1' UNION SELECT username,password FROM users--")])
    assert v is not None and v.attack_class == "sqli_attempt" and v.certificate.reverify()


# --------------------------------------------------------------------------- near-zero-FP corpus

def test_normal_user_agents_do_not_trip():
    uas = [
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
        "python-requests/2.25.1",
        "curl/7.88.1",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "PostmanRuntime/7.32.3",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
    ]
    for ua in uas:
        assert _req([("User-Agent", ua)]) is None, ua


def test_normal_cookies_and_forwarded_headers_do_not_trip():
    benign = [
        [("Cookie", "session=9f8b7a6c5d4e3f2a1b0c; csrftoken=abc123def456; theme=light")],
        [("X-Forwarded-For", "203.0.113.7, 198.51.100.4, 10.0.0.1")],
        [("Referer", "https://example.com/products?id=42&sort=price")],
        [("X-Real-IP", "192.0.2.55")],
        [("From", "user@example.com")],
        [("X-Api-Version", "2024-01-15")],
        [("Cookie", "prefs=%7B%22lang%22%3A%22en%22%7D")],   # url-encoded JSON, decodes benign
        [("Forwarded", "for=192.0.2.60;proto=https;by=203.0.113.43")],
    ]
    for headers in benign:
        assert _req(headers) is None, headers


def test_excluded_headers_are_not_inspected_even_with_a_payload():
    # a payload smuggled into a NON-curated header (Host / Authorization) is not inspected here — the
    # curated allowlist is deliberately bounded (those surfaces have their own defences).
    assert _req([("Host", "x'; DROP TABLE users--")]) is None
    assert _req([("Accept-Language", "en; cat /etc/passwd -a")]) is None
