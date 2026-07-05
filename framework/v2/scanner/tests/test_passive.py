"""
Passive check library — real response analysis, no traffic.

Each test feeds a concrete response and asserts the exact findings (and their
absence on clean input). These are deterministic facts about bytes, so the
assertions are exact, not heuristic.
"""

from __future__ import annotations

from framework.v2.scanner.passive import (
    Response,
    check_cookie_flags,
    check_cors,
    check_dangerous_methods,
    check_info_disclosure,
    check_security_headers,
    scan_passive,
)


def _ids(findings) -> set[str]:
    return {f.check_id for f in findings}


def test_missing_security_headers_on_html() -> None:
    resp = Response(url="https://t/", status=200, headers=[("Content-Type", "text/html")], body="<html>")
    ids = _ids(check_security_headers(resp))
    assert {"missing-content-security-policy", "missing-x-content-type-options",
            "missing-x-frame-options", "missing-referrer-policy", "missing-hsts"} <= ids


def test_frame_ancestors_csp_mitigates_xfo() -> None:
    resp = Response(url="https://t/", headers=[
        ("Content-Type", "text/html"),
        ("Content-Security-Policy", "frame-ancestors 'none'"),
    ], body="<html>")
    assert "missing-x-frame-options" not in _ids(check_security_headers(resp))


def test_fully_hardened_response_is_clean() -> None:
    resp = Response(url="https://t/", headers=[
        ("Content-Type", "text/html"),
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Strict-Transport-Security", "max-age=31536000"),
    ], body="<html>ok</html>")
    assert check_security_headers(resp) == []


def test_cookie_flags() -> None:
    resp = Response(url="https://t/", headers=[("Set-Cookie", "sid=abc; Path=/")])
    ids = _ids(check_cookie_flags(resp))
    assert ids == {"cookie-missing-httponly", "cookie-missing-secure", "cookie-missing-samesite"}

    secure = Response(url="https://t/", headers=[
        ("Set-Cookie", "sid=abc; HttpOnly; Secure; SameSite=Strict")])
    assert check_cookie_flags(secure) == []

    # Secure is only demanded over HTTPS
    http_cookie = Response(url="http://t/", headers=[("Set-Cookie", "sid=abc; HttpOnly; SameSite=Lax")])
    assert _ids(check_cookie_flags(http_cookie)) == set()


def test_info_disclosure_variants() -> None:
    stack = Response(url="https://t/", body="Traceback (most recent call last):\n  File x")
    assert "info-stack-trace" in _ids(check_info_disclosure(stack))

    ip = Response(url="https://t/", body="connected to 10.0.0.5 backend")
    assert "info-private-ip" in _ids(check_info_disclosure(ip))

    key = Response(url="https://t/", body="-----BEGIN RSA PRIVATE KEY-----\nMII...")
    kf = [f for f in check_info_disclosure(key) if f.check_id == "info-private-key"]
    assert kf and kf[0].severity == "High"

    banner = Response(url="https://t/", headers=[("Server", "Apache/2.4.49"), ("X-Powered-By", "PHP/7.2")])
    assert {"info-server-banner", "info-x-powered-by"} <= _ids(check_info_disclosure(banner))


def test_cors_misconfig() -> None:
    wild = Response(url="https://t/api", headers=[
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Credentials", "true")])
    f = check_cors(wild)
    assert f and f[0].check_id == "cors-wildcard-with-credentials" and f[0].severity == "High"

    null = Response(url="https://t/api", headers=[("Access-Control-Allow-Origin", "null")])
    assert _ids(check_cors(null)) == {"cors-null-origin"}

    same = Response(url="https://t/api", headers=[("Access-Control-Allow-Origin", "https://t")])
    assert check_cors(same) == []


def test_dangerous_methods_from_allow_header() -> None:
    resp = Response(url="https://t/", headers=[("Allow", "GET, POST, PUT, DELETE, TRACE")])
    f = check_dangerous_methods(resp)
    assert f and f[0].check_id == "dangerous-http-methods"
    assert "PUT" in f[0].evidence and "TRACE" in f[0].evidence

    safe = Response(url="https://t/", headers=[("Allow", "GET, HEAD, POST")])
    assert check_dangerous_methods(safe) == []


def test_scan_passive_aggregates_and_is_clean_on_good_response() -> None:
    bad = Response(url="http://t/", status=500,
                   headers=[("Content-Type", "text/html"), ("Set-Cookie", "s=1")],
                   body="Fatal error: something at 10.1.2.3")
    ids = _ids(scan_passive(bad))
    assert "missing-content-security-policy" in ids
    assert "cookie-missing-httponly" in ids
    assert "info-stack-trace" in ids and "info-private-ip" in ids

    clean = Response(url="https://t/", headers=[
        ("Content-Type", "application/json"),  # non-HTML: HTML header hygiene not demanded
        ("Strict-Transport-Security", "max-age=31536000"),  # but HSTS still expected on HTTPS
    ], body='{"ok":true}')
    # a hardened JSON API response with no cookies/banners/disclosure yields nothing
    assert scan_passive(clean) == []
