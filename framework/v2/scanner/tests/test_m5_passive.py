"""
M5 module B — broadened passive checks.

Every new check gets two fixtures: a response that *proves* the signal (assert
the check_id and its severity) and a clean one that lacks it (assert no false
positive). A fully-hardened response must surface none of these; a deliberately
broken one must surface many. These are facts about bytes, so the assertions are
exact — not heuristic — except where a check is honestly ``Tentative``.
"""

from __future__ import annotations

from framework.v2.scanner.passive import (
    PASSIVE_CHECKS,
    Response,
    check_cache_control_sensitive,
    check_charset_missing,
    check_content_type_mismatch,
    check_cookie_broad_domain,
    check_cookie_persistent_session,
    check_cookie_prefix_violation,
    check_cookie_samesite_none_insecure,
    check_csp_report_only_only,
    check_csp_weaknesses,
    check_debug_mode,
    check_directory_listing,
    check_filesystem_path_disclosure,
    check_form_insecure_action,
    check_git_metadata_exposed,
    check_hsts_weaknesses,
    check_html_comment_keywords,
    check_insecure_redirect,
    check_missing_coep,
    check_missing_coop,
    check_missing_corp,
    check_missing_permissions_policy,
    check_missing_sri,
    check_missing_x_permitted_cross_domain_policies,
    check_mixed_content,
    check_password_autocomplete,
    check_referrer_policy_unsafe,
    check_secrets_in_body,
    check_source_map_reference,
    check_tech_version_headers,
    check_wsdl_disclosure,
    check_x_content_type_options_weak,
    check_x_frame_options_weak,
    check_xss_protection_legacy,
    scan_passive,
)


def _ids(findings) -> set[str]:
    return {f.check_id for f in findings}


def _sev(findings, cid: str) -> str:
    return next(f.severity for f in findings if f.check_id == cid)


def _conf(findings, cid: str) -> str:
    return next(f.confidence for f in findings if f.check_id == cid)


def _html(headers=None, body="<html></html>", url="https://t/"):
    hdrs = [("Content-Type", "text/html; charset=utf-8")]
    if headers:
        hdrs = headers
    return Response(url=url, headers=hdrs, body=body)


# --- the new checks each function should appear in the registry -------------

NEW_CHECKS = [
    check_csp_weaknesses, check_csp_report_only_only, check_hsts_weaknesses,
    check_missing_permissions_policy, check_missing_coop, check_missing_coep,
    check_missing_corp, check_missing_x_permitted_cross_domain_policies,
    check_x_content_type_options_weak, check_x_frame_options_weak,
    check_referrer_policy_unsafe, check_xss_protection_legacy,
    check_cache_control_sensitive, check_cookie_samesite_none_insecure,
    check_cookie_prefix_violation, check_cookie_broad_domain,
    check_cookie_persistent_session, check_tech_version_headers,
    check_source_map_reference, check_html_comment_keywords,
    check_filesystem_path_disclosure, check_secrets_in_body,
    check_git_metadata_exposed, check_debug_mode, check_mixed_content,
    check_form_insecure_action, check_password_autocomplete, check_missing_sri,
    check_content_type_mismatch, check_directory_listing, check_charset_missing,
    check_wsdl_disclosure, check_insecure_redirect,
]


def test_every_new_check_is_registered() -> None:
    for fn in NEW_CHECKS:
        assert fn in PASSIVE_CHECKS, f"{fn.__name__} not registered in PASSIVE_CHECKS"


def test_registry_size_grew() -> None:
    # 6 original + 33 new
    assert len(PASSIVE_CHECKS) == 39


# ---------------------------------------------------------------------------
# CSP weaknesses
# ---------------------------------------------------------------------------


def test_csp_unsafe_inline_eval_wildcard() -> None:
    resp = Response(url="https://t/", headers=[
        ("Content-Type", "text/html"),
        ("Content-Security-Policy", "default-src *; script-src 'unsafe-inline' 'unsafe-eval'")],
        body="<html>")
    ids = _ids(check_csp_weaknesses(resp))
    assert {"csp-unsafe-inline", "csp-unsafe-eval", "csp-wildcard-source"} == ids
    assert _sev(check_csp_weaknesses(resp), "csp-unsafe-inline") == "Medium"


def test_csp_strong_policy_clean() -> None:
    resp = Response(url="https://t/", headers=[
        ("Content-Security-Policy", "default-src 'self'; script-src 'self' https://cdn.example.com")],
        body="<html>")
    assert check_csp_weaknesses(resp) == []
    # a *.example.com host source is NOT a bare wildcard
    star_host = Response(url="https://t/", headers=[
        ("Content-Security-Policy", "script-src https://*.example.com")], body="")
    assert check_csp_weaknesses(star_host) == []


def test_csp_report_only_not_enforced() -> None:
    ro = _html(headers=[("Content-Type", "text/html"),
                        ("Content-Security-Policy-Report-Only", "default-src 'self'")])
    assert "csp-report-only-not-enforced" in _ids(check_csp_report_only_only(ro))
    enforced = _html(headers=[("Content-Type", "text/html"),
                              ("Content-Security-Policy", "default-src 'self'"),
                              ("Content-Security-Policy-Report-Only", "default-src 'self'")])
    assert check_csp_report_only_only(enforced) == []


# ---------------------------------------------------------------------------
# HSTS weaknesses
# ---------------------------------------------------------------------------


def test_hsts_short_and_no_subdomains() -> None:
    resp = _html(headers=[("Content-Type", "text/html"),
                          ("Strict-Transport-Security", "max-age=3600")])
    ids = _ids(check_hsts_weaknesses(resp))
    assert ids == {"hsts-short-max-age", "hsts-no-include-subdomains"}


def test_hsts_strong_clean() -> None:
    resp = _html(headers=[("Content-Type", "text/html"),
                          ("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")])
    assert check_hsts_weaknesses(resp) == []
    # not applied to non-HTML API responses (keeps the base passive suite green)
    api = Response(url="https://t/", headers=[
        ("Content-Type", "application/json"),
        ("Strict-Transport-Security", "max-age=31536000")], body="{}")
    assert check_hsts_weaknesses(api) == []


# ---------------------------------------------------------------------------
# missing isolation headers (only on HTML documents)
# ---------------------------------------------------------------------------


def test_missing_isolation_headers_on_html() -> None:
    resp = Response(url="https://t/", headers=[("Content-Type", "text/html")], body="<html>")
    assert "missing-permissions-policy" in _ids(check_missing_permissions_policy(resp))
    assert "missing-coop" in _ids(check_missing_coop(resp))
    assert "missing-coep" in _ids(check_missing_coep(resp))
    assert "missing-corp" in _ids(check_missing_corp(resp))
    assert "missing-x-permitted-cross-domain-policies" in \
        _ids(check_missing_x_permitted_cross_domain_policies(resp))


def test_isolation_headers_present_or_json_clean() -> None:
    present = Response(url="https://t/", headers=[
        ("Content-Type", "text/html"),
        ("Permissions-Policy", "geolocation=()"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Cross-Origin-Embedder-Policy", "require-corp"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
        ("X-Permitted-Cross-Domain-Policies", "none")], body="<html>")
    for fn in (check_missing_permissions_policy, check_missing_coop, check_missing_coep,
               check_missing_corp, check_missing_x_permitted_cross_domain_policies):
        assert fn(present) == []
    api = Response(url="https://t/", headers=[("Content-Type", "application/json")], body="{}")
    for fn in (check_missing_permissions_policy, check_missing_coop, check_missing_coep,
               check_missing_corp, check_missing_x_permitted_cross_domain_policies):
        assert fn(api) == []
    # legacy Feature-Policy satisfies the permissions-policy check
    legacy = Response(url="https://t/", headers=[
        ("Content-Type", "text/html"), ("Feature-Policy", "geolocation 'none'")], body="<html>")
    assert check_missing_permissions_policy(legacy) == []


# ---------------------------------------------------------------------------
# weak/wrong header values
# ---------------------------------------------------------------------------


def test_x_content_type_options_weak() -> None:
    bad = Response(url="https://t/", headers=[("X-Content-Type-Options", "sniff")])
    assert _ids(check_x_content_type_options_weak(bad)) == {"x-content-type-options-invalid"}
    good = Response(url="https://t/", headers=[("X-Content-Type-Options", "nosniff")])
    assert check_x_content_type_options_weak(good) == []
    absent = Response(url="https://t/", headers=[])
    assert check_x_content_type_options_weak(absent) == []


def test_x_frame_options_weak() -> None:
    bad = Response(url="https://t/", headers=[("X-Frame-Options", "ALLOW-FROM https://x")])
    assert _ids(check_x_frame_options_weak(bad)) == {"x-frame-options-invalid"}
    for good in ("DENY", "SAMEORIGIN", "sameorigin"):
        r = Response(url="https://t/", headers=[("X-Frame-Options", good)])
        assert check_x_frame_options_weak(r) == []


def test_referrer_policy_unsafe() -> None:
    bad = Response(url="https://t/", headers=[("Referrer-Policy", "unsafe-url")])
    assert _ids(check_referrer_policy_unsafe(bad)) == {"referrer-policy-unsafe-url"}
    good = Response(url="https://t/", headers=[("Referrer-Policy", "strict-origin-when-cross-origin")])
    assert check_referrer_policy_unsafe(good) == []


def test_xss_protection_legacy() -> None:
    legacy = Response(url="https://t/", headers=[("X-XSS-Protection", "1; mode=block")])
    f = check_xss_protection_legacy(legacy)
    assert _ids(f) == {"x-xss-protection-legacy"} and f[0].confidence == "Certain"
    disabled = Response(url="https://t/", headers=[("X-XSS-Protection", "0")])
    assert check_xss_protection_legacy(disabled) == []
    absent = Response(url="https://t/", headers=[])
    assert check_xss_protection_legacy(absent) == []


def test_cache_control_sensitive() -> None:
    cacheable = Response(url="https://t/", headers=[("Set-Cookie", "sid=1")])
    assert _ids(check_cache_control_sensitive(cacheable)) == {"sensitive-response-cacheable"}
    nostore = Response(url="https://t/", headers=[
        ("Set-Cookie", "sid=1"), ("Cache-Control", "no-store, private")])
    assert check_cache_control_sensitive(nostore) == []
    no_cookie = Response(url="https://t/", headers=[("Cache-Control", "public")])
    assert check_cache_control_sensitive(no_cookie) == []


# ---------------------------------------------------------------------------
# cookie hygiene
# ---------------------------------------------------------------------------


def test_cookie_samesite_none_insecure() -> None:
    bad = Response(url="https://t/", headers=[("Set-Cookie", "sid=1; SameSite=None")])
    f = check_cookie_samesite_none_insecure(bad)
    assert _ids(f) == {"cookie-samesite-none-insecure"} and f[0].severity == "Medium"
    ok = Response(url="https://t/", headers=[("Set-Cookie", "sid=1; SameSite=None; Secure")])
    assert check_cookie_samesite_none_insecure(ok) == []


def test_cookie_host_prefix_violation() -> None:
    # __Host- requires Secure + Path=/ + no Domain
    no_secure = Response(url="https://t/", headers=[("Set-Cookie", "__Host-sid=1; Path=/")])
    assert _ids(check_cookie_prefix_violation(no_secure)) == {"cookie-host-prefix-invalid"}
    with_domain = Response(url="https://t/", headers=[
        ("Set-Cookie", "__Host-sid=1; Secure; Path=/; Domain=example.com")])
    assert _ids(check_cookie_prefix_violation(with_domain)) == {"cookie-host-prefix-invalid"}
    valid = Response(url="https://t/", headers=[("Set-Cookie", "__Host-sid=1; Secure; Path=/")])
    assert check_cookie_prefix_violation(valid) == []


def test_cookie_secure_prefix_violation() -> None:
    bad = Response(url="https://t/", headers=[("Set-Cookie", "__Secure-sid=1; Path=/")])
    assert _ids(check_cookie_prefix_violation(bad)) == {"cookie-secure-prefix-invalid"}
    ok = Response(url="https://t/", headers=[("Set-Cookie", "__Secure-sid=1; Secure")])
    assert check_cookie_prefix_violation(ok) == []


def test_cookie_broad_domain() -> None:
    bad = Response(url="https://t/", headers=[("Set-Cookie", "sid=1; Domain=.example.com")])
    assert _ids(check_cookie_broad_domain(bad)) == {"cookie-broad-domain"}
    scoped = Response(url="https://t/", headers=[("Set-Cookie", "sid=1; Domain=app.example.com")])
    assert check_cookie_broad_domain(scoped) == []
    nodomain = Response(url="https://t/", headers=[("Set-Cookie", "sid=1; Path=/")])
    assert check_cookie_broad_domain(nodomain) == []


def test_cookie_persistent_session() -> None:
    persistent = Response(url="https://t/", headers=[
        ("Set-Cookie", "JSESSIONID=abc; Max-Age=86400")])
    assert _ids(check_cookie_persistent_session(persistent)) == {"cookie-persistent-session"}
    expires = Response(url="https://t/", headers=[
        ("Set-Cookie", "sessionid=abc; Expires=Wed, 09 Jun 2027 10:18:14 GMT")])
    assert _ids(check_cookie_persistent_session(expires)) == {"cookie-persistent-session"}
    # a true session cookie (no expiry) is fine, and a persistent non-session cookie is ignored
    session = Response(url="https://t/", headers=[("Set-Cookie", "sid=abc; HttpOnly")])
    assert check_cookie_persistent_session(session) == []
    pref = Response(url="https://t/", headers=[("Set-Cookie", "theme=dark; Max-Age=999999")])
    assert check_cookie_persistent_session(pref) == []


# ---------------------------------------------------------------------------
# information disclosure
# ---------------------------------------------------------------------------


def test_tech_version_headers() -> None:
    resp = Response(url="https://t/", headers=[
        ("X-AspNet-Version", "4.0.30319"),
        ("X-AspNetMvc-Version", "5.2"),
        ("X-Generator", "Drupal 9"),
        ("X-Runtime", "0.012"),
        ("Via", "1.1 varnish")])
    ids = _ids(check_tech_version_headers(resp))
    assert ids == {"info-x-aspnet-version", "info-x-aspnetmvc-version",
                   "info-x-generator", "info-x-runtime", "info-via"}
    assert all(f.severity == "Info" for f in check_tech_version_headers(resp))
    assert check_tech_version_headers(Response(url="https://t/", headers=[])) == []


def test_source_map_reference() -> None:
    resp = Response(url="https://t/app.js", body="var a=1;\n//# sourceMappingURL=app.js.map")
    assert _ids(check_source_map_reference(resp)) == {"source-map-reference"}
    clean = Response(url="https://t/app.js", body="var a=1;")
    assert check_source_map_reference(clean) == []


def test_html_comment_keywords() -> None:
    resp = Response(url="https://t/", body="<html><!-- TODO: remove hardcoded password before launch --></html>")
    f = check_html_comment_keywords(resp)
    assert _ids(f) == {"html-comment-keyword"}
    # keyword outside a comment is not flagged (avoids body-wide false positives)
    visible = Response(url="https://t/", body="<p>Enter your password below</p>")
    assert check_html_comment_keywords(visible) == []
    benign = Response(url="https://t/", body="<html><!-- main navigation --></html>")
    assert check_html_comment_keywords(benign) == []


def test_filesystem_path_disclosure() -> None:
    unix = Response(url="https://t/", body="Warning in /var/www/html/inc/db.php on line 20")
    assert _ids(check_filesystem_path_disclosure(unix)) == {"filesystem-path-disclosure"}
    win = Response(url="https://t/", body=r"could not open C:\inetpub\wwwroot\config\secret.ini")
    assert _ids(check_filesystem_path_disclosure(win)) == {"filesystem-path-disclosure"}
    clean = Response(url="https://t/", body="page loaded from /about and /contact")
    assert check_filesystem_path_disclosure(clean) == []


def test_secrets_in_body() -> None:
    aws = Response(url="https://t/", body="key: AKIAIOSFODNN7EXAMPLE more")
    f = check_secrets_in_body(aws)
    assert "secret-aws-access-key" in _ids(f) and _sev(f, "secret-aws-access-key") == "High"

    google = Response(url="https://t/", body="key=AIza" + "b" * 35 + " end")
    assert "secret-google-api-key" in _ids(check_secrets_in_body(google))

    slack = Response(url="https://t/", body="token=xoxb-123456789012-abcdefghijklmn")
    assert "secret-slack-token" in _ids(check_secrets_in_body(slack))

    gh = Response(url="https://t/", body="ghp_012345678901234567890123456789abcdef")
    assert "secret-github-token" in _ids(check_secrets_in_body(gh))

    jwt = Response(url="https://t/",
                   body="Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w")
    fj = check_secrets_in_body(jwt)
    assert "secret-jwt" in _ids(fj) and _sev(fj, "secret-jwt") == "Low"

    generic = Response(url="https://t/", body='config = {"api_key": "9f8b7c6d5e4a3b2c1d0e"}')
    fg = check_secrets_in_body(generic)
    assert "secret-generic-assignment" in _ids(fg)
    assert _conf(fg, "secret-generic-assignment") == "Tentative"

    # placeholder is not a leak
    placeholder = Response(url="https://t/", body='api_key = "YOUR_API_KEY_HERE"')
    assert "secret-generic-assignment" not in _ids(check_secrets_in_body(placeholder))
    assert check_secrets_in_body(Response(url="https://t/", body="nothing here")) == []


def test_git_metadata_exposed() -> None:
    head = Response(url="https://t/.git/HEAD", body="ref: refs/heads/main\n")
    f = check_git_metadata_exposed(head)
    assert _ids(f) == {"git-metadata-exposed"} and f[0].severity == "High"
    cfg = Response(url="https://t/.git/config",
                   body="[core]\n\trepositoryformatversion = 0\n\tbare = false")
    assert "git-metadata-exposed" in _ids(check_git_metadata_exposed(cfg))
    assert check_git_metadata_exposed(Response(url="https://t/", body="<html>ok</html>")) == []


def test_debug_mode() -> None:
    symfony = Response(url="https://t/", headers=[("X-Debug-Token", "a1b2c3")])
    f = check_debug_mode(symfony)
    assert _ids(f) == {"debug-profiler-exposed"} and f[0].severity == "Medium"
    generic = Response(url="https://t/", headers=[("X-Debug-Mode", "on")])
    assert _ids(check_debug_mode(generic)) == {"debug-header"}
    assert check_debug_mode(Response(url="https://t/", headers=[("Server", "nginx")])) == []


# ---------------------------------------------------------------------------
# content & transport
# ---------------------------------------------------------------------------


def test_mixed_content_active_and_passive() -> None:
    body = ('<script src="http://cdn.example.com/a.js"></script>'
            '<img src="http://img.example.com/p.png">')
    resp = Response(url="https://t/", body=body)
    ids = _ids(check_mixed_content(resp))
    assert ids == {"mixed-content-active", "mixed-content-passive"}
    assert _sev(check_mixed_content(resp), "mixed-content-active") == "Medium"


def test_mixed_content_ignores_namespaces_and_anchors() -> None:
    body = ('<html xmlns="http://www.w3.org/1999/xhtml">'
            '<a href="http://example.com/page">link</a>'
            '<link rel="canonical" href="http://example.com/c">'
            '<script src="https://cdn/x.js"></script>')
    resp = Response(url="https://t/", body=body)
    assert check_mixed_content(resp) == []
    # http page is out of scope for this check entirely
    assert check_mixed_content(Response(url="http://t/", body='<img src="http://x/p.png">')) == []


def test_form_insecure_action() -> None:
    resp = Response(url="https://t/", body='<form action="http://t/login" method="post">')
    assert _ids(check_form_insecure_action(resp)) == {"form-insecure-action"}
    secure = Response(url="https://t/", body='<form action="/login" method="post">')
    assert check_form_insecure_action(secure) == []


def test_password_autocomplete_tentative() -> None:
    resp = Response(url="https://t/", body='<input type="password" name="pw">')
    f = check_password_autocomplete(resp)
    assert _ids(f) == {"password-input-autocomplete"} and f[0].confidence == "Tentative"
    off = Response(url="https://t/", body='<input type="password" autocomplete="new-password">')
    assert check_password_autocomplete(off) == []
    none = Response(url="https://t/", body="<input type=text name=q>")
    assert check_password_autocomplete(none) == []


def test_missing_sri() -> None:
    ext = Response(url="https://site.test/", body='<script src="https://cdn.other.test/x.js"></script>')
    assert _ids(check_missing_sri(ext)) == {"missing-sri"}
    with_integrity = Response(url="https://site.test/",
                              body='<script src="https://cdn.other.test/x.js" integrity="sha384-abc"></script>')
    assert check_missing_sri(with_integrity) == []
    same_origin = Response(url="https://site.test/", body='<script src="/local.js"></script>')
    assert check_missing_sri(same_origin) == []


def test_content_type_mismatch() -> None:
    plain = Response(url="https://t/", headers=[("Content-Type", "text/plain")],
                     body="<!doctype html><html><body>hi</body></html>")
    assert _ids(check_content_type_mismatch(plain)) == {"content-type-mismatch-html"}
    missing = Response(url="https://t/", headers=[], body="<html><body>hi</body></html>")
    assert _ids(check_content_type_mismatch(missing)) == {"content-type-missing-html"}
    proper = Response(url="https://t/", headers=[("Content-Type", "text/html; charset=utf-8")],
                      body="<!doctype html><html>ok</html>")
    assert check_content_type_mismatch(proper) == []
    json_resp = Response(url="https://t/", headers=[("Content-Type", "application/json")],
                         body='{"ok":true}')
    assert check_content_type_mismatch(json_resp) == []


def test_directory_listing() -> None:
    apache = Response(url="https://t/files/", body="<html><head><title>Index of /files</title></head>")
    assert _ids(check_directory_listing(apache)) == {"directory-listing"}
    py = Response(url="https://t/", body="<title>Directory listing for /uploads/</title>")
    assert _ids(check_directory_listing(py)) == {"directory-listing"}
    normal = Response(url="https://t/", body="<html><title>Welcome</title></html>")
    assert check_directory_listing(normal) == []


def test_charset_missing() -> None:
    resp = Response(url="https://t/", headers=[("Content-Type", "text/html")], body="<html>hi</html>")
    assert _ids(check_charset_missing(resp)) == {"html-charset-missing"}
    in_ctype = Response(url="https://t/", headers=[("Content-Type", "text/html; charset=utf-8")],
                        body="<html>hi</html>")
    assert check_charset_missing(in_ctype) == []
    in_meta = Response(url="https://t/", headers=[("Content-Type", "text/html")],
                       body='<html><head><meta charset="utf-8"></head></html>')
    assert check_charset_missing(in_meta) == []
    json_resp = Response(url="https://t/", headers=[("Content-Type", "application/json")], body="{}")
    assert check_charset_missing(json_resp) == []


def test_wsdl_disclosure() -> None:
    body = ('<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/" '
            'targetNamespace="urn:svc">')
    resp = Response(url="https://t/service?wsdl", body=body)
    assert _ids(check_wsdl_disclosure(resp)) == {"wsdl-disclosure"}
    assert check_wsdl_disclosure(Response(url="https://t/", body="<html>ok</html>")) == []


def test_insecure_redirect() -> None:
    resp = Response(url="https://t/go", status=302, headers=[("Location", "http://t/next")])
    assert _ids(check_insecure_redirect(resp)) == {"insecure-redirect"}
    secure = Response(url="https://t/go", status=302, headers=[("Location", "https://t/next")])
    assert check_insecure_redirect(secure) == []
    relative = Response(url="https://t/go", status=302, headers=[("Location", "/next")])
    assert check_insecure_redirect(relative) == []


# ---------------------------------------------------------------------------
# integration — hardened vs. broken, through scan_passive
# ---------------------------------------------------------------------------


def test_fully_hardened_html_yields_no_new_findings() -> None:
    resp = Response(url="https://t/", status=200, headers=[
        ("Content-Type", "text/html; charset=utf-8"),
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "geolocation=()"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Cross-Origin-Embedder-Policy", "require-corp"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
        ("X-Permitted-Cross-Domain-Policies", "none"),
        ("Cache-Control", "no-store"),
    ], body="<!doctype html><html><head><title>ok</title></head><body>clean</body></html>")
    # every M5 check must be silent on a hardened document
    findings = []
    for fn in NEW_CHECKS:
        findings.extend(fn(resp))
    assert findings == [], f"unexpected findings on hardened response: {_ids(findings)}"


def test_badly_misconfigured_response_surfaces_many() -> None:
    body = (
        '<!doctype html><html>'
        '<!-- FIXME: default admin password is admin123 -->'
        '<form action="http://t/login"><input type="password" name="pw"></form>'
        '<script src="http://cdn.other.test/a.js"></script>'
        '<img src="http://img.other.test/p.png">'
        'AKIAIOSFODNN7EXAMPLE  /var/www/html/app/config.php'
        '//# sourceMappingURL=app.js.map'
        '</html>')
    resp = Response(url="https://t/", status=200, headers=[
        ("Content-Type", "text/html"),  # HTML so page-hardening checks apply
        ("Content-Security-Policy", "script-src 'unsafe-inline' *"),
        ("Strict-Transport-Security", "max-age=100"),
        ("X-Frame-Options", "ALLOW-FROM https://x"),
        ("Referrer-Policy", "unsafe-url"),
        ("X-XSS-Protection", "1"),
        ("X-Powered-By", "PHP/8.1"),
        ("X-Generator", "WordPress 6.0"),
        ("X-Debug-Token", "deadbeef"),
        ("Set-Cookie", "__Host-sid=1; SameSite=None; Domain=.t; Max-Age=999999"),
        ("Location", "http://t/downgrade"),
    ], body=body)
    ids = _ids(scan_passive(resp))
    expected = {
        "csp-unsafe-inline", "csp-wildcard-source",
        "hsts-short-max-age", "hsts-no-include-subdomains",
        "missing-permissions-policy", "missing-coop", "missing-coep", "missing-corp",
        "missing-x-permitted-cross-domain-policies",
        "x-frame-options-invalid", "referrer-policy-unsafe-url", "x-xss-protection-legacy",
        "sensitive-response-cacheable",
        "cookie-samesite-none-insecure", "cookie-host-prefix-invalid",
        "cookie-broad-domain", "cookie-persistent-session",
        "info-x-generator",
        "source-map-reference", "html-comment-keyword", "filesystem-path-disclosure",
        "secret-aws-access-key", "debug-profiler-exposed",
        "mixed-content-active", "mixed-content-passive",
        "form-insecure-action", "password-input-autocomplete", "missing-sri",
        "insecure-redirect",
    }
    missing = expected - ids
    assert not missing, f"missing expected findings: {missing}"


def test_scan_passive_surfaces_new_checks() -> None:
    resp = Response(url="https://t/", headers=[
        ("Content-Type", "text/html"),
        ("Content-Security-Policy", "script-src 'unsafe-eval'")],
        body="<html><!-- TODO: secret token here --></html>")
    ids = _ids(scan_passive(resp))
    assert "csp-unsafe-eval" in ids
    assert "html-comment-keyword" in ids
    assert "missing-coop" in ids
