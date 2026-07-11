"""
Workstream C — client-side passive checks (postMessage / CSRF / clickjacking).

Every check gets a POSITIVE fixture that proves the signal (assert the check_id,
its severity and confidence) and a NEGATIVE, properly-defended fixture that must
stay silent (postMessage to a specific origin, a form carrying a CSRF token, a
page framed-guarded by X-Frame-Options: DENY or CSP frame-ancestors). These
checks read only already-collected bytes and send nothing, so they can never
change the scanner's active-finding count or request budget.
"""

from __future__ import annotations

from framework.v2.scanner.passive import (
    PASSIVE_CHECKS,
    Response,
    check_clickjacking_sensitive_framable,
    check_csrf_token_absent_form,
    check_postmessage_listener_no_origin,
    check_postmessage_wildcard_target,
    scan_passive,
)


def _ids(findings) -> set[str]:
    return {f.check_id for f in findings}


def _sev(findings, cid: str) -> str:
    return next(f.severity for f in findings if f.check_id == cid)


def _conf(findings, cid: str) -> str:
    return next(f.confidence for f in findings if f.check_id == cid)


NEW_CHECKS = [
    check_postmessage_wildcard_target,
    check_postmessage_listener_no_origin,
    check_csrf_token_absent_form,
    check_clickjacking_sensitive_framable,
]


def test_client_side_checks_are_registered() -> None:
    for fn in NEW_CHECKS:
        assert fn in PASSIVE_CHECKS, f"{fn.__name__} not registered in PASSIVE_CHECKS"


# ---------------------------------------------------------------------------
# postMessage — wildcard target origin
# ---------------------------------------------------------------------------


def test_postmessage_wildcard_target_positive() -> None:
    resp = Response(url="https://t/", body="<script>child.postMessage(secret, '*');</script>")
    f = check_postmessage_wildcard_target(resp)
    assert _ids(f) == {"postmessage-wildcard-target"}
    assert _sev(f, "postmessage-wildcard-target") == "Medium"
    assert _conf(f, "postmessage-wildcard-target") == "Firm"
    # double-quoted wildcard, extra spacing
    dq = Response(url="https://t/", body='win.postMessage( data ,  "*" )')
    assert _ids(check_postmessage_wildcard_target(dq)) == {"postmessage-wildcard-target"}


def test_postmessage_specific_origin_is_clean() -> None:
    ok = Response(url="https://t/",
                  body="<script>frame.postMessage(data, 'https://trusted.example.com');</script>")
    assert check_postmessage_wildcard_target(ok) == []
    # a variable target origin is not a provable wildcard -> no finding
    var = Response(url="https://t/", body="<script>frame.postMessage(data, targetOrigin);</script>")
    assert check_postmessage_wildcard_target(var) == []


# ---------------------------------------------------------------------------
# postMessage — listener with no origin check
# ---------------------------------------------------------------------------


def test_postmessage_listener_no_origin_positive() -> None:
    add = Response(url="https://t/",
                   body="<script>window.addEventListener('message', function(e){ render(e.data); });</script>")
    f = check_postmessage_listener_no_origin(add)
    assert _ids(f) == {"postmessage-listener-no-origin-check"}
    assert _sev(f, "postmessage-listener-no-origin-check") == "Medium"
    assert _conf(f, "postmessage-listener-no-origin-check") == "Tentative"
    # the onmessage= handler form is detected too
    on = Response(url="https://t/", body="<script>window.onmessage = function(e){ use(e.data); };</script>")
    assert _ids(check_postmessage_listener_no_origin(on)) == {"postmessage-listener-no-origin-check"}


def test_postmessage_listener_with_origin_is_clean() -> None:
    guarded = Response(url="https://t/", body=(
        "<script>window.addEventListener('message', function(e){"
        " if (e.origin !== 'https://trusted') return; render(e.data); });</script>"))
    assert check_postmessage_listener_no_origin(guarded) == []
    # no message listener at all
    none = Response(url="https://t/", body="<script>window.addEventListener('click', h);</script>")
    assert check_postmessage_listener_no_origin(none) == []


# ---------------------------------------------------------------------------
# CSRF — state-changing POST form with no anti-CSRF token
# ---------------------------------------------------------------------------


def test_csrf_token_absent_post_form_positive() -> None:
    resp = Response(url="https://t/account",
                    body='<form method="post" action="/transfer"><input name="amount"></form>')
    f = check_csrf_token_absent_form(resp)
    assert _ids(f) == {"csrf-token-absent-form"}
    assert _sev(f, "csrf-token-absent-form") == "Medium"
    assert _conf(f, "csrf-token-absent-form") == "Tentative"


def test_csrf_form_with_token_is_clean() -> None:
    # a hidden anti-CSRF token satisfies the check for several framework names
    for token_name in ("csrf_token", "authenticity_token", "csrfmiddlewaretoken",
                        "__RequestVerificationToken", "_token", "nonce"):
        body = (f'<form method="post" action="/x">'
                f'<input type="hidden" name="{token_name}" value="z"><input name="v"></form>')
        assert check_csrf_token_absent_form(Response(url="https://t/", body=body)) == [], token_name


def test_csrf_get_or_methodless_form_is_skipped() -> None:
    # missing method defaults to GET -> not a state-changing form
    methodless = Response(url="https://t/", body='<form action="/search"><input name="q"></form>')
    assert check_csrf_token_absent_form(methodless) == []
    get = Response(url="https://t/", body='<form method="get" action="/search"><input name="q"></form>')
    assert check_csrf_token_absent_form(get) == []


def test_csrf_off_origin_action_is_skipped() -> None:
    # posting to a clearly foreign site is not this origin's CSRF surface
    off = Response(url="https://t/pay",
                   body='<form method="post" action="https://other.example.com/collect"><input name="x"></form>')
    assert check_csrf_token_absent_form(off) == []


# ---------------------------------------------------------------------------
# clickjacking — framable page carrying a sensitive element
# ---------------------------------------------------------------------------


def _html(body: str, headers=None, url="https://t/") -> Response:
    hdrs = [("Content-Type", "text/html")]
    if headers:
        hdrs = hdrs + headers
    return Response(url=url, headers=hdrs, body=body)


def test_clickjacking_sensitive_framable_positive() -> None:
    pw = _html('<form><input type="password" name="pw"></form>')
    f = check_clickjacking_sensitive_framable(pw)
    assert _ids(f) == {"clickjacking-sensitive-form-framable"}
    assert _sev(f, "clickjacking-sensitive-form-framable") == "Medium"
    assert _conf(f, "clickjacking-sensitive-form-framable") == "Firm"
    # a POST form is also a sensitive/state-changing element
    post = _html('<form method="post" action="/x"><input name="v"></form>')
    assert _ids(check_clickjacking_sensitive_framable(post)) == {"clickjacking-sensitive-form-framable"}


def test_clickjacking_frame_guarded_is_clean() -> None:
    body = '<form><input type="password" name="pw"></form>'
    xfo = _html(body, headers=[("X-Frame-Options", "DENY")])
    assert check_clickjacking_sensitive_framable(xfo) == []
    xfo_so = _html(body, headers=[("X-Frame-Options", "SAMEORIGIN")])
    assert check_clickjacking_sensitive_framable(xfo_so) == []
    csp = _html(body, headers=[("Content-Security-Policy", "frame-ancestors 'self'")])
    assert check_clickjacking_sensitive_framable(csp) == []


def test_clickjacking_requires_sensitive_element_and_html() -> None:
    # framable but no sensitive element -> nothing (this is not the generic missing-XFO note)
    plain = _html("<p>hello world</p>")
    assert check_clickjacking_sensitive_framable(plain) == []
    # a password string in a non-HTML response is not a framable document
    api = Response(url="https://t/", headers=[("Content-Type", "application/json")],
                   body='{"field":"<input type=password>"}')
    assert check_clickjacking_sensitive_framable(api) == []


# ---------------------------------------------------------------------------
# integration through scan_passive
# ---------------------------------------------------------------------------


def test_scan_passive_surfaces_all_client_side_checks() -> None:
    body = (
        "<html>"
        '<form method="post" action="/update"><input type="password" name="pw"></form>'
        "<script>"
        "window.addEventListener('message', function(e){ render(e.data); });"
        "child.postMessage(secret, '*');"
        "</script>"
        "</html>"
    )
    resp = Response(url="https://t/account", headers=[("Content-Type", "text/html")], body=body)
    ids = _ids(scan_passive(resp))
    assert {"postmessage-wildcard-target", "postmessage-listener-no-origin-check",
            "csrf-token-absent-form", "clickjacking-sensitive-form-framable"} <= ids


def test_client_side_defended_page_surfaces_none() -> None:
    body = (
        "<html>"
        '<form method="post" action="/update">'
        '<input type="hidden" name="csrf_token" value="x"><input name="v"></form>'
        "<script>"
        "window.addEventListener('message', function(e){ if (e.origin !== 'https://t') return; render(e.data); });"
        "child.postMessage(data, 'https://t');"
        "</script>"
        "</html>"
    )
    resp = Response(url="https://t/", headers=[
        ("Content-Type", "text/html"),
        ("X-Frame-Options", "DENY"),
    ], body=body)
    ids = _ids(scan_passive(resp))
    for cid in ("postmessage-wildcard-target", "postmessage-listener-no-origin-check",
                "csrf-token-absent-form", "clickjacking-sensitive-form-framable"):
        assert cid not in ids, cid
