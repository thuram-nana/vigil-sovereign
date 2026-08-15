"""
AEGIS — multipart request-body injection surface + per-source starvation fix (candidate_values).

A payload in a multipart/form-data field used to BYPASS inline inspection entirely, and a flood of junk
query params could exhaust the 256-value global cap before a cookie/header was inspected. This closes
both, and it does so WITHOUT widening the near-zero-FP contract:

  * multipart text fields are inspected at PARITY with the existing urlencoded/JSON form surface — the
    same named-injection-point contract, same oracles. A SQL break-out / shell construct in a field is a
    CONFIRMED block; a benign single-field form is clear; a FILE part is never inspected.
  * text/plain and XML *document* bodies are deliberately NOT extracted — free text is not a structured
    injection point (see the module docstring), so they stay out of the request-side FP surface.
  * each source has a RESERVED share of the bound, so neither a query flood NOR a body flood can starve
    the cookie/header surface out of inspection.
"""

from __future__ import annotations

from framework.v2.aegis.inspect import (
    _MAX_HC_VALUES,
    _MAX_QUERY_VALUES,
    candidate_values,
    inspect_request,
)

SQLI = "x' OR '1'='1"       # a string-literal break-out the sqli oracle confirms (single-line field value)

MP = "multipart/form-data; boundary=----WebKitFormBoundaryABC"


def _multipart(*fields, file_part=None):
    """Build a multipart body from (name, value) text fields (+ an optional (name, disposition, data))."""
    b = "------WebKitFormBoundaryABC"
    parts = []
    for name, val in fields:
        parts.append(f'{b}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{val}')
    if file_part:
        name, disposition, data = file_part
        parts.append(f'{b}\r\nContent-Disposition: form-data; name="{name}"; {disposition}\r\n'
                     f'Content-Type: application/octet-stream\r\n\r\n{data}')
    return "\r\n".join(parts) + f"\r\n{b}--\r\n"


def _block(ctype, body, path="/"):
    v = inspect_request("POST", path, [("Content-Type", ctype)] if ctype else [], body, enforce=True)
    return v.attack_class if (v and v.action == "block") else None


# --------------------------------------------------------------------------- extraction

def test_multipart_text_fields_become_candidates():
    body = _multipart(("username", "alice"), ("comment", "hello world"))
    got = dict(candidate_values("/", [("Content-Type", MP)], body))
    assert got.get("username") == "alice"
    assert got.get("comment") == "hello world"


def test_multipart_boundary_is_read_case_sensitively():
    # the boundary in the body keeps its original case even though the content-type match is lowercased
    body = _multipart(("q", "v"))
    assert dict(candidate_values("/", [("Content-Type", MP)], body)).get("q") == "v"


def test_urlencoded_and_json_bodies_are_unchanged():
    ue = dict(candidate_values("/", [("Content-Type", "application/x-www-form-urlencoded")], "a=1&b=two"))
    assert ue.get("a") == "1" and ue.get("b") == "two"
    js = dict(candidate_values("/", [("Content-Type", "application/json")], '{"x":{"y":"deep"}}'))
    assert js.get("x.y") == "deep"


def test_empty_content_type_still_parsed_as_urlencoded():
    got = dict(candidate_values("/", [], "a=1&b=2"))
    assert got.get("a") == "1" and got.get("b") == "2"


def test_text_plain_and_xml_document_bodies_are_not_extracted():
    # free text is not a structured injection point — it must NOT become a candidate value.
    assert candidate_values("/", [("Content-Type", "text/plain")], "just some free text with a ; and a '") == []
    assert candidate_values("/", [("Content-Type", "application/xml")],
                            "<n>alice</n><c>hi</c>") == []


# --------------------------------------------------------------------------- confirmed block (parity)

def test_sqli_in_a_multipart_field_is_confirmed():
    body = _multipart(("q", SQLI))
    v = inspect_request("POST", "/", [("Content-Type", MP)], body, enforce=True)
    assert v is not None and v.decision == "confirmed" and v.attack_class == "sqli_attempt"
    assert v.certificate is not None and v.certificate.reverify() is True
    assert v.contributing == ["q"]


def test_multipart_matches_urlencoded_parity_on_the_same_value():
    # whatever a single field value does on urlencoded, it does identically on multipart — same contract.
    import urllib.parse
    ue = _block("application/x-www-form-urlencoded", "q=" + urllib.parse.quote(SQLI))
    mp = _block(MP, _multipart(("q", SQLI)))
    assert ue == mp == "sqli_attempt"


# --------------------------------------------------------------------------- NEGATIVE CONTROLS (near-zero-FP)

def test_benign_single_field_form_does_not_block():
    body = _multipart(("name", "Alice O'Brien"), ("city", "São Paulo"), ("topic", "SQL databases"))
    v = inspect_request("POST", "/signup", [("Content-Type", MP)], body, enforce=True)
    assert v is None or v.action != "block", f"benign form flagged: {v and v.attack_class}"


def test_a_file_part_is_never_inspected_even_with_a_hostile_payload_and_odd_filename():
    # BLOCK-5: the file-part skip must survive `filename =` (space) and RFC-5987 `filename*=` — otherwise
    # a benign .sql/.sh upload whose BYTES look hostile is spuriously blocked.
    hostile = "'; DROP TABLE users; -- \n cat /etc/passwd"
    for disposition in ('filename="a.sql"', 'filename ="a.sql"', "filename*=UTF-8''r%C3%A9sum%C3%A9.sql"):
        body = _multipart(("caption", "my file"), file_part=("f", disposition, hostile))
        v = inspect_request("POST", "/upload", [("Content-Type", MP)], body, enforce=True)
        assert v is None or v.action != "block", f"a file part was inspected for disposition {disposition!r}"


def test_text_plain_note_is_not_blocked_because_it_is_not_inspected():
    # the fetch() default content-type carrying benign technical prose must never block.
    assert _block("text/plain", "To debug run:\ncat /etc/hosts\nthanks") is None
    assert _block("text/plain", "Your search box broke when I typed '; DROP TABLE users; --") is None


def test_benign_xml_document_is_not_blocked_because_it_is_not_inspected():
    assert _block("application/xml", "<comment>the app broke on '; DROP TABLE t; --</comment>") is None
    assert _block("application/xml", "<doc><![CDATA[ if (a>b) { run('x'); } ]]></doc>") is None


# --------------------------------------------------------------------------- starvation fix

def test_a_query_flood_cannot_starve_the_header_cookie_surface():
    flood = "&".join(f"j{i}=v{i}" for i in range(500))
    got = candidate_values("/?" + flood, [("Cookie", "sid=abc")], None)
    assert any(n.startswith("cookie:") for n in (n for n, _ in got)), "a query flood starved the cookie surface"


def test_a_BODY_flood_cannot_starve_the_header_cookie_surface():
    # BLOCK-4: the BODY per-source cap is load-bearing too — a huge form body must not crowd out cookies.
    flood = "&".join(f"b{i}=v{i}" for i in range(500))
    headers = [("Content-Type", "application/x-www-form-urlencoded"), ("Cookie", "sid=abc")]
    got = candidate_values("/", headers, flood)
    assert any(n.startswith("cookie:") for n in (n for n, _ in got)), "a body flood starved the cookie surface"
    # and a cookie SQLi is still caught despite the body flood
    import urllib.parse
    v = inspect_request("POST", "/", [("Content-Type", "application/x-www-form-urlencoded"),
                                      ("Cookie", "t=" + urllib.parse.quote(SQLI))], flood, enforce=True)
    assert v is not None and v.decision == "confirmed"


def test_each_source_share_is_bounded():
    flood = "&".join(f"j{i}=v{i}" for i in range(500))
    assert len([n for n, _ in candidate_values("/?" + flood, [], None)]) <= _MAX_QUERY_VALUES
    many_cookies = "; ".join(f"c{i}=v{i}" for i in range(500))
    hc = [n for n, _ in candidate_values("/", [("Cookie", many_cookies)], None) if n.startswith("cookie:")]
    assert len(hc) <= _MAX_HC_VALUES
