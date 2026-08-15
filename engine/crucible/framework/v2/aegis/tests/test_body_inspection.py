"""
AEGIS — request-body injection surface (candidate_values extension).

A payload used to BYPASS inline inspection entirely if it arrived in a body type candidate extraction
did not parse: multipart/form-data, text/plain, and XML all fell through with zero candidate values,
and a flood of junk query params could exhaust the 256-value global cap before a single cookie/header
was inspected. This closes both. The contract, per AEGIS's near-zero-FP discipline:

  * a SQL break-out / shell construct in a multipart field, a text/plain body, or an XML text node is a
    CONFIRMED block with a re-runnable certificate;
  * NORMAL bodies of those types — a benign form upload, an ordinary text note, a well-formed XML
    document, a file-upload part — never trip (widening EXTRACTION never widens the VERDICT: the oracle
    still decides);
  * each surface has a RESERVED share of the bound, so hundreds of junk query params can no longer
    starve the cookie/header surface out of inspection.
"""

from __future__ import annotations

from framework.v2.aegis.inspect import (
    _MAX_HC_VALUES,
    _MAX_QUERY_VALUES,
    candidate_values,
    inspect_request,
)

SQLI = "x' OR '1'='1"       # a string-literal break-out the sqli oracle confirms

MP = "multipart/form-data; boundary=----WebKitFormBoundaryABC"


def _multipart(*fields, file_part=None):
    """Build a multipart body from (name, value) text fields (+ an optional (name, filename, data))."""
    b = "------WebKitFormBoundaryABC"
    parts = []
    for name, val in fields:
        parts.append(f'{b}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{val}')
    if file_part:
        name, filename, data = file_part
        parts.append(f'{b}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                     f'Content-Type: application/octet-stream\r\n\r\n{data}')
    return "\r\n".join(parts) + f"\r\n{b}--\r\n"


# --------------------------------------------------------------------------- extraction

def test_multipart_text_fields_become_candidates():
    body = _multipart(("username", "alice"), ("comment", "hello world"))
    got = dict(candidate_values("/", [("Content-Type", MP)], body))
    assert got.get("username") == "alice"
    assert got.get("comment") == "hello world"


def test_multipart_file_part_is_skipped():
    body = _multipart(("caption", "ok"), file_part=("upload", "evil.bin", "x' OR '1'='1 binary junk"))
    got = candidate_values("/", [("Content-Type", MP)], body)
    names = [n for n, _ in got]
    assert "caption" in names
    assert "upload" not in names, "a file-upload part must not be extracted as a string value"


def test_text_plain_body_is_one_candidate():
    got = dict(candidate_values("/", [("Content-Type", "text/plain")], "just some free text"))
    assert got.get("body") == "just some free text"


def test_xml_text_nodes_become_candidates_but_not_tags():
    body = "<order><user>alice</user><note>hello</note></order>"
    vals = [v for _, v in candidate_values("/", [("Content-Type", "application/xml")], body)]
    assert "alice" in vals and "hello" in vals
    assert "order" not in vals and "user" not in vals, "tag names must not be extracted as values"


def test_urlencoded_and_json_bodies_are_unchanged():
    # regression: the pre-existing branches still work exactly as before
    ue = dict(candidate_values("/", [("Content-Type", "application/x-www-form-urlencoded")], "a=1&b=two"))
    assert ue.get("a") == "1" and ue.get("b") == "two"
    js = dict(candidate_values("/", [("Content-Type", "application/json")], '{"x":{"y":"deep"}}'))
    assert js.get("x.y") == "deep"


def test_empty_content_type_still_parsed_as_urlencoded():
    # unchanged behaviour: no content-type is treated as a form body, not a whole-body text blob
    got = dict(candidate_values("/", [], "a=1&b=2"))
    assert got.get("a") == "1" and got.get("b") == "2"
    assert "body" not in got


# --------------------------------------------------------------------------- confirmed blocks

def test_sqli_in_a_multipart_field_is_confirmed():
    body = _multipart(("q", SQLI))
    v = inspect_request("POST", "/", [("Content-Type", MP)], body, enforce=True)
    assert v is not None and v.decision == "confirmed" and v.attack_class == "sqli_attempt"
    assert v.certificate is not None and v.certificate.reverify() is True
    assert v.contributing == ["q"]


def test_sqli_in_a_text_plain_body_is_confirmed():
    v = inspect_request("POST", "/", [("Content-Type", "text/plain")], SQLI, enforce=True)
    assert v is not None and v.decision == "confirmed" and v.attack_class == "sqli_attempt"
    assert v.certificate is not None and v.certificate.reverify() is True


def test_sqli_in_an_xml_text_node_is_confirmed():
    body = f"<q><term>{SQLI}</term></q>"
    v = inspect_request("POST", "/", [("Content-Type", "application/xml")], body, enforce=True)
    assert v is not None and v.decision == "confirmed" and v.attack_class == "sqli_attempt"


# --------------------------------------------------------------------------- NEGATIVE CONTROLS (near-zero-FP)

def test_benign_multipart_form_does_not_block():
    body = _multipart(("name", "Alice O'Brien"), ("city", "São Paulo"), ("bio", "I love SQL databases."))
    v = inspect_request("POST", "/signup", [("Content-Type", MP)], body, enforce=True)
    assert v is None or v.decision in ("clear", "lead"), f"benign form flagged: {v and v.decision}"
    assert v is None or v.action != "block"


def test_benign_text_plain_does_not_block():
    v = inspect_request("POST", "/note", [("Content-Type", "text/plain")],
                        "Meeting notes: ship the release, review the OR-mapper, drop the old table next week.",
                        enforce=True)
    assert v is None or v.action != "block"


def test_benign_xml_document_does_not_block():
    body = ("<?xml version='1.0'?><order id='7'><customer>Acme Ltd</customer>"
            "<item qty='2'>widget</item><note>deliver before 5pm</note></order>")
    v = inspect_request("POST", "/orders", [("Content-Type", "application/xml")], body, enforce=True)
    assert v is None or v.action != "block", f"benign XML flagged: {v and v.attack_class}"


def test_a_benign_file_upload_does_not_block_even_if_its_bytes_look_hostile():
    # the file part is NOT inspected, so hostile-looking file BYTES cannot trip a block; the text
    # caption is benign, so the whole request is clear.
    body = _multipart(("caption", "my resume"),
                      file_part=("cv", "cv.pdf", "'; DROP TABLE users; -- %00 <script>alert(1)</script>"))
    v = inspect_request("POST", "/upload", [("Content-Type", MP)], body, enforce=True)
    assert v is None or v.action != "block"


# --------------------------------------------------------------------------- starvation fix

def test_a_query_flood_cannot_starve_the_header_cookie_surface():
    # hundreds of junk query params must NOT crowd the cookie/header surface out of inspection.
    flood = "&".join(f"j{i}=v{i}" for i in range(500))
    headers = [("Cookie", "tracking=" + "x' OR '1'='1".replace("'", "%27"))]
    got = candidate_values("/?" + flood, headers, None)
    names = [n for n, _ in got]
    assert any(n.startswith("cookie:") for n in names), "a query flood starved the cookie surface"
    # and end to end the cookie SQLi is still caught despite the flood
    v = inspect_request("GET", "/?" + flood, [("Cookie", "t=" + "x%27%20OR%20%271%27%3D%271")], None,
                        enforce=True)
    assert v is not None and v.decision == "confirmed"


def test_each_source_share_is_bounded():
    flood = "&".join(f"j{i}=v{i}" for i in range(500))
    q = [n for n, _ in candidate_values("/?" + flood, [], None)]
    assert len(q) <= _MAX_QUERY_VALUES, "query surface exceeded its reserved share"
    many_cookies = "; ".join(f"c{i}=v{i}" for i in range(500))
    hc = [n for n, _ in candidate_values("/", [("Cookie", many_cookies)], None)]
    assert len([n for n in hc if n.startswith("cookie:")]) <= _MAX_HC_VALUES
