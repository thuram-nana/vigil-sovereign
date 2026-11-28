"""The VIGIL Security & Trust Center (https://vigilguard.net/trust) and its access-request endpoint.

Honesty-critical invariants (a false or unverified claim on a security product's trust page is a defect):
  * the page is served at /trust with the strict public headers and no cookie, titled the Security & Trust Center;
  * EVERY approved public claim appears VERBATIM with its honest status, and a "Partially Implemented" claim is
    never rounded up to "Verified" (the approved set is docs/trust/public-claims.json, from the code-anchored audit);
  * NO withheld / fabricated claim appears: no wording that ASSERTS a certification, no SOC 2 / ISO / HIPAA /
    FedRAMP badge or "compliant/ready" claim, none of the documents that do not exist;
  * the compliance statements appear verbatim, with no certification badge or seal;
  * the access-request endpoint is same-origin gated, per-source rate-limited, validates every field, records the
    request to a restricted queue (never logs the PII, no PII in any path), and returns a NEUTRAL acknowledgement
    that never claims access was granted or a document delivered.

A negative control proves the honesty checks are not a no-op (an injected affirmative certification / withheld
claim is caught).
"""
from __future__ import annotations

import html
import http.client
import json
import os
import re
import stat
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.pubui import PublicHandler, build_public_server
from sigil.ui import trust_access_requests_store as store

ROOT = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "public_site"
TRUST = ROOT / "trust" / "index.html"
REPO = Path(__file__).resolve().parents[3]
CONTENT = json.loads((REPO / "docs" / "trust" / "public-claims.json").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------------------------
def _collapse(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def _page_text(html_src: str) -> str:
    """The page's visible text, tags stripped and whitespace collapsed (for verbatim substring checks)."""
    return _collapse(html.unescape(re.sub(r"<[^>]+>", " ", html_src)))


# The certification honesty guard is an ALLOWLIST (the same approach the public_site guard uses), re-stated here so
# this suite is self-contained and carries its own negative control. A proximity-negation heuristic is UNSOUND (it
# cannot tell which noun a negator governs). So a certification word-family token is a violation UNLESS it is part
# of a reviewed approved string (every public claim text + every compliance statement in the governance snapshot).
_CERT_FAMILY = re.compile(r"\bcertif(?:y|ies|ied|ying|ication|ications|iable|iably)\b", re.IGNORECASE)
_APPROVED_STRINGS = [c["claim"] for c in CONTENT["public_claims"]] + list(CONTENT["compliance_statements"].values())

# fabricated assertions the old proximity heuristic wrongly cleared; each MUST be flagged (none is an approved denial).
_CERT_BYPASS_ATTEMPTS = (
    "There is no doubt VIGIL is SOC 2 Type II certified.",
    "VIGIL is never not SOC 2 certified.",
    "VIGIL leaves no gaps in its SOC 2 certification.",
    "We spare no effort to keep VIGIL ISO 27001 certified.",
    "No vendor is more thoroughly certified than VIGIL.",
)


def certification_violations(text: str) -> list[str]:
    """Certification word-family tokens that are NOT part of a reviewed approved string (empty == clean). The exact
    approved strings are removed first, so affirmative or cleverly-negated wording that is not a reviewed denial is
    returned as a violation."""
    scrubbed = text
    for s in _APPROVED_STRINGS:
        if s:
            scrubbed = scrubbed.replace(s, " ")
    return _CERT_FAMILY.findall(scrubbed)


# affirmative constructs that must NEVER appear on the page (the withheld / absent set). Each is affirmative-only,
# so an honest denial elsewhere on the page does not trip it.
_FORBIDDEN = [
    r"soc\s*2[\w\s]{0,20}\bcompliant\b",
    r"iso[\s/]*(?:iec)?\s*27001[\w\s]{0,20}\bcompliant\b",
    r"hipaa[\s-]*(?:compliant|ready)\b",
    r"\bfedramp\b",
    r"\bpci[\s-]*dss\b",
    r"security\s+whitepaper",
    r"business\s+continuity\s+policy",
    r"disaster\s+recovery\s+policy",
    r"standalone\s+data\s+deletion\s+policy",
    r"subprocessor\s+register",
    r"data\s+protection\s+overview",
    r"data\s+protection\s+officer",
    r"(?:download|sign)[\w\s]{0,30}(?:data\s+processing\s+agreement|\bdpa\b)",
]


def forbidden_hits(text: str) -> list[str]:
    flat = _collapse(text)
    return [p for p in _FORBIDDEN if re.search(p, flat, re.IGNORECASE)] + certification_violations(flat)


def _serve(root=None, *, access_requests_dir=None, access_limiter=None):
    srv = build_public_server(host="127.0.0.1", port=0, root=root, access_requests_dir=access_requests_dir,
                              access_limiter=access_limiter)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, srv.server_address[1]


def _get(port, path, *, method="GET"):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _post(port, path, body, *, headers=None, host=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {"Host": host or f"127.0.0.1:{port}", **(headers or {})}
    conn.request("POST", path, body=body, headers=h)
    r = conn.getresponse()
    data = r.read()
    out = (r.status, {k.lower(): v for k, v in r.getheaders()}, data)
    conn.close()
    return out


def _json_post(port, payload, *, origin=True, host=None):
    hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
    if origin is True:
        hdrs["Origin"] = f"http://127.0.0.1:{port}"
    elif isinstance(origin, str):
        hdrs["Origin"] = origin
    return _post(port, "/api/trust/access-request", json.dumps(payload), headers=hdrs, host=host)


_GOOD = {"full_name": "Dana Okoro", "organisation": "Acme Security GmbH",
         "email": "dana.okoro@acme-security.example", "job_title": "Head of Security",
         "reason": "Vendor security review ahead of a procurement decision."}


# --------------------------------------------------------------------------------------------------------------
# the page: served, titled, branded
# --------------------------------------------------------------------------------------------------------------
def test_trust_page_served_with_strict_headers_titles_and_no_cookie():
    assert TRUST.is_file()
    srv, port = _serve()
    try:
        code, hdrs, body = _get(port, "/trust")
        assert code == 200 and hdrs.get("Content-Type", "").startswith("text/html")
        text = body.decode("utf-8")
        assert "<h1>VIGIL Security &amp; Trust Center</h1>" in text
        assert "Security. Sovereignty. Verifiable Trust." in text
        assert "default-src 'self'" in hdrs.get("Content-Security-Policy", "")
        assert hdrs.get("X-Frame-Options") == "DENY"
        assert hdrs.get("X-Content-Type-Options") == "nosniff"
        assert "Set-Cookie" not in hdrs
    finally:
        srv.shutdown()


def test_customer_facing_headings_say_vigil_never_sigil():
    text = TRUST.read_text(encoding="utf-8")
    # SIGIL may appear only as the legal entity name "SIGIL SARL" / "SIGIL S" inside a verbatim register statement;
    # it must never be a product name in a heading. Check every heading is SIGIL-free.
    for tag in ("h1", "h2", "h3"):
        for m in re.findall(rf"<{tag}[^>]*>(.*?)</{tag}>", text, re.S | re.I):
            assert "SIGIL" not in m.upper() or "SARL" in m, f"<{tag}> names SIGIL as a product: {m!r}"
    # the brand wordmark + favicons (the brand-asset invariant), and the product name VIGIL is present
    assert 'class="brand__logo" src="/assets/vigil-wordmark-white.svg" alt="VIGIL"' in text
    assert "VIGIL Security &amp; Trust Center" in text


# --------------------------------------------------------------------------------------------------------------
# every approved claim verbatim + honest status; nothing withheld
# --------------------------------------------------------------------------------------------------------------
def _parsed_claim_cards() -> dict:
    text = TRUST.read_text(encoding="utf-8")
    out = {}
    for block in re.findall(r'<article class="claim">(.*?)</article>', text, re.S):
        status = ("Partially Implemented" if "Partially Implemented" in block
                  else ("Verified" if "Verified" in block else None))
        m = re.search(r'<p class="claim__text">(.*?)</p>', block, re.S)
        body = _collapse(html.unescape(re.sub(r"<[^>]+>", " ", m.group(1)))) if m else ""
        out[body] = status
    return out


def test_every_approved_public_claim_appears_verbatim_with_its_honest_status():
    cards = _parsed_claim_cards()
    assert len(cards) == len(CONTENT["public_claims"]), (len(cards), len(CONTENT["public_claims"]))
    for c in CONTENT["public_claims"]:
        want = _collapse(c["claim"])
        assert want in cards, f"claim not shown verbatim: {c['claim'][:70]}..."
        assert cards[want] == c["status"], f"claim shown with wrong status (got {cards[want]}): {c['claim'][:60]}"


def test_partially_implemented_claims_are_shown_as_partial_not_verified():
    cards = _parsed_claim_cards()
    partial = [c for c in CONTENT["public_claims"] if c["status"] == "Partially Implemented"]
    assert partial, "the register has Partially Implemented claims; the test must exercise them"
    for c in partial:
        assert cards[_collapse(c["claim"])] == "Partially Implemented"
    # counts on the page match the register (no rounding up)
    text = TRUST.read_text(encoding="utf-8")
    assert text.count("Partially Implemented</span>") >= len(partial)
    # and there is no invented "certified" status chip
    assert "chip--certified" not in text and ">Certified<" not in text


def test_no_withheld_or_fabricated_claim_appears_on_the_page():
    text = TRUST.read_text(encoding="utf-8")
    hits = forbidden_hits(text)
    assert hits == [], f"the Trust Center shows a withheld/affirmative claim: {hits}"
    # no certification badge or seal image/element
    for m in re.findall(r'<img[^>]*>', text, re.I):
        low = m.lower()
        assert not any(w in low for w in ("soc2", "soc-2", "iso27001", "iso-27001", "hipaa", "fedramp",
                                          "badge", "seal", "certified")), f"a certification badge image: {m}"
    # the absent documents are never named as available
    flat = _page_text(text)
    for absent in ("Security Whitepaper", "Business Continuity Policy", "Disaster Recovery Policy",
                   "Subprocessor Register", "Data Protection Overview", "Data Protection Officer"):
        assert absent not in flat, f"an absent document is shown: {absent}"


def test_the_honesty_checks_are_not_a_no_op():
    # negative controls: every fabricated certification assertion is caught when appended to the real page, however
    # it is phrased (the allowlist does not reason about negation scope), and so is a withheld compliance claim.
    page = TRUST.read_text(encoding="utf-8")
    for attempt in _CERT_BYPASS_ATTEMPTS:
        assert forbidden_hits(page + " <p>" + attempt + "</p>"), f"bypass not flagged: {attempt!r}"
    assert forbidden_hits(page + " <p>VIGIL is HIPAA compliant.</p>")
    assert certification_violations("Our platform is SOC 2 certified") == ["certified"]
    # the genuine reviewed denials that appear on the page are allowed (scrubbed, no violation)
    cert_bearing = [s for s in _APPROVED_STRINGS if _CERT_FAMILY.search(s)]
    assert len(cert_bearing) >= 3
    for denial in cert_bearing:
        assert certification_violations(denial) == [], f"approved denial wrongly flagged: {denial[:60]}"
    assert forbidden_hits("A data processing agreement is available on request.") == []


# --------------------------------------------------------------------------------------------------------------
# compliance statements verbatim, no badges
# --------------------------------------------------------------------------------------------------------------
def test_compliance_statements_appear_verbatim_with_no_badges():
    flat = _page_text(TRUST.read_text(encoding="utf-8"))
    for key, stmt in CONTENT["compliance_statements"].items():
        assert _collapse(stmt) in flat, f"compliance statement {key} not shown verbatim"
    # SOC 2 states no attestation is available; no framework shows a badge word
    assert _collapse(CONTENT["compliance_statements"]["soc2"]).startswith("No SOC 2 attestation report is currently "
                                                                          "available")


# --------------------------------------------------------------------------------------------------------------
# documents: public linked, confidential locked, absent omitted
# --------------------------------------------------------------------------------------------------------------
def test_documents_public_linked_confidential_locked_absent_omitted():
    text = TRUST.read_text(encoding="utf-8")
    srv, port = _serve()
    try:
        # public documents link out and are served
        for href in ("/privacy", "/terms", "/cookies", "/support", "/.well-known/security.txt"):
            assert f'href="{href}"' in text, f"public document not linked: {href}"
            assert _get(port, href)[0] == 200, f"linked public document not served: {href}"
    finally:
        srv.shutdown()
    # the two confidential documents sit behind a lock + a Request access action, NOT a direct link
    for name in ("Data Retention Policy", "Security Incident Response Policy"):
        assert name in text, f"confidential document not offered behind access: {name}"
    assert 'class="doc doc--locked"' in text and "Request access" in text
    # the confidential docs are NOT directly linked to their internal docs/ path
    assert "docs/legal/DATA-RETENTION" not in text and "docs/legal/INCIDENT-RESPONSE" not in text


def test_trust_page_references_its_own_versioned_css_and_js_csp_clean():
    srv, port = _serve()
    try:
        _c, _h, body = _get(port, "/trust")
        page = body.decode("utf-8")
        # trust.css and trust.js are referenced and versioned by the snapshot (?v=<digest>)
        refs = dict(re.findall(r'(?:href|src)="(/assets/trust\.(?:css|js))\?v=([0-9a-f]{12})"', page))
        assert "/assets/trust.css" in refs and "/assets/trust.js" in refs, page
        for url, digest in refs.items():
            code, h, _ = _get(port, f"{url}?v={digest}")
            assert code == 200 and "immutable" in h.get("Cache-Control", ""), (url, h)
        # CSP clean: no inline <script>...</script> body, no inline style attribute on interactive bits, no remote src
        assert not re.search(r"<script(?![^>]*\ssrc=)[^>]*>\s*\S", page), "an inline script is present"
        for src in re.findall(r'<script[^>]*\ssrc="([^"]+)"', page):
            assert src.startswith("/assets/"), f"remote script: {src}"
        # no inline event handlers and no inline style attribute (the CSP has no 'unsafe-inline')
        assert "onclick=" not in page.lower() and "onsubmit=" not in page.lower()
        assert 'style="' not in page, "the page carries an inline style attribute (the CSP forbids it)"
        # every stylesheet link is same-origin (no remote font/CDN)
        for url in re.findall(r'<link[^>]*\shref="([^"]+)"', page):
            assert url.startswith("/"), f"off-site stylesheet/link: {url}"
    finally:
        srv.shutdown()


# --------------------------------------------------------------------------------------------------------------
# the access-request endpoint
# --------------------------------------------------------------------------------------------------------------
def _loose_limiter(tmp):
    return LoginRateLimiter(tmp, max_fails=1000, window_s=3600, base_lock_s=1, max_lock_s=1)


def test_access_request_valid_submission_stores_and_returns_neutral_ack(tmp_path):
    reqdir = tmp_path / "req"
    srv, port = _serve(access_requests_dir=reqdir, access_limiter=_loose_limiter(tmp_path / "lim"))
    try:
        code, hdrs, body = _json_post(port, _GOOD)
        assert code == 200, (code, body)
        data = json.loads(body)
        assert data["ok"] is True
        msg = data["message"].lower()
        # the acknowledgement is NEUTRAL: it never claims access was granted or a document delivered/sent
        assert "received" in msg
        assert "no access has been granted" in msg and "no document has been sent" in msg  # explicit denials
        for forbidden in ("access granted", "you now have access", "document attached", "download your",
                          "here is the", "has been granted access", "we have granted", "your request is approved"):
            assert forbidden not in msg, f"the ack over-promises: {forbidden!r}"
        assert "set-cookie" not in hdrs and hdrs.get("cache-control") == "no-store"
        # it was actually stored (we never ack a request we did not record)
        assert store.pending_count(reqdir) == 1
    finally:
        srv.shutdown()


def test_access_request_rejects_cross_origin_and_missing_origin(tmp_path):
    srv, port = _serve(access_requests_dir=tmp_path / "req", access_limiter=_loose_limiter(tmp_path / "lim"))
    try:
        # foreign Origin
        code, _h, _b = _json_post(port, _GOOD, origin="https://evil.example")
        assert code == 403
        # Sec-Fetch-Site: cross-site
        code2, _h, _b = _post(port, "/api/trust/access-request", json.dumps(_GOOD),
                              headers={"Content-Type": "application/json", "Accept": "application/json",
                                       "Origin": f"http://127.0.0.1:{port}", "Sec-Fetch-Site": "cross-site"})
        assert code2 == 403
        # no Origin and no Referer at all
        code3, _h, _b = _post(port, "/api/trust/access-request", json.dumps(_GOOD),
                              headers={"Content-Type": "application/json", "Accept": "application/json"})
        assert code3 == 403
        assert store.pending_count(tmp_path / "req") == 0   # nothing stored for a rejected origin
    finally:
        srv.shutdown()


def test_access_request_validates_every_field(tmp_path):
    reqdir = tmp_path / "req"
    srv, port = _serve(access_requests_dir=reqdir, access_limiter=_loose_limiter(tmp_path / "lim"))
    try:
        # missing a required field
        bad = dict(_GOOD); bad.pop("organisation")
        code, _h, body = _json_post(port, bad)
        assert code == 400 and json.loads(body)["fields"].get("organisation")
        # malformed email
        bad2 = dict(_GOOD, email="not-an-email")
        code2, _h, body2 = _json_post(port, bad2)
        assert code2 == 400 and json.loads(body2)["fields"].get("email")
        # a blank field
        bad3 = dict(_GOOD, full_name="   ")
        code3, _h, body3 = _json_post(port, bad3)
        assert code3 == 400 and json.loads(body3)["fields"].get("full_name")
        # nothing invalid was stored
        assert store.pending_count(reqdir) == 0
    finally:
        srv.shutdown()


def test_access_request_rate_limits_per_source(tmp_path):
    limiter = LoginRateLimiter(tmp_path / "lim", max_fails=3, window_s=3600, base_lock_s=60, max_lock_s=60)
    srv, port = _serve(access_requests_dir=tmp_path / "req", access_limiter=limiter)
    try:
        codes = [_json_post(port, _GOOD)[0] for _ in range(4)]
        assert codes[:3] == [200, 200, 200], codes
        assert codes[3] == 429, codes
        # the 429 carries a Retry-After and stored nothing beyond the admitted three
        _c, hdrs, _b = _json_post(port, _GOOD)
        assert "Retry-After" in {k.title(): v for k, v in hdrs.items()} or "retry-after" in hdrs
        assert store.pending_count(tmp_path / "req") == 3
    finally:
        srv.shutdown()


def test_access_request_rate_limit_keys_on_the_trusted_client_ip(tmp_path):
    # Issue-B regression: the limiter must key on the real client IP taken from X-Real-IP (trusted ONLY from the
    # loopback proxy hop), so two distinct sources have INDEPENDENT budgets. The shipped public proxies now SET
    # X-Real-IP from the real peer (overwriting any client value), so this per-source key cannot be spoofed to
    # dodge the throttle, nor collapsed onto one global bucket. With no X-Real-IP the earlier test keys them all
    # onto the loopback peer; here two different X-Real-IP values must NOT share a budget.
    limiter = LoginRateLimiter(tmp_path / "lim", max_fails=1, window_s=3600, base_lock_s=60, max_lock_s=60)
    srv, port = _serve(access_requests_dir=tmp_path / "req", access_limiter=limiter)

    def submit(ip):
        return _post(port, "/api/trust/access-request", json.dumps(_GOOD),
                     headers={"Content-Type": "application/json", "Accept": "application/json",
                              "Origin": f"http://127.0.0.1:{port}", "X-Real-IP": ip})[0]
    try:
        assert submit("203.0.113.10") == 200          # source A, first attempt: admitted on A's own budget
        assert submit("203.0.113.20") == 200          # source B: an INDEPENDENT key, also admitted (not collapsed)
        assert submit("203.0.113.10") == 429          # A is now locked on A's budget alone
        assert submit("203.0.113.20") == 429          # B is locked on B's budget alone
        # exactly the two admitted requests were queued (one per distinct source)
        assert store.pending_count(tmp_path / "req") == 2
    finally:
        srv.shutdown()


def test_access_request_stores_restricted_and_never_puts_pii_in_a_path(tmp_path):
    reqdir = tmp_path / "req"
    srv, port = _serve(access_requests_dir=reqdir, access_limiter=_loose_limiter(tmp_path / "lim"))
    try:
        assert _json_post(port, _GOOD)[0] == 200
    finally:
        srv.shutdown()
    files = list(reqdir.glob("*.json"))
    assert len(files) == 1
    f = files[0]
    # the queue file is 0600 in a 0700 dir (protected at rest), filename carries NO submitted value
    assert stat.S_IMODE(f.stat().st_mode) == 0o600, oct(f.stat().st_mode)
    assert stat.S_IMODE(os.stat(reqdir).st_mode) == 0o700
    assert _GOOD["email"] not in f.name and "Dana" not in f.name and "Okoro" not in f.name
    rec = json.loads(f.read_text(encoding="utf-8"))
    # the owner-side intake needs the contact details, so the record holds them (queued, not logged)
    assert rec["email"] == _GOOD["email"] and rec["full_name"] == _GOOD["full_name"]
    # the public handler never logs (so the PII is never written to a log in plaintext)
    assert PublicHandler.log_message.__qualname__.startswith("PublicHandler")
    # calling it is a no-op (does not raise, returns None)
    assert PublicHandler.log_message(object(), "%s", "x") is None


def test_access_request_no_js_form_post_degrades_to_an_html_ack(tmp_path):
    reqdir = tmp_path / "req"
    srv, port = _serve(access_requests_dir=reqdir, access_limiter=_loose_limiter(tmp_path / "lim"))
    try:
        from urllib.parse import urlencode
        body = urlencode(_GOOD)
        code, hdrs, data = _post(port, "/api/trust/access-request", body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded",
                                          "Accept": "text/html", "Origin": f"http://127.0.0.1:{port}",
                                          "Sec-Fetch-Mode": "navigate"})
        assert code == 200 and hdrs.get("content-type", "").startswith("text/html")
        assert b"Request received" in data and b"No access has been granted" in data
        assert store.pending_count(reqdir) == 1
    finally:
        srv.shutdown()


def test_only_get_head_post_are_answered_and_other_post_paths_404(tmp_path):
    srv, port = _serve(access_requests_dir=tmp_path / "req", access_limiter=_loose_limiter(tmp_path / "lim"))
    try:
        code, _h, _b = _post(port, "/api/trust/other", "{}",
                             headers={"Content-Type": "application/json",
                                      "Origin": f"http://127.0.0.1:{port}"})
        assert code == 404
    finally:
        srv.shutdown()


# --------------------------------------------------------------------------------------------------------------
# the store's own validation (unit)
# --------------------------------------------------------------------------------------------------------------
def test_store_validate_accepts_good_and_rejects_bad():
    clean, errors = store.validate(dict(_GOOD))
    assert not errors and clean["email"] == _GOOD["email"]
    # required
    _c, e = store.validate({**_GOOD, "reason": ""})
    assert "reason" in e
    # email format
    _c, e = store.validate({**_GOOD, "email": "a@b"})
    assert "email" in e
    # over-long
    _c, e = store.validate({**_GOOD, "full_name": "x" * 500})
    assert "full_name" in e
    # control characters / header-injection attempt in a single-line field
    _c, e = store.validate({**_GOOD, "organisation": "Acme\r\nBcc: evil@x"})
    assert "organisation" in e


def test_store_record_is_fail_closed_on_bad_input(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        store.record_request({"full_name": "x"}, requests_dir=tmp_path / "q")   # missing fields
