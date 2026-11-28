"""VIGIL public site plane (`pubui`) — a keyless, cookieless, offense-free static server.

Load-bearing invariants:
  * serves static files from the content root with the strict public CSP + nosniff + no-referrer + DENY
    framing, and NEVER a Set-Cookie / token (there is no session on this plane);
  * pretty/extension-less routes resolve to `<path>.html` then `<path>/index.html`; "/" → index.html;
  * path traversal outside the content root is refused (404), never served;
  * an unknown path returns the custom 404 page;
  * binds a bind_ok address only (a public/unspecified bind is refused fail-closed);
  * HEAD works and sends no body.
"""
from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.request

import pytest

from sigil.ui.pubui import PublicHandler, PublicServer, build_public_server


def _serve(root=None):
    srv = build_public_server(host="127.0.0.1", port=0, root=root)
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


def test_landing_is_served_with_strict_headers_and_no_cookie():
    srv, port = _serve()
    try:
        code, hdrs, body = _get(port, "/")
        assert code == 200
        assert hdrs.get("Content-Type", "").startswith("text/html")
        assert b"VIGIL" in body and b"Prove, don" in body             # the real landing content
        # strict public headers, set as headers (never <meta>)
        assert "default-src 'self'" in hdrs.get("Content-Security-Policy", "")
        assert hdrs.get("X-Content-Type-Options") == "nosniff"
        assert hdrs.get("Referrer-Policy") == "no-referrer"
        assert hdrs.get("X-Frame-Options") == "DENY"
        # the public plane is cookieless + tokenless by construction
        assert "Set-Cookie" not in hdrs
    finally:
        srv.shutdown()


def test_static_assets_and_wellknown_served_with_types():
    srv, port = _serve()
    try:
        c, h, _ = _get(port, "/assets/site.css")
        assert c == 200 and h.get("Content-Type", "").startswith("text/css")
        c, h, _ = _get(port, "/assets/favicon.svg")
        assert c == 200 and h.get("Content-Type") == "image/svg+xml"
        c, h, b = _get(port, "/.well-known/security.txt")
        assert c == 200 and h.get("Content-Type", "").startswith("text/plain") and b"Contact:" in b
    finally:
        srv.shutdown()


def test_unknown_path_returns_custom_404():
    srv, port = _serve()
    try:
        code, hdrs, body = _get(port, "/does-not-exist")
        assert code == 404
        assert b"couldn't be proven to exist" in body                 # the custom 404.html
        assert "default-src 'self'" in hdrs.get("Content-Security-Policy", "")
        assert "Set-Cookie" not in hdrs
    finally:
        srv.shutdown()


def test_pretty_routes_resolve_to_html_and_index(tmp_path):
    # <path> -> <path>.html, and <dir> -> <dir>/index.html
    (tmp_path / "vs").mkdir()
    (tmp_path / "vs" / "index.html").write_text("<h1>compare</h1>", encoding="utf-8")
    (tmp_path / "trust.html").write_text("<h1>trust</h1>", encoding="utf-8")
    (tmp_path / "index.html").write_text("<h1>home</h1>", encoding="utf-8")
    srv, port = _serve(root=str(tmp_path))
    try:
        assert _get(port, "/vs")[2] == b"<h1>compare</h1>"            # dir -> index.html
        assert _get(port, "/trust")[2] == b"<h1>trust</h1>"           # extensionless -> .html
        assert _get(port, "/")[2] == b"<h1>home</h1>"
    finally:
        srv.shutdown()


def test_path_traversal_is_refused(tmp_path):
    (tmp_path / "index.html").write_text("ok", encoding="utf-8")
    secret = tmp_path.parent / "secret.txt"
    secret.write_text("TOP SECRET", encoding="utf-8")
    srv, port = _serve(root=str(tmp_path))
    try:
        # encoded ../ must not climb out of the content root
        code, _, body = _get(port, "/%2e%2e/secret.txt")
        assert code == 404 and b"TOP SECRET" not in body
        code, _, body = _get(port, "/assets/%2e%2e/%2e%2e/secret.txt")
        assert code == 404 and b"TOP SECRET" not in body
    finally:
        srv.shutdown()


def test_head_sends_headers_without_body():
    srv, port = _serve()
    try:
        code, hdrs, body = _get(port, "/", method="HEAD")
        assert code == 200 and body == b""
        assert int(hdrs.get("Content-Length", "0")) > 0              # length advertised, body omitted
    finally:
        srv.shutdown()


def test_public_bind_is_fail_closed():
    for bad in ("0.0.0.0", "::", "8.8.8.8"):
        with pytest.raises(ValueError):
            PublicServer((bad, 0), PublicHandler)


# The certification word-family (certify/certified/certification/...); "certificate" (the cryptographic term) is
# deliberately NOT matched. The guard's documented intent (tools/reviewer-package/assemble.py) is to forbid wording
# that ASSERTS a certification. The Security & Trust Center states, VERBATIM from the code-anchored register, that
# VIGIL holds NO certification; those exact reviewed denials are the ONLY place a certification word may appear.
#
# A proximity-negation heuristic is UNSOUND: it measures how close a negator sits, not which noun it governs, so
# "there is no doubt VIGIL is SOC 2 certified", a double negative, or "leaves no gaps in its SOC 2 certification"
# all slip through. So the guard is an ALLOWLIST, not a heuristic: it removes the exact reviewed approved strings
# (docs/trust/public-claims.json: every public claim text and every compliance statement) from the scanned text,
# then flags ANY remaining certification word. Any certification wording that is not verbatim an approved denial,
# affirmative or cleverly negated, survives the scrub and fails CI, forcing a human to review it.
_CERT_FAMILY_RE = re.compile(r"\bcertif(?:y|ies|ied|ying|ication|ications|iable|iably)\b", re.IGNORECASE)


def _approved_public_strings() -> list[str]:
    """The reviewed strings that may carry a certification word: every public claim text and every compliance
    statement in the committed governance snapshot (docs/trust/public-claims.json)."""
    from pathlib import Path
    repo = Path(__file__).resolve().parents[3]
    data = json.loads((repo / "docs" / "trust" / "public-claims.json").read_text(encoding="utf-8"))
    return [c["claim"] for c in data["public_claims"]] + list(data["compliance_statements"].values())


def certification_violations(text: str, approved: "list[str] | None" = None) -> list[str]:
    """Certification word-family tokens in ``text`` that are NOT part of a reviewed approved string (empty ==
    clean). The exact approved strings are removed first, so only verbatim approved denials are permitted; every
    other certification token (an affirmative claim, or a negated one that is not a reviewed denial) is returned."""
    scrubbed = text
    for s in (approved if approved is not None else _approved_public_strings()):
        if s:
            scrubbed = scrubbed.replace(s, " ")
    return _CERT_FAMILY_RE.findall(scrubbed)


# The fabricated assertions the old proximity heuristic let through (negator present, but governing another noun,
# or a double negative). Each MUST now be flagged, because none is a verbatim approved denial.
_CERT_BYPASS_ATTEMPTS = (
    "There is no doubt VIGIL is SOC 2 Type II certified.",
    "VIGIL is never not SOC 2 certified.",
    "VIGIL leaves no gaps in its SOC 2 certification.",
    "We spare no effort to keep VIGIL ISO 27001 certified.",
    "No vendor is more thoroughly certified than VIGIL.",
)


def test_certification_guard_flags_unapproved_cert_wording_and_allows_only_reviewed_denials():
    approved = _approved_public_strings()
    # every fabricated assertion is caught, however it is phrased (the allowlist does not reason about negation scope)
    for attempt in _CERT_BYPASS_ATTEMPTS:
        assert certification_violations(attempt, approved), f"bypass not flagged: {attempt!r}"
    assert certification_violations("VIGIL is ISO 27001 certified.", approved) == ["certified"]
    # the genuine, reviewed denials that DO appear on the page are allowed (scrubbed, no violation)
    cert_bearing = [s for s in approved if _CERT_FAMILY_RE.search(s)]
    assert len(cert_bearing) >= 3, "the approved set must carry the ISO / GDPR / infrastructure denials"
    for denial in cert_bearing:
        assert certification_violations(denial, approved) == [], f"approved denial wrongly flagged: {denial[:60]}"
    # "certificate" (the cryptographic term) is never a certification word
    assert certification_violations("Every finding ships as a signed certificate.", approved) == []


def test_public_site_honors_the_honesty_constraints():
    # Durable guard for the honesty rules the build spec (and the reviewer-package gate
    # tools/reviewer-package/assemble.py::assert_no_certification_wording) require on public copy:
    #   * "source-available", NEVER "open source";
    #   * no certification word-family token that is not part of a reviewed approved denial (an allowlist, not a
    #     negation heuristic); "certificate" is allowed;
    #   * no fabricated "start for free" hosted-signup CTA (SaaS is not shipped).
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1] / "sigil" / "ui" / "public_site"
    approved = _approved_public_strings()
    opensrc_re = re.compile(r"open[\s-]?source", re.IGNORECASE)
    freecta_re = re.compile(r"start\s+for\s+free", re.IGNORECASE)
    offenders = []
    for f in root.rglob("*"):
        if f.suffix.lower() not in (".html", ".css", ".js", ".txt", ".xml"):
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        rel = f.relative_to(root)
        if opensrc_re.search(text):
            offenders.append(f"{rel}: 'open source' (say 'source-available')")
        cviol = certification_violations(text, approved)
        if cviol:
            offenders.append(f"{rel}: certification word(s) {sorted(set(cviol))} not part of a reviewed approved "
                             "denial (affirmative or cleverly-negated wording must be reviewed)")
        if freecta_re.search(text):
            offenders.append(f"{rel}: 'start for free' (no hosted signup is shipped)")
    assert not offenders, "public-site honesty violations:\n  " + "\n  ".join(offenders)


def test_cve_api_over_a_seeded_catalog(tmp_path):
    from sigil.cve.catalog import CveCatalogStore
    from sigil.ui.pubui import PublicHandler, PublicServer
    db = tmp_path / "cat.db"
    st = CveCatalogStore(str(db))
    st.merge_many([
        {"id": "CVE-2021-44228", "title": "Log4Shell", "cvss_base": 10.0, "kev": True,
         "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "cwes": ["CWE-502"]},
        {"id": "CVE-2023-0001", "title": "lesser", "cvss_base": 5.0},
    ])
    srv = PublicServer(("127.0.0.1", 0), PublicHandler, catalog_path=str(db))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    port = srv.server_address[1]
    try:
        c, h, b = _get(port, "/api/cve?per_page=10")
        d = json.loads(b)
        assert c == 200 and h.get("Content-Type", "").startswith("application/json")
        assert d["populated"] is True and d["total"] == 2
        assert json.loads(_get(port, "/api/cve?kev=1")[2])["total"] == 1
        assert json.loads(_get(port, "/api/cve?severity=critical")[2])["total"] == 1
        rec = json.loads(_get(port, "/api/cve/CVE-2021-44228")[2])
        assert rec["id"] == "CVE-2021-44228" and rec["kev"] is True and rec["severity"] == "critical"
        assert json.loads(_get(port, "/api/cve/stats")[2])["kev"] == 1
        assert any(y["year"] == 2021 for y in json.loads(_get(port, "/api/cve/years")[2])["years"])
        assert _get(port, "/api/cve/CVE-1999-0000")[0] == 404
        # pretty dynamic routes serve the static shells (then client JS fills them)
        c, _, b = _get(port, "/cve/CVE-2021-44228")
        assert c == 200 and b"cve-detail" in b
        c, _, b = _get(port, "/cve/year/2021")
        assert c == 200 and b"cve-year-h1" in b
        # no cookie on any public-plane response
        assert "Set-Cookie" not in h
    finally:
        srv.shutdown()


def test_cve_api_is_honestly_empty_without_a_catalog(tmp_path):
    from sigil.ui.pubui import PublicHandler, PublicServer
    srv = PublicServer(("127.0.0.1", 0), PublicHandler, catalog_path=str(tmp_path / "absent.db"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    port = srv.server_address[1]
    try:
        d = json.loads(_get(port, "/api/cve")[2])
        assert d["populated"] is False and d["total"] == 0 and d["items"] == []
        assert json.loads(_get(port, "/api/cve/stats")[2])["populated"] is False
    finally:
        srv.shutdown()


def test_every_page_carries_the_owner_logo_and_favicons():
    # The owner's logo replaced the old shield mark: every page links the ICO + SVG favicons and the iOS icon, its
    # header shows the white wordmark (the site is dark-only), and every /assets/ file a page names exists.
    import pathlib
    import re
    root = pathlib.Path(__file__).resolve().parents[1] / "sigil" / "ui" / "public_site"
    pages = sorted(root.rglob("*.html"))
    assert len(pages) >= 15
    for page in pages:
        html = page.read_text(encoding="utf-8")
        rel = page.relative_to(root)
        assert '<link rel="icon" href="/assets/favicon.ico" sizes="any">' in html, rel
        assert '<link rel="icon" href="/assets/favicon.svg" type="image/svg+xml">' in html, rel
        assert '<link rel="apple-touch-icon" href="/assets/apple-touch-icon.png">' in html, rel
        assert 'class="brand__logo" src="/assets/vigil-wordmark-white.svg" alt="VIGIL"' in html, rel
        assert "brand__mark" not in html, rel
        for ref in re.findall(r'(?:href|src)="(/assets/[^"?#]+)"', html):
            assert (root / ref.lstrip("/")).is_file(), f"{rel} names a missing asset {ref}"
