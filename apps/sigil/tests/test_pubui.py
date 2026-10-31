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


def test_public_site_honors_the_honesty_constraints():
    # Durable guard for the three honesty rules the build spec (and the reviewer-package gate
    # tools/reviewer-package/assemble.py::assert_no_certification_wording) require on public copy:
    #   * "source-available", NEVER "open source";
    #   * no certification word-family claim (certify/certified/certification/...) — "certificate" is allowed;
    #   * no fabricated "start for free" hosted-signup CTA (SaaS is not shipped).
    import pathlib
    import re
    root = pathlib.Path(__file__).resolve().parents[1] / "sigil" / "ui" / "public_site"
    cert_re = re.compile(r"\bcertif(?:y|ies|ied|ying|ication|ications|iable|iably)\b", re.IGNORECASE)
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
        if cert_re.search(text):
            offenders.append(f"{rel}: certification word-family (negated or not — avoid it)")
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
