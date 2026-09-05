"""Wave 2 — the ENGAGE oracle seam confirms the RESPONSE-DERIVED classes via ``live.runtime_redrive``.

path_traversal (side_effect over a KNOWN file-content signature), reflected xss (reflection_context — the
canary reaches an EXECUTABLE HTML position), and exposure (predicate over a secret signature at a fixed
framework path) now mint signed FACTs from the autonomous chat/engage re-drive. This pins:

  * ``VigilEngine._redrive_spec`` emits a ``{"kind": "runtime", ...}`` spec for these classes (+ aliases).
  * ``wiring._live_runtime_redrive_fact`` mints a signed FACT ONLY when the matching deterministic oracle
    confirms the CLAIMED class over VIGIL's own gated live capture — and mints NOTHING for a benign endpoint
    (the mandatory negative controls), a non-runtime class, or an out-of-scope URL.

Reuses the reviewed gated send (web_redrive._gated_web_send) and the existing checks
(ContentSignatureCheck / MarkerReflectionCheck / PathProbeCheck) + oracles; this file proves the routing +
live positive + the negative controls end-to-end.
"""
from __future__ import annotations

import http.server
import threading
import types
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")


# ---------------------------------------------------------------------------------------------------
# hermetic: _redrive_spec routing
# ---------------------------------------------------------------------------------------------------

def _decision(bug_class: str, *, url: str) -> types.SimpleNamespace:
    analysis = types.SimpleNamespace(exploit_succeeded=True, extracted_info={"bug_class": bug_class})
    tool = types.SimpleNamespace(tool_args={"url": url})
    return types.SimpleNamespace(tool=tool, output_analysis=analysis)


@pytest.mark.parametrize("claimed,norm", [
    ("path_traversal", "path_traversal"), ("directory_traversal", "path_traversal"),
    ("xss", "xss"), ("reflected_xss", "xss"), ("cross_site_scripting", "xss"),
    ("exposure", "exposure"), ("information_disclosure", "exposure"), ("framework_exposure", "exposure"),
])
def test_redrive_spec_emits_a_runtime_spec_for_response_derived_classes(claimed, norm):
    from vigil_integration.live.engine import VigilEngine
    spec = VigilEngine._redrive_spec(
        _decision(claimed, url="http://127.0.0.1:19010/documents/download?file=x"), None)
    assert spec is not None, f"{claimed} should be re-drivable"
    assert spec["kind"] == "runtime"
    assert spec["bug_class"] == norm
    assert spec["url"].endswith("/documents/download?file=x")


# ---------------------------------------------------------------------------------------------------
# live: _live_runtime_redrive_fact over a loopback app (positive + mandatory negative controls)
# ---------------------------------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")


def _grant_active_recon(monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path: Path, host: str, slug: str = "alpha") -> None:
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `tester`     Date: `2026-05-04`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n"
        f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def _prov(slug: str = "alpha"):
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    from vigil_integration.live.wiring import Provisioned
    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return Provisioned(keypair=kp, trust_root=tr, signers=[("gov0", kp.private_key_b64)],
                       authority_path="", slug=slug)


_DECOY_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
_DOTENV = "APP_ENV=production\nDB_PASSWORD=Sup3rSecret-LAB-DECOY-not-real\nJWT_SECRET=lab-decoy\n"


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&#x27;"))


class _VulnApp(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        from urllib.parse import parse_qs, urlsplit
        parts = urlsplit(self.path)
        q = parse_qs(parts.query)
        path = parts.path
        if path == "/download":                                   # VULNERABLE path traversal
            f = (q.get("file") or [""])[0]
            if any(t in f for t in ("..", "%2e", "/etc/", "passwd")):
                return self._text(_DECOY_PASSWD, "text/plain")
            return self._text("report contents", "text/plain")
        if path == "/static":                                     # BENIGN: fixed body, no file signature
            return self._text("<html><body>static page</body></html>", "text/html")
        if path == "/search":                                     # VULNERABLE reflected xss (unescaped)
            v = (q.get("q") or [""])[0]
            return self._text(f"<html><body><h1>Results for: {v}</h1></body></html>", "text/html")
        if path == "/search-safe":                               # BENIGN: HTML-escaped reflection (inert)
            v = (q.get("q") or [""])[0]
            return self._text(f"<html><body><h1>Results for: {_esc(v)}</h1></body></html>", "text/html")
        if path == "/.env":                                       # VULNERABLE exposure
            return self._text(_DOTENV, "text/plain")
        self.send_response(404); self.end_headers()

    def _text(self, body: str, ctype: str):
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):  # silence
        return


class _SafeApp(http.server.BaseHTTPRequestHandler):
    """404s everything — the exposure negative control (no /.env, no /actuator/env, no /.git/config)."""
    def do_GET(self):  # noqa: N802
        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"Not Found")

    def log_message(self, *a):  # silence
        return


def _serve(handler=_VulnApp):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _redrive(url: str, bug_class: str) -> dict:
    return {"kind": "runtime", "url": url, "bug_class": bug_class}


def _fact(monkeypatch, tmp_path, url: str, bug_class: str, handler=_VulnApp):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.wiring import _live_runtime_redrive_fact
    srv = _serve(handler); port = srv.server_address[1]
    try:
        return _live_runtime_redrive_fact(_prov(), {}, _redrive(url.format(port=port), bug_class))
    finally:
        srv.shutdown()


# -- positives --------------------------------------------------------------------------------------

def test_live_path_traversal_mints_a_fact(monkeypatch, tmp_path):
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/download?file=report.pdf", "path_traversal")
    assert ref, "a live traversal that reads /etc/passwd must mint a signed FACT"


def test_live_reflected_xss_mints_a_fact(monkeypatch, tmp_path):
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/search?q=hello", "xss")
    assert ref, "a live unescaped reflection into an executable position must mint a signed FACT"


def test_live_exposure_mints_a_fact(monkeypatch, tmp_path):
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/", "exposure")
    assert ref, "a live /.env leaking DB_PASSWORD must mint a signed FACT"


# -- mandatory negative controls --------------------------------------------------------------------

def test_negctl_path_traversal_benign_endpoint_mints_nothing(monkeypatch, tmp_path):
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/static", "path_traversal")
    assert ref is None, "an endpoint that never returns file content must not mint a traversal FACT"


def test_negctl_reflected_xss_escaped_endpoint_mints_nothing(monkeypatch, tmp_path):
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/search-safe?q=hello", "xss")
    assert ref is None, "an HTML-escaping endpoint (inert reflection) must not mint an xss FACT"


def test_negctl_exposure_no_secret_mints_nothing(monkeypatch, tmp_path):
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/", "exposure", handler=_SafeApp)
    assert ref is None, "a host that 404s /.env etc. must not mint an exposure FACT"


def test_negctl_wrong_class_mints_nothing(monkeypatch, tmp_path):
    """An exposure claim over a traversal-only endpoint must not mint (the /.env probe 404s here)."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/download?file=x", "exposure",
                handler=_SafeApp)
    assert ref is None


def test_non_runtime_class_is_not_handled_here(monkeypatch, tmp_path):
    """A web-fact class (open_redirect) is routed to the web seam, not this one → None here."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/search?q=x", "open_redirect")
    assert ref is None


def test_out_of_scope_url_mints_nothing(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")   # only 127.0.0.1 is in scope
    from vigil_integration.live.wiring import _live_runtime_redrive_fact
    ref = _live_runtime_redrive_fact(
        _prov(), {}, _redrive("http://10.99.99.99/download?file=x", "path_traversal"))
    assert ref is None, "an out-of-scope target must never mint a FACT"


# ---------------------------------------------------------------------------------------------------
# red-pen near-miss negative controls (BLOCK-1/2/3): presence != causation
# ---------------------------------------------------------------------------------------------------

class _DocsApp(http.server.BaseHTTPRequestHandler):
    """BLOCK-1 near-miss: a benign docs page that IGNORES ?file and always prints the passwd signature as
    documentation. A presence-only check would false-FACT; the control differential must refuse it."""
    def do_GET(self):  # noqa: N802
        body = ("<html><body><h1>Docs</h1><p>An /etc/passwd line looks like: "
                "<code>root:x:0:0:root:/root:/bin/bash</code></p></body></html>")
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers(); self.wfile.write(raw)

    def log_message(self, *a):
        return


class _SpaApp(http.server.BaseHTTPRequestHandler):
    """BLOCK-2 near-miss: a 200 soft-404 SPA that serves the SAME bundle (naming DB_PASSWORD=... in a JS
    config) at EVERY path. The random-path control must catch the catch-all and refuse."""
    def do_GET(self):  # noqa: N802
        body = ("<html><head><script>window.__CFG='APP_ENV=prod;DB_PASSWORD=placeholder;'</script></head>"
                "<body>app</body></html>")
        raw = body.encode("utf-8")
        self.send_response(200)   # 200 for EVERYTHING (soft-404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers(); self.wfile.write(raw)

    def log_message(self, *a):
        return


class _JsStringApp(http.server.BaseHTTPRequestHandler):
    """BLOCK-3 near-miss: /search reflects q into a QUOTE-ESCAPED JS string literal inside <script> (the SAFE
    server-side pattern). The canary is present in <script> text but did NOT break out — must NOT mint."""
    def do_GET(self):  # noqa: N802
        from urllib.parse import parse_qs, urlsplit
        v = (parse_qs(urlsplit(self.path).query).get("q") or [""])[0]
        safe = v.replace("\\", "\\\\").replace('"', '\\"')   # escape the JS string literal
        body = f'<html><head><script>var searchTerm = "{safe}";</script></head><body>ok</body></html>'
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers(); self.wfile.write(raw)

    def log_message(self, *a):
        return


def test_negctl_path_traversal_docs_page_with_signature_mints_nothing(monkeypatch, tmp_path):
    """BLOCK-1: a page that always shows root:x:0:0: (docs) but does not READ the file must not mint."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/docs", "path_traversal", handler=_DocsApp)
    assert ref is None, "a docs page that merely prints the signature must not mint a traversal FACT"


def test_negctl_exposure_soft_404_spa_mints_nothing(monkeypatch, tmp_path):
    """BLOCK-2: a 200 soft-404 SPA that names DB_PASSWORD everywhere must not mint (control catches it)."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/", "exposure", handler=_SpaApp)
    assert ref is None, "a soft-404 catch-all naming the signature everywhere must not mint an exposure FACT"


def test_negctl_xss_quote_escaped_js_string_mints_nothing(monkeypatch, tmp_path):
    """BLOCK-3: a canary reflected into a quote-escaped <script> string literal (no breakout) must not mint."""
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/search?q=hello", "xss", handler=_JsStringApp)
    assert ref is None, "a quote-escaped JS-string reflection (presence, not breakout) must not mint an xss FACT"
