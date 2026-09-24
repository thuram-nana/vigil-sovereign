"""Wave 4.1 — the ENGAGE oracle seam confirms Server-Side Includes (SSI, CWE-97) via ``live.runtime_redrive``.

SSI now mints a signed FACT from the autonomous chat/engage re-drive on the SOUND minting path: the
``ssi_evaluation`` oracle over VIGIL's OWN gated live capture, where the RUNNER (never a tool/LLM) crafts an
``<!--#set var=X value="N1*N2" --><!--#echo var=X -->`` directive pair carrying a PER-PROBE RANDOM product and
the oracle confirms the server EVALUATED it — the product present, the raw directive ABSENT, and a benign
no-directive control lacking it. This pins:

  * ``VigilEngine._redrive_spec`` emits a ``{"kind": "runtime", ...}`` spec for ``ssi`` (+ aliases).
  * ``wiring._live_runtime_redrive_fact`` mints a signed FACT ONLY when the deterministic oracle confirms a
    real evaluation over VIGIL's own gated live capture — and mints NOTHING for the benign twin (SSI disabled,
    the directive reflected verbatim as an inert comment: reflected, not evaluated — the honest boundary), a
    benign no-directive endpoint, or an out-of-scope URL.

Reuses the reviewed gated send (web_redrive._gated_web_send) + the runtime_redrive discipline; this file proves
the routing + the live positive + the negative controls end-to-end.
"""
from __future__ import annotations

import http.server
import re
import threading
import types
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")


# The SAME set+echo directive shape the naive include processor evaluates (mirrors the benchmark model).
_SSI_SET_ECHO = re.compile(
    r'<!--#\s*set\s+var="(?P<name>[A-Za-z_][A-Za-z0-9_]*)"\s+'
    r'value="(?P<a>\d+)\s*\*\s*(?P<b>\d+)"\s*-->'
    r'\s*<!--#\s*echo\s+var="(?P=name)"\s*-->'
)


def _eval_ssi(raw: str) -> str | None:
    m = _SSI_SET_ECHO.fullmatch((raw or "").strip())
    return str(int(m.group("a")) * int(m.group("b"))) if m else None


# ---------------------------------------------------------------------------------------------------
# hermetic: _redrive_spec routing
# ---------------------------------------------------------------------------------------------------

def _decision(bug_class: str, *, url: str) -> types.SimpleNamespace:
    analysis = types.SimpleNamespace(exploit_succeeded=True, extracted_info={"bug_class": bug_class})
    tool = types.SimpleNamespace(tool_args={"url": url})
    return types.SimpleNamespace(tool=tool, output_analysis=analysis)


@pytest.mark.parametrize("claimed,norm", [
    ("ssi", "ssi"), ("server_side_includes", "ssi"), ("ssi_injection", "ssi"),
])
def test_redrive_spec_emits_a_runtime_spec_for_ssi(claimed, norm):
    from vigil_integration.live.engine import VigilEngine
    spec = VigilEngine._redrive_spec(
        _decision(claimed, url="http://127.0.0.1:19010/ssi?doc=index"), None)
    assert spec is not None, f"{claimed} should be re-drivable"
    assert spec["kind"] == "runtime"
    assert spec["bug_class"] == norm
    assert spec["url"].endswith("/ssi?doc=index")


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


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&#x27;"))


class _VulnApp(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        from urllib.parse import parse_qs, urlsplit
        parts = urlsplit(self.path)
        q = parse_qs(parts.query)
        path = parts.path
        doc = (q.get("doc") or [""])[0]
        if path == "/ssi":                                        # VULNERABLE SSI (evaluates set+echo)
            rendered = _eval_ssi(doc) or "index"
            return self._text(f"<html><body><h1>Included</h1><p>{rendered}</p></body></html>", "text/html")
        if path == "/ssi-safe":                                   # BENIGN twin: SSI disabled — reflect verbatim
            shown = doc if _SSI_SET_ECHO.fullmatch(doc.strip()) else "index"
            return self._text(f"<html><body><h1>Included</h1><p>{shown}</p></body></html>", "text/html")
        if path == "/ssi-escaped":                                # BENIGN: HTML-escaped reflection (never eval)
            return self._text(f"<html><body><h1>Included</h1><p>{_esc(doc)}</p></body></html>", "text/html")
        if path == "/static":                                     # BENIGN: fixed body, input ignored
            return self._text("<html><body>static page</body></html>", "text/html")
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


# -- positive ---------------------------------------------------------------------------------------

def test_live_ssi_mints_a_fact(monkeypatch, tmp_path):
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/ssi?doc=index", "ssi")
    assert ref, "a live SSI directive the server EVALUATES (computed product, raw absent) must mint a signed FACT"


# -- mandatory negative controls --------------------------------------------------------------------

def test_negctl_reflected_directive_mints_nothing(monkeypatch, tmp_path):
    # SSI disabled — the directive is echoed verbatim as an inert comment. Reflected, not evaluated:
    # the raw directive survives and the product never appears, so the oracle is a conclusive clean.
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/ssi-safe?doc=index", "ssi")
    assert ref is None, "a page that reflects but does not evaluate the directive must not mint an SSI FACT"


def test_negctl_escaped_directive_mints_nothing(monkeypatch, tmp_path):
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/ssi-escaped?doc=index", "ssi")
    assert ref is None, "an HTML-escaping endpoint (inert, no product) must not mint an SSI FACT"


def test_negctl_benign_endpoint_mints_nothing(monkeypatch, tmp_path):
    ref = _fact(monkeypatch, tmp_path, "http://127.0.0.1:{port}/static", "ssi")
    assert ref is None, "an endpoint that never evaluates the directive must not mint an SSI FACT"
