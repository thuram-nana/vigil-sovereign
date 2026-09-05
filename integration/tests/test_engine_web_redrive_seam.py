"""Wave 1 — the ENGAGE oracle seam routes web-fact claims into the reviewed ``live.web_redrive`` engine.

Before this wave the chat/engage T2 re-drive was hardcoded to ``error_based_sqli`` (`engine._redrive_spec`
+ `wiring._live_redrive_fact`), so of the MERIDIAN classes only error-based SQLi could ever mint a FACT —
and only if the model spelled the class exactly (MERIDIAN labels its plant ``sqli``, "landmine 1"). This
test pins the two seam changes:

  * ``VigilEngine._redrive_spec`` now normalizes AUTHORITATIVELY (``normalize_bug_class``, landmine 2) and
    emits a ``{"kind": "web", ...}`` spec for the web-fact classes and a ``{"kind": "sqli", ...}`` spec for
    the whole SQLi family (``sqli``/``sql_injection``/``error_based_sqli``, landmine 1).
  * ``wiring._live_web_redrive_fact`` re-drives a web-fact claim through ``web_redrive`` and mints a signed
    FACT ONLY when web_redrive independently confirms the CLAIMED class over VIGIL's own gated live capture —
    and mints NOTHING for a benign endpoint (the mandatory negative control) or a wrong-class claim.

The seam REUSES the already-red-penned ``web_redrive`` soundness (canary-host predicate, "found nothing ≠
CLEAN"); this file proves the ROUTING, plus one live positive + the negative controls end-to-end.
"""
from __future__ import annotations

import http.server
import threading
import types
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")


# ---------------------------------------------------------------------------------------------------
# hermetic: _redrive_spec routing (no network)
# ---------------------------------------------------------------------------------------------------

def _decision(bug_class: str, *, url: str = "http://127.0.0.1:19010/auth/continue?next=x",
              insertion_point: str = "", payload: str = "") -> types.SimpleNamespace:
    info = {"bug_class": bug_class}
    if insertion_point:
        info["insertion_point"] = insertion_point
    if payload:
        info["request_payload"] = payload
    analysis = types.SimpleNamespace(exploit_succeeded=True, extracted_info=info)
    tool = types.SimpleNamespace(tool_args={"url": url})
    return types.SimpleNamespace(tool=tool, output_analysis=analysis)


@pytest.mark.parametrize("claimed", ["open_redirect", "cors", "host_header_injection",
                                     "graphql_introspection"])
def test_redrive_spec_emits_a_web_spec_for_web_fact_classes(claimed):
    from vigil_integration.live.engine import VigilEngine
    spec = VigilEngine._redrive_spec(_decision(claimed), None)
    assert spec is not None, f"{claimed} should be re-drivable"
    assert spec["kind"] == "web"
    assert spec["bug_class"] == claimed
    assert spec["url"].endswith("/auth/continue?next=x")   # the FULL url (query preserved for param grounding)


@pytest.mark.parametrize("claimed", ["oidc_redirect_uri", "oidc_open_redirect", "redirect_uri_validation"])
def test_redrive_spec_excludes_oidc_from_the_llm_claim_seam_block_1(claimed):
    """red-pen BLOCK-1: an OIDC (A07) class is NOT oracle-verifiable from the wire (evidence is byte-identical
    to a plain open_redirect), so an LLM-supplied oidc label must NOT route through the web-fact seam — else
    a plain open redirect would mint a signed A07 certificate the oracle only proved as A01."""
    from vigil_integration.live.engine import VigilEngine
    assert VigilEngine._redrive_spec(_decision(claimed), None) is None


def test_redrive_spec_normalizes_the_class_authoritatively_landmine_2():
    """A spaced/cased spelling must still route (proves the hand-rolled normalizer was replaced)."""
    from vigil_integration.live.engine import VigilEngine
    spec = VigilEngine._redrive_spec(_decision("Open-Redirect"), None)
    assert spec is not None and spec["kind"] == "web" and spec["bug_class"] == "open_redirect"


@pytest.mark.parametrize("claimed", ["error_based_sqli", "sqli", "sql_injection"])
def test_redrive_spec_accepts_the_whole_sqli_family_landmine_1(claimed):
    from vigil_integration.live.engine import VigilEngine
    spec = VigilEngine._redrive_spec(
        _decision(claimed, url="http://127.0.0.1:19010/records/search?q=1",
                  insertion_point="q", payload="' OR '1'='1"), None)
    assert spec is not None, f"{claimed} should re-drive via the error_signature channel"
    assert spec["kind"] == "sqli"
    # the minted class is decided by the oracle, so the spec normalizes the whole family to error_based_sqli
    assert spec["bug_class"] == "error_based_sqli"
    assert spec["param"] == "q" and spec["payload"]


def test_redrive_spec_sqli_without_a_complete_spec_is_not_redrivable():
    from vigil_integration.live.engine import VigilEngine
    assert VigilEngine._redrive_spec(_decision("sqli", insertion_point="", payload=""), None) is None


@pytest.mark.parametrize("claimed", ["path_traversal", "directory_traversal", "xss", "idor",
                                     "business_logic", "not_a_real_class"])
def test_redrive_spec_returns_none_for_classes_not_yet_wired(claimed):
    """Wave-2+ classes and unknown classes must NOT produce a spec (they stay LEAD-only for now)."""
    from vigil_integration.live.engine import VigilEngine
    assert VigilEngine._redrive_spec(_decision(claimed), None) is None


def test_redrive_spec_needs_exploit_succeeded():
    from vigil_integration.live.engine import VigilEngine
    d = _decision("open_redirect")
    d.output_analysis.exploit_succeeded = False
    assert VigilEngine._redrive_spec(d, None) is None


# ---------------------------------------------------------------------------------------------------
# live: _live_web_redrive_fact over a loopback app (positive + mandatory negative controls)
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


class _WebApp(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        from urllib.parse import parse_qs, urlsplit
        parts = urlsplit(self.path)
        q = parse_qs(parts.query)
        if parts.path == "/redirect":                       # VULNERABLE open redirect (Location authority)
            self.send_response(302)
            self.send_header("Location", (q.get("next") or [""])[0])
            self.end_headers()
        elif parts.path == "/api":                          # VULNERABLE CORS (reflects Origin + creds)
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b"{}")
        elif parts.path == "/safe":                         # BENIGN: reflects into plain-text body only
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"you asked for: {(q.get('next') or [''])[0]}".encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):  # silence
        return


def _serve():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _WebApp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _redrive(url: str, bug_class: str) -> dict:
    return {"kind": "web", "url": url, "bug_class": bug_class}


def test_live_seam_mints_a_fact_for_a_claimed_open_redirect(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.wiring import _live_web_redrive_fact
    srv = _serve(); port = srv.server_address[1]
    try:
        ref = _live_web_redrive_fact(
            _prov(), {}, _redrive(f"http://127.0.0.1:{port}/redirect?next=orig", "open_redirect"))
    finally:
        srv.shutdown()
    assert ref, "a claimed open_redirect over a live vulnerable endpoint must mint a signed FACT ref"


def test_live_seam_mints_a_fact_for_a_claimed_cors(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.wiring import _live_web_redrive_fact
    srv = _serve(); port = srv.server_address[1]
    try:
        ref = _live_web_redrive_fact(_prov(), {}, _redrive(f"http://127.0.0.1:{port}/api", "cors"))
    finally:
        srv.shutdown()
    assert ref, "a claimed cors misconfig over a live credential-reflecting endpoint must mint a FACT"


def test_live_seam_negative_control_benign_endpoint_mints_nothing(monkeypatch, tmp_path):
    """MANDATORY negative control: a benign endpoint that merely reflects the value into a plain-text body
    is NOT an open redirect — the seam must return None (no FACT)."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.wiring import _live_web_redrive_fact
    srv = _serve(); port = srv.server_address[1]
    try:
        ref = _live_web_redrive_fact(
            _prov(), {}, _redrive(f"http://127.0.0.1:{port}/safe?next=orig", "open_redirect"))
    finally:
        srv.shutdown()
    assert ref is None, "a benign reflecting endpoint must NOT mint an open_redirect FACT"


def test_live_seam_wrong_class_claim_mints_nothing(monkeypatch, tmp_path):
    """A cors claim against an endpoint that only does an open redirect (no CORS reflection) must not mint —
    the FACT is tied to the CLAIMED class, not to whatever web_redrive happens to also probe."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.wiring import _live_web_redrive_fact
    srv = _serve(); port = srv.server_address[1]
    try:
        ref = _live_web_redrive_fact(
            _prov(), {}, _redrive(f"http://127.0.0.1:{port}/redirect?next=orig", "cors"))
    finally:
        srv.shutdown()
    assert ref is None, "a cors claim over a non-CORS endpoint must not mint (class-tied)"


def test_live_seam_non_web_class_is_not_handled_here(monkeypatch, tmp_path):
    """A non-web class (sqli) is routed to the error_signature path, not this one — returns None here."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.wiring import _live_web_redrive_fact
    srv = _serve(); port = srv.server_address[1]
    try:
        ref = _live_web_redrive_fact(
            _prov(), {}, _redrive(f"http://127.0.0.1:{port}/redirect?next=orig", "sqli"))
    finally:
        srv.shutdown()
    assert ref is None, "a non-web-fact class must not be handled by the web seam"


def test_live_seam_out_of_scope_url_mints_nothing(monkeypatch, tmp_path):
    """A URL whose host is not in the charter scope is refused before any traffic → no FACT (fail-closed)."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")   # only 127.0.0.1 is in scope
    from vigil_integration.live.wiring import _live_web_redrive_fact
    ref = _live_web_redrive_fact(
        _prov(), {}, _redrive("http://10.99.99.99/redirect?next=orig", "open_redirect"))
    assert ref is None, "an out-of-scope target must never mint a FACT"


def test_live_seam_oidc_claim_on_a_plain_open_redirect_mints_nothing_block_1(monkeypatch, tmp_path):
    """red-pen BLOCK-1 (live): an oidc_redirect_uri claim over an endpoint that is only a plain open redirect
    must mint NO FACT via the LLM-claim seam (the OIDC impact is unverified; the class is claim-carried)."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.wiring import _live_web_redrive_fact
    srv = _serve(); port = srv.server_address[1]
    try:
        ref = _live_web_redrive_fact(
            _prov(), {}, _redrive(f"http://127.0.0.1:{port}/redirect?next=orig", "oidc_redirect_uri"))
    finally:
        srv.shutdown()
    assert ref is None, "an LLM oidc claim over a plain open redirect must not mint an A07 FACT"
