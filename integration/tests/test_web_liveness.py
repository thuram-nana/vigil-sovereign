"""HexStrike W2 — endpoint LIVENESS (the L7 analogue of the TCP tcp_handshake reachability FACT).

A web-discovery tool (httpx / ffuf) PROPOSES a URL; VIGIL re-drives it with its OWN plain gated GET plus a
known-nonexistent sibling CONTROL, and the EXISTING ACHIEVED_STATE predicate_oracle mints a signed
``achieved_state.endpoint_liveness`` FACT ONLY when the target returns a served status (2xx/3xx) AND the
control returns a genuine not-found (>= 400). The proofs are genuinely live: a real loopback HTTP server.

Headline properties:
  * a really-live URL → a signed liveness FACT that re-verifies OFFLINE, and tamper is rejected;
  * a tool-claimed-but-UNREACHABLE URL → a LEAD (deceptive_no_fact — the tool's say-so never confirms);
  * a SOFT-404 (a server that answers 200 for EVERYTHING) → a LEAD/no-fact (the key red-pen trap);
  * a channel-confirmed hard 404 → a CLEAN bounded to the EXACT probed URL, never an enumeration claim;
  * httpx + ffuf each PASS the full conformance battery through the REAL gated runner;
  * the two operator surfaces (capability matrix + the body's oracle-mapped set) AGREE.

Offense-process test (loads framework.* + vigil_integration.live.*): CI runs it in the offense group.
"""
from __future__ import annotations

import http.server
import json
import re
import threading
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
pytest.importorskip("vigil_gateway", reason="vigil_gateway (gated transport) not importable here")


# ---- gate isolation + charter (mirrors test_web_redrive / test_conformance) -----------------------
@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path: Path, host: str, slug: str = "alpha") -> None:
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `tester`     Date: `2026-09-25`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n"
        f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def _signers_and_trust():
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return signers, tr


# ---- loopback web apps: a CORRECT server (404s the unknown) and a SOFT-404 server (200s EVERYTHING) -
class _CorrectApp(http.server.BaseHTTPRequestHandler):
    """Serves 200 for /live and /, 404 for every other path (including the random liveness control) — a
    server that correctly distinguishes a real resource from a nonexistent one."""

    def log_message(self, *a):  # noqa: D401 — silence the test server
        pass

    def do_GET(self):  # noqa: N802
        if self.path in ("/live", "/"):
            body = b"<html><body>a real, live resource</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"<html><body>404 not found</body></html>"
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


class _SoftNotFoundApp(http.server.BaseHTTPRequestHandler):
    """The TRIVIAL soft-404 trap: answers 200 with the SAME 'not found' page for EVERY path (uniform body,
    no path echo). Target and same-shape controls share status+body, so the re-drive must mint NO fact."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        body = b"<html><body>Sorry, that page was not found.</body></html>"   # UNIFORM — no path echo
        self.send_response(200)                       # <-- 200 for a nonexistent page: the soft-404 lie
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _PathEchoSoftApp(http.server.BaseHTTPRequestHandler):
    """A soft-404 that ECHOES the requested path in its 200 body. A single control would look 'different' from
    the target and false-FACT; the two same-shape controls echo DIFFERENT paths, so no stable baseline forms."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        body = f"<html><body>Sorry, page {self.path} was not found.</body></html>".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


_NUMERIC_ROUTE = re.compile(r"^/api/users/(\d+)/?$")


class _NumericRouteSoftApp(http.server.BaseHTTPRequestHandler):
    """FP1 — a numeric-ID REST route (Django <int:pk> / Rails /:id(\\d+) / Express :id(\\d+)): 200 for ANY
    numeric user id (even a nonexistent one — the soft-404 lie {"user": null}), 404 for a non-numeric segment
    (the route does not match). A DISTINCTIVE non-numeric control 404s while a nonexistent numeric target 200s
    -> the old status-only predicate false-FACTed. A SAME-SHAPE numeric control also matches the route -> 200
    {"user": null} == the target's body -> LEAD."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if _NUMERIC_ROUTE.match(path):
            body, code = b'{"user": null}', 200        # nonexistent numeric id STILL 200s (soft-404)
        else:
            body, code = b'{"error": "not found"}', 404
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _NumericRouteLiveApp(http.server.BaseHTTPRequestHandler):
    """The NON-REGRESSION twin of _NumericRouteSoftApp: /api/users/1 is a REAL user (distinct body), every
    other numeric id is the soft-404 {"user": null}. A same-shape numeric control 200s with {"user": null},
    but the target /api/users/1 body DIFFERS -> the body differential still mints a FACT for the live id."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        m = _NUMERIC_ROUTE.match(self.path.split("?")[0])
        if m and m.group(1) == "1":
            body, code = b'{"user": {"id": 1, "name": "alice"}}', 200
        elif m:
            body, code = b'{"user": null}', 200
        else:
            body, code = b'{"error": "not found"}', 404
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _LengthSignatureApp(http.server.BaseHTTPRequestHandler):
    """FP2 — a blanket-200 soft-404 whose ONLY 404 is a WAF/edge rule that blocks any last path segment longer
    than 20 chars (long/high-entropy = 'suspicious'), equivalently a signature block on a fixed control prefix.
    The old fixed 39-char `vigil-liveness-<hex>` control was 404'd while the short target 200'd -> false FACT.
    A SAME-LENGTH control (e.g. 5 chars for /admin) is under the limit -> 200 == target -> LEAD."""

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        seg = self.path.split("?")[0].rstrip("/").rsplit("/", 1)[-1]
        if len(seg) > 20:
            body, code = b"blocked", 404               # the edge/WAF 404s the long/high-entropy segment
        else:
            body, code = b"<html>page not found (but 200)</html>", 200   # blanket soft-404 for normal paths
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve(handler):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def _grant_active_recon(monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


# ---- canned tool backends (the tool is only a PROPOSER; VIGIL's own gated GET is the fact authority) ---
class _CannedBackend:
    """Returns a fixed stdout for ANY argv — supplies a tool's real-format proposal with no binary present."""
    name = "canned"

    def __init__(self, stdout: str) -> None:
        self._stdout = stdout

    def available(self):
        return True, "canned"

    def run(self, argv, *, timeout=0):
        from vigil_integration.live.external_tool import ToolOutcome
        return ToolOutcome(list(argv), 0, self._stdout, "", self.name)


def _httpx_jsonl(url: str) -> str:
    return json.dumps({"url": url, "input": url, "status_code": 200, "failed": False}) + "\n"


def _ffuf_report(url: str) -> str:
    return json.dumps({"results": [{"input": {"FUZZ": "live"}, "status": 200, "url": url,
                                    "host": "127.0.0.1"}], "config": {}})


def _scope_gate(hosts):
    from vigil_gateway.scope_source import StaticScopeSource
    from vigil_integration.live.external_tool import ScopeGate
    return ScopeGate(scope=StaticScopeSource(list(hosts)), loopback_allowed_if_scoped=True)


# ===================================================================================================
# The direct re-drive proofs (the endpoint_liveness_redrive itself).
# ===================================================================================================
def test_live_url_mints_a_signed_liveness_fact_that_reverifies_offline(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, tr = _signers_and_trust()
    srv = _serve(_CorrectApp)
    port = srv.server_address[1]
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/live",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert wl.is_fact, f"expected a liveness FACT; outcome={wl.outcome} note={wl.note}"
    assert wl.outcome == "positive" and wl.target_status == 200 and wl.control_statuses == [404, 404]
    # the FACT re-verifies OFFLINE from the retained JSON-safe capture — no network, no VIGIL runner
    assert verify_certificate(wl.fact.signed, oracle_context=wl.context, trust_root=tr).ok is True


def test_liveness_fact_is_rejected_when_the_retained_context_is_tampered(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, tr = _signers_and_trust()
    srv = _serve(_CorrectApp)
    port = srv.server_address[1]
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/live",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert wl.is_fact
    # flip a control status in the retained context: the server's not-found (404) becomes a soft-404 (200),
    # which would NO LONGER satisfy the predicate — the cert bound the original context, so verify must FAIL.
    tampered = json.loads(json.dumps(wl.context))
    tampered["observed_evidence"]["control1_status"] = 200
    assert verify_certificate(wl.fact.signed, oracle_context=tampered, trust_root=tr).ok is False


@pytest.mark.parametrize("app,path,label", [
    (_SoftNotFoundApp, "/anything", "uniform blanket-200"),
    (_PathEchoSoftApp, "/anything", "path-echoing 200"),
    (_NumericRouteSoftApp, "/api/users/999999999", "numeric-route soft-404 (FP1)"),
    (_LengthSignatureApp, "/admin", "length/shape-signature 404 (FP2)"),
])
def test_soft_404_classes_mint_no_liveness_fact(app, path, label, monkeypatch, tmp_path):
    """Every soft-404 CLASS the red-pen raised must be a LEAD, never a FACT: the uniform blanket-200, a
    path-echoing 200, the numeric-route soft-404 (FP1 — a same-shape numeric control also matches the route),
    and the shape/length-signature 404 (FP2 — a same-length control is treated identically). FP1/FP2 minted a
    FALSE offline-re-verifiable FACT on the pre-fix status-only + distinctive-token control."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    srv = _serve(app)
    port = srv.server_address[1]
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}{path}",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert not wl.is_fact, f"{label}: must NOT mint a liveness FACT (got {wl.outcome}, {wl.note})"
    assert wl.outcome == "inconclusive" and wl.lead is not None and not wl.lead.is_fact


def test_numeric_route_live_id_still_mints_a_fact(monkeypatch, tmp_path):
    """NON-REGRESSION for the same-shape + body differential: a GENUINELY live numeric id (/api/users/1) is
    served 200 with a distinct body while a same-shape numeric control 200s with {"user": null}; the body
    differential distinguishes them, so the live id still mints a FACT that re-verifies OFFLINE."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, tr = _signers_and_trust()
    srv = _serve(_NumericRouteLiveApp)
    port = srv.server_address[1]
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/api/users/1",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert wl.is_fact, f"a genuinely-live numeric id must mint a FACT; outcome={wl.outcome} note={wl.note}"
    assert wl.control_statuses == [200, 200]     # same-status baseline; distinguished by the BODY differential
    assert verify_certificate(wl.fact.signed, oracle_context=wl.context, trust_root=tr).ok is True


def test_root_url_fails_closed_to_a_lead(monkeypatch, tmp_path):
    """A root/directory URL has no last segment to mirror into a same-shape control, so the liveness FACT
    FAILS CLOSED to a LEAD rather than mint over an unsound control."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import _liveness_control_urls, endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    srv = _serve(_CorrectApp)          # serves 200 at "/"
    port = srv.server_address[1]
    assert _liveness_control_urls(f"http://127.0.0.1:{port}/") == [], "root URL must yield no same-shape control"
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert not wl.is_fact and wl.outcome == "inconclusive"
    assert "no sound SAME-SHAPE control" in wl.note


def test_hard_404_is_a_clean_bounded_to_the_exact_url(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    srv = _serve(_CorrectApp)
    port = srv.server_address[1]
    try:
        wl = endpoint_liveness_redrive(f"http://127.0.0.1:{port}/definitely-not-here",
                                       slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert not wl.is_fact
    assert wl.outcome == "clean" and wl.target_status == 404
    assert "bounded to the probed URL" in wl.note and "no other endpoint" in wl.note


def test_unreachable_url_is_a_lead_deceptive_no_fact(monkeypatch, tmp_path):
    """A URL the tool claims live but VIGIL's OWN gated GET cannot reach (closed port) → NO fact."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    import socket
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp.bind(("127.0.0.1", 0))
    closed_port = tmp.getsockname()[1]
    tmp.close()
    wl = endpoint_liveness_redrive(f"http://127.0.0.1:{closed_port}/live",
                                   slug="alpha", engagement_slug="alpha", signers=signers)
    assert not wl.is_fact and wl.outcome == "deceptive_no_fact"
    assert wl.lead is not None and "not reproducible" in wl.note


def test_out_of_scope_url_is_refused_before_any_traffic(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")          # only 127.0.0.1 is in scope
    from vigil_integration.live.web_redrive import endpoint_liveness_redrive
    signers, _ = _signers_and_trust()
    wl = endpoint_liveness_redrive("http://10.99.99.99/live",
                                   slug="alpha", engagement_slug="alpha", signers=signers)
    assert wl.refused is True and not wl.is_fact and wl.outcome == "refused"


# ===================================================================================================
# End-to-end through the R4 gated runner (httpx / ffuf → run_external_tool → the liveness re-drive).
# ===================================================================================================
@pytest.mark.parametrize("tool,canned", [("httpx", _httpx_jsonl), ("ffuf", _ffuf_report)])
def test_web_tool_live_url_mints_a_fact_through_the_runner(tool, canned, monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    from vigil_integration.live.external_tool import ffuf_content_scan, httpx_url_scan, run_external_tool
    signers, tr = _signers_and_trust()
    srv = _serve(_CorrectApp)
    port = srv.server_address[1]
    url = f"http://127.0.0.1:{port}/live"
    spec = httpx_url_scan() if tool == "httpx" else ffuf_content_scan(wordlist="/tmp/wl.txt")
    try:
        res = run_external_tool(spec, "127.0.0.1", scope_gate=_scope_gate(["127.0.0.1"]),
                                backend=_CannedBackend(canned(url)), engagement_slug="alpha",
                                signers=signers, timeout=30.0)
    finally:
        srv.shutdown()
    assert res.status == "ran"
    assert any(getattr(p, "url", "") == url for p in res.proposed), f"{tool} did not propose {url}: {res.proposed}"
    assert len(res.facts) == 1, f"expected 1 liveness FACT via {tool}; facts={res.facts} leads={res.leads}"
    fact = res.facts[0]
    assert fact.is_fact and fact.confirmed_by == "achieved_state"
    ctx = res.contexts[fact.finding_ref]
    assert verify_certificate(fact.signed, oracle_context=ctx, trust_root=tr).ok is True


@pytest.mark.parametrize("tool,canned", [("httpx", _httpx_jsonl), ("ffuf", _ffuf_report)])
@pytest.mark.parametrize("app,path,label", [
    (_SoftNotFoundApp, "/admin", "uniform blanket-200"),
    (_PathEchoSoftApp, "/admin", "path-echoing 200"),
    (_NumericRouteSoftApp, "/api/users/999999999", "numeric-route soft-404 (FP1)"),
    (_LengthSignatureApp, "/admin", "length/shape-signature 404 (FP2)"),
])
def test_web_tool_soft_404_classes_are_a_lead_through_the_runner(tool, canned, app, path, label,
                                                                 monkeypatch, tmp_path):
    """Every soft-404 CLASS is a LEAD through BOTH the httpx and ffuf runner legs — including FP1 (numeric
    route) and FP2 (shape/length signature), which minted a FALSE FACT before the same-shape-control fix."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.external_tool import ffuf_content_scan, httpx_url_scan, run_external_tool
    signers, _ = _signers_and_trust()
    srv = _serve(app)
    port = srv.server_address[1]
    url = f"http://127.0.0.1:{port}{path}"
    spec = httpx_url_scan() if tool == "httpx" else ffuf_content_scan(wordlist="/tmp/wl.txt")
    try:
        res = run_external_tool(spec, "127.0.0.1", scope_gate=_scope_gate(["127.0.0.1"]),
                                backend=_CannedBackend(canned(url)), engagement_slug="alpha",
                                signers=signers, timeout=30.0)
    finally:
        srv.shutdown()
    assert res.status == "ran"
    assert res.proposed, "the tool must still PROPOSE the URL"
    assert res.facts == [], f"{label} via {tool}: must mint NO liveness FACT (the tool's say-so never confirms)"
    assert any(o.get("outcome") == "inconclusive" for o in res.outcomes)


@pytest.mark.parametrize("tool,canned", [("httpx", _httpx_jsonl), ("ffuf", _ffuf_report)])
def test_web_tool_numeric_route_live_id_still_a_fact_through_the_runner(tool, canned, monkeypatch, tmp_path):
    """NON-REGRESSION through both runner legs: a genuinely-live numeric id (distinct body vs a same-shape
    numeric not-found control) still mints one signed liveness FACT."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    from vigil_integration.live.external_tool import ffuf_content_scan, httpx_url_scan, run_external_tool
    signers, tr = _signers_and_trust()
    srv = _serve(_NumericRouteLiveApp)
    port = srv.server_address[1]
    url = f"http://127.0.0.1:{port}/api/users/1"
    spec = httpx_url_scan() if tool == "httpx" else ffuf_content_scan(wordlist="/tmp/wl.txt")
    try:
        res = run_external_tool(spec, "127.0.0.1", scope_gate=_scope_gate(["127.0.0.1"]),
                                backend=_CannedBackend(canned(url)), engagement_slug="alpha",
                                signers=signers, timeout=30.0)
    finally:
        srv.shutdown()
    assert len(res.facts) == 1, f"expected 1 liveness FACT via {tool}; facts={res.facts} leads={res.leads}"
    fact = res.facts[0]
    assert verify_certificate(fact.signed, oracle_context=res.contexts[fact.finding_ref], trust_root=tr).ok is True


# ===================================================================================================
# The conformance battery over the REAL gated runner (the gate the matrix requires before fact_capable).
# ===================================================================================================
@pytest.mark.parametrize("tool", ["httpx", "ffuf"])
def test_web_tool_passes_the_full_conformance_battery(tool, monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.authority import KillSwitch
    from vigil_integration.live.conformance import REQUIRED_PROPERTIES, run_toolspec_conformance
    from vigil_integration.live.external_tool import ffuf_content_scan, httpx_url_scan
    signers, tr = _signers_and_trust()

    srv = _serve(_CorrectApp)
    port = srv.server_address[1]
    live_url = f"http://127.0.0.1:{port}/live"
    # a definitely-CLOSED port for the deceptive fixture (the tool proposes it; VIGIL's GET cannot reach it)
    import socket
    tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp.bind(("127.0.0.1", 0))
    closed_port = tmp.getsockname()[1]
    tmp.close()
    dead_url = f"http://127.0.0.1:{closed_port}/live"

    if tool == "httpx":
        spec = httpx_url_scan()
        pos_backend = _CannedBackend(_httpx_jsonl(live_url))
        dec_backend = _CannedBackend(_httpx_jsonl(dead_url))
    else:
        spec = ffuf_content_scan(wordlist="/tmp/wl.txt")
        pos_backend = _CannedBackend(_ffuf_report(live_url))
        dec_backend = _CannedBackend(_ffuf_report(dead_url))

    halt = tmp_path / "alpha.halt"
    try:
        report = run_toolspec_conformance(
            tool_name=tool,
            positive_spec=spec, positive_backend=pos_backend,
            deceptive_spec=spec, deceptive_backend=dec_backend,
            target="127.0.0.1",
            scope_gate_in=_scope_gate(["127.0.0.1"]),
            scope_gate_out=_scope_gate(["10.99.99.99"]),
            engagement_slug="alpha", signers=signers, trust_root=tr,
            trip_killswitch=lambda: KillSwitch("alpha").trip("conformance"),
            clear_killswitch=lambda: halt.unlink(missing_ok=True),
            timeout=30.0)
    finally:
        srv.shutdown()

    assert report.conformant, report.summary() + " | notes: " + "; ".join(report.notes)
    for prop in REQUIRED_PROPERTIES:
        assert report.checks.get(prop) is True, f"{tool}: {prop} not satisfied: {report.summary()}"


# ===================================================================================================
# Two operator surfaces AGREE: the capability matrix and the body's oracle-mapped set both say
# httpx + ffuf are fact_capable web-discovery tools (ACHIEVED_STATE endpoint-liveness).
# ===================================================================================================
def test_two_surfaces_agree_httpx_ffuf_are_fact_capable_web_discovery():
    from vigil_integration.brains.hexstrike_body import _ORACLE_MAPPED_TOOLS, _spec_for_kind
    from vigil_integration.live.oracle_families import family_for, is_fact_capable_family
    from vigil_integration.live.tool_manifest import load_manifests

    root = Path(__file__).resolve().parents[2]
    matrix = root / "docs" / "capability-matrix" / "hexstrike.json"
    by = {m.name: m for m in load_manifests(str(matrix))}
    for tool in ("httpx", "ffuf"):
        # surface 1 — the capability matrix
        assert by[tool].fact_capable, f"{tool}: matrix must mark it fact_capable"
        assert by[tool].oracle_family.upper() == "ACHIEVED_STATE"
        # surface 2 — the body's runner-owned oracle-mapped set + family routing
        assert tool in _ORACLE_MAPPED_TOOLS, f"{tool}: body must treat it as oracle-mapped"
        assert is_fact_capable_family(tool) and family_for(tool).name == "web_discovery"
        spec = _spec_for_kind(tool, {})
        assert spec is not None and spec.name == tool and spec.propose_urls is not None
