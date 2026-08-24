"""WAVE #3 — the runner-owned gated HTTP re-drive → ACHIEVED_STATE FACT (the web column).

The headline proofs are genuinely live: a real loopback HTTP server serves a vulnerable open-redirect and
a credential-reflecting CORS misconfiguration; ``web_redrive`` re-drives it through the SHIPPED exploitable-condition
web checks via a GATED, no-redirect send, and the existing deterministic ``predicate_oracle`` mints a signed
FACT that re-verifies OFFLINE. A safe endpoint mints nothing (the runner's own re-drive refutes a would-be
scanner claim — the criterion-6 firewall). The kill-switch refuses the capture before any traffic reaches
the server. No external tool is installed or run — the transport is VIGIL's own, gated.
"""
from __future__ import annotations

import http.server
import json
import pathlib
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")


# ---- gate isolation + charter (mirrors the reachability_cloud live-capture tests) -----------------
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


def _signers_and_trust():
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return signers, tr


# ---- a loopback web app: a REAL open-redirect + a REAL credential-reflecting CORS + safe endpoints -
_HITS = {"n": 0}


class _WebApp(http.server.BaseHTTPRequestHandler):
    def _count(self):
        _HITS["n"] += 1

    def do_GET(self):  # noqa: N802
        self._count()
        parts = urlsplit(self.path)
        q = parse_qs(parts.query)
        if parts.path == "/redirect":                      # VULNERABLE: reflects `next` into Location
            nxt = (q.get("next") or [""])[0]
            self.send_response(302)
            self.send_header("Location", nxt)
            self.end_headers()
        elif parts.path == "/api":                         # VULNERABLE: reflects Origin + allows creds
            origin = self.headers.get("Origin", "")
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b"{}")
        elif parts.path == "/safe":                        # SAFE: reflects the value in plain text only
            nxt = (q.get("next") or [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")   # declared: body is adjudicable
            self.end_headers()
            self.wfile.write(f"you requested: {nxt}".encode("utf-8"))
        elif parts.path == "/preview":                     # SAFE (red-pen BLOCK-1): 200 HTML that reflects
            nxt = (q.get("next") or [""])[0]               # `next` verbatim AND has a legacy <meta
            self.send_response(200)                        # http-equiv=Content-Type> — NO redirect at all.
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            page = ('<!doctype html><html><head>'
                    '<meta http-equiv="Content-Type" content="text/html; charset=utf-8">'
                    f'<title>Link preview</title></head><body><p>We could not open: {nxt}</p></body></html>')
            self.wfile.write(page.encode("utf-8"))
        elif parts.path == "/metarefresh":                 # VULNERABLE: a REAL meta-refresh open redirect —
            nxt = (q.get("next") or [""])[0]               # reflects `next` into the meta-refresh URL.
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            page = ('<!doctype html><html><head>'
                    f'<meta http-equiv="refresh" content="0; url={nxt}">'
                    '</head><body>redirecting…</body></html>')
            self.wfile.write(page.encode("utf-8"))
        elif parts.path == "/corswild":                    # SAFE-ish (red-pen MEDIUM-1): ACAO:* + creds —
            self.send_response(200)                        # a misconfig, but browsers refuse *+creds so it
            self.send_header("Access-Control-Allow-Origin", "*")   # is NOT credential-readable → not a FACT.
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b"{}")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):  # silence
        return


def _serve():
    _HITS["n"] = 0
    srv = http.server.HTTPServer(("127.0.0.1", 0), _WebApp)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


# ---- the live proofs -----------------------------------------------------------------------------

def test_live_open_redirect_mints_a_signed_fact_that_reverifies_offline(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    from vigil_integration.live.web_redrive import web_redrive
    signers, tr = _signers_and_trust()
    srv = _serve()
    port = srv.server_address[1]
    try:
        res = web_redrive(f"http://127.0.0.1:{port}/redirect?next=orig",
                          slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert res.n_facts >= 1, f"expected an open_redirect FACT; leads={res.leads} notes={res.notes}"
    f = next(x for x in res.facts if "open_redirect" in x.finding_ref)
    ctx = res.contexts[f.finding_ref]
    # the FACT re-verifies OFFLINE from the retained JSON-safe capture — no network, no VIGIL runner
    assert verify_certificate(f.signed, oracle_context=ctx, trust_root=tr).ok is True


def test_live_cors_reflection_with_credentials_mints_a_fact(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    from vigil_integration.live.web_redrive import web_redrive
    signers, tr = _signers_and_trust()
    srv = _serve()
    port = srv.server_address[1]
    try:
        res = web_redrive(f"http://127.0.0.1:{port}/api",
                          slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    facts = [x for x in res.facts if "cors" in x.finding_ref]
    assert facts, f"expected a cors FACT; leads={res.leads} notes={res.notes}"
    ctx = res.contexts[facts[0].finding_ref]
    assert verify_certificate(facts[0].signed, oracle_context=ctx, trust_root=tr).ok is True


def test_a_safe_endpoint_mints_no_fact(monkeypatch, tmp_path):
    """The server reflects the canary in plain text but never redirects to it — the runner's OWN re-drive
    refutes it, so nothing is minted (a scanner that flagged this would be a LEAD at most)."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import web_redrive
    signers, _ = _signers_and_trust()
    srv = _serve()
    port = srv.server_address[1]
    try:
        res = web_redrive(f"http://127.0.0.1:{port}/safe?next=orig",
                          slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    # the send GENUINELY reached the server (this was not a gated refusal) — the oracle refuted it live
    assert _HITS["n"] > 0, "the re-drive must actually contact the server (a refusal would be a vacuous pass)"
    assert res.n_facts == 0, f"a safe reflection must NOT mint a FACT: {[x.finding_ref for x in res.facts]}"
    # ... and the refutation is a channel-confirmed CLEAN, not an inconclusive/no-channel outcome
    assert any(x.outcome == "clean" for x in res.leads), f"expected a channel-confirmed CLEAN: {res.leads}"


def test_kill_switch_refuses_the_capture_before_any_traffic(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.authority import KillSwitch
    from vigil_integration.live.web_redrive import web_redrive
    KillSwitch("alpha").trip("halt")
    signers, _ = _signers_and_trust()
    srv = _serve()
    port = srv.server_address[1]
    try:
        res = web_redrive(f"http://127.0.0.1:{port}/redirect?next=orig",
                          slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert res.n_facts == 0
    assert _HITS["n"] == 0, "the kill-switch must refuse BEFORE any HTTP request reaches the target"
    # honest: a refusal is NOT a channel-confirmed CLEAN — no checks ran, no leads were minted
    assert res.refused is True and res.leads == [], f"a refusal must not produce (false-CLEAN) leads: {res.leads}"


def test_out_of_scope_target_is_refused_before_any_traffic(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "example.test")   # 127.0.0.1 is NOT in scope
    from vigil_integration.live.web_redrive import web_redrive
    signers, _ = _signers_and_trust()
    srv = _serve()
    port = srv.server_address[1]
    try:
        res = web_redrive(f"http://127.0.0.1:{port}/redirect?next=orig",
                          slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert res.n_facts == 0 and _HITS["n"] == 0, "an out-of-scope target must never be contacted"
    assert res.refused is True and res.leads == [], "an out-of-scope refusal must not mint (false-CLEAN) leads"


def test_the_gated_send_never_honours_an_environment_proxy(monkeypatch, tmp_path):
    """CONVERGENCE RED-PEN (critical): urllib honours http_proxy/https_proxy/ALL_PROXY by default, so an
    opener built without an EMPTY ProxyHandler would send the "gated" request to a proxy the scope gate
    never authorized — the charter/single-host check would pass while the real TCP peer was somewhere else,
    and the proxy's fabricated bytes would be minted as provenance="live_redrive". The opener must be
    proxy-free: the request has to reach the authorized target itself."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import _gated_web_send
    from framework.v2.scanner.insertion import HttpRequest

    class _Proxy(http.server.BaseHTTPRequestHandler):
        """Answers everything with a DISTINCTIVE body, so a response that came via the proxy is
        unmistakable (a proxy sharing the target's handler would make this test pass vacuously)."""
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"PROXIED-NOT-THE-TARGET")

        def log_message(self, *a):
            return

    proxy = http.server.HTTPServer(("127.0.0.1", 0), _Proxy)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    proxy_port = proxy.server_address[1]
    target = _serve()                     # the real, authorized target
    target_port = target.server_address[1]
    for var in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(var, f"http://127.0.0.1:{proxy_port}")
    try:
        send, _state = _gated_web_send("alpha")
        resp = send(HttpRequest(method="GET", url=f"http://127.0.0.1:{target_port}/safe?next=x"))
    finally:
        proxy.shutdown()
        target.shutdown()
    # the response came from the AUTHORIZED target (its /safe body), not from the proxy
    assert "PROXIED" not in resp["body"], f"the gated send was routed through an env proxy: {resp}"
    assert resp["status"] == 200 and "you requested" in resp["body"], (
        f"the gated send must reach the authorized target directly, not an env proxy: {resp}")


# ---- red-pen regression: the exact false-FACT / false-CLEAN surfaces, now permanent negative controls -

def test_benign_html_reflecting_page_mints_no_open_redirect_fact(monkeypatch, tmp_path):
    """RED-PEN BLOCK-1: a benign 200 HTML page that reflects `next` verbatim AND carries an unrelated
    <meta http-equiv=Content-Type> tag must NOT mint an open_redirect FACT. It is contacted LIVE and
    refuted (not gated off): the tightened predicate requires the canary to be an actual navigation
    target (meta-refresh / JS sink), not two independent substring hits."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import web_redrive
    signers, _ = _signers_and_trust()
    srv = _serve()
    port = srv.server_address[1]
    try:
        res = web_redrive(f"http://127.0.0.1:{port}/preview?next=orig",
                          slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert _HITS["n"] > 0, "the re-drive must actually contact the server (not a vacuous refusal pass)"
    assert res.n_facts == 0, f"a benign reflecting page must NOT mint a FACT: {[x.finding_ref for x in res.facts]}"
    assert any(x.outcome == "clean" for x in res.leads), "the open_redirect probe must be a channel-confirmed CLEAN"


def test_a_real_meta_refresh_open_redirect_mints_a_fact(monkeypatch, tmp_path):
    """The co-location fix TIGHTENS, it does not disable: a page that reflects the canary into a REAL
    <meta http-equiv=refresh content='0;url=<canary>'> still mints a signed open_redirect FACT."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    from vigil_integration.live.web_redrive import web_redrive
    signers, tr = _signers_and_trust()
    srv = _serve()
    port = srv.server_address[1]
    try:
        res = web_redrive(f"http://127.0.0.1:{port}/metarefresh?next=orig",
                          slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    facts = [x for x in res.facts if "open_redirect" in x.finding_ref]
    assert facts, f"a real meta-refresh redirect to the canary must mint a FACT; leads={res.leads}"
    ctx = res.contexts[facts[0].finding_ref]
    assert verify_certificate(facts[0].signed, oracle_context=ctx, trust_root=tr).ok is True


def test_wildcard_cors_with_credentials_mints_no_fact(monkeypatch, tmp_path):
    """RED-PEN MEDIUM-1: ACAO:* + Allow-Credentials:true is a misconfig but browsers refuse *+creds, so it
    is NOT credential-readable — it must NOT mint an exploitable cors FACT."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import web_redrive
    signers, _ = _signers_and_trust()
    srv = _serve()
    port = srv.server_address[1]
    try:
        res = web_redrive(f"http://127.0.0.1:{port}/corswild",
                          slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert _HITS["n"] > 0, "the re-drive must actually contact the server"
    assert not [x for x in res.facts if "cors" in x.finding_ref], "ACAO:* + creds must NOT mint a cors FACT"


def test_a_connection_refused_midrun_is_inconclusive_not_clean(tmp_path, monkeypatch):
    """RED-PEN BLOCK-2: an in-scope target that refuses the connection (closed port) passes the pre-flight
    but the actual sends get connection-refused — NO channel. Every probe must be INCONCLUSIVE, never a
    'channel-confirmed CLEAN' (the 'found nothing != CLEAN' invariant). No FACT, no CLEAN lead."""
    import socket
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import web_redrive
    signers, _ = _signers_and_trust()
    # bind then immediately close → a port nothing listens on (connection refused), still in scope
    s = socket.socket(); s.bind(("127.0.0.1", 0)); closed_port = s.getsockname()[1]; s.close()
    res = web_redrive(f"http://127.0.0.1:{closed_port}/redirect?next=orig",
                      slug="alpha", engagement_slug="alpha", signers=signers, timeout=2.0)
    assert res.refused is False, "pre-flight passes (in scope); the refusal is at connect-time, not the gate"
    assert res.n_facts == 0
    assert res.leads == [], f"a target that was never reached must NOT yield CLEAN leads: {res.leads}"
    assert res.inconclusive, "a no-channel probe must be recorded INCONCLUSIVE, not clean"


# ---- per-surface negative controls: each insertion surface has its own way of looking like a redirect ----

class _RoutingApp(http.server.BaseHTTPRequestHandler):
    """Benign framework behaviour that superficially resembles an open redirect on each surface."""

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def do_GET(self):  # noqa: N802
        _HITS["n"] += 1
        parts = urlsplit(self.path)
        if parts.path.startswith("/canon") and not parts.path.endswith("/"):
            return self._redirect(parts.path + "/")          # canonical-slash normalisation
        if parts.path.startswith("/dbl"):
            return self._redirect(parts.path.replace("//", "/"))  # path normalisation
        if parts.path.startswith("/auth"):
            return self._redirect("/login?next=" + parts.path)    # generic login redirect
        if parts.path.startswith("/missing"):
            return self._redirect("/404")                    # framework not-found redirect
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        return


def _serve_routing():
    _HITS["n"] = 0
    srv = http.server.HTTPServer(("127.0.0.1", 0), _RoutingApp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.mark.parametrize("route", ["/canon/x", "/dbl//x", "/auth/x", "/missing/x"])
def test_path_normalisation_and_framework_redirects_mint_no_fact(monkeypatch, tmp_path, route) -> None:
    """PATH-surface control. Probing a path segment means the canary lands in the URL PATH, where a framework
    will happily 302 — for a trailing slash, a collapsed `//`, a login gate, or a 404. None of those is an
    application-controlled redirect to the attacker: the Location authority stays the app's own. A re-drive
    that scored any of them would turn ordinary routing into a signed FACT."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import web_redrive
    signers, _ = _signers_and_trust()
    srv = _serve_routing()
    try:
        res = web_redrive(f"http://127.0.0.1:{srv.server_address[1]}{route}",
                          slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert _HITS["n"] > 0, "the control must actually be probed, not gated off"
    assert res.n_facts == 0, f"routing behaviour minted a FACT: {[f.finding_ref for f in res.facts]}"


def test_every_insertion_surface_is_admitted_and_attributed(monkeypatch, tmp_path) -> None:
    """Whatever the surface, an outcome must reach a REGISTERED branch — an unattributed probe would be a
    verdict no capability check ever saw."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    import sys
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "integration"))
    from vigil_integration.live.verdict import branch_ids
    from vigil_integration.live.web_redrive import web_redrive
    signers, _ = _signers_and_trust()
    srv = _serve_routing()
    try:
        res = web_redrive(f"http://127.0.0.1:{srv.server_address[1]}/canon/x?next=orig",
                          slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert res.admissions, "no admission was recorded for any probe"
    unknown = [b for b, _v, _r in res.admissions if b not in branch_ids()]
    assert not unknown, f"outcomes attributed to unregistered branches: {unknown}"



def test_location_header_branch_requires_a_real_3xx_not_a_reflected_location(monkeypatch, tmp_path):
    """ADVERSARIAL BLOCK-1: a status-200 page that reflects the canary into a Location header (and carries a
    body redirect) must NOT mint an open_redirect.location_header FACT — that branch's declared evidence is
    a 3xx REDIRECT, and attributing a render-dependent body redirect to the header surface laundered
    evidence that was never observed into a clean-capable, offline-verifiable certificate. The body branch
    still fires on its real evidence, so the family verdict stays FACT via the branch actually observed."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import web_redrive
    signers, _ = _signers_and_trust()

    class _Soft(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            nxt = (parse_qs(urlsplit(self.path).query).get("next") or [""])[0]
            self.send_response(200)                       # NOT a redirect
            self.send_header("Location", nxt)             # ... but reflects the canary into Location
            self.send_header("Content-Type", "text/html; charset=utf-8")   # declared: body is adjudicable
            self.end_headers()
            self.wfile.write(f'<meta http-equiv="refresh" content="0;url={nxt}">'.encode())

        def log_message(self, *a):
            return

    srv = http.server.HTTPServer(("127.0.0.1", 0), _Soft)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        res = web_redrive(f"http://127.0.0.1:{srv.server_address[1]}/x?next=orig",
                          slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    verdicts = res.branch_verdicts.get("open_redirect", {})
    assert verdicts.get("open_redirect.location_header") != "FACT", (
        "a status-200 reflected Location was laundered into a header-surface FACT")
    assert verdicts.get("open_redirect.body_markup") == "FACT", "the real body evidence should still fire"
    assert res.family_verdict("open_redirect") == "FACT", "the family is FACT via the branch truly observed"


def test_family_verdict_survives_a_benign_insertion_point_after_the_firing_one(monkeypatch, tmp_path):
    """RE-ATTACK BLOCK: _run fires once per insertion point with the same branch names, so a benign point
    processed AFTER the firing one used to OVERWRITE its verdict (last-wins), reporting the family as
    INCONCLUSIVE while a live signed FACT sat in res.facts. `?next=<redirect>&utm_source=x` is an everyday
    URL. The family must be FACT whenever ANY point produced one, independent of param order."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import web_redrive
    signers, _ = _signers_and_trust()

    class _Meta(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            nxt = (parse_qs(urlsplit(self.path).query).get("next") or [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")   # declared: body is adjudicable
            self.end_headers()
            self.wfile.write(f'<meta http-equiv="refresh" content="0;url={nxt}">'.encode())

        def log_message(self, *a):
            return

    for path in ("/x?next=orig&z=orig", "/x?a=orig&next=orig"):   # firing point last, then first
        srv = http.server.HTTPServer(("127.0.0.1", 0), _Meta)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            res = web_redrive(f"http://127.0.0.1:{srv.server_address[1]}{path}",
                              slug="alpha", engagement_slug="alpha", signers=signers)
        finally:
            srv.shutdown()
        assert res.n_facts >= 1, f"{path}: expected a signed FACT"
        assert res.family_verdict("open_redirect") == "FACT", (
            f"{path}: family collapsed to {res.family_verdict('open_redirect')} despite a live FACT")


# ---- W16-STD-1: insertion coverage — cookie / urlencoded-body / JSON-body redirect params ----------
#
# Before this slice the re-drive built a bare GET template, so a redirect reachable ONLY via a cookie, a
# urlencoded body, or a JSON body was NEVER probed — invisible to adjudication, which reads to a consumer as
# "nothing there". These tests drive each of those surfaces LIVE and prove (a) the vuln is FOUND when it is
# there, and (b) a target with none is a bounded CLEAN whose coverage statement NAMES every surface examined.
_REDIRECT_SURFACES = {"query_value", "url_path_seg", "cookie_value", "body_form_value", "json_value"}


class _BodyRedirect(http.server.BaseHTTPRequestHandler):
    """A target that redirects to whatever host it is handed — but on exactly ONE surface, chosen by the
    handler subclass. Every other surface must be examined and found clean. The redirect parameter name is
    ``next`` (in the fixed candidate set AND grounded when the URL carries it)."""

    surface = ""   # one of: cookie / form / json

    def _maybe_redirect(self, nxt: str) -> None:
        if nxt and nxt.startswith("http"):
            self.send_response(302)
            self.send_header("Location", nxt)
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"ok")

    def _read_body(self) -> bytes:
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n) if n > 0 else b""

    def do_GET(self):  # noqa: N802
        _HITS["n"] += 1
        nxt = ""
        if self.surface == "cookie":
            for part in (self.headers.get("Cookie", "") or "").split(";"):
                k, _s, v = part.strip().partition("=")
                if k.strip() == "next":
                    nxt = v.strip()
        self._maybe_redirect(nxt)

    def do_POST(self):  # noqa: N802
        _HITS["n"] += 1
        raw = self._read_body()
        ct = (self.headers.get("Content-Type", "") or "").split(";")[0].strip().lower()
        nxt = ""
        if self.surface == "form" and ct == "application/x-www-form-urlencoded":
            nxt = parse_qs(raw.decode("utf-8", "replace")).get("next", [""])[0]
        elif self.surface == "json" and ct == "application/json":
            try:
                nxt = str((json.loads(raw.decode("utf-8")) or {}).get("next", ""))
            except Exception:  # noqa: BLE001
                nxt = ""
        self._maybe_redirect(nxt)

    def log_message(self, *a):
        return


def _serve_body_redirect(surface: str):
    _HITS["n"] = 0
    handler = type(f"_BR_{surface}", (_BodyRedirect,), {"surface": surface})
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.mark.parametrize("surface,marker", [
    ("cookie", "cookie_value"),
    ("form", "body_form_value"),
    ("json", "json_value"),
])
def test_a_redirect_reachable_only_via_cookie_form_or_json_body_is_found(monkeypatch, tmp_path, surface, marker):
    """Each non-query surface, driven LIVE: a target that redirects to the attacker host ONLY when the
    redirect parameter arrives via a Cookie / urlencoded body / JSON body must be FOUND. The runner
    synthesises the matching carrier (correct method + Content-Type), injects the canary into that insertion
    point, and the oracle fires on the real 302→canary host. The FACT is attributed to the exact surface."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    from vigil_integration.live.web_redrive import web_redrive
    signers, tr = _signers_and_trust()
    srv = _serve_body_redirect(surface)
    try:
        res = web_redrive(f"http://127.0.0.1:{srv.server_address[1]}/login",
                          slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    facts = [x for x in res.facts if "open_redirect" in x.finding_ref]
    assert facts, f"a {surface}-only open redirect was not found; leads={res.leads} notes={res.notes}"
    assert any(marker in x.finding_ref for x in facts), (
        f"the FACT was not attributed to the {marker} insertion surface: {[f.finding_ref for f in facts]}")
    ctx = res.contexts[facts[0].finding_ref]
    assert verify_certificate(facts[0].signed, oracle_context=ctx, trust_root=tr).ok is True


class _NeverRedirect(http.server.BaseHTTPRequestHandler):
    """Answers every method 200 and NEVER redirects to the canary — a genuinely clean target on every
    surface, so a bounded negative is legitimately earned."""

    def _ok(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<html><body>ok</body></html>")

    def do_GET(self):  # noqa: N802
        _HITS["n"] += 1
        self._ok()

    def do_POST(self):  # noqa: N802
        _HITS["n"] += 1
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n:
            self.rfile.read(n)
        self._ok()

    def log_message(self, *a):
        return


def test_clean_target_is_bounded_clean_and_names_every_insertion_surface(monkeypatch, tmp_path):
    """The negative half of criterion (b): a target with NO redirect on any surface reports the header-derived
    open_redirect.location_header branch CLEAN, and that CLEAN is a BOUNDED negative whose coverage statement
    NAMES every insertion surface examined (query, path, cookie, urlencoded body, JSON body). Naming the
    coverage is what makes it 'examined here and found nothing' rather than an unbounded 'nothing there'."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import web_redrive
    signers, _ = _signers_and_trust()
    _HITS["n"] = 0
    srv = http.server.HTTPServer(("127.0.0.1", 0), _NeverRedirect)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        res = web_redrive(f"http://127.0.0.1:{srv.server_address[1]}/app/page?next=orig",
                          slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    assert _HITS["n"] > 0, "the target must actually be probed on every surface"
    assert res.n_facts == 0, f"a clean target minted a FACT: {[f.finding_ref for f in res.facts]}"
    # the header-derived branch earns a bounded negative (CLEAN) — surfaced as a channel-confirmed clean lead
    assert res.branch_verdicts.get("open_redirect", {}).get("open_redirect.location_header") == "CLEAN", (
        f"the header branch did not reach a bounded CLEAN: {res.branch_verdicts.get('open_redirect')}")
    # ... and the CLEAN is bounded to the NAMED insertion surfaces — all five were examined
    probed = set(res.surfaces_probed("open_redirect"))
    assert probed == _REDIRECT_SURFACES, f"coverage did not span every insertion surface: {sorted(probed)}"
    statement = res.coverage_statement("open_redirect")
    for surface in _REDIRECT_SURFACES:
        assert surface in statement, f"coverage statement omits {surface!r}: {statement}"


def test_insertion_coverage_went_from_two_surfaces_to_five(monkeypatch, tmp_path):
    """The count criterion (d), made concrete: the live re-drive now EXAMINES all five redirect insertion
    surfaces, not the two (QUERY_VALUE, URL_PATH_SEG) it used to. Each of the three added surfaces is what
    lets the corresponding evidence branch assert a bounded negative it could not assert before."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.web_redrive import web_redrive
    signers, _ = _signers_and_trust()
    _HITS["n"] = 0
    srv = http.server.HTTPServer(("127.0.0.1", 0), _NeverRedirect)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        res = web_redrive(f"http://127.0.0.1:{srv.server_address[1]}/app/page?next=orig",
                          slug="alpha", engagement_slug="alpha", signers=signers)
    finally:
        srv.shutdown()
    probed = set(res.surfaces_probed("open_redirect"))
    assert probed == _REDIRECT_SURFACES, f"expected 5 surfaces, got {sorted(probed)}"
    added = {"cookie_value", "body_form_value", "json_value"}
    assert added <= probed, f"the three newly-covered surfaces are missing: {sorted(added - probed)}"
