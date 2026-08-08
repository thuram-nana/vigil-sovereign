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
            self.send_header("Content-Type", "text/plain")
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
