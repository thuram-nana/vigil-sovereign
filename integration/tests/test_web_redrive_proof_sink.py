"""S7 (web column) — the proof SINK re-drives a Strix web finding through VIGIL's own gated probes.

This is the production wiring that gives ``live/web_redrive.py`` its first caller: when a Strix finding whose
class is web-re-drivable (open_redirect / cors / host_header_injection) reaches ``proof.sink``, the mint
callback RE-SENDS VIGIL's own crafted, gated probe against the finding's ``endpoint`` and mints a signed FACT
ONLY over that fresh, VIGIL-produced capture — never over bytes Strix recorded. A benign endpoint mints
nothing (the finding stays a LEAD). The traffic is VIGIL's own gated transport; no external tool is run.

The headline proofs are genuinely live against a loopback server. The load-bearing test is the FALSE-FACT
one: a safe endpoint must NOT mint.
"""
from __future__ import annotations

import http.server
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")

from vigil_integration.proof.run import _web_redrive_class, build_report_mint  # noqa: E402
from vigil_integration.proof.sink import CAPTURE_KEY, ProofSink, _web_redrivable  # noqa: E402


# ---- gate isolation + charter (mirrors test_web_redrive / the reachability_cloud live tests) ---------
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


# ---- a loopback app: a REAL open-redirect + a REAL credential-reflecting CORS + a SAFE endpoint ------
class _WebApp(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        parts = urlsplit(self.path)
        q = parse_qs(parts.query)
        if parts.path == "/redirect":                       # VULNERABLE open redirect: reflects `next`
            self.send_response(302)
            self.send_header("Location", (q.get("next") or [""])[0])
            self.end_headers()
        elif parts.path == "/api":                          # VULNERABLE cors: reflects Origin + creds
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b"{}")
        elif parts.path == "/safe":                         # SAFE: plain-text reflection only
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"you requested: {(q.get('next') or [''])[0]}".encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):  # silence
        return


def _serve():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _WebApp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _sink(tmp_path: Path):
    signers, tr = _signers_and_trust()
    mint = build_report_mint(run_dir=tmp_path, signers=signers, engagement_slug="alpha")
    return ProofSink(quarantine_dir=str(tmp_path / "q"), mint=mint), signers, tr


# ---- class routing (unit) ---------------------------------------------------------------------------

def test_web_redrive_class_routing():
    assert _web_redrive_class({"bug_class": "open_redirect"}) == "open_redirect"
    assert _web_redrive_class({"bug_class": "cors"}) == "cors"
    assert _web_redrive_class({"finding_class": "host_header_injection"}) == "host_header_injection"
    assert _web_redrive_class({"cwe": "CWE-601"}) == "open_redirect"
    assert _web_redrive_class({"cwe": "CWE-942: permissive CORS"}) == "cors"
    assert _web_redrive_class({"cwe": "CWE-644"}) == "host_header_injection"
    # NOT web-re-drivable → None (falls through to captured-bytes mint / LEAD)
    for r in ({"bug_class": "error_based_sqli"}, {"cwe": "CWE-89"}, {"bug_class": "xss"}, {}, {"endpoint": "/x"}):
        assert _web_redrive_class(r) is None
    assert _web_redrivable({"bug_class": "open_redirect"}) is True
    assert _web_redrivable({"bug_class": "error_based_sqli"}) is False


# ---- the live sink proofs ---------------------------------------------------------------------------

def test_vulnerable_endpoint_mints_a_signed_fact_via_the_sink(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    sink, _, _ = _sink(tmp_path)
    port = _serve().server_address[1]
    out = sink({"id": "f1", "bug_class": "open_redirect",
                "endpoint": f"http://127.0.0.1:{port}/redirect?next=http://canary.evil.example/"})
    assert out.gate == "allow"
    assert out.minted is True, "a live open-redirect re-driven by VIGIL did not mint a FACT"
    # and a web-redrive record was persisted for the Proof-Studio screen. (The signed cert's OFFLINE
    # re-verification is exercised directly on web_redrive's output by test_web_redrive.py + inv10; here we
    # assert only what this SINK test observes — minted + a persisted record.)
    recs = sorted((tmp_path / "proofs").glob("webredrive-*.json"))
    assert recs, "no web-redrive record persisted"


def test_benign_endpoint_mints_nothing_the_false_fact_control(monkeypatch, tmp_path):
    """THE load-bearing test: a safe endpoint must NOT mint. VIGIL's own re-drive refutes a would-be claim."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    sink, _, _ = _sink(tmp_path)
    port = _serve().server_address[1]
    out = sink({"id": "f2", "bug_class": "open_redirect",
                "endpoint": f"http://127.0.0.1:{port}/safe?next=http://canary.evil.example/"})
    assert out.gate == "allow"
    assert out.minted is False, "a BENIGN endpoint minted a FACT — the re-drive false-FACT control failed"


def test_out_of_scope_endpoint_is_refused_and_mints_nothing(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")            # charter authorises 127.0.0.1 only
    sink, _, _ = _sink(tmp_path)
    out = sink({"id": "f3", "bug_class": "open_redirect",
                "endpoint": "http://198.51.100.7/redirect?next=http://evil.example/"})  # NOT in scope
    assert out.minted is False, "an out-of-charter endpoint minted — the pre-flight gate did not refuse"


def test_no_channel_is_inconclusive_not_a_fact(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    sink, _, _ = _sink(tmp_path)
    # a closed port on an in-scope host → no channel established → INCONCLUSIVE, never a FACT
    out = sink({"id": "f4", "bug_class": "open_redirect",
                "endpoint": "http://127.0.0.1:1/redirect?next=http://evil.example/"})
    assert out.minted is False, "a no-channel probe minted a FACT (found-nothing must not become a claim)"


# ---- the sink-gate relaxation + non-web regression --------------------------------------------------

def test_web_class_without_a_capture_reaches_the_mint(monkeypatch, tmp_path):
    """Proves the sink.py gate change: a web-class report with NO _vigil_capture must reach the mint."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    port = _serve().server_address[1]
    calls = {"n": 0}
    real = build_report_mint(run_dir=tmp_path, signers=_signers_and_trust()[0], engagement_slug="alpha")

    def _spy(report):
        calls["n"] += 1
        return real(report)

    sink = ProofSink(quarantine_dir=str(tmp_path / "q"), mint=_spy)
    sink({"id": "f5", "bug_class": "cors", "endpoint": f"http://127.0.0.1:{port}/api"})
    assert calls["n"] == 1, "a web-class report with no capture never reached the mint (gate not relaxed)"


def test_non_redrivable_class_without_a_capture_still_does_not_reach_the_mint(tmp_path):
    """Regression on the gate: a report in a class VIGIL cannot re-drive (neither a web class nor a W1a
    error-signature injection class) with no capture must NOT reach the mint. W1a relaxed the gate for the
    four injection classes (error_based_sqli / nosqli / ldap_injection / xpath_injection — covered in
    test_strix_errsig_redrive.py), so the example here is a genuinely non-re-drivable class."""
    calls = {"n": 0}
    sink = ProofSink(quarantine_dir=str(tmp_path / "q"), mint=lambda r: calls.__setitem__("n", calls["n"] + 1))
    sink({"id": "f6", "bug_class": "rce"})   # no capture, not web, not an errsig-re-drivable injection class
    assert calls["n"] == 0, "a non-re-drivable report with no capture reached the mint — the gate over-relaxed"


def test_errsig_injection_class_without_a_capture_reaches_the_mint(tmp_path):
    """The W1a gate relaxation: an injection-class report (error_based_sqli) with NO _vigil_capture must reach
    the mint (the error-signature re-drive rail then re-drives / fail-closes to a LEAD)."""
    calls = {"n": 0}
    sink = ProofSink(quarantine_dir=str(tmp_path / "q"), mint=lambda r: calls.__setitem__("n", calls["n"] + 1))
    sink({"id": "f6b", "bug_class": "error_based_sqli", "param": "q",
          "endpoint": "http://127.0.0.1/search"})   # no capture, but an errsig-re-drivable class
    assert calls["n"] == 1, "an injection-class report with no capture never reached the mint (gate not relaxed)"


def test_non_web_capture_uses_the_captured_bytes_path_not_web_redrive(monkeypatch, tmp_path):
    """A error_based_sqli report WITH a valid capture takes the existing captured-bytes mint; web_redrive is
    never invoked (proven by monkeypatching it to explode — the mint must not touch it)."""
    import vigil_integration.live.web_redrive as wr
    monkeypatch.setattr(wr, "web_redrive", lambda *a, **k: (_ for _ in ()).throw(AssertionError("web_redrive called for a non-web finding")))
    mint = build_report_mint(run_dir=tmp_path, signers=_signers_and_trust()[0], engagement_slug="alpha")
    cap = {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                          "status": 500, "bug_class": "error_based_sqli"}],
           "blobs": {"resp": b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended"}}
    # must not raise (web_redrive not called); returns the captured-bytes mint result (may be a fact or lead)
    mint({"id": "f7", "bug_class": "error_based_sqli", CAPTURE_KEY: cap})


# ---- sink never raises ------------------------------------------------------------------------------

def test_a_web_redrive_that_raises_degrades_to_lead_never_propagates(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    import vigil_integration.live.web_redrive as wr
    monkeypatch.setattr(wr, "web_redrive", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    sink, _, _ = _sink(tmp_path)
    out = sink({"id": "f8", "bug_class": "open_redirect", "endpoint": "http://127.0.0.1:9/redirect"})
    assert out.gate == "allow" and out.minted is False, "a raising re-drive did not degrade to a LEAD"
