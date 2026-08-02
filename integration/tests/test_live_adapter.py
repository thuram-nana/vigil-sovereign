"""VF-1a.2 — the REAL live-HTTP remediation re-drive adapter, end-to-end against a GENUINE loopback server.

Unlike test_prove_driver.py (the four-state machine offline against a fake adapter), this drives the REAL
:class:`LiveHttpAdapter` through CRUCIBLE's gated :class:`HttpExecutor` against a stdlib
``ThreadingHTTPServer`` on 127.0.0.1 — actual sockets, actual HTTP, the actual error_signature oracle
re-firing over the freshly-captured bytes. It produces all four states from the ONE adapter by toggling the
server (patched ↔ vulnerable ↔ down ↔ nonce-not-echoed) and the capability (valid ↔ expired):

  * PATCHED server + firing retained control → REMEDIATED, and the signed cert verifies (cross-bound).
  * VULNERABLE server                        → STILL_VULNERABLE (the live oracle fires over FRESH evidence).
  * server DOWN                              → INCONCLUSIVE (the fresh trial is unreachable).
  * server does NOT echo the nonce           → INCONCLUSIVE (freshness cannot be established).
  * expired capability                       → REFUSED (testing must not begin).

Gating: the HttpExecutor scope gate is CRUCIBLE's per-target CHARTER (charter signed + host in scope), which
is what admits a loopback fetch — so the fixture writes a signed charter with 127.0.0.1 in scope and points
the framework path helpers at a tmp tree (hermetic; mirrors test_http_executor_oracle_context.py). The
provisioned CRUCIBLE authority supplies the governance keypair + cert signers used to mint/verify the prove
certificate. Needs framework (reverify + the translator) → PYTHONPATH=integration:engine/crucible:gateway.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("framework.v2.verify.confirmation", reason="CRUCIBLE (offense) not importable here")

from vigil_core import (  # noqa: E402
    generate_keypair, identity_digest, prove_wielder, sign_capability, sign_identity_attestation,
)
from vigil_integration.live.wiring import provision_authority  # noqa: E402
from vigil_integration.remediation.live_adapter import LiveHttpAdapter  # noqa: E402
from vigil_integration.remediation.prove_driver import (  # noqa: E402
    Freshness, ProvePolicy, Reason, State, prove_remediation, verify_prove_certificate,
)

from framework.v2.agents import HttpExecutor  # noqa: E402
from framework.v2.common import paths as _paths  # noqa: E402

ENG = "remediate-live"
NOW = 1_000
BUG = "error_based_sqli"
WIELDER = generate_keypair()

# The RETAINED original firing bytes (the positive control): a real MySQL error-based-SQLi signature.
_ORIG_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near '' at line 1"


def _error_context(body: bytes) -> dict:
    """Build the error_signature oracle_context the original oracle re-fires over — the SAME translator the
    adapter and the base RemediationCertificate use."""
    from framework.v2.evidence.poc import CapturedExchange
    from framework.v2.verify.poc_translate import context_from_exchanges
    ex = CapturedExchange(channel="error_signature", role="mutated", response_bytes_ref="resp")
    ctx = context_from_exchanges([ex], bug_class=BUG, resolve=lambda _r: body)
    assert ctx is not None
    return ctx.model_dump(mode="json")


# --------------------------------------------------------------------------------------------------------
# A genuine loopback HTTP target (stdlib only — pytest_httpserver is NOT importable in the offense venv).
# --------------------------------------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # keep the test output quiet
        pass

    def do_GET(self):  # noqa: N802 — BaseHTTPRequestHandler contract
        srv = self.server
        q = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        exploit_present = any(v for v in q.get(srv.exploit_param, []))    # the injectable param carried a value
        nonce = (q.get(srv.nonce_param) or [""])[0]
        if (not srv.patched) and exploit_present:
            # the VULNERABLE build leaks a datastore parser error the error_signature oracle fires on.
            body = "HTTP 500 Internal Server Error\nYou have an error in your SQL syntax near '' at line 1\n"
        else:
            # the PATCHED build (or a benign request) answers cleanly — the oracle stays silent.
            body = '{"results": [], "ok": true}\n'
        if srv.echo_nonce and nonce:
            body += f"\n<!-- vigil-echo:{nonce} -->\n"                    # freshness: echo the run challenge
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _start(*, patched: bool, echo_nonce: bool = True,
           exploit_param: str = "q", nonce_param: str = "rc") -> _Server:
    srv = _Server(("127.0.0.1", 0), _Handler)
    srv.patched = patched            # type: ignore[attr-defined]
    srv.echo_nonce = echo_nonce      # type: ignore[attr-defined]
    srv.exploit_param = exploit_param  # type: ignore[attr-defined]
    srv.nonce_param = nonce_param    # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# --------------------------------------------------------------------------------------------------------
# hermetic CRUCIBLE paths — a signed charter so the HttpExecutor scope gate ADMITS loopback.
# --------------------------------------------------------------------------------------------------------
_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `127.0.0.1` | Loopback test app | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
- [ ] **AUDIT**
- [ ] **EMULATE**
"""


@pytest.fixture()
def gated_root(tmp_path, monkeypatch):
    """Point the framework path helpers at a throwaway tree: the signed charter (so the executor's scope gate
    admits 127.0.0.1), the kill-switch, per-target evidence, and the provisioned authority all land under
    tmp_path — hermetic, and independent of the cached CRUCIBLE_ROOT."""
    targets = tmp_path / "targets"
    (targets / ENG).mkdir(parents=True)
    (targets / ENG / "charter.md").write_text(_CHARTER.format(slug=ENG), encoding="utf-8")
    authdir = tmp_path / "authority"
    authdir.mkdir()
    monkeypatch.setattr(_paths, "target_dir", lambda s: targets / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets / s / "charter.md")
    monkeypatch.setattr(_paths, "killswitch_path", lambda s: targets / s / ".halt")
    monkeypatch.setattr(_paths, "authority_path", lambda s: authdir / f"{s}.authority.json")
    return tmp_path


def _executor(base_url: str) -> HttpExecutor:
    # a bare gated executor: the charter scope gate + auto-wired (untripped) kill-switch bound it; GET is
    # non-destructive so the deny-by-default prompt is never hit.
    return HttpExecutor(engagement_slug=ENG, base_url=base_url, prompt_callback=lambda *_a: False)


def _adapter(srv: _Server) -> LiveHttpAdapter:
    base = f"http://127.0.0.1:{srv.server_address[1]}/"
    return LiveHttpAdapter(
        executor=_executor(base), base_url=base, endpoint_path="/search", param="q",
        payload="x' OR '1'='1", nonce_param="rc",
        original_firing_context=_error_context(_ORIG_SQL_ERROR), bug_class=BUG)


def _drive(adapter, *, now=NOW, not_after=9_000, rate_limit=10, revocation_id="rev-1",
           revoked_ids=frozenset(), policy=ProvePolicy(), classes=None):
    """Compose the owner-attested identity + capability + wielder proof (over a freshly provisioned
    governance keypair) and run the gated four-state flow. Returns (outcome, pinned-pubkeys)."""
    prov = provision_authority(slug=ENG, scope=["127.0.0.1"])
    owner = prov.keypair
    # the identity attestation stays valid (it is verified FIRST); ``not_after`` expires only the CAPABILITY,
    # so an expired capability is refused as EXPIRED_CAPABILITY (not masked by a stale identity).
    ident = sign_identity_attestation(owner, engagement=ENG, policy={"host": ["127.0.0.1"]}, not_after=9_000)
    cap = sign_capability(owner, engagement=ENG, identity_digest=identity_digest(ident),
                          class_allowlist=(classes or [adapter.bug_class]), not_before=0, not_after=not_after,
                          rate_limit=rate_limit, revocation_id=revocation_id,
                          audience=WIELDER.public_key_b64)
    wproof = prove_wielder(WIELDER, challenge="pop-1", capability=cap)
    out = prove_remediation(
        adapter=adapter, identity=ident, capability=cap, wielder_proof=wproof,
        trusted_owner_pubkey=owner.public_key_b64, engagement=ENG, finding_id="errsqli-1",
        original_certificate_digest="sha256:orig", signers=prov.signers, now=now, run_id="run-1",
        pop_challenge="pop-1", freshness_nonce="fresh-nonce-xyz", revoked_ids=revoked_ids, policy=policy)
    pubkeys = {prov.signers[0][0]: owner.public_key_b64}
    return out, pubkeys


# ============================ the four states, live ============================
def test_patched_server_is_remediated_and_cert_verifies(gated_root):
    srv = _start(patched=True)
    try:
        out, pubkeys = _drive(_adapter(srv))
    finally:
        srv.shutdown(); srv.server_close()
    assert out.state == State.REMEDIATED, out
    assert out.reason_code == Reason.ORACLE_SILENT_ACROSS_TRIALS
    assert out.trials_valid == 3 and out.achieved_freshness == Freshness.F2_PATH_TRAVERSED
    ok, reason = verify_prove_certificate(out.certificate, signer_pubkeys=pubkeys)
    assert ok, reason
    assert "cross-bound" in reason
    assert out.certificate["evidence"]["embedded_remediation_cert"] is not None


def test_vulnerable_server_is_still_vulnerable_over_fresh_evidence(gated_root):
    srv = _start(patched=False)
    try:
        out, pubkeys = _drive(_adapter(srv))
    finally:
        srv.shutdown(); srv.server_close()
    assert out.state == State.STILL_VULNERABLE and out.reason_code == Reason.ORACLE_FIRED
    ok, _ = verify_prove_certificate(out.certificate, signer_pubkeys=pubkeys)
    assert ok and out.certificate["verdict"]["oracle_fired"] is True


def test_down_server_is_inconclusive_target_unavailable(gated_root):
    srv = _start(patched=True)
    adapter = _adapter(srv)
    srv.shutdown(); srv.server_close()          # take the target DOWN before the run
    out, _ = _drive(adapter)
    assert out.state == State.INCONCLUSIVE, out
    assert out.reason_code in (Reason.TARGET_UNAVAILABLE, Reason.RESPONSE_CHANNEL_DEGRADED)


def test_missing_nonce_echo_is_inconclusive_freshness(gated_root):
    srv = _start(patched=True, echo_nonce=False)
    try:
        out, _ = _drive(_adapter(srv))
    finally:
        srv.shutdown(); srv.server_close()
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.FRESHNESS_ECHO_MISSING


def test_expired_capability_is_refused(gated_root):
    srv = _start(patched=True)
    try:
        out, _ = _drive(_adapter(srv), not_after=NOW - 1)
    finally:
        srv.shutdown(); srv.server_close()
    assert out.state == State.REFUSED and out.reason_code == Reason.EXPIRED_CAPABILITY
