"""VF-2c — the live remediation adapter binds a RemediationCertificate to the target's OBSERVED TLS SPKI.

Sibling to test_live_adapter.py (the four-state re-drive over a plaintext loopback). Here the target is a
GENUINE loopback HTTPS server with a self-signed cert, so the adapter's ``identity_sample()`` performs the
SAME audited, bounded TLS handshake as ``verify.reachability`` and binds the sha256 of the leaf-key
SubjectPublicKeyInfo (the ACTUAL key the endpoint presented), not a producer-asserted host string.

What is proven end-to-end through ``prove_remediation``:

  * ``capture_tls_handshake`` against the server returns ``spki_sha256`` equal to an INDEPENDENT computation
    of sha256(SubjectPublicKeyInfo DER) of the server cert.
  * the adapter's ``identity_sample()`` includes that ``tls_spki_sha256`` ALONGSIDE ``host``.
  * an ``IdentityAttestation`` pinning the REAL observed SPKI → the run proceeds to REMEDIATED (identity gate
    passes; the SPKI is bound into the signed cert's target identity digest).
  * an ``IdentityAttestation`` pinning a DIFFERENT (wrong) SPKI → REFUSED (IDENTITY_POLICY_MISMATCH). This is
    the anti-transplant property: a verdict earned against key K cannot be transplanted onto key K'.

httpx (the executor's trial client) verifies TLS, so the self-signed server cert is trusted for the trial
leg by pointing ``SSL_CERT_FILE`` at it (a test-only trust decision; the handshake in identity_sample uses
the reachability probe which deliberately does not validate — a posture/identity probe, not a trust check).
Needs framework (reverify + translator + tls) → PYTHONPATH=integration:engine/crucible:gateway.
"""
from __future__ import annotations

import hashlib
import ipaddress
import ssl
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
    Freshness, ProvePolicy, Reason, State, prove_remediation, target_identity_digest_of, verify_prove_certificate,
)

from framework.v2.agents import HttpExecutor  # noqa: E402
from framework.v2.common import paths as _paths  # noqa: E402
from framework.v2.verify.tls import capture_tls_handshake  # noqa: E402

ENG = "remediate-live-tls"
NOW = 1_000
BUG = "error_based_sqli"
WIELDER = generate_keypair()
WRONG_SPKI = "00" * 32   # a syntactically valid-but-wrong pin (a different target's key)

# The RETAINED original firing bytes (the positive control): a real MySQL error-based-SQLi signature.
_ORIG_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near '' at line 1"


def _error_context(body: bytes) -> dict:
    from framework.v2.evidence.poc import CapturedExchange
    from framework.v2.verify.poc_translate import context_from_exchanges
    ex = CapturedExchange(channel="error_signature", role="mutated", response_bytes_ref="resp")
    ctx = context_from_exchanges([ex], bug_class=BUG, resolve=lambda _r: body)
    assert ctx is not None
    return ctx.model_dump(mode="json")


# --------------------------------------------------------------------------------------------------------
# A genuine loopback HTTPS target (self-signed cert with SAN 127.0.0.1 so httpx hostname-verifies).
# --------------------------------------------------------------------------------------------------------
def _mint_https_cert(tmp_path):
    """Mint a self-signed cert+key PEM (SAN 127.0.0.1) for the loopback HTTPS server. Returns
    (certfile, keyfile, reference_spki) or None if cryptography is unavailable. The reference SPKI is
    computed INDEPENDENTLY of the function under test (from the cert object)."""
    try:
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except Exception:
        return None
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime(2026, 1, 1)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(datetime.datetime(2030, 1, 1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                           critical=False)
            .sign(key, hashes.SHA256()))
    certfile = tmp_path / "srv-cert.pem"
    keyfile = tmp_path / "srv-key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.TraditionalOpenSSL,
                                          serialization.NoEncryption()))
    spki_der = cert.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
    return str(certfile), str(keyfile), hashlib.sha256(spki_der).hexdigest()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # keep the test output quiet
        pass

    def do_GET(self):  # noqa: N802 — BaseHTTPRequestHandler contract
        srv = self.server
        q = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        exploit_present = any(v for v in q.get(srv.exploit_param, []))
        nonce = (q.get(srv.nonce_param) or [""])[0]
        if (not srv.patched) and exploit_present:
            body = "HTTP 500 Internal Server Error\nYou have an error in your SQL syntax near '' at line 1\n"
        else:
            body = '{"results": [], "ok": true}\n'
        if srv.echo_nonce and nonce:
            body += f"\n<!-- vigil-echo:{nonce} -->\n"
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        # identity_sample's TLS handshake probe closes without sending an HTTP request line; that surfaces as
        # a BrokenPipe/EOF in the handler thread. It is expected and harmless — swallow the noisy traceback.
        pass


def _start_https(certfile, keyfile, *, patched: bool, echo_nonce: bool = True,
                 exploit_param: str = "q", nonce_param: str = "rc") -> _Server:
    srv = _Server(("127.0.0.1", 0), _Handler)
    srv.patched = patched            # type: ignore[attr-defined]
    srv.echo_nonce = echo_nonce      # type: ignore[attr-defined]
    srv.exploit_param = exploit_param  # type: ignore[attr-defined]
    srv.nonce_param = nonce_param    # type: ignore[attr-defined]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)   # serve HTTPS
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# --------------------------------------------------------------------------------------------------------
# hermetic CRUCIBLE paths — a signed charter so the executor scope gate AND the reachability TLS gate admit
# loopback. (Same pattern as test_live_adapter.py.)
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
    return HttpExecutor(engagement_slug=ENG, base_url=base_url, prompt_callback=lambda *_a: False)


def _adapter(srv: _Server) -> LiveHttpAdapter:
    # base_url is HTTPS; the adapter derives the handshake slug from the executor it already holds.
    base = f"https://127.0.0.1:{srv.server_address[1]}/"
    return LiveHttpAdapter(
        executor=_executor(base), base_url=base, endpoint_path="/search", param="q",
        payload="x' OR '1'='1", nonce_param="rc",
        original_firing_context=_error_context(_ORIG_SQL_ERROR), bug_class=BUG)


def _drive(adapter, *, identity_policy, now=NOW, not_after=9_000, rate_limit=10, policy=ProvePolicy()):
    prov = provision_authority(slug=ENG, scope=["127.0.0.1"])
    owner = prov.keypair
    ident = sign_identity_attestation(owner, engagement=ENG, policy=identity_policy, not_after=9_000)
    cap = sign_capability(owner, engagement=ENG, identity_digest=identity_digest(ident),
                          class_allowlist=[adapter.bug_class], not_before=0, not_after=not_after,
                          rate_limit=rate_limit, revocation_id="rev-1", audience=WIELDER.public_key_b64)
    wproof = prove_wielder(WIELDER, challenge="pop-1", capability=cap)
    out = prove_remediation(
        adapter=adapter, identity=ident, capability=cap, wielder_proof=wproof,
        trusted_owner_pubkey=owner.public_key_b64, engagement=ENG, finding_id="errsqli-1",
        original_certificate_digest="sha256:orig", signers=prov.signers, now=now, run_id="run-1",
        pop_challenge="pop-1", freshness_nonce="fresh-nonce-xyz", policy=policy)
    pubkeys = {prov.signers[0][0]: owner.public_key_b64}
    return out, pubkeys


# ============================ the observed-SPKI identity ============================
def test_capture_tls_handshake_observes_the_server_spki(gated_root, tmp_path):
    minted = _mint_https_cert(tmp_path)
    if minted is None:
        pytest.skip("cryptography not available")
    certfile, keyfile, ref_spki = minted
    srv = _start_https(certfile, keyfile, patched=True)
    try:
        tls = capture_tls_handshake("127.0.0.1", srv.server_address[1], slug=ENG, timeout=5.0)
    finally:
        srv.shutdown(); srv.server_close()
    assert tls["connected"] is True
    assert tls.get("spki_sha256") == ref_spki   # the OBSERVED leaf-key, over a genuine handshake


def test_identity_sample_includes_the_observed_spki(gated_root, tmp_path):
    minted = _mint_https_cert(tmp_path)
    if minted is None:
        pytest.skip("cryptography not available")
    certfile, keyfile, ref_spki = minted
    srv = _start_https(certfile, keyfile, patched=True)
    try:
        sample = _adapter(srv).identity_sample()
    finally:
        srv.shutdown(); srv.server_close()
    assert sample["host"] == "127.0.0.1"
    assert sample.get("tls_spki_sha256") == ref_spki   # bound ALONGSIDE host


def test_http_base_url_is_host_only_no_fabricated_spki(gated_root):
    # honesty: a plaintext target yields a host-only binding — an SPKI is NEVER invented.
    srv = _Server(("127.0.0.1", 0), _Handler)
    srv.patched = True; srv.echo_nonce = True          # type: ignore[attr-defined]
    srv.exploit_param = "q"; srv.nonce_param = "rc"    # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}/"
    adapter = LiveHttpAdapter(executor=_executor(base), base_url=base, endpoint_path="/search", param="q",
                              payload="x' OR '1'='1", nonce_param="rc",
                              original_firing_context=_error_context(_ORIG_SQL_ERROR), bug_class=BUG)
    try:
        sample = adapter.identity_sample()
    finally:
        srv.shutdown(); srv.server_close()
    assert sample == {"host": "127.0.0.1"}
    assert "tls_spki_sha256" not in sample


# ============================ the anti-transplant property, end-to-end ============================
def test_policy_pinning_the_real_spki_reaches_remediated(gated_root, tmp_path, monkeypatch):
    minted = _mint_https_cert(tmp_path)
    if minted is None:
        pytest.skip("cryptography not available")
    certfile, keyfile, ref_spki = minted
    # trust the self-signed cert for the httpx TRIAL leg (identity_sample's handshake does not validate).
    monkeypatch.setenv("SSL_CERT_FILE", certfile)
    srv = _start_https(certfile, keyfile, patched=True)
    try:
        out, pubkeys = _drive(_adapter(srv),
                              identity_policy={"host": ["127.0.0.1"], "tls_spki_sha256": [ref_spki]})
    finally:
        srv.shutdown(); srv.server_close()
    assert out.state == State.REMEDIATED, (out.state, out.reason_code, out.detail)
    assert out.reason_code == Reason.ORACLE_SILENT_ACROSS_TRIALS
    assert out.achieved_freshness == Freshness.F1_TARGET_ECHOES
    ok, reason = verify_prove_certificate(out.certificate, signer_pubkeys=pubkeys)
    assert ok, reason
    # the SIGNED cert's target identity binds the OBSERVED SPKI (not a bare host).
    expected_tid = target_identity_digest_of({"host": "127.0.0.1", "tls_spki_sha256": ref_spki})
    assert out.certificate["target"]["target_identity_digest"] == expected_tid


def test_policy_pinning_a_wrong_spki_is_refused_anti_transplant(gated_root, tmp_path, monkeypatch):
    minted = _mint_https_cert(tmp_path)
    if minted is None:
        pytest.skip("cryptography not available")
    certfile, keyfile, _ref_spki = minted
    monkeypatch.setenv("SSL_CERT_FILE", certfile)
    srv = _start_https(certfile, keyfile, patched=True)
    try:
        # the owner pins a DIFFERENT key — this target's real SPKI does not satisfy the policy.
        out, _ = _drive(_adapter(srv),
                        identity_policy={"host": ["127.0.0.1"], "tls_spki_sha256": [WRONG_SPKI]})
    finally:
        srv.shutdown(); srv.server_close()
    assert out.state == State.REFUSED, (out.state, out.reason_code, out.detail)
    assert out.reason_code == Reason.IDENTITY_POLICY_MISMATCH
