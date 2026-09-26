"""SLICE S2 — "transport intake": two more re-drive arms on the Strix proof-sink rail whose evidence is a
TRANSPORT handshake rather than an HTTP response body. A Strix LEAD becomes an oracle-confirmed FACT only
because VIGIL re-fires its OWN gated probe; the report supplies the host:port (and the class) and nothing else.

  * request_smuggling (CWE-444) — ``live.smuggling_redrive`` / ``smuggling_desync_oracle``, admitted to the
    FACT-capable ``request_smuggling.differential_desync`` branch. VIGIL's unique per-probe canary must be
    echoed in ITS OWN second response on the framing-conflict connection AND absent from an identical
    well-formed control connection. The named false positives each get a real fixture and must stay LEADs:
    a timing/hang origin, a bare mangled-method status differential, and a SHARED-POOL desync whose leak
    lands on a co-tenant's connection rather than VIGIL's own second request.
  * service_reachable / weak_tls / weak_crypto_artifact — ``live.transport_redrive``, which re-authorises
    the reported host:port through the charter/scope gate and then performs VIGIL's OWN bounded
    ``capture_handshake`` / ``capture_tls_handshake``, admitting to the VIGIL-OWNED FACT-capable branches
    ``service_reachability.tcp_handshake`` / ``tls_weakness.tls_handshake`` /
    ``weak_crypto.cert_signature_algorithm``.

INVARIANT PINNED HERE: the PRODUCER branches ``strix.service_reachability`` / ``strix.tls_negotiation`` stay
``fact_capable: false``. VIGIL mints on its OWN branches over its OWN capture — never on a Strix say-so. A
non-tcp (udp) row and an out-of-scope host are both refused with NO SOCKET ATTEMPTED (asserted by counting
connector calls, not by inspecting a reason string).
"""

from __future__ import annotations

import contextlib
import datetime
import json
import re
import socket
import socketserver
import ssl
import sys
import threading
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
for _p in (str(_ROOT / "engine" / "crucible"), str(_ROOT / "integration"),
           str(_ROOT / "packages" / "core" / "vigil_core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
pytest.importorskip("vigil_gateway", reason="the gateway package is not on the path here")


# ---- gate isolation + charter (mirrors test_strix_http_redrive / test_smuggling_redrive) --------------
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
        f"Signed: `tester`     Date: `2026-09-26`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n"
        f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def _signers_and_trust():
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return signers, tr


def _mint(tmp_path: Path, signers, slug: str = "alpha"):
    """The proof-sink mint callback — the SAME rail Strix's reporting path drives."""
    from vigil_integration.proof.run import build_report_mint
    return build_report_mint(run_dir=tmp_path, signers=signers, engagement_slug=slug)


def _branch(branch_id: str) -> dict:
    raw = json.loads((_ROOT / "docs" / "capability-matrix" / "evidence-branches.json")
                     .read_text(encoding="utf-8"))
    for b in raw["branches"]:
        if b["id"] == branch_id:
            return b
    raise AssertionError(f"branch {branch_id!r} is not in the registry")


# =======================================================================================================
# The rail wiring: the two arms exist, the sink screens them in, and the PRODUCER branches stay LEAD-only.
# =======================================================================================================

def test_the_two_new_arms_are_on_the_rail_and_the_sink_screens_them_in():
    from vigil_integration.proof import run, sink

    classifiers = {c for c, _d, _n in run._REDRIVE_ARMS}
    assert run._smuggling_redrive_class in classifiers
    assert run._transport_redrive_class in classifiers
    # every arm is requires_no_capture except the web arm (a transport re-drive needs no attached capture —
    # it crafts its own handshake), and a capture-bearing report still takes the executor-capture path.
    for classify, _drive, requires_no_capture in run._REDRIVE_ARMS:
        if classify in (run._smuggling_redrive_class, run._transport_redrive_class):
            assert requires_no_capture is True

    assert sink._smuggling_redrivable({"bug_class": "request_smuggling"}) is True
    assert sink._smuggling_redrivable({"cwe": "CWE-444"}) is True
    assert sink._transport_redrivable({"bug_class": "service_reachable"}) is True
    assert sink._transport_redrivable({"bug_class": "tls_negotiation"}) is True
    assert sink._transport_redrivable({"bug_class": "weak_crypto_artifact"}) is True
    assert sink._transport_redrivable({"bug_class": "xss"}) is False


def test_the_strix_producer_branches_stay_lead_only():
    """S2 mints on the VIGIL-OWNED branches over VIGIL's OWN capture. The Strix producer branches describe a
    report VIGIL did not re-drive and must NEVER become FACT-capable — flipping them would let a producer's
    narrative mint."""
    for producer in ("strix.service_reachability", "strix.tls_negotiation"):
        b = _branch(producer)
        assert b["fact_capable"] is False, f"{producer} must stay LEAD-only"
        assert b["clean_capable"] is False, f"{producer} must never clear on the producer's say-so"
    # ... while the VIGIL-owned twins this slice routes INTO are the FACT-capable ones.
    for owned in ("service_reachability.tcp_handshake", "tls_weakness.tls_handshake",
                  "weak_crypto.cert_signature_algorithm", "request_smuggling.differential_desync"):
        assert _branch(owned)["fact_capable"] is True


def test_the_classifier_maps_only_its_own_classes():
    from vigil_integration.proof import run
    assert run._transport_redrive_class({"bug_class": "open_port"}) == "service_reachable"
    assert run._transport_redrive_class({"bug_class": "weak_tls"}) == "weak_tls"
    assert run._transport_redrive_class({"cwe": "CWE-328"}) == "weak_crypto_artifact"
    assert run._transport_redrive_class({"bug_class": "request_smuggling"}) is None
    assert run._smuggling_redrive_class({"bug_class": "http_request_smuggling"}) == "request_smuggling"
    assert run._smuggling_redrive_class({"bug_class": "weak_tls"}) is None
    assert run._smuggling_redrive_class({"cwe": "CWE-89"}) is None


# =======================================================================================================
# transport intake — service_reachable (VIGIL's OWN bounded TCP handshake)
# =======================================================================================================

@contextlib.contextmanager
def _open_tcp_port():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    try:
        yield srv.getsockname()[1]
    finally:
        srv.close()


def _closed_tcp_port() -> int:
    """A port that was bound and then RELEASED — nothing listens on it, so a connect is actively refused."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _count_tcp_connects(monkeypatch: pytest.MonkeyPatch) -> list:
    """Replace the reachability capture's CONNECTOR with a recorder, so "refused before any traffic" is
    proven by an EMPTY call list rather than by reading a reason string."""
    from framework.v2.verify import reachability
    calls: list = []

    def _recording(host, port, timeout, read_banner):
        calls.append((host, port))
        raise OSError("the test connector must not be reached")

    monkeypatch.setattr(reachability, "_socket_connect", _recording)
    return calls


def _count_tls_connects(monkeypatch: pytest.MonkeyPatch) -> list:
    from framework.v2.verify import tls as tls_mod
    calls: list = []

    def _recording(host, port, timeout):
        calls.append((host, port))
        raise OSError("the test connector must not be reached")

    monkeypatch.setattr(tls_mod, "_tls_connect", _recording)
    return calls


def test_an_open_port_mints_a_reachability_fact_that_reverifies_offline(monkeypatch, tmp_path):
    """A Strix "this port is open" report drives VIGIL's OWN gated TCP handshake; the signed FACT is minted
    on the VIGIL-owned ``service_reachability.tcp_handshake`` branch and re-verifies OFFLINE."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, tr = _signers_and_trust()
    with _open_tcp_port() as port:
        mr = _mint(tmp_path, signers)({"id": "svc-1", "bug_class": "service_reachable",
                                       "host": "127.0.0.1", "port": port, "protocol": "tcp"})
    assert mr is not None and mr.is_fact, f"expected a reachability FACT; got {mr}"
    res = mr.result
    assert res.n_facts == 1, res.admissions
    fact = res.facts[0]
    assert fact.signed is not None
    assert [a[0] for a in res.admissions] == ["service_reachability.tcp_handshake"]
    assert res.admissions[0][1] == "FACT"
    _assert_reverifies_and_rejects_tamper(fact, res.contexts[fact.finding_ref], tr, tmp_path)


def _assert_reverifies_and_rejects_tamper(fact, ctx, tr, tmp_path):
    """The signed certificate re-verifies OFFLINE over its retained JSON-safe context; a GROSS tamper of that
    context is rejected; and the persisted proofs/reverifiable.json re-fires through the offline CLI."""
    from framework.v2.evidence.certify import verify_certificate
    from framework.v2.verify import reverify

    assert verify_certificate(fact.signed, oracle_context=ctx, trust_root=tr).ok is True
    tampered = json.loads(json.dumps(ctx))
    _corrupt_context(tampered)
    assert verify_certificate(fact.signed, oracle_context=tampered, trust_root=tr).ok is False

    report_path = tmp_path / "proofs" / "reverifiable.json"
    assert report_path.is_file(), "a FACT must persist a re-verifiable report for the offline CLI"
    assert reverify.main([str(report_path)]) == 0, "the persisted FACT must re-verify offline"
    doc = json.loads(report_path.read_text(encoding="utf-8"))
    for f in doc["active_findings"]:
        _corrupt_context(f.get("oracle_context") or {})
    bad = tmp_path / "tampered.json"
    bad.write_text(json.dumps(doc), encoding="utf-8")
    assert reverify.main([str(bad)]) != 0, "a tampered context must not re-verify"


def _corrupt_context(oc: dict) -> None:
    """Strip the evidence of the fire out of a retained transport/smuggling context so the deterministic
    oracle can no longer re-fire over it."""
    hs = oc.get("handshake")
    if isinstance(hs, dict):                       # reachability: the connect never completed
        hs["connected"] = False
        hs["peer"] = ""
    tls = oc.get("tls")
    if isinstance(tls, dict):                      # weak TLS: a strong, modern negotiation
        tls["tls_version"] = "TLSv1.3"
        tls["cipher"] = "TLS_AES_256_GCM_SHA384"
        tls["connected"] = True
    art = oc.get("crypto_artifact")
    if isinstance(art, dict):                      # weak crypto: a modern signature + a full-size key
        art["signature_algorithm"] = "sha256WithRSAEncryption"
        art["oid"] = "1.2.840.113549.1.1.11"
        art["key_bits"] = 4096
    sd = oc.get("smuggling_desync")
    if isinstance(sd, dict) and isinstance(sd.get("conflict"), dict):
        sd["conflict"] = {**sd["conflict"], "body": "HTTP/1.1 200 OK\r\n\r\nno canary here"}


def test_a_closed_port_mints_nothing(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _tr = _signers_and_trust()
    mr = _mint(tmp_path, signers)({"id": "svc-closed", "bug_class": "service_reachable",
                                   "host": "127.0.0.1", "port": _closed_tcp_port()})
    assert mr is None or not mr.is_fact, "a closed port must never mint a reachability FACT"
    assert mr is not None and mr.result.n_facts == 0
    assert not mr.result.refused, "a genuinely refused connect is an OBSERVATION, not a gate refusal"


def test_a_non_tcp_row_mints_nothing_and_attempts_no_socket(monkeypatch, tmp_path):
    """UDP soundness (a prior wave's invariant): the bounded TCP connect cannot prove udp reachability, so a
    udp-open row must be refused BEFORE any socket — never a TCP handshake relabelled as udp."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _tr = _signers_and_trust()
    calls = _count_tcp_connects(monkeypatch)
    with _open_tcp_port() as port:
        mr = _mint(tmp_path, signers)({"id": "svc-udp", "bug_class": "service_reachable",
                                       "host": "127.0.0.1", "port": port, "protocol": "udp"})
    assert mr is not None and not mr.is_fact and mr.result.n_facts == 0
    assert mr.result.refused is True
    assert calls == [], "a non-tcp row must not reach the connector at all"


def test_an_out_of_scope_host_is_refused_before_any_traffic(monkeypatch, tmp_path):
    """The charter/scope gate re-authorises the reported host BEFORE the capture: an out-of-scope host never
    reaches a socket, and (critically) is never reported as a clean negative either."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")          # the charter authorises 127.0.0.1 ONLY
    signers, _tr = _signers_and_trust()
    calls = _count_tcp_connects(monkeypatch)
    mr = _mint(tmp_path, signers)({"id": "svc-oos", "bug_class": "service_reachable",
                                   "host": "127.0.0.2", "port": 9})
    assert mr is not None and not mr.is_fact and mr.result.n_facts == 0
    assert mr.result.refused is True
    assert calls == [], "an out-of-scope host must be refused BEFORE any connect"
    assert not mr.result.leads, "a refusal is not an observation — it may not produce a clean/lead verdict"


def test_an_out_of_scope_tls_host_is_refused_before_any_handshake(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _tr = _signers_and_trust()
    calls = _count_tls_connects(monkeypatch)
    mr = _mint(tmp_path, signers)({"id": "tls-oos", "bug_class": "weak_tls",
                                   "endpoint": "https://127.0.0.2:8443/"})
    assert mr is not None and not mr.is_fact and mr.result.refused is True
    assert calls == [], "an out-of-scope TLS host must be refused BEFORE any handshake"


def test_a_tripped_kill_switch_refuses_the_reachability_redrive(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    (tmp_path / "alpha.halt").write_text("stop", encoding="utf-8")
    signers, _tr = _signers_and_trust()
    calls = _count_tcp_connects(monkeypatch)
    with _open_tcp_port() as port:
        mr = _mint(tmp_path, signers)({"id": "svc-halt", "bug_class": "service_reachable",
                                       "host": "127.0.0.1", "port": port})
    assert mr is not None and not mr.is_fact and mr.result.refused is True
    assert calls == []


# =======================================================================================================
# transport intake — weak_tls / weak_crypto_artifact (ONE VIGIL-owned TLS negotiation, two branches)
# =======================================================================================================

def _make_cert(path: Path, *, bits: int) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(key, hashes.SHA256()))
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM)
                     + key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.TraditionalOpenSSL,
                                         serialization.NoEncryption()))
    return str(path)


@contextlib.contextmanager
def _tls_endpoint(certfile: str, *, version=None):
    """A REAL loopback TLS endpoint. ``version`` pins the server to exactly one protocol (used to plant the
    deprecated-protocol weakness); the default serves whatever a modern client prefers."""
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if version is not None:
        sctx.minimum_version = version
        sctx.maximum_version = version
    sctx.load_cert_chain(certfile)

    class _H(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            try:
                with sctx.wrap_socket(self.request, server_side=True) as s:
                    s.settimeout(2.0)
                    with contextlib.suppress(OSError, ssl.SSLError):
                        s.recv(16)
            except (OSError, ssl.SSLError):
                pass

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _H)
    srv.daemon_threads = True
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


def _tls_negotiable(port: int) -> bool:
    """Can a STANDARD client (the one ``capture_tls_handshake`` uses) reach this endpoint at all? Some
    OpenSSL builds forbid the deprecated protocol outright — then the weakness is not constructible here."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as raw, \
                ctx.wrap_socket(raw, server_hostname="127.0.0.1"):
            return True
    except (OSError, ssl.SSLError):
        return False


def test_a_deprecated_tls_protocol_mints_a_tls_weakness_fact(monkeypatch, tmp_path):
    """A REAL TLS 1.0 loopback endpoint: VIGIL negotiates it ITSELF and the deterministic tls_weakness oracle
    fires over VIGIL's OWN retained negotiation, minting on ``tls_weakness.tls_handshake``."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, tr = _signers_and_trust()
    cert = _make_cert(tmp_path / "strong-key.pem", bits=2048)
    with _tls_endpoint(cert, version=ssl.TLSVersion.TLSv1) as port:
        if not _tls_negotiable(port):
            pytest.skip("this OpenSSL refuses TLSv1.0 outright — the weakness is not constructible here")
        mr = _mint(tmp_path, signers)({"id": "tls-weak", "bug_class": "weak_tls",
                                       "endpoint": f"https://127.0.0.1:{port}/"})
    assert mr is not None and mr.is_fact, f"expected a TLS_WEAKNESS FACT; got {mr}"
    res = mr.result
    assert res.n_facts == 1, res.admissions
    fact = res.facts[0]
    assert "tls_weakness.tls_handshake" in {a[0] for a in res.admissions if a[1] == "FACT"}
    # the SAME single handshake was also judged for a broken-hash / undersized-key certificate, and that
    # branch did NOT fire over this strong 2048-bit SHA-256 leaf.
    assert {a[0] for a in res.admissions} == {"tls_weakness.tls_handshake",
                                              "weak_crypto.cert_signature_algorithm"}
    assert [a[1] for a in res.admissions if a[0] == "weak_crypto.cert_signature_algorithm"] == ["INCONCLUSIVE"]
    _assert_reverifies_and_rejects_tamper(fact, res.contexts[fact.finding_ref], tr, tmp_path)


def test_an_undersized_certificate_key_mints_a_weak_crypto_fact(monkeypatch, tmp_path):
    """A REAL modern-protocol endpoint presenting a 1024-bit RSA leaf: VIGIL retrieves the certificate in its
    OWN handshake and the weak_crypto_artifact oracle fires on ``weak_crypto.cert_signature_algorithm``."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, tr = _signers_and_trust()
    cert = _make_cert(tmp_path / "short-key.pem", bits=1024)
    with _tls_endpoint(cert) as port:
        mr = _mint(tmp_path, signers)({"id": "tls-shortkey", "bug_class": "weak_crypto_artifact",
                                       "endpoint": f"https://127.0.0.1:{port}/"})
    assert mr is not None and mr.is_fact, f"expected a weak-crypto FACT; got {mr}"
    res = mr.result
    assert res.n_facts == 1, res.admissions
    fact = res.facts[0]
    firing = {a[0] for a in res.admissions if a[1] == "FACT"}
    assert firing == {"weak_crypto.cert_signature_algorithm"}, res.admissions
    _assert_reverifies_and_rejects_tamper(fact, res.contexts[fact.finding_ref], tr, tmp_path)


def test_a_strong_tls_endpoint_mints_nothing(monkeypatch, tmp_path):
    """The benign twin: a modern protocol with a full-size SHA-256 leaf. Neither TLS branch may fire, and
    the weak-crypto branch (clean_capable: false) may not report CLEAN either."""
    from vigil_integration.live.verdict import Verdict
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _tr = _signers_and_trust()
    cert = _make_cert(tmp_path / "modern.pem", bits=2048)
    with _tls_endpoint(cert) as port:
        mr = _mint(tmp_path, signers)({"id": "tls-strong", "bug_class": "weak_tls",
                                       "endpoint": f"https://127.0.0.1:{port}/"})
    assert mr is not None and not mr.is_fact and mr.result.n_facts == 0, mr.result.admissions
    verdicts = {a[0]: a[1] for a in mr.result.admissions}
    assert verdicts.get("weak_crypto.cert_signature_algorithm") == Verdict.INCONCLUSIVE.value
    assert verdicts.get("tls_weakness.tls_handshake") in (Verdict.CLEAN.value, Verdict.INCONCLUSIVE.value)


def test_a_dead_tls_port_mints_nothing(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _tr = _signers_and_trust()
    mr = _mint(tmp_path, signers)({"id": "tls-dead", "bug_class": "weak_tls",
                                   "endpoint": f"https://127.0.0.1:{_closed_tcp_port()}/"})
    assert mr is not None and not mr.is_fact and mr.result.n_facts == 0
    assert not mr.result.admissions, "no handshake ⇒ nothing judgeable ⇒ no admission at all"


# =======================================================================================================
# request smuggling — the rail arm over the planted desync fixture, and the named FALSE POSITIVES
# =======================================================================================================

def test_the_smuggling_arm_mints_a_fact_against_the_planted_desync(monkeypatch, tmp_path):
    """The Strix report says only "request smuggling, here". VIGIL drives its OWN gated raw-socket canary
    differential and mints only because ITS OWN second response on the conflict connection echoed the canary
    while the well-formed control's did not."""
    from framework.v2.eval.benchmark_app import serve_smuggling_desync
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, tr = _signers_and_trust()
    with serve_smuggling_desync() as url:
        mr = _mint(tmp_path, signers)({"id": "smug-1", "bug_class": "request_smuggling", "endpoint": url})
    assert mr is not None and mr.is_fact, f"expected a desync FACT; got {mr}"
    res = mr.result
    assert res.n_facts == 1, res.admissions
    fact = res.facts[0]
    _assert_reverifies_and_rejects_tamper(fact, res.contexts[fact.finding_ref], tr, tmp_path)


def test_the_smuggling_arm_is_reached_by_a_bare_cwe_444_report(monkeypatch, tmp_path):
    from framework.v2.eval.benchmark_app import serve_smuggling_desync
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _tr = _signers_and_trust()
    with serve_smuggling_desync() as url:
        mr = _mint(tmp_path, signers)({"id": "smug-cwe", "cwe": "CWE-444", "endpoint": url})
    assert mr is not None and mr.is_fact


def test_the_smuggling_arm_never_flags_the_benign_or_reflecting_twin(monkeypatch, tmp_path):
    """The two shipped safe twins, driven through the RAIL: a back-end that rejects the ambiguous framing,
    and one that additionally ECHOES the request (canary and all) into its 400 page. Neither leaks the canary
    into VIGIL's GENUINE second response, so neither may mint."""
    from framework.v2.eval.benchmark_app import serve_smuggling_benign, serve_smuggling_reflect_error
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _tr = _signers_and_trust()
    for name, server in (("benign", serve_smuggling_benign), ("reflect_error", serve_smuggling_reflect_error)):
        with server() as url:
            mr = _mint(tmp_path, signers)({"id": f"smug-{name}", "bug_class": "request_smuggling",
                                           "endpoint": url})
        assert mr is None or not mr.is_fact, f"the {name} twin was flagged"
        if mr is not None:
            assert mr.result.n_facts == 0 and not mr.result.facts


# ---- the named false positives, each with a REAL fixture ----------------------------------------------

_CANARY_RE = re.compile(rb"vgsmug[0-9a-f]{20,}")


def _http(status: str, body: bytes, *, close: bool = False) -> bytes:
    return (f"HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
            f"Connection: {'close' if close else 'keep-alive'}\r\n\r\n").encode("latin-1") + body


class _FpHandler(socketserver.BaseRequestHandler):
    """A minimal raw-HTTP origin used to plant ONE named false positive per ``mode``.

    ``hang``         — accepts the connection and NEVER answers (the retired TIMING signal: a normal origin
                       awaiting an incomplete declared body stalls identically). No response ⇒ no channel.
    ``mangled``      — answers the ambiguous framing with a BARE 405 status differential and a normal,
                       canary-free follow-up response. A status-only differential is not a desync.
    ``shared_pool``  — a SHARED-POOL desync: the smuggled prefix poisons the NEXT connection (a co-tenant),
                       never this connection's own second request. VIGIL's conflict-leg second response is
                       clean and the leak lands on the control connection, so the differential cannot hold —
                       and this is the strongest form of the FP: an unsound implementation that looked for
                       the canary "anywhere in the pair" would mint here.
    """

    mode = "mangled"
    pool: list = []          # class-level: the canary a previous connection left for a co-tenant

    def _read_head(self, buf: bytearray):
        while b"\r\n\r\n" not in buf:
            try:
                chunk = self.request.recv(4096)
            except OSError:
                return None
            if not chunk:
                return None
            buf.extend(chunk)
            if len(buf) > 65536:
                return None
        head, rest = bytes(buf).split(b"\r\n\r\n", 1)
        buf.clear()
        buf.extend(rest)
        return head

    def _drain(self, buf: bytearray) -> bytes:
        """Consume the remainder of the current request. VIGIL blocks on the first response before sending
        its follow-up, so a short idle read consumes exactly this request's body and leaves nothing."""
        self.request.settimeout(0.3)
        drained = bytes(buf)
        buf.clear()
        try:
            while len(drained) < 65536:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                drained += chunk
        except OSError:
            pass
        self.request.settimeout(3.0)
        return drained

    def handle(self) -> None:  # noqa: C901 — a flat fixture state machine reads better whole
        mode = type(self).mode
        poisoned = type(self).pool.pop(0) if type(self).pool else None
        self.request.settimeout(3.0)
        buf = bytearray()
        try:
            head = self._read_head(buf)
            if head is None:
                return
            body = self._drain(buf)
            conflict = (b"transfer-encoding" in head.lower()) and (b"content-length" in head.lower())
            canary_m = _CANARY_RE.search(head + body)
            canary = canary_m.group(0) if canary_m else None

            if mode == "hang":
                time.sleep(2.5)          # never answer: the timing/hang signal, which is NOT proof
                return
            if mode == "shared_pool" and conflict and canary:
                type(self).pool.append(canary)   # leaks to the NEXT connection, not to this one
            if mode == "mangled" and conflict:
                self.request.sendall(_http("405 Method Not Allowed", b"ambiguous framing"))
            else:
                self.request.sendall(_http("200 OK", b"vigil-start accepted"))

            head2 = self._read_head(buf)
            if head2 is None:
                return
            self._drain(buf)
            if mode == "shared_pool" and poisoned is not None:
                self.request.sendall(_http("200 OK", b"reflected c=" + poisoned, close=True))
            else:
                self.request.sendall(_http("200 OK", b"vigil-follow ok", close=True))
        except OSError:
            pass


@contextlib.contextmanager
def _fp_origin(mode: str):
    handler = type("_H", (_FpHandler,), {"mode": mode, "pool": []})
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/"
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("mode", ["hang", "mangled", "shared_pool"])
def test_the_named_smuggling_false_positives_stay_leads(monkeypatch, tmp_path, mode):
    """Each named FP gets a REAL origin and must mint NOTHING: a timing/hang stall, a bare mangled-method
    status differential, and a shared-pool desync whose leak needs a co-tenant victim to observe."""
    from vigil_integration.live.smuggling_redrive import smuggling_redrive
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _tr = _signers_and_trust()
    with _fp_origin(mode) as url:
        res = smuggling_redrive(url, slug="alpha", engagement_slug="alpha", signers=signers, timeout=1.5)
    assert res.n_facts == 0, f"the {mode} origin was flagged as a desync FACT: {res.admissions}"
    assert not res.facts
    assert not any(v == "FACT" for _b, v, _r in res.admissions), res.admissions


def test_the_shared_pool_leak_really_reaches_the_control_leg(monkeypatch, tmp_path):
    """Soundness of the shared_pool fixture itself: it MUST actually leak the canary (otherwise the FP test
    above would pass vacuously) — just onto the CO-TENANT connection, which is exactly why VIGIL may not
    attribute it. The oracle sees a canary in the control leg's second response and refuses."""
    from vigil_integration.live.smuggling_redrive import smuggling_redrive
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _tr = _signers_and_trust()
    with _fp_origin("shared_pool") as url:
        res = smuggling_redrive(url, slug="alpha", engagement_slug="alpha", signers=signers, timeout=1.5)
    leaked = any("reflected c=vgsmug" in json.dumps(ctx) for ctx in res.contexts.values())
    assert leaked, "the shared-pool fixture never leaked a canary — the FP test would be vacuous"
    assert res.n_facts == 0


def test_the_smuggling_arm_is_refused_without_a_signed_charter(monkeypatch, tmp_path):
    """No charter ⇒ the raw-socket burst is refused and no byte leaves the box (the rail inherits the gate)."""
    from framework.v2.eval.benchmark_app import serve_smuggling_desync
    _grant_active_recon(monkeypatch)                   # entitlement granted, but NO charter written
    signers, _tr = _signers_and_trust()
    with serve_smuggling_desync() as url:
        mr = _mint(tmp_path, signers)({"id": "smug-nocharter", "bug_class": "request_smuggling",
                                       "endpoint": url})
    assert mr is not None and not mr.is_fact
    assert mr.result.refused is True and mr.result.n_facts == 0
