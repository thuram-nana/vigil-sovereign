"""SLICE S2 — "transport intake": two more re-drive arms on the Strix proof-sink rail whose evidence is a
TRANSPORT handshake rather than an HTTP response body. A Strix LEAD becomes an oracle-confirmed FACT only
because VIGIL re-fires its OWN gated probe; the report supplies the host:port (and the class) and nothing else.

  * request_smuggling (CWE-444) — ``live.smuggling_redrive`` / ``smuggling_desync_oracle`` over the
    ``request_smuggling.differential_desync`` branch, which #863 soundly DEMOTED to ``fact_capable: false``:
    a single-connection canary differential is ONE parser, not two disagreeing across a trust boundary. The
    branch declares the precondition ``second_parser_observation_on_an_unpipelined_connection``, which a
    single-connection capture can never satisfy, so admission returns INCONCLUSIVE and the finding STAYS A
    LEAD — the re-drive still RUNS end-to-end (VIGIL's unique per-probe canary echoed in ITS OWN second
    response on the framing-conflict connection AND absent from an identical well-formed control connection)
    and retains its differential, but it NEVER mints a CWE-444 FACT and is never re-armed to one. The named
    false positives each get a real fixture and must stay non-firing: a timing/hang origin, a bare
    mangled-method status differential, and a SHARED-POOL desync whose leak lands on a co-tenant's connection
    rather than VIGIL's own second request.
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
from urllib.parse import urlsplit
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
    narrative mint. The GUARD must also hold for request_smuggling.differential_desync: #863 soundly demoted
    it to fact_capable:false (a single-connection differential is ONE parser, not two), so the smuggling arm
    stays a LEAD and must never be re-armed to a FACT."""
    for producer in ("strix.service_reachability", "strix.tls_negotiation"):
        b = _branch(producer)
        assert b["fact_capable"] is False, f"{producer} must stay LEAD-only"
        assert b["clean_capable"] is False, f"{producer} must never clear on the producer's say-so"
    # request_smuggling.differential_desync is LEAD-only and STAYS retired (#863) — never re-armed here.
    smug = _branch("request_smuggling.differential_desync")
    assert smug["fact_capable"] is False, "request_smuggling.differential_desync must stay LEAD-only (#863)"
    assert smug["clean_capable"] is False, "request_smuggling.differential_desync may never assert absence"
    # ... while the VIGIL-owned TRANSPORT twins this slice routes INTO are the FACT-capable ones.
    for owned in ("service_reachability.tcp_handshake", "tls_weakness.tls_handshake",
                  "weak_crypto.cert_signature_algorithm"):
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


def _cert_der(certfile: str) -> bytes:
    """The leaf DER of a PEM bundle written by :func:`_make_cert` — the same bytes a real peer presents."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    pem = Path(certfile).read_bytes()
    return x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)


def _force_negotiation(monkeypatch: pytest.MonkeyPatch, *, version: str, cipher: str, bits: int,
                       certfile: str) -> None:
    """Make the PINNED TLS connector return a specific negotiation, so the positive coverage below is
    UNCONDITIONAL.

    Why this exists: both weak-TLS positives used to sit behind ``pytest.skip`` gated on whether the HOST's
    OpenSSL would still negotiate the weakness. On this machine it does (0 skips), but a stricter CI
    OpenSSL would SILENTLY delete the only positive coverage for ``weak_tls`` and ``weak_crypto_artifact``
    and the suite would still go green. The substituted value is ONLY the four bytes-on-the-wire facts a
    handshake yields; every layer that decides anything — the gate chain, the never-liftable egress floor,
    the connect-pin, ``capture_tls_handshake``, the context builders, the deterministic oracle, ``admit``,
    the signing and the offline re-verification — is the real one, unchanged."""
    from vigil_integration.live import egress_floor

    der = _cert_der(certfile)

    def _synthetic(address, host, port, timeout):
        return version, cipher, bits, der

    monkeypatch.setattr(egress_floor, "_tls_socket_connect", _synthetic)


def test_a_deprecated_tls_protocol_mints_a_tls_weakness_fact(monkeypatch, tmp_path):
    """A REAL TLS 1.0 loopback endpoint: VIGIL negotiates it ITSELF and the deterministic tls_weakness oracle
    fires over VIGIL's OWN retained negotiation, minting on ``tls_weakness.tls_handshake``."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, tr = _signers_and_trust()
    cert = _make_cert(tmp_path / "strong-key.pem", bits=2048)
    with _tls_endpoint(cert, version=ssl.TLSVersion.TLSv1) as port:
        if not _tls_negotiable(port):
            # A stricter OpenSSL cannot SPEAK TLS 1.0, so the endpoint cannot be planted for real. The
            # coverage stays UNCONDITIONAL: the same admission path is driven with the negotiation itself
            # substituted (see _force_negotiation) rather than skipped away.
            _force_negotiation(monkeypatch, version="TLSv1", cipher="AES128-SHA", bits=128, certfile=cert)
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
        if not _tls_negotiable(port):
            # As above: a build that refuses a 1024-bit leaf outright cannot host the weakness, so the
            # negotiation is substituted and the rest of the admission path runs for real.
            _force_negotiation(monkeypatch, version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", bits=256,
                               certfile=cert)
        mr = _mint(tmp_path, signers)({"id": "tls-shortkey", "bug_class": "weak_crypto_artifact",
                                       "endpoint": f"https://127.0.0.1:{port}/"})
    assert mr is not None and mr.is_fact, f"expected a weak-crypto FACT; got {mr}"
    res = mr.result
    assert res.n_facts == 1, res.admissions
    fact = res.facts[0]
    firing = {a[0] for a in res.admissions if a[1] == "FACT"}
    assert firing == {"weak_crypto.cert_signature_algorithm"}, res.admissions
    _assert_reverifies_and_rejects_tamper(fact, res.contexts[fact.finding_ref], tr, tmp_path)


def test_the_two_weak_tls_positives_have_openssl_independent_coverage(monkeypatch, tmp_path):
    """FINDING-7's standing guarantee. The two positives above prefer a REAL planted weak endpoint, but a
    stricter OpenSSL cannot host one; this control drives the SAME admission path with the negotiation
    substituted, so ``weak_tls`` and ``weak_crypto_artifact`` keep a positive control on EVERY build. It
    also exercises the substitution helper itself, which on a permissive host the two tests above never
    reach. Only the four handshake facts are synthetic; the gate chain, the egress floor, the pin, the
    oracle, admission, signing and the OFFLINE re-verification are all the real ones."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, tr = _signers_and_trust()

    weak_proto_cert = _make_cert(tmp_path / "uncond-strong-key.pem", bits=2048)
    with _tls_endpoint(weak_proto_cert) as port:
        _force_negotiation(monkeypatch, version="TLSv1", cipher="AES128-SHA", bits=128,
                           certfile=weak_proto_cert)
        mr = _mint(tmp_path, signers)({"id": "uncond-tls-weak", "bug_class": "weak_tls",
                                       "endpoint": f"https://127.0.0.1:{port}/"})
    assert mr is not None and mr.is_fact, mr
    res = mr.result
    assert {a[0] for a in res.admissions if a[1] == "FACT"} == {"tls_weakness.tls_handshake"}, res.admissions
    fact = res.facts[0]
    _assert_reverifies_and_rejects_tamper(fact, res.contexts[fact.finding_ref], tr, tmp_path)


def test_the_weak_crypto_positive_has_openssl_independent_coverage(monkeypatch, tmp_path):
    """The twin of the above for the leaf-certificate branch: a modern protocol carrying an undersized
    1024-bit leaf, admitted on ``weak_crypto.cert_signature_algorithm`` on any OpenSSL."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, tr = _signers_and_trust()

    short_cert = _make_cert(tmp_path / "uncond-short-key.pem", bits=1024)
    strong_cert = _make_cert(tmp_path / "uncond-host.pem", bits=2048)
    with _tls_endpoint(strong_cert) as port:
        _force_negotiation(monkeypatch, version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", bits=256,
                           certfile=short_cert)
        mr = _mint(tmp_path, signers)({"id": "uncond-tls-shortkey", "bug_class": "weak_crypto_artifact",
                                       "endpoint": f"https://127.0.0.1:{port}/"})
    assert mr is not None and mr.is_fact, mr
    res = mr.result
    assert {a[0] for a in res.admissions if a[1] == "FACT"} == {"weak_crypto.cert_signature_algorithm"}, \
        res.admissions
    fact = res.facts[0]
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
    # PINNED to the MEASURED verdict, not to a disjunction. ``tls_weakness.tls_handshake`` is registered
    # clean_capable, but the oracle's no-weakness return is built WITHOUT conclusive=True, so probe_verdict
    # can never say "clean" and admit() can only reach INCONCLUSIVE (see that branch's blocking_work). The
    # old ``in (CLEAN, INCONCLUSIVE)`` could not fail either way — it would have waved through a newly
    # emitted FALSE clean exactly as readily as the honest INCONCLUSIVE. When the conclusive-negative work
    # lands, THIS is the assertion that must be deliberately updated.
    assert verdicts.get("tls_weakness.tls_handshake") == Verdict.INCONCLUSIVE.value, mr.result.admissions


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

def test_the_smuggling_arm_stays_a_lead_against_the_planted_desync(monkeypatch, tmp_path):
    """The Strix report says only "request smuggling, here". VIGIL drives its OWN gated raw-socket canary
    differential end-to-end against the planted fixture — ITS OWN second response on the conflict connection
    echoes the canary and the well-formed control's does not, so the oracle fires over the retained bytes.
    But request_smuggling.differential_desync is fact_capable:false and declares the precondition
    ``second_parser_observation_on_an_unpipelined_connection``, which a single-connection capture can NEVER
    satisfy (a genuine CWE-444 desync needs a SECOND parser on a connection VIGIL did not pipeline the prefix
    onto — #863). So admission returns INCONCLUSIVE and the finding STAYS A LEAD: no CWE-444 FACT is minted,
    and the arm is never re-armed to one. This asserts the arm is REACHED, DRIVES the re-drive, and retains
    its differential — it must not silently become a no-op."""
    from framework.v2.eval.benchmark_app import serve_smuggling_desync
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _tr = _signers_and_trust()
    with serve_smuggling_desync() as url:
        mr = _mint(tmp_path, signers)({"id": "smug-1", "bug_class": "request_smuggling", "endpoint": url})
    # the arm was REACHED and returned a result (not None), but it is NEVER a FACT — it stays a LEAD.
    assert mr is not None and mr.is_fact is False, f"the smuggling arm must stay a LEAD, never a FACT; got {mr}"
    res = mr.result
    assert res.n_facts == 0 and not res.facts, res.admissions
    # the re-drive actually RAN and was adjudicated (not a no-op): admissions exist, all INCONCLUSIVE, each
    # naming the second-parser precondition the single-connection differential can never satisfy.
    assert res.admissions, "the re-drive must have run and been adjudicated"
    assert all(v == "INCONCLUSIVE" for _b, v, _r in res.admissions), res.admissions
    assert all("second_parser_observation_on_an_unpipelined_connection" in r
               for _b, _v, r in res.admissions), res.admissions
    # the retained differential IS carried on the finding for the operator: canary + both legs per technique.
    assert res.contexts, "the differential must be retained on the finding"
    for ctx in res.contexts.values():
        sd = ctx.get("smuggling_desync") or {}
        assert sd.get("canary") and sd.get("technique") and "conflict" in sd and "control" in sd, sd


def test_the_smuggling_arm_is_reached_by_a_bare_cwe_444_report(monkeypatch, tmp_path):
    """A bare CWE-444 report (no bug_class token) still REACHES the arm and DRIVES the gated re-drive; the
    outcome stays a LEAD (INCONCLUSIVE admission over the fact_capable:false branch), never a FACT."""
    from framework.v2.eval.benchmark_app import serve_smuggling_desync
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _tr = _signers_and_trust()
    with serve_smuggling_desync() as url:
        mr = _mint(tmp_path, signers)({"id": "smug-cwe", "cwe": "CWE-444", "endpoint": url})
    assert mr is not None and mr.is_fact is False
    assert mr.result.n_facts == 0
    assert mr.result.admissions, "the bare CWE-444 report must reach the arm and drive the re-drive"
    assert all(v == "INCONCLUSIVE" for _b, v, _r in mr.result.admissions), mr.result.admissions


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


# =======================================================================================================
# THE NEVER-LIFTABLE EGRESS FLOOR (live/egress_floor.py) — the BLOCK-1 / BLOCK-1b controls.
#
# Both re-drive arms used to compose only string-matching gates (agents.scope_gate.validate_action +
# verify.reachability._authorize, which bottom out in ethics.host_matches_scope). Nothing resolved at gate
# time, so an in-scope NAME that resolved to 169.254.169.254 CONNECTED AND MINTED A SIGNED FACT, and a
# charter that directly LISTED the literal connected too — the exact case the gateway denylist declares
# impossible ("denied even if an operator lists them"). One shared helper now closes it at every site.
#
# EVERY control below asserts POSITIVELY that the floor RAN and REFUSED (the (address, denied, reason) row
# it records), never merely that nothing came back. Deleting the guard turns each of these red.
# =======================================================================================================

_IMDS = "169.254.169.254"
_IMDS_V4MAPPED = "::ffff:169.254.169.254"
_RFC1918 = "10.11.12.13"


def _charter_hosts(tmp_path: Path, *hosts: str, slug: str = "alpha") -> None:
    """A signed charter whose scope table lists EVERY given host (``_charter`` handles only one)."""
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    rows = "".join(f"| `{h}` | Host | Yes |\n" for h in hosts)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `tester`     Date: `2026-09-26`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n{rows}\n"
        f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def _fake_dns(monkeypatch: pytest.MonkeyPatch, mapping: "dict[str, str]") -> None:
    """Make the named hosts resolve to the given addresses; everything else resolves for real."""
    real = socket.getaddrinfo

    def _gai(host, port, *a, **kw):
        addr = mapping.get(str(host))
        if addr is None:
            return real(host, port, *a, **kw)
        family = socket.AF_INET6 if ":" in addr else socket.AF_INET
        sockaddr = (addr, int(port or 0), 0, 0) if family is socket.AF_INET6 else (addr, int(port or 0))
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)]

    monkeypatch.setattr(socket, "getaddrinfo", _gai)


def _count_every_connector(monkeypatch: pytest.MonkeyPatch) -> list:
    """Record EVERY connector this slice can reach: the engine's TCP and TLS defaults AND the pinned
    connectors' own primitives, plus the raw ``socket.create_connection`` the smuggling burst uses. A
    control that asserts an EMPTY list is therefore asserting that no path opened a socket, not just that
    one particular path did not."""
    from framework.v2.verify import reachability
    from framework.v2.verify import tls as tls_mod

    from vigil_integration.live import egress_floor

    calls: list = []

    def _tcp(host, port, timeout, read_banner):
        calls.append((host, port))
        raise OSError("the test connector must not be reached")

    def _tls(host, port, timeout):
        calls.append((host, port))
        raise OSError("the test connector must not be reached")

    def _pinned_tls(address, host, port, timeout):
        calls.append((address, port))
        raise OSError("the test connector must not be reached")

    def _raw(address, timeout=None, *a, **kw):
        calls.append(tuple(address))
        raise OSError("the test connector must not be reached")

    monkeypatch.setattr(reachability, "_socket_connect", _tcp)
    monkeypatch.setattr(tls_mod, "_tls_connect", _tls)
    monkeypatch.setattr(egress_floor, "_tls_socket_connect", _pinned_tls)
    monkeypatch.setattr(socket, "create_connection", _raw)
    return calls


def _floor_refusals(res) -> list:
    """The (address, reason) pairs the floor DENIED on this result — the positive proof it ran."""
    return [(a, why) for a, denied, why in (getattr(res, "egress_checked", None) or []) if denied]


def _drive_transport(tmp_path, signers, host, *, port=80, cls="service_reachable"):
    from vigil_integration.live.transport_redrive import transport_redrive
    return transport_redrive("", claimed_class=cls, slug="alpha", engagement_slug="alpha",
                             signers=signers, host=host, port=port, protocol="tcp", timeout=1.0)


# ---- transport arm ------------------------------------------------------------------------------------

def test_an_in_scope_name_resolving_to_cloud_metadata_is_refused_with_no_connector_call(monkeypatch,
                                                                                        tmp_path):
    """BLOCK-1. ``imds.corp.example`` is squarely in the signed charter scope, so BOTH string gates pass.
    It resolves to the cloud instance-metadata address, which no charter may authorise."""
    _grant_active_recon(monkeypatch)
    _charter_hosts(tmp_path, "imds.corp.example")
    _fake_dns(monkeypatch, {"imds.corp.example": _IMDS})
    calls = _count_every_connector(monkeypatch)
    signers, _tr = _signers_and_trust()

    res = _drive_transport(tmp_path, signers, "imds.corp.example")

    assert calls == [], f"a metadata destination must attempt NO connection; got {calls}"
    assert res.n_facts == 0 and not res.admissions
    assert res.refused is True
    denied = _floor_refusals(res)
    assert denied and denied[0][0] == _IMDS, f"the floor must have adjudicated {_IMDS}; got {res.egress_checked}"
    assert "always-denied range" in denied[0][1]
    assert res.pinned_address == "", "a refused target must never be pinned"


def test_a_charter_that_directly_lists_a_tier1_floor_address_is_still_refused(monkeypatch, tmp_path):
    """The denylist's own contract: 'A charter can NOT re-enable these; they are denied even if an operator
    lists them.' A scope row naming the metadata address is far likelier an injection or a mistake than a
    real intent, so the string gates passing is exactly why the floor exists."""
    _grant_active_recon(monkeypatch)
    _charter_hosts(tmp_path, _IMDS)
    calls = _count_every_connector(monkeypatch)
    signers, _tr = _signers_and_trust()

    res = _drive_transport(tmp_path, signers, _IMDS)

    assert calls == [], f"a charter listing cannot lift the floor; got {calls}"
    assert res.refused is True and res.n_facts == 0
    denied = _floor_refusals(res)
    assert denied and denied[0][0] == _IMDS, res.egress_checked
    # and the lift set really did contain the listed address — the floor refused DESPITE being asked to allow it
    from vigil_integration.live.egress_floor import charter_allowed_ips
    assert _IMDS in charter_allowed_ips("alpha"), "the charter really did authorise this IP; the floor overrode it"


def test_an_ipv4_mapped_ipv6_spelling_of_the_metadata_address_is_refused(monkeypatch, tmp_path):
    """``::ffff:169.254.169.254`` is the same destination wearing a v6 costume. The denylist unwraps embedded
    IPv4; this proves the helper hands it the address in a form where that unwrap happens."""
    _grant_active_recon(monkeypatch)
    _charter_hosts(tmp_path, "v6imds.corp.example")
    _fake_dns(monkeypatch, {"v6imds.corp.example": _IMDS_V4MAPPED})
    calls = _count_every_connector(monkeypatch)
    signers, _tr = _signers_and_trust()

    res = _drive_transport(tmp_path, signers, "v6imds.corp.example")

    assert calls == [], f"an IPv4-mapped metadata address must attempt NO connection; got {calls}"
    assert res.refused is True and res.n_facts == 0
    denied = _floor_refusals(res)
    assert denied, res.egress_checked
    assert denied[0][0] == _IMDS_V4MAPPED
    assert _IMDS in denied[0][1], f"the unwrapped v4 address must be named in the refusal: {denied[0][1]}"


def test_a_wildcard_scoped_name_resolving_into_rfc1918_is_refused(monkeypatch, tmp_path):
    """The split-horizon / rebinding shape. ``*.corp.example`` is a legitimate wildcard scope, and
    ``app.corp.example`` matches it, so both string gates pass — but a wildcard names no host to resolve, so
    nothing in the charter authorises the private address it lands on. The target's OWN resolved IP is never
    self-added to the lift set (that is precisely what would let a wildcard scope reach 10.x)."""
    _grant_active_recon(monkeypatch)
    _charter_hosts(tmp_path, "*.corp.example")
    _fake_dns(monkeypatch, {"app.corp.example": _RFC1918})
    calls = _count_every_connector(monkeypatch)
    signers, _tr = _signers_and_trust()

    res = _drive_transport(tmp_path, signers, "app.corp.example")

    assert calls == [], f"an unauthorised private destination must attempt NO connection; got {calls}"
    assert res.refused is True and res.n_facts == 0
    denied = _floor_refusals(res)
    assert denied and denied[0][0] == _RFC1918, res.egress_checked
    assert "not in the charter-authorized allowlist" in denied[0][1]


def test_an_ip_literal_scoped_rfc1918_staging_host_still_works(monkeypatch, tmp_path):
    """The other half of the contract: over-correcting into a dead path is also a defect. A charter that
    WRITES the private address (alongside the name, which the string gates need) puts that address in the
    lift set, so the private tier lifts for it — while the metadata floor above stays unliftable.

    Writing the ADDRESS is what authorises it. The negative control immediately below is the same test
    with the IP-literal row removed, and it must REFUSE: an operator's signed attestation to a NAME is
    not an attestation to whatever a resolver says that name is, milliseconds before the target's own
    query, on the same resolver."""
    _grant_active_recon(monkeypatch)
    _charter_hosts(tmp_path, "staging.corp.example", _RFC1918)
    _fake_dns(monkeypatch, {"staging.corp.example": _RFC1918})
    calls = _count_every_connector(monkeypatch)
    signers, _tr = _signers_and_trust()

    res = _drive_transport(tmp_path, signers, "staging.corp.example")

    assert res.refused is False, res.notes
    assert _floor_refusals(res) == [], res.egress_checked
    assert res.egress_checked and res.egress_checked[0][0] == _RFC1918, "the floor must still have RUN"
    # ...and the SCOPE-over-addresses step ran too, and said WHY it authorised this address.
    assert res.scope_checked == [(_RFC1918, True, "attested",
                                  f"{_RFC1918} is written as an IP-literal row of the signed charter "
                                  f"scope")], res.scope_checked
    assert res.pinned_address == _RFC1918, "the connect must be pinned to the validated literal"
    assert calls == [(_RFC1918, 80)], f"the capture must dial the PINNED literal exactly once; got {calls}"


def test_an_exact_scoped_name_moved_to_an_unintended_rfc1918_address_is_refused(monkeypatch, tmp_path):
    """B1 NEGATIVE CONTROL — the one the suite lacked, and the reason the private-tier lift was rewritten.

    The old lift set was ``CharterScopeSource.resolved_allowed_ips()``: every non-wildcard scope entry
    RESOLVED AT REQUEST TIME. When the target IS the scope entry — the common case for an exact-hostname
    scope — both sides of "the private tier lifts only for an exactly-charter-authorized IP" were the
    SAME QUERY on the SAME resolver, so the rule collapsed into "lifts for whatever the resolver just
    said". A split-horizon view or a poisoned resolver moved ``staging.example.com`` to an internal host
    and the arm dialled it, minting a signed ``service_reachable`` FACT about a machine nobody
    authorized. The lift set is now the charter's IP LITERALS, which no resolver can rewrite.

    This is the SAME charter as the positive above with the IP-literal row removed — the difference that
    must decide it."""
    _grant_active_recon(monkeypatch)
    _charter_hosts(tmp_path, "staging.corp.example")            # the NAME only — no address attested
    _fake_dns(monkeypatch, {"staging.corp.example": _RFC1918})
    calls = _count_every_connector(monkeypatch)
    signers, _tr = _signers_and_trust()

    res = _drive_transport(tmp_path, signers, "staging.corp.example")

    assert calls == [], f"a name-only scope may not lift the private tier; got {calls}"
    assert res.refused is True and res.n_facts == 0
    denied = _floor_refusals(res)
    assert denied and denied[0][0] == _RFC1918, res.egress_checked
    assert "not in the charter-authorized allowlist" in denied[0][1], denied
    assert res.pinned_address == ""
    # POSITIVE: the charter really did list the NAME (both string gates passed) and the lift set really
    # is empty — so it is the literal-only rule, not an accident of scope, that refused.
    from vigil_integration.live.egress_floor import charter_allowed_ips, charter_scope_entries
    assert charter_scope_entries("alpha")[0] == ("staging.corp.example",)
    assert charter_allowed_ips("alpha") == frozenset()


def test_an_exact_scoped_dual_homed_name_cannot_lift_the_private_tier_for_itself(monkeypatch, tmp_path):
    """The same defect with NO resolver compromise at all. An exactly-scoped name with an ordinary
    dual-homed / round-robin record — one internal address, one public — put BOTH into the old
    request-time lift set, and ``pin.addresses[0]`` then dialled the internal one. All-or-nothing plus an
    IP-literal lift set refuses the pair outright."""
    _grant_active_recon(monkeypatch)
    _charter_hosts(tmp_path, "dual.corp.example")
    real = socket.getaddrinfo

    def _multi(host, port, *a, **kw):
        if str(host) != "dual.corp.example":
            return real(host, port, *a, **kw)
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, int(port or 0)))
                for addr in ("10.0.0.5", "93.184.216.34")]

    monkeypatch.setattr(socket, "getaddrinfo", _multi)
    calls = _count_every_connector(monkeypatch)
    signers, _tr = _signers_and_trust()

    res = _drive_transport(tmp_path, signers, "dual.corp.example")

    assert calls == [], f"the internal half of a dual-homed answer must never be dialled; got {calls}"
    assert res.refused is True and res.n_facts == 0
    denied = _floor_refusals(res)
    assert denied and denied[0][0] == "10.0.0.5", res.egress_checked
    assert "not in the charter-authorized allowlist" in denied[0][1], denied


def test_an_authorized_loopback_target_still_mints(monkeypatch, tmp_path):
    """Loopback engagements are a heavily-used legitimate mode. The floor hard-denies loopback by DEFAULT;
    this path opts in via the denylist's own ``loopback_allowed_if_scoped``, which still requires the exact
    loopback IP to be charter-authorized. A real FACT over a real open port proves the path is not dead."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _tr = _signers_and_trust()
    with _open_tcp_port() as port:
        res = _drive_transport(tmp_path, signers, "127.0.0.1", port=port)
    assert res.refused is False, res.notes
    assert res.n_facts == 1, res.admissions
    assert _floor_refusals(res) == [], res.egress_checked
    assert res.egress_checked == [("127.0.0.1", False, "allowed (127.0.0.1 is a charter-authorized "
                                                       "loopback target)")], res.egress_checked
    assert res.pinned_address == "127.0.0.1"


def test_an_unscoped_loopback_address_is_still_refused_by_the_floor(monkeypatch, tmp_path):
    """The loopback opt-in is not a blanket exception: the EXACT address must be in the charter-authorized
    set. Under a WILDCARD scope there is no concrete host to resolve into that set, so a matching name that
    lands on loopback is refused — loopback lifts for an operator who NAMED the target, not for anything
    whose string matches."""
    _grant_active_recon(monkeypatch)
    _charter_hosts(tmp_path, "*.corp.example")
    _fake_dns(monkeypatch, {"lo.corp.example": "127.0.0.2"})
    calls = _count_every_connector(monkeypatch)
    signers, _tr = _signers_and_trust()

    res = _drive_transport(tmp_path, signers, "lo.corp.example")

    assert calls == [], calls
    assert res.refused is True and res.n_facts == 0
    denied = _floor_refusals(res)
    assert denied and denied[0][0] == "127.0.0.2" and "loopback" in denied[0][1], res.egress_checked


def test_the_tls_leg_is_pinned_and_floor_gated_too(monkeypatch, tmp_path):
    """The TLS arm shares the chain: the metadata name is refused with no handshake, and an authorized
    private host is dialled at the PINNED literal with the original hostname kept for SNI."""
    _grant_active_recon(monkeypatch)
    _charter_hosts(tmp_path, "imds.corp.example", "staging.corp.example", _RFC1918)
    _fake_dns(monkeypatch, {"imds.corp.example": _IMDS, "staging.corp.example": _RFC1918})
    calls = _count_every_connector(monkeypatch)
    signers, _tr = _signers_and_trust()

    bad = _drive_transport(tmp_path, signers, "imds.corp.example", port=443, cls="weak_tls")
    assert calls == [], f"a metadata TLS target must attempt NO handshake; got {calls}"
    assert bad.refused is True and bad.n_facts == 0
    assert [a for a, _w in _floor_refusals(bad)] == [_IMDS]

    ok = _drive_transport(tmp_path, signers, "staging.corp.example", port=443, cls="weak_tls")
    assert ok.refused is False, ok.notes
    assert ok.pinned_address == _RFC1918
    assert calls == [(_RFC1918, 443)], f"the TLS capture must dial the PINNED literal; got {calls}"


def test_the_pinned_tls_connector_keeps_the_hostname_for_sni(monkeypatch):
    """Pinning the transport must not silently change WHICH certificate the peer selects: the address is
    substituted, the SNI name is not."""
    from vigil_integration.live import egress_floor
    seen: list = []
    monkeypatch.setattr(egress_floor, "_tls_socket_connect",
                        lambda address, host, port, timeout: seen.append((address, host, port)) or
                        ("TLSv1.3", "X", 256, None))
    egress_floor.pinned_tls_connector("10.0.0.9")("www.example.test", 443, 2.0)
    assert seen == [("10.0.0.9", "www.example.test", 443)]


# ---- the same battery on the smuggling site (BLOCK-1b: ONE shared helper, both sites) -------------------

def _drive_smuggling(signers, url: str):
    from vigil_integration.live.smuggling_redrive import smuggling_redrive
    return smuggling_redrive(url, slug="alpha", engagement_slug="alpha", signers=signers, timeout=1.0)


@pytest.mark.parametrize("label,scope_hosts,dns,target,expect_addr,expect_reason", [
    ("in-scope name -> IMDS", ("imds.corp.example",), {"imds.corp.example": _IMDS},
     "imds.corp.example", _IMDS, "always-denied range"),
    ("charter LISTS the IMDS literal", (_IMDS,), {}, _IMDS, _IMDS, "always-denied range"),
    ("IPv4-mapped IPv6 IMDS", ("v6imds.corp.example",), {"v6imds.corp.example": _IMDS_V4MAPPED},
     "v6imds.corp.example", _IMDS_V4MAPPED, "always-denied range"),
    ("wildcard scope -> RFC1918", ("*.corp.example",), {"app.corp.example": _RFC1918},
     "app.corp.example", _RFC1918, "not in the charter-authorized allowlist"),
])
def test_the_smuggling_site_enforces_the_same_floor(monkeypatch, tmp_path, label, scope_hosts, dns,
                                                    target, expect_addr, expect_reason):
    """BLOCK-1b. ``smuggling_redrive`` DID DNS-pin — but charter-relatively, re-asking the same string gate
    about the resolved address, so a charter listing the metadata literal opened TWO raw connects to it.
    It now goes through the SAME ``egress_floor.pin_egress`` as the transport arm.

    The reason assertion is deliberately the FLOOR's own wording, not the generic pin wording: on three of
    these four the runner's charter-relative predicate would ALSO refuse, so a control that accepted any
    refusal would still pass with the floor deleted. The floor runs FIRST, so its wording is what a working
    guard produces."""
    _grant_active_recon(monkeypatch)
    _charter_hosts(tmp_path, *scope_hosts)
    if dns:
        _fake_dns(monkeypatch, dns)
    calls = _count_every_connector(monkeypatch)
    signers, _tr = _signers_and_trust()

    res = _drive_smuggling(signers, f"http://{target}/")

    assert calls == [], f"[{label}] no raw socket may be opened; got {calls}"
    assert res.refused is True and res.n_facts == 0, res.notes
    # POSITIVE proof the FLOOR is what refused (not some earlier accident): every leg's reason names it.
    reasons = [why for _t, why in res.inconclusive]
    assert reasons, res.notes
    assert all(r.startswith("conflict leg: egress-floor/dns-pin refused: egress floor refused")
               for r in reasons), reasons
    assert all(expect_addr in r and expect_reason in r for r in reasons), reasons


def test_the_smuggling_site_still_drives_an_authorized_loopback_origin(monkeypatch, tmp_path):
    """The over-correction control for the smuggling site: the planted desync fixture on loopback must still
    be DRIVEN end-to-end, so the floor did not turn a working mode into a dead/refused path. The re-drive runs
    and is adjudicated INCONCLUSIVE (the finding stays a LEAD, never a FACT — #863)."""
    from framework.v2.eval.benchmark_app import serve_smuggling_desync
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _tr = _signers_and_trust()
    with serve_smuggling_desync() as url:
        res = _drive_smuggling(signers, url)
    # not refused (the floor let the authorized loopback origin through) and the burst actually ran ...
    assert res.refused is False, (res.notes, res.admissions)
    assert res.admissions, "the re-drive must have run and been adjudicated (not refused/dead)"
    # ... but it stays a LEAD: no FACT, all admissions INCONCLUSIVE on the single-connection differential.
    assert res.n_facts == 0, res.admissions
    assert all(v == "INCONCLUSIVE" for _b, v, _r in res.admissions), res.admissions


def test_a_charter_scoped_rfc1918_origin_reaches_the_smuggling_burst(monkeypatch, tmp_path):
    """A charter-authorized RFC1918 staging origin must still reach the burst. On THIS site the charter
    names the address itself — the runner's own ``_addr_authorized`` predicate re-asks the string-matching
    charter gate about the RESOLVED address, so only an IP-literal (or an IP-literal scope row) satisfies
    it; that predicate is unchanged and is kept ON TOP of the floor. The floor then lifts the private tier
    because the exact IP is charter-authorized, and the raw socket is dialled at the pinned literal."""
    _grant_active_recon(monkeypatch)
    _charter_hosts(tmp_path, _RFC1918)
    calls = _count_every_connector(monkeypatch)
    signers, _tr = _signers_and_trust()

    res = _drive_smuggling(signers, f"http://{_RFC1918}:8080/")

    # Not refused by any gate: the floor and the scope predicate both passed and a connect was attempted at
    # the PINNED literal (the connector raises, so no traffic actually leaves this test host).
    assert res.refused is False, res.notes
    assert calls and all(c == (_RFC1918, 8080) for c in calls), calls
    from vigil_integration.live.egress_floor import charter_allowed_ips, pin_egress
    assert _RFC1918 in charter_allowed_ips("alpha")
    pin = pin_egress(_RFC1918, 8080, slug="alpha")
    assert pin.allowed and pin.pinned == _RFC1918 and pin.checked == [(_RFC1918, False, "allowed")]


# ---- the helper's own contract (so a future site cannot get it subtly wrong) -----------------------------

# ---- R2-B1: a charter address is ONE address, however it is legally spelled -----------------------------
#
# The literal set and ``_row_addresses`` kept the RAW spelling while the address under test came from
# ``getaddrinfo`` (or straight from an IP-literal target the caller typed). Measured on the unfixed code:
# NINE of these ten legal spellings of a charter's OWN only scope row REFUSED that row's own target — and
# the split was diagnostic, because the denylist FLOOR allowed every one of them (``_coerce_allowed``
# canonicalises) while the scope predicate refused. Two halves of the same check disagreeing about the
# same row. It matters because the whole IP-literal rule is justified by "breaks no operator workflow on
# record", and this is a way it breaks one — absent from the record only because no charter here uses IPv6.

_IPV6_SPELLINGS = [
    ("compressed row / expanded target",   "::1",                                     "0:0:0:0:0:0:0:1"),
    ("bracketed row / bare target",        "[::1]",                                   "::1"),
    ("expanded row / compressed target",   "0:0:0:0:0:0:0:1",                         "::1"),
    ("lower row / UPPER+zeros target",     "2606:2800:220:1:248:1893:25c8:1946",
                                           "2606:2800:0220:0001:0248:1893:25C8:1946"),
    ("leading-zeros row / compressed",     "2606:2800:0220:0001:0248:1893:25c8:1946",
                                           "2606:2800:220:1:248:1893:25c8:1946"),
    ("bracketed UPPER row / lower target", "[2606:2800:220:1:248:1893:25C8:1946]",
                                           "2606:2800:220:1:248:1893:25c8:1946"),
    ("ULA compressed / expanded",          "fd12:3456::1",      "fd12:3456:0000:0000:0000:0000:0000:1"),
    ("ULA expanded / compressed",          "fd12:3456:0:0:0:0:0:1",                   "fd12:3456::1"),
    ("ULA UPPER / lower",                  "FD12:3456::1",                            "fd12:3456::1"),
    ("ULA UPPER+zeros / compressed",       "FD12:3456:0000:0000:0000:0000:0000:0001", "fd12:3456::1"),
]


@pytest.mark.parametrize("label,row,target", _IPV6_SPELLINGS,
                         ids=[c[0] for c in _IPV6_SPELLINGS])
def test_a_legal_ipv6_spelling_of_the_charters_own_row_authorises_its_own_target(tmp_path, label, row,
                                                                                 target):
    """``ethics.host_matches_scope`` documents that ``fe80::1``, ``fe80:0:0:0:0:0:0:1`` and ``[fe80::1]``
    are the SAME host. The scope-over-addresses predicate must agree, or a charter refuses its own
    target. Asserted POSITIVELY: the floor ran and allowed, and the scope step ran and ATTESTED."""
    from vigil_integration.live.egress_floor import charter_address_authorizer, pin_egress
    import ipaddress as _ip
    assert _ip.ip_address(row.strip("[]")) == _ip.ip_address(target.strip("[]")), "the case is malformed"
    _charter_hosts(tmp_path, row)

    pin = pin_egress(target, 443, slug="alpha",
                     address_authorized=charter_address_authorizer("alpha", target))

    assert pin.floor_ran and not [a for a, d, _w in pin.checked if d], pin.checked
    assert pin.scope_over_addresses == "enforced", pin.scope_over_addresses
    assert pin.scope_checked and pin.scope_checked[0][1] is True, pin.scope_checked
    assert pin.scope_checked[0][2] == "attested", pin.scope_checked
    assert pin.allowed and pin.pinned == target, pin.refused_reason


def test_canonicalising_does_not_make_a_DIFFERENT_ipv6_address_match(tmp_path):
    """The over-correction control for the fix above: canonicalisation must equate SPELLINGS, never
    ADDRESSES. A neighbouring ULA address is still unattributable."""
    from vigil_integration.live.egress_floor import charter_address_authorizer, pin_egress
    _charter_hosts(tmp_path, "fd12:3456::1")

    pin = pin_egress("fd12:3456:0:0:0:0:0:2", 443, slug="alpha",
                     address_authorized=charter_address_authorizer("alpha", "fd12:3456:0:0:0:0:0:2"))

    assert not pin.allowed and pin.pinned == ""
    # the FLOOR refuses it first (a ULA the charter does not name cannot lift the private tier) — which
    # is itself the B1 rule working on a canonicalised literal set.
    assert [a for a, d, _w in pin.checked if d] == ["fd12:3456:0:0:0:0:0:2"], pin.checked
    assert "not in the charter-authorized allowlist" in pin.refused_reason, pin.refused_reason
    assert pin.scope_over_addresses == "not reached", pin.scope_over_addresses


def test_a_hostname_row_resolving_to_a_noncanonical_ipv6_is_still_name_derived(monkeypatch, tmp_path):
    """The same canonicalisation on the OTHER side: ``_row_addresses`` holds what the resolver said for a
    NAME row, and the target's own answer may be spelled differently. Branch 2b must still match."""
    from vigil_integration.live.egress_floor import charter_address_authorizer, pin_egress
    _charter_hosts(tmp_path, "v6.corp.example")
    real = socket.getaddrinfo
    seq = {"n": 0}

    def _gai(host, port, *a, **kw):
        if str(host) != "v6.corp.example":
            return real(host, port, *a, **kw)
        seq["n"] += 1
        # the TARGET resolution and the SCOPE-ROW resolution spell the same address differently
        addr = "2606:2800:220:1:248:1893:25C8:1946" if seq["n"] == 1 else \
               "2606:2800:0220:0001:0248:1893:25c8:1946"
        return [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, int(port or 0), 0, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _gai)

    pin = pin_egress("v6.corp.example", 443, slug="alpha",
                     address_authorized=charter_address_authorizer("alpha", "v6.corp.example"))

    assert pin.allowed, pin.refused_reason
    assert pin.scope_checked[0][1] is True and pin.scope_checked[0][2] == "name_derived", pin.scope_checked


def test_the_exhaustive_branch_still_refuses_an_extra_address_when_the_charter_spells_ipv6_differently(
        monkeypatch, tmp_path):
    """The OTHER half of the canonicalisation, and the soundness-relevant one. Branch 2a ("the charter
    states this host's addresses explicitly, so that statement is exhaustive") computes
    ``literals & _row_addresses(row)``. If either side kept a raw spelling, that intersection MISSES and
    branch 2a silently degrades to branch 2b — i.e. the extra address is AUTHORIZED instead of refused.
    Here the charter writes the address expanded and the resolver answers it compressed."""
    from vigil_integration.live.egress_floor import charter_address_authorizer, pin_egress
    _EXPANDED = "2606:2800:0220:0001:0248:1893:25c8:1946"
    _COMPRESSED = "2606:2800:220:1:248:1893:25c8:1946"
    _EXTRA = "2001:4860:4860::8888"                      # a public, floor-passing, out-of-scope address
    _charter_hosts(tmp_path, "shop.example.test", _EXPANDED)
    real = socket.getaddrinfo

    def _gai(host, port, *a, **kw):
        if str(host) != "shop.example.test":
            return real(host, port, *a, **kw)
        return [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (x, int(port or 0), 0, 0))
                for x in (_COMPRESSED, _EXTRA)]

    monkeypatch.setattr(socket, "getaddrinfo", _gai)

    pin = pin_egress("shop.example.test", 443, slug="alpha",
                     address_authorized=charter_address_authorizer("alpha", "shop.example.test"))

    # the FLOOR allows both (globally routable), so only the scope step can refuse
    assert pin.floor_ran and [d for _a, d, _w in pin.checked] == [False, False], pin.checked
    assert [(ok, t) for _a, ok, t, _w in pin.scope_checked] == [
        (True, "attested"), (False, "not_stated")], pin.scope_checked
    assert not pin.allowed and pin.pinned == ""


def test_an_ip_literal_row_authorises_a_wildcard_matched_host_because_literals_are_charter_wide(
        monkeypatch, tmp_path):
    """N1. Branch 3's docstring used to say a wildcard row means "no address can be attributed to the
    charter". Falsifiable as written: ``literals`` is CHARTER-WIDE and branch 1 fires BEFORE any row
    matching, so with ``[10.20.30.40, *.corp.example]`` the host ``dc.corp.example`` -> ``10.20.30.40``
    IS authorized — the operator attested to that address somewhere in this charter, and the denylist's
    own lift works the same way. The docstring was corrected to say so; this pins the behaviour it
    describes, so the two cannot drift apart again."""
    from vigil_integration.live.egress_floor import charter_address_authorizer, pin_egress
    _charter_hosts(tmp_path, "10.20.30.40", "*.corp.example")
    _fake_dns(monkeypatch, {"dc.corp.example": "10.20.30.40"})

    pin = pin_egress("dc.corp.example", 445, slug="alpha",
                     address_authorized=charter_address_authorizer("alpha", "dc.corp.example"))

    assert pin.allowed and pin.pinned == "10.20.30.40", pin.refused_reason
    assert pin.scope_checked == [("10.20.30.40", True, "attested",
                                  "10.20.30.40 is written as an IP-literal row of the signed charter "
                                  "scope")], pin.scope_checked
    # ...and the same wildcard scope WITHOUT that literal row refuses, which is branch 3 proper.
    _charter_hosts(tmp_path, "*.corp.example")
    from vigil_integration.live import egress_floor
    egress_floor._SCOPE_CACHE.clear()
    bare = pin_egress("dc.corp.example", 445, slug="alpha",
                      address_authorized=charter_address_authorizer("alpha", "dc.corp.example"))
    assert not bare.allowed, bare.pinned


def test_a_floor_refusal_on_a_wired_site_reads_not_reached_not_not_requested(monkeypatch, tmp_path):
    """N3. ``scope_over_addresses`` said "not requested" both when NO predicate was passed and when one
    was passed but the floor short-circuited first, so a refusal record could not distinguish a wired
    site from an unwired one — while ``EgressPin``'s docstring sells this as the field you read to assert
    the step ran. Three states now."""
    from vigil_integration.live.egress_floor import charter_address_authorizer, pin_egress
    _charter_hosts(tmp_path, "imds.corp.example")
    _fake_dns(monkeypatch, {"imds.corp.example": _IMDS})

    unwired = pin_egress("imds.corp.example", 80, slug="alpha")
    wired = pin_egress("imds.corp.example", 80, slug="alpha",
                       address_authorized=charter_address_authorizer("alpha", "imds.corp.example"))

    assert not unwired.allowed and not wired.allowed
    assert [a for a, d, _w in wired.checked if d] == [_IMDS], wired.checked   # the FLOOR refused both
    assert unwired.scope_over_addresses == "not requested", unwired.scope_over_addresses
    assert wired.scope_over_addresses == "not reached", wired.scope_over_addresses
    assert wired.scope_checked == [] and not wired.scope_ran


def test_a_write_landing_between_the_cache_stamp_and_the_parse_makes_the_cache_COLD_not_stale(tmp_path,
                                                                                               monkeypatch):
    """R2-B2 / C5. The cache key is stamped at the TOP of ``charter_scope_entries``, but the value comes
    from ``CharterScopeSource.hosts()``, which performs its OWN read. A write landing in that window was
    cached under the PREVIOUS stamp — and after reverting the file to its exact earlier bytes with
    ``os.utime`` restoring ``mtime_ns``, the cache kept serving a scope the charter never had:

        stamp(A) = (…318829887, 211) ca114f5b722c
        value cached under stamp(A): ['10.20.30.99']      # a re-sign landed inside the window
        <file reverted to A byte-for-byte, mtime_ns + size restored>
        charter FILE says 10.20.30.40; cache returned:    ['10.20.30.99']   -> STALE

    ``charter_scope_entries`` now RE-STAMPS after the parse and caches ONLY when the two stamps agree, so
    the window makes the cache go COLD (a re-read next call), never stale."""
    import os

    from vigil_integration.live import egress_floor
    egress_floor._SCOPE_CACHE.clear()
    _charter_hosts(tmp_path, "10.20.30.40")
    cp = tmp_path / "alpha" / "charter.md"
    byte_a, stat_a = cp.read_bytes(), cp.stat()

    # Land the interfering write INSIDE the window: hosts() re-reads the file, so patch the class to
    # rewrite the charter immediately before it parses.
    from vigil_gateway.scope_source import CharterScopeSource
    real_hosts = CharterScopeSource.hosts
    once = {"done": False}

    def _hosts_with_a_write_in_the_window(self):
        if not once["done"]:                          # interfere on the FIRST parse only
            once["done"] = True
            _charter_hosts(tmp_path, "10.20.30.99")   # the re-sign that lands mid-window
        return real_hosts(self)

    # NB: do NOT monkeypatch.undo() here — it would also undo the autouse ``_isolate`` charter_path
    # patch and point the next read at the real target root.
    monkeypatch.setattr(CharterScopeSource, "hosts", _hosts_with_a_write_in_the_window)
    raced = egress_floor.charter_scope_entries("alpha")
    assert raced[0] == ("10.20.30.99",), raced      # the value returned is the freshly parsed one

    # revert byte-for-byte AND restore mtime_ns + size, exactly as the red-pen did
    cp.write_bytes(byte_a)
    os.utime(cp, ns=(stat_a.st_atime_ns, stat_a.st_mtime_ns))
    assert cp.read_bytes() == byte_a and cp.stat().st_mtime_ns == stat_a.st_mtime_ns

    after = egress_floor.charter_scope_entries("alpha")
    assert after[0] == ("10.20.30.40",), (
        f"the cache served a scope the charter never had: file says 10.20.30.40, cache returned {after[0]}")
    assert after[1] == frozenset({"10.20.30.40"}), after[1]


def test_the_charter_cache_still_HITS_when_nothing_writes_during_the_parse(tmp_path):
    """The over-correction control for the fix above: the C5 guard must not disable the cache. With no
    interfering write the two stamps agree, the entry is stored, and a second call is served from it —
    which is the whole 14.0x DNS / 15 s saving (B7)."""
    from vigil_integration.live import egress_floor
    egress_floor._SCOPE_CACHE.clear()
    _charter_hosts(tmp_path, "10.20.30.40")

    first = egress_floor.charter_scope_entries("alpha")
    assert len(egress_floor._SCOPE_CACHE) == 1, "a quiet parse must CACHE"
    second = egress_floor.charter_scope_entries("alpha")
    assert second is first, "the second call must be served from the cache, not re-parsed"


def test_the_charter_relative_dns_pin_is_removed_and_cannot_be_revived_by_accident(monkeypatch):
    """RESIDUAL — make the footgun unusable. ``dns_pin.resolve_and_validate`` is a charter-RELATIVE pin
    with a name that reads like the safe thing: it required every resolved address to satisfy the
    caller's own predicate and never consulted the L3/L4 floor, so a charter listing 169.254.169.254
    satisfied it and it pinned the connection at cloud instance metadata. It is now called by nothing,
    which is exactly when the next author imports it for a new resolve-then-connect site — how this
    class-bug reached four sites. It must RAISE, and point at the replacement.

    ``pinned_handlers`` is NOT removed: ``web_redrive`` uses it to dial the address ``pin_egress``
    validated, so this control also pins that it stays."""
    import socket as _socket

    from vigil_integration.live import dns_pin
    dialled: list = []
    monkeypatch.setattr(_socket, "getaddrinfo",
                        lambda *a, **kw: dialled.append(a) or [
                            (_socket.AF_INET, _socket.SOCK_STREAM, _socket.IPPROTO_TCP, "",
                             (_IMDS, 80))])

    with pytest.raises(RuntimeError) as exc:
        dns_pin.resolve_and_validate(_IMDS, 80, lambda _a: True)

    assert dialled == [], "the removed pin must not even resolve"
    assert "pin_egress" in str(exc.value), exc.value
    assert "egress floor" in str(exc.value), exc.value
    assert callable(dns_pin.pinned_handlers), "the PIN half is still used by web_redrive"
    # and nothing in the shipped tree calls it any more.
    import subprocess
    hits = subprocess.run(
        ["grep", "-rn", "resolve_and_validate", "--include=*.py",
         str(_ROOT / "integration" / "vigil_integration"), str(_ROOT / "engine")],
        capture_output=True, text=True).stdout.splitlines()
    offenders = [h for h in hits if "dns_pin.py" not in h and "egress_floor.py" not in h]
    assert offenders == [], f"a live caller of the removed charter-relative pin reappeared: {offenders}"


def test_pin_egress_fails_closed_when_the_gateway_denylist_is_unavailable(monkeypatch):
    """No conscience ⇒ no authorization. A missing denylist must never degrade to an unguarded connect."""
    from vigil_integration.live import egress_floor

    def _boom():
        raise ImportError("no vigil_gateway here")

    monkeypatch.setattr(egress_floor, "_denylist", _boom)
    pin = egress_floor.pin_egress("127.0.0.1", 80, slug="alpha")
    assert not pin.allowed and not pin.floor_ran
    assert "not importable" in pin.refused_reason


def test_pin_egress_refuses_a_mixed_answer_where_only_one_address_is_denied(monkeypatch):
    """All-or-nothing: connecting to the one good address would leave the bad one reachable on a retry."""
    from vigil_integration.live import egress_floor
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, *a, **kw: [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 80)),
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (_IMDS, 80)),
    ])
    pin = egress_floor.pin_egress("multi.example", 80, allowed_ips=())
    assert not pin.allowed and pin.pinned == ""
    assert [a for a, d, _w in pin.checked if d] == [_IMDS]


# ---- SCOPE OVER ADDRESSES (step 3) — the step mutation M8 proved was COMPLETELY UNTESTED ---------------
#
# ``if False and address_authorized is not None:`` in ``pin_egress`` killed 105 passed / 2 skipped and
# ZERO tests. The floor cannot substitute for it: ``is_egress_denied`` allows ANY globally-routable
# address, so on a call site that passes no predicate the property the shared docstring advertises —
# "every resolved address must be in scope" — is simply absent. Two of the four sites (transport, race)
# passed no predicate at all. Each control below asserts POSITIVELY that the floor RAN AND ALLOWED the
# address, and that the SCOPE step is what refused; deleting either step fails them.

_PUBLIC = "93.184.216.34"
_OFF_SCOPE = "8.8.8.8"


def _multi_a(monkeypatch, name: str, *addrs: str) -> None:
    real = socket.getaddrinfo

    def _gai(host, port, *a, **kw):
        if str(host) != name:
            return real(host, port, *a, **kw)
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (x, int(port or 0)))
                for x in addrs]

    monkeypatch.setattr(socket, "getaddrinfo", _gai)


def test_the_scope_step_refuses_an_extra_address_the_floor_allows(monkeypatch, tmp_path):
    """M8's killer, at the helper. The charter states ``shop.example.com``'s address explicitly
    (``93.184.216.34``), and the name answers with a SECOND, globally-routable, out-of-scope address.
    Both clear the floor — ``is_egress_denied`` only ever asks "is this globally routable" of a public
    address — so ONLY the scope step can refuse, and it must."""
    from vigil_integration.live.egress_floor import charter_address_authorizer, pin_egress
    _charter_hosts(tmp_path, "shop.example.com", _PUBLIC)
    _multi_a(monkeypatch, "shop.example.com", _PUBLIC, _OFF_SCOPE)

    pin = pin_egress("shop.example.com", 443, slug="alpha",
                     address_authorized=charter_address_authorizer("alpha", "shop.example.com"))

    # POSITIVE: the floor RAN over both addresses and ALLOWED both — it is not what refused.
    assert pin.floor_ran and [(a, d) for a, d, _w in pin.checked] == [(_PUBLIC, False),
                                                                      (_OFF_SCOPE, False)], pin.checked
    # POSITIVE: the scope step RAN, authorised the attested address, and refused the other.
    assert pin.scope_ran and pin.scope_over_addresses == "enforced"
    assert [(a, ok, t) for a, ok, t, _w in pin.scope_checked] == [
        (_PUBLIC, True, "attested"), (_OFF_SCOPE, False, "not_stated")], pin.scope_checked
    assert not pin.allowed and pin.pinned == ""
    assert _OFF_SCOPE in pin.refused_reason and "exhaustive" in pin.refused_reason, pin.refused_reason


def test_the_transport_site_runs_the_scope_step_and_never_dials_the_extra_address(monkeypatch, tmp_path):
    """M8's killer AT A SITE, not only at the helper: ``transport_redrive`` passed NO predicate, so this
    exact answer was pinned and dialled there while the smuggling/web sites refused it."""
    _grant_active_recon(monkeypatch)
    _charter_hosts(tmp_path, "shop.example.com", _PUBLIC)
    _multi_a(monkeypatch, "shop.example.com", _PUBLIC, _OFF_SCOPE)
    calls = _count_every_connector(monkeypatch)
    signers, _tr = _signers_and_trust()

    res = _drive_transport(tmp_path, signers, "shop.example.com", port=443)

    assert calls == [], f"an out-of-scope co-resident address must attempt NO connection; got {calls}"
    assert res.refused is True and res.n_facts == 0
    assert _floor_refusals(res) == [], f"the FLOOR allowed both; the SCOPE step must be the refuser: {res.egress_checked}"
    assert [(a, ok, t) for a, ok, t, _w in res.scope_checked] == [
        (_PUBLIC, True, "attested"), (_OFF_SCOPE, False, "not_stated")], res.scope_checked
    assert res.pinned_address == ""


def test_a_wildcard_only_scope_names_no_address_so_the_scope_step_refuses(monkeypatch, tmp_path):
    """A wildcard row authorises a NAME PATTERN and names no address at all, so no address is
    attributable to the charter. The address here is PUBLIC, so the floor allows it — this is a scope
    refusal or nothing. (The RFC1918 sibling above is refused one layer earlier, by the floor.)"""
    from vigil_integration.live.egress_floor import charter_address_authorizer, pin_egress
    _charter_hosts(tmp_path, "*.corp.example")
    _fake_dns(monkeypatch, {"app.corp.example": _PUBLIC})

    pin = pin_egress("app.corp.example", 443, slug="alpha",
                     address_authorized=charter_address_authorizer("alpha", "app.corp.example"))

    assert pin.floor_ran and pin.checked == [(_PUBLIC, False, "allowed")], pin.checked
    assert pin.scope_checked == [(_PUBLIC, False, "unattributable",
                                  pin.scope_checked[0][3])], pin.scope_checked
    assert not pin.allowed and pin.pinned == ""
    assert "attributable to no row" in pin.scope_checked[0][3], pin.scope_checked


def test_a_hostname_only_charter_is_authorized_on_every_site(monkeypatch, tmp_path):
    """THE ASYMMETRY, closed. ``web_redrive`` / ``smuggling_redrive`` re-asked the string gate about the
    resolved IP LITERAL — a question only an IP-literal charter row can satisfy — so they refused a
    HOSTNAME-ONLY charter outright, while ``transport`` / ``race`` (no predicate) allowed it. Verified
    against the shipped ``targets/testasp/charter.md`` shape: one hostname row, nothing else.

    The shared predicate authorises it as NAME-DERIVED and says so in the audit row, so the certificate
    reader can see exactly how much was proven: the charter attested to the NAME, not to the address."""
    from vigil_integration.live.egress_floor import charter_address_authorizer, pin_egress
    _charter_hosts(tmp_path, "testasp.example.test")
    _fake_dns(monkeypatch, {"testasp.example.test": _PUBLIC})

    pin = pin_egress("testasp.example.test", 80, slug="alpha",
                     address_authorized=charter_address_authorizer("alpha", "testasp.example.test"))

    assert pin.allowed and pin.pinned == _PUBLIC, pin.refused_reason
    assert pin.scope_ran and pin.scope_checked[0][:3] == (_PUBLIC, True, "name_derived"), pin.scope_checked
    assert "name-derived" in pin.scope_checked[0][3], pin.scope_checked
    assert "no address-level attestation" in pin.scope_checked[0][3], pin.scope_checked


def test_the_smuggling_site_accepts_the_same_hostname_only_charter(monkeypatch, tmp_path):
    """The other half of the asymmetry, at the site that used to refuse it. A connect is ATTEMPTED at the
    pinned literal (the recording connector raises, so nothing leaves this host) — the point is that no
    gate refused first."""
    _grant_active_recon(monkeypatch)
    _charter_hosts(tmp_path, "testasp.example.test")
    _fake_dns(monkeypatch, {"testasp.example.test": _PUBLIC})
    calls = _count_every_connector(monkeypatch)
    signers, _tr = _signers_and_trust()

    res = _drive_smuggling(signers, "http://testasp.example.test/")

    assert res.refused is False, res.notes
    assert calls and all(c == (_PUBLIC, 80) for c in calls), calls


# ---- the two REMEDIATION-VALIDATION sites: no floor at all before this slice ---------------------------
#
# ``remediation/live_adapter.py`` and ``remediation/differential_adapter.py`` both called
# ``capture_tls_handshake(host, port, slug=...)`` with no pin, no denylist and no scope-over-addresses.
# With a charter listing 169.254.169.254 the socket fired: SOCKET ATTEMPTS = [('169.254.169.254', 443)].
# These run on an operator-triggered RE-TEST after a fix — the moment nobody is watching the wire.

@pytest.mark.parametrize("module_name, cls_name", [
    ("vigil_integration.remediation.live_adapter", "LiveHttpAdapter"),
    ("vigil_integration.remediation.differential_adapter", "DifferentialHttpAdapter"),
])
def test_a_remediation_adapter_tls_sample_is_floor_gated_and_pinned(monkeypatch, tmp_path,
                                                                    module_name, cls_name):
    """The charter LISTS the metadata address, so every string gate in ``capture_tls_handshake``'s own
    chain says yes. The floor must refuse before a socket exists, and the refusal must RAISE (a gate
    refusal is a "cannot test", never a silently weaker host-only identity pin)."""
    import importlib
    mod = importlib.import_module(module_name)
    assert hasattr(mod, cls_name), f"{module_name} lost {cls_name}"
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, _IMDS)
    calls = _count_every_connector(monkeypatch)

    # Drive the bound method directly with a minimal stand-in: the site under test is the TLS sample,
    # not the executor plumbing above it.
    class _Probe:
        _host = _IMDS
        _slug = "alpha"
        _observed_tls_spki = mod.__dict__[cls_name]._observed_tls_spki
        _looks_like_transport_failure = staticmethod(
            mod.__dict__[cls_name]._looks_like_transport_failure)

    split = urlsplit(f"https://{_IMDS}:443/")
    with pytest.raises(RuntimeError) as exc:
        _Probe()._observed_tls_spki(split)

    assert calls == [], f"the metadata address must attempt NO handshake; got {calls}"
    assert "egress floor" in str(exc.value), exc.value
    assert "always-denied range" in str(exc.value), exc.value


# ---- the two EXTERNAL-TOOL captures: the floor ran, but the CONNECT was not pinned --------------------

def test_the_external_tool_captures_dial_the_pinned_literal_not_the_name(monkeypatch, tmp_path):
    """B2b. ``ScopeGate.authorize`` resolved and adjudicated the addresses BEFORE the tool launched, then
    ``_default_capture`` / ``_tls_capture`` handed the NAME to the capture, so the OS re-resolved it at
    connect time — the rebinding window the pin exists to close. Measured on the unfixed code: the gate
    authorised 93.184.216.34, the capture dialled the name, and the next resolution returned
    169.254.169.254.

    Here the resolver flips to the metadata address after the FIRST answer. The pinned capture must dial
    the literal it validated, and the UNPINNED shape (the old call, exercised alongside) must not be what
    ships."""
    from vigil_integration.live import external_tool
    _grant_active_recon(monkeypatch)
    _charter_hosts(tmp_path, "rebind.example.test", _PUBLIC)
    answers = {"n": 0}
    real = socket.getaddrinfo

    def _flipping(host, port=None, *a, **kw):
        if str(host) != "rebind.example.test":
            return real(host, port, *a, **kw)
        answers["n"] += 1
        addr = _PUBLIC if answers["n"] <= 1 else _IMDS     # every answer AFTER the pin is the floor case
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, int(port or 0)))]

    monkeypatch.setattr(socket, "getaddrinfo", _flipping)
    calls = _count_every_connector(monkeypatch)

    cap = external_tool._default_capture("rebind.example.test", 80, slug="alpha", protocol="tcp")

    assert calls == [(_PUBLIC, 80)], (
        f"the capture must dial the address the floor VALIDATED, never re-resolve the name; got {calls}")
    assert cap["connected"] is False   # the recording connector raises; the point is WHICH address

    # ...and the TLS twin is pinned the same way. The resolver has already flipped, so the pin itself now
    # lands on the metadata address and the floor refuses it BEFORE any handshake — also the right answer.
    calls.clear()
    tls = external_tool._tls_capture("rebind.example.test", 443, slug="alpha")
    assert calls == [], f"a flipped resolver must not produce a handshake; got {calls}"
    assert "always-denied range" in str(tls.get("error") or ""), tls


def test_a_udp_row_still_never_reaches_the_floor_or_a_socket(monkeypatch, tmp_path):
    """Over-correction control for the added pin in ``_default_capture``: the TCP-only guard must still
    run FIRST, so a udp-open row is refused by the capture's own soundness check and the floor is never
    even consulted (a udp row must not become a resolve-and-adjudicate)."""
    from vigil_integration.live import external_tool
    _grant_active_recon(monkeypatch)
    _charter_hosts(tmp_path, "svc.example.test", _PUBLIC)
    _fake_dns(monkeypatch, {"svc.example.test": _PUBLIC})
    calls = _count_every_connector(monkeypatch)

    cap = external_tool._default_capture("svc.example.test", 53, slug="alpha", protocol="udp")

    assert calls == []
    assert cap["connected"] is False and "TCP-only" in str(cap.get("error") or ""), cap


# =======================================================================================================
# The lower-severity red-pen findings, each with a control that fails if the fix is reverted.
# =======================================================================================================

def test_the_persisted_record_stamps_the_PROVEN_class_not_the_claimed_one(monkeypatch, tmp_path):
    """FINDING-5. One TLS handshake is judged for TWO classes, so a ``weak_tls``-CLAIMED report can prove
    only ``weak_crypto_artifact``. The Proof-Studio record used to stamp the CLAIM, producing
    ``{"bug_class": "weak_tls", "n_facts": 1}`` — a weakness no oracle fired on. S2 is the first arm where
    claimed and proven can differ, so this is where it must be pinned."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _tr = _signers_and_trust()
    short_cert = _make_cert(tmp_path / "claimvsproven-short.pem", bits=1024)
    host_cert = _make_cert(tmp_path / "claimvsproven-host.pem", bits=2048)
    with _tls_endpoint(host_cert) as port:
        # a MODERN protocol (so weak_tls does NOT fire) presenting an undersized leaf (so weak_crypto does)
        _force_negotiation(monkeypatch, version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", bits=256,
                           certfile=short_cert)
        mr = _mint(tmp_path, signers)({"id": "claim-vs-proven", "bug_class": "weak_tls",
                                       "endpoint": f"https://127.0.0.1:{port}/"})
    assert mr is not None and mr.is_fact, mr
    fired = {a[0] for a in mr.result.admissions if a[1] == "FACT"}
    assert fired == {"weak_crypto.cert_signature_algorithm"}, mr.result.admissions

    records = [json.loads(p.read_text(encoding="utf-8"))
               for p in sorted((tmp_path / "proofs").glob("runtimeredrive-*.json"))]
    assert len(records) == 1, records
    rec = records[0]
    assert rec["n_facts"] == 1
    assert rec["bug_class"] == "weak_crypto_artifact", rec
    assert rec["claimed_bug_class"] == "weak_tls", rec
    assert rec["proven_bug_classes"] == ["weak_crypto_artifact"], rec


def test_the_smuggling_branch_does_not_claim_a_mechanism_the_differential_cannot_show():
    """FINDING-3 / #863. A single-connection canary differential cannot discriminate a genuine
    front-end/back-end desync (TWO parsers disagreeing across a trust boundary) from a benign single origin
    that merely honours TE over CL and pipelines the remainder (ONE parser). The branch is therefore an
    UNCONFIRMED LEAD, and its registry claim must be exactly main's demoted (sound) text — it may NOT assert
    the back-end-desync MECHANISM the differential cannot establish (the over-claim S2's own former
    blocking_work flagged)."""
    b = _branch("request_smuggling.differential_desync")
    text = f"{b['evidence']}\n{b['limitation']}"
    # the SOUND LEAD claim (main's demoted evidence/limitation text)
    assert b["fact_capable"] is False, b
    assert "UNCONFIRMED LEAD" in b["evidence"], b["evidence"]
    assert "not a CWE-444 fact" in b["evidence"], b["evidence"]
    assert b["limitation"].startswith("LEAD-ONLY"), b["limitation"]
    # the mechanism (two parsers disagreeing) appears ONLY as what the differential CANNOT show ...
    assert "TWO PARSERS DISAGREEING" in b["evidence"], b["evidence"]
    assert "one parser" in text, text
    # ... any "treated the smuggled prefix" statement is scoped to the SAME single connection (one parser),
    # never the FACT-era unscoped claim that a fire proves a back-end desync (a mechanism).
    assert "ON THAT CONNECTION" in b["evidence"], b["evidence"]
    assert "back-end treated the smuggled prefix" not in text, text
    assert "ACHIEVED-DESYNC FACT" not in text, text


@pytest.mark.parametrize("branch_id", ["service_reachability.tcp_handshake", "tls_weakness.tls_handshake"])
def test_the_clean_capable_transport_branches_name_the_work_that_makes_clean_reachable(branch_id):
    """FINDING-4 / CLAIM-DISCIPLINE. Both branches are registered ``clean_capable: true``, but the oracles
    build their non-firing signals WITHOUT ``conclusive=True``, so ``probe_verdict`` can never return clean
    and ``admit`` can only reach INCONCLUSIVE — the runner is strictly weaker than the row reads. The claim
    is NOT softened (meet-up, not downgrade); the concrete engineering that closes the gap is named."""
    b = _branch(branch_id)
    assert b["clean_capable"] is True and b["target_clean_capable"] is True
    work = (b.get("blocking_work") or "").strip()
    assert len(work) > 40, f"{branch_id}: the unreachable-CLEAN gap must name its blocking_work"
    assert "conclusive=True" in work, work
    assert "INCONCLUSIVE" in work, work
