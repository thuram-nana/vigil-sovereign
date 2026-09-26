"""HexStrike WAVE 3 — breadth of TLS CLAIMS, each red-penned against a same-shape negative control.

Every claim in ``live.tls_breadth`` is exercised here against REAL loopback TLS servers, through the REAL
gated runner (``run_external_tool``), with the tool reduced to what it is — a proposer whose bytes are never
evidence. For each claim there is a positive fixture that MUST mint and a same-shape negative that MUST NOT:

  * a TLS1.0-accepting server mints "deprecated protocol accepted"; a TLS1.2/1.3-only server does NOT, and
    instead admits the CHANNEL-CONFIRMED CLEAN;
  * a NULL-cipher server mints "weak cipher negotiated"; a strong-cipher-only server does NOT;
  * an expired / not-yet-valid / mismatched / self-signed leaf is classified; a CA-issued, in-date,
    IP-matching leaf is not;
  * a host that TIMES OUT or resets is INCONCLUSIVE and NEVER CLEAN — the laundering bug this slice is most
    exposed to, pinned by name in ``test_a_black_hole_host_is_inconclusive_never_clean`` and
    ``test_a_reset_host_is_inconclusive_never_clean``.

Each positive is additionally re-verified OFFLINE from its certificate, and a TAMPERED retained capture is
shown to FAIL that re-verification.

Offense-process test (loads ``framework.*``): CI runs it in the offense group (see ci.yml).
"""
from __future__ import annotations

import base64
import datetime
import socket
import ssl
import threading
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
pytest.importorskip("cryptography", reason="cryptography is needed to mint the fixture certificates")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from vigil_core import AuthorizerKey, TrustRoot, generate_keypair  # noqa: E402
from vigil_gateway.scope_source import StaticScopeSource  # noqa: E402
from vigil_integration.live import tls_breadth as tb  # noqa: E402
from vigil_integration.live.external_tool import (  # noqa: E402
    ScopeGate,
    ToolOutcome,
    run_external_tool,
    tls_scan,
)
from vigil_integration.oracle_adapter import Outcome  # noqa: E402

_SIGNER = generate_keypair()
SIGNERS = [("root0", _SIGNER.private_key_b64)]
TRUST = TrustRoot(threshold=1, authorizers=[
    AuthorizerKey(key_id="root0", name="root0", public_key_b64=_SIGNER.public_key_b64)])

_DEPRECATED_BRANCH = "tls_weakness.deprecated_protocol_offer"
_WEAK_CIPHER_BRANCH = "tls_weakness.weak_cipher_offer"
_CERT_BRANCH = "tls_weakness.certificate_validity"

#: A genuinely strong server suite list. Python's DEFAULT PROTOCOL_TLS_SERVER list on this OpenSSL build
#: contains ANONYMOUS key exchange (ADH / AECDH — no server authentication), so "leave it at the
#: default" does not produce a strong endpoint and a negative control built that way would not be one.
_STRONG_SUITES = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"


# ===================================================================================================
# Fixtures: isolation, charter, certificates, servers, and the sslscan stand-in.
# ===================================================================================================
@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path, host="127.0.0.1", slug="alpha"):
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `t`  Date: `2026-09-26`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n## 7. Posture\n\n- [x] **TEST**\n",
        encoding="utf-8")


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _leaf(*, cn="vigil-tls-breadth.test", sans=None, not_before_days=-1, not_after_days=365, issuer=None):
    """A 2048-bit RSA leaf. ``issuer=(ca_cert, ca_key)`` makes it CA-issued (issuer != subject, so it is NOT
    self-signed); omitted, it is self-signed. Returns (cert, key)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer_name = issuer[0].subject if issuer else subject
    signing_key = issuer[1] if issuer else key
    b = (x509.CertificateBuilder()
         .subject_name(subject).issuer_name(issuer_name)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(_now() + datetime.timedelta(days=not_before_days))
         .not_valid_after(_now() + datetime.timedelta(days=not_after_days)))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return b.sign(signing_key, hashes.SHA256()), key


def _ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "VIGIL Wave3 Test CA")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(_now() - datetime.timedelta(days=1))
            .not_valid_after(_now() + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert, key


def _pem(cert, key):
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                              serialization.NoEncryption()))


def _der_b64(cert) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")


class _TLSServer:
    """A threaded loopback TLS server with an explicitly controlled protocol range and cipher list."""

    def __init__(self, cert_pem: bytes, key_pem: bytes, *, min_version, max_version,
                 ciphers: "str | None" = None, seclevel0: bool = True, tmp: "Path | None" = None):
        import tempfile
        d = Path(tmp or tempfile.mkdtemp())
        cf, kf = d / "c.pem", d / "k.pem"
        cf.write_bytes(cert_pem)
        kf.write_bytes(key_pem)
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if seclevel0:
            self._ctx.set_ciphers((ciphers or "ALL") + ":@SECLEVEL=0")
        elif ciphers:
            self._ctx.set_ciphers(ciphers)
        self._ctx.minimum_version = min_version
        self._ctx.maximum_version = max_version
        self._ctx.load_cert_chain(str(cf), str(kf))
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop:
            try:
                self._sock.settimeout(0.4)
                raw, _ = self._sock.accept()
            except (TimeoutError, socket.timeout, OSError):
                continue
            threading.Thread(target=self._handle, args=(raw,), daemon=True).start()

    def _handle(self, raw):
        try:
            with self._ctx.wrap_socket(raw, server_side=True) as t:
                t.settimeout(2.0)
                t.recv(16)
        except (ssl.SSLError, OSError):
            pass
        finally:
            try:
                raw.close()
            except OSError:
                pass

    def close(self):
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass


class _BlackHole:
    """Accepts the TCP connection and then says NOTHING — the shape a client cannot distinguish from a slow
    server, and the exact shape that must never launder into CLEAN."""

    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self._held: list = []
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop:
            try:
                self._sock.settimeout(0.4)
                raw, _ = self._sock.accept()
            except (TimeoutError, socket.timeout, OSError):
                continue
            self._held.append(raw)          # hold it open, send nothing

    def close(self):
        self._stop = True
        for s in self._held:
            try:
                s.close()
            except OSError:
                pass
        try:
            self._sock.close()
        except OSError:
            pass


def _closed_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _FakeSslscan:
    """The PROPOSER. It says "there is a TLS service here" and nothing more — every claim in this file is
    produced by VIGIL's own handshakes, never by these bytes."""
    name = "fake-sslscan"

    def available(self):
        return True, ""

    def run(self, argv, *, timeout=0):
        return ToolOutcome(list(argv), 0, "Connected to 127.0.0.1\nTesting SSL server\n", "", self.name)


def _gate():
    return ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)


def _run(port, tmp_path, timeout=20.0):
    _charter(tmp_path)
    return run_external_tool(tls_scan(port=port), "127.0.0.1", scope_gate=_gate(),
                             backend=_FakeSslscan(), engagement_slug="alpha", signers=SIGNERS,
                             timeout=timeout)


def _outcomes(res, label):
    return [o for o in res.outcomes if o["check_id"].endswith("@" + label)]


def _facts(res, label):
    return [f for f in res.facts if str(getattr(f, "finding_ref", "")).endswith("@" + label)]


# ===================================================================================================
# 0. STRUCTURE — the budget, the registry, and the closed vocabularies.
# ===================================================================================================
def test_the_handshake_budget_is_structural_not_a_comment():
    """``run_external_tool`` memoises ONE capture per DISTINCT capture callable per proposed service, so the
    number of distinct callables on the spec IS the per-endpoint handshake budget. Pinning it here means the
    budget cannot drift by someone adding a re-drive with a fresh capture function."""
    spec = tls_scan(port=443)
    distinct = {id(r.capture) for r in spec.redrives}
    assert len(distinct) == tb.TLS_HANDSHAKE_BUDGET_PER_ENDPOINT == 4, (
        f"{len(distinct)} distinct captures != declared budget {tb.TLS_HANDSHAKE_BUDGET_PER_ENDPOINT}")
    # and every re-drive that shares a bug_class carries a discriminating label, so no two overwrite each
    # other's retained context
    keys = [(r.bug_class, r.label) for r in spec.redrives]
    assert len(set(keys)) == len(keys), f"two re-drives collide on (bug_class, label): {keys}"


def test_the_three_new_branches_are_registered_with_the_capability_they_actually_have():
    import json
    branches = {b["id"]: b for b in json.loads(
        Path(__file__).resolve().parents[2].joinpath(
            "docs/capability-matrix/evidence-branches.json").read_text(encoding="utf-8"))["branches"]}

    dep = branches[_DEPRECATED_BRANCH]
    assert dep["fact_capable"] is True and dep["clean_capable"] is True
    assert dep["oracle_version"] == "tls_weakness"
    assert "channel_established" in dep["preconditions"] and "gate_authorized" in dep["preconditions"]

    wc = branches[_WEAK_CIPHER_BRANCH]
    assert wc["fact_capable"] is True and wc["clean_capable"] is False, (
        "a weak-cipher refusal may not be sold as clean — the local build limits what can be offered")
    assert len((wc.get("blocking_work") or "").strip()) > 40

    cv = branches[_CERT_BRANCH]
    assert cv["fact_capable"] is False and cv["clean_capable"] is False, (
        "certificate validity is LEAD-only: no OracleKind adjudicates it")
    assert cv["oracle_version"] == "", "a LEAD-only branch names no oracle"
    assert "lead-only" in cv["limitation"].lower()


def test_the_weak_cipher_vocabulary_is_a_closed_list_not_a_pattern():
    """Membership, never a pattern. A modern AEAD suite whose NAME contains a weak token as a substring
    (``TLS_AES_128_GCM_SHA256`` contains ``AES``; ``ECDHE-ECDSA-AES128-GCM-SHA256`` contains ``DES`` inside
    ``ECDSA``) is not in the offer and is never reported as negotiated-weak."""
    assert "TLS_AES_128_GCM_SHA256" not in tb.WEAK_CIPHER_OFFER
    assert "ECDHE-ECDSA-AES128-GCM-SHA256" not in tb.WEAK_CIPHER_OFFER
    strong = {"connected": True, "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256",
              "offered_ciphers": list(tb.WEAK_CIPHER_OFFER)}
    assert tb.negotiated_weak_cipher(strong) == "", (
        "a suite outside the recorded offer was scored as a negotiated weak cipher")
    weak = {"connected": True, "cipher": "NULL-SHA256", "offered_ciphers": ["NULL-SHA256", "RC4-MD5"]}
    assert tb.negotiated_weak_cipher(weak) == "NULL-SHA256"
    # the membership set is the offer RECORDED IN THIS CAPTURE, not the global vocabulary
    off_offer = {"connected": True, "cipher": "RC4-MD5", "offered_ciphers": ["NULL-SHA256"]}
    assert tb.negotiated_weak_cipher(off_offer) == "", (
        "a suite VIGIL did not offer in THIS capture must not be scored")


def test_offerable_weak_ciphers_is_a_subset_of_the_closed_vocabulary_and_sends_nothing():
    offerable = tb.offerable_weak_ciphers()
    assert set(offerable) <= set(tb.WEAK_CIPHER_OFFER)
    # an empty offer means NOTHING was tested — the capture must say so rather than imply a negative
    empty = tb.capture_weak_cipher_handshake("127.0.0.1", 1, slug="alpha", offer=())
    assert empty["connected"] is False
    assert empty["failure_class"] == tb.FAILURE_LOCAL_UNSUPPORTED
    assert empty["offered_ciphers"] == []
    assert empty["tcp_established"] is False


# ===================================================================================================
# 1. THE CLEAN PREDICATE — the single most attackable decision in the slice.
# ===================================================================================================
def _refusal(**over):
    ev = {"connected": False, "host": "h", "port": 443, "gate_authorized": True, "tcp_established": True,
          "offered_only_version": "TLSv1", "failure_class": tb.FAILURE_VERSION_REJECTED,
          "ssl_reason": "TLSV1_ALERT_PROTOCOL_VERSION"}
    ev.update(over)
    return ev


def test_only_a_peer_protocol_version_alert_on_an_open_channel_is_conclusive():
    assert tb.is_conclusive_protocol_refusal(_refusal()) is True
    assert tb.is_conclusive_protocol_refusal(_refusal(offered_only_version="TLSv1.1")) is True


@pytest.mark.parametrize("over,why", [
    ({"connected": True}, "a COMPLETED handshake is claim 1, never the clean"),
    ({"tcp_established": False}, "a negative the peer never had a chance to state"),
    ({"gate_authorized": False}, "the gate refused — nothing was sent"),
    ({"failure_class": tb.FAILURE_TRANSPORT, "ssl_reason": ""}, "a timeout/reset is not a refusal"),
    ({"failure_class": tb.FAILURE_GATE_REFUSED, "ssl_reason": ""}, "a gate refusal is not a refusal"),
    ({"failure_class": tb.FAILURE_LOCAL_UNSUPPORTED, "ssl_reason": "NO_PROTOCOLS_AVAILABLE"},
     "OUR stack could not offer it — a gap in VIGIL, not a statement by the endpoint"),
    ({"failure_class": tb.FAILURE_TLS_OTHER, "ssl_reason": "SSLV3_ALERT_HANDSHAKE_FAILURE"},
     "alert(40) is ambiguous — a server sends it for no shared cipher too"),
    ({"ssl_reason": "SSLV3_ALERT_HANDSHAKE_FAILURE"},
     "a forged failure_class alone must not manufacture a clean — the reason is checked too"),
    ({"ssl_reason": ""}, "no recorded peer reason"),
    ({"offered_only_version": "TLSv1.2"}, "we did not narrow the offer to a DEPRECATED version"),
    ({"offered_only_version": ""}, "no restricted offer was recorded"),
])
def test_every_other_shape_is_inconclusive_never_clean(over, why):
    assert tb.is_conclusive_protocol_refusal(_refusal(**over)) is False, why


def test_the_predicate_rejects_non_dict_and_empty_evidence():
    for bad in (None, "", 0, [], {}):
        assert tb.is_conclusive_protocol_refusal(bad) is False


def test_the_version_rejection_vocabulary_is_a_closed_singleton():
    """A pin, so widening it is a reviewed edit rather than a drift. Each excluded reason is excluded for a
    stated cause (see VERSION_REJECTION_REASONS' docstring); admitting any of them would let a non-version
    failure launder into a clean bill of health for that version."""
    assert tb.VERSION_REJECTION_REASONS == frozenset({"TLSV1_ALERT_PROTOCOL_VERSION"})
    for excluded in ("SSLV3_ALERT_HANDSHAKE_FAILURE", "TLSV1_ALERT_INSUFFICIENT_SECURITY",
                     "WRONG_VERSION_NUMBER", "UNSUPPORTED_PROTOCOL", "CERTIFICATE_VERIFY_FAILED"):
        assert excluded not in tb.VERSION_REJECTION_REASONS


def test_admission_turns_the_predicate_into_the_verdict_at_the_choke():
    """The predicate only computes ``conclusive``; ``verdict.admit`` is what produces the verdict, under the
    branch's declared capability AND its declared preconditions. Both halves are asserted here, including
    the independent second guard: an observation with no established channel is INCONCLUSIVE even if a
    caller claimed conclusive=True."""
    from vigil_integration.live import verdict as V

    ok = {"gate_authorized": True, "channel_established": True}
    assert V.admit(_DEPRECATED_BRANCH, fired=False, conclusive=True, observed=ok).verdict is V.Verdict.CLEAN
    assert V.admit(_DEPRECATED_BRANCH, fired=True, conclusive=True, observed=ok).verdict is V.Verdict.FACT
    assert V.admit(_DEPRECATED_BRANCH, fired=False, conclusive=False,
                   observed=ok).verdict is V.Verdict.INCONCLUSIVE
    no_channel = {"gate_authorized": True, "channel_established": False}
    assert V.admit(_DEPRECATED_BRANCH, fired=False, conclusive=True,
                   observed=no_channel).verdict is V.Verdict.INCONCLUSIVE, (
        "a branch with no established channel cleared itself — the precondition guard is not load-bearing")
    # the weak-cipher branch may NEVER clear, whatever conclusiveness is claimed
    assert V.admit(_WEAK_CIPHER_BRANCH, fired=False, conclusive=True,
                   observed=ok).verdict is V.Verdict.INCONCLUSIVE
    # the certificate-validity branch may neither mint nor clear
    assert V.admit(_CERT_BRANCH, fired=True, conclusive=True, observed=ok).verdict is V.Verdict.LEAD
    assert V.admit(_CERT_BRANCH, fired=False, conclusive=True, observed=ok).verdict is V.Verdict.INCONCLUSIVE


# ===================================================================================================
# 2. CLAIM 1 + 2 — deprecated protocol accepted (FACT) / refused (CLEAN), live.
# ===================================================================================================
def test_a_tls10_accepting_server_mints_a_deprecated_protocol_fact_that_reverifies_offline(tmp_path):
    from framework.v2.evidence.certify import verify_certificate

    cert, key = _leaf(sans=[x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))])
    cpem, kpem = _pem(cert, key)
    srv = _TLSServer(cpem, kpem, min_version=ssl.TLSVersion.TLSv1, max_version=ssl.TLSVersion.TLSv1_2)
    try:
        res = _run(srv.port, tmp_path)
    finally:
        srv.close()

    assert res.status == "ran"
    facts = _facts(res, "offer_tls1_0")
    assert facts, (
        "a server that completed a TLS1.0-only handshake minted no deprecated-protocol FACT; "
        f"outcomes={res.outcomes}")
    fact = facts[0]
    ctx = res.contexts[fact.finding_ref]
    assert ctx["tls"]["tls_version"] == "TLSv1"
    assert ctx["tls"]["offered_only_version"] == "TLSv1"
    assert verify_certificate(fact.signed, oracle_context=ctx, trust_root=TRUST).ok is True, (
        "the deprecated-protocol FACT did not re-verify offline")
    # TLS1.1 was offered separately and also accepted by this server
    assert _facts(res, "offer_tls1_1"), "the TLS1.1-only probe minted nothing against a TLS1.0-1.2 server"


def test_a_tampered_deprecated_protocol_capture_fails_offline_reverification(tmp_path):
    """The certificate binds the retained context. Rewriting the negotiated version to a modern one both
    breaks the digest AND stops the oracle firing, so the tampered record does not re-verify."""
    from framework.v2.evidence.certify import verify_certificate

    cert, key = _leaf()
    cpem, kpem = _pem(cert, key)
    srv = _TLSServer(cpem, kpem, min_version=ssl.TLSVersion.TLSv1, max_version=ssl.TLSVersion.TLSv1_2)
    try:
        res = _run(srv.port, tmp_path)
    finally:
        srv.close()
    fact = _facts(res, "offer_tls1_0")[0]
    good = res.contexts[fact.finding_ref]
    tampered = {**good, "tls": {**good["tls"], "tls_version": "TLSv1.3"}}
    assert verify_certificate(fact.signed, oracle_context=tampered, trust_root=TRUST).ok is False, (
        "a TAMPERED retained capture re-verified — the certificate does not bind its evidence")


def test_a_tls12_only_server_does_not_mint_tls10_accepted_and_admits_the_clean(tmp_path):
    """THE same-shape negative control for claim 1, and the positive for claim 2."""
    cert, key = _leaf()
    cpem, kpem = _pem(cert, key)
    # STRONG in every dimension the other probes look at, so this is a single-variable negative control
    # for the VERSION claim. (Python's default server suite list on this OpenSSL contains ANONYMOUS
    # key exchange, which the weak-cipher probe would correctly flag — that would be a true finding,
    # but it would muddy what this test is isolating.)
    srv = _TLSServer(cpem, kpem, min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_3,
                     ciphers=_STRONG_SUITES, seclevel0=False)
    try:
        res = _run(srv.port, tmp_path)
    finally:
        srv.close()

    assert res.status == "ran"
    assert not _facts(res, "offer_tls1_0"), "a TLS1.2+-only server minted a 'TLS1.0 accepted' FACT"
    assert not _facts(res, "offer_tls1_1"), "a TLS1.2+-only server minted a 'TLS1.1 accepted' FACT"
    for label in ("offer_tls1_0", "offer_tls1_1"):
        outs = _outcomes(res, label)
        assert outs, f"the {label} probe produced no outcome at all"
        assert all(o["outcome"] == Outcome.CLEAN.value for o in outs), (
            f"the {label} probe against a TLS1.2+-only server must be CLEAN (the peer sent "
            f"protocol_version(70)); got {outs}")


def test_the_clean_is_reproducible_offline_from_the_retained_capture(tmp_path):
    """A CLEAN is not a signed certificate in this system (only FACTs are signed), so what makes it
    auditable is that the deterministic predicate re-runs over the RETAINED capture and gives the same
    answer — with no clock, no network and no live handle."""
    cert, key = _leaf()
    cpem, kpem = _pem(cert, key)
    srv = _TLSServer(cpem, kpem, min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_3,
                     ciphers=_STRONG_SUITES, seclevel0=False)
    try:
        res = _run(srv.port, tmp_path)
    finally:
        srv.close()
    refs = [o["check_id"] for o in _outcomes(res, "offer_tls1_0")]
    ctx = res.contexts[refs[0]]
    retained = ctx["tls"]
    assert tb.is_conclusive_protocol_refusal(retained) is True
    assert retained["ssl_reason"] == "TLSV1_ALERT_PROTOCOL_VERSION"
    assert retained["tcp_established"] is True and retained["gate_authorized"] is True
    # and a tamper of the retained reason removes the CLEAN
    assert tb.is_conclusive_protocol_refusal(
        {**retained, "ssl_reason": "SSLV3_ALERT_HANDSHAKE_FAILURE"}) is False


# ===================================================================================================
# 3. THE LAUNDERING PIN — a host that times out or resets is INCONCLUSIVE, never CLEAN.
# ===================================================================================================
def test_a_black_hole_host_is_inconclusive_never_clean(tmp_path):
    """A host that accepts the TCP connection and then says nothing is the single most dangerous shape: the
    channel IS established, so the ``channel_established`` precondition alone would not save us. Only the
    failure-class predicate does. This must be INCONCLUSIVE."""
    _charter(tmp_path)
    hole = _BlackHole()
    try:
        ev = tb.capture_version_restricted_handshake(
            "127.0.0.1", hole.port, slug="alpha", version_attr="TLSv1", version_label="TLSv1", timeout=1.0)
    finally:
        hole.close()

    assert ev["connected"] is False
    assert ev["tcp_established"] is True, "precondition of this test: the channel really came up"
    assert ev["failure_class"] == tb.FAILURE_TRANSPORT, (
        f"a silent host was classified {ev['failure_class']!r} — only a peer alert(70) may be a refusal")
    assert tb.is_conclusive_protocol_refusal(ev) is False, "A TIMEOUT LAUNDERED INTO A CLEAN"

    from vigil_integration.live import verdict as V
    from vigil_integration.live.external_tool import _tls_probe_observed
    got = V.admit(_DEPRECATED_BRANCH, fired=False,
                  conclusive=tb.is_conclusive_protocol_refusal(ev), observed=_tls_probe_observed(ev))
    assert got.verdict is V.Verdict.INCONCLUSIVE, f"a timed-out host was admitted {got.verdict}"


def test_a_reset_host_is_inconclusive_never_clean(tmp_path):
    """The other transport shape: nothing is listening, so the connect is refused before any TLS byte. No
    channel ⇒ both the predicate AND the precondition guard reject it."""
    _charter(tmp_path)
    ev = tb.capture_version_restricted_handshake(
        "127.0.0.1", _closed_port(), slug="alpha", version_attr="TLSv1", version_label="TLSv1", timeout=2.0)
    assert ev["connected"] is False and ev["tcp_established"] is False
    assert ev["failure_class"] == tb.FAILURE_TRANSPORT
    assert tb.is_conclusive_protocol_refusal(ev) is False, "A RESET LAUNDERED INTO A CLEAN"

    from vigil_integration.live import verdict as V
    from vigil_integration.live.external_tool import _tls_probe_observed
    assert V.admit(_DEPRECATED_BRANCH, fired=False, conclusive=True,
                   observed=_tls_probe_observed(ev)).verdict is V.Verdict.INCONCLUSIVE


def test_a_closed_port_run_produces_no_clean_and_no_fact_anywhere(tmp_path):
    """The same laundering pin driven through the WHOLE runner rather than the predicate: every re-drive
    over a dead endpoint must be skipped or inconclusive."""
    res = _run(_closed_port(), tmp_path, timeout=10.0)
    assert res.status == "ran"
    assert res.facts == [], f"a dead endpoint minted FACTs: {res.facts}"
    bad = [o for o in res.outcomes if o["outcome"] == Outcome.CLEAN.value]
    assert not bad, f"a dead endpoint produced CLEAN outcomes: {bad}"


def test_a_gate_refusal_sends_nothing_and_is_never_clean(tmp_path):
    """An out-of-charter host: the audited gate refuses inside ``capture_tls_handshake`` before a socket is
    opened, so ``gate_authorized`` is False and no verdict is reachable."""
    _charter(tmp_path, host="127.0.0.1")
    ev = tb.capture_version_restricted_handshake(
        "10.99.99.99", 443, slug="alpha", version_attr="TLSv1", version_label="TLSv1", timeout=1.0)
    assert ev["connected"] is False
    assert ev["gate_authorized"] is False and ev["tcp_established"] is False
    assert ev["failure_class"] == tb.FAILURE_GATE_REFUSED
    assert tb.is_conclusive_protocol_refusal(ev) is False


# ===================================================================================================
# 4. CLAIM 3 — weak cipher negotiated (FACT) vs a strong-cipher-only server (must NOT mint).
# ===================================================================================================
def _weak_offerable_or_skip():
    offerable = tb.offerable_weak_ciphers()
    if not offerable:
        pytest.skip("this OpenSSL build can offer none of the closed weak-cipher vocabulary")
    return offerable


def test_a_weak_cipher_server_mints_a_weak_cipher_fact_that_reverifies_offline(tmp_path):
    from framework.v2.evidence.certify import verify_certificate

    offerable = _weak_offerable_or_skip()
    cert, key = _leaf()
    cpem, kpem = _pem(cert, key)
    # the server offers the SAME weak suites plus a strong one, so the choice is genuinely the server's
    srv = _TLSServer(cpem, kpem, min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_2,
                     ciphers=":".join(offerable) + ":AES128-SHA")
    try:
        res = _run(srv.port, tmp_path)
    finally:
        srv.close()

    facts = _facts(res, "offer_weak_ciphers")
    assert facts, f"a NULL/anon-cipher server minted no weak-cipher FACT; outcomes={res.outcomes}"
    fact = facts[0]
    ctx = res.contexts[fact.finding_ref]
    negotiated = ctx["tls"]["cipher"]
    assert negotiated in set(ctx["tls"]["offered_ciphers"]), (
        "the negotiated suite was not a member of the closed offer recorded in this capture")
    assert negotiated in set(tb.WEAK_CIPHER_OFFER)
    assert verify_certificate(fact.signed, oracle_context=ctx, trust_root=TRUST).ok is True
    tampered = {**ctx, "tls": {**ctx["tls"], "cipher": "ECDHE-RSA-AES256-GCM-SHA384"}}
    assert verify_certificate(fact.signed, oracle_context=tampered, trust_root=TRUST).ok is False, (
        "a TAMPERED negotiated cipher re-verified")


def test_a_tls13_preferring_server_is_still_probed_for_weak_tls12_suites(tmp_path):
    """Without capping the weak-cipher offer at TLS1.2 this server would negotiate a TLS1.3 AEAD suite — one
    outside the recorded offer, which the membership check would rightly decline to score — and the weak
    suite it ALSO supports would silently go untested. The cap is what keeps the restricted offer
    governing."""
    offerable = _weak_offerable_or_skip()
    cert, key = _leaf()
    cpem, kpem = _pem(cert, key)
    srv = _TLSServer(cpem, kpem, min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_3,
                     ciphers=":".join(offerable) + ":AES128-SHA")
    try:
        res = _run(srv.port, tmp_path)
    finally:
        srv.close()
    facts = _facts(res, "offer_weak_ciphers")
    assert facts, (
        "a TLS1.3-capable server that also supports a weak TLS1.2 suite escaped the weak-cipher probe; "
        f"outcomes={res.outcomes}")
    ctx = res.contexts[facts[0].finding_ref]
    assert ctx["tls"]["tls_version"] == "TLSv1.2"
    assert ctx["tls"]["offered_max_version"] == "TLSv1.2"


def test_a_strong_cipher_only_server_mints_no_weak_cipher_fact_and_no_clean(tmp_path):
    """The same-shape negative control for claim 3: the server refuses every weak suite. That is NOT a
    clean — the local build could not even offer most of the vocabulary — so the probe must be skipped or
    inconclusive, and certainly must not mint."""
    _weak_offerable_or_skip()
    cert, key = _leaf()
    cpem, kpem = _pem(cert, key)
    srv = _TLSServer(cpem, kpem, min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_3,
                     ciphers=_STRONG_SUITES, seclevel0=False)
    try:
        res = _run(srv.port, tmp_path)
    finally:
        srv.close()

    assert not _facts(res, "offer_weak_ciphers"), "a strong-cipher-only server minted a weak-cipher FACT"
    outs = _outcomes(res, "offer_weak_ciphers")
    assert all(o["outcome"] != Outcome.CLEAN.value for o in outs), (
        f"the weak-cipher branch leaked a CLEAN on a refusal: {outs}")
    assert all(o["outcome"] == Outcome.SKIPPED.value for o in outs), (
        f"a refused weak-cipher offer must be SKIPPED (nothing was proven, nothing cleared): {outs}")


# ===================================================================================================
# 5. CLAIM 4 — certificate defects re-derived from the RETAINED DER at the RETAINED instant.
# ===================================================================================================
def _cert_evidence(cert, *, host="127.0.0.1", at_epoch=None):
    return {"connected": True, "host": host, "port": 443, "cert_der_b64": _der_b64(cert),
            "captured_at_epoch": int(at_epoch if at_epoch is not None else _now().timestamp()),
            "capture_time_source": "runner_clock"}


def test_an_expired_leaf_is_classified_expired_against_the_retained_instant():
    cert, _ = _leaf(not_before_days=-40, not_after_days=-10)
    rec = tb.classify_certificate_defects(_cert_evidence(cert))
    assert rec is not None and "expired" in rec["defects"]
    assert rec["at_epoch_source"] == "runner_clock"


def test_a_not_yet_valid_leaf_is_classified_not_yet_valid():
    cert, _ = _leaf(not_before_days=10, not_after_days=40)
    rec = tb.classify_certificate_defects(_cert_evidence(cert))
    assert rec is not None and "not_yet_valid" in rec["defects"]


def test_expiry_is_decided_by_the_RETAINED_instant_not_a_wall_clock():
    """THE determinism property. The SAME retained DER yields 'expired' or 'in date' purely as a function of
    the instant retained in the evidence — so an offline re-verification a year from now reproduces the
    verdict the capture supports, instead of silently flipping as the real clock passes notAfter."""
    import ipaddress
    ca = _ca()
    cert, _ = _leaf(sans=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))],
                    not_before_days=-10, not_after_days=10, issuer=ca)
    inside = int((_now()).timestamp())
    after = int((_now() + datetime.timedelta(days=30)).timestamp())
    before = int((_now() - datetime.timedelta(days=30)).timestamp())

    assert tb.classify_certificate_defects(_cert_evidence(cert, at_epoch=inside))["defects"] == []
    assert tb.classify_certificate_defects(_cert_evidence(cert, at_epoch=after))["defects"] == ["expired"]
    assert tb.classify_certificate_defects(
        _cert_evidence(cert, at_epoch=before))["defects"] == ["not_yet_valid"]
    # idempotent: re-running over the same retained evidence gives the identical record
    ev = _cert_evidence(cert, at_epoch=after)
    assert tb.classify_certificate_defects(ev) == tb.classify_certificate_defects(ev)


def test_hostname_mismatch_and_match_are_both_derived_from_the_presented_identities():
    import ipaddress
    ca = _ca()
    mismatch, _ = _leaf(cn="other.example", sans=[x509.DNSName("other.example")], issuer=ca)
    rec = tb.classify_certificate_defects(_cert_evidence(mismatch))
    assert "hostname_mismatch" in rec["defects"]
    assert "other.example" in rec["presented_identities"]

    match, _ = _leaf(sans=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))], issuer=ca)
    assert "hostname_mismatch" not in tb.classify_certificate_defects(_cert_evidence(match))["defects"]

    wild, _ = _leaf(cn="*.example.test", sans=[x509.DNSName("*.example.test")], issuer=ca)
    assert "hostname_mismatch" not in tb.classify_certificate_defects(
        _cert_evidence(wild, host="api.example.test"))["defects"]
    assert "hostname_mismatch" in tb.classify_certificate_defects(
        _cert_evidence(wild, host="a.b.example.test"))["defects"], (
        "a wildcard matched more than one label")


def test_self_signed_needs_issuer_equals_subject_AND_a_self_verifying_signature():
    import ipaddress
    selfsigned, _ = _leaf(sans=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    assert "self_signed" in tb.classify_certificate_defects(_cert_evidence(selfsigned))["defects"]
    ca = _ca()
    issued, _ = _leaf(sans=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))], issuer=ca)
    assert "self_signed" not in tb.classify_certificate_defects(_cert_evidence(issued))["defects"]


def test_a_valid_in_date_hostname_matching_ca_issued_cert_reports_no_defect():
    """THE same-shape negative control for claim 4: a clean certificate must produce an EMPTY defect list,
    and the runner's context builder must therefore produce no lead at all."""
    import ipaddress
    from vigil_integration.live.external_tool import _certificate_validity_context
    ca = _ca()
    good, _ = _leaf(sans=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))], issuer=ca)
    ev = _cert_evidence(good)
    assert tb.classify_certificate_defects(ev)["defects"] == []
    assert _certificate_validity_context(ev) is None, "a defect-free certificate produced a lead"


def test_missing_or_unparseable_inputs_judge_nothing_rather_than_clearing():
    cert, _ = _leaf()
    assert tb.classify_certificate_defects(None) is None
    assert tb.classify_certificate_defects({"connected": True}) is None                 # no cert
    assert tb.classify_certificate_defects({"cert_der_b64": _der_b64(cert)}) is None    # no instant
    assert tb.classify_certificate_defects(
        {"cert_der_b64": base64.b64encode(b"not a certificate").decode(), "captured_at_epoch": 1}) is None


def test_the_certificate_validity_branch_can_neither_mint_nor_clear_end_to_end(tmp_path):
    """LEAD-only, proven through the whole runner against a server presenting an EXPIRED, mismatched,
    self-signed leaf — the strongest possible input. It must still produce no FACT and no CLEAN."""
    cert, key = _leaf(cn="wrong.example", sans=[x509.DNSName("wrong.example")],
                      not_before_days=-40, not_after_days=-10)
    cpem, kpem = _pem(cert, key)
    srv = _TLSServer(cpem, kpem, min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_3,
                     seclevel0=False)
    try:
        res = _run(srv.port, tmp_path)
    finally:
        srv.close()

    outs = _outcomes(res, "cert_validity")
    assert outs, f"the certificate-validity re-drive produced no outcome; outcomes={res.outcomes}"
    assert not _facts(res, "cert_validity"), "a LEAD-only branch minted a FACT"
    assert all(o["outcome"] != Outcome.CLEAN.value for o in outs), f"a LEAD-only branch cleared: {outs}"
    # the classification IS retained for the operator even though it cannot be promoted
    ref = outs[0]["check_id"]
    if ref in res.contexts:
        record = res.contexts[ref]["certificate_validity"]
        assert "expired" in record["defects"] and "hostname_mismatch" in record["defects"]
        assert "self_signed" in record["defects"]
        assert record["at_epoch"] == record["at_epoch"] and record["at_epoch"] > 0


# ===================================================================================================
# 6. THE CONFORMANCE BATTERY — a tool may not be fact_capable until its ToolSpec passes it.
# ===================================================================================================
class _LyingSslscan:
    """Claims a TLS service where there is none — the criterion-6 firewall: a say-so never confirms."""
    name = "lying-sslscan"

    def available(self):
        return True, ""

    def run(self, argv, *, timeout=0):
        return ToolOutcome(list(argv), 0, "Connected to 127.0.0.1\nAccepted  TLSv1.0  RC4-MD5\n", "",
                           self.name)


def test_the_wave3_tls_toolspec_passes_the_full_conformance_battery(tmp_path):
    """``sslscan`` stays ``fact_capable: true`` in the matrix only while its ToolSpec — now carrying the
    WAVE-3 re-drives — passes every REQUIRED_PROPERTY through the real gated runner."""
    from framework.v2.authority import KillSwitch
    from vigil_integration.live.conformance import REQUIRED_PROPERTIES, run_toolspec_conformance

    _charter(tmp_path, "127.0.0.1")
    cert, key = _leaf()
    cpem, kpem = _pem(cert, key)
    srv = _TLSServer(cpem, kpem, min_version=ssl.TLSVersion.TLSv1, max_version=ssl.TLSVersion.TLSv1_2)
    dead = _closed_port()
    halt = tmp_path / "alpha.halt"
    try:
        report = run_toolspec_conformance(
            tool_name="sslscan",
            positive_spec=tls_scan(port=srv.port), positive_backend=_FakeSslscan(),
            deceptive_spec=tls_scan(port=dead), deceptive_backend=_LyingSslscan(),
            target="127.0.0.1",
            scope_gate_in=_gate(),
            scope_gate_out=ScopeGate(scope=StaticScopeSource(["10.99.99.99"]),
                                     loopback_allowed_if_scoped=True),
            engagement_slug="alpha", signers=SIGNERS, trust_root=TRUST,
            trip_killswitch=lambda: KillSwitch("alpha").trip("conformance"),
            clear_killswitch=lambda: halt.unlink(missing_ok=True),
            timeout=30.0)
    finally:
        srv.close()

    assert report.conformant, report.summary() + " | notes: " + "; ".join(report.notes)
    for prop in REQUIRED_PROPERTIES:
        assert report.checks.get(prop) is True, f"{prop} not satisfied: {report.summary()}"


# ===================================================================================================
# 7. NO NEW EGRESS PATH — every WAVE-3 capture goes through the SAME audited gate.
# ===================================================================================================
def test_every_wave3_capture_goes_through_capture_tls_handshake(monkeypatch):
    """Structural: ``tls_breadth`` opens no socket of its own — it INJECTS its connector into
    ``verify.tls.capture_tls_handshake``, so the kill-switch / single-host / ACTIVE_RECON / charter-scope
    gate and the one-bounded-attempt shape are exactly the ones the pre-existing TLS re-drive already used.
    Asserted by replacing that one function and observing that every probe stops."""
    import framework.v2.verify as fv

    calls: list = []

    def fake(host, port=443, *, slug="", timeout=5.0, connect=None):
        calls.append((host, port, slug))
        return {"connected": False, "host": host, "port": port, "error": "stubbed"}

    monkeypatch.setattr(fv, "capture_tls_handshake", fake)
    tb.capture_version_restricted_handshake("127.0.0.1", 8443, slug="alpha", version_attr="TLSv1")
    tb.capture_weak_cipher_handshake("127.0.0.1", 8443, slug="alpha")
    assert len(calls) == 2 and {c[2] for c in calls} == {"alpha"}, (
        f"a WAVE-3 capture bypassed the audited gate; calls={calls}")


def test_tls_breadth_imports_no_framework_at_module_load():
    """FATAL-2: the offense engine must not be co-loaded by importing a sovereign live module."""
    import ast
    src = Path(__file__).resolve().parents[2].joinpath(
        "integration/vigil_integration/live/tls_breadth.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in tree.body:                      # MODULE-LEVEL statements only
        if isinstance(node, ast.Import):
            assert not any(a.name.split(".")[0] == "framework" for a in node.names)
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] != "framework", (
                f"module-level framework import at line {node.lineno} breaks the two-env boundary")
