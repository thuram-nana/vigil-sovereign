"""HexStrike WAVE 3 — breadth of TLS CLAIMS, each red-penned against a same-shape negative control.

Every claim in ``live.tls_breadth`` is exercised here against REAL loopback TLS servers, through the REAL
gated runner (``run_external_tool``), with the tool reduced to what it is — a proposer whose bytes are never
evidence. For each claim there is a positive fixture that MUST mint and a same-shape negative that MUST NOT:

  * a TLS1.0-accepting server mints "deprecated protocol accepted"; a TLS1.2/1.3-only server does NOT,
    and is admitted INCONCLUSIVE — NEVER CLEAN. The branch was clean-capable for one commit and was
    DEMOTED: the refusal and the corroborating handshake are on two different TCP connections and nothing
    binds them to one peer, so a round-robin TLS pool clears a version it accepts. That pool is a
    permanent negative control here (``test_a_round_robin_tls_pool_would_have_been_falsely_cleared``);
  * a NULL-cipher server mints "weak cipher negotiated"; a strong-cipher-only server does NOT;
  * an expired / not-yet-valid / mismatched / self-signed leaf is classified by the (UNWIRED) claim-4
    derivation; a CA-issued, in-date, IP-matching leaf is not;
  * a host that TIMES OUT or resets is INCONCLUSIVE and NEVER CLEAN — the laundering bug this slice is most
    exposed to, pinned by name in ``test_a_black_hole_host_is_inconclusive_never_clean`` and
    ``test_a_reset_host_is_inconclusive_never_clean``;
  * a socket that is NOT a TLS service but replies to every ClientHello with the same seven-byte
    ``alert(70) protocol_version`` record does not even reach a conclusive refusal — pinned in
    ``test_a_bare_alert70_emitter_is_never_clean`` and ``..._end_to_end``. ``channel_established`` alone
    does not exclude it; the peer-TLS-session witness does. That witness and the closed reason set are
    KEPT and still exercised sub-condition by sub-condition, even though the branch no longer reaches
    CLEAN: they are the right guards if a sound CLEAN ever becomes reachable, and the weak-cipher
    membership guard is defended the same way by
    ``test_a_substring_rule_would_score_a_suite_the_endpoint_was_never_offered``.

Each positive is additionally re-verified OFFLINE from its certificate, and a TAMPERED retained capture is
shown to FAIL that re-verification.

Offense-process test (imports ``framework.*`` behind an ``importorskip``, so in the SOVEREIGN leg it is
collected and SKIPPED). It therefore runs in exactly one CI job: the offense leg of the "integration
two-env boundary (P5)" job, where it is listed explicitly in ``.github/workflows/ci.yml``. That listing is
not optional — ``test_ci_framework_tests_run_in_offense_leg.py`` fails the build if a file like this one is
missing from it, precisely so a suite cannot go green by never running.

THE VERSION PROBE OFFERS ``ALL:@SECLEVEL=0`` (see ``tls_breadth._restricted_connect``), so it puts a
deprecated ClientHello on the wire on any host whose OpenSSL still compiles TLS1.0/1.1 in — a stock
``@SECLEVEL=2`` box included. The only host that cannot is one built ``no-tls1``, and whether THAT is the
case is a property of its OpenSSL, not of the product; it decides which path the two FACT positives take.
See "THE DEPRECATED-PROTOCOL OFFER MODE" below: the mode is MEASURED at import, named in the pytest
warnings summary and in every assertion it affects, and it is never a skip. The one ``pytest.skip`` left in
this file (``_weak_offerable_or_skip``, for a build that can offer none of the closed weak-cipher
vocabulary) is itself backstopped by
``test_the_two_fact_classes_keep_positive_coverage_whatever_this_host_can_offer``, which reddens rather
than skips if either FACT class ends a run with no positive.
"""
from __future__ import annotations

import base64
import datetime
import socket
import ssl
import threading
import warnings
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


class _BareAlert70Emitter:
    """NOT A TLS SERVICE. It accepts the TCP connection and writes ONE well-formed seven-byte TLS record —
    ``alert(fatal, protocol_version(70))`` — to whatever connects, then closes. It never completes a
    handshake, at any version, ever.

    This is the shape the CLEAN predicate is most exposed to, and the one ``channel_established`` cannot
    exclude: the channel really is established and the peer really did send ``alert(70)``, so every
    condition except the peer-TLS-session witness is satisfied. Clearing it would mean asserting "this
    endpoint does not accept TLS1.0" about a host VIGIL never spoke TLS to."""

    #: content_type=21 (alert) | legacy_record_version 0x0303 | length 2 | level=2 (fatal) | desc=70
    RECORD = bytes([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46])

    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self.served = 0
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop:
            try:
                self._sock.settimeout(0.4)
                raw, _ = self._sock.accept()
            except (TimeoutError, socket.timeout, OSError):
                continue
            self.served += 1
            threading.Thread(target=self._handle, args=(raw,), daemon=True).start()

    def _handle(self, raw):
        try:
            raw.settimeout(2.0)
            try:
                raw.recv(4096)          # swallow the ClientHello, whatever it offered
            except OSError:
                pass
            raw.sendall(self.RECORD)
        except OSError:
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


class _RoundRobinTlsPool:
    """ONE listening socket, TWO real OpenSSL backends, alternating per accepted connection — the shape of
    a Kubernetes Service with two pods, an haproxy/nginx TCP pool, an L4 VIP, or a DNS A-record pool
    mid-rollout.

    Backend A speaks TLS1.0-1.2. Backend B is TLS1.2+ only, so it answers a TLS1.0-only ClientHello with a
    genuine ``alert(70) protocol_version``. Every byte on the wire is real: this is not a stub, it is two
    stock ``PROTOCOL_TLS_SERVER`` contexts on one port.

    THIS IS A PERMANENT NEGATIVE CONTROL. It is the fixture that withdrew the CLEAN from
    ``tls_weakness.deprecated_protocol_offer``: VIGIL's TLS1.0 probe lands on B and retains a genuine
    refusal, its baseline probe lands on A and retains a genuine completed session, every guard in
    ``is_conclusive_protocol_refusal`` is satisfied, and the endpoint accepts TLS1.0 anyway. Nothing in
    the retained evidence can tell — ``minimum_version=TLSv1.1`` is a legal configuration, so "refused at
    TLS1.0, completed at TLS1.1" is internally consistent, and the refusing peer presents no certificate
    for the completed peer's ``spki_sha256`` to bind against."""

    def __init__(self, cert_pem: bytes, key_pem: bytes):
        import tempfile
        d = Path(tempfile.mkdtemp())
        cf, kf = d / "c.pem", d / "k.pem"
        cf.write_bytes(cert_pem)
        kf.write_bytes(key_pem)

        def ctx(minv, maxv, ciphers, seclevel0):
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            if seclevel0:
                c.set_ciphers(ciphers + ":@SECLEVEL=0")
            else:
                c.set_ciphers(ciphers)
            c.minimum_version = minv
            c.maximum_version = maxv
            c.load_cert_chain(str(cf), str(kf))
            return c

        self._a = ctx(ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_2, "ALL", True)     # accepts TLS1.0
        self._b = ctx(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3, _STRONG_SUITES, False)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self.n = 0
        self.log: list = []
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop:
            try:
                self._sock.settimeout(0.4)
                raw, _ = self._sock.accept()
            except (TimeoutError, socket.timeout, OSError):
                continue
            i, self.n = self.n, self.n + 1
            threading.Thread(target=self._handle, args=(raw, i), daemon=True).start()

    def _handle(self, raw, i):
        which = "A" if i % 2 == 0 else "B"
        try:
            with (self._a if which == "A" else self._b).wrap_socket(raw, server_side=True) as t:
                self.log.append((i, which, t.version()))
                t.settimeout(2.0)
                try:
                    t.recv(16)
                except OSError:
                    pass
        except (ssl.SSLError, OSError) as e:
            self.log.append((i, which, "REFUSED:" + type(e).__name__))
        finally:
            try:
                raw.close()
            except OSError:
                pass

    def accepts_tls10(self, attempts: int = 6) -> list:
        """GROUND TRUTH, measured on the SAME (host, port) with TLS1.0-only ClientHellos."""
        seen = []
        for _ in range(attempts):
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            c.set_ciphers("ALL:@SECLEVEL=0")
            c.minimum_version = ssl.TLSVersion.TLSv1
            c.maximum_version = ssl.TLSVersion.TLSv1
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=3) as raw:
                    with c.wrap_socket(raw, server_hostname="127.0.0.1") as t:
                        seen.append(t.version())
            except (ssl.SSLError, OSError) as e:
                seen.append("REFUSED:" + type(e).__name__)
        return seen

    def close(self):
        self._stop = True
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
# THE DEPRECATED-PROTOCOL OFFER MODE — measured on THIS box, named in the output, never a silent skip.
#
# A deprecated-protocol FACT requires VIGIL to put a TLS1.0-only (then TLS1.1-only) ClientHello ON THE
# WIRE. As of the ``@SECLEVEL=0`` fix in ``tls_breadth._restricted_connect`` the version probe does that on
# any host whose OpenSSL still has TLS1.0/1.1 COMPILED IN — INCLUDING a stock Debian/Ubuntu box with
# ``CipherString = DEFAULT:@SECLEVEL=2``. The probe now offers ``ALL:@SECLEVEL=0`` on the version path, so
# OpenSSL's ``ssl_security(SSL_SECOP_VERSION)`` screen no longer strips the deprecated versions from the
# ClientHello version table (it grants the target nothing — see the module docstring and the connector
# comment). Before that fix a stock host aborted with ``NO_PROTOCOLS_AVAILABLE`` / ``local_unsupported``
# and the whole capability was inert; that failure is what reddened CI, and it is now fixed AT THE SOURCE
# rather than worked around here.
#
# So there are now only TWO honest modes. The middle "relax the security level inside the test" mode is
# GONE — the product does that itself, and leaving a test shim that claimed to would be dead machinery.
#
#   native      the product's own version probe puts a deprecated ClientHello on the wire and the peer
#               answers. NOTHING is patched. This is the common case — stock hosts included, and the mode
#               CI now runs in.
#   fabricated  the ONLY genuinely-unreachable case left: an OpenSSL BUILT ``no-tls1`` (the TLSv1 method
#               compiled out), where no security-level relaxation can conjure a version the library does
#               not implement. The connector then runs a REAL, gated handshake to the SAME peer with the
#               version restriction lifted and substitutes ONE of the four handshake facts it returns —
#               the negotiated VERSION. Cipher, key bits and leaf DER are the ones actually negotiated.
#               WHAT A FABRICATED RUN DOES NOT COVER, stated plainly: that OpenSSL can negotiate TLS1.0
#               with the peer at all, and therefore nothing about the peer. It is not evidence about any
#               endpoint and no such run happens outside this file.
#               WHAT IT DOES COVER: the audited gate (``capture_tls_handshake`` authorises and then invokes
#               the connector, so ``gate_authorized`` is genuinely earned), the evidence assembly in
#               ``_capture``, the ``_version_offer_context`` builder, the REAL ``tls_weakness_oracle``
#               firing on the negotiated version, admission under the branch's declared capability, the
#               minted certificate, its OFFLINE re-verification against the retained context, and that a
#               TAMPERED context fails that verification.
#
# The mode is MEASURED at import by driving the PRODUCT's own ``_restricted_connect`` — the very call the
# version probe makes, ``ciphers=None`` — against a TLS1.0-1.2 loopback server. It is NEVER a
# ``pytest.skip`` (the review's FINDING-7 blocked that: a stricter host OpenSSL would then silently delete
# positive coverage of two FACT classes, and a skipped proof is the same colour as a passing one). Both
# paths are reachable and TESTED on every host:
# ``test_the_deprecated_protocol_fact_is_minted_with_the_handshake_version_substituted`` forces the
# fabricated path unconditionally, and
# ``test_the_two_fact_classes_keep_positive_coverage_whatever_this_host_can_offer`` is the neither-ran
# guard — it mints BOTH FACT classes in one run and fails loudly, naming the mode and the host OpenSSL's
# refusal reason, if the deprecated-protocol class produced nothing.
# ===================================================================================================
_OFFER_NATIVE = "native"
_OFFER_FABRICATED = "fabricated-version-fact"

#: version_attr -> wire label, taken from the product's own probe list so the two cannot drift.
_DEPRECATED_OFFER_LABELS = dict(tb.DEPRECATED_VERSION_PROBES)

#: The product's own connector, captured BEFORE any monkeypatch, so the fabricated backstop delegates to
#: the real thing rather than reimplementing it.
_REAL_RESTRICTED_CONNECT = tb._restricted_connect


def _measure_deprecated_offer() -> dict:
    """Can THIS box put a TLS1.0-only ClientHello on the wire through the PRODUCT's own version probe?

    Drives ``_restricted_connect`` exactly as ``capture_version_restricted_handshake`` does — ``ciphers=None``,
    so the product now offers ``ALL:@SECLEVEL=0`` on the version path. A ``no-tls1`` OpenSSL build is the
    only host that still fails, and it fails identically to the way the old strict-SECLEVEL host did before
    the source fix (``local_unsupported`` / ``NO_PROTOCOLS_AVAILABLE``)."""
    out = {"native": False, "why": "not measured", "openssl": ssl.OPENSSL_VERSION}
    try:
        cert, key = _leaf()
        cpem, kpem = _pem(cert, key)
        srv = _TLSServer(cpem, kpem, min_version=ssl.TLSVersion.TLSv1,
                         max_version=ssl.TLSVersion.TLSv1_2)
    except Exception as e:  # noqa: BLE001 — a box that cannot even stand the server up is "fabricated"
        out["why"] = f"fixture server unavailable: {type(e).__name__}: {e}"
        return out
    box: dict = {}
    try:
        version, _cipher, _bits, _der = _REAL_RESTRICTED_CONNECT(
            "127.0.0.1", srv.port, 5.0, min_version_name="TLSv1", max_version_name="TLSv1",
            ciphers=None, box=box)
        out["native"], out["why"] = version == "TLSv1", f"negotiated {version!r}"
    except Exception as e:  # noqa: BLE001 — the refusal IS the measurement
        out["why"] = f"{box.get('failure_class') or 'error'} / {box.get('ssl_reason') or type(e).__name__}"
    finally:
        srv.close()
    return out


_OFFER_PROBE = _measure_deprecated_offer()
OFFER_MODE = _OFFER_NATIVE if _OFFER_PROBE["native"] else _OFFER_FABRICATED

#: Appended to every assertion whose outcome depends on the mode, so a failure diagnoses itself.
_MODE_NOTE = (f"[deprecated-protocol offer mode={OFFER_MODE}; {_OFFER_PROBE['openssl']}; "
              f"product version probe: {_OFFER_PROBE['why']}]")

# Reported through the warnings summary, which pytest prints in the default (and the CI) output, so the
# log always says which mode ran rather than leaving it to be inferred from a failure.
warnings.warn(f"test_tls_breadth {_MODE_NOTE}", stacklevel=2)


def _fabricated_restricted_connect(host, port, timeout, *, min_version_name, max_version_name,
                                   ciphers, box):
    """The fabricated backstop (see the block above), for a ``no-tls1`` OpenSSL build. A REAL gated
    handshake to the same peer with the version restriction lifted, with ONE of the four returned handshake
    facts substituted — the negotiated version. The other three (cipher, key bits, leaf DER) and the
    socket, the gate and the retained shape are the real ones. A probe that is not a deprecated-version
    probe is passed straight through UNTOUCHED, so a negative control can never be turned into a positive
    by this shim."""
    label = _DEPRECATED_OFFER_LABELS.get(min_version_name or "")
    if label is None or ciphers is not None:
        return _REAL_RESTRICTED_CONNECT(
            host, port, timeout, min_version_name=min_version_name,
            max_version_name=max_version_name, ciphers=ciphers, box=box)
    version, cipher, bits, der = _REAL_RESTRICTED_CONNECT(
        host, port, timeout, min_version_name=None, max_version_name=None, ciphers=None, box=box)
    box["substituted_from_version"] = version
    return label, cipher, bits, der


@pytest.fixture
def offer_mode():
    """The mode handle for the six peer-behaviour controls. It patches NOTHING: since the product's own
    version probe now offers at ``@SECLEVEL=0``, ``native`` runs those controls against the REAL product
    connector on every TLS1.0-capable host — a stock CI runner included. On a ``no-tls1`` build
    (``fabricated``) they cannot observe a real peer and FAIL loudly; that precondition is stated once in
    ``test_this_host_can_put_a_deprecated_clienthello_on_the_wire`` rather than fabricated away, because
    fabricating a version for a refusal / silent-host / pool control would simulate the very thing it
    exists to observe."""
    return OFFER_MODE


@pytest.fixture
def best_offer_mode(monkeypatch):
    """For the POSITIVES: keep both FACT classes covered on every host. ``native`` uses the real product
    connector; ``fabricated`` (a ``no-tls1`` build) falls back to the substituted-version handshake."""
    if OFFER_MODE == _OFFER_FABRICATED:
        monkeypatch.setattr(tb, "_restricted_connect", _fabricated_restricted_connect)
    return OFFER_MODE


@pytest.fixture
def forced_fabricated_offer(monkeypatch):
    """Force the fabricated backstop whatever this host can do, so the substituted path is exercised
    EVERYWHERE and cannot rot into a branch that only a ``no-tls1`` runner ever takes."""
    monkeypatch.setattr(tb, "_restricted_connect", _fabricated_restricted_connect)
    return _OFFER_FABRICATED


def test_this_host_can_put_a_deprecated_clienthello_on_the_wire():
    """THE PEER-BEHAVIOUR CONTROLS' PRECONDITION, asserted once instead of six times.

    ``native`` measures a real peer; ``fabricated`` does not, and on a ``no-tls1`` OpenSSL build the
    refusal / silent-host / bare-alert(70) / round-robin-pool controls cannot run against real bytes. That
    is a coverage loss, so it is RED and named here rather than skipped or quietly degraded. The two FACT
    classes keep their positive coverage regardless — see
    ``test_the_two_fact_classes_keep_positive_coverage_whatever_this_host_can_offer``."""
    assert OFFER_MODE == _OFFER_NATIVE, (
        "this host's OpenSSL will not put a TLS1.0 ClientHello on the wire even at @SECLEVEL=0, so it is a "
        "no-tls1 build and the peer-behaviour controls in sections 2-3 cannot observe a real peer. Use an "
        "OpenSSL with TLS1.0 compiled in, or accept a named coverage loss — do NOT add a skip. " + _MODE_NOTE)


def test_the_offer_mode_measurement_is_coherent_and_named():
    """The mode is DERIVED from the measurement of the product's own probe and cannot be set by hand, and
    it is always reported."""
    assert OFFER_MODE in (_OFFER_NATIVE, _OFFER_FABRICATED)
    assert (OFFER_MODE == _OFFER_NATIVE) is bool(_OFFER_PROBE["native"])
    assert (OFFER_MODE == _OFFER_FABRICATED) is not bool(_OFFER_PROBE["native"])
    assert _OFFER_PROBE["openssl"] in _MODE_NOTE and OFFER_MODE in _MODE_NOTE


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
    assert len(spec.redrives) == 5, [(r.bug_class, r.label, r.branch) for r in spec.redrives]
    # and every re-drive that shares a bug_class carries a discriminating label, so no two overwrite each
    # other's retained context
    keys = [(r.bug_class, r.label) for r in spec.redrives]
    assert len(set(keys)) == len(keys), f"two re-drives collide on (bug_class, label): {keys}"


def test_the_certificate_validity_branch_is_not_wired_and_says_so():
    """CLAIM 4 IS NOT WIRED, and this is the pin that keeps the code and the registry saying the same thing.

    A re-drive WAS wired to ``tls_weakness.certificate_validity`` and was removed. It could not work: the
    branch's only route to a non-INCONCLUSIVE verdict is ``fired=True`` (it is not clean-capable), and no
    ``OracleKind`` dispatches on the ``certificate_validity`` context key, so the oracle can never fire.
    A branch that always returns INCONCLUSIVE while naming a reason that is not the real one is worse than
    an absent branch. Asserted three ways so re-adding a dead branch reddens CI:
      (a) no re-drive on the shipped ToolSpec admits to it;
      (b) the registry row declares ``wired: false`` and says NOT WIRED in its limitation;
      (c) the mechanism is still true — a context under that key draws no oracle signal.
    """
    import json
    from vigil_integration.live.external_tool import _oracle_signal

    spec = tls_scan(port=443)
    assert _CERT_BRANCH not in {r.branch for r in spec.redrives}, (
        "a re-drive admits to the certificate-validity branch again; it can only emit INCONCLUSIVE with a "
        "reason that is not the real one — wire a real oracle first (see the row's blocking_work)")
    assert not any(r.label == "cert_validity" for r in spec.redrives)

    row = {b["id"]: b for b in json.loads(
        Path(__file__).resolve().parents[2].joinpath(
            "docs/capability-matrix/evidence-branches.json").read_text(encoding="utf-8"))["branches"]
    }[_CERT_BRANCH]
    assert row.get("wired") is False, "the registry must declare this branch unwired"
    assert "not wired" in row["limitation"].lower()
    assert row["fact_capable"] is False and row["clean_capable"] is False

    # (c) the mechanism: even a fully-populated certificate_validity context draws NO oracle signal, which
    # is exactly why a re-drive there is dead. Non-vacuous — the same call shape over the branch that IS
    # wired does produce a signal.
    cert, _ = _leaf(not_before_days=-40, not_after_days=-10)
    record = tb.classify_certificate_defects(_cert_evidence(cert))
    assert record and record["defects"], "precondition of this test: the derivation found real defects"
    dead = {"check_id": "x", "bug_class": "weak_tls", "insertion_point": "h:443",
            "oracle_context": {"bug_class": "weak_tls", "certificate_validity": record}}
    assert _oracle_signal(dead) == (False, False), (
        "an OracleKind now adjudicates certificate validity — WIRE the branch and delete this pin")
    live = {"check_id": "y", "bug_class": "weak_tls", "insertion_point": "h:443",
            "oracle_context": {"bug_class": "weak_tls",
                               "tls": {"connected": True, "host": "h", "tls_version": "TLSv1",
                                       "cipher": "AES128-SHA"}}}
    assert _oracle_signal(live)[0] is True, (
        "control: the TLS oracle does fire over a context it DOES dispatch on, so the (False, False) above "
        "is the certificate_validity key drawing no oracle, not a broken call shape")


def test_the_three_new_branches_are_registered_with_the_capability_they_actually_have():
    import json
    branches = {b["id"]: b for b in json.loads(
        Path(__file__).resolve().parents[2].joinpath(
            "docs/capability-matrix/evidence-branches.json").read_text(encoding="utf-8"))["branches"]}

    dep = branches[_DEPRECATED_BRANCH]
    assert dep["fact_capable"] is True, "the deprecated-protocol FACT is existential and must stay"
    assert dep["clean_capable"] is False, (
        "a protocol refusal may NOT be sold as clean: the refusal and the corroborating handshake are on "
        "two different TCP connections and nothing in the evidence binds them to the same peer, so an L4 "
        "pool refuses TLS1.0 on one connection and accepts it on the next — see "
        "test_a_round_robin_tls_pool_would_have_been_falsely_cleared")
    assert dep["target_clean_capable"] is True and len((dep.get("blocking_work") or "").strip()) > 40, (
        "a demoted capability keeps its TARGET and must name the engineering that closes the gap")
    assert "MISSING: cross_connection_peer_identity_binding" in dep["control_requirements"]
    assert dep["oracle_version"] == "tls_weakness"
    assert "channel_established" in dep["preconditions"] and "gate_authorized" in dep["preconditions"]

    wc = branches[_WEAK_CIPHER_BRANCH]
    assert wc["fact_capable"] is True and wc["clean_capable"] is False, (
        "a weak-cipher refusal may not be sold as clean — the local build limits what can be offered")
    assert len((wc.get("blocking_work") or "").strip()) > 40

    cv = branches[_CERT_BRANCH]
    assert cv["fact_capable"] is False and cv["clean_capable"] is False, (
        "certificate validity is not adjudicated by any OracleKind")
    assert cv["oracle_version"] == "", "an unadjudicated branch names no oracle"
    assert cv.get("wired") is False and "not wired" in cv["limitation"].lower(), (
        "the certificate-validity row must say plainly that nothing drives it")
    assert all(c.startswith("MISSING:") for c in cv["control_requirements"]), (
        f"an unwired branch may not claim satisfied controls: {cv['control_requirements']}")


def test_the_weak_cipher_vocabulary_size_is_pinned():
    """29 named suites. Pinned so a silent widening of what VIGIL is willing to OFFER is a reviewed edit,
    and so any prose stating the count can be checked against the data."""
    assert len(tb.WEAK_CIPHER_OFFER) == 29, f"the closed vocabulary is now {len(tb.WEAK_CIPHER_OFFER)}"
    assert len(set(tb.WEAK_CIPHER_OFFER)) == len(tb.WEAK_CIPHER_OFFER), "duplicate suite in the vocabulary"


def test_the_weak_cipher_vocabulary_is_a_closed_list_not_a_pattern():
    """Membership, never a pattern — because weak and strong OpenSSL suite names share long substrings, so
    any name rule is a hand-approximation waiting to be wrong in one direction or the other.

    Two REAL collisions, checked here rather than asserted in prose: ``AECDH-AES128-SHA`` is weak (ANONYMOUS
    key exchange, no server authentication) yet contains both ``ECDH`` and ``AES128-SHA``, each of which
    also occurs in authenticated suites; and ``ECDHE-ECDSA-RC4-SHA`` (weak) and
    ``ECDHE-ECDSA-AES128-GCM-SHA256`` (strong) are identical up to the shared key-exchange prefix. A
    membership test on a fixed list is immune to both."""
    # the collisions are real, not rhetorical
    assert "ECDH" in "AECDH-AES128-SHA" and "AES128-SHA" in "AECDH-AES128-SHA"
    assert "AECDH-AES128-SHA" in tb.WEAK_CIPHER_OFFER
    assert "ECDHE-RSA-AES128-SHA" not in tb.WEAK_CIPHER_OFFER
    shared = "ECDHE-ECDSA-"
    assert "ECDHE-ECDSA-RC4-SHA" in tb.WEAK_CIPHER_OFFER
    assert "ECDHE-ECDSA-AES128-GCM-SHA256".startswith(shared) and "ECDHE-ECDSA-RC4-SHA".startswith(shared)
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


def test_a_substring_rule_would_score_a_suite_the_endpoint_was_never_offered():
    """THE KILL FIXTURE for the membership guard, and the one the suite was missing.

    ``WEAK_CIPHER_OFFER``'s docstring spends eight lines arguing that deciding "is this suite weak?" by
    pattern-matching its name is the hand-approximation this program forbids. A review measured that
    argument: replacing the exact set membership in :func:`negotiated_weak_cipher` with a bidirectional
    substring rule left 109 tests passing and 0 failing. The closed-list test above asserted the name
    collisions as STRING facts but never fed one through the function, and both of its negative fixtures
    return ``""`` under either rule — so nothing in the suite could tell the two rules apart.

    This is the input that can. The endpoint negotiated ``AES128-SHA``, which VIGIL NEVER OFFERED; what it
    offered was ``AECDH-AES128-SHA`` (anonymous key exchange), a DIFFERENT suite that merely CONTAINS that
    name. Exact membership scores nothing (correct: VIGIL cannot say what it did not offer). A substring
    rule scores ``AES128-SHA`` and ``_weak_cipher_offer_context`` then builds a weak-cipher oracle context
    over a suite that was never in the ClientHello.

    Defence in depth, stated honestly: ``tls_weakness_oracle`` re-classifies the negotiated name
    afterwards, so a bad membership answer would not automatically become a FACT. But this function is the
    LAST gate before a context is built, and a guard no test defends is not a guard."""
    from vigil_integration.live.external_tool import _weak_cipher_offer_context

    def substring_rule(ev):
        """The mutation, spelled out so the reader can see exactly what is being excluded."""
        offered = ev.get("offered_ciphers") or []
        name = str(ev.get("cipher") or "")
        return name if any(str(x) and (str(x) in name or name in str(x)) for x in offered) else ""

    # (a) a weak ANONYMOUS suite was offered; the endpoint reports a DIFFERENT, authenticated name that is
    #     a strict substring of it.
    never_offered = {"connected": True, "host": "h", "port": 443,
                     "cipher": "AES128-SHA", "offered_ciphers": ["AECDH-AES128-SHA"],
                     "tls_version": "TLSv1.2"}
    assert tb.negotiated_weak_cipher(never_offered) == "", (
        "a suite VIGIL never put in the ClientHello was scored as the negotiated weak cipher — the "
        "membership test has become a pattern match")
    assert substring_rule(never_offered) == "AES128-SHA", (
        "this fixture no longer separates membership from a substring rule and has stopped being a test")
    assert _weak_cipher_offer_context(never_offered) is None, (
        "a weak-cipher ORACLE CONTEXT was built over a suite that was never offered")

    # (b) the collision in the other direction: the offer is the short name, the endpoint reports a longer
    #     one that contains it. Membership declines; a substring rule accepts.
    superstring = {"connected": True, "host": "h", "port": 443,
                   "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256", "offered_ciphers": ["AES128-GCM-SHA256"],
                   "tls_version": "TLSv1.2"}
    assert tb.negotiated_weak_cipher(superstring) == ""
    assert substring_rule(superstring) == "ECDHE-ECDSA-AES128-GCM-SHA256"
    assert _weak_cipher_offer_context(superstring) is None

    # POSITIVE CONTROL: exact membership still scores a genuine selection, so the two rows above are the
    # guard doing work rather than the function having become unable to return anything.
    real = {"connected": True, "host": "h", "port": 443,
            "cipher": "AECDH-AES128-SHA", "offered_ciphers": ["AECDH-AES128-SHA", "NULL-SHA"],
            "tls_version": "TLSv1.2"}
    assert tb.negotiated_weak_cipher(real) == "AECDH-AES128-SHA"
    assert _weak_cipher_offer_context(real) is not None, (
        "the weak-cipher context builder cannot build ANY context — the rows above would be vacuous")


def test_offerable_weak_ciphers_is_a_subset_of_the_closed_vocabulary_and_sends_nothing(tmp_path, monkeypatch):
    """The zero-offerable path: nothing was tested, and the evidence must say that WITHOUT sending a packet
    and WITHOUT skipping the audited gate.

    The gate matters even here. Asserting ``gate_authorized: False`` unconditionally (as a draft did) would
    report a gate refusal that never happened and make "the gate said no" indistinguishable from "we were
    authorised and had nothing to offer". So the no-op is routed through ``capture_tls_handshake`` with a
    connector that raises before touching a socket — proven below by making ``socket.create_connection``
    fatal for the duration."""
    import socket as _socket
    offerable = tb.offerable_weak_ciphers()
    assert set(offerable) <= set(tb.WEAK_CIPHER_OFFER)

    _charter(tmp_path)
    monkeypatch.setattr(_socket, "create_connection",
                        lambda *a, **k: pytest.fail("the zero-offerable path opened a socket"))
    empty = tb.capture_weak_cipher_handshake("127.0.0.1", 1, slug="alpha", offer=())
    assert empty["connected"] is False
    assert empty["failure_class"] == tb.FAILURE_LOCAL_UNSUPPORTED
    assert empty["offered_ciphers"] == []
    assert empty["tcp_established"] is False
    assert empty["gate_authorized"] is True, (
        "the in-charter no-op must record that the GATE authorised it — otherwise a local capability gap "
        "is reported as a gate refusal")

    # and the same no-op OUTSIDE the charter is a gate refusal, not a local gap: the two are distinguished
    out_of_scope = tb.capture_weak_cipher_handshake("10.99.99.99", 1, slug="alpha", offer=())
    assert out_of_scope["gate_authorized"] is False
    assert out_of_scope["failure_class"] == tb.FAILURE_GATE_REFUSED


# ===================================================================================================
# 1. THE CONCLUSIVENESS PREDICATE — the single most attackable decision in the slice.
#
# It is NO LONGER a CLEAN predicate: the branch is registered clean_capable:false, so a True here reaches
# the operator as INCONCLUSIVE. It is kept, and kept mutation-defended sub-condition by sub-condition,
# because it is the correct guard for this class (it is what excludes a bare non-TLS alert(70) emitter)
# and would be needed again if a sound CLEAN ever became reachable.
# ===================================================================================================
def _refusal(**over):
    ev = {"connected": False, "host": "h", "port": 443, "gate_authorized": True, "tcp_established": True,
          "offered_only_version": "TLSv1", "failure_class": tb.FAILURE_VERSION_REJECTED,
          "ssl_reason": "TLSV1_ALERT_PROTOCOL_VERSION",
          tb.PEER_SESSION_KEY: {"completed": True, "tls_version": "TLSv1.2",
                                "cipher": "ECDHE-RSA-AES128-GCM-SHA256", "probe": "baseline_handshake"}}
    ev.update(over)
    return ev


def test_only_a_peer_protocol_version_alert_on_an_open_channel_is_conclusive():
    assert tb.is_conclusive_protocol_refusal(_refusal()) is True
    assert tb.is_conclusive_protocol_refusal(_refusal(offered_only_version="TLSv1.1")) is True


def test_the_peer_session_witness_is_derived_only_from_a_completed_same_endpoint_handshake():
    """The witness itself, as a pure function. It must not be satisfiable by a sibling that failed, by a
    sibling for a DIFFERENT endpoint, or by the probe itself."""
    own = {"connected": False, "host": "h", "port": 443, "probe": "deprecated_protocol_offer"}
    failed = {"connected": False, "host": "h", "port": 443}
    other_host = {"connected": True, "host": "elsewhere", "port": 443, "tls_version": "TLSv1.2"}
    other_port = {"connected": True, "host": "h", "port": 8443, "tls_version": "TLSv1.2"}
    good = {"connected": True, "host": "h", "port": 443, "tls_version": "TLSv1.2", "cipher": "X"}

    assert tb.peer_tls_session_witness(own, ())[tb.PEER_SESSION_KEY]["completed"] is False
    assert tb.peer_tls_session_witness(
        own, (failed, other_host, other_port))[tb.PEER_SESSION_KEY]["completed"] is False, (
        "a failed / different-endpoint sibling witnessed a TLS session")
    got = tb.peer_tls_session_witness(own, (failed, good))[tb.PEER_SESSION_KEY]
    assert got["completed"] is True and got["tls_version"] == "TLSv1.2"
    # a probe may not witness for itself
    self_only = {"connected": True, "host": "h", "port": 443, "tls_version": "TLSv1.2"}
    assert tb.peer_tls_session_witness(
        self_only, (self_only,))[tb.PEER_SESSION_KEY]["completed"] is False
    # and the function does not mutate its input
    assert tb.PEER_SESSION_KEY not in own


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
    # --- the peer-TLS-session witness: without it, `channel_established` does not constrain what its
    # name promises, and a CLEAN would be asserted about a host VIGIL never spoke TLS to.
    ({tb.PEER_SESSION_KEY: None}, "no witness at all — the peer was never shown to be a TLS service"),
    ({tb.PEER_SESSION_KEY: {"completed": False, "tls_version": "", "cipher": "", "probe": ""}},
     "no capture in the run completed a TLS session with this peer"),
    ({tb.PEER_SESSION_KEY: {"completed": True, "tls_version": "", "cipher": "", "probe": "x"}},
     "a 'completed' witness naming no version proves nothing"),
    ({tb.PEER_SESSION_KEY: {"completed": True, "tls_version": "TLSv1", "cipher": "", "probe": "x"}},
     "a session at the VERY version we report as refused is a contradiction, not a corroboration"),
    ({tb.PEER_SESSION_KEY: "yes"}, "a non-dict witness is not a witness"),
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
    branch's declared capability AND its declared preconditions.

    THE DECISIVE ROW IS THE FIRST ONE. Even a fully conclusive non-fire, with every precondition satisfied,
    is INCONCLUSIVE on this branch — because the registry declares it ``clean_capable: false``. That is the
    demotion, asserted at the choke rather than only in the JSON, and it is what stops a round-robin TLS
    pool being cleared. The FACT direction is untouched."""
    from vigil_integration.live import verdict as V

    ok = {"gate_authorized": True, "channel_established": True}
    cleared = V.admit(_DEPRECATED_BRANCH, fired=False, conclusive=True, observed=ok)
    assert cleared.verdict is V.Verdict.INCONCLUSIVE, (
        f"a conclusive protocol refusal was admitted {cleared.verdict} — this branch may not assert "
        "absence; the peer that refused and the peer that completed a session need not be the same one")
    assert "may not assert absence" in cleared.reason, (
        f"the operator must be told WHY it is inconclusive, not merely that it is: {cleared.reason!r}")
    assert V.admit(_DEPRECATED_BRANCH, fired=True, conclusive=True, observed=ok).verdict is V.Verdict.FACT
    assert V.admit(_DEPRECATED_BRANCH, fired=False, conclusive=False,
                   observed=ok).verdict is V.Verdict.INCONCLUSIVE
    no_channel = {"gate_authorized": True, "channel_established": False}
    assert V.admit(_DEPRECATED_BRANCH, fired=False, conclusive=True,
                   observed=no_channel).verdict is V.Verdict.INCONCLUSIVE, (
        "a branch with no established channel cleared itself — the precondition guard is not load-bearing")
    # NON-VACUITY for the row above: admission CAN still emit CLEAN, so "INCONCLUSIVE" there is this
    # branch's declared capability doing work rather than a renderer that never emits CLEAN at all.
    assert V.admit("tls_weakness.tls_handshake", fired=False, conclusive=True,
                   observed={"gate_authorized": True, "channel_established": True}
                   ).verdict is V.Verdict.CLEAN, (
        "no TLS branch can reach CLEAN at all — the demotion assertions above would be vacuous")
    # the weak-cipher branch may NEVER clear, whatever conclusiveness is claimed
    assert V.admit(_WEAK_CIPHER_BRANCH, fired=False, conclusive=True,
                   observed=ok).verdict is V.Verdict.INCONCLUSIVE
    # the certificate-validity ROW may neither mint nor clear. Nothing admits to it (the branch is
    # unwired — see test_the_certificate_validity_branch_is_not_wired_and_says_so); these two lines pin
    # the registry declaration itself, so if it is ever wired it starts from a capability nobody can
    # accidentally raise.
    assert V.admit(_CERT_BRANCH, fired=True, conclusive=True, observed=ok).verdict is V.Verdict.LEAD
    assert V.admit(_CERT_BRANCH, fired=False, conclusive=True, observed=ok).verdict is V.Verdict.INCONCLUSIVE


# ===================================================================================================
# 2. CLAIM 1 + 2 — deprecated protocol accepted (FACT) / refused (INCONCLUSIVE, never CLEAN), live.
# ===================================================================================================
def test_a_tls10_accepting_server_mints_a_deprecated_protocol_fact_that_reverifies_offline(
        tmp_path, best_offer_mode):
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
        f"outcomes={res.outcomes} {_MODE_NOTE}")
    fact = facts[0]
    ctx = res.contexts[fact.finding_ref]
    assert ctx["tls"]["tls_version"] == "TLSv1"
    assert ctx["tls"]["offered_only_version"] == "TLSv1"
    assert verify_certificate(fact.signed, oracle_context=ctx, trust_root=TRUST).ok is True, (
        "the deprecated-protocol FACT did not re-verify offline")
    # TLS1.1 was offered separately and also accepted by this server
    assert _facts(res, "offer_tls1_1"), (
        f"the TLS1.1-only probe minted nothing against a TLS1.0-1.2 server {_MODE_NOTE}")


def test_the_deprecated_protocol_fact_is_minted_with_the_handshake_version_substituted(
        tmp_path, forced_fabricated_offer):
    """THE SUBSTITUTED PATH, FORCED — run on EVERY host, not only on one whose OpenSSL refuses TLS1.0.

    This is the mode that keeps the deprecated-protocol FACT class covered when the box will not put the
    ClientHello on the wire (see the offer-mode block above for exactly how CI's OpenSSL refuses). The
    connector performs a REAL gated handshake to the SAME loopback server and substitutes ONE of its four
    returned facts — the negotiated version. So this test proves the ADMISSION PATH, and says plainly
    what it does not prove.

    WHAT IS REAL HERE: the audited gate (``gate_authorized`` is earned inside ``capture_tls_handshake``,
    which authorises before it calls the connector), the TCP channel, the presented leaf, the negotiated
    cipher, the evidence assembly, ``_version_offer_context``, the ``tls_weakness_oracle`` fire, admission
    under ``tls_weakness.deprecated_protocol_offer``, the signed certificate, its OFFLINE re-verification
    against the retained context, and the tamper check.

    WHAT IS NOT: that OpenSSL can negotiate TLS1.0 with this peer. Nothing here is evidence about any
    endpoint, and no substituted capture exists outside this file — pinned below by asserting the
    product's own connector is restored and by
    ``test_the_shipped_connector_is_the_one_the_product_uses``."""
    from framework.v2.evidence.certify import verify_certificate

    cert, key = _leaf()
    cpem, kpem = _pem(cert, key)
    # a server pinned to EXACTLY TLS1.2 — so "TLSv1" in the evidence is unambiguously the SUBSTITUTED
    # fact (this test cannot pass by accidentally negotiating a real TLS1.0 session), and the strong
    # suite list really governs the negotiation, so the cipher assertion below is not vacuous.
    srv = _TLSServer(cpem, kpem, min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_2,
                     ciphers=_STRONG_SUITES, seclevel0=False)
    try:
        res = _run(srv.port, tmp_path)
    finally:
        srv.close()

    assert res.status == "ran"
    facts = _facts(res, "offer_tls1_0")
    assert facts, (
        "THE SUBSTITUTED PATH DID NOT ENGAGE — the admission path ran with the four handshake facts "
        f"substituted and still produced no FACT; outcomes={res.outcomes}")
    fact = facts[0]
    ctx = res.contexts[fact.finding_ref]
    tls = ctx["tls"]
    # the gate really authorised, the channel really came up, and the other three handshake facts are
    # the ones this peer really produced
    assert tls["gate_authorized"] is True and tls["tcp_established"] is True
    assert tls["connected"] is True and tls["tls_version"] == "TLSv1"
    assert tls["offered_only_version"] == "TLSv1"
    assert tls["cipher"] in _STRONG_SUITES.split(":"), (
        f"the NEGOTIATED cipher must be the real one this peer chose, not a substituted one: {tls!r}")
    assert tls["cert_der_b64"] == _der_b64(cert), "the retained leaf must be the one the peer presented"
    assert verify_certificate(fact.signed, oracle_context=ctx, trust_root=TRUST).ok is True, (
        "the substituted-capture FACT did not re-verify offline — the admission path is not intact")
    tampered = {**ctx, "tls": {**tls, "tls_version": "TLSv1.3"}}
    assert verify_certificate(fact.signed, oracle_context=tampered, trust_root=TRUST).ok is False, (
        "a TAMPERED substituted capture re-verified")
    assert _facts(res, "offer_tls1_1"), "the TLS1.1 re-drive did not reach admission under substitution"


def test_the_two_fact_classes_keep_positive_coverage_whatever_this_host_can_offer(
        tmp_path, best_offer_mode):
    """THE NEITHER-RAN GUARD. Self-contained and order-independent: one gated run against one server that
    is both TLS1.0-capable and weak-cipher-capable, asserting that BOTH FACT classes minted.

    The shape this exists to kill is "the positive quietly produced nothing": before this, a stricter host
    OpenSSL made the deprecated-protocol positive assert over an empty list, and the only signal was a
    bare ``assert []``. Here the failure names the mode and the host OpenSSL's own refusal reason."""
    offerable = tb.offerable_weak_ciphers()
    cert, key = _leaf()
    cpem, kpem = _pem(cert, key)
    srv = _TLSServer(cpem, kpem, min_version=ssl.TLSVersion.TLSv1, max_version=ssl.TLSVersion.TLSv1_2,
                     ciphers=":".join([*offerable, "AES128-SHA"]))
    try:
        res = _run(srv.port, tmp_path)
    finally:
        srv.close()

    assert res.status == "ran" and res.proposed, f"the server was never proposed; {res.detail}"
    assert _facts(res, "offer_tls1_0"), (
        "NEITHER the real-endpoint path NOR the substituted path minted a deprecated-protocol FACT, so "
        "that FACT class has NO positive coverage in this run. Do not add a skip — find out why. "
        f"outcomes={res.outcomes} {_MODE_NOTE}")
    assert offerable, (
        "this OpenSSL can offer none of the closed weak-cipher vocabulary, so the weak-cipher FACT class "
        f"has no positive coverage in this run {_MODE_NOTE}")
    assert _facts(res, "offer_weak_ciphers"), (
        "the weak-cipher FACT class produced nothing against a server that offers the very suites VIGIL "
        f"offered; outcomes={res.outcomes} {_MODE_NOTE}")


def test_the_shipped_connector_is_the_one_the_product_uses():
    """No mode shim outlives the fixture that installed it: at rest ``tls_breadth._restricted_connect`` is
    the product's own function, so nothing in this file can leak a relaxed or substituted offer into
    another test or into the product."""
    assert tb._restricted_connect is _REAL_RESTRICTED_CONNECT
    assert _REAL_RESTRICTED_CONNECT.__module__ == "vigil_integration.live.tls_breadth"


def test_a_tampered_deprecated_protocol_capture_fails_offline_reverification(tmp_path, best_offer_mode):
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
    facts = _facts(res, "offer_tls1_0")
    assert facts, (
        "the TLS1.0 probe minted nothing, so there is no capture to tamper with and this test cannot "
        f"report what it is for; outcomes={res.outcomes} {_MODE_NOTE}")
    fact = facts[0]
    good = res.contexts[fact.finding_ref]
    tampered = {**good, "tls": {**good["tls"], "tls_version": "TLSv1.3"}}
    assert verify_certificate(fact.signed, oracle_context=tampered, trust_root=TRUST).ok is False, (
        "a TAMPERED retained capture re-verified — the certificate does not bind its evidence")


def test_a_tls12_only_server_does_not_mint_tls10_accepted_and_is_inconclusive_not_clean(
        tmp_path, offer_mode):
    """THE same-shape negative control for claim 1 — and the pin that even the BEST case for claim 2 is
    INCONCLUSIVE.

    This server really is TLS1.2+-only and really does send ``alert(70)``. It is the single most favourable
    input the refusal claim will ever get, and it is STILL not cleared, because VIGIL cannot show that the
    peer that refused is the peer that completed the TLS1.2 session — they are different connections. The
    test asserts POSITIVELY that the refusal path was reached (the predicate itself says True over the
    retained capture) and that the reported outcome is nonetheless inconclusive, so it cannot pass by the
    probe silently not running."""
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
        # POSITIVE non-vacuity: the probe RAN and the PEER REFUSED. Without this the assertion below
        # would also pass if the handshake had timed out or never been attempted.
        retained = res.contexts[outs[0]["check_id"]]["tls"]
        assert retained["tcp_established"] is True and retained["gate_authorized"] is True
        assert retained["failure_class"] == tb.FAILURE_VERSION_REJECTED, (
            f"precondition of this test: the peer must have sent alert(70); got {retained!r} "
            f"{_MODE_NOTE}")
        assert tb.is_conclusive_protocol_refusal(retained) is True, (
            "precondition of this test: this is the BEST case — the predicate is satisfied in full")
        # ... and it is STILL not a clean bill of health.
        assert all(o["outcome"] == Outcome.INCONCLUSIVE.value for o in outs), (
            f"the {label} probe cleared a TLS1.2+-only endpoint. A refusal is INCONCLUSIVE: the peer that "
            f"refused and the peer that completed the TLS1.2 session are different connections; got {outs}")


def test_the_refusal_predicate_is_reproducible_offline_from_the_retained_capture(tmp_path, offer_mode):
    """The conclusiveness predicate re-runs over the RETAINED capture and gives the same answer — no clock,
    no network, no live handle, no siblings. That purity is why the witness is STAMPED INTO the evidence
    rather than consulted at decision time, and it is the property the guard keeps even though the branch
    no longer reaches CLEAN.

    Worth stating plainly, because it is easy to over-read: reproducibility is all a non-FACT verdict has.
    ``oracle_adapter.certify_admitted`` mints a signed certificate ONLY for a FACT; a CLEAN or an
    INCONCLUSIVE carries no signature, no context digest and no trust root, so its only integrity is
    provenance-by-custody. The registry's top-level note says so for every branch."""
    cert, key = _leaf()
    cpem, kpem = _pem(cert, key)
    srv = _TLSServer(cpem, kpem, min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_3,
                     ciphers=_STRONG_SUITES, seclevel0=False)
    try:
        res = _run(srv.port, tmp_path)
    finally:
        srv.close()
    refs = [o["check_id"] for o in _outcomes(res, "offer_tls1_0")]
    assert refs, f"the TLS1.0 probe produced no outcome to re-run the predicate over {_MODE_NOTE}"
    ctx = res.contexts[refs[0]]
    retained = ctx["tls"]
    assert tb.is_conclusive_protocol_refusal(retained) is True, (
        f"precondition of this test: the retained capture must be a real peer refusal; got {retained!r} "
        f"{_MODE_NOTE}")
    assert retained["ssl_reason"] == "TLSV1_ALERT_PROTOCOL_VERSION"
    assert retained["tcp_established"] is True and retained["gate_authorized"] is True
    # the peer-TLS-session witness must be RETAINED, not recomputed: that is what keeps the CLEAN a pure
    # function of this one dict and therefore reproducible with no siblings, no network and no clock.
    witness = retained[tb.PEER_SESSION_KEY]
    assert witness["completed"] is True and witness["tls_version"] not in ("", "TLSv1"), witness
    # and a tamper of the retained reason removes the CLEAN
    assert tb.is_conclusive_protocol_refusal(
        {**retained, "ssl_reason": "SSLV3_ALERT_HANDSHAKE_FAILURE"}) is False
    # ... as does a tamper that removes the witness
    assert tb.is_conclusive_protocol_refusal(
        {**retained, tb.PEER_SESSION_KEY: dict(witness, completed=False)}) is False


# ===================================================================================================
# 3. THE LAUNDERING PIN — a host that times out or resets is INCONCLUSIVE, never CLEAN.
# ===================================================================================================
def test_a_round_robin_tls_pool_would_have_been_falsely_cleared(tmp_path, offer_mode):
    """THE PERMANENT NEGATIVE CONTROL FOR THE WITHDRAWN CLEAN, and the reason it was withdrawn.

    One listening socket, two real OpenSSL backends, alternating per connection: A speaks TLS1.0-1.2, B is
    TLS1.2+. That is an ordinary k8s Service with two pods, an haproxy/nginx TCP pool, an L4 VIP, or a DNS
    A-record pool mid-rollout — not an exotic adversary.

    The endpoint ACCEPTS TLS1.0 (measured below, on the same host:port, after the run). VIGIL's TLS1.0
    probe nevertheless lands on B and retains a genuine ``alert(70)``, while a sibling capture lands on A
    and retains a genuine completed session, so EVERY guard in ``is_conclusive_protocol_refusal`` is
    satisfied over the retained evidence — this test asserts that it is, positively, so it cannot pass by
    the probe failing to run. Before the demotion this produced ``outcome == clean``. It must now produce
    INCONCLUSIVE, and the thing that makes it INCONCLUSIVE is the registry capability, because the
    predicate itself still (correctly, per connection) says True.

    Nothing here is detectable as self-contradiction: ``minimum_version=TLSv1.1`` is legal, so "refused at
    TLS1.0, completed at TLS1.1" is internally consistent, and the refusing peer presents no certificate
    for the completed peer's ``spki_sha256`` to bind against. THIS IS THE IRREDUCIBLE PART."""
    cert, key = _leaf()
    cpem, kpem = _pem(cert, key)
    pool = _RoundRobinTlsPool(cpem, kpem)
    try:
        res = _run(pool.port, tmp_path, timeout=30.0)
        ground_truth = pool.accepts_tls10()
    finally:
        pool.close()

    assert res.status == "ran"
    # (1) GROUND TRUTH: the endpoint really does accept TLS1.0.
    assert any(v == "TLSv1" for v in ground_truth), (
        f"fixture precondition: a pool member must complete a TLS1.0 handshake; saw {ground_truth}")

    outs = _outcomes(res, "offer_tls1_0")
    assert outs, f"the TLS1.0 probe produced no outcome at all; outcomes={res.outcomes}"
    retained = res.contexts[outs[0]["check_id"]]["tls"]

    # (2) NON-VACUITY: the run really reached the dangerous state — a genuine peer alert(70) PLUS a
    #     genuine completed-session witness, i.e. the full predicate is satisfied over one retained dict.
    assert retained["gate_authorized"] is True and retained["tcp_established"] is True
    assert retained["failure_class"] == tb.FAILURE_VERSION_REJECTED, (
        f"precondition of this control: a pool member must have sent alert(70); got {retained!r} "
        f"{_MODE_NOTE}")
    assert retained["ssl_reason"] == "TLSV1_ALERT_PROTOCOL_VERSION"
    witness = retained[tb.PEER_SESSION_KEY]
    assert witness["completed"] is True and witness["tls_version"] not in ("", "TLSv1"), witness
    assert tb.is_conclusive_protocol_refusal(retained) is True, (
        "this control is vacuous unless the predicate is FULLY SATISFIED here — that is the whole point: "
        "every guard holds and the conclusion is still false")

    # (3) AND THE VERDICT IS STILL NOT A CLEAN. This is the demotion, measured end to end.
    assert all(o["outcome"] == Outcome.INCONCLUSIVE.value for o in outs), (
        f"A ROUND-ROBIN TLS POOL WAS CLEARED FOR A VERSION IT ACCEPTS: {outs} (ground truth {ground_truth})")
    cleans = [o for o in res.outcomes if o["outcome"] == Outcome.CLEAN.value]
    assert not cleans, f"the pool produced CLEAN outcomes elsewhere in the run: {cleans}"

    # (4) and the false CLEAN must not travel as a lead either — this is where it went before the fix
    #     (external_tool -> brains/hexstrike_body -> live/wiring -> report leads).
    leaked = [l for l in res.leads
              if getattr(l, "outcome", "") == Outcome.CLEAN.value
              and str(getattr(l, "finding_ref", "")).endswith("@offer_tls1_0")]
    assert not leaked, f"a clean-labelled lead escaped for the pool: {[l.finding_ref for l in leaked]}"


def test_a_black_hole_host_is_inconclusive_never_clean(tmp_path, offer_mode):
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
        f"a silent host was classified {ev['failure_class']!r} — only a peer alert(70) may be a refusal "
        f"{_MODE_NOTE}")
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


def test_a_bare_alert70_emitter_is_never_clean(tmp_path, offer_mode):
    """MEDIUM (five-lens review): a socket that is not a TLS service, but answers every ClientHello with
    the same seven-byte ``alert(70)`` record, satisfied every condition the predicate had before the
    witness existed. The channel is established and the peer really sent the alert — so this test FIRST
    proves it reaches that exact state (non-vacuity), and only then that the predicate still says no.

    The witness is retained even though the branch is no longer CLEAN-capable: it is what separates "a
    TLS endpoint refused this version on this connection" from "seven bytes came back from a socket", and
    that distinction is worth keeping in the evidence whatever the verdict ceiling is."""
    _charter(tmp_path)
    emitter = _BareAlert70Emitter()
    try:
        ev = tb.capture_version_restricted_handshake(
            "127.0.0.1", emitter.port, slug="alpha", version_attr="TLSv1", version_label="TLSv1",
            timeout=3.0)
    finally:
        emitter.close()

    # NON-VACUITY: the dangerous state really was reached — every pre-witness condition holds.
    assert emitter.served >= 1, "precondition of this test: the emitter was actually contacted"
    assert ev["connected"] is False
    assert ev["gate_authorized"] is True and ev["tcp_established"] is True
    assert ev["failure_class"] == tb.FAILURE_VERSION_REJECTED, (
        f"precondition of this test: OpenSSL must classify the bare record as a peer alert(70); "
        f"got {ev['failure_class']!r} / {ev.get('ssl_reason')!r} {_MODE_NOTE}")
    assert ev["ssl_reason"] == "TLSV1_ALERT_PROTOCOL_VERSION"

    # ... and it is STILL not clean, because nothing ever completed a TLS session with this peer.
    stamped = tb.peer_tls_session_witness(ev, (ev,))
    assert stamped[tb.PEER_SESSION_KEY]["completed"] is False
    assert tb.is_conclusive_protocol_refusal(stamped) is False, (
        "A NON-TLS ALERT EMITTER LAUNDERED INTO A CLEAN")

    # the control: the SAME evidence with a genuine completed session beside it DOES satisfy the
    # predicate — so the False above is the witness doing work, not the predicate having become
    # unsatisfiable. (Satisfying the predicate still does not reach CLEAN; the branch is
    # clean_capable:false. See test_a_round_robin_tls_pool_would_have_been_falsely_cleared.)
    session = {"connected": True, "host": ev["host"], "port": ev["port"], "tls_version": "TLSv1.2",
               "cipher": "ECDHE-RSA-AES128-GCM-SHA256", "probe": "baseline_handshake"}
    assert tb.is_conclusive_protocol_refusal(
        tb.peer_tls_session_witness(ev, (session,))) is True


def test_a_bare_alert70_emitter_is_never_clean_end_to_end(tmp_path, offer_mode):
    """The same pin driven through the WHOLE gated runner: no FACT and no CLEAN anywhere against a peer
    VIGIL never completed a TLS session with.

    Asserted POSITIVELY, not as "no CLEAN appeared": the emitter must have been contacted, the probes must
    have produced outcomes, the retained capture must show the real alert(70), and the retained WITNESS
    must be the thing that is absent. Otherwise this would pass against a host that was never probed."""
    emitter = _BareAlert70Emitter()
    try:
        res = _run(emitter.port, tmp_path, timeout=20.0)
    finally:
        emitter.close()

    assert res.status == "ran"
    assert emitter.served >= 1, "precondition: the runner really probed the emitter"
    outs = _outcomes(res, "offer_tls1_0") + _outcomes(res, "offer_tls1_1")
    assert outs, f"the version probes produced no outcome at all; outcomes={res.outcomes}"
    # the dangerous state was REACHED: real alert(70) on a real channel, and the witness is what is missing
    retained = res.contexts[outs[0]["check_id"]]["tls"]
    assert retained["tcp_established"] is True and retained["gate_authorized"] is True
    assert retained["failure_class"] == tb.FAILURE_VERSION_REJECTED, (
        f"precondition: OpenSSL must read the bare record as a peer alert(70); got {retained!r} "
        f"{_MODE_NOTE}")
    assert retained[tb.PEER_SESSION_KEY]["completed"] is False, (
        "the witness must be the thing that is absent — otherwise this test is not about the witness")
    assert tb.is_conclusive_protocol_refusal(retained) is False, (
        "A NON-TLS ALERT EMITTER REACHED A CONCLUSIVE REFUSAL")
    assert all(o["outcome"] == Outcome.INCONCLUSIVE.value for o in outs), (
        f"the version probes over a non-TLS emitter must be INCONCLUSIVE; got {outs}")
    cleans = [o for o in res.outcomes if o["outcome"] == Outcome.CLEAN.value]
    assert not cleans, f"a non-TLS alert emitter was CLEARED: {cleans}"
    assert res.facts == [], f"a non-TLS alert emitter minted FACTs: {[f.finding_ref for f in res.facts]}"


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

    # NON-VACUITY FIRST: the probe must really have run against a really-reachable server, or "no FACT"
    # would be satisfied by the test never reaching the server at all.
    assert res.status == "ran" and res.proposed, f"the server was never proposed; {res.detail}"
    assert _facts(res, "offer_tls1_0") == [] and _outcomes(res, "offer_tls1_0"), (
        "control: the version probes ran against this same endpoint")
    outs = _outcomes(res, "offer_weak_ciphers")
    assert outs, f"the weak-cipher probe produced no outcome at all; outcomes={res.outcomes}"

    assert not _facts(res, "offer_weak_ciphers"), "a strong-cipher-only server minted a weak-cipher FACT"
    assert all(o["outcome"] != Outcome.CLEAN.value for o in outs), (
        f"the weak-cipher branch leaked a CLEAN on a refusal: {outs}")
    assert all(o["outcome"] == Outcome.SKIPPED.value for o in outs), (
        f"a refused weak-cipher offer must be SKIPPED (nothing was proven, nothing cleared): {outs}")


# ===================================================================================================
# 5. CLAIM 4 — BUILT, TESTED, NOT WIRED. The derivation below is pure and re-runnable; nothing in the
#    product drives it (see test_the_certificate_validity_branch_is_not_wired_and_says_so above, and
#    test_no_live_capture_retains_a_wallclock_instant below, which pins WHY it is inert on live evidence).
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
    """THE same-shape negative control for the claim-4 derivation: a clean certificate must produce an
    EMPTY defect list. Paired with the expired/mismatched/self-signed positives above, so "no defects" is
    a discrimination and not a function that never reports anything."""
    import ipaddress
    ca = _ca()
    good, _ = _leaf(sans=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))], issuer=ca)
    assert tb.classify_certificate_defects(_cert_evidence(good))["defects"] == []
    bad, _ = _leaf(cn="other.example", not_before_days=-40, not_after_days=-10)
    assert tb.classify_certificate_defects(_cert_evidence(bad))["defects"] != [], (
        "control: the same call shape over a defective leaf DOES report defects")


def test_missing_or_unparseable_inputs_judge_nothing_rather_than_clearing():
    cert, _ = _leaf()
    assert tb.classify_certificate_defects(None) is None
    assert tb.classify_certificate_defects({"connected": True}) is None                 # no cert
    assert tb.classify_certificate_defects({"cert_der_b64": _der_b64(cert)}) is None    # no instant
    assert tb.classify_certificate_defects(
        {"cert_der_b64": base64.b64encode(b"not a certificate").decode(), "captured_at_epoch": 1}) is None


def test_the_certificate_validity_derivation_is_inert_against_live_evidence(tmp_path):
    """THE honest end-to-end statement of claim 4, driven through the whole runner against the strongest
    possible input — a server presenting an EXPIRED, hostname-MISMATCHED, SELF-SIGNED leaf.

    The previous version of this test was vacuous: every substantive assertion sat behind
    ``if ref in res.contexts:`` and one of them was ``record["at_epoch"] == record["at_epoch"]``, so it
    passed whether or not the path under test ran at all. This one asserts POSITIVELY, in both directions:

      1. the runner really captured that certificate (non-vacuity — the defects are derivable from the DER
         the runner itself retained, which is the whole value of the derivation), AND
      2. NOTHING in the run adjudicates it: no ``cert_validity`` outcome exists at all, because the branch
         is unwired; and the live capture retains no ``captured_at_epoch``, so handing that same capture to
         the derivation returns ``None`` rather than a verdict.
    """
    cert, key = _leaf(cn="wrong.example", sans=[x509.DNSName("wrong.example")],
                      not_before_days=-40, not_after_days=-10)
    cpem, kpem = _pem(cert, key)
    srv = _TLSServer(cpem, kpem, min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_3,
                     ciphers=_STRONG_SUITES, seclevel0=False)
    try:
        res = _run(srv.port, tmp_path)
    finally:
        srv.close()

    assert res.status == "ran" and res.proposed
    # (1) NON-VACUITY: the runner's OWN baseline capture really retained this defective leaf. Reached via
    # the weak_crypto re-drive's retained context, which is built from the same shared baseline handshake.
    live_der = _der_b64(cert)
    retained_leaf = [c["tls"]["cert_der_b64"] for c in res.contexts.values()
                     if isinstance(c, dict) and isinstance(c.get("tls"), dict)
                     and c["tls"].get("cert_der_b64")]
    assert live_der in retained_leaf, (
        f"the runner's own captures did not retain this defective leaf at all; outcomes={res.outcomes}")
    # the derivation DOES find every defect when it is given an instant to compare against
    record = tb.classify_certificate_defects(
        {"connected": True, "host": "127.0.0.1", "port": srv.port, "cert_der_b64": live_der,
         "captured_at_epoch": int(_now().timestamp())})
    assert record is not None
    assert {"expired", "hostname_mismatch", "self_signed"} <= set(record["defects"]), record

    # (2a) NOTHING adjudicates it: the branch is unwired, so there is no cert_validity outcome to inspect.
    assert _outcomes(res, "cert_validity") == [], (
        "a cert_validity outcome exists again — the dead branch was re-wired; see "
        "test_the_certificate_validity_branch_is_not_wired_and_says_so")
    assert all(_CERT_BRANCH not in str(o.get("check_id", "")) for o in res.outcomes)

    # (2b) and it is inert on live evidence, because no live capture retains a comparison instant.
    for probe_label in ("offer_tls1_0", "offer_tls1_1", "offer_weak_ciphers"):
        for out in _outcomes(res, probe_label):
            ctx = res.contexts.get(out["check_id"])
            if isinstance(ctx, dict) and isinstance(ctx.get("tls"), dict):
                assert tb.classify_certificate_defects(ctx["tls"]) is None, (
                    "a live capture now carries a comparison instant — if that is deliberate, it is a "
                    "certificate-invalidating change for that branch and must be declared")


def test_no_live_capture_retains_a_wallclock_instant(tmp_path):
    """HIGH (five-lens review): a draft stamped ``captured_at_epoch`` / ``capture_time_source`` into the
    SHARED baseline capture, which is the signed oracle context of two ALREADY-SHIPPED branches
    (``tls_weakness.tls_handshake`` and ``weak_crypto.cert_signature_algorithm``) — so every certificate
    ever issued for them would have changed digest, for a consumer that turned out to be structurally
    dead. No capture stamps it now. This pins that, over EVERY capture the TLS spec performs."""
    from framework.v2.verify import capture_tls_handshake
    from vigil_integration.live.external_tool import _tls_capture
    _charter(tmp_path)
    cert, key = _leaf()
    cpem, kpem = _pem(cert, key)
    srv = _TLSServer(cpem, kpem, min_version=ssl.TLSVersion.TLSv1, max_version=ssl.TLSVersion.TLSv1_3)
    try:
        baseline = _tls_capture("127.0.0.1", srv.port, slug="alpha")
        direct = capture_tls_handshake("127.0.0.1", srv.port, slug="alpha")
        others = [
            tb.capture_version_restricted_handshake("127.0.0.1", srv.port, slug="alpha",
                                                    version_attr="TLSv1", version_label="TLSv1"),
            tb.capture_weak_cipher_handshake("127.0.0.1", srv.port, slug="alpha"),
            tb.capture_weak_cipher_handshake("127.0.0.1", srv.port, slug="alpha", offer=()),
        ]
    finally:
        srv.close()

    assert baseline.get("connected") is True, "precondition: the baseline handshake really completed"
    for cap in [baseline, *others]:
        assert "captured_at_epoch" not in cap, f"a runner wallclock is back in signed evidence: {cap}"
        assert "capture_time_source" not in cap, cap
    # the SHARED baseline capture's evidence SHAPE is exactly what verify.tls returns — WAVE 3 added no
    # field to it, so the two branches it feeds keep the oracle context (and so the certificate digest)
    # they shipped with.
    assert set(baseline) == set(direct), (
        f"_tls_capture added {sorted(set(baseline) - set(direct))} to a SHIPPED branch's signed context")
    assert tb.PEER_SESSION_KEY not in baseline, (
        "the shared baseline capture was enriched; its two shipped branches' digests must not move")


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
    # ... INCLUDING the zero-offerable no-op, which used to return a hand-built dict without ever
    # consulting the gate, while the module docstring claimed every capture went through it.
    tb.capture_weak_cipher_handshake("127.0.0.1", 8443, slug="alpha", offer=())
    assert len(calls) == 3 and {c[2] for c in calls} == {"alpha"}, (
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
