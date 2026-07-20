"""
quantum_era — quantum-AWARE crypto exposure classifiers + an exact 0/1-knapsack
optimizer over an attack-path portfolio.

The optimizer test compares against an independent exhaustive brute-force optimum, so it
proves the solver actually *reaches* the optimum rather than checking a fixture.
The pqc_scan test stands up a real local TLS server with a self-signed RSA certificate
(generated at test time) and asserts the probe reports the classical KEX / RSA-signature
exposure and harvest-now-decrypt-later risk.
"""

from __future__ import annotations

import datetime
import itertools
import socket
import ssl
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from random import Random

import pytest

from framework.v2.scanner.quantum_era import (
    PortfolioSelection,
    PqcReport,
    anneal_path_portfolio,
    classify_kex,
    classify_signature,
    pqc_scan,
)

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False


# ---------------------------------------------------------------------------
# (1) classifiers
# ---------------------------------------------------------------------------

def test_classify_kex_classical_is_vulnerable() -> None:
    for name in ("RSA", "DHE-RSA-AES128", "ECDHE-RSA-AES256-GCM-SHA384", "ecdhe",
                 "X25519", "x448", "secp256r1", "ffdhe2048"):
        assert classify_kex(name) == "vulnerable", name


def test_classify_kex_pqc_and_hybrid() -> None:
    assert classify_kex("ML-KEM-768") == "pqc"
    assert classify_kex("kyber768") == "pqc"
    assert classify_kex("FrodoKEM-976") == "pqc"
    # hybrid = classical X25519 combined with PQC ML-KEM.
    assert classify_kex("X25519MLKEM768") == "hybrid"
    assert classify_kex("x25519_kyber768") == "hybrid"


def test_classify_kex_unknown() -> None:
    # a bare TLS 1.3 suite carries no KEX token.
    assert classify_kex("TLS_AES_256_GCM_SHA384") == "unknown"
    assert classify_kex("") == "unknown"


def test_classify_signature() -> None:
    for name in ("sha256WithRSAEncryption", "ecdsa-with-SHA256", "ed25519", "RSASSA-PSS"):
        assert classify_signature(name) == "vulnerable", name
    # ML-DSA must NOT read as classical DSA.
    assert classify_signature("ML-DSA-65") == "pqc"
    assert classify_signature("dilithium3") == "pqc"
    assert classify_signature("SPHINCS+-SHA2-128s") == "pqc"
    assert classify_signature("SLH-DSA-SHA2-128f") == "pqc"
    assert classify_signature("Falcon-512") == "pqc"


# ---------------------------------------------------------------------------
# (2) live pqc_scan against a local self-signed RSA TLS server
# ---------------------------------------------------------------------------

def _self_signed_rsa(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())  # -> sha256WithRSAEncryption, a classical signature
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


class _Quiet(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):  # silence
        return


@pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography needed to mint a test cert")
def test_pqc_scan_reports_classical_exposure(tmp_path) -> None:
    cert_path, key_path = _self_signed_rsa(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Quiet)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        report = pqc_scan("127.0.0.1", port, timeout=5.0)
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=5.0)

    assert report is not None
    assert isinstance(report, PqcReport)
    assert report.sig_class == "vulnerable"
    assert report.signature_algorithm and "rsa" in report.signature_algorithm.lower()
    assert report.harvest_now_decrypt_later is True
    assert report.kex_class == "vulnerable"
    assert report.weaknesses  # at least the HNDL note


def test_pqc_scan_returns_none_on_dead_port() -> None:
    # bind then close to obtain a definitely-closed port.
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert pqc_scan("127.0.0.1", port, timeout=0.5) is None


# ---------------------------------------------------------------------------
# (3) simulated-annealing knapsack vs. brute force
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Path:
    value: float
    detection_cost: float


def _brute_force(items, budget):
    n = len(items)
    best_val = -1.0
    best_idx: tuple[int, ...] = ()
    count_at_best = 0
    for r in range(n + 1):
        for combo in itertools.combinations(range(n), r):
            cost = sum(items[i].detection_cost for i in combo)
            if cost > budget + 1e-9:
                continue
            val = sum(items[i].value for i in combo)
            if val > best_val + 1e-12:
                best_val, best_idx, count_at_best = val, combo, 1
            elif abs(val - best_val) <= 1e-12:
                count_at_best += 1
    return best_val, best_idx, count_at_best


_INSTANCE = [
    _Path(value=10.0, detection_cost=5.0),
    _Path(value=7.0, detection_cost=4.0),
    _Path(value=3.0, detection_cost=2.0),
    _Path(value=13.0, detection_cost=6.0),
    _Path(value=2.0, detection_cost=1.0),
    _Path(value=9.0, detection_cost=5.0),
    _Path(value=4.0, detection_cost=3.0),
    _Path(value=6.0, detection_cost=4.0),
    _Path(value=11.0, detection_cost=7.0),
    _Path(value=5.0, detection_cost=2.0),
    _Path(value=8.0, detection_cost=5.0),
    _Path(value=1.0, detection_cost=1.0),
]
_BUDGET = 15.0


def test_annealer_matches_brute_force_optimum() -> None:
    opt_val, opt_idx, _ = _brute_force(_INSTANCE, _BUDGET)
    # try several seeds: each is deterministic, and each must reach the optimum.
    for seed in range(6):
        res = anneal_path_portfolio(
            _INSTANCE, budget=_BUDGET, rng=Random(seed), iterations=3000
        )
        assert isinstance(res, PortfolioSelection)
        assert res.feasible
        assert res.detection_cost <= _BUDGET + 1e-9
        assert abs(res.value - opt_val) < 1e-9, (seed, res.value, opt_val)


def test_annealer_is_deterministic() -> None:
    a = anneal_path_portfolio(_INSTANCE, budget=_BUDGET, rng=Random(42), iterations=3000)
    b = anneal_path_portfolio(_INSTANCE, budget=_BUDGET, rng=Random(42), iterations=3000)
    assert a.indices == b.indices
    assert a.value == b.value


def test_annealer_respects_budget_and_empty() -> None:
    # zero budget with all positive costs -> nothing selected.
    res = anneal_path_portfolio(_INSTANCE, budget=0.0, rng=Random(1), iterations=500)
    assert res.indices == ()
    assert res.value == 0.0
    assert res.feasible
    # empty pool.
    empty = anneal_path_portfolio([], budget=10.0, rng=Random(1), iterations=100)
    assert empty.indices == () and empty.value == 0.0


def test_annealer_duck_types_via_value_of() -> None:
    # an AttackPath-like object exposing detection_cost but not value.
    @dataclass(frozen=True)
    class _APLike:
        impact: float
        detection_cost: float

    pool = [_APLike(impact=8.0, detection_cost=3.0), _APLike(impact=2.0, detection_cost=3.0)]
    res = anneal_path_portfolio(
        pool, budget=3.0, rng=Random(0), iterations=400, value_of=lambda p: p.impact
    )
    assert res.value == 8.0
    assert res.indices == (0,)
