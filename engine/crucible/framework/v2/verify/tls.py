"""
verify.tls — reproduce a real TLS handshake and confirm a weak protocol/cipher.

The TLS-posture half of prove-don't-guess (Wave 3). A scanner may *observe* "weak TLS"; this turns that
into a FACT by negotiating the handshake INDEPENDENTLY — a bounded TLS connect CRUCIBLE performs itself —
and judging the retained negotiated (protocol, cipher) with the pure ``tls_weakness_oracle``. Because the
evidence is JSON-safe, a confirmed weakness RE-VERIFIES OFFLINE from its certificate (``verify.reverify``)
with no network — the endpoint really agreed to that protocol/suite, and the record proves it.

The active connect reuses the SAME audited gate as ``verify.reachability`` (kill-switch -> single-host ->
ACTIVE_RECON entitlement -> charter scope, engagement slug required, fail-closed) and is bounded (one
attempt, hard timeout). Certificate validation is intentionally disabled — this is a crypto-POSTURE probe
of what a standard client negotiates, not a trust check, so it must work against self-signed / internal
endpoints (mirrors ``scanner.quantum_era.pqc_scan``). ``connect`` is injectable for offline tests.
"""

from __future__ import annotations

import base64
import socket
import ssl
from typing import Any, Callable

from .adapter import FindingContext
from .models import VerificationResult
from .reachability import _authorize   # reuse the audited active-connect gate (identical policy)
from .verifier import OracleVerifier

_DEFAULT_TIMEOUT = 5.0


def _tls_connect(host: str, port: int, timeout: float) -> tuple[str, str, int | None, bytes | None]:
    """The default connector: ONE bounded TLS handshake with a standard client. Returns
    (tls_version, cipher_name, cipher_bits, peer_cert_der); raises OSError/SSLError on a failed handshake.
    Cert validation is disabled on purpose (posture probe, not trust check — see the module docstring);
    ``getpeercert(binary_form=True)`` still returns the presented leaf DER under CERT_NONE, which the
    weak-crypto oracle judges (a broken-hash signature)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        raw.settimeout(timeout)
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            version = tls.version() or ""
            cipher = tls.cipher()
            try:
                cert_der = tls.getpeercert(binary_form=True)
            except Exception:
                cert_der = None
    name = cipher[0] if cipher else ""
    bits = cipher[2] if cipher and len(cipher) > 2 else None
    return version, name, (int(bits) if isinstance(bits, int) else None), cert_der


def capture_tls_handshake(
    host: str,
    port: int = 443,
    *,
    slug: str = "",
    timeout: float = _DEFAULT_TIMEOUT,
    connect: Callable[[str, int, float], tuple[str, str, int | None]] | None = None,
) -> dict:
    """Reproduce a bounded, gated TLS handshake to ``host:port`` and return JSON-safe evidence the
    oracle judges. Fail-closed: a gate refusal or a failed handshake returns ``connected: False`` with
    a reason — never an exception, never a fabricated negotiation. ``connect`` is injectable for tests."""
    base = {"connected": False, "host": str(host), "port": port}
    refusal = _authorize(str(host), port, slug)
    if refusal is not None:
        return {**base, "error": refusal}
    conn = connect or _tls_connect
    try:
        result = conn(str(host), int(port), timeout)
    except Exception as e:
        return {**base, "error": f"{type(e).__name__}: {e}"[:200]}
    # Flexible unpack: the default connector returns (version, cipher, bits, cert_der); an injected/legacy
    # connector may return the 3-tuple (version, cipher, bits) with no cert — both are honoured.
    version, cipher, bits = result[0], result[1], result[2]
    cert_der = result[3] if len(result) > 3 else None
    out = {"connected": True, "host": str(host), "port": int(port),
           "tls_version": str(version or ""), "cipher": str(cipher or "")}
    if isinstance(bits, int):
        out["cipher_bits"] = bits
    if cert_der:
        try:
            out["cert_der_b64"] = base64.b64encode(bytes(cert_der)).decode("ascii")
        except Exception:
            pass
    return out


def weak_tls_context(tls: dict) -> dict:
    """The verifier context for a captured TLS handshake — routes to the TLS-weakness oracle."""
    return FindingContext.from_tls_handshake(tls).to_verifier_context()


def confirm_weak_tls(tls: dict, *, verifier: OracleVerifier | None = None) -> VerificationResult:
    """Judge a captured TLS handshake: ``confirmed`` iff the endpoint really negotiated a deprecated
    protocol or a weak cipher. The retained ``tls`` is JSON-safe, so the same verdict re-verifies
    offline from the finding's certificate via ``verify.reverify``."""
    return (verifier or OracleVerifier()).confirm(weak_tls_context(tls))
