"""verify.weak_crypto — a certificate signed with a BROKEN hash (MD5/SHA1) as a weak-crypto FACT.

Offline + unconditionally provable (Phase-2 crypto coverage): an X.509 cert whose signatureAlgorithm
uses MD5/MD4/MD2 or SHA-1 is collision-forgeable (MD5 chosen-prefix, SHA-1 SHAttered), with NO benign use
for a certificate signature — a benign modern cert (SHA-256+) does not fire. The oracle
(``oracles.weak_crypto_artifact_oracle``, TLS_WEAKNESS kind) judges the retained signatureAlgorithm OID
NAME — a pure, re-verifiable string classification (no ambiguity, no rendering, no context). This module
is the CAPTURE seam: it parses a supplied cert (PEM or DER) into that descriptor. The
``weak_crypto_artifact`` bug_class / ``crypto_artifact`` ctx key is carried by no benchmark finding, so
the gate stays byte-identical.
"""

from __future__ import annotations

import re
from typing import Any

from .adapter import FindingContext

_PEM_BLOCK_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


def _descriptor_of(c: Any) -> dict[str, str]:
    """One parsed cert -> ``{signature_algorithm, oid, subject}``."""
    oid = c.signature_algorithm_oid
    try:
        subject = c.subject.rfc4514_string()
    except Exception:
        subject = ""
    return {"signature_algorithm": getattr(oid, "_name", None) or "",
            "oid": oid.dotted_string, "subject": subject}


def signature_descriptors(cert: Any) -> list[dict[str, str]]:
    """Parse a PEM/DER cert (or a PEM chain / bundle) into the per-cert ``{signature_algorithm, oid,
    subject}`` descriptors — ALL certs, so a weak-hash INTERMEDIATE CA (not just the leaf) is judged.
    ``[]`` when nothing parses (or ``cryptography`` is absent). Pure w.r.t. the bytes; never raises."""
    try:
        from cryptography import x509  # noqa: PLC0415
    except Exception:
        return []
    try:
        raw = cert.encode() if isinstance(cert, str) else bytes(cert)
    except Exception:
        return []
    certs: list[Any] = []
    if raw.lstrip().startswith(b"-----BEGIN"):
        try:  # cryptography >= 39 parses every CERTIFICATE block in one call
            certs = list(x509.load_pem_x509_certificates(raw))
        except AttributeError:  # older lib: split the blocks ourselves (skip a non-cert block like a key)
            for block in _PEM_BLOCK_RE.findall(raw):
                try:
                    certs.append(x509.load_pem_x509_certificate(block))
                except Exception:
                    continue
        except Exception:  # a single malformed / non-cert PEM (e.g. a private key) — try one, else none
            try:
                certs = [x509.load_pem_x509_certificate(raw)]
            except Exception:
                return []
    else:
        try:
            certs = [x509.load_der_x509_certificate(raw)]
        except Exception:
            return []
    return [_descriptor_of(c) for c in certs]


def signature_descriptor(cert: Any) -> dict[str, str] | None:
    """The LEAF cert's ``{signature_algorithm, oid, subject}`` descriptor, or ``None`` when nothing parses.
    (The leaf is the first block; :func:`signature_descriptors` returns the whole chain.)"""
    descs = signature_descriptors(cert)
    return descs[0] if descs else None


def weak_crypto_context(cert: Any) -> FindingContext | None:
    """A FindingContext for a supplied cert/chain, or ``None`` when nothing parses. When a chain is given,
    certify the FIRST cert whose signature hash is broken (so a weak-hash INTERMEDIATE fires, not just the
    leaf); if none is broken, certify the leaf (the context exists but the oracle will not fire). The
    oracle — not this builder — decides weakness; here it only PICKS which retained descriptor to judge."""
    from .oracles import weak_crypto_artifact_oracle
    descs = signature_descriptors(cert)
    if not descs:
        return None
    broken = next((d for d in descs if weak_crypto_artifact_oracle(d).fired), None)
    return FindingContext.from_crypto_artifact(broken if broken is not None else descs[0])


def confirm_weak_crypto_artifact(cert: Any) -> Any:
    """Confirm a broken-signature-hash cert as a FACT, or ``None`` (unparseable, lib absent, or the
    signature hash is not broken). Thin seam over ``confirm_finding``."""
    from .confirmation import confirm_finding
    ctx = weak_crypto_context(cert)
    if ctx is None:
        return None
    subject = (ctx.crypto_artifact or {}).get("subject") or "certificate"
    return confirm_finding({"bug_class": "weak_crypto_artifact", "surface": subject}, ctx)


def crypto_descriptor_context(descriptor: Any) -> dict:
    """The verifier context for an ALREADY-PARSED cert descriptor (``{signature_algorithm, oid,
    subject}``) — routes to the weak-crypto-artifact oracle. Used by the cert-capture feed
    (``sensors.tls_cert`` / ``engage_fusion``), which retains the descriptor rather than the raw bytes."""
    from collections.abc import Mapping
    src = descriptor if isinstance(descriptor, Mapping) else {}
    return FindingContext.from_crypto_artifact(dict(src)).to_verifier_context()


def confirm_crypto_descriptor(descriptor: Any, *, verifier: Any = None) -> Any:
    """Judge one retained cert descriptor: ``confirmed`` iff the oracle re-derives a broken signature hash
    over its OID name. Offline; never raises. Mirrors ``confirm_cicd_posture`` / ``confirm_mobile_posture``
    (routes through the verifier, the sole fact authority) for the fusion promotion path."""
    from .verifier import OracleVerifier
    return (verifier or OracleVerifier()).confirm(crypto_descriptor_context(descriptor))
