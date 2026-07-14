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

from typing import Any

from .adapter import FindingContext


def signature_descriptor(cert: Any) -> dict[str, str] | None:
    """Parse a PEM/DER X.509 cert into ``{signature_algorithm, oid, subject}``, or ``None`` when it cannot
    be parsed (or the ``cryptography`` lib is absent — the crypto branch is then dormant). Pure w.r.t.
    the cert bytes; never raises."""
    try:
        from cryptography import x509  # noqa: PLC0415
    except Exception:
        return None
    try:
        raw = cert.encode() if isinstance(cert, str) else bytes(cert)
        c = (x509.load_pem_x509_certificate(raw) if raw.lstrip().startswith(b"-----BEGIN")
             else x509.load_der_x509_certificate(raw))
    except Exception:
        return None
    oid = c.signature_algorithm_oid
    try:
        subject = c.subject.rfc4514_string()
    except Exception:
        subject = ""
    return {"signature_algorithm": getattr(oid, "_name", None) or "",
            "oid": oid.dotted_string, "subject": subject}


def weak_crypto_context(cert: Any) -> FindingContext | None:
    """A FindingContext for a supplied cert, or ``None`` when it cannot be parsed. The oracle — not this
    builder — decides whether the signature hash is broken; this only retains the descriptor it judges."""
    desc = signature_descriptor(cert)
    if desc is None:
        return None
    return FindingContext.from_crypto_artifact(desc)


def confirm_weak_crypto_artifact(cert: Any) -> Any:
    """Confirm a broken-signature-hash cert as a FACT, or ``None`` (unparseable, lib absent, or the
    signature hash is not broken). Thin seam over ``confirm_finding``."""
    from .confirmation import confirm_finding
    ctx = weak_crypto_context(cert)
    if ctx is None:
        return None
    subject = (ctx.crypto_artifact or {}).get("subject") or "certificate"
    return confirm_finding({"bug_class": "weak_crypto_artifact", "surface": subject}, ctx)
