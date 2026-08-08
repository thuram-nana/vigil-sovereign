"""posture.bundle — the PORTABLE posture bundle: a self-contained directory a distrusting third party
re-verifies OFFLINE, with no VIGIL installed.

It ships the signed certificate + its signature + the out-of-band pins + a copy of the standalone
VIGIL-free verifier (``verify_offline.py`` == ``docs/proof-carrying-finding/verify_vf.py``) + a
HOW-TO-VERIFY.md with the exact command. The consumer input is ``bundle.json`` =
``{"posture": {"certificate": <cert>, "signature": <sig env>}}`` — exactly what
``verify_vf verify --bundle`` consumes.

Sovereign-safe: stdlib + vigil_core only. Deterministic content (no wall-clock / rng).
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from vigil_core import canonical_json

# The shipped standalone verifier (the VIGIL-free re-checker).
_VERIFIER_SRC = Path(__file__).resolve().parents[3] / "docs" / "proof-carrying-finding" / "verify_vf.py"


def _secure_write(path: Path, data: bytes | str) -> None:
    """Write 0600 (the bundle may sit in a shared dir before it is published)."""
    b = data if isinstance(data, bytes) else data.encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, b)
    finally:
        os.close(fd)


def _howto(fingerprint: str, owner_pubkey: str, engagement: str) -> str:
    return f"""# How to verify this posture certificate — OFFLINE, without VIGIL, without trusting the producer

This bundle contains a **Certificate of Non-Exploitability**: a signed, coverage-bounded proof that,
for each `(surface, parameter, vuln-class)` listed CLOSED, an applicable deterministic oracle had a
LIVE channel to the target and did **not** fire — bound to the target's owner-signed identity, with the
coverage denominator and honest residual on the face of the certificate.

You need only Python 3 + the `cryptography` package. You do **not** need VIGIL installed, network
access, or to trust us.

```bash
python3 verify_offline.py verify \\
    --bundle bundle.json \\
    --posture-fingerprint {fingerprint} \\
    --posture-owner-pubkey {owner_pubkey} \\
    --posture-engagement {engagement} \\
    --posture-now $(date +%s)
```

Exit 0 = SOUND. It re-checks, fail-closed: the m-of-n governance signature over the canonical bytes;
the out-of-band **fingerprint pin** above (obtain it from us on a channel separate from this bundle —
a forger who re-signs a tampered certificate with a fresh key is rejected before any signature check);
that every posture claim re-projects byte-identically from the embedded coverage evidence (a forged
CLOSED, or a CLOSED with no conclusive oracle, is refused); and that the embedded owner-signed identity
attestation binds the certificate to the scanned target (closes target-swap). Flip a single byte
anywhere → NOT SOUND.

## The honest boundary (read it — it is what makes the negative believable)
CLOSED means "not exploitable **by the oracle family, over the reached surface, as of the freshness
bound**" — NOT "secure against everything". Undiscovered endpoints/parameters are out of the
denominator (see `denominator` in the certificate). This offline check re-derives the signatures,
binding, coverage projection, and target-binding; it does **not** re-fire the oracle over raw bytes
(that needs VIGIL: a coverage re-run). The certificate states this residual on its face.
"""


def export_posture_bundle(
    out_dir: str | Path,
    *,
    certificate: dict,
    sig_env: dict,
    fingerprint: str,
    owner_pubkey: str,
    engagement: str,
) -> Path:
    """Assemble the portable posture bundle at ``out_dir``. ``certificate`` is the posture certificate
    dict (written back as its canonical bytes so it re-signs identically); ``sig_env`` is its signature
    envelope; ``fingerprint`` is the out-of-band authorizer pin; ``owner_pubkey`` / ``engagement`` bind
    the identity attestation. Returns the bundle directory."""
    out = Path(out_dir).expanduser()
    out.mkdir(parents=True, exist_ok=True)

    cert_bytes = canonical_json(certificate)
    # the consumer input the verifier reads
    bundle = {"posture": {"certificate": certificate, "signature": sig_env}}
    _secure_write(out / "bundle.json", canonical_json(bundle))
    # human-readable copies + the out-of-band pins (published on a SEPARATE channel)
    _secure_write(out / "posture-certificate.json", cert_bytes)
    _secure_write(out / "posture-certificate.sig.json", json.dumps(sig_env, indent=2, sort_keys=True) + "\n")
    _secure_write(out / "TRUST-ROOT-FINGERPRINT.txt", fingerprint.strip() + "\n")
    _secure_write(out / "posture-owner-pubkey.txt", owner_pubkey.strip() + "\n")
    _secure_write(out / "engagement.txt", engagement.strip() + "\n")
    _secure_write(out / "HOW-TO-VERIFY.md", _howto(fingerprint.strip(), owner_pubkey.strip(), engagement.strip()))
    # the shipped VIGIL-free verifier (a copy, so the bundle is self-contained)
    if _VERIFIER_SRC.is_file():
        shutil.copyfile(_VERIFIER_SRC, out / "verify_offline.py")
        os.chmod(out / "verify_offline.py", 0o644)
    return out
