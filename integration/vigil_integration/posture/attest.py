"""posture.attest — mint a PostureCertificate from a live coverage scan.

The scan itself is offense-side (framework); every framework import here is FUNCTION-LOCAL, so importing
this module co-loads no framework (FATAL-2). The pure projection + signing live in ``posture.certificate``
(sovereign-safe); this module only supplies the live coverage cert and threads the keys.

The MVP live path scans the in-process loopback benchmark app (a reproducible, authorized target with a
complete ground truth), so a real end-to-end run — scan → coverage cert → posture cert → sign → bundle
→ third-party offline re-verify — is exercisable in CI with no external target. A real external target
reuses the same coverage machinery behind the gated executor + charter scope (a follow-on wiring).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from vigil_core.crypto import KeyPair, generate_keypair
from vigil_core.capability import sign_identity_attestation

from .bundle import export_posture_bundle
from .certificate import build_posture_certificate, sign_posture_certificate


def coverage_cert_from_report(report: Any, *, max_pages: int, max_depth: int,
                              budget_exhausted: bool = False) -> dict:
    """Build a coverage certificate dict from a ScanReport (framework import is function-local)."""
    from framework.v2.verify import coverage_oracle as co  # noqa: PLC0415 (FATAL-2: function-local)

    return co.build_coverage_certificate(report, max_pages=max_pages, max_depth=max_depth,
                                         budget_exhausted=budget_exhausted)


def scan_loopback_benchmark(*, max_pages: int = 25, max_depth: int = 4,
                            retain_evidence: bool = False) -> Any:
    """Run ONE real coverage scan of the in-process benchmark app → its ScanReport (framework
    import is function-local). The reproducible, authorized live target for the MVP proof.

    ``retain_evidence`` (OPT-IN) retains the re-execution kernel (predicate + observed values) on
    predicate-oracle probes so the resulting posture certificate carries RE-EXECUTABLE CLOSED claims a
    VIGIL-free verifier re-derives itself. Default OFF → the coverage certificate is byte-identical."""
    from framework.v2.eval.benchmark_app import serve  # noqa: PLC0415 (FATAL-2: function-local)
    from framework.v2.eval.benchmark_run import loopback_send  # noqa: PLC0415
    from framework.v2.scanner.campaign import WebScanCampaign  # noqa: PLC0415
    from framework.v2.scanner.insertion import InsertionKind  # noqa: PLC0415

    with serve() as base:
        return WebScanCampaign(
            loopback_send, max_pages=max_pages, max_depth=max_depth, enable_oob=False,
            insertion_kinds=(InsertionKind.QUERY_VALUE,), retain_evidence=retain_evidence,
        ).run(base)


def attest_loopback_benchmark(
    out_dir: str | Path,
    *,
    owner_key: Optional[KeyPair] = None,
    gov_key: Optional[KeyPair] = None,
    engagement: str = "posture-demo",
    max_pages: int = 25,
    max_depth: int = 4,
    retain_evidence: bool = False,
) -> dict:
    """End-to-end: scan the loopback benchmark app → coverage cert → posture cert → sign → export the
    portable bundle at ``out_dir``. Keys default to fresh ephemerals (the operator pins the returned
    fingerprint + owner pubkey OUT OF BAND, mirroring the benchmark's --sign fresh-key mode). Returns a
    dict of the artifacts (cert path, fingerprint, owner_pubkey, engagement, bundle dir, summary).

    ``retain_evidence`` (OPT-IN) mints RE-EXECUTABLE CLOSED claims (predicate + observed values embedded)
    so a third party re-derives the VERDICT from the retained (producer-supplied) values; the returned summary reports the
    per-tier CLOSED counts. Default OFF → a byte-identical binding-tier certificate."""
    owner = owner_key or generate_keypair()
    gov = gov_key or generate_keypair()
    report = scan_loopback_benchmark(max_pages=max_pages, max_depth=max_depth,
                                     retain_evidence=retain_evidence)
    coverage = coverage_cert_from_report(report, max_pages=max_pages, max_depth=max_depth)

    # The target's identity: the benchmark app is loopback. Bind to host 127.0.0.1.
    target_sample = {"host": "127.0.0.1"}
    identity = sign_identity_attestation(owner, engagement=engagement, policy={"host": ["127.0.0.1"]},
                                         not_after=9_999_999_999)
    cert = build_posture_certificate(coverage, target_identity=identity, target_sample=target_sample)

    out = Path(out_dir).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    cert_path = out / "posture-certificate.json"
    signers = [("posture-gov", gov.private_key_b64)]
    authorizers = [{"key_id": "posture-gov", "public_key_b64": gov.public_key_b64}]
    sig_env = sign_posture_certificate(cert, cert_path, signers=signers, authorizers=authorizers, threshold=1)
    fingerprint = (cert_path.with_suffix(".fingerprint.txt")).read_text().strip()

    bundle_dir = export_posture_bundle(out / "bundle", certificate=cert, sig_env=sig_env,
                                       fingerprint=fingerprint, owner_pubkey=owner.public_key_b64,
                                       engagement=engagement)
    return {
        "certificate_path": str(cert_path),
        "bundle_dir": str(bundle_dir),
        "fingerprint": fingerprint,
        "owner_pubkey": owner.public_key_b64,
        "engagement": engagement,
        "summary": cert.get("summary", {}),
        "target_sample": target_sample,
    }
