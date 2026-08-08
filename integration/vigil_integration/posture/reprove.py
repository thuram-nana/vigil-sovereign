"""posture.reprove — the CONTINUOUS posture re-proof loop (the "continuously re-proven" operating
property, mirroring remediation.reprove).

Each cycle re-scans the target, re-mints a fresh PostureCertificate, and appends it to the signed,
anti-rollback attestation series (``posture.series``). The cadence ``sleep`` is the ONLY clock and is
INJECTABLE, so tests run N cycles with a no-op sleep; nothing wall-clock/rng enters the signed series.
Ships as ``python -m vigil_integration.posture serve`` (a later packaging step wires the systemd unit
``vigil-posture@.timer``).

FATAL-2: framework is reached only through ``posture.attest`` (function-local imports); importing this
module co-loads no framework.

HONEST RESIDUAL (do not overclaim): "continuously re-proven" means "re-proven on a cadence" — the
freshness bound is only as current as the last cycle; it needs the target reachable; and, like every
posture claim, closure is bounded to the oracle family over the reached surface.
"""

from __future__ import annotations

import time as _time
from pathlib import Path
from typing import Any, Callable, Optional

from vigil_core.crypto import KeyPair, generate_keypair

from .series import append_posture_tick, verify_posture_series


def _default_build_cert(owner_key: KeyPair, engagement: str, *, max_pages: int, max_depth: int) -> dict:
    """Re-scan the authorized loopback benchmark and mint a fresh posture certificate (framework imports
    are function-local, in posture.attest)."""
    from vigil_core.capability import sign_identity_attestation

    from .attest import coverage_cert_from_report, scan_loopback_benchmark
    from .certificate import build_posture_certificate

    report = scan_loopback_benchmark(max_pages=max_pages, max_depth=max_depth)
    coverage = coverage_cert_from_report(report, max_pages=max_pages, max_depth=max_depth)
    att = sign_identity_attestation(owner_key, engagement=engagement, policy={"host": ["127.0.0.1"]},
                                    not_after=9_999_999_999)
    return build_posture_certificate(coverage, target_identity=att, target_sample={"host": "127.0.0.1"})


def run_posture_reprove(
    series_dir: str | Path,
    *,
    cycles: int,
    owner_key: Optional[KeyPair] = None,
    gov_key: Optional[KeyPair] = None,
    engagement: str = "posture-demo",
    interval: float = 0.0,
    sleep: Callable[[float], Any] = _time.sleep,
    build_cert: Optional[Callable[[], dict]] = None,
    max_pages: int = 25,
    max_depth: int = 4,
) -> dict:
    """Run ``cycles`` re-proof cycles, appending each fresh posture certificate to the anti-rollback
    series at ``series_dir``. ``build_cert`` (a fresh cert per call) defaults to a re-scan of the loopback
    benchmark; ``sleep``/``interval`` are injectable (determinism). Returns a summary."""
    owner = owner_key or generate_keypair()
    gov = gov_key or generate_keypair()
    if build_cert is None:
        build_cert = lambda: _default_build_cert(owner, engagement, max_pages=max_pages, max_depth=max_depth)
    signers = [("posture-gov", gov.private_key_b64)]
    last_head = None
    for i in range(int(cycles)):
        cert = build_cert()
        last_head = append_posture_tick(series_dir, cert, engagement_slug=engagement, signers=signers)
        if i < int(cycles) - 1:
            sleep(interval)
    return {
        "series_dir": str(series_dir),
        "cycles": int(cycles),
        "head_hash": getattr(last_head, "head_hash", None),
        "entry_count": getattr(last_head, "entry_count", None),
        "owner_pubkey": owner.public_key_b64,
        "gov_pubkey": gov.public_key_b64,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="vigil posture serve",
                                 description="continuous posture re-proof (anti-rollback series)")
    ap.add_argument("--series-dir", required=True)
    ap.add_argument("--cycles", type=int, default=1)
    ap.add_argument("--interval", type=float, default=0.0, help="seconds between cycles")
    ap.add_argument("--engagement", default="posture-demo")
    args = ap.parse_args(argv)
    res = run_posture_reprove(args.series_dir, cycles=args.cycles, engagement=args.engagement,
                              interval=args.interval)
    import json

    print(json.dumps(res, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
