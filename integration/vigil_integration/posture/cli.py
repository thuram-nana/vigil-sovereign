"""posture.cli — ``python -m vigil_integration.posture <attest|verify>``.

  attest  — scan the authorized loopback benchmark target, mint + sign a PostureCertificate, and export
            a portable bundle a third party re-verifies offline. Prints the artifacts + the OUT-OF-BAND
            pins (publish the fingerprint + owner pubkey on a channel separate from the bundle).
  verify  — re-verify a bundle exactly as a distrusting third party would: shell out to the bundle's
            OWN shipped ``verify_offline.py`` (VIGIL-free) with the pins. Exit 0 iff SOUND.

(A future packaging step registers this as the ``vigil posture`` dispatch verb; the logic is here so it
is runnable + testable today without a reinstall.)
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path


def _cmd_attest(args: argparse.Namespace) -> int:
    from .attest import attest_loopback_benchmark  # function-local (framework touch is deeper still)

    res = attest_loopback_benchmark(args.out, engagement=args.engagement,
                                    max_pages=args.max_pages, max_depth=args.max_depth)
    print(json.dumps(res, indent=2, sort_keys=True))
    print("\nPUBLISH THESE OUT-OF-BAND (a verifier needs them, on a channel separate from the bundle):")
    print(f"  --posture-fingerprint   {res['fingerprint']}")
    print(f"  --posture-owner-pubkey  {res['owner_pubkey']}")
    print(f"  --posture-engagement    {res['engagement']}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    bundle = Path(args.bundle).expanduser()
    if bundle.is_dir():
        d = bundle
        bundle_json = d / "bundle.json"
    else:
        d = bundle.parent
        bundle_json = bundle
    verifier = d / "verify_offline.py"
    if not verifier.is_file() or not bundle_json.is_file():
        print(f"[ERROR] {d} is not a posture bundle (needs bundle.json + verify_offline.py)", file=sys.stderr)
        return 3
    fp = args.posture_fingerprint or _read(d / "TRUST-ROOT-FINGERPRINT.txt")
    owner = args.posture_owner_pubkey or _read(d / "posture-owner-pubkey.txt")
    eng = args.posture_engagement or _read(d / "engagement.txt")
    now = str(args.posture_now if args.posture_now is not None else int(time.time()))
    # Run the bundle's OWN shipped verifier — the exact third-party, VIGIL-free experience.
    cmd = [sys.executable, str(verifier), "verify", "--bundle", str(bundle_json),
           "--posture-fingerprint", fp, "--posture-owner-pubkey", owner,
           "--posture-engagement", eng, "--posture-now", now]
    return subprocess.run(cmd).returncode


def _cmd_endpoint(args: argparse.Namespace) -> int:
    from .endpoint import run_posture_endpoint_forever
    print(f"serving posture bundle {args.bundle} read-only at http://{args.host}:{args.port}/posture "
          f"(GET-only; loopback/tunnel-bound). Ctrl-C to stop.")
    run_posture_endpoint_forever(args.host, args.port, args.bundle)
    return 0


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8").strip() if p.is_file() else ""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vigil posture",
                                 description="Certificate of Non-Exploitability — mint + verify.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("attest", help="scan the authorized loopback target, mint + sign a posture "
                                      "certificate, export a portable bundle")
    a.add_argument("--out", required=True, help="output directory for the certificate + bundle")
    a.add_argument("--engagement", default="posture-demo")
    a.add_argument("--max-pages", type=int, default=25)
    a.add_argument("--max-depth", type=int, default=4)
    a.set_defaults(fn=_cmd_attest)

    v = sub.add_parser("verify", help="re-verify a bundle offline via its own shipped verify_offline.py")
    v.add_argument("--bundle", required=True, help="the bundle directory (or its bundle.json)")
    v.add_argument("--posture-fingerprint", default="", help="override the bundle's fingerprint pin")
    v.add_argument("--posture-owner-pubkey", default="", help="override the bundle's owner pubkey")
    v.add_argument("--posture-engagement", default="", help="override the bundle's engagement")
    v.add_argument("--posture-now", type=int, default=None, help="epoch time to check not_after (default: now)")
    v.set_defaults(fn=_cmd_verify)

    e = sub.add_parser("endpoint", help="serve the latest signed bundle read-only (loopback/tunnel only) so "
                                        "a counterparty can poll + verify it offline")
    e.add_argument("--bundle", required=True, help="the bundle directory to serve")
    e.add_argument("--host", default="127.0.0.1")
    e.add_argument("--port", type=int, default=8787)
    e.set_defaults(fn=_cmd_endpoint)

    args = ap.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
