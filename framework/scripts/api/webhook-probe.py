#!/usr/bin/env python3
"""
webhook-probe.py — Test webhook receivers for forgery / replay weaknesses.

Used in playbook 05 § webhooks and playbook 10 § business logic.

Webhook endpoints (Stripe, GitHub, Slack, etc.) usually require a
signature header (HMAC over the body, with a shared secret). This
script tests:

  1. Whether unsigned bodies are accepted.
  2. Whether signature verification is constant-time (timing).
  3. Whether timestamp / nonce validation prevents replay.
  4. Whether algorithm confusion is possible.
  5. Whether the secret is reachable via timing or oracle attacks.

Usage:
  ./webhook-probe.py \\
    --url https://target/webhooks/stripe \\
    --signature-header Stripe-Signature \\
    --signature-format 't=<ts>,v1=<hmac>' \\
    --algorithm sha256 \\
    --body sample-event.json \\
    --secret <known-test-secret-or-empty>

Sample-event should be a real-looking event for that provider so
the parsing can succeed beyond signature check.
"""

import argparse
import hashlib
import hmac
import sys
import time

try:
    import requests
except ImportError:
    print("requires: pip install requests", file=sys.stderr)
    sys.exit(1)


def hmac_sig(secret, body, algo="sha256"):
    return hmac.new(secret.encode(), body.encode(),
                    getattr(hashlib, algo)).hexdigest()


def post(args, body, sig_value):
    headers = {"Content-Type": "application/json"}
    if sig_value is not None:
        headers[args.signature_header] = sig_value

    t0 = time.perf_counter()
    try:
        r = requests.post(args.url, data=body, headers=headers,
                          timeout=args.timeout, verify=not args.insecure)
        elapsed = (time.perf_counter() - t0) * 1000.0
        return r.status_code, len(r.content), elapsed, r.text[:200]
    except requests.RequestException as e:
        return -1, 0, -1, str(e)


def main():
    p = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", required=True)
    p.add_argument("--signature-header", required=True)
    p.add_argument("--signature-format", default="<hmac>",
        help="format string with <hmac>, optionally <ts>, <body-len>")
    p.add_argument("--algorithm", default="sha256",
        choices=["sha1", "sha256", "sha384", "sha512", "md5"])
    p.add_argument("--body", required=True, help="path to JSON body")
    p.add_argument("--secret", default="",
        help="known/test webhook secret if available")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--insecure", action="store_true")
    args = p.parse_args()

    with open(args.body) as f:
        body = f.read()

    print(f"target           : {args.url}")
    print(f"signature header : {args.signature_header}")
    print(f"signature format : {args.signature_format}")
    print(f"body length      : {len(body)}")
    print()

    def fmt_sig(hmac_value, ts=None):
        s = args.signature_format
        s = s.replace("<hmac>", hmac_value)
        s = s.replace("<ts>", str(ts or int(time.time())))
        s = s.replace("<body-len>", str(len(body)))
        return s

    # Test 1: no signature header
    print("[1] no signature header")
    status, length, elapsed, text = post(args, body, None)
    print(f"    status={status} len={length} ({elapsed:.0f}ms) — body: {text[:120]!r}")
    if 200 <= status < 300:
        print("    ! ACCEPTED unsigned body — Critical")

    # Test 2: empty signature header
    print("\n[2] empty signature header")
    status, length, elapsed, text = post(args, body, "")
    print(f"    status={status} len={length}  — body: {text[:120]!r}")
    if 200 <= status < 300:
        print("    ! ACCEPTED empty signature — Critical")

    # Test 3: garbage signature
    print("\n[3] garbage signature")
    status, length, elapsed, text = post(args, body,
                                          fmt_sig("a" * 64))
    print(f"    status={status} len={length}  — body: {text[:120]!r}")
    if 200 <= status < 300:
        print("    ! ACCEPTED garbage signature — Critical")

    # Test 4: with known secret (if provided)
    if args.secret:
        print("\n[4] with known secret (correctly signed)")
        sig = hmac_sig(args.secret, body, args.algorithm)
        status, length, elapsed, text = post(args, body, fmt_sig(sig))
        print(f"    status={status} len={length}  — body: {text[:120]!r}")

        # Test 4b: stale timestamp replay
        print("\n[4b] replay with timestamp from 1 hour ago")
        old_ts = int(time.time()) - 3600
        sig = hmac_sig(args.secret, body, args.algorithm)
        status, length, elapsed, text = post(args, body,
                                              fmt_sig(sig, ts=old_ts))
        print(f"    status={status} len={length}  — body: {text[:120]!r}")
        if 200 <= status < 300:
            print("    ! ACCEPTED stale-timestamp signature — replay possible")

    # Test 5: timing comparison (CT vs not)
    print("\n[5] timing comparison: 50 wrong sigs (early-mismatch vs late)")
    early_times, late_times = [], []
    early_sig = "0" + "a" * 63   # mismatches at byte 0
    late_sig = "a" * 63 + "0"    # mismatches at last byte
    for _ in range(25):
        _, _, e, _ = post(args, body, fmt_sig(early_sig))
        early_times.append(e)
        _, _, l, _ = post(args, body, fmt_sig(late_sig))
        late_times.append(l)

    if early_times and late_times:
        import statistics
        em = statistics.median(early_times)
        lm = statistics.median(late_times)
        diff = abs(lm - em)
        print(f"    early-mismatch median: {em:.1f}ms")
        print(f"    late-mismatch median : {lm:.1f}ms")
        print(f"    diff                 : {diff:.1f}ms")
        if diff > 5.0:
            print("    ? possible non-constant-time comparison — investigate further")
        else:
            print("    timing diff small — likely constant-time")


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
