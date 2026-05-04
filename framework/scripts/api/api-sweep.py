#!/usr/bin/env python3
"""
api-sweep.py — enumerate API endpoints with method × parameter variations.

Used in playbook 05.

Reads an OpenAPI/Swagger document or an endpoint list, and for each
endpoint:
  - tries supported methods (GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD)
  - tries with/without auth
  - tries with mass-assignment probe fields
  - logs status / length / content-type to a CSV

The output is the basis for the role × endpoint matrix and for
identifying interesting cells (e.g. endpoint accepts unauthenticated
PUT but expected to be auth-required).

Usage:
  ./api-sweep.py --base-url https://target.example \\
                 --endpoints endpoints.txt \\
                 --auth-cookie 'sid=...' \\
                 --output api-sweep.csv

endpoints.txt format: one path per line, e.g.:
  /api/v2/orders
  /api/v2/orders/{id}
  /api/v2/users
"""

import argparse
import csv
import sys
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    print("requires: pip install requests", file=sys.stderr)
    sys.exit(1)


METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

# Mass-assignment probe fields (per playbook 07 §7.4)
MASS_ASSIGN_PROBE = {
    "role": "admin",
    "is_admin": True,
    "admin": True,
    "scope": "admin",
    "permissions": ["admin"],
    "balance": 999999,
    "verified": True,
    "email_verified": True,
}


def request_one(base_url, path, method, cookies, headers,
                body=None, params=None, timeout=15):
    url = urljoin(base_url, path)
    try:
        r = requests.request(method, url, cookies=cookies, headers=headers,
                             json=body, params=params, timeout=timeout,
                             allow_redirects=False, verify=False)
        return {
            "url": url,
            "status": r.status_code,
            "len": len(r.content),
            "ctype": r.headers.get("Content-Type", "")[:40],
            "location": r.headers.get("Location", "")[:80],
            "excerpt": r.text[:120].replace("\n", " "),
        }
    except requests.RequestException as e:
        return {
            "url": url,
            "status": -1,
            "len": 0,
            "ctype": "",
            "excerpt": f"ERR: {e.__class__.__name__}",
        }


def main():
    p = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base-url", required=True)
    p.add_argument("--endpoints", required=True,
        help="file with one path per line")
    p.add_argument("--auth-cookie", default="",
        help="cookie string for auth (e.g. 'sid=abc')")
    p.add_argument("--auth-header", default="",
        help="header for auth (e.g. 'Authorization: Bearer abc')")
    p.add_argument("--id-substitution", default="1",
        help="value to substitute for {id} placeholders")
    p.add_argument("--output", default="api-sweep.csv")
    p.add_argument("--mass-assign", action="store_true",
        help="also probe with mass-assignment fields on POST/PUT/PATCH")
    p.add_argument("--probe-anonymous", action="store_true",
        help="also probe each endpoint with no auth")
    args = p.parse_args()

    cookies = {}
    if args.auth_cookie:
        for c in args.auth_cookie.split(";"):
            if "=" in c:
                k, v = c.split("=", 1)
                cookies[k.strip()] = v.strip()
    headers = {"User-Agent": "OBSIDIAN/1.0 (+playbook-05)"}
    if args.auth_header and ":" in args.auth_header:
        k, v = args.auth_header.split(":", 1)
        headers[k.strip()] = v.strip()

    with open(args.endpoints) as f:
        paths = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    rows = []
    for raw_path in paths:
        # Substitute placeholders
        path = raw_path.replace("{id}", args.id_substitution)
        path = path.replace("{user_id}", args.id_substitution)
        path = path.replace("{order_id}", args.id_substitution)

        for method in METHODS:
            # Authed
            res = request_one(args.base_url, path, method, cookies, headers)
            rows.append({
                "path": path, "method": method, "auth": "authed",
                "probe": "", **res,
            })

            # Anonymous
            if args.probe_anonymous:
                res = request_one(args.base_url, path, method, {}, headers)
                rows.append({
                    "path": path, "method": method, "auth": "anonymous",
                    "probe": "", **res,
                })

        # Mass-assignment probes
        if args.mass_assign:
            for field, value in MASS_ASSIGN_PROBE.items():
                body = {field: value}
                for method in ["POST", "PUT", "PATCH"]:
                    res = request_one(args.base_url, path, method,
                                      cookies, headers, body=body)
                    rows.append({
                        "path": path, "method": method, "auth": "authed",
                        "probe": f"mass:{field}", **res,
                    })

    # Write CSV
    keys = ["path", "method", "auth", "probe", "status", "len",
            "ctype", "location", "excerpt"]
    with open(args.output, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows)} rows to {args.output}")

    # Summary highlights
    print("\n=== highlights ===")
    print("# anonymous getting 200 / 201 / 204:")
    for r in rows:
        if r["auth"] == "anonymous" and r["status"] in (200, 201, 204):
            print(f"  {r['method']:>6} {r['path']:<50} → {r['status']}")

    print("\n# unexpected 200 on DELETE / PUT (often sign of weak protection):")
    for r in rows:
        if r["method"] in ("DELETE", "PUT") and r["status"] == 200:
            print(f"  {r['auth']:>9} {r['method']:>6} {r['path']:<40} → 200")

    print("\n# mass-assignment 200 responses (investigate manually):")
    for r in rows:
        if r["probe"].startswith("mass:") and r["status"] == 200:
            print(f"  {r['method']:>6} {r['path']:<40} probe={r['probe']} → 200")


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
