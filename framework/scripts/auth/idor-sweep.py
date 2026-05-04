#!/usr/bin/env python3
"""
idor-sweep.py — Authorization matrix sweep across endpoints × sessions.

Used in playbook 07 §7.2, §7.3.

Reads a list of endpoints (with placeholders for IDs) and a list of
session profiles (each with cookies/auth-headers and a "self" user-
id). For every (endpoint, ID-context, session) triple, it issues a
request and logs status, content-length, content-type, and response
hash.

Then it prints a summary table that highlights:
  - Endpoints where session A returns OK on session B's IDs
    (horizontal IDOR / BOLA).
  - Endpoints where lower-priv session returns OK on admin endpoints
    (vertical / BFLA).

Configuration:
  ./idor-sweep.py --config config.yaml --output results.csv

config.yaml format:
---
sessions:
  alice:
    cookies:
      laravel_session: "<value>"
    self_id: 1001
  bob:
    cookies:
      laravel_session: "<value>"
    self_id: 1002
  admin:
    cookies:
      laravel_session: "<value>"
    self_id: 1
endpoints:
  - method: GET
    path: /api/v2/users/{id}
    id_field: id
    id_context: user
    expected:
      anonymous: 401
      self: 200
      sibling: 403
      admin: 200
  - method: GET
    path: /api/v2/orders/{id}
    id_field: id
    id_context: order
    expected: ...
ids:
  user:
    alice: 1001
    bob: 1002
    admin: 1
  order:
    alice: [12345, 12346]
    bob: [12347, 12348]
    admin: [1, 2, 3]
base_url: https://target.example
---
"""

import argparse
import csv
import hashlib
import sys
from urllib.parse import urljoin

try:
    import requests
    import yaml
except ImportError:
    print("requires: pip install requests pyyaml", file=sys.stderr)
    sys.exit(1)


def fetch(session_cfg, base_url, method, path, replacements, timeout=15):
    """Make one request. Return (status, body_len, content_type, body_sha)."""
    url = urljoin(base_url, path.format(**replacements))
    cookies = session_cfg.get("cookies", {})
    headers = session_cfg.get("headers", {})

    try:
        r = requests.request(method, url, cookies=cookies, headers=headers,
                             timeout=timeout, allow_redirects=False)
        body_sha = hashlib.sha256(r.content).hexdigest()[:12]
        return {
            "url": url,
            "status": r.status_code,
            "body_len": len(r.content),
            "content_type": r.headers.get("Content-Type", "")[:40],
            "body_sha": body_sha,
            "location": r.headers.get("Location", ""),
        }
    except requests.RequestException as e:
        return {
            "url": url,
            "status": -1,
            "body_len": 0,
            "content_type": "",
            "body_sha": "",
            "error": str(e),
        }


def main():
    p = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", required=True, help="YAML config")
    p.add_argument("--output", default="idor-sweep.csv")
    args = p.parse_args()

    with open(args.config) as f:
        cfg = yaml.safe_load(f)

    base_url = cfg["base_url"]
    sessions = cfg["sessions"]
    endpoints = cfg["endpoints"]
    ids = cfg["ids"]
    sessions["anonymous"] = {}  # add anonymous baseline

    # Collect results
    rows = []
    for ep in endpoints:
        method = ep["method"]
        path = ep["path"]
        ctx = ep["id_context"]    # "user", "order", etc.

        for session_name, session_cfg in sessions.items():
            # Test against each session-owner's IDs from the ids map
            for owner_name, owner_ids in ids.get(ctx, {}).items():
                if isinstance(owner_ids, list):
                    test_ids = owner_ids
                else:
                    test_ids = [owner_ids]

                for tid in test_ids:
                    replacements = {ep["id_field"]: tid}
                    res = fetch(session_cfg, base_url, method, path, replacements)
                    rows.append({
                        "session": session_name,
                        "method": method,
                        "path": path,
                        "id_owner": owner_name,
                        "id_value": tid,
                        **res,
                    })

    # Write CSV
    if rows:
        keys = ["session", "method", "path", "id_owner", "id_value",
                "status", "body_len", "content_type", "body_sha", "url"]
        with open(args.output, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
    print(f"wrote {len(rows)} rows to {args.output}")

    # Print summary highlighting cells of concern
    print("\n=== potentially interesting cells ===")
    print("# session reading another user's resource with status 200")
    for r in rows:
        if r["status"] == 200 and r["session"] != r["id_owner"] and \
           r["session"] != "anonymous":
            print(f"  {r['session']:>10} -> {r['method']:>4} {r['path']:<40} "
                  f"(owner={r['id_owner']}, id={r['id_value']}) → 200")

    print("\n# anonymous getting 200 on any resource")
    for r in rows:
        if r["status"] == 200 and r["session"] == "anonymous":
            print(f"  anonymous -> {r['method']:>4} {r['path']:<40} "
                  f"(owner={r['id_owner']}, id={r['id_value']}) → 200")

    print("\n# review the CSV for full matrix and outlier statuses")


if __name__ == "__main__":
    main()
