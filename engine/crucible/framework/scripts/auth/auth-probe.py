#!/usr/bin/env python3
"""
auth-probe.py — Authentication endpoint enumeration & timing analysis.

Used in playbook 06 §6.2.

Probes a login endpoint with known-valid usernames vs known-invalid
usernames (each with a deliberately wrong password) and analyzes
timing, status, body length, and headers to detect username
enumeration.

Usage:
  ./auth-probe.py \\
    --url https://target.example/login \\
    --method POST \\
    --content-type form \\
    --username-field email \\
    --password-field password \\
    --valid-list known-valid-users.txt \\
    --invalid-list nonexistent-users.txt \\
    --password 'WrongPassword123!' \\
    --rounds 20

Output: stats printed; per-request log to ./auth-probe.log.

Notes:
- Use a wrong password that's unlikely to actually authenticate.
- Respect rate limits; add --delay if needed.
- Run from one IP for cleanest comparison; if rate-limit per IP
  fires, use --delay or split into smaller --rounds.
- This script does not bypass rate limiting; if you trip a lockout,
  back off.
"""

import argparse
import json
import statistics
import sys
import time
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("requires: pip install requests", file=sys.stderr)
    sys.exit(1)


def make_request(session, args, username):
    """Make one login attempt with the wrong password."""
    headers = {
        "User-Agent": args.user_agent,
    }

    if args.content_type == "json":
        headers["Content-Type"] = "application/json"
        body = json.dumps({
            args.username_field: username,
            args.password_field: args.password,
        })
    elif args.content_type == "form":
        body = {
            args.username_field: username,
            args.password_field: args.password,
        }
        # requests handles content-type for form
    else:
        raise ValueError(f"unknown content-type: {args.content_type}")

    start = time.perf_counter()
    try:
        if args.content_type == "json":
            resp = session.request(
                args.method, args.url,
                data=body, headers=headers,
                timeout=args.timeout,
                allow_redirects=False,
                verify=not args.insecure,
            )
        else:
            resp = session.request(
                args.method, args.url,
                data=body, headers=headers,
                timeout=args.timeout,
                allow_redirects=False,
                verify=not args.insecure,
            )
        elapsed = time.perf_counter() - start
        return {
            "username": username,
            "elapsed_ms": elapsed * 1000.0,
            "status": resp.status_code,
            "body_len": len(resp.content),
            "set_cookie": "Set-Cookie" in resp.headers,
            "location": resp.headers.get("Location", ""),
            "body_excerpt": resp.text[:200],
        }
    except requests.RequestException as e:
        return {
            "username": username,
            "elapsed_ms": -1,
            "status": -1,
            "error": str(e),
        }


def summarize(results, label):
    """Print per-class summary."""
    timings = [r["elapsed_ms"] for r in results if r["elapsed_ms"] > 0]
    statuses = [r["status"] for r in results if r["status"] > 0]
    body_lens = [r["body_len"] for r in results if "body_len" in r]
    set_cookies = [r["set_cookie"] for r in results if "set_cookie" in r]

    if not timings:
        print(f"[{label}] no successful requests")
        return None

    print(f"[{label}]")
    print(f"  count        : {len(results)}")
    print(f"  status set   : {sorted(set(statuses))}")
    print(f"  body len     : min={min(body_lens)} max={max(body_lens)} "
          f"mean={statistics.mean(body_lens):.0f}")
    print(f"  set-cookie   : {sum(set_cookies)} / {len(set_cookies)}")
    print(f"  timing ms    : min={min(timings):.1f} max={max(timings):.1f} "
          f"mean={statistics.mean(timings):.1f} "
          f"median={statistics.median(timings):.1f} "
          f"stdev={statistics.stdev(timings):.1f}" if len(timings) > 1 else
          f"  timing ms    : {timings[0]:.1f}")

    return {
        "label": label,
        "count": len(results),
        "statuses": sorted(set(statuses)),
        "body_lens": (min(body_lens), max(body_lens), statistics.mean(body_lens)),
        "set_cookies": sum(set_cookies),
        "timing_mean": statistics.mean(timings),
        "timing_median": statistics.median(timings),
    }


def diff_summary(s_valid, s_invalid):
    """Compare valid vs invalid stats."""
    if not s_valid or not s_invalid:
        return

    print("\n[diff] valid vs invalid")
    if s_valid["statuses"] != s_invalid["statuses"]:
        print(f"  STATUS DIFFERS: valid={s_valid['statuses']} "
              f"invalid={s_invalid['statuses']}")
    else:
        print(f"  status same: {s_valid['statuses']}")

    body_diff = s_valid["body_lens"][2] - s_invalid["body_lens"][2]
    print(f"  body length mean diff: {body_diff:+.1f} bytes "
          f"({'differs' if abs(body_diff) > 5 else 'similar'})")

    cookie_diff = s_valid["set_cookies"] - s_invalid["set_cookies"]
    if cookie_diff != 0:
        print(f"  SET-COOKIE DIFFERS: valid={s_valid['set_cookies']} "
              f"invalid={s_invalid['set_cookies']}")

    timing_diff = s_valid["timing_median"] - s_invalid["timing_median"]
    print(f"  timing median diff: {timing_diff:+.1f} ms "
          f"({'differs' if abs(timing_diff) > 50 else 'similar'})")

    if (s_valid["statuses"] != s_invalid["statuses"] or
            abs(body_diff) > 5 or
            cookie_diff != 0 or
            abs(timing_diff) > 50):
        print("  >> ENUMERATION SIGNAL DETECTED — investigate")
    else:
        print("  >> no obvious enumeration signal")


def main():
    p = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", required=True)
    p.add_argument("--method", default="POST")
    p.add_argument("--content-type", choices=["form", "json"], default="form")
    p.add_argument("--username-field", default="email")
    p.add_argument("--password-field", default="password")
    p.add_argument("--valid-list", required=True,
        help="file with one valid username/email per line")
    p.add_argument("--invalid-list", required=True,
        help="file with one nonexistent username/email per line")
    p.add_argument("--password", required=True,
        help="wrong password to use for all requests")
    p.add_argument("--rounds", type=int, default=20,
        help="how many usernames from each list to test")
    p.add_argument("--delay", type=float, default=0.0,
        help="seconds between requests")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--user-agent",
        default="OBSIDIAN/1.0 (+playbook-06)")
    p.add_argument("--insecure", action="store_true",
        help="skip TLS verification")
    p.add_argument("--log", default="auth-probe.log")
    args = p.parse_args()

    with open(args.valid_list) as f:
        valid_users = [line.strip() for line in f if line.strip()]
    with open(args.invalid_list) as f:
        invalid_users = [line.strip() for line in f if line.strip()]

    valid_users = valid_users[:args.rounds]
    invalid_users = invalid_users[:args.rounds]

    if not valid_users or not invalid_users:
        print("error: lists must be non-empty", file=sys.stderr)
        sys.exit(1)

    target = urlparse(args.url)
    print(f"target      : {target.netloc}{target.path}")
    print(f"method      : {args.method}")
    print(f"valid users : {len(valid_users)}")
    print(f"invalid users: {len(invalid_users)}")
    print(f"rounds      : {args.rounds}")
    print()

    session = requests.Session()

    valid_results = []
    invalid_results = []

    print("running valid-user probes...")
    for u in valid_users:
        r = make_request(session, args, u)
        valid_results.append(r)
        if args.delay:
            time.sleep(args.delay)

    print("running invalid-user probes...")
    for u in invalid_users:
        r = make_request(session, args, u)
        invalid_results.append(r)
        if args.delay:
            time.sleep(args.delay)

    # Write log
    with open(args.log, "w") as f:
        for r in valid_results + invalid_results:
            f.write(json.dumps(r) + "\n")
    print(f"\nlog written : {args.log}")

    # Summaries
    print()
    s_valid = summarize(valid_results, "valid-user")
    print()
    s_invalid = summarize(invalid_results, "invalid-user")
    diff_summary(s_valid, s_invalid)


if __name__ == "__main__":
    main()
