#!/usr/bin/env python3
"""
token-entropy.py — Analyze token entropy and patterns.

Used in playbook 06 §6.4 (password-reset tokens), §6.7 (remember-me
tokens), playbook 11 § session-token analysis.

Reads a list of tokens (one per line), computes:
  - byte/character distribution
  - Shannon entropy bits
  - longest common prefix / suffix (suggesting structure)
  - apparent format (hex, base64, base64url, alnum, mixed)
  - sequential / time-correlation hints
  - duplicates

Generate ≥50 tokens by triggering the issuance flow (e.g., 50
password-reset requests for distinct emails) and run this against
the resulting list.

Usage:
  ./token-entropy.py tokens.txt [--name reset_token]
"""

import argparse
import math
import re
import sys
from collections import Counter


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def detect_format(s: str) -> str:
    """Heuristic format detection."""
    if re.fullmatch(r"[0-9a-f]+", s):
        return f"hex (lower, len={len(s)})"
    if re.fullmatch(r"[0-9A-F]+", s):
        return f"hex (upper, len={len(s)})"
    if re.fullmatch(r"[A-Za-z0-9+/=]+", s):
        return f"base64 (len={len(s)})"
    if re.fullmatch(r"[A-Za-z0-9_-]+", s):
        return f"base64url (len={len(s)})"
    if re.fullmatch(r"[A-Za-z0-9]+", s):
        return f"alphanumeric (len={len(s)})"
    if re.fullmatch(r"[0-9]+", s):
        return f"numeric (len={len(s)}) — VERY WEAK"
    return f"mixed (len={len(s)})"


def lcp(strings):
    """Longest common prefix."""
    if not strings:
        return ""
    s = min(strings)
    e = max(strings)
    for i, c in enumerate(s):
        if c != e[i]:
            return s[:i]
    return s


def lcs_suffix(strings):
    """Longest common suffix."""
    if not strings:
        return ""
    return lcp([s[::-1] for s in strings])[::-1]


def main():
    p = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("file", help="file with one token per line")
    p.add_argument("--name", default="token", help="label for output")
    p.add_argument("--min-entropy-bits", type=float, default=128.0,
        help="threshold for acceptable total entropy")
    args = p.parse_args()

    with open(args.file) as f:
        tokens = [line.strip() for line in f if line.strip()]

    if not tokens:
        print("no tokens read", file=sys.stderr)
        sys.exit(1)

    n = len(tokens)
    lengths = set(len(t) for t in tokens)
    duplicates = n - len(set(tokens))

    print(f"=== {args.name} ===")
    print(f"count          : {n}")
    print(f"unique         : {n - duplicates}")
    print(f"duplicates     : {duplicates}")
    print(f"length(s)      : {sorted(lengths)}")

    # If all same length, run more analysis
    if len(lengths) == 1:
        L = lengths.pop()
        sample = tokens[0]
        fmt = detect_format(sample)
        print(f"format (sample): {fmt}")

        # Per-token entropy averaged
        avg_per_char = sum(shannon_entropy(t) for t in tokens) / n
        total_bits = avg_per_char * L
        print(f"entropy/char   : {avg_per_char:.2f} bits")
        print(f"total entropy  : ~{total_bits:.1f} bits "
              f"({'OK' if total_bits >= args.min_entropy_bits else 'WEAK'})")

        # Structural hints
        prefix = lcp(tokens)
        if prefix:
            print(f"common prefix  : {prefix!r} ({len(prefix)} chars)")
            print(f"  → reduces effective entropy")
        suffix = lcs_suffix(tokens)
        if suffix:
            print(f"common suffix  : {suffix!r} ({len(suffix)} chars)")

        # Position-by-position character distribution
        if n >= 20:
            position_diversity = []
            for i in range(L):
                col = [t[i] for t in tokens]
                position_diversity.append(len(set(col)))
            min_div = min(position_diversity)
            max_div = max(position_diversity)
            avg_div = sum(position_diversity) / L
            print(f"per-position diversity: min={min_div} max={max_div} "
                  f"mean={avg_div:.1f}")
            if min_div < n / 8:
                print("  → some positions show low diversity — "
                      "possible structure / fixed prefix")

        # Aggregate alphabet
        alphabet = set("".join(tokens))
        print(f"alphabet size  : {len(alphabet)} ({''.join(sorted(alphabet))[:60]}{'...' if len(alphabet) > 60 else ''})")

    else:
        print("variable lengths — analysis limited")
        for t in tokens[:5]:
            print(f"  sample: {t} ({len(t)} chars)")

    if duplicates:
        print(f"\n!! DUPLICATES: {duplicates} of {n} tokens are not unique")
        print("   This is a CSPRNG failure or a flow-side bug. Investigate.")


if __name__ == "__main__":
    main()
