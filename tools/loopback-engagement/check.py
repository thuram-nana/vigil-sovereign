"""Assertions for the W11-1 loopback-engagement CI job (issue #482).

The end-to-end job (``tools/loopback-engagement/run_loopback_engagement.sh``) drives the real
``python3 -m framework.v2 scan`` against the repository's own loopback target and re-verifies the
result offline with ``python3 -m framework.v2 verify``. This module turns each leg of that chain into
a hard, machine-checked assertion so the job FAILS — rather than prints a wall of green text — when the
chain regresses. Every predicate is a pure function of parsed JSON so the negative controls in
``tests/test_check.py`` can perturb the inputs in-process and prove the checker BITES.

Two report artifacts feed the checks (both produced by one scan invocation):
  * the ``--format json`` report (``built``): carries ``summary.confirmed`` and the ``coverage`` object
    whose ``full_coverage`` flag is the CONCLUSIVE-coverage statement — the thing that makes a
    zero-finding result a SOUND negative rather than merely "the scanner reached nothing".
  * the ``--reverifiable-out`` report (``reverify``): the raw ScanReport whose ``active_findings`` each
    retain their ``oracle_context`` certificate — the document ``verify`` re-runs offline.

Usage:
    python3 check.py positive  --built V.json --reverify V.reverify.json [--floor N] [--require-class C ...]
    python3 check.py negative  --built S.json
    python3 check.py tamper    --in V.reverify.json --out V.tampered.json

Exit 0 iff the assertion holds (for ``tamper``: iff a certificate was actually mutated).
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

# The weaknesses PLANTED in infra/loopback/vulnapp.py's /search?q= surface (a string-concatenated
# query + an unescaped reflection). They are structural to the app, so a real end-to-end scan MUST
# confirm all three; the count floor is deliberately loose (library checks may confirm more, e.g.
# auth_bypass/nosqli that ride the same concatenated query) but these three are non-negotiable.
PLANTED_CLASSES = ("error_based_sqli", "boolean_sqli", "xss")

# A bug class the retained evidence can never adjudicate — used to forge a tampered certificate. The
# re-verifier rejects a finding whose requested class differs from the class its own evidence proves,
# so relabelling a finding to this class must make `verify` report BAD (the gate is not a rubber stamp).
_TAMPER_CLASS = "remote_code_execution_TAMPER_never_proved"


def load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------------------------------
# Pure predicates (perturbable in-process by the negative-control tests).
# --------------------------------------------------------------------------------------------------
def confirmed_count(built: dict) -> int:
    """Number of oracle-confirmed findings the scan reported (from the --format json summary)."""
    return int((built.get("summary") or {}).get("confirmed", -1))


def coverage_full(built: dict) -> bool:
    """The CONCLUSIVE-coverage flag: True only when the full check corpus (scanner.library, run under
    --library) actually contributed checks. This is what distinguishes a sound negative from silence."""
    return bool((built.get("coverage") or {}).get("full_coverage", False))


def confirmed_classes(reverify: dict) -> list[str]:
    """The bug classes of the confirmed findings in the raw (re-verifiable) ScanReport."""
    return [str(f.get("bug_class", "")) for f in (reverify.get("active_findings") or [])]


def every_finding_has_certificate(reverify: dict) -> bool:
    """A confirmed finding with no oracle_context could never be re-verified — refuse that as a fact."""
    findings = reverify.get("active_findings") or []
    return bool(findings) and all(isinstance(f.get("oracle_context"), dict) and f["oracle_context"]
                                  for f in findings)


def positive_reasons(built: dict, reverify: dict, floor: int, required: tuple[str, ...]) -> list[str]:
    """Empty iff the VULNERABLE-target scan is a valid positive: enough confirmed facts, the planted
    classes all present, full coverage, and every fact carrying a re-verifiable certificate."""
    reasons: list[str] = []
    n = confirmed_count(built)
    if n < floor:
        reasons.append(f"confirmed findings {n} < floor {floor}")
    classes = set(confirmed_classes(reverify))
    missing = [c for c in required if c not in classes]
    if missing:
        reasons.append(f"planted classes not confirmed: {missing} (saw {sorted(classes)})")
    if not coverage_full(built):
        reasons.append("coverage.full_coverage is false — the full corpus did not run (add --library)")
    if not every_finding_has_certificate(reverify):
        reasons.append("a confirmed finding carries no oracle_context certificate (not re-verifiable)")
    # The two artifacts must agree on how many facts there are — a built summary that disagrees with the
    # re-verifiable document would let one be gamed against the other.
    rv = len(reverify.get("active_findings") or [])
    if rv != n:
        reasons.append(f"built summary says {n} confirmed but the re-verifiable report has {rv}")
    return reasons


def negative_reasons(built: dict) -> list[str]:
    """Empty iff the PATCHED-target scan is a SOUND negative: zero confirmed findings AND a conclusive
    (full-corpus) coverage statement. Zero findings without full coverage is NOT a sound negative."""
    reasons: list[str] = []
    n = confirmed_count(built)
    if n != 0:
        reasons.append(f"patched target still produced {n} confirmed finding(s) — not clean")
    if not coverage_full(built):
        reasons.append("coverage.full_coverage is false — a zero-finding result over a partial corpus is "
                       "not a sound negative, only silence")
    return reasons


def tamper_document(doc: dict) -> tuple[dict, str]:
    """Return a COPY of a re-verifiable ScanReport with its first finding's certificate forged, plus a
    human note. Relabels the finding to a class its own retained evidence never proved, which the
    re-verifier must reject. Raises if there is no finding to tamper (a tamper control needs real input)."""
    out = copy.deepcopy(doc)
    findings = out.get("active_findings") or []
    if not findings:
        raise ValueError("no active_findings to tamper — the tamper control needs a real confirmed finding")
    original = str(findings[0].get("bug_class", ""))
    findings[0]["bug_class"] = _TAMPER_CLASS
    return out, f"relabelled finding[0] {original!r} -> {_TAMPER_CLASS!r}"


# --------------------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------------------
def _cmd_positive(args: argparse.Namespace) -> int:
    built, reverify = load(args.built), load(args.reverify)
    required = tuple(args.require_class) if args.require_class else PLANTED_CLASSES
    reasons = positive_reasons(built, reverify, args.floor, required)
    if reasons:
        print("POSITIVE CONTROL FAILED:")
        for r in reasons:
            print(f"  - {r}")
        return 1
    print(f"positive OK: {confirmed_count(built)} oracle-confirmed fact(s) "
          f"({', '.join(sorted(set(confirmed_classes(reverify))))}); full corpus; all certificated")
    return 0


def _cmd_negative(args: argparse.Namespace) -> int:
    built = load(args.built)
    reasons = negative_reasons(built)
    if reasons:
        print("NEGATIVE CONTROL FAILED (patched target should be a sound CLEAN):")
        for r in reasons:
            print(f"  - {r}")
        return 1
    print("negative OK: 0 confirmed findings over the FULL corpus — a sound negative (clean + conclusive)")
    return 0


def coverage_line(built: dict) -> str:
    """Reconstruct the operator-facing conclusive-coverage sentence from the machine report."""
    cov = built.get("coverage") or {}
    tail = "full corpus" if cov.get("full_coverage") else "PARTIAL corpus (library not run)"
    return (f"checks: {cov.get('built_in_run', '?')} built-in + {cov.get('library_run', '?')} library "
            f"— {tail}")


def _cmd_summarize(args: argparse.Namespace) -> int:
    built, reverify = load(args.built), load(args.reverify)
    print(f"scan {built.get('target', '?')}")
    print(f"  confirmed findings: {confirmed_count(built)}")
    for f in reverify.get("active_findings") or []:
        print(f"    [{f.get('confirmed_by')}] {f.get('bug_class')} @ {f.get('insertion_point')} "
              f"(conf {float(f.get('confidence', 0)):.2f})")
    print(f"  {coverage_line(built)}")
    return 0


def _cmd_tamper(args: argparse.Namespace) -> int:
    doc = load(args.inp)
    tampered, note = tamper_document(doc)
    Path(args.out).write_text(json.dumps(tampered, indent=2), encoding="utf-8")
    print(f"tampered certificate written to {args.out} ({note})")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="check.py", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    pp = sub.add_parser("positive", help="assert the vulnerable-target scan is a valid positive")
    pp.add_argument("--built", required=True)
    pp.add_argument("--reverify", required=True)
    pp.add_argument("--floor", type=int, default=3)
    pp.add_argument("--require-class", action="append", default=None)
    pp.set_defaults(func=_cmd_positive)

    pn = sub.add_parser("negative", help="assert the patched-target scan is a sound negative")
    pn.add_argument("--built", required=True)
    pn.set_defaults(func=_cmd_negative)

    ps = sub.add_parser("summarize", help="print a human-readable summary of a scan (for the demo)")
    ps.add_argument("--built", required=True)
    ps.add_argument("--reverify", required=True)
    ps.set_defaults(func=_cmd_summarize)

    pt = sub.add_parser("tamper", help="forge a tampered copy of a re-verifiable report")
    pt.add_argument("--in", dest="inp", required=True)
    pt.add_argument("--out", required=True)
    pt.set_defaults(func=_cmd_tamper)

    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
