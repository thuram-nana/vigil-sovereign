#!/usr/bin/env python3
"""Post-process a Trivy JSON report into an issue-opening decision for the scheduled scan.

WHY THIS EXISTS. The A14 gate (.github/workflows/supply-chain.yml) scans on every push/PR to
`main`, so a CVE that lands in an already-merged dependency is invisible until the NEXT pull
request happens to touch a lock. The scheduled scan (.github/workflows/scheduled-supply-chain-scan.yml)
closes that window by running daily and OPENING AN ISSUE when a finding crosses the threshold.

This module is the deterministic, network-free half of that job: it reads a Trivy `--format json`
report and decides whether an issue should be opened and, if so, what its title and body are. It is
pure standard library on purpose — it is exercised both by the workflow (which shells `gh issue
create` with the body this produces) and by integration/tests/test_dependency_automation.py, which
runs in the REQUIRED `integration two-env boundary (P5)` job with no network and no Trivy binary.

Keeping the DECISION here (rather than in shell inside the workflow) is what makes it testable: the
"open an issue" path can be proven to FIRE on a known-vulnerable fixture and to STAY SILENT on a
clean report, in-process, without a live scanner.

Exit codes:
  0  — ran cleanly (whether or not it decided to open an issue). This is an ADVISORY job.
  2  — `--expect-findings` was given but no finding at/above the threshold was present. This is the
       NEGATIVE CONTROL: the workflow feeds a fixture with a known-vulnerable package and asserts
       the decision path actually fires, so a green run can never mean a silently-broken scanner.
  3  — usage / unreadable report error.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from datetime import datetime, timezone

# Trivy severities, lowest to highest. A threshold of CRITICAL admits only CRITICAL; a threshold of
# HIGH admits HIGH and CRITICAL; and so on. This ordering is the single place severity is compared.
_SEVERITY_ORDER = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _rank(severity: str) -> int:
    try:
        return _SEVERITY_ORDER.index((severity or "UNKNOWN").upper())
    except ValueError:
        return 0


def collect_findings(report: dict, min_severity: str) -> list[dict]:
    """Every vulnerability in `report` at or above `min_severity`, de-duplicated.

    Pure and total: an empty report, a report whose Results carry no Vulnerabilities key, or a
    report with only sub-threshold findings all yield an empty list — which is exactly the clean-tree
    outcome the scheduled scan must treat as "nothing to open".
    """
    floor = _rank(min_severity)
    seen: set[tuple[str, str, str, str]] = set()
    out: list[dict] = []
    for result in report.get("Results") or []:
        target = str(result.get("Target", "") or "")
        for vuln in result.get("Vulnerabilities") or []:
            sev = str(vuln.get("Severity", "UNKNOWN") or "UNKNOWN").upper()
            if _rank(sev) < floor:
                continue
            key = (
                str(vuln.get("VulnerabilityID", "")),
                str(vuln.get("PkgName", "")),
                str(vuln.get("InstalledVersion", "")),
                target,
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "id": key[0],
                    "pkg": key[1],
                    "installed": key[2],
                    "fixed": str(vuln.get("FixedVersion", "") or ""),
                    "severity": sev,
                    "target": target,
                    "title": str(vuln.get("Title", "") or ""),
                    "url": str(vuln.get("PrimaryURL", "") or ""),
                }
            )
    # Most severe first, then by package for a stable body.
    out.sort(key=lambda f: (-_rank(f["severity"]), f["pkg"], f["id"]))
    return out


def build_issue(findings: list[dict], *, min_severity: str, run_url: str = "") -> tuple[str, str] | None:
    """(title, body) for the issue to open, or None when there is nothing at/above the threshold.

    Returning None on an empty finding list is the property that keeps this from being a gate that
    always fires: on a clean tree the scheduled scan opens nothing.
    """
    if not findings:
        return None
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    n = len(findings)
    noun = "vulnerability" if n == 1 else "vulnerabilities"
    title = f"Supply-chain scan: {n} {min_severity.upper()}+ {noun} ({day})"

    lines = [
        f"The scheduled supply-chain scan found **{n}** dependency {noun} at or above "
        f"**{min_severity.upper()}**.",
        "",
        "| Severity | Package | Installed | Fixed in | Advisory | Manifest |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for f in findings:
        adv = f"[{f['id']}]({f['url']})" if f["url"] else f["id"]
        fixed = f["fixed"] or "_none_"
        lines.append(
            f"| {f['severity']} | `{f['pkg']}` | `{f['installed']}` | `{fixed}` | {adv} | `{f['target']}` |"
        )
    lines += [
        "",
        "### What to do",
        "1. Bump each package to its **Fixed in** version (or add a justified `.trivyignore` entry "
        "if it is not exploitable in this context — see `docs/SUPPLY-CHAIN.md`).",
        "2. Regenerate the affected lock and re-run the A14 gate.",
        "",
        "_Opened automatically by `.github/workflows/scheduled-supply-chain-scan.yml`. "
        "Re-runs update nothing; close this issue once the finding is remediated or suppressed._",
    ]
    if run_url:
        lines.append(f"\nScan run: {run_url}")
    return title, "\n".join(lines)


def _emit_github_output(findings_count: int, title: str, body: str) -> None:
    """Write step outputs for the workflow's `gh issue create` step to consume."""
    out_path = os.environ.get("GITHUB_OUTPUT")
    if not out_path:
        return
    delim = "GHO_" + secrets.token_hex(8)
    with open(out_path, "a", encoding="utf-8") as fh:
        fh.write(f"findings={findings_count}\n")
        fh.write(f"issue_title<<{delim}\n{title}\n{delim}\n")
        fh.write(f"issue_body<<{delim}\n{body}\n{delim}\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", required=True, help="path to a Trivy --format json report")
    ap.add_argument("--min-severity", default="CRITICAL",
                    help="open an issue only on findings at or above this severity (default CRITICAL)")
    ap.add_argument("--run-url", default="", help="URL of the scan run, embedded in the body")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the decision but never write step outputs (used by the negative control)")
    ap.add_argument("--expect-findings", action="store_true",
                    help="exit 2 if NO finding at/above the threshold is present (the negative control assertion)")
    args = ap.parse_args(argv)

    try:
        with open(args.report, encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"::error::cannot read Trivy report {args.report!r}: {exc}", file=sys.stderr)
        return 3

    findings = collect_findings(report, args.min_severity)
    issue = build_issue(findings, min_severity=args.min_severity, run_url=args.run_url)

    if issue is None:
        print(f"no findings at or above {args.min_severity.upper()} — nothing to open.")
        if args.expect_findings:
            print("::error::NEGATIVE CONTROL FAILED — a fixture with a known-vulnerable package "
                  "produced no finding at/above the threshold. The issue-opening path cannot fire, "
                  "so a green scheduled run would mean nothing. Fix the scanner configuration.",
                  file=sys.stderr)
            return 2
        return 0

    title, body = issue
    if args.dry_run:
        print(f"DRY RUN — would open issue: {title}")
        print("----- body -----")
        print(body)
        print("----- end body -----")
        return 0

    _emit_github_output(len(findings), title, body)
    print(f"decided to open an issue: {title}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
