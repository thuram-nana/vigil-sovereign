#!/usr/bin/env python3
"""Emit a machine-readable VERIFICATION MANIFEST for a test run.

Rule 7 of docs/CLAIM-DISCIPLINE.md says verification claims must be re-checkable. Until now nothing made
them so: a quoted "1871 passed" was a sentence in a commit message, with no way to tell whether it came from
this commit, whether the suite was the one named, or whether a third of it skipped. That is the same class
of defect as an unbacked capability claim — an assertion about the world with no artifact behind it.

This runs a suite and writes a manifest recording what was actually executed: the command, the commit,
whether the tree was dirty, the exit status, pass/fail/skip/error counts, EVERY skipped test with its
reason (a suite that silently skipped its important half must not read as green), duration, and a digest
over the raw output so the manifest cannot be edited to disagree with the run it describes.

Counts come from pytest's JUnit XML, not from its prose. The first version scraped the human summary and
reported ZERO counts, because this pytest prints no summary line at all when a run is entirely green — a
verification tool that silently reports nothing is the same defect as a test that cannot fail.

    python3 tools/verification_manifest.py --out artifacts/verify.json -- pytest engine/... -q

The companion checker verifies a claim against a manifest:

    python3 tools/verification_manifest.py --check artifacts/verify.json --expect-passed 1871

Exit status is the suite's own, so this is safe to wrap around an existing CI step.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import os
import subprocess
import sys
import time
from pathlib import Path

_COUNT = re.compile(r"(\d+)\s+(passed|failed|skipped|error|errors|xfailed|xpassed|deselected)")


def _from_junit(xml_path: Path) -> "tuple[dict, list]":
    """Counts and per-test skips from pytest's JUnit XML.

    Scraping the human summary is not a sound source: this pytest prints NO summary line when a run is
    entirely green, so a text parser silently reported zero counts — a verification tool that cannot fail is
    the same defect as a test that cannot fail. The XML is emitted for every run and names each skipped test,
    which is what makes "no skip covers the behaviour I am claiming" checkable rather than assumed."""
    import xml.etree.ElementTree as ET

    if not xml_path.is_file():
        return {}, []
    root = ET.parse(xml_path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    total = failures = errors = skipped = 0
    skips: list[dict] = []
    for suite in suites:
        total += int(suite.get("tests", 0))
        failures += int(suite.get("failures", 0))
        errors += int(suite.get("errors", 0))
        skipped += int(suite.get("skipped", 0))
        for case in suite.iter("testcase"):
            for skip in case.findall("skipped"):
                skips.append({
                    "test": f"{case.get('classname', '')}::{case.get('name', '')}".lstrip(":"),
                    "reason": (skip.get("message") or "").strip(),
                })
    return ({"passed": total - failures - errors - skipped, "failed": failures,
             "error": errors, "skipped": skipped, "total": total}, skips)


# A skip is not just a number. "Green with a third skipped" is the failure mode this manifest exists to
# expose, and WHICH kind of skip it is changes what the run can support: an absent dependency leaves a
# capability unproven, an absent host capability leaves an integration unproven.
_DEPENDENCY_SKIP = re.compile(r"could not import|no module named|importorskip|requires? [\w.-]+ package", re.I)
_CAPABILITY_SKIP = re.compile(r"no working|not installed|unavailable|no running|not provisioned|browser|"
                              r"service|docker|network", re.I)


def _classify(skips: "list[dict]") -> "list[dict]":
    for skip in skips:
        text = f"{skip.get('test','')} {skip.get('reason','')}"
        if _DEPENDENCY_SKIP.search(text):
            skip["category"] = "unavailable_dependency"
        elif _CAPABILITY_SKIP.search(text):
            skip["category"] = "unavailable_capability"
        else:
            skip["category"] = "other"
    return skips


def _suite_identity(xml_path: Path) -> "dict":
    """Identify WHAT ran, so a narrowed selection cannot pass for the suite it claims to be.

    Records the test files that reported results and a digest over the sorted node ids. A run that quietly
    dropped half its files still reports a green exit status and a plausible count; only the identity
    catches it."""
    import xml.etree.ElementTree as ET

    if not xml_path.is_file():
        return {}
    root = ET.parse(xml_path).getroot()
    nodes = sorted(f"{c.get('classname','')}::{c.get('name','')}"
                   for s in ([root] if root.tag == "testsuite" else root.iter("testsuite"))
                   for c in s.iter("testcase"))
    files = sorted({n.split("::")[0] for n in nodes if n})
    return {
        "files": files,
        "file_count": len(files),
        "node_count": len(nodes),
        "node_digest": hashlib.sha256("\n".join(nodes).encode()).hexdigest(),
    }


def _git(*args: str) -> str:
    try:
        return subprocess.run(["git", *args], capture_output=True, text=True, check=False).stdout.strip()
    except OSError:                                     # pragma: no cover - git absent
        return ""


def run(command: "list[str]", out_path: Path) -> int:
    started = time.time()
    # Ask pytest for machine-readable results rather than parsing its prose.
    junit = out_path.with_suffix(".junit.xml")
    if any("pytest" in part for part in command) and not any(p.startswith("--junitxml") for p in command):
        command = [*command, f"--junitxml={junit}"]
    proc = subprocess.run(command, capture_output=True, text=True)
    output = proc.stdout + proc.stderr

    counts, skips = _from_junit(junit)
    skips = _classify(skips)
    if not counts:                                      # non-pytest command: fall back to the text summary
        for number, label in _COUNT.findall(output):
            counts[label.rstrip("s") if label == "errors" else label] = int(number)

    manifest = {
        "schema": "vigil-verification-manifest/1",
        "command": command,
        "commit": _git("rev-parse", "HEAD"),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "dirty": bool(_git("status", "--porcelain")),
        "exit_status": proc.returncode,
        "counts": counts,
        # Skips are recorded per TEST with their reasons on purpose: "green" while the meaningful half
        # skipped is the failure mode this manifest exists to expose, and naming them is what lets a claim
        # like "no skip covers admission" be checked instead of asserted.
        "skips": skips,
        "suite": _suite_identity(junit),
        # Bind the environment too: the same command on a different interpreter or without an optional
        # dependency is a different run, and a claim carried across them is not the claim that was checked.
        "environment": {
            "python": sys.version.split()[0],
            "platform": sys.platform,
            "pythonpath": os.environ.get("PYTHONPATH", ""),
            "executable": sys.executable,
        },
        "duration_seconds": round(time.time() - started, 2),
        "output_sha256": hashlib.sha256(output.encode("utf-8", "replace")).hexdigest(),
        "output_bytes": len(output.encode("utf-8", "replace")),
        "junit_sha256": (hashlib.sha256(junit.read_bytes()).hexdigest() if junit.is_file() else ""),
        "junit_path": str(junit) if junit.is_file() else "",
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    sys.stderr.write(
        f"[verification-manifest] {out_path}: exit={proc.returncode} counts={counts} "
        f"skips={len(manifest['skips'])} commit={manifest['commit'][:8]}"
        f"{' DIRTY' if manifest['dirty'] else ''}\n")
    sys.stdout.write(output)
    return proc.returncode


def check(manifest_path: Path, *, expect_passed: int | None, expect_commit: str | None,
          allow_dirty: bool, max_skipped: int | None, no_skip_covering: "list[str]" | None = None,
          expect_nodes: int | None = None, expect_suite_digest: str | None = None) -> int:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    problems: list[str] = []
    if manifest.get("exit_status") != 0:
        problems.append(f"the run FAILED (exit {manifest.get('exit_status')})")
    if expect_passed is not None and manifest["counts"].get("passed") != expect_passed:
        problems.append(f"claimed {expect_passed} passed, manifest says {manifest['counts'].get('passed')}")
    if expect_commit and not manifest.get("commit", "").startswith(expect_commit):
        problems.append(f"claimed commit {expect_commit}, manifest says {manifest.get('commit', '')[:12]}")
    if manifest.get("dirty") and not allow_dirty:
        problems.append("the tree was DIRTY, so the manifest does not describe the committed state")
    if max_skipped is not None and manifest["counts"].get("skipped", 0) > max_skipped:
        problems.append(f"{manifest['counts'].get('skipped')} skipped exceeds the allowed {max_skipped}")
    if expect_nodes is not None and manifest.get("suite", {}).get("node_count") != expect_nodes:
        problems.append(f"claimed {expect_nodes} tests, manifest ran "
                        f"{manifest.get('suite', {}).get('node_count')} — a narrowed selection can look green")
    if expect_suite_digest and manifest.get("suite", {}).get("node_digest") != expect_suite_digest:
        problems.append("the suite identity differs from the one claimed (different tests ran)")
    for term in (no_skip_covering or []):
        hits = [s for s in manifest.get("skips", [])
                if term.lower() in (s.get("test", "") + " " + s.get("reason", "")).lower()]
        if hits:
            problems.append(
                f"a skipped test covers {term!r} — the claim rests on behaviour that did not run: "
                + "; ".join(h.get("test", "?") for h in hits))
    if problems:
        print("VERIFICATION CLAIM REJECTED:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    by_category: dict[str, int] = {}
    for skip in manifest.get("skips", []):
        by_category[skip.get("category", "other")] = by_category.get(skip.get("category", "other"), 0) + 1
    print(f"verification claim OK: {manifest['counts']} at {manifest.get('commit','')[:8]} "
          f"({manifest.get('suite', {}).get('node_count')} tests"
          + (f", skips: {by_category}" if by_category else "") + ")")
    return 0


def main(argv: "list[str]") -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, help="write a manifest for the command after --")
    parser.add_argument("--check", type=Path, help="verify a claim against an existing manifest")
    parser.add_argument("--expect-passed", type=int)
    parser.add_argument("--expect-commit")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--max-skipped", type=int)
    parser.add_argument("--expect-nodes", type=int, help="fail if a different NUMBER of tests ran")
    parser.add_argument("--expect-suite-digest", help="fail if a different SET of tests ran")
    parser.add_argument("--no-skip-covering", action="append", default=[],
                        help="fail if any SKIPPED test mentions this term (e.g. admission, attribution)")
    parser.add_argument("command", nargs="*", help="the suite to run (after --)")
    args = parser.parse_args(argv)

    if args.check:
        return check(args.check, expect_passed=args.expect_passed, expect_commit=args.expect_commit,
                     allow_dirty=args.allow_dirty, max_skipped=args.max_skipped,
                     no_skip_covering=args.no_skip_covering, expect_nodes=args.expect_nodes,
                     expect_suite_digest=args.expect_suite_digest)
    if not args.out or not args.command:
        parser.error("give --out plus a command after --, or --check a manifest")
    return run(args.command, args.out)


if __name__ == "__main__":                              # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
