#!/usr/bin/env python3
"""Fail the two-env boundary job unless the boundary proof ACTUALLY executed.

A required check must never go green with its proof SKIPPED — "a skipped proof and a passing proof are the
same colour on a dashboard." The two-env boundary proof runs from SOURCE (test_two_env_boundary builds its
own sovereign venv; the keyless-actor governance-forge proof puts apps/sigil on sys.path itself), so a
failed best-effort sovereign build cannot stop it — but nothing re-checked that it RAN. Slice W0-13: the
boundary job's `pip install -e apps/sigil || echo "…boundary test will skip"` swallowed a build failure and
let the job pass with the proof unproven. This reads the JUnit XML the sovereign pytest leg wrote and exits
non-zero unless every named boundary proof is present in the report AND was not skipped/errored.

Usage: assert_boundary_proof_ran.py <junit.xml>

Matched by test-function NAME (so a module-path rename cannot silently drop a requirement) plus a classname
substring (so a same-named test elsewhere cannot satisfy it). A `pytest.importorskip` skip leaves a
<skipped> child on the testcase and pytest still exits 0 — that is precisely the case this turns red.
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET

# (required test-function name, substring its JUnit classname must contain).
REQUIRED: tuple[tuple[str, str], ...] = (
    # the dependency-graph guarantee — no sovereign member declares an offense dependency
    ("test_no_sovereign_member_declares_offense_dependency", "two_env_boundary"),
    # the assert_no_offense / sys.modules scan in a REAL sovereign venv (framework/strix unimportable)
    ("test_real_sovereign_venv_cannot_reach_offense", "two_env_boundary"),
    # a keyless offense actor cannot forge a verifiable governance event (proven vs the real sigil module)
    ("test_keyless_actor_cannot_forge_a_verifiable_governance_event", "offense_worker_keyless"),
)

_NON_EXECUTED = ("skipped", "error", "failure")


def _testcases(path: str) -> list[ET.Element]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        sys.exit(f"::error::cannot read the boundary-proof JUnit report {path!r}: {exc}")
    return list(root.iter("testcase"))


def evaluate(cases: list[ET.Element]) -> list[str]:
    """Return a list of human-readable problems; empty means every boundary proof executed cleanly."""
    problems: list[str] = []
    for name, classname_sub in REQUIRED:
        matches = [
            c
            for c in cases
            if (c.get("name") == name or (c.get("name") or "").startswith(name + "["))
            and classname_sub in (c.get("classname") or "")
        ]
        if not matches:
            problems.append(f"boundary proof {name!r} was NOT collected — it did not run at all")
            continue
        for c in matches:
            not_run = [child.tag for child in c if child.tag in _NON_EXECUTED]
            if not_run:
                problems.append(f"boundary proof {name!r} did not execute cleanly (found {not_run})")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.exit("usage: assert_boundary_proof_ran.py <junit.xml>")
    problems = evaluate(_testcases(argv[1]))
    if problems:
        for p in problems:
            print(f"::error::{p}")
        print(
            "::error::the two-env boundary proof did not actually execute — refusing to pass this REQUIRED "
            "job (a skipped proof and a passing proof are the same colour on a dashboard)"
        )
        return 1
    print(f"two-env boundary proof executed: {len(REQUIRED)}/{len(REQUIRED)} proofs ran, 0 skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
