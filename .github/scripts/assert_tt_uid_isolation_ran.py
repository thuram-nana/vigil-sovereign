#!/usr/bin/env python3
"""Fail the AEGIS TT distinct-uid isolation leg unless the real-OS-boundary proofs ACTUALLY executed.

AS-1a's cross-tenant isolation guarantee is only a real OS boundary when each test tenant runs in its OWN
process under a DISTINCT uid (framework/v2/aegis/tt_rig.py: ``_start_subprocess_tenant`` chowns the tenant
subtree to the tenant uid at mode 0700; ``_serve_tenant`` drops privilege with ``setgid``/``setgroups([])``/
``setuid``). The two tests that exercise that boundary —

    integration/tests/IT/test_aegis_tt_rig.py::test_observe_acceptance_distinct_uids
    integration/tests/IT/test_aegis_tt_rig.py::test_cli_require_uids_runs_distinct

— are guarded by ``@pytest.mark.skipif(not tt_uids_provisionable())``, i.e. they can only run where the
process is root AND ``useradd`` is on PATH. The only other leg that collects this file is the offense leg of
the "integration two-env boundary (P5)" job, which runs on a plain ``ubuntu-latest`` as the non-root
``runner`` user — so both tests SKIP there, silently, on every run. A skipped proof and a passing proof are
the same colour on a dashboard: with isolation never exercised, a regression (e.g. ``os.chmod(tenant_root,
0o700)`` → ``0o755`` or dropping ``os.setgroups([])``) would ship GREEN. The new root-container leg makes
them RUN; this guard is what stops that leg from silently regressing back to skipping.

``pytest`` exits 0 when a skipif skip fires (``<skipped>`` child on the testcase) and exits 0 when a node id
selects nothing after a rename — both would leave the leg green having proved nothing. So this does not trust
the exit code: it reads the JUnit report the pytest run wrote and FAILS unless every named proof below is
present AND was neither skipped, errored, nor failed. ``pytest_require_planes`` does NOT cover this skip —
its reason ("distinct-uid TT path needs a root runner with useradd") names no plane — which is exactly why
this dedicated assertion exists.

Usage: assert_tt_uid_isolation_ran.py <junit.xml>

Matched by test-function NAME (so a module-path rename cannot silently drop a requirement) plus a classname
substring (so a same-named test elsewhere cannot satisfy it).
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET

# (required test-function name, substring its JUnit classname must contain).
REQUIRED: tuple[tuple[str, str], ...] = (
    # the acceptance re-run with each tenant in its OWN process under a DISTINCT uid — the cross-tenant
    # isolation is then a real OS boundary, not just in-process separation.
    ("test_observe_acceptance_distinct_uids", "aegis_tt_rig"),
    # the CLI entry honours --require-uids / VIGIL_REQUIRE_TT_UIDS and actually runs the distinct-uid path.
    ("test_cli_require_uids_runs_distinct", "aegis_tt_rig"),
)

_NON_EXECUTED = ("skipped", "error", "failure")


def _testcases(path: str) -> list[ET.Element]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        sys.exit(f"::error::cannot read the TT-uid-isolation JUnit report {path!r}: {exc}")
    return list(root.iter("testcase"))


def evaluate(cases: list[ET.Element]) -> list[str]:
    """Return a list of human-readable problems; empty means every isolation proof executed cleanly."""
    problems: list[str] = []
    for name, classname_sub in REQUIRED:
        matches = [
            c
            for c in cases
            if (c.get("name") == name or (c.get("name") or "").startswith(name + "["))
            and classname_sub in (c.get("classname") or "")
        ]
        if not matches:
            problems.append(
                f"distinct-uid isolation proof {name!r} was NOT collected — it did not run at all "
                "(a skipif on a non-root runner, or a rename)"
            )
            continue
        for c in matches:
            not_run = [child.tag for child in c if child.tag in _NON_EXECUTED]
            if not_run:
                problems.append(
                    f"distinct-uid isolation proof {name!r} did not execute cleanly (found {not_run}) — "
                    "the leg must RUN as root with useradd so the OS-boundary test is not skipped"
                )
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.exit("usage: assert_tt_uid_isolation_ran.py <junit.xml>")
    problems = evaluate(_testcases(argv[1]))
    if problems:
        for p in problems:
            print(f"::error::{p}")
        print(
            "::error::the AEGIS TT distinct-uid isolation proof did not actually execute — refusing to pass "
            "this leg (a skipped proof and a passing proof are the same colour on a dashboard)"
        )
        return 1
    print(f"TT distinct-uid isolation proof executed: {len(REQUIRED)}/{len(REQUIRED)} proofs ran, 0 skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
