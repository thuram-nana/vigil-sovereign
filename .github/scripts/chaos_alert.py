#!/usr/bin/env python3
"""W11-7 (#488) — the alert DECISION for the scheduled chaos-and-failover suite.

The scheduled workflow (``.github/workflows/scheduled-chaos-failover.yml``) runs the chaos suite on a
cadence; when it FAILS, its failure must ALERT (the #467 principle — a failing scheduled guardrail must
surface on its own, not sit silently red on a dashboard). On GitHub that alert is an opened issue.

This module is the small, PURE, stdlib-only decision the workflow calls, so the "failures alert" behaviour
is FALSIFIABLE offline (a required unit test asserts both outcomes) rather than buried in an ``if:``
expression no test can exercise:

  * ``should_alert(exit_code)`` — True iff the chaos run FAILED (any nonzero pytest exit: 1 = tests failed,
    2 = usage/collection error, 5 = no tests collected — all are alert-worthy). A PASS (0) does NOT alert
    (the negative control).
  * ``issue(exit_code, run_url)`` — the alert's issue title + body.

Run as ``python3 .github/scripts/chaos_alert.py --exit-code N [--run-url URL] [--expect-alert]``: it writes
``alert=true|false`` (+ ``issue_title`` / ``issue_body`` when alerting) to ``$GITHUB_OUTPUT`` and, with
``--expect-alert``, exits nonzero if the decision was NOT to alert — the workflow's negative-control step
uses that to prove the alert path fires on a known failure.
"""
from __future__ import annotations

import argparse
import os
import sys


def should_alert(exit_code: int) -> bool:
    """Alert iff the chaos suite did not pass cleanly. ANY nonzero exit is a failure worth alerting: a
    real assertion failure (1), a collection/usage error (2), or an empty collection (5, e.g. the suite was
    renamed away) — a silent no-run is exactly the failure a scheduled guardrail must not hide."""
    return int(exit_code) != 0


def issue(exit_code: int, *, run_url: str = "") -> tuple[str, str]:
    """The (title, body) of the alert issue for a failed scheduled chaos run."""
    title = f"chaos-and-failover scheduled suite FAILED (pytest exit {int(exit_code)})"
    body = (
        "The scheduled **chaos and failover** suite "
        "(`apps/sigil/tests/test_chaos_failover.py`, W11-7 / #488) failed on its cadence run.\n\n"
        f"- pytest exit code: `{int(exit_code)}`\n"
        f"- run: {run_url or '(url unavailable)'}\n\n"
        "This suite pins the DOCUMENTED behaviour of the single-writer sovereign spine under network "
        "partition, clock skew, a byzantine witness, and torn-page injection "
        "(`docs/architecture/HA-PROFILE.md`). A failure means real HA/failover behaviour has drifted from "
        "the documented guarantee, or a chaos guardrail regressed — investigate before the next failover.\n\n"
        "See the run log for the failing scenario. The same suite runs required per-PR in "
        "`SIGIL governor gates (P7 — offense gate + authn)`."
    )
    return title, body


def _emit_output(name: str, value: str) -> None:
    """Append a step output to $GITHUB_OUTPUT (multiline-safe via a heredoc delimiter)."""
    out = os.environ.get("GITHUB_OUTPUT")
    if not out:
        return
    with open(out, "a", encoding="utf-8") as f:
        if "\n" in value:
            f.write(f"{name}<<__CHAOS_EOF__\n{value}\n__CHAOS_EOF__\n")
        else:
            f.write(f"{name}={value}\n")


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(prog="chaos_alert")
    ap.add_argument("--exit-code", type=int, required=True, help="the chaos suite's pytest exit code")
    ap.add_argument("--run-url", default="", help="the Actions run URL to cite in the alert")
    ap.add_argument("--expect-alert", action="store_true",
                    help="negative control: exit nonzero if the decision was NOT to alert")
    args = ap.parse_args(argv)

    alert = should_alert(args.exit_code)
    _emit_output("alert", "true" if alert else "false")
    if alert:
        title, body = issue(args.exit_code, run_url=args.run_url)
        _emit_output("issue_title", title)
        _emit_output("issue_body", body)
        print(f"chaos_alert: ALERT (exit {args.exit_code}) — {title}")
    else:
        print(f"chaos_alert: no alert (exit {args.exit_code}) — the chaos suite passed")

    if args.expect_alert and not alert:
        print("::error::--expect-alert set but the decision was NOT to alert — the alert path is broken",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
