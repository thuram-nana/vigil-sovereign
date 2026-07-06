"""
eval.benchmark_run — the public benchmark runner.

This is the deliverable that puts precision/recall numbers on the board: it stands
up the labelled vulnerable app (``eval.benchmark_app``), points CRUCIBLE and every
*available* incumbent scanner at it, scores each against the ground-truth manifest
with the comparative spine (``eval.validation``), and emits a public scoreboard.

Three entry points:

  * :func:`run_benchmark` — stand up the app, build the corpus, run the adapters,
    return the per-tool :class:`~eval.validation.Scoreboard` list. ``incumbents=False``
    is the CRUCIBLE-only path (no external tool required) the test drives.
  * :func:`write_report` — render a clean markdown scoreboard with an honest preamble.
  * :func:`main` — a CLI that prints the text table and writes the markdown report.
    (Exposed for the ``benchmark`` subcommand to wire; this module registers nothing.)

CRUCIBLE runs through :class:`BenchmarkCrucibleAdapter` — a thin ``CrucibleAdapter``
variant that enables the declarative check library (so the framework/exposure
checks run) and static DOM-XSS, scopes the sweep to query-value insertion points,
and drops the (slow, response-invisible) timing checks — every planted bug here is
response-visible, so out-of-band and timing coverage add cost without recall. It
reuses ``CrucibleAdapter``'s loopback guard and oracle-confirmed normalization.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from ..scanner.campaign import WebScanCampaign
from ..scanner.cli import loopback_send
from ..scanner.insertion import InsertionKind
from ..scanner.library import load_library
from .adapters import SqlmapAdapter
from .adapters_ext import NiktoAdapter, WapitiAdapter
from .benchmark_app import benchmark_corpus, serve
from .validation import (
    CorpusTarget,
    CrucibleAdapter,
    HarnessError,
    NormalizedFinding,
    Scoreboard,
    _is_loopback,
    comparative_report,
    render_table,
)

# CRUCIBLE's stated precision target for this benchmark (the success criterion).
PRECISION_TARGET = 0.98


class BenchmarkCrucibleAdapter(CrucibleAdapter):
    """CrucibleAdapter tuned for the benchmark: the declarative library on (so the
    exposure/framework checks run), static DOM-XSS on, query-value scope, timing
    checks dropped (irrelevant to the response-visible planted bugs and the
    dominant request cost), OOB off (bounded + fast). Reuses the parent's
    loopback-only guard and oracle-confirmed :meth:`_normalize`."""

    name: str = "crucible"

    def __init__(self, *, use_browser: bool = False, max_pages: int = 25, max_depth: int = 4) -> None:
        super().__init__(
            max_pages=max_pages,
            max_depth=max_depth,
            max_audit_requests=0,
            enable_oob=False,
            insertion_kinds=(InsertionKind.QUERY_VALUE,),
        )
        self._use_browser = use_browser

    def run(self, target: CorpusTarget) -> list[NormalizedFinding]:
        if not _is_loopback(target.base_url):
            raise HarnessError(
                f"BenchmarkCrucibleAdapter is loopback-only; refusing {target.base_url!r}."
            )
        # The shipped library minus the timing entries: every benchmark bug is
        # response-visible, so a statistical time-based sweep only adds latency.
        entries = [e for e in load_library() if e.oracle.kind != "timing"]
        report = WebScanCampaign(
            loopback_send,
            max_pages=self.max_pages,
            max_depth=self.max_depth,
            max_audit_requests=self.max_audit_requests,
            enable_oob=False,
            use_library=True,
            library_entries=entries,
            enable_domxss=True,
            enable_browser_xss=self._use_browser,
            enable_spa_crawl=self._use_browser,
            insertion_kinds=self.insertion_kinds,
        ).run(target.base_url)
        return [self._normalize(f) for f in report.active_findings]


def run_benchmark(*, use_browser: bool = False, incumbents: bool = True) -> list[Scoreboard]:
    """Stand up the benchmark app, score every available tool against its ground
    truth, and return the per-tool scoreboards.

    CRUCIBLE always runs (in-process). With ``incumbents=True`` the available
    incumbents (sqlmap + Wapiti + Nikto here) are added; :func:`comparative_report`
    silently skips any that are not installed. ``incumbents=False`` is the
    CRUCIBLE-only path — no external tool is invoked or required. ``use_browser``
    enables CRUCIBLE's dynamic browser passes (needs Chromium; skipped if absent)."""
    with serve() as base_url:
        corpus = benchmark_corpus(base_url)
        adapters = [BenchmarkCrucibleAdapter(use_browser=use_browser)]
        if incumbents:
            adapters += [SqlmapAdapter(), WapitiAdapter(), NiktoAdapter()]
        return comparative_report(corpus, adapters)


def write_report(scoreboards: list[Scoreboard], path: str | Path) -> Path:
    """Write a public markdown scoreboard (``tool | tp | fp | fn | precision |
    recall | f1``) with a short, honest preamble, and return the written path."""
    p = Path(path).expanduser()
    target = scoreboards[0].target if scoreboards else "crucible-benchmark-app"
    crucible = next((s for s in scoreboards if s.tool == "crucible"), None)

    lines: list[str] = []
    lines.append("# CRUCIBLE public benchmark scoreboard")
    lines.append("")
    lines.append(f"**Target corpus:** `{target}` — a single self-contained, labelled")
    lines.append("vulnerable web app with a known ground truth of eight planted bugs")
    lines.append("(reflected XSS, boolean-blind SQLi, error-based SQLi, open redirect,")
    lines.append("CORS-with-credentials, and three exposures: `.git/config`, `.env`, and")
    lines.append("Spring `/actuator/env`) plus three SAFE endpoints (`/profile`,")
    lines.append("`/api/health`, `/download`) that must never be flagged. Because the")
    lines.append("ground truth is complete, anything a tool reports off-manifest is a")
    lines.append("false positive **by construction** — that is what makes the FP column honest.")
    lines.append("")
    tools_ran = ", ".join(s.tool for s in scoreboards) or "(none)"
    lines.append(f"**Tools scored on this host:** {tools_ran}. Incumbents that are not")
    lines.append("installed are skipped, not failed. CRUCIBLE runs in-process against the")
    lines.append("loopback target and reports only oracle-confirmed findings.")
    lines.append("")
    lines.append(f"**CRUCIBLE precision target:** ≥ {PRECISION_TARGET:.2f} (zero false")
    lines.append("positives on the safe endpoints is the hard requirement).")
    if crucible is not None:
        verdict = "MEETS" if crucible.precision >= PRECISION_TARGET else "BELOW"
        lines.append("")
        lines.append(
            f"**CRUCIBLE result:** precision {crucible.precision:.3f} "
            f"({verdict} target), recall {crucible.recall:.3f}, f1 {crucible.f1:.3f} "
            f"(tp={crucible.true_positives}, fp={crucible.false_positives}, "
            f"fn={crucible.false_negatives})."
        )
    lines.append("")
    lines.append("## Scoreboard")
    lines.append("")
    lines.append("| tool | tp | fp | fn | precision | recall | f1 |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for s in scoreboards:
        lines.append(
            f"| {s.tool} | {s.true_positives} | {s.false_positives} | "
            f"{s.false_negatives} | {s.precision:.3f} | {s.recall:.3f} | {s.f1:.3f} |"
        )
    lines.append("")
    lines.append("### Reading the table")
    lines.append("")
    lines.append("Scores compare a tool's output against CRUCIBLE's ground-truth manifest,")
    lines.append("matched on `(normalized bug class, path+parameter)`. Incumbents that")
    lines.append("detect a bug under a different label vocabulary (e.g. generic")
    lines.append("`SQL Injection` vs the manifest's `error_based_sqli`) or a different")
    lines.append("location granularity (a host-level message vs a `request:<check>` token)")
    lines.append("will score below what they *found* — the raw finding lists tell the fuller")
    lines.append("story. The FP column, by contrast, is unambiguous: it counts detections on")
    lines.append("surfaces the corpus proves are clean.")
    lines.append("")

    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def main(argv: list[str]) -> int:
    """CLI: run the benchmark, print the comparative table, write the markdown
    report. Exposed for the ``benchmark`` subcommand to wire (this module
    registers nothing in ``__main__``)."""
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 benchmark",
        description="Run the CRUCIBLE public benchmark (CRUCIBLE vs available incumbents).",
    )
    parser.add_argument("--no-incumbents", action="store_true",
                        help="Score CRUCIBLE only; do not invoke sqlmap/wapiti/nikto.")
    parser.add_argument("--browser", action="store_true",
                        help="Enable CRUCIBLE's dynamic browser passes (needs Chromium).")
    parser.add_argument("--report", default="benchmark-report.md",
                        help="Path to write the markdown scoreboard (default: benchmark-report.md).")
    args = parser.parse_args(argv)

    boards = run_benchmark(use_browser=args.browser, incumbents=not args.no_incumbents)

    print(render_table(boards))
    report_path = write_report(boards, args.report)
    print(f"\nwrote {report_path}")
    return 0
