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
import json
import subprocess
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
    MeasuredBoard,
    NormalizedFinding,
    RunMetrics,
    Scoreboard,
    _is_loopback,
    comparative_report_measured,
    render_measured_table,
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
        return self._record(report)


def run_benchmark_measured(
    *, use_browser: bool = False, incumbents: bool = True
) -> list[MeasuredBoard]:
    """Stand up the benchmark app and return each available tool's accuracy
    Scoreboard paired with its :class:`RunMetrics` (time / requests / RSS /
    discovery). The measured superset of :func:`run_benchmark`."""
    with serve() as base_url:
        corpus = benchmark_corpus(base_url)
        adapters = [BenchmarkCrucibleAdapter(use_browser=use_browser)]
        if incumbents:
            adapters += [SqlmapAdapter(), WapitiAdapter(), NiktoAdapter()]
        return comparative_report_measured(corpus, adapters)


def run_benchmark(*, use_browser: bool = False, incumbents: bool = True) -> list[Scoreboard]:
    """Stand up the benchmark app, score every available tool against its ground
    truth, and return the per-tool scoreboards.

    CRUCIBLE always runs (in-process). With ``incumbents=True`` the available
    incumbents (sqlmap + Wapiti + Nikto here) are added; the comparative spine
    silently skips any that are not installed. ``incumbents=False`` is the
    CRUCIBLE-only path — no external tool is invoked or required. ``use_browser``
    enables CRUCIBLE's dynamic browser passes (needs Chromium; skipped if absent)."""
    return [
        mb.scoreboard
        for mb in run_benchmark_measured(use_browser=use_browser, incumbents=incumbents)
    ]


def write_report(
    scoreboards: list[Scoreboard],
    path: str | Path,
    *,
    metrics: list[RunMetrics] | None = None,
) -> Path:
    """Write a public markdown scoreboard (``tool | tp | fp | fn | precision |
    recall | f1``) with a short, honest preamble, and return the written path.

    When ``metrics`` is supplied, a ``## Performance`` section is appended with the
    per-tool wall-clock, active-request budget, and best-effort peak RSS — the cost
    axis the accuracy table is silent on."""
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

    if metrics:
        lines.append("## Performance")
        lines.append("")
        lines.append("Cost of the same runs — wall-clock, active requests issued, and")
        lines.append("best-effort peak RSS. A `-` means the tool does not report that")
        lines.append("number (an incumbent CRUCIBLE shells out to does not expose its")
        lines.append("internal request count); it is left blank rather than faked to 0.")
        lines.append("")
        lines.append("| tool | time_s | requests_sent | peak_rss_mb | pages_found | findings_reported |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
        for m in metrics:
            reqs = "-" if m.requests_sent is None else str(m.requests_sent)
            rss = "-" if m.peak_rss_mb is None else f"{m.peak_rss_mb:.1f}"
            pages = "-" if m.pages_discovered is None else str(m.pages_discovered)
            lines.append(
                f"| {m.tool} | {m.elapsed_s:.2f} | {reqs} | {rss} | {pages} | "
                f"{m.findings_reported} |"
            )
        lines.append("")

    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _incumbent_versions() -> dict[str, str]:
    """Best-effort version strings for the incumbents on this host — the
    reproducibility metadata a scoreboard is meaningless without. A tool that is
    absent or answers no version query is recorded as such, never omitted."""
    probes = {
        "sqlmap": ["sqlmap", "--version"],
        "wapiti": ["wapiti", "--version"],
        "nikto": ["nikto", "-Version"],
        "nuclei": ["nuclei", "-version"],
    }
    import re

    ver = re.compile(r"\d+\.\d+")
    out: dict[str, str] = {}
    for tool, cmd in probes.items():
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)  # noqa: S603
            lines = [ln.strip() for ln in (p.stdout or p.stderr or "").splitlines() if ln.strip()]
            # prefer the first line carrying a version-looking token (skip ASCII banners)
            pick = next((ln for ln in lines if ver.search(ln)), lines[0] if lines else "")
            out[tool] = pick or "installed (no version output)"
        except FileNotFoundError:
            out[tool] = "absent"
        except Exception:
            out[tool] = "unknown"
    return out


def write_json_report(measured: list[MeasuredBoard], path: str | Path) -> Path:
    """Write the machine-readable benchmark snapshot: per-tool accuracy + cost, the
    exact incumbent invocations, and the incumbent versions on this host — the
    committed artifact that makes the markdown scoreboard reproducible and auditable."""
    p = Path(path).expanduser()
    doc = {
        "tool": "CRUCIBLE",
        "corpus": "in-process benchmark app (9 planted bugs, 3 safe controls)",
        "matcher": "(normalized bug_class family, path+parameter); greedy 1-1; "
                   "off-manifest detections are false positives by construction",
        "incumbent_versions": _incumbent_versions(),
        "incumbent_invocations": {
            "sqlmap": "sqlmap -u <url> --batch",
            "wapiti": "wapiti -u <url> -f json -o <file>",
            "nikto": "nikto -h <url> -Format json -output <file>",
            "nuclei": "nuclei -u <url> -jsonl -silent",
        },
        "results": [
            {
                "tool": mb.scoreboard.tool,
                "tp": mb.scoreboard.true_positives,
                "fp": mb.scoreboard.false_positives,
                "fn": mb.scoreboard.false_negatives,
                "precision": mb.scoreboard.precision,
                "recall": mb.scoreboard.recall,
                "f1": mb.scoreboard.f1,
                "elapsed_s": mb.metrics.elapsed_s,
                "requests_sent": mb.metrics.requests_sent,
                "peak_rss_mb": mb.metrics.peak_rss_mb,
                "findings_reported": mb.metrics.findings_reported,
            }
            for mb in measured
        ],
    }
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return p


def _default_baseline_path() -> Path:
    """The committed in-process benchmark baseline — the always-runnable CI spine."""
    return Path(__file__).resolve().parent / "baselines" / "benchmark-app.json"


def _apply_gate(results: dict, args) -> int:
    """Update the baseline, or gate ``results`` against it. Returns the process exit
    code: 0 on pass/update, 1 on a regression."""
    from .gate import Baseline, gate, snapshot

    path = args.baseline or _default_baseline_path()
    if args.update_baseline:
        snapshot(results).dump(path)
        print(f"\nbaseline updated: {path}")
        return 0

    verdict = gate(results, Baseline.load(path))
    print("\n== regression gate ==")
    for w in verdict.warnings:
        print(f"  warn: {w}")
    for imp in verdict.improvements:
        print(f"  improved: {imp}")
    for r in verdict.regressions:
        print(f"  REGRESSION: {r}")
    print(f"gate: {'PASS' if verdict.passed else 'FAIL'}")
    return 0 if verdict.passed else 1


def _run_corpus_cli(args) -> int:
    """Run the dockerized multi-app corpus and print each app's accuracy+cost table,
    then the honest skip list. Real apps, real containers, real numbers — or an
    explicit skip reason; nothing is faked for an app that did not run."""
    from .corpus_run import run_corpus

    incumbents = None if args.no_incumbents else [SqlmapAdapter(), WapitiAdapter(), NiktoAdapter()]
    names = [n.strip() for n in args.apps.split(",")] if args.apps else None
    outcome = run_corpus(
        names=names, include_heavy=args.include_heavy, incumbent_adapters=incumbents)

    for name, measured in outcome.results.items():
        print(f"\n== {name} ==")
        print(render_measured_table(measured))
    if outcome.skipped:
        print("\n== skipped (honest) ==")
        for name, reason in outcome.skipped.items():
            print(f"  {name}: {reason}")
    ran = len(outcome.results)
    print(f"\ncorpus: ran {ran} app(s), skipped {len(outcome.skipped)}.")

    if (args.update_baseline or args.gate) and outcome.results:
        return _apply_gate(outcome.results, args)
    return 0


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
    parser.add_argument("--json", default=None,
                        help="Also write a machine-readable results snapshot (accuracy + cost + "
                             "incumbent versions/invocations) to this JSON path.")
    parser.add_argument("--corpus", action="store_true",
                        help="Run the dockerized multi-app corpus (eval/corpus_apps/) instead of "
                             "the single in-process app. Skips heavy/unavailable apps with a reason.")
    parser.add_argument("--apps", default=None,
                        help="Comma-separated corpus app names to run (default: all non-heavy).")
    parser.add_argument("--include-heavy", action="store_true",
                        help="Also attempt the RAM-heavy corpus apps (owasp-benchmark/gitlab-ce/mattermost).")
    parser.add_argument("--gate", action="store_true",
                        help="Regression-gate the run against the committed baseline; exit 1 on any "
                             "new FP, newly-missed finding, or precision drop for CRUCIBLE.")
    parser.add_argument("--update-baseline", action="store_true",
                        help="Overwrite the baseline with this run's scoreboards (accept the new numbers).")
    parser.add_argument("--baseline", default=None,
                        help="Baseline JSON path (default: the committed in-process benchmark baseline).")
    args = parser.parse_args(argv)

    if args.corpus:
        return _run_corpus_cli(args)

    measured = run_benchmark_measured(
        use_browser=args.browser, incumbents=not args.no_incumbents)
    boards = [mb.scoreboard for mb in measured]
    metrics = [mb.metrics for mb in measured]

    print(render_measured_table(measured))

    if args.update_baseline or args.gate:
        return _apply_gate({"benchmark-app": measured}, args)

    report_path = write_report(boards, args.report, metrics=metrics)
    print(f"\nwrote {report_path}")
    if args.json:
        json_path = write_json_report(measured, args.json)
        print(f"wrote {json_path}")
    return 0
