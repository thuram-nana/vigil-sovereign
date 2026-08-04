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
    lines.append("vulnerable web app with a known ground truth of eleven planted bugs")
    lines.append("(reflected XSS, boolean-blind SQLi, error-based SQLi, open redirect,")
    lines.append("path traversal, SSTI, host-header injection, CORS-with-credentials, and")
    lines.append("three exposures: `.git/config`, `.env`, and Spring `/actuator/env`) plus")
    lines.append("five SAFE endpoints (`/profile`, `/api/health`, `/download`, `/greeting`,")
    lines.append("`/support`) that must never be flagged. Because the")
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
    # Strip ANSI SGR/color escapes so a tool that colourises its version banner (e.g.
    # nuclei) records a clean, diff-stable string rather than raw terminal control codes
    # in the committed, signed scorecard.
    ansi = re.compile(r"\x1b\[[0-9;]*m")
    out: dict[str, str] = {}
    for tool, cmd in probes.items():
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)  # noqa: S603
            raw = ansi.sub("", (p.stdout or p.stderr or ""))
            lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
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
        "corpus": "in-process benchmark app (11 planted bugs, 5 safe controls)",
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


def _scorecard_fingerprint(authorizers: list[dict]) -> str:
    """A stable out-of-band pin for the signing trust root: sha256 over the canonical authorizer set
    (key_id + public key). A reader compares this to a fingerprint the operator publishes independently."""
    import hashlib

    from vigil_core import canonical_json
    body = canonical_json(sorted(authorizers, key=lambda a: a["key_id"]))
    return "sha256:" + hashlib.sha256(body).hexdigest()


def sign_scorecard(scorecard_json_path: str | Path, *, signers: list[tuple[str, str]],
                   authorizers: list[dict], threshold: int) -> dict:
    """Sign a benchmark scorecard JSON so its published numbers are TAMPER-EVIDENT + independently
    checkable (with the proof-carrying-finding verifier's ``verify_threshold`` over the SAME canonical
    bytes). Deterministic: the signature covers ``vigil_core.canonical_json(scorecard)`` — the exact bytes a
    verifier re-derives from the loaded JSON. Keys are passed IN (FATAL-2: no key provisioning here). Writes
    ``<name>.sig.json`` + ``<name>.fingerprint.txt`` beside the scorecard and returns the signature envelope."""
    import hashlib

    from vigil_core import canonical_json, sign
    p = Path(scorecard_json_path).expanduser()
    doc = json.loads(p.read_text(encoding="utf-8"))
    body = canonical_json(doc)
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    sig_env = {
        "schema": "vigil-benchmark-scorecard-sig/1",
        "scorecard": p.name,
        "scorecard_digest": digest,
        "threshold": int(threshold),
        "trust_root": {"threshold": int(threshold),
                       "authorizers": sorted(authorizers, key=lambda a: a["key_id"])},
        "signatures": sorted(({"key_id": kid, "signature_b64": sign(priv, body)} for kid, priv in signers),
                             key=lambda s: s["key_id"]),
    }
    sig_path = p.with_suffix(".sig.json")
    sig_path.write_text(json.dumps(sig_env, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    p.with_suffix(".fingerprint.txt").write_text(_scorecard_fingerprint(authorizers) + "\n", encoding="utf-8")
    return sig_env


def verify_scorecard(
    scorecard_json_path: str | Path,
    sig_env: dict,
    *,
    trust_root_fingerprint: str | None = None,
) -> bool:
    """Re-verify a signed scorecard offline: re-derive the canonical digest from the JSON on disk and check
    an m-of-n threshold of DISTINCT authorizers' Ed25519 signatures over those bytes. Fail-closed on any
    mismatch (a flipped number → digest changes → every signature fails).

    TRUST ROOT PINNING (the property this call's tamper-evidence actually depends on).
    The authorizer set lives INSIDE ``sig_env``. Without an out-of-band pin, verification proves only that
    ``sig_env`` is INTERNALLY self-consistent — a repo-write / forked-bundle / malicious-PR adversary who
    rewrites the baseline AND its ``.sig.json`` together simply re-signs the lie with a FRESH key, embeds
    that key as the authorizer, and passes. The signature then binds to a root the attacker controls, so it
    proves nothing about origin.

    Pass ``trust_root_fingerprint`` (an ``sha256:...`` string the caller holds OUT OF BAND — pinned in
    source, published on a separate channel) to close that hole: the authorizer set embedded in ``sig_env``
    must hash (via :func:`_scorecard_fingerprint`) to EXACTLY that pin, else fail-closed. A forger's fresh
    key hashes to a different fingerprint and is rejected before any signature is checked. When the pin is
    ``None`` the check is skipped and only the weaker self-consistency guarantee holds — do not rely on that
    mode for tamper-evidence against an adversary who can rewrite the signature file."""
    import hashlib

    from vigil_core import canonical_json, verify_one
    try:
        doc = json.loads(Path(scorecard_json_path).read_text(encoding="utf-8"))
        body = canonical_json(doc)
        if ("sha256:" + hashlib.sha256(body).hexdigest()) != sig_env.get("scorecard_digest"):
            return False
        tr = sig_env.get("trust_root", {})
        authorizers = tr.get("authorizers", [])
        # Out-of-band pin enforcement: the embedded authorizer set must match the pin the caller holds
        # independently. This is what makes the trust root NOT attacker-supplied — checked before any
        # signature so a forged root is rejected outright.
        if trust_root_fingerprint is not None:
            if _scorecard_fingerprint(authorizers) != trust_root_fingerprint:
                return False
        pub = {a["key_id"]: a["public_key_b64"] for a in authorizers}
        good = set()
        for s in sig_env.get("signatures", []):
            kid = s.get("key_id")
            if kid in pub and kid not in good and verify_one(pub[kid], body, s.get("signature_b64", "")):
                good.add(kid)
        return len(good) >= int(tr.get("threshold", 1))
    except Exception:  # noqa: BLE001 — any error is fail-closed (not verified)
        return False


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
    parser.add_argument("--sign", action="store_true",
                        help="Sign the JSON scorecard (m-of-n Ed25519) → a tamper-evident, "
                             "independently-verifiable artifact + an out-of-band fingerprint pin.")
    parser.add_argument("--signing-key", default=None,
                        help="Owner governance private key (b64) to sign with; default mints a fresh key "
                             "and prints its fingerprint to pin out-of-band.")
    parser.add_argument("--key-id", default="benchmark-owner", help="Signer key id for --sign.")
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
    json_target = args.json or ("benchmark-results.json" if args.sign else None)
    if json_target:
        json_path = write_json_report(measured, json_target)
        print(f"wrote {json_path}")
        if args.sign:
            from vigil_core import generate_keypair
            if args.signing_key:
                # derive the public key from the raw-32-byte Ed25519 private seed (vigil_core key format)
                import base64 as _b64

                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
                priv = args.signing_key
                _pk = Ed25519PrivateKey.from_private_bytes(_b64.b64decode(priv))
                pub = _b64.b64encode(_pk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")
            else:
                kp = generate_keypair()
                priv, pub = kp.private_key_b64, kp.public_key_b64
                print("NOTE: no --signing-key given — minted a FRESH governance key for this scorecard.")
            authorizers = [{"key_id": args.key_id, "public_key_b64": pub}]
            sig = sign_scorecard(json_path, signers=[(args.key_id, priv)],
                                 authorizers=authorizers, threshold=1)
            print(f"signed scorecard: {Path(json_path).with_suffix('.sig.json')}")
            print(f"trust-root fingerprint (PIN OUT-OF-BAND): {sig['scorecard_digest']}")
            print(f"                                          {Path(json_path).with_suffix('.fingerprint.txt')}")
    return 0
