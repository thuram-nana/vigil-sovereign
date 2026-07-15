"""
report.cli — `python3 -m framework.v2 report` (additive, default-safe).

Assembles the three engagement documents (executive / technical / remediation) from
confirmed findings, DETERMINISTICALLY, and either writes them under
``targets/<slug>/reports/`` or prints them.

Two finding sources:

  * an engagement slug — reads the blackboard for that engagement's REPORTABLE
    findings (oracle-``confirmed`` and ``llm_advisory``), exactly the set
    ``agents/reporter_agent.py`` renders. Each finding is re-graded at report time.
  * ``--from-json PATH`` — a JSON document of ``FindingPayload``-shaped findings
    (a list, or ``{"findings": [...]}``). Hermetic; needs no blackboard.

By default no wallclock is written (the render is reproducible). ``--timestamp ISO``
opt-in stamps a generation time. Reporting is read-only over findings and sends no
traffic.

    python3 -m framework.v2 report <slug> [--out DIR]
    python3 -m framework.v2 report --from-json findings.json --out DIR
    python3 -m framework.v2 report --from-json findings.json --stdout
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import ValidationError

from ..common import paths
from .generate import ReportMeta, generate_reports

_DOC_FILENAMES = {
    "executive": "executive.md",
    "technical": "technical.md",
    "remediation-roadmap": "remediation-roadmap.md",
}


def _reportable_from_blackboard(slug: str) -> list[tuple[dict, int]]:
    """The (payload, event_id) pairs for an engagement's reportable findings —
    oracle-``confirmed`` and ``llm_advisory`` — mirroring reporter_agent's set."""
    from ..agents.blackboard import open_blackboard

    bb = open_blackboard()
    try:
        eid = bb.engagement_id(slug, create=False)
        rows = bb.read(engagement=eid, kinds=["finding"])
        out: list[tuple[dict, int]] = []
        for r in rows:
            if r.payload.get("critique_status") in ("confirmed", "llm_advisory"):
                out.append((r.payload, r.id))
        return out
    finally:
        bb.close()


def _load_json_findings(path: Path) -> list[dict]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(doc, dict):
        for key in ("findings", "active_findings"):
            if isinstance(doc.get(key), list):
                return list(doc[key])
        # a single finding object
        return [doc]
    if isinstance(doc, list):
        return list(doc)
    raise ValueError("JSON must be a list of findings, a {findings:[...]} object, or one finding")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 report",
        description="Deterministically assemble executive/technical/remediation reports "
        "from confirmed findings (prove-don't-guess: a lead is never rendered as a fact).",
    )
    parser.add_argument("slug", nargs="?", help="Engagement slug (reads the blackboard).")
    parser.add_argument("--from-json", metavar="PATH",
                        help="Read findings from a JSON document instead of the blackboard.")
    parser.add_argument("--out", metavar="DIR",
                        help="Output directory (default: targets/<slug>/reports/ in slug mode).")
    parser.add_argument("--stdout", action="store_true",
                        help="Print the reports to stdout instead of writing files.")
    parser.add_argument("--format", choices=("markdown", "json", "sarif"), default="markdown",
                        help="Output format. 'markdown' (default) writes the three operator "
                             "documents; 'json'/'sarif' emit ONE machine export (findings + "
                             "certificates + provenance) for a dashboard or CI ingest.")
    parser.add_argument("--only", choices=sorted(_DOC_FILENAMES),
                        help="Render only one document (markdown format only).")
    parser.add_argument("--target", metavar="NAME",
                        help="Target name for the headers (default: the slug, or 'engagement').")
    parser.add_argument("--window-start", metavar="DATE")
    parser.add_argument("--window-end", metavar="DATE")
    parser.add_argument("--status", default="Draft", help="Report status header (default: Draft).")
    parser.add_argument("--timestamp", metavar="ISO",
                        help="Opt-in generation timestamp (default: none — deterministic).")
    # Opt-in OUTBOUND push to an operator-configured sink (nothing is sent unless --push-url is given).
    parser.add_argument("--push-url", metavar="URL",
                        help="Deliver the graded report to this sink URL (webhook/Slack). OUTBOUND + "
                             "opt-in: a bounded POST to EXACTLY this URL, redirects refused, correlatable "
                             "UA. Nothing is sent without this flag.")
    parser.add_argument("--push-sink", choices=("webhook", "slack"), default="webhook",
                        help="Sink format for --push-url (default: webhook).")
    parser.add_argument("--push-facts-only", action="store_true",
                        help="Push only proven FACTs (drop leads).")
    parser.add_argument("--push-dry-run", action="store_true",
                        help="Build the push payload and print it, but do NOT send (preview).")
    parser.add_argument("--push-header", action="append", metavar="K:V", default=[],
                        help="An extra header for the push (e.g. your sink's auth), repeatable.")
    args = parser.parse_args(argv)

    if not args.slug and not args.from_json:
        print("error: give an engagement slug or --from-json PATH", flush=True)
        return 2

    # gather findings
    findings: list
    if args.from_json:
        p = Path(args.from_json)
        if not p.is_file():
            print(f"error: no file at {p}")
            return 2
        try:
            findings = _load_json_findings(p)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"error: cannot read {p}: {e}")
            return 2
    else:
        try:
            findings = _reportable_from_blackboard(args.slug)
        except Exception as e:  # noqa: BLE001 — surface a clean message, not a traceback
            print(f"error: cannot read blackboard for {args.slug!r}: {e}")
            return 2

    meta = ReportMeta(
        target=args.target or args.slug or "engagement",
        window_start=args.window_start,
        window_end=args.window_end,
        status=args.status,
        generated_at=args.timestamp,
    )

    # OUTBOUND push (opt-in) — deliver the graded report to the operator's sink, then continue to the
    # normal render below. Isolated + best-effort: a push failure never aborts report generation.
    if args.push_url:
        from .push import PushConfig, push_report
        headers: dict[str, str] = {}
        for h in (args.push_header or []):
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
        cfg = PushConfig(sink=args.push_sink, url=args.push_url, headers=headers,
                         facts_only=args.push_facts_only, dry_run=args.push_dry_run)
        try:
            res = push_report(findings, cfg, meta=meta)
        except ValidationError as e:
            print(f"error: invalid finding data for push: {e}")
            return 2
        if res.payload is not None:   # dry-run preview
            print(json.dumps(res.payload, indent=2, ensure_ascii=False))
        print(f"push[{res.sink}] -> {res.url}: "
              f"{'delivered' if res.pushed else res.note} ({res.facts} fact(s), {res.leads} lead(s))")

    # machine export (json | sarif): ONE document, same graded-findings input as the
    # markdown docs. Additive; the default 'markdown' path below is unchanged.
    if args.format in ("json", "sarif"):
        from .export import export_json, export_sarif
        try:
            body = (export_json(findings, meta) if args.format == "json"
                    else export_sarif(findings, meta))
        except ValidationError as e:
            print(f"error: invalid finding data: {e}")
            return 2
        if args.stdout:
            print(body)
            return 0
        if args.out:
            out_dir = Path(args.out)
        elif args.slug:
            out_dir = paths.target_dir(args.slug) / "reports"
        else:
            print("error: --from-json needs --out DIR (or use --stdout)")
            return 2
        fp = out_dir / f"report.{args.format}"
        paths.secure_write(fp, body)
        print(f"report: rendered {args.format} export from {len(findings)} finding(s):")
        print(f"  {fp}")
        return 0

    try:
        docs = generate_reports(findings, meta)
    except ValidationError as e:
        # a --from-json document can parse as JSON yet carry a finding missing/mistyping a required
        # field; surface a clean error + exit 2 like every other bad-input case, never a raw traceback.
        print(f"error: invalid finding data: {e}")
        return 2
    if args.only:
        docs = {args.only: docs[args.only]}

    if args.stdout:
        for name in sorted(docs):
            print(f"\n===== {name} =====\n")
            print(docs[name], end="")
        return 0

    # write files
    if args.out:
        out_dir = Path(args.out)
    elif args.slug:
        out_dir = paths.target_dir(args.slug) / "reports"
    else:
        print("error: --from-json needs --out DIR (or use --stdout)")
        return 2

    written: list[str] = []
    for name, body in docs.items():
        fp = out_dir / _DOC_FILENAMES[name]
        paths.secure_write(fp, body)  # owner-only; content byte-identical to a plain write
        written.append(str(fp))

    n_findings = len(findings)
    print(f"report: rendered {len(docs)} document(s) from {n_findings} finding(s):")
    for w in written:
        print(f"  {w}")
    return 0
