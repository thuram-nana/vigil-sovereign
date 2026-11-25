"""
evidence.retention — read-only retention ANALYSIS of per-engagement raw evidence (V13, phase 1).

The scan executors capture raw HTTP (request / response / body, which can hold Authorization /
Cookie headers) under ``targets/<slug>/evidence/<action_id>/``. Most of that is transient *scan*
traffic; only the subset an ACTIVE FINDING references by ``action_id`` is the ground truth a
certificate binds and that must be retained. This module computes, per engagement, which per-action
evidence dirs are REFERENCED by a finding (the KEEP set) and which are orphan raw-scan evidence
(SWEEP candidates), with byte sizes — **WITHOUT deleting, sealing, or writing anything**.

It is the shared, decision-independent core of the 90-day retention feature (V13). Run it to see
exactly what a sweep WOULD remove, independent of whichever deletion mechanism (hard-delete vs
crypto-shred) and whichever "engagement ended at T" trigger are wired in the later, gated,
destructive slice.

Conservative by construction, two ways:
  * An evidence dir is a sweep candidate ONLY when NO active finding references its ``action_id``.
    Over-keeping is safe; under-keeping (deleting finding-backing evidence) is not.
  * An engagement whose report snapshot is absent or unreadable is reported ``report_present=False``
    and ALL of its evidence is KEPT — a missing keep-set must never be read as "nothing to keep".

Pure read: opens no network, deletes nothing, writes nothing. The keep-set derivation mirrors the
canonical ``evidence.cli._findings`` (an engagement report lists findings under ``active_findings``).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..common import paths


def _active_findings(report: dict) -> list[dict]:
    """Findings of an engagement report. Mirrors ``evidence.cli._findings`` (kept inline to avoid
    importing the CLI module and its signing deps into this pure-read analyzer): a report lists its
    findings under ``active_findings``; a bare single-finding report is itself the finding."""
    fs = report.get("active_findings")
    if isinstance(fs, list):
        return [f for f in fs if isinstance(f, dict)]
    return [report] if report.get("oracle_context") else []


def _dir_bytes(d: Path) -> int:
    """Total bytes of regular files under ``d`` (recursive). Symlinks are not followed and
    unreadable entries are skipped — sizing is best-effort and never raises."""
    total = 0
    try:
        for p in d.rglob("*"):
            try:
                if p.is_file() and not p.is_symlink():
                    total += p.stat().st_size
            except OSError:
                continue
    except OSError:
        pass
    return total


def _keep_action_ids(report_path: Path) -> set[str]:
    """The set of ``action_id``s any active finding references in the report at ``report_path``.
    An absent / unreadable / malformed report yields the empty set (the caller treats that as
    report-absent and keeps everything)."""
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    if not isinstance(report, dict):
        return set()
    out: set[str] = set()
    for f in _active_findings(report):
        aid = f.get("action_id")
        if isinstance(aid, str) and aid:
            out.add(aid)
    return out


@dataclass
class EngagementRetention:
    """Per-engagement classification of raw evidence into keep vs sweep-candidate."""

    slug: str
    report_present: bool
    keep_action_ids: set[str] = field(default_factory=set)
    keep_dirs: list[str] = field(default_factory=list)
    sweep_candidate_dirs: list[str] = field(default_factory=list)
    keep_bytes: int = 0
    sweep_candidate_bytes: int = 0

    @property
    def total_action_dirs(self) -> int:
        return len(self.keep_dirs) + len(self.sweep_candidate_dirs)


@dataclass
class RetentionReport:
    """A read-only, repo-wide dry-run view of what a retention sweep would keep vs remove."""

    engagements: list[EngagementRetention] = field(default_factory=list)

    @property
    def total_sweep_candidate_dirs(self) -> int:
        return sum(len(e.sweep_candidate_dirs) for e in self.engagements)

    @property
    def total_sweep_candidate_bytes(self) -> int:
        return sum(e.sweep_candidate_bytes for e in self.engagements)

    @property
    def total_keep_dirs(self) -> int:
        return sum(len(e.keep_dirs) for e in self.engagements)


def analyze_engagement(slug: str, *, targets_root: Path) -> EngagementRetention:
    """Classify one engagement's per-action evidence dirs. Read-only."""
    tdir = targets_root / slug
    evidence_root = tdir / "evidence"
    report_path = tdir / f"{slug}.report.json"
    report_present = report_path.is_file()
    keep = _keep_action_ids(report_path) if report_present else set()
    res = EngagementRetention(slug=slug, report_present=report_present, keep_action_ids=keep)
    if not evidence_root.is_dir():
        return res
    for action_dir in sorted(p for p in evidence_root.iterdir() if p.is_dir()):
        aid = action_dir.name
        size = _dir_bytes(action_dir)
        # Fail-safe: with no report snapshot the keep-set is UNKNOWN, so keep everything — never
        # treat "couldn't determine what backs a finding" as "nothing backs a finding".
        if (not report_present) or (aid in keep):
            res.keep_dirs.append(aid)
            res.keep_bytes += size
        else:
            res.sweep_candidate_dirs.append(aid)
            res.sweep_candidate_bytes += size
    return res


def analyze_retention(targets_root: Path | None = None) -> RetentionReport:
    """Classify every engagement under ``targets_root`` (defaults to ``paths.targets_root()``).
    Read-only: deletes nothing, writes nothing, sends no traffic. ``_template`` is skipped."""
    root = Path(targets_root) if targets_root is not None else paths.targets_root()
    report = RetentionReport()
    if not root.is_dir():
        return report
    for tdir in sorted(p for p in root.iterdir() if p.is_dir()):
        slug = tdir.name
        if slug == "_template":
            continue
        report.engagements.append(analyze_engagement(slug, targets_root=root))
    return report


def report_to_dict(report: RetentionReport) -> dict[str, object]:
    """JSON-serialisable view of a :class:`RetentionReport` (read-only)."""
    return {
        "engagements": [
            {
                "slug": e.slug,
                "report_present": e.report_present,
                "keep_dirs": e.keep_dirs,
                "sweep_candidate_dirs": e.sweep_candidate_dirs,
                "keep_bytes": e.keep_bytes,
                "sweep_candidate_bytes": e.sweep_candidate_bytes,
            }
            for e in report.engagements
        ],
        "total_keep_dirs": report.total_keep_dirs,
        "total_sweep_candidate_dirs": report.total_sweep_candidate_dirs,
        "total_sweep_candidate_bytes": report.total_sweep_candidate_bytes,
    }


def format_report_text(report: RetentionReport) -> str:
    """Human-readable, one-line-per-engagement summary of a :class:`RetentionReport`."""
    lines = ["evidence retention — DRY RUN (read-only; nothing is deleted)"]
    if not report.engagements:
        lines.append("  no engagements found")
        return "\n".join(lines)
    for e in report.engagements:
        tag = "report" if e.report_present else "NO REPORT — keeping all"
        lines.append(
            f"  {e.slug}: keep {len(e.keep_dirs)} dir(s) / {e.keep_bytes} B,"
            f" sweep-candidate {len(e.sweep_candidate_dirs)} dir(s) / {e.sweep_candidate_bytes} B"
            f"  [{tag}]")
    lines.append(
        f"  TOTAL: sweep-candidate {report.total_sweep_candidate_dirs} dir(s) /"
        f" {report.total_sweep_candidate_bytes} B; keep {report.total_keep_dirs} dir(s)"
        f" across {len(report.engagements)} engagement(s)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Read-only CLI: print the dry-run retention report (text, or ``--json``). Deletes nothing."""
    import argparse

    p = argparse.ArgumentParser(
        prog="python3 -m framework.v2.evidence.retention",
        description="Dry-run evidence-retention report. Classifies each engagement's raw "
                    "evidence/<action_id>/ dir as KEEP (backs an active finding) or a SWEEP "
                    "candidate (orphan scan traffic) with byte totals. Read-only — deletes nothing. "
                    "The 90-day 'engagement ended' trigger and the actual sweep are a later, gated slice.")
    p.add_argument("--json", action="store_true", help="emit JSON instead of the text summary")
    p.add_argument("--targets-root", default=None,
                   help="override the targets/ root (default: resolved from CRUCIBLE_ROOT)")
    args = p.parse_args(list(argv) if argv is not None else None)
    report = analyze_retention(Path(args.targets_root) if args.targets_root else None)
    print(json.dumps(report_to_dict(report), indent=2) if args.json else format_report_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
