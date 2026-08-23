#!/usr/bin/env python3
"""Render a Keep-a-Changelog section from conventional-commit history, and extract a version's
notes for a GitHub release (W4-2, #442).

Two subcommands, both pure-stdlib (no network, no third-party):

  render --from <ref> --to <ref> --version X.Y.Z [--date YYYY-MM-DD]
      Read ``git log <from>..<to>`` and print a ``## [X.Y.Z] - DATE`` section grouping the
      CONVENTIONAL commits (``type(scope)?: subject``) into Keep-a-Changelog buckets. Commits
      that are not conventional (and merge commits) are not "notable changes" and are omitted;
      ``--verbose`` prints the count of omitted subjects to stderr so nothing is hidden.

  notes --version X.Y.Z --changelog CHANGELOG.md [--output FILE]
      Print (or write) the body of the ``## [X.Y.Z]`` section already in CHANGELOG.md — the
      release workflow feeds this to ``gh release create --notes-file`` so the published release
      notes ARE the committed changelog, not a second, drifting source.

The staleness guard that keeps CHANGELOG.md honest relative to the tag range lives in
docs/tests/test_changelog_staleness.py (a required CI job); this module is the generator/reader it
documents. The rendering logic here is unit-tested there via its pure functions.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

# type(scope)?!?: subject  — the conventional-commit subject grammar.
_CONVENTIONAL = re.compile(
    r"^(?P<type>[a-z]+)(?:\((?P<scope>[^)]+)\))?(?P<bang>!)?: (?P<desc>.+)$"
)

# Conventional type -> Keep-a-Changelog section. Unmapped known types collapse into "Changed".
_SECTION_FOR: dict[str, str] = {
    "feat": "Added",
    "fix": "Fixed",
    "security": "Security",
    "perf": "Changed",
    "refactor": "Changed",
    "build": "Changed",
    "ci": "Changed",
    "chore": "Changed",
    "docs": "Changed",
    "style": "Changed",
    "test": "Changed",
    "deprecate": "Deprecated",
    "remove": "Removed",
    "revert": "Removed",
}

# Canonical Keep-a-Changelog ordering.
_SECTION_ORDER = ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security")


class Entry(NamedTuple):
    section: str
    scope: str | None
    description: str
    breaking: bool


def parse_commit(subject: str) -> Entry | None:
    """Parse ONE commit subject line. ``None`` for a non-conventional or merge subject."""
    subject = subject.strip()
    if not subject or subject.startswith("Merge "):
        return None
    m = _CONVENTIONAL.match(subject)
    if not m:
        return None
    ctype = m.group("type")
    section = _SECTION_FOR.get(ctype)
    if section is None:
        return None
    return Entry(
        section=section,
        scope=m.group("scope"),
        description=m.group("desc").strip(),
        breaking=bool(m.group("bang")),
    )


def render_section(version: str, date: str, subjects: list[str]) -> str:
    """Render a single ``## [version] - date`` Keep-a-Changelog section from raw commit subjects.

    Pure: no git, no clock — the same subjects always render the same text (determinism)."""
    buckets: dict[str, list[str]] = {s: [] for s in _SECTION_ORDER}
    for subj in subjects:
        entry = parse_commit(subj)
        if entry is None:
            continue
        prefix = "**BREAKING** " if entry.breaking else ""
        scope = f"**{entry.scope}:** " if entry.scope else ""
        buckets[entry.section].append(f"- {prefix}{scope}{entry.description}")

    lines = [f"## [{version}] - {date}"]
    any_entry = False
    for section in _SECTION_ORDER:
        items = buckets[section]
        if not items:
            continue
        any_entry = True
        lines.append("")
        lines.append(f"### {section}")
        lines.extend(items)
    if not any_entry:
        lines.append("")
        lines.append("_No conventional-commit changes in this range._")
    return "\n".join(lines) + "\n"


def extract_section(changelog_text: str, version: str) -> str | None:
    """Return the body of the ``## [version]`` section (everything up to the next ``## `` header),
    or ``None`` if that version has no section. Pure."""
    lines = changelog_text.splitlines()
    header = re.compile(r"^## \[" + re.escape(version) + r"\]")
    start = next((i for i, ln in enumerate(lines) if header.match(ln)), None)
    if start is None:
        return None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j].startswith("## "):
            end = j
            break
    body = "\n".join(lines[start + 1 : end]).strip("\n")
    return body


def _git_subjects(from_ref: str | None, to_ref: str, root: Path) -> list[str]:
    rng = f"{from_ref}..{to_ref}" if from_ref else to_ref
    out = subprocess.run(
        ["git", "-C", str(root), "log", "--no-merges", "--format=%s", rng],
        capture_output=True,
        text=True,
        check=True,
    )
    return [ln for ln in out.stdout.splitlines() if ln.strip()]


def _cmd_render(args: argparse.Namespace) -> int:
    root = Path(args.repo).resolve()
    subjects = _git_subjects(args.from_ref, args.to_ref, root)
    kept = [s for s in subjects if parse_commit(s) is not None]
    if args.verbose:
        print(f"changelog: {len(kept)}/{len(subjects)} commits are conventional", file=sys.stderr)
    date = args.date or _today(root)
    sys.stdout.write(render_section(args.version, date, subjects))
    return 0


def _today(root: Path) -> str:
    """Release date for a rendered section. Prefer the tip commit's authored date (deterministic and
    tied to the code) over the wallclock, so a re-render of the same range is reproducible."""
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "log", "-1", "--format=%cs"],
            capture_output=True,
            text=True,
            check=True,
        )
        stamp = out.stdout.strip()
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", stamp):
            return stamp
    except (OSError, subprocess.SubprocessError):
        pass
    return "UNRELEASED"


def _cmd_notes(args: argparse.Namespace) -> int:
    text = Path(args.changelog).read_text(encoding="utf-8")
    body = extract_section(text, args.version)
    if body is None:
        print(f"changelog: no section for version {args.version!r} in {args.changelog}", file=sys.stderr)
        return 2
    if args.output:
        Path(args.output).write_text(body + "\n", encoding="utf-8")
    else:
        sys.stdout.write(body + "\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="changelog", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("render", help="render a changelog section from a git range")
    pr.add_argument("--version", required=True)
    pr.add_argument("--from", dest="from_ref", default=None, help="start ref (exclusive); omit for all history")
    pr.add_argument("--to", dest="to_ref", default="HEAD", help="end ref (default HEAD)")
    pr.add_argument("--date", default=None, help="YYYY-MM-DD; default = tip commit date")
    pr.add_argument("--repo", default=".", help="repo root (default .)")
    pr.add_argument("--verbose", action="store_true")
    pr.set_defaults(func=_cmd_render)

    pn = sub.add_parser("notes", help="print a version's section body from CHANGELOG.md")
    pn.add_argument("--version", required=True)
    pn.add_argument("--changelog", default="CHANGELOG.md")
    pn.add_argument("--output", default=None, help="write to this file instead of stdout")
    pn.set_defaults(func=_cmd_notes)

    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
