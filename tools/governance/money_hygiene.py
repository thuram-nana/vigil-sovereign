#!/usr/bin/env python3
"""Public-repo money hygiene: keep margin and markup VALUES out of this public repository.

WHY. This repository is public. The pricing markup and the target gross margin are owner-set
values that live ONLY in the private deploy environment. The repository may name the settings
(`VIGIL_BILLING_MARKUP_K`, `VIGIL_BILLING_TARGET_MARGIN`), state mechanisms and invariants, and
publish customer prices; it must never carry the value itself. A value once pushed stays in
history, so the guard runs on every pull request, over:

  * every tracked text file (`git ls-files`; binaries are skipped by a NUL sniff);
  * the commit messages of the pull request (`git log --format=%B <base>..HEAD`);
  * the pull request title and body (from `$GITHUB_EVENT_PATH`) and the branch name.

Patterns are anchored on markup and margin WORDING, never on a bare `K<digit>`, because the repo's
slice ids (K4, K6, ...) and unrelated algorithm constants (`K = 6` in a fold test) are not prices.

A finding is reported by location and pattern id only: the matched text is never echoed, because CI
logs of a public repository are public too.

Stdlib only. Usage:
  python tools/governance/money_hygiene.py tree                 # scan tracked files
  python tools/governance/money_hygiene.py ci --base <sha> [--head <sha>]  # commit/PR/branch text
  python tools/governance/money_hygiene.py text --label <name>  # scan stdin
Exit status 1 on any finding, 0 when clean.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# (pattern id, compiled pattern). Each is a VALUE carried next to markup or margin wording.
_NUM = r"[-+]?(?:\d+(?:\.\d+)?|\.\d+)"
_PCT = r"(?:%|\s*(?:percent|per\s*cent|pct)\b)"
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # A markup or target-margin setting assigned a number, in any env/config/code spelling and case:
    # VIGIL_BILLING_MARKUP_K=..., markup_k: ..., "targetMargin": ..., target-margin = ..., a table cell
    # "| NAME | <n> |", a call argument "getenv('NAME', '<n>')", a shell fallback "${NAME:-<n>}".
    ("setting-value", re.compile(
        r"(?:markup[\s_-]*k|target[\s_-]*margin)\b[`\"']?\s*(?::=|:-|\?\?|\|\||[=:(|,])\s*[`\"'(]*\s*"
        r"(?:\$\{\w*:-)?[`\"']?" + _NUM,
        re.IGNORECASE)),
    # A code default for the markup or the margin, optionally annotated or wrapped:
    # DEFAULT_MARKUP = "...", DEFAULT_MARKUP: str = ..., DEFAULT_TARGET_MARGIN = Fraction("...")
    ("default-value", re.compile(
        r"DEFAULT_\w*(?:MARKUP|MARGIN)\w*\s*(?::\s*[\w.\[\], ]+?\s*)?=\s*(?:[\w.]+\()?\s*(?:\$\{\w*:-)?[\"']?" + _NUM)),
    # "<n>% margin", "<n> % gross margin", "<n> percent target margin", "<n>% (gross) margin"
    ("percent-margin", re.compile(
        r"\d+(?:\.\d+)?\s*" + _PCT + r"[\s()]*(?:(?:gross|target|net|profit|operating|contribution|blended"
        r"|minimum|average|overall)[\s()]+){0,2}margin", re.IGNORECASE)),
    # "margin target: <n>", "margin of <n>"
    ("margin-target", re.compile(r"margin[\s_-]+(?:target|of)[\s_-]*[:=]?[\s_-]*\d", re.IGNORECASE)),
    # "margin: <n>%", "gross margin is ~<n>%", "target margin <n> percent" — the value AFTER the wording.
    ("margin-then-percent", re.compile(
        r"\bmargin\b[^\n\d;]{0,24}?[~≈≥>]?\s*\d+(?:\.\d+)?\s*" + _PCT, re.IGNORECASE)),
    # A multiplier on cost: "<n>x cost", "<n>× the direct cost", "price = <n>×", "markup of <n>x".
    ("cost-multiplier", re.compile(
        r"\d+(?:\.\d+)?\s*[x×]\s*(?:the\s+|our\s+)?(?:direct|ai|model|run|compute|unit|delivery)\s+cost\b"
        r"|\bpric\w*\s+(?:at\s+)?\d+(?:\.\d+)?\s*[x×](?![\w])"
        r"|\b(?:price|markup|margin)\b[^\n\d;]{0,16}?\d+(?:\.\d+)?\s*[x×](?![\w])", re.IGNORECASE)),
)

# "K = <n>", "K -> <n>", "K → <n>" counts only within this many characters of markup/margin wording.
_K_ASSIGN = re.compile(r"\bK\s*(?:=|->|→)\s*\d")
_K_CONTEXT = re.compile(r"markup|margin", re.IGNORECASE)
K_WINDOW = 40
# "Markup K | <n>", "markup K: <n>": any number within the window after the wording, unless that number is a
# bound (directly preceded by <, >, ≤ or ≥, as in "(≥ 1, ≤ 100)").
_MARKUP_K = re.compile(r"(?i:markup)\s+K\b")
_NUMBER = re.compile(r"\d+(?:\.\d+)?")
_BOUND = "≤≥<>"

# Lines that may match a pattern without being a price. Each entry: (path regex, line regex the WHOLE line
# must match). A line carrying money wording is never excused.
_MONEY_WORDS = re.compile(r"gross|profit|markup|target|revenue|cogs|price|our\s+margin|\bfee", re.IGNORECASE)
_CSS_DECL = r"(?<![\w-])margin(?:-[a-z-]+)?\s*:\s*[-\d.%\sa-z()]*"
_ALLOW: tuple[tuple[re.Pattern[str], re.Pattern[str]], ...] = (
    # A stylesheet: CSS box-model margins anywhere on the line.
    (re.compile(r"\.(?:css|scss|less)$"), re.compile(r".*" + _CSS_DECL + r".*")),
    # Markup / script files: only a bare declaration line, or a declaration inside a style attribute/object.
    (re.compile(r"\.(?:html?|svg|jsx?|tsx?|vue)$"),
     re.compile(r"\s*(?:[a-z-]+\s*:\s*[-\w.%#\s(),]*;\s*)*[a-z-]+\s*:\s*[-\w.%#\s(),]*;?\s*(?:/\*.*\*/)?\s*")),
    (re.compile(r"\.(?:html?|svg|jsx?|tsx?|vue)$"),
     re.compile(r".*\bstyle\s*=\s*[\"'{][^\"'}]*" + _CSS_DECL + r"[^\"'}]*[\"'}].*")),
    # The pricing design doc's model-token TOLERANCE ("within a <n>% margin" of a meter reading) is
    # an accuracy bound on a measurement, not a price.
    (re.compile(r"(?:^|/)docs/decisions/PRICING-RED-PEN-DESIGN\.md$"),
     re.compile(r".*\btoleran(?:ce|t)\b.*", re.IGNORECASE)),
)

_NUL_SNIFF = 8192


@dataclass(frozen=True)
class Hit:
    source: str
    line: int
    pattern: str

    def render(self) -> str:
        return f"{self.source}:{self.line}: money value next to markup/margin wording [{self.pattern}]"


def _allowed(source: str, line: str) -> bool:
    if _MONEY_WORDS.search(line):
        return False
    for path_re, line_re in _ALLOW:
        if path_re.search(source) and line_re.fullmatch(line):
            return True
    return False


def _line_hits(line: str) -> list[str]:
    found = [pid for pid, rx in PATTERNS if rx.search(line)]
    for m in _K_ASSIGN.finditer(line):
        window = line[max(0, m.start() - K_WINDOW): m.end() + K_WINDOW]
        if _K_CONTEXT.search(window):
            found.append("k-near-wording")
            break
    for m in _MARKUP_K.finditer(line):
        tail = line[m.end(): m.end() + K_WINDOW]
        if any(not tail[:n.start()].rstrip().endswith(tuple(_BOUND)) for n in _NUMBER.finditer(tail)):
            found.append("markup-k-cell")
            break
    return found


def scan_text(text: str, source: str = "<text>") -> list[Hit]:
    """Per line, plus each pair of adjacent lines joined (a value wrapped onto the next line is still one
    statement); a joined-pair hit not already seen on either line is reported at the first line."""
    hits: list[Hit] = []
    lines = text.splitlines()
    per_line = [_line_hits(ln) for ln in lines]
    for n, line in enumerate(lines):
        if per_line[n] and not _allowed(source, line):
            hits.extend(Hit(source, n + 1, pid) for pid in per_line[n])
        if n + 1 < len(lines):
            joined = line.rstrip() + " " + lines[n + 1].lstrip()
            extra = [p for p in _line_hits(joined) if p not in per_line[n] and p not in per_line[n + 1]]
            if extra and not _allowed(source, joined):
                hits.extend(Hit(source, n + 1, pid) for pid in extra)
    return hits


def is_binary(data: bytes) -> bool:
    return b"\0" in data[:_NUL_SNIFF]


def tracked_files(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], check=True, capture_output=True
    ).stdout
    return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]


def scan_tree(root: Path) -> list[Hit]:
    hits: list[Hit] = []
    for rel in tracked_files(root):
        path = root / rel
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        if is_binary(data):
            continue
        hits.extend(scan_text(data.decode("utf-8", "replace"), rel))
    return hits


def ci_texts(root: Path, base: str | None, event_path: str | None,
             head_ref: str | None, head: str = "HEAD") -> list[tuple[str, str]]:
    """The non-file text a pull request publishes: commit messages, PR title/body, branch name."""
    texts: list[tuple[str, str]] = []
    if base:
        log = subprocess.run(
            ["git", "-C", str(root), "log", "--format=%H%n%B%x00", f"{base}..{head}"],
            check=True, capture_output=True, text=True,
        ).stdout
        for chunk in log.split("\0"):
            chunk = chunk.strip("\n")
            if not chunk:
                continue
            sha, _, body = chunk.partition("\n")
            texts.append((f"commit {sha[:12]}", body))
    if event_path and Path(event_path).is_file():
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
        pr = event.get("pull_request") or {}
        texts.append(("pull request title", str(pr.get("title") or "")))
        texts.append(("pull request body", str(pr.get("body") or "")))
        ref = (pr.get("head") or {}).get("ref")
        if ref:
            texts.append(("branch name", str(ref)))
    if head_ref and ("branch name", head_ref) not in texts:
        texts.append(("branch name", head_ref))
    return texts


def _report(hits: list[Hit]) -> int:
    for h in hits:
        print(h.render())
    if hits:
        print(f"money hygiene: {len(hits)} finding(s). The repo is PUBLIC: name the setting, never "
              "its value (the value lives in the private deploy environment).")
        return 1
    print("money hygiene OK")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("tree")
    t.add_argument("--root", default=".")
    c = sub.add_parser("ci")
    c.add_argument("--root", default=".")
    c.add_argument("--base", default=None)
    c.add_argument("--head", default="HEAD")
    c.add_argument("--event", default=os.environ.get("GITHUB_EVENT_PATH"))
    c.add_argument("--head-ref", default=os.environ.get("GITHUB_HEAD_REF"))
    x = sub.add_parser("text")
    x.add_argument("--label", default="<stdin>")
    args = ap.parse_args(argv)
    if args.cmd == "tree":
        return _report(scan_tree(Path(args.root).resolve()))
    if args.cmd == "ci":
        hits: list[Hit] = []
        for label, body in ci_texts(Path(args.root).resolve(), args.base, args.event, args.head_ref,
                                  args.head):
            hits.extend(scan_text(body, label))
        return _report(hits)
    return _report(scan_text(sys.stdin.read(), args.label))


if __name__ == "__main__":
    sys.exit(main())
