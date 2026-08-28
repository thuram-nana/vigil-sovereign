"""Audit F-10: a repo-wide Markdown relative-link checker.

Every `[text](relative)` link in a FIRST-PARTY doc must resolve to a file in the tracked tree. Would have
caught the three F-10 defects (README deploy path, the SOVEREIGNTY-EGRESS-AUDIT framework/v2 prefix, the
untracked POST-ENGAGEMENT.md). Scope + hygiene:

  * Excludes `docs/research/raw-session-research/` (auto-generated session dumps whose links are copied
    verbatim from other contexts) and `vendor/` (third-party trees we do not own).
  * Strips fenced AND inline code first, so a code snippet like `top['ale'+'rt'](1)` is never mistaken for
    a link.
  * Skips external URLs (http/https/mailto/tel/ftp), pure anchors (`#...`), and repo-absolute (`/...`)
    targets; a `path#anchor` link is checked for the file, not the anchor.
"""
import re
import subprocess
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_EXCLUDE_PREFIXES = ("docs/research/raw-session-research/", "vendor/")
_LINK = re.compile(r'(?<!\!)\[[^\]]*\]\(([^)]+)\)')   # [text](target), not ![img](...)
_FENCE = re.compile(r'```.*?```', re.S)
_INLINE = re.compile(r'`[^`\n]*`')


def _tracked_md() -> list[str]:
    out = subprocess.run(["git", "ls-files", "*.md"], cwd=_REPO, capture_output=True, text=True, check=False)
    return [f for f in out.stdout.split() if not f.startswith(_EXCLUDE_PREFIXES)]


def test_first_party_markdown_relative_links_resolve():
    files = _tracked_md()
    assert len(files) > 100, "expected many first-party .md files — did `git ls-files` run in the repo?"
    checked = 0
    broken: list[str] = []
    for f in files:
        p = _REPO / f
        txt = _INLINE.sub("", _FENCE.sub("", p.read_text(encoding="utf-8", errors="replace")))
        for m in _LINK.finditer(txt):
            tgt = m.group(1).strip()
            if tgt.startswith(("http://", "https://", "mailto:", "#", "tel:", "ftp:", "<")):
                continue
            path = tgt.split("#")[0].split("?")[0]
            if not path or path.startswith("/"):
                continue
            checked += 1
            if not (p.parent / path).resolve().exists():
                broken.append(f"{f} -> {tgt}")
    assert checked > 100, f"only {checked} relative links checked — the matcher likely broke (non-vacuity guard)"
    assert not broken, (
        "broken relative Markdown links (target missing from the tracked tree):\n  " + "\n  ".join(broken))
