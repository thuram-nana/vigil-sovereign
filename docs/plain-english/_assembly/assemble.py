"""Build VIGIL-EXPLAINED.md from the chapters. Deterministic; run it after editing any chapter.

    python3 docs/plain-english/_assembly/assemble.py

WHY THIS EXISTS. The single-file briefing was assembled by hand, so it drifted: it was measurably
smaller than the chapters it was supposedly made of, and a reader given the single file was reading
an older document than a reader given the chapters. Assembly is mechanical work and a machine should
do it, so that "the master is current" is a fact rather than a hope.

THE RULE. Preamble, then each numbered chapter, then the glossary. A chapter contributes its title
as `## Chapter N. <title>` and its body with every heading pushed down one level, so the chapter's
own top-level headings become sub-headings of the chapter within the combined document.

The per-chapter standalone note — the italic line orienting a reader who opens one chapter alone —
is dropped when the chapter is folded into the master, where it is redundant and where its "chapter
N of M" wording is a second thing that can go stale.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BRIEFING = HERE.parent
MASTER = BRIEFING / "VIGIL-EXPLAINED.md"
PREAMBLE = HERE / "preamble.md"


def chapters() -> list[Path]:
    """Numbered chapters in order. New chapters are picked up by existing; nothing to register."""
    return sorted(p for p in BRIEFING.glob("[0-9][0-9]-*.md") if not p.name.startswith("00-"))


def _split_title(text: str) -> tuple[str, str]:
    lines = text.splitlines()
    assert lines and lines[0].startswith("# "), "a chapter must open with its `# ` title"
    return lines[0][2:].strip(), "\n".join(lines[1:])


def _demote(body: str) -> str:
    """Push every heading down one level so chapter headings nest under the chapter."""
    return re.sub(r"^(#{1,5}) ", r"#\1 ", body, flags=re.M)


def _strip_standalone_note(body: str) -> str:
    """Drop a leading italic orientation note, if the chapter has one."""
    stripped = body.lstrip("\n")
    if stripped.startswith("*"):
        end = stripped.find("\n\n")
        if end != -1 and stripped[:end].count("\n") < 8:
            return stripped[end:]
    return body


def build() -> str:
    out = [PREAMBLE.read_text(encoding="utf-8").rstrip(), ""]
    for n, path in enumerate(chapters(), start=1):
        title, body = _split_title(path.read_text(encoding="utf-8"))
        out += ["", f"## Chapter {n}. {title}", "", _demote(_strip_standalone_note(body)).strip(), "", "---"]
    gtitle, gbody = _split_title((BRIEFING / "00-glossary.md").read_text(encoding="utf-8"))
    out += ["", f"## {gtitle}", "", _demote(_strip_standalone_note(gbody)).strip(), ""]
    return "\n".join(out).rstrip() + "\n"


if __name__ == "__main__":
    built = build()
    if "--check" in sys.argv:
        current = MASTER.read_text(encoding="utf-8") if MASTER.exists() else ""
        if current != built:
            print("VIGIL-EXPLAINED.md is stale. Re-run assemble.py.", file=sys.stderr)
            sys.exit(1)
        print("VIGIL-EXPLAINED.md is in sync.")
    else:
        MASTER.write_text(built, encoding="utf-8")
        print(f"wrote {MASTER.relative_to(BRIEFING.parent.parent)} "
              f"({len(built.split()):,} words, {len(chapters())} chapters)")
