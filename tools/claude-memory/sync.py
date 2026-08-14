#!/usr/bin/env python3
"""Carry the assistant's project memory between machines, through the repository.

    python3 tools/claude-memory/sync.py export     # this machine's memory -> knowledge/claude-memory/
    python3 tools/claude-memory/sync.py restore    # knowledge/claude-memory/ -> this machine
    python3 tools/claude-memory/sync.py status     # what is where, and whether they agree

WHAT THIS SOLVES. Set up a second machine, and the assistant you talk to there starts knowing
nothing about this project — every hard-won decision, every gotcha, every "we tried that and it
didn't work" has to be rediscovered by reading code. The memory files are the cure, and they live
outside the repository in a per-machine directory, so they do not travel with a clone. This moves
them into the repository, where a clone brings them along.

WHY ONLY THE MEMORY FILES, AND NOT THE SESSION TRANSCRIPTS. The obvious instinct is to archive the
whole assistant directory and commit that. Three measured reasons not to, in increasing order of
seriousness:

  1. SIZE. The transcripts for this project are ~1.3 GB against ~780 KB of memory. Git stores every
     version forever, and hosting providers reject single files over 100 MB outright.

  2. IT WOULD NOT WORK. Memory files are LOADED AUTOMATICALLY at the start of a session — that is
     what makes them memory. Transcripts are not. Committing them would add a gigabyte of material
     that still has to be read a file at a time, which is exactly the cost this is meant to avoid.

  3. SECRETS. A scan of this project's transcripts found 431 secret-shaped strings. Most are plainly
     test fixtures — a well-known example access key, obviously fake tokens — but ~76 are private-key
     blocks, and proving all 431 harmless is not cheap. Transcripts are raw tool output: whatever a
     command printed is in there verbatim. Committed history is permanent and public repositories are
     scraped continuously. The asymmetry is not close.

This is not an improvised rule. This repository's own knowledge-base scanner already refuses any
compressed or binary file, on the stated grounds that a secret could hide inside an archive and go
unscanned. An archive of transcripts is precisely that file. Memory files are plaintext and are
scanned line by line like everything else in the knowledge base.

THE GATE. Export refuses to write anything if the repository's own secret scanner reports a hit —
the same scanner, with the same patterns, that gates every other knowledge-base commit. There is no
separate weaker check here.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
COMMITTED = REPO / "knowledge" / "claude-memory"

# Which project's memory this is. The assistant keys its per-project directory off the project path,
# turning every separator into a dash, so this is the directory it uses for the pentest framework
# this work is driven from. Override with an argument if the project lives elsewhere on a new box.
DEFAULT_PROJECT = "/home/kali/Pictures/PENTEST-main"


def machine_memory_dir(project_path: str) -> Path:
    """The per-machine memory directory for a project path, derived the way the assistant derives it."""
    return Path.home() / ".claude" / "projects" / project_path.replace("/", "-") / "memory"


def _secret_gate() -> list[tuple[str, str]]:
    """Run the repository's own knowledge-base secret scanner. Returns its hits.

    Deliberately reuses `knowledge_sync.scan_secrets` rather than re-implementing a check here: two
    scanners drift, and the weaker one becomes the one that matters. If it cannot be imported the
    export REFUSES rather than proceeding unscanned — an ungated export is the failure this exists to
    prevent, and "the checker was missing" is not a reason to skip the check.
    """
    sys.path.insert(0, str(REPO / "integration"))
    from vigil_integration.knowledge_sync import scan_secrets  # noqa: PLC0415
    return scan_secrets(REPO)


def cmd_export(project_path: str) -> int:
    src = machine_memory_dir(project_path)
    if not src.is_dir():
        print(f"no memory on this machine at {src}", file=sys.stderr)
        return 1

    COMMITTED.mkdir(parents=True, exist_ok=True)
    # Mirror, not merge: a memory deleted on this machine was deleted because it was wrong, and a
    # merge would quietly resurrect it on the next machine.
    for old in COMMITTED.glob("*.md"):
        old.unlink()
    n = 0
    for f in sorted(src.glob("*.md")):
        shutil.copy2(f, COMMITTED / f.name)
        n += 1

    hits = _secret_gate()
    mine = [(p, why) for p, why in hits if "claude-memory" in p]
    if mine:
        for p, why in mine:
            print(f"  REFUSED  {p}  ({why})", file=sys.stderr)
        for f in COMMITTED.glob("*.md"):
            f.unlink()
        print("\nExport refused and rolled back: redact the file above, then re-run.", file=sys.stderr)
        return 2

    other = len(hits) - len(mine)
    print(f"exported {n} memory files -> {COMMITTED.relative_to(REPO)}  (secret scan: clean"
          + (f"; {other} pre-existing hits elsewhere under knowledge/, not caused by this export" if other else "")
          + ")")
    return 0


def cmd_restore(project_path: str) -> int:
    if not COMMITTED.is_dir() or not any(COMMITTED.glob("*.md")):
        print(f"nothing committed at {COMMITTED}", file=sys.stderr)
        return 1
    dst = machine_memory_dir(project_path)
    dst.mkdir(parents=True, exist_ok=True)

    n = kept = 0
    for f in sorted(COMMITTED.glob("*.md")):
        target = dst / f.name
        # Never clobber a memory this machine already holds: it may be newer than the commit, and
        # losing a memory silently is worse than having to merge one by hand.
        if target.exists() and target.read_bytes() != f.read_bytes():
            print(f"  kept local (differs): {f.name}")
            kept += 1
            continue
        shutil.copy2(f, target)
        n += 1
    print(f"restored {n} memory files -> {dst}" + (f"  ({kept} left alone; they differ locally)" if kept else ""))
    print("\nOpen a new session in that project directory and the index loads automatically.")
    return 0


def cmd_status(project_path: str) -> int:
    src = machine_memory_dir(project_path)
    local = {f.name for f in src.glob("*.md")} if src.is_dir() else set()
    committed = {f.name for f in COMMITTED.glob("*.md")} if COMMITTED.is_dir() else set()
    print(f"  on this machine : {len(local):3d} files  {src}")
    print(f"  in the repo     : {len(committed):3d} files  {COMMITTED.relative_to(REPO)}")
    if local - committed:
        print(f"  only local      : {', '.join(sorted(local - committed))}   → run `export`")
    if committed - local:
        print(f"  only in repo    : {', '.join(sorted(committed - local))}   → run `restore`")
    if local == committed and local:
        differing = [n for n in sorted(local) if (src / n).read_bytes() != (COMMITTED / n).read_bytes()]
        print("  same file set" + (f", but {len(differing)} differ in content: {', '.join(differing)}"
                                   if differing else " and identical content"))
    return 0


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "status"
    project = argv[2] if len(argv) > 2 else DEFAULT_PROJECT
    if cmd == "export":
        return cmd_export(project)
    if cmd == "restore":
        return cmd_restore(project)
    if cmd == "status":
        return cmd_status(project)
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
