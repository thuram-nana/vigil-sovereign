#!/usr/bin/env python3
"""W3-2: record the versions CI actually RESOLVED and compare them to the committed lock.

`pip install --require-hashes -r <lock>` already forces the resolved tree to equal the lock (pip
installs exactly each pinned `==version` or refuses the file). This script is the explicit,
recorded assertion of that invariant, run in the A14 gate right after the require-hashes install:
it reads the lock and a `pip freeze` and fails if any package the lock pins is installed at a
different version (or missing). That catches the one way the invariant could still break — a
package pre-baked into the runner image shadowing the locked one — turning a silent divergence
between the tested tree and the locked tree into a red build.

Pure stdlib. Usage:  compare_resolved_to_lock.py <lock.txt> <pip-freeze.txt>
Exit 0 iff every locked package is resolved at its pinned version; prints the comparison either way.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

_PIN = re.compile(r"^([A-Za-z0-9._-]+)==([^\s\;]+)")


def _canon(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _locked(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        m = _PIN.match(line)
        if m:
            out[_canon(m.group(1))] = m.group(2)
    return out


def _resolved(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-e ")) or " @ " in line:
            continue
        m = _PIN.match(line)
        if m:
            out[_canon(m.group(1))] = m.group(2)
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    lock = _locked(Path(argv[1]))
    got = _resolved(Path(argv[2]))
    if not lock:
        print(f"error: {argv[1]} pinned nothing — not a lock", file=sys.stderr)
        return 2

    mismatches: list[str] = []
    for name, want in sorted(lock.items()):
        have = got.get(name)
        flag = "OK" if have == want else "DRIFT"
        print(f"  [{flag}] {name}: lock={want} resolved={have}")
        if have != want:
            mismatches.append(f"{name}: lock={want} resolved={have or '<not installed>'}")

    if mismatches:
        print(
            "\nERROR: the CI-resolved tree DIFFERS from the committed lock (W3-2 invariant broken):\n  "
            + "\n  ".join(mismatches),
            file=sys.stderr,
        )
        return 1
    print(f"\nall {len(lock)} locked packages resolved at their pinned version")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
