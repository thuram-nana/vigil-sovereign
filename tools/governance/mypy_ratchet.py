#!/usr/bin/env python3
"""Per-module mypy ratchet — make mypy BLOCKING without a big-bang refactor (W2-1, #418).

WHY THIS EXISTS. `mypy` was advisory: the `sigil-lint` CI step ran it and then `exit 0`, so real
type errors shipped green ("a type checker that cannot fail is not running"). Turning it fully
blocking in one step is impossible while the package still carries type-error debt. This ratchet is
the middle path: a committed allowlist of the modules that are NOT YET type-clean. Every module OFF
the list is BLOCKING (a single new error there reddens CI); the set of allowlisted modules may only
SHRINK. Debt is burned down module by module; it can never silently grow back.

THE CONTRACT the guard enforces against `<pkg>/mypy-ratchet.txt` (see `evaluate`):

  1. REGRESSION — a module with mypy errors that is NOT on the allowlist fails the build. This is
     the whole point: a previously-clean (or brand-new) module that acquires a type error is caught.
  2. STALE — a module ON the allowlist that mypy now reports CLEAN fails the build, instructing the
     author to remove it. This is what makes "can only shrink" real: an improvement must be recorded,
     and the list can never be padded with modules that do not actually fail.
  3. CEILING — the committed `ceiling:` must equal the number of listed modules. Because (1)+(2) force
     the list to equal exactly the currently-failing set, the ceiling is a restatement of the debt
     count on ONE labelled line. Adding a module therefore requires raising `ceiling:` in the SAME
     commit — an explicit, reviewable, CI-flagged loosening; the guard fails until it is bumped.
     Removing a module requires lowering it — a tightening. Neither can happen silently.

HONEST LIMIT (do NOT overclaim). The ratchet is at MODULE granularity, as the issue specifies: a
listed ("not-yet-clean") module may still accrue additional errors without tripping the guard — its
contract is only that a CLEAN module never regresses to dirty and that the dirty SET only shrinks.
The ceiling's monotonicity (only-shrink) is enforced per-tree by (3) plus the fact that every change
is a labelled diff line a reviewer sees; like every in-repo baseline (the perf gate, coverage floors)
it is a review-enforced high-water mark, not a cryptographic one. What is enforced UNCONDITIONALLY,
every run, is: no un-allowlisted module may carry a type error, and the allowlist equals the real
failing set.

Deterministic, standard-library only, imports neither trust domain — so it is safe to run in the
reads-only CI legs and as a pre-commit hook (P5 two-env boundary untouched).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# A mypy diagnostic line: "<path>:<line>: error: <msg>  [code]". Only `error:` severities count;
# `note:` lines (e.g. the "By default the bodies of untyped functions are not checked" hint) do NOT.
_ERROR_LINE = re.compile(r"^(?P<path>[^:\n]+\.py):\d+:(?:\d+:)?\s*error:")

_HEADER = """\
# Per-module mypy ratchet for the SIGIL package (W2-1, #418) — enforced by
# tools/governance/mypy_ratchet.py, run blocking in the required `SIGIL lint (ruff + mypy ratchet,
# blocking)` CI job (see .github/workflows/ci.yml) and mirrored by the pre-commit hook.
#
# Each line below is a module that is NOT YET mypy-clean under apps/sigil's [tool.mypy] config.
# Every module NOT listed here is BLOCKING: one new type error in it reddens CI. This list may only
# SHRINK — fix a module's type errors and remove its line (run `mypy_ratchet.py update` to do it for
# you). Adding a line requires raising `ceiling:` in the same commit; the guard fails until you do,
# so a loosening is always an explicit, reviewed change. Do not edit by hand to silence a regression:
# fix the type error instead.
#
# `ceiling:` MUST equal the number of module lines below. It is the debt high-water mark; it goes
# DOWN as modules are cleaned and can only go UP through an explicit, reviewable commit.
"""


def parse_error_modules(mypy_output: str) -> set[str]:
    """The set of module paths (relative to the mypy working dir) that have at least one `error:`."""
    modules: set[str] = set()
    for line in mypy_output.splitlines():
        m = _ERROR_LINE.match(line.strip())
        if m:
            modules.add(m.group("path").strip())
    return modules


def parse_ratchet(text: str) -> tuple[int, set[str]]:
    """Parse a ratchet file's text into (ceiling, allowlist). Raises ValueError on a malformed file
    (a missing/duplicate/non-integer ceiling, or a duplicated module) — a ratchet that cannot be
    parsed must FAIL closed, never be treated as empty (which would silence every regression)."""
    ceiling: int | None = None
    allowlist: set[str] = set()
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if s.lower().startswith("ceiling:"):
            if ceiling is not None:
                raise ValueError("ratchet has more than one `ceiling:` line")
            val = s.split(":", 1)[1].strip()
            if not val.isdigit():
                raise ValueError(f"ratchet `ceiling:` is not a non-negative integer: {val!r}")
            ceiling = int(val)
            continue
        if s in allowlist:
            raise ValueError(f"ratchet lists {s!r} more than once")
        allowlist.add(s)
    if ceiling is None:
        raise ValueError("ratchet is missing its required `ceiling:` line")
    return ceiling, allowlist


def evaluate(failing: set[str], allowlist: set[str], ceiling: int) -> tuple[bool, list[str]]:
    """Pure gate over plain sets. Returns (ok, reasons-for-failure).

    Kept free of I/O so the negative controls can feed it synthetic sets in-process and prove it
    bites (and prove it passes a matching state)."""
    reasons: list[str] = []

    regressed = sorted(failing - allowlist)
    if regressed:
        reasons.append(
            "REGRESSION — module(s) have mypy errors but are NOT on the ratchet (a previously-clean "
            "or new module regressed): " + ", ".join(regressed)
            + ". Fix the type errors; do not add these to the ratchet."
        )

    stale = sorted(allowlist - failing)
    if stale:
        reasons.append(
            "STALE — ratcheted module(s) are now type-clean and MUST be removed (the ratchet only "
            "shrinks): " + ", ".join(stale)
            + ". Run `python tools/governance/mypy_ratchet.py update` to record the improvement."
        )

    if len(allowlist) != ceiling:
        reasons.append(
            f"CEILING — the ratchet lists {len(allowlist)} module(s) but `ceiling:` is {ceiling}. "
            "The ceiling must equal the number of listed modules; raising it (to add debt) is a "
            "loosening that must be an explicit, reviewed change, and lowering it records a fix."
        )

    return (not reasons), reasons


def render_ratchet(modules: set[str]) -> str:
    body = "\n".join(sorted(modules))
    return f"{_HEADER}ceiling: {len(modules)}\n{body}\n" if body else f"{_HEADER}ceiling: 0\n"


# --- commands --------------------------------------------------------------------------------------
def _read_mypy_output(path: str | None) -> str:
    if path is None or path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def cmd_check(ratchet_path: Path, mypy_output: str) -> int:
    try:
        ceiling, allowlist = parse_ratchet(ratchet_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"::error::mypy ratchet unreadable ({ratchet_path}): {e}", file=sys.stderr)
        return 1
    failing = parse_error_modules(mypy_output)
    ok, reasons = evaluate(failing, allowlist, ceiling)
    if ok:
        print(f"mypy ratchet OK — {len(allowlist)} not-yet-clean module(s) at ceiling {ceiling}; "
              "every other module is type-clean and blocking.")
        return 0
    for r in reasons:
        print(f"::error::mypy ratchet: {r}", file=sys.stderr)
    return 1


def cmd_update(ratchet_path: Path, mypy_output: str) -> int:
    failing = parse_error_modules(mypy_output)
    ratchet_path.write_text(render_ratchet(failing), encoding="utf-8")
    print(f"wrote {ratchet_path}: {len(failing)} not-yet-clean module(s) (ceiling {len(failing)}).")
    return 0


def cmd_selftest() -> int:
    # Deterministic in-process controls (the docs/tests suite is the authoritative proof; this is a
    # convenience so `mypy_ratchet.py selftest` bites by hand too).
    allow = {"a.py", "b.py"}
    assert evaluate({"a.py"}, allow, 2)[0] is False, "stale not caught"
    assert evaluate({"a.py", "b.py", "c.py"}, allow, 2)[0] is False, "regression not caught"
    assert evaluate({"a.py", "b.py"}, allow, 3)[0] is False, "ceiling mismatch not caught"
    assert evaluate({"a.py", "b.py"}, allow, 2)[0] is True, "matching state rejected"
    assert parse_error_modules("x.py:1: error: bad\nx.py:2: note: hint\ny.py:3: error: bad") == {
        "x.py", "y.py"}, "parse wrong"
    print("mypy_ratchet selftest OK")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Per-module mypy ratchet gate (W2-1/#418)")
    ap.add_argument("command", choices=["check", "update", "selftest"])
    ap.add_argument("--ratchet", type=Path, help="path to the ratchet file")
    ap.add_argument("--mypy-output", default=None,
                    help="file with mypy output, or '-' / omitted for stdin")
    ns = ap.parse_args(argv)
    if ns.command == "selftest":
        return cmd_selftest()
    if ns.ratchet is None:
        ap.error("--ratchet is required for check/update")
    out = _read_mypy_output(ns.mypy_output)
    if ns.command == "update":
        return cmd_update(ns.ratchet, out)
    return cmd_check(ns.ratchet, out)


if __name__ == "__main__":
    raise SystemExit(main())
