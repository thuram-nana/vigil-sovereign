"""The per-module mypy ratchet is real, blocking, committed, and NOT a no-op (W2-1 / #418).

WHY THIS TEST EXISTS. mypy was ADVISORY: the `sigil-lint` CI step ran `mypy sigil` and then `exit 0`,
so a real type error shipped green. This test proves the advisory swallow is gone and the ratchet that
replaced it actually bites — a previously-clean module that acquires a type error, or a not-yet-clean
list that grows, turns the required CI job red.

This test rides the ALREADY-REQUIRED `the briefing explains every agent and capability` job
(`pytest docs/tests -q`), which installs only pytest and imports nothing beyond the standard library.
The guard (`tools/governance/mypy_ratchet.py`) is stdlib-only and imports neither trust domain, so
importing it here is safe and this proof runs in a REQUIRED check without adding a new required check.

WHAT IT PROVES:

  (a) The gate's pure `evaluate()` is not a no-op — fed a REGRESSION (an un-allowlisted module with an
      error), a STALE entry (a listed module now clean), or a CEILING mismatch it REPORTS the failure;
      fed a matching state it PASSES. Deterministic negative + positive controls, in-process.

  (b) The mypy output parser counts `error:` lines and ignores `note:` lines.

  (c) The committed ratchet file (`apps/sigil/mypy-ratchet.txt`) exists, parses, and its `ceiling:`
      equals the number of listed modules — the invariant the guard enforces.

  (d) The wiring is true of the code and the OLD advisory swallow is gone: the `sigil-lint` CI job runs
      `tools/governance/mypy_ratchet.sh`, no longer discards mypy's exit with `exit 0`, the job is
      renamed to advertise the ratchet, and that (renamed) job is in the canonical required-check set.

HOW TO SEE IT BITE BY HAND (the failure is real on a tree without the fix, not assumed):
  * restore `exit 0` to the mypy CI step               -> test_ci_mypy_step_is_blocking_and_wired fails;
  * make `evaluate()` always return `(True, [])`       -> the (a) controls fail;
  * set `ceiling:` in apps/sigil/mypy-ratchet.txt wrong -> test_committed_ratchet_is_self_consistent fails.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
GUARD_DIR = REPO / "tools" / "governance"
RATCHET_FILE = REPO / "apps" / "sigil" / "mypy-ratchet.txt"
WRAPPER = GUARD_DIR / "mypy_ratchet.sh"
CI_YAML = REPO / ".github" / "workflows" / "ci.yml"
CANONICAL = REPO / ".github" / "required-status-checks.txt"

JOB_NAME = "SIGIL lint (ruff + mypy ratchet, blocking)"

sys.path.insert(0, str(GUARD_DIR))
import mypy_ratchet


# --- (a) the pure gate is not a no-op -------------------------------------------------------------
def test_evaluate_passes_a_matching_state():
    ok, reasons = mypy_ratchet.evaluate({"a.py", "b.py"}, {"a.py", "b.py"}, 2)
    assert ok and reasons == []


def test_evaluate_rejects_a_regression():
    # c.py has an error but is NOT on the allowlist — a clean/new module regressed.
    ok, reasons = mypy_ratchet.evaluate({"a.py", "b.py", "c.py"}, {"a.py", "b.py"}, 2)
    assert not ok
    assert any("REGRESSION" in r and "c.py" in r for r in reasons)


def test_evaluate_rejects_a_stale_entry():
    # b.py is allowlisted but no longer fails — the ratchet must force its removal (only shrinks).
    ok, reasons = mypy_ratchet.evaluate({"a.py"}, {"a.py", "b.py"}, 2)
    assert not ok
    assert any("STALE" in r and "b.py" in r for r in reasons)


def test_evaluate_rejects_a_grown_list_without_a_ceiling_bump():
    # Three real failures all on the list, but ceiling still says 2 — the list grew without the
    # explicit, reviewable ceiling bump the loosening requires.
    ok, reasons = mypy_ratchet.evaluate({"a.py", "b.py", "c.py"}, {"a.py", "b.py", "c.py"}, 2)
    assert not ok
    assert any("CEILING" in r for r in reasons)


# --- (b) the parser ------------------------------------------------------------------------------
def test_parser_counts_errors_and_ignores_notes():
    out = (
        "sigil/x.py:1: error: bad thing  [misc]\n"
        "sigil/x.py:2: note: By default the bodies of untyped functions are not checked\n"
        "sigil/y.py:3:5: error: another  [assignment]\n"
        "Found 2 errors in 2 files (checked 10 source files)\n"
    )
    assert mypy_ratchet.parse_error_modules(out) == {"sigil/x.py", "sigil/y.py"}


def test_parse_ratchet_fails_closed_on_a_missing_ceiling():
    with pytest.raises(ValueError):
        mypy_ratchet.parse_ratchet("a.py\nb.py\n")  # no `ceiling:` line -> must not read as empty


# --- (c) the committed ratchet -------------------------------------------------------------------
def test_committed_ratchet_is_self_consistent():
    assert RATCHET_FILE.is_file(), f"missing ratchet file: {RATCHET_FILE}"
    ceiling, allowlist = mypy_ratchet.parse_ratchet(RATCHET_FILE.read_text(encoding="utf-8"))
    assert ceiling == len(allowlist), (
        f"ceiling {ceiling} != {len(allowlist)} listed modules — the invariant the guard enforces"
    )
    # Every listed module is a real .py path under the sigil package.
    for mod in allowlist:
        assert mod.startswith("sigil/") and mod.endswith(".py"), mod
        assert (REPO / "apps" / "sigil" / mod).is_file(), f"ratchet lists a non-existent module: {mod}"


# --- (d) the CI wiring is true and the advisory swallow is gone -----------------------------------
def _job_block(name: str) -> str | None:
    lines = CI_YAML.read_text(encoding="utf-8").splitlines()
    start = next((i for i, l in enumerate(lines) if l.strip() == f"name: {name}"), None)
    if start is None:
        return None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[j]):
            end = j
            break
    return "\n".join(lines[start:end])


def test_ci_mypy_step_is_blocking_and_wired():
    block = _job_block(JOB_NAME)
    assert block is not None, f"no ci.yml job named {JOB_NAME!r} (was it renamed?)"
    assert "tools/governance/mypy_ratchet.sh" in block, "the mypy ratchet gate is not invoked"
    # The old advisory swallow discarded mypy's exit code with a trailing `exit 0`. It must be gone.
    assert not re.search(r"^\s*exit 0\s*$", block, re.MULTILINE), (
        "the mypy step still swallows the exit code with `exit 0` — the gate is advisory"
    )


def test_the_renamed_job_is_a_required_check():
    required = {l.strip() for l in CANONICAL.read_text(encoding="utf-8").splitlines()
                if l.strip() and not l.strip().startswith("#")}
    assert JOB_NAME in required, f"{JOB_NAME!r} is not in the canonical required-check set"


def test_the_wrapper_exists_and_fails_closed_on_absent_mypy():
    assert WRAPPER.is_file(), f"missing wrapper: {WRAPPER}"
    text = WRAPPER.read_text(encoding="utf-8")
    # Fail-closed: an absent mypy or a missing allowlist must NOT report clean.
    assert "command -v mypy" in text and "must not fail-open" in text
    assert "mypy-ratchet.txt" in text
