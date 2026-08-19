#!/usr/bin/env bash
# mypy "can-complete" gate for the SIGIL package (W2-5, #422).
#
# The fast mypy subset used by the pre-commit gate. It mirrors the existing `sigil-lint` CI job exactly:
# mypy must be able to FINISH. Exit 2 — a parse / type-comment / config abort, the class of failure that
# once silently disabled type-checking for the entire package (a "# type:" PROSE comment parsed as a PEP
# 484 type comment) — FAILS the hook. Exit 0 (clean) or exit 1 (pre-existing type-error debt, tracked as
# a follow-on and NOT gated here) PASSES. This keeps mypy RUNNABLE; it does not claim type-cleanliness.
set -u

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
pkg="$root/apps/sigil"
if [ ! -d "$pkg/sigil" ]; then
  echo "mypy-can-complete: $pkg/sigil not found" >&2
  exit 1
fi
cd "$pkg" || exit 1

# An ABSENT type-checker must FAIL the gate, not silently pass: without this, `mypy sigil` returns
# 127 (command-not-found) which is != 2, so the gate would fail-open (report can-complete on no check).
if ! command -v mypy >/dev/null 2>&1; then
  echo "::error::mypy is not installed — the can-complete gate cannot run and must not fail-open" >&2
  exit 1
fi

mypy sigil
rc=$?
# Treat a command-not-found / cannot-execute (>=126) the same as an abort: the gate did not really run.
if [ "$rc" -ge 126 ]; then
  echo "::error::mypy could not execute (exit $rc) — the can-complete gate did not run" >&2
  exit 1
fi
if [ "$rc" -eq 2 ]; then
  echo "::error::mypy could NOT complete (exit 2) — a parse/type-comment/config abort regressed" >&2
  exit 1
fi
echo "mypy-can-complete: mypy finished (exit $rc); pre-existing type-error debt is not gated here."
exit 0
