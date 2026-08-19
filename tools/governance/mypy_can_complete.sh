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

mypy sigil
rc=$?
if [ "$rc" -eq 2 ]; then
  echo "::error::mypy could NOT complete (exit 2) — a parse/type-comment/config abort regressed" >&2
  exit 1
fi
echo "mypy-can-complete: mypy finished (exit $rc); pre-existing type-error debt is not gated here."
exit 0
