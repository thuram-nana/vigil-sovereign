#!/usr/bin/env bash
# BLOCKING per-module mypy gate for the SIGIL package (W2-1, #418).
#
# Runs mypy over apps/sigil/sigil and hands the output to tools/governance/mypy_ratchet.py, which
# fails the build if any module NOT on apps/sigil/mypy-ratchet.txt carries a type error, if a listed
# module is now clean (the ratchet only shrinks), or if the committed ceiling is inconsistent. This is
# the gate that replaced the old advisory `exit 0` swallow. It is used by the required `SIGIL lint
# (ruff + mypy ratchet, blocking)` CI job and is safe to run locally.
#
# Fail-closed: an ABSENT or NON-EXECUTABLE mypy, or a mypy PARSE/CONFIG abort (exit 2), fails the gate
# — it must never report "clean" because the check did not really run (the "# type:" prose-comment
# abort that once silently disabled type-checking for the whole package is exactly this class).
set -u

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
pkg="$root/apps/sigil"
ratchet="$pkg/mypy-ratchet.txt"
guard="$root/tools/governance/mypy_ratchet.py"

if [ ! -d "$pkg/sigil" ]; then
  echo "::error::mypy-ratchet: $pkg/sigil not found" >&2
  exit 1
fi
if [ ! -f "$ratchet" ]; then
  echo "::error::mypy-ratchet: allowlist $ratchet is missing — the gate must not fail-open" >&2
  exit 1
fi
if ! command -v mypy >/dev/null 2>&1; then
  echo "::error::mypy is not installed — the ratchet gate cannot run and must not fail-open" >&2
  exit 1
fi

cd "$pkg" || exit 1
out="$(mktemp)"
trap 'rm -f "$out"' EXIT

mypy sigil >"$out" 2>&1
rc=$?
cat "$out"

# A command-not-found / cannot-execute (>=126) or a parse/config abort (exit 2) means the check did
# NOT really run — fail, never treat as clean.
if [ "$rc" -ge 126 ]; then
  echo "::error::mypy could not execute (exit $rc) — the ratchet gate did not run" >&2
  exit 1
fi
if [ "$rc" -eq 2 ]; then
  echo "::error::mypy could NOT complete (exit 2) — a parse/type-comment/config abort regressed" >&2
  exit 1
fi

# rc 0 (clean) or rc 1 (type errors present) — the ratchet decides pass/fail.
python3 "$guard" check --ratchet "$ratchet" --mypy-output "$out"
