#!/usr/bin/env bash
# Build VIGIL's two isolated environments (FATAL-2). They MUST NOT share an interpreter:
# env-sovereign is offense-free by construction; env-offense runs the offense engine.
#
# Prefers uv when present (two separate `uv pip install` targets over the workspace); falls back
# to stdlib venv + pip. Re-runnable.
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

PY="${PYTHON:-python3}"

build() {  # name  reqs-file
  local name="$1" reqs="$2" venv=".venv-$1"
  echo ">>> building env-$name in $venv"
  if command -v uv >/dev/null 2>&1; then
    uv venv "$venv"
    # shellcheck disable=SC1091
    VIRTUAL_ENV="$venv" uv pip install -r "$reqs"
  else
    "$PY" -m venv "$venv"
    "$venv/bin/pip" install --upgrade pip >/dev/null
    "$venv/bin/pip" install -r "$reqs"
  fi
}

build sovereign envs/sovereign.txt
build offense   envs/offense.txt

echo ">>> verifying the boundary holds"
.venv-sovereign/bin/python - <<'PY'
import sys
for m in ("framework", "strix"):
    try:
        __import__(m); sys.exit(f"SOVEREIGNTY VIOLATION: {m} importable in env-sovereign")
    except ImportError:
        pass
from sigil.reuse import assert_no_offense
assert_no_offense()
print("env-sovereign is offense-free (framework/strix unimportable, guard passes)")
PY
echo ">>> done"
