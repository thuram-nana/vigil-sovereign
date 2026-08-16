#!/usr/bin/env bash
# Build VIGIL's two isolated environments (FATAL-2) REPRODUCIBLY. They MUST NOT share an interpreter:
# env-sovereign is offense-free by construction; env-offense runs the offense engine.
#
# Third-party runtime deps come from the COMMITTED, fully --hash-pinned supply-chain locks
# (docs/SUPPLY-CHAIN.md) via `--require-hashes`, so a fresh machine reproduces the SAME closure the
# deployment path uses — NOT a fresh index resolution (the previous behaviour, which pinned nothing
# and diverged machine-to-machine). The first-party members (declared in envs/<plane>.txt) are then
# installed EDITABLE with `--no-deps` — their runtime deps are already satisfied by the lock. Python
# is pinned to 3.13, the minor the locks target. Prefers uv when present; falls back to venv+pip.
# Re-runnable.
#
# Reproducibility scope (documented, not hidden):
#   * env-sovereign is FULLY reproducible — the sovereign lock covers every third-party runtime dep of
#     its members (vigil_core, sigil, integration), all installed --no-deps over the lock.
#   * env-offense's FRAMEWORK closure (vigil_core, engine/crucible, gateway, integration) is
#     reproducible from the offense lock; vendor/strix's live-scan extras are NOT in that lock and are
#     fetched fresh (see the strix note in build() — matches the existing "install as needed" design).
#     Locking strix too would need a separate strix lock (a follow-on).
#   * PEP 517 BUILD backends (setuptools-rust for the Rust WARDEN kernel; hatchling/setuptools) are
#     fetched from the index under build isolation — build-time tools are not in the runtime locks.
# If a lock is absent on this checkout the build falls back to fresh member resolution (warned) so it
# degrades rather than hard-failing.
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

# Pin to the 3.13 minor the locks target (docs/SUPPLY-CHAIN.md) so a machine whose default python3 is
# a different minor does not silently diverge from the locked wheels.
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  if command -v python3.13 >/dev/null 2>&1; then PY=python3.13; else PY=python3; fi
fi

SOVEREIGN_LOCK="infra/supply-chain/sovereign.lock.txt"
OFFENSE_LOCK="engine/crucible/framework/v2/requirements.lock.txt"

venv_pip() {  # venv_pip <venv> <pip-args...>  — uv when present, else the venv's pip
  local venv="$1"; shift
  if command -v uv >/dev/null 2>&1; then
    # shellcheck disable=SC1091
    VIRTUAL_ENV="$venv" uv pip install "$@"
  else
    "$venv/bin/pip" install "$@"
  fi
}

members_of() {  # echo the `-e <path>` editable targets declared in a plane's reqs file
  grep -oE '^-e[[:space:]]+[^[:space:]]+' "$1" | awk '{print $2}'
}

build() {  # name  lock  reqs-file
  local name="$1" lock="$2" reqs="$3" venv=".venv-$1"
  echo ">>> building env-$name in $venv"
  if command -v uv >/dev/null 2>&1; then
    uv venv --python "$PY" "$venv"
  else
    "$PY" -m venv "$venv"
    "$venv/bin/pip" install --upgrade pip >/dev/null
  fi
  # Split the editable members (single source of membership = envs/<plane>.txt):
  #  * MOST members' runtime deps ARE in the lock -> install --no-deps (fully reproducible).
  #  * vendor/strix is the exception: its heavy live-scan deps (openai-agents/litellm/docker/textual/…)
  #    are deliberately NOT in the framework lock ("install as needed to run a live scan"), so it is
  #    installed WITH deps. Its SHARED deps (pydantic/requests) are already pinned by the lock and
  #    satisfy strix, so this adds strix's extras without churning the locked closure.
  local nodep=() withdep=() m
  while IFS= read -r m; do
    [ -z "$m" ] && continue
    if [ "$m" = "./vendor/strix" ]; then withdep+=(-e "$m"); else nodep+=(-e "$m"); fi
  done < <(members_of "$reqs")
  if [ -f "$lock" ]; then
    echo "    third-party (reproducible, hash-locked): $lock"
    venv_pip "$venv" --require-hashes -r "$lock"      # refuses ANY unpinned/unhashed package
    [ "${#nodep[@]}" -gt 0 ] && { echo "    members (editable, --no-deps): ${nodep[*]}"; venv_pip "$venv" --no-deps "${nodep[@]}"; }
    [ "${#withdep[@]}" -gt 0 ] && { echo "    strix (editable, WITH live-scan deps — not hash-locked): ${withdep[*]}"; venv_pip "$venv" "${withdep[@]}"; }
  else
    echo "    [warn] $lock missing on this checkout — falling back to FRESH member resolution (NOT hash-locked)"
    venv_pip "$venv" "${nodep[@]}" "${withdep[@]}"
  fi
  # Completeness gate: `pip check` verifies every INSTALLED package's declared dependencies are
  # satisfied, so a member that declares a runtime dep the lock OMITTED fails HERE, at build time. This
  # is metadata-based and robust — deeper than the import smoke below, which (being shallow) would miss a
  # dep that is only imported lazily. `set -e` aborts the build on a non-zero check.
  echo "    completeness check (pip check — a member dep the lock omitted fails here):"
  if command -v uv >/dev/null 2>&1; then VIRTUAL_ENV="$venv" uv pip check; else "$venv/bin/pip" check; fi
}

build sovereign "$SOVEREIGN_LOCK" envs/sovereign.txt
build offense   "$OFFENSE_LOCK"   envs/offense.txt

echo ">>> verifying the boundary holds + smoke-importing each env"
.venv-sovereign/bin/python - <<'PY'
import sys
for m in ("framework", "strix"):
    try:
        __import__(m); sys.exit(f"SOVEREIGNTY VIOLATION: {m} importable in env-sovereign")
    except ImportError:
        pass
from sigil.reuse import assert_no_offense
assert_no_offense()
import sigil, vigil_integration   # sanity: the members import (lock completeness is enforced by pip check above)
print("env-sovereign OK (offense-free; members import; completeness checked)")
PY
.venv-offense/bin/python - <<'PY'
import framework, vigil_integration   # sanity: the members import (lock completeness is enforced by pip check above)
print("env-offense OK (members import; completeness checked)")
PY
echo ">>> done"
