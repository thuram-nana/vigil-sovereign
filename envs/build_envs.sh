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
#     reproducible from the offense lock; vendor/strix's heavy live-scan extras (openai-agents/litellm/
#     openai/docker/textual/cvss/caido-sdk-client + their transitive closure) are NOT in that lock but
#     ARE reproducible from a DEDICATED hash-pinned strix lock (infra/supply-chain/strix.lock, exported
#     from the committed vendor/strix/uv.lock — regenerate with infra/supply-chain/gen-strix-lock.sh).
#     Both layers install under `--require-hashes`; the strix lock is applied FIRST so the framework
#     lock, applied next, wins any shared-dependency version (e.g. keeps cryptography>=50 — the
#     CVE-2026-69247 fix — over strix's older transitive pin). The members go in --no-deps on top.
#   * PEP 517 BUILD backends (setuptools-rust for the Rust WARDEN kernel; hatchling/setuptools/wheel)
#     are hash-locked too (W3-10): they are NOT in the RUNTIME locks (build-time tools would bloat a
#     shipped deployment), but they have their own hash-pinned lock (infra/supply-chain/build-backends
#     .lock.txt). It is installed FIRST under --require-hashes, then every member is built with
#     --no-build-isolation, so a backend is never fetched fresh/unhashed under isolation. The only
#     package shared with the runtime locks is `packaging`, pinned identically, so the runtime closure
#     is unperturbed (`pip check` proves it).
# If a required lock is absent on this checkout the build FAILS in production posture
# (VIGIL_POSTURE=production) and otherwise warns LOUDLY and degrades to fresh, unlocked resolution —
# never a SILENT fallback. That fail-closed posture is the control [W9-4] builds on.
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
STRIX_LOCK="infra/supply-chain/strix.lock"   # vendor/strix's hash-pinned live-scan extras (env-offense only)
# PEP 517 build backends (hatchling / setuptools+wheel / setuptools-rust), hash-pinned (W3-10 #433).
# Installed FIRST, then members build with --no-build-isolation so the backend comes from these exact
# pins instead of a fresh index fetch. See docs/SUPPLY-CHAIN.md §2 and this file's build() below.
BUILD_BACKENDS_LOCK="infra/supply-chain/build-backends.lock.txt"

venv_pip() {  # venv_pip <venv> <pip-args...>  — uv when present, else the venv's pip
  local venv="$1"; shift
  if command -v uv >/dev/null 2>&1; then
    # shellcheck disable=SC1091
    VIRTUAL_ENV="$venv" uv pip install "$@"
  else
    "$venv/bin/pip" install "$@"
  fi
}

lock_missing_or_die() {  # <lock-path> <human-label> — the fail-closed rule for a missing hash lock.
  # PRODUCTION posture (VIGIL_POSTURE=production|prod) REFUSES to resolve dependencies unlocked and
  # aborts the build (set -e amplifies the explicit exit). Any other posture (dev, the default) warns
  # LOUDLY and lets the caller degrade to fresh resolution. Never a SILENT fallback. See [W9-4].
  local lock="$1" label="$2" posture="${VIGIL_POSTURE:-}"
  posture="${posture,,}"
  case "$posture" in
    production|prod)
      echo "    [FATAL] $label is missing ($lock) and VIGIL_POSTURE=${VIGIL_POSTURE} — refusing to" \
           "resolve dependencies UNLOCKED in production posture. Commit the lock (regenerate the strix" \
           "lock with infra/supply-chain/gen-strix-lock.sh; see docs/SUPPLY-CHAIN.md), or unset" \
           "VIGIL_POSTURE for a dev build." >&2
      exit 1 ;;
    *)
      echo "    [warn] $label is MISSING ($lock) — falling back to FRESH, UNLOCKED resolution (NOT" \
           "hash-locked). VIGIL_POSTURE=production REFUSES this; set it in every deployment." >&2 ;;
  esac
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
  #  * MOST members' runtime deps ARE in the framework lock -> install --no-deps (fully reproducible).
  #  * vendor/strix is the exception: its heavy live-scan deps (openai-agents/litellm/docker/textual/…)
  #    are deliberately NOT in the framework lock, so they come from the DEDICATED hash-pinned strix
  #    lock ($STRIX_LOCK) — installed under --require-hashes too, so strix's extras NEVER resolve fresh
  #    from PyPI. strix itself then installs editable --no-deps over those pinned extras.
  local nodep=() strix=() m s framework_locked="" strix_locked="" backends_locked="" nbi=()
  while IFS= read -r m; do
    [ -z "$m" ] && continue
    if [ "$m" = "./vendor/strix" ]; then strix+=("$m"); else nodep+=(-e "$m"); fi
  done < <(members_of "$reqs")

  # 0. PEP 517 build backends FIRST, hash-pinned (W3-10 #433). Every member is built through a backend
  #    declared in its pyproject `[build-system].requires` (hatchling / setuptools+wheel / setuptools-
  #    rust). Under build isolation pip/uv would fetch those FRESH and UNHASHED from the index — a
  #    build-time supply-chain hole. Install them here under --require-hashes, then build members with
  #    --no-build-isolation (below) so the backend is exactly these pins. The only package shared with
  #    the runtime locks is `packaging`, pinned identically, so this does not perturb the runtime
  #    closure (`pip check` at the end proves it). A hashed CONSTRAINT can't be used instead: any hash
  #    in PIP_CONSTRAINT flips the OUTER editable install into require-hashes mode, which rejects `-e`.
  if [ -f "$BUILD_BACKENDS_LOCK" ]; then
    echo "    PEP 517 build backends (reproducible, hash-locked): $BUILD_BACKENDS_LOCK"
    venv_pip "$venv" --require-hashes -r "$BUILD_BACKENDS_LOCK"   # refuses ANY unpinned/unhashed package
    backends_locked=1
    nbi=(--no-build-isolation)   # members/strix build against the pins above, never a fresh backend fetch
  else
    lock_missing_or_die "$BUILD_BACKENDS_LOCK" "the PEP 517 build-backends lock"   # production: exits here
  fi

  # 1. vendor/strix's live-scan extras FIRST (offense only), so the framework lock applied in step 2
  #    WINS every shared-dependency version — e.g. keeps cryptography>=50 (the CVE-2026-69247 fix) over
  #    strix's older transitive pin. strix's UNIQUE extras stay at the strix lock's pins.
  if [ "${#strix[@]}" -gt 0 ]; then
    if [ -f "$STRIX_LOCK" ]; then
      echo "    strix live-scan extras (reproducible, hash-locked): $STRIX_LOCK"
      venv_pip "$venv" --require-hashes -r "$STRIX_LOCK"      # refuses ANY unpinned/unhashed package
      strix_locked=1
    else
      lock_missing_or_die "$STRIX_LOCK" "the strix live-scan lock"   # production: exits here
    fi
  fi

  # 2. Framework third-party closure — the AUTHORITATIVE layer for shared deps.
  if [ -f "$lock" ]; then
    echo "    third-party (reproducible, hash-locked): $lock"
    venv_pip "$venv" --require-hashes -r "$lock"      # refuses ANY unpinned/unhashed package
    framework_locked=1
  else
    lock_missing_or_die "$lock" "the env-$name framework lock"       # production: exits here
  fi

  # 3. First-party members. Their runtime deps are already satisfied by the framework lock -> --no-deps
  #    (except in the dev-only unlocked fallback, where the lock was absent and they pull deps fresh).
  #    --no-build-isolation ($nbi, set in step 0) makes each member build against the hash-pinned
  #    backends; empty in the unlocked fallback, so the member falls back to a fresh isolated build.
  if [ "${#nodep[@]}" -gt 0 ]; then
    if [ -n "$framework_locked" ]; then
      echo "    members (editable, --no-deps${backends_locked:+, --no-build-isolation}): ${nodep[*]}"
      venv_pip "$venv" --no-deps "${nbi[@]}" "${nodep[@]}"
    else
      echo "    members (editable, WITH deps — UNLOCKED dev fallback): ${nodep[*]}"; venv_pip "$venv" "${nodep[@]}"
    fi
  fi

  # 4. strix itself. Its extras are already present from the strix lock (step 1) -> editable --no-deps;
  #    in the dev-only unlocked fallback (strix lock absent) it pulls its extras fresh.
  if [ "${#strix[@]}" -gt 0 ]; then
    if [ -n "$strix_locked" ]; then
      echo "    strix (editable, --no-deps${backends_locked:+, --no-build-isolation} — extras satisfied by the strix lock): ${strix[*]}"
      for s in "${strix[@]}"; do venv_pip "$venv" --no-deps "${nbi[@]}" -e "$s"; done
    else
      echo "    [warn] strix (editable, WITH deps — UNLOCKED dev fallback): ${strix[*]}" >&2
      for s in "${strix[@]}"; do venv_pip "$venv" -e "$s"; done
    fi
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

# --- egress guard (loopback-only connect(2)/sendto(2)/sendmsg(2) supervisor) --------------------------
# Another native artifact this build produces, alongside the Rust WARDEN kernel: the syscall-level
# no-egress supervisor the live executor wraps a tool spawn in when VIGIL_EGRESS_GUARD is set. It is
# in-repo C (raw seccomp BPF against the kernel uapi headers — NO external dependency, NO network) and was
# previously built ONLY in CI, so a normal `bootstrap.sh` / `make envs` install produced no binary and
# VIGIL_EGRESS_GUARD=1 fell open SILENTLY. Build it here so building the system also builds the guard.
# Linux-only (seccomp); FAIL-SOFT (a warning, never an abort) so a non-Linux host or a missing compiler
# degrades gracefully — the argv allowlist stays in force and VIGIL_EGRESS_GUARD=require still fails closed.
if [ "$(uname -s 2>/dev/null)" = "Linux" ] && command -v make >/dev/null 2>&1 \
   && { command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1; }; then
  if make -C tools/egress-guard >/dev/null 2>&1 && [ -x tools/egress-guard/egress_guard ]; then
    echo ">>> egress guard built (tools/egress-guard/egress_guard)"
  else
    echo ">>> [warn] egress guard build FAILED — run 'make -C tools/egress-guard' to see the error;" \
         "VIGIL_EGRESS_GUARD=1 would then proceed UNGUARDED at the syscall level (=require fails closed)" >&2
  fi
else
  echo ">>> [warn] egress guard not built (needs Linux + make + cc/gcc) —" \
       "VIGIL_EGRESS_GUARD=1 has no binary on this host (=require fails closed)" >&2
fi
echo ">>> done"
