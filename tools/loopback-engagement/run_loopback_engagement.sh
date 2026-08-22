#!/usr/bin/env bash
# W11-1 (#482) — the end-to-end loopback engagement, offline re-verification, and negative controls.
#
# THE GAP THIS CLOSES. The flagship demonstration of the whole engine — scan a live target, confirm a
# real weakness through the oracle, and RE-VERIFY that evidence offline with no trust in the tool that
# produced it — existed only as a hand-run recorded in a memory file. A hand-run proves nothing on the
# next commit. This script is that demonstration, mechanized, so a REQUIRED CI job runs it on every PR.
#
# It is hermetic: the target is this repository's own stdlib HTTP app (infra/loopback/vulnapp.py) bound
# to 127.0.0.1; there is NO docker, NO network egress and NO root. `scan` is loopback-only by design.
#
# The chain, each leg ASSERTED (a failure exits non-zero; nothing is merely printed green):
#   1. POSITIVE  — scan the VULNERABLE app -> oracle-confirmed facts (the planted SQLi/XSS on /search),
#                  each carrying a re-verifiable oracle_context certificate, over the FULL check corpus.
#   2. RE-VERIFY — re-run `framework.v2 verify` over those certificates OFFLINE, on a CLEAN independent
#                  checkout when one is provided (VIGIL_LE_REVERIFY_DIR) — proving the proof is portable.
#   3. TAMPER    — forge a copy with one finding relabelled to a class its evidence never proved, and
#                  assert `verify` REJECTS it. This proves the re-verify gate is not a rubber stamp.
#   4. NEGATIVE  — scan the PATCHED twin (vulnapp --safe): assert a SOUND CLEAN — zero confirmed findings
#                  AND a conclusive full-corpus coverage statement, not merely "no findings".
# The retained $VIGIL_LE_OUT directory is the reviewer demonstration artifact.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

PY="${VIGIL_LE_PYTHON:-python}"
PP="${VIGIL_LE_PYTHONPATH:-integration:engine/crucible:gateway:packages/core/vigil_core}"
OUT="${VIGIL_LE_OUT:-$REPO/loopback-engagement-out}"
PORT="${VIGIL_LE_PORT:-18080}"
SAFE_PORT="$((PORT + 1))"
MAX_PAGES="${VIGIL_LE_MAX_PAGES:-25}"
MAX_DEPTH="${VIGIL_LE_MAX_DEPTH:-3}"
FLOOR="${VIGIL_LE_FLOOR:-3}"
# The CLEAN checkout `verify` re-runs from. Empty => re-verify in this same tree (still offline; the
# certificate never touches the target). CI sets this to a second, independent checkout of the same ref.
RVDIR="${VIGIL_LE_REVERIFY_DIR:-$REPO}"

mkdir -p "$OUT"
VULN_LOG="$(mktemp -d)"; SAFE_LOG="$(mktemp -d)"
APP_PID=""

log()  { printf '\n=== %s ===\n' "$*"; }
die()  { printf '::error::%s\n' "$*" >&2; exit 1; }

stop_app() {
  if [ -n "$APP_PID" ] && kill -0 "$APP_PID" 2>/dev/null; then
    kill "$APP_PID" 2>/dev/null || true
    wait "$APP_PID" 2>/dev/null || true
  fi
  APP_PID=""
}
cleanup() { stop_app; }
trap cleanup EXIT

start_app() {   # start_app <port> <logdir> [--safe]
  local port="$1" logdir="$2"; shift 2
  ( cd "$REPO" && "$PY" infra/loopback/vulnapp.py --port "$port" --logdir "$logdir" "$@" ) &
  APP_PID=$!
  local i
  for i in $(seq 1 50); do
    if curl -fsS "http://127.0.0.1:$port/" >/dev/null 2>&1; then return 0; fi
    if ! kill -0 "$APP_PID" 2>/dev/null; then die "vulnapp on :$port exited before becoming reachable"; fi
    sleep 0.2
  done
  die "vulnapp on :$port never became reachable"
}

scan() {        # scan <seedurl> <built.json> <reverify.json> <summary.txt>
  local seed="$1" built="$2" reverify="$3" summary="$4"
  ( cd "$REPO" && PYTHONPATH="$PP" "$PY" -m framework.v2 scan "$seed" \
      --library --no-oob --max-pages "$MAX_PAGES" --max-depth "$MAX_DEPTH" \
      --format json --reverifiable-out "$reverify" ) > "$built"
  # A human-readable summary for the demo artifact — derived from the machine report (no second scan).
  "$PY" "$HERE/check.py" summarize --built "$built" --reverify "$reverify" > "$summary" 2>&1 || true
}

VERIFY_RC=0
run_verify() {  # run_verify <reverify.json> <out.txt> ; sets VERIFY_RC, prints the verdict, never aborts
  local report="$1" outfile="$2"
  VERIFY_RC=0
  ( cd "$RVDIR" && PYTHONPATH="$PP" "$PY" -m framework.v2 verify "$report" ) > "$outfile" 2>&1 || VERIFY_RC=$?
  cat "$outfile"
}

# ---- 1. POSITIVE: the vulnerable target -----------------------------------------------------------
log "POSITIVE — scan the vulnerable loopback target"
start_app "$PORT" "$VULN_LOG"
scan "http://127.0.0.1:$PORT/" "$OUT/vuln.report.json" "$OUT/vuln.reverify.json" "$OUT/vuln.summary.txt"
stop_app
cat "$OUT/vuln.summary.txt"
"$PY" "$HERE/check.py" positive --built "$OUT/vuln.report.json" --reverify "$OUT/vuln.reverify.json" \
      --floor "$FLOOR" || die "positive control failed — the engine did not confirm the planted weaknesses"

# ---- 2. RE-VERIFY offline (on the clean checkout when provided) ------------------------------------
log "RE-VERIFY — re-run the oracle over the retained certificates, offline${VIGIL_LE_REVERIFY_DIR:+ (clean checkout: $RVDIR)}"
run_verify "$OUT/vuln.reverify.json" "$OUT/reverify.txt"
[ "$VERIFY_RC" = "0" ] || die "offline re-verification did NOT reproduce every certificate (verify rc=$VERIFY_RC)"

# ---- 3. TAMPER: the re-verify gate must reject a forged certificate --------------------------------
log "TAMPER — a forged certificate must be REJECTED (the gate is not a no-op)"
"$PY" "$HERE/check.py" tamper --in "$OUT/vuln.reverify.json" --out "$OUT/vuln.tampered.json"
run_verify "$OUT/vuln.tampered.json" "$OUT/tamper.txt"
[ "$VERIFY_RC" != "0" ] || die "TAMPER CONTROL FAILED: verify accepted a forged certificate (rc=0) — the gate is a no-op"
echo "tamper rejected as required (verify rc=$VERIFY_RC)"

# ---- 4. NEGATIVE: the patched twin must be a SOUND clean ------------------------------------------
log "NEGATIVE — scan the PATCHED twin (vulnapp --safe): a sound clean, not merely silence"
start_app "$SAFE_PORT" "$SAFE_LOG" --safe
scan "http://127.0.0.1:$SAFE_PORT/" "$OUT/safe.report.json" "$OUT/safe.reverify.json" "$OUT/safe.summary.txt"
stop_app
cat "$OUT/safe.summary.txt"
"$PY" "$HERE/check.py" negative --built "$OUT/safe.report.json" \
      || die "negative control failed — the patched target did not yield a sound clean"

# ---- 5. The reviewer demonstration artifact -------------------------------------------------------
CONFIRMED="$("$PY" -c "import json;print(json.load(open('$OUT/vuln.report.json'))['summary']['confirmed'])")"
{
  echo "# VIGIL loopback engagement — reviewer demonstration (W11-1 #482)"
  echo
  echo "Generated by tools/loopback-engagement/run_loopback_engagement.sh on a hermetic loopback range."
  echo
  echo "## 1. Positive — vulnerable target"
  echo "- oracle-confirmed facts: **$CONFIRMED** (planted classes present: error_based_sqli, boolean_sqli, xss)"
  echo "- every fact carries a re-verifiable oracle_context certificate; full check corpus exercised."
  echo
  echo "## 2. Offline re-verification"
  echo '```'; cat "$OUT/reverify.txt"; echo '```'
  echo
  echo "## 3. Tamper control (gate is not a no-op)"
  echo '```'; cat "$OUT/tamper.txt"; echo '```'
  echo
  echo "## 4. Negative control — patched twin (--safe)"
  echo "- confirmed findings: 0, over the FULL corpus — a sound negative (clean + conclusive)."
  echo '```'; sed -n '1,12p' "$OUT/safe.summary.txt"; echo '```'
} > "$OUT/DEMO.md"

log "DONE — reviewer demonstration written to $OUT/DEMO.md"
echo "positive=$CONFIRMED confirmed · offline re-verify OK · tamper rejected · negative clean+conclusive"
