#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# F1 — machine-check the four VIGIL core invariants with TLC (the TLA+ model
# checker). For EACH invariant we check TWO models:
#   * the FAITHFUL spec        -> TLC MUST report "No error has been found"
#   * a MUTANT with the one     -> TLC MUST report the invariant "is violated"
#     load-bearing guard removed   (a mutant that PASSES means the check is
#                                   vacuous / the guard was not load-bearing —
#                                   that is a FAILURE of this gate).
#
# So this script fails closed in BOTH directions: a real regression (the
# invariant stops holding) AND a rotted check (the mutant stops being caught)
# both turn the gate red.
#
# TLC resolution (no network needed locally if you set TLA2TOOLS_JAR):
#   * $TLA2TOOLS_JAR if set and readable; else
#   * a cached download of a PINNED tla2tools release, sha256-verified.
# ---------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pinned TLC (TLA+ tools). Pin BOTH the URL and the sha256 — a changed artifact
# fails the gate loudly rather than silently model-checking against a different
# checker. Override the jar entirely with TLA2TOOLS_JAR for offline/air-gapped runs.
TLA_URL="${TLA2TOOLS_URL:-https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar}"
TLA_SHA256="e22f8ffb4bacdea0a871f444dd94fe5fb0d8013b3388ae39e82e26f852c735d5"
CACHE="${TLA2TOOLS_CACHE:-$HERE/.tla2tools.jar}"

resolve_jar() {
  if [[ -n "${TLA2TOOLS_JAR:-}" && -r "${TLA2TOOLS_JAR}" ]]; then
    echo "${TLA2TOOLS_JAR}"; return 0
  fi
  if [[ -r "$CACHE" ]] && echo "${TLA_SHA256}  $CACHE" | sha256sum -c - >/dev/null 2>&1; then
    echo "$CACHE"; return 0
  fi
  echo "  [tlc] fetching pinned tla2tools -> $CACHE" >&2
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$CACHE" "$TLA_URL"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$CACHE" "$TLA_URL"
  else
    echo "  [tlc] FATAL: no curl/wget and TLA2TOOLS_JAR unset" >&2; exit 3
  fi
  if ! echo "${TLA_SHA256}  $CACHE" | sha256sum -c - >/dev/null 2>&1; then
    echo "  [tlc] FATAL: tla2tools.jar sha256 mismatch (expected ${TLA_SHA256})" >&2
    rm -f "$CACHE"; exit 3
  fi
  echo "$CACHE"
}

JAR="$(resolve_jar)"
command -v java >/dev/null 2>&1 || { echo "  [tlc] FATAL: java not found on PATH" >&2; exit 3; }
echo "  [tlc] jar=$JAR"
echo "  [tlc] $(java -cp "$JAR" tlc2.TLC 2>&1 | head -1)"
echo

# invariant dir | module base | the invariant name the mutant must violate
SPECS=(
  "gate|VigilGate|GateSound"
  "oracle-mint|OracleMint|OracleOnlyMints"
  "boundary|Boundary|BoundaryHolds"
  "antirollback|MonotoneFloor|MonotoneFloor"
)

fail=0
run_tlc() { # dir base cfg  -> prints TLC output
  ( cd "$HERE/$1" && java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC -config "$3" "$2" 2>&1 )
}

for row in "${SPECS[@]}"; do
  IFS='|' read -r dir base inv <<<"$row"
  echo "=== $dir/$base — FAITHFUL spec (invariant $inv must HOLD) ==="
  out="$(run_tlc "$dir" "$base.tla" "$base.cfg" || true)"
  if grep -q "No error has been found" <<<"$out"; then
    echo "  PASS: $(grep -Eo '[0-9,]+ distinct states found' <<<"$out" | head -1)"
  else
    echo "  FAIL: faithful $base did NOT model-check clean"; grep -Ei 'violated|Error|Exception' <<<"$out" | head -4; fail=1
  fi

  echo "=== $dir/${base}_broken — MUTANT (invariant $inv must be VIOLATED) ==="
  out="$(run_tlc "$dir" "${base}_broken.tla" "${base}_broken.cfg" || true)"
  if grep -q "Invariant $inv is violated" <<<"$out"; then
    echo "  PASS: mutant caught — TLC produced a counterexample to $inv"
  else
    echo "  FAIL: mutant was NOT caught (check is vacuous / guard not load-bearing)"; grep -Ei 'No error|Error|Exception' <<<"$out" | head -4; fail=1
  fi
  echo
done

if [[ "$fail" -ne 0 ]]; then
  echo "FORMAL CHECK: FAILED"; exit 1
fi
echo "FORMAL CHECK: all 4 invariants hold in their faithful models AND all 4 mutants are caught."
