#!/usr/bin/env bash
# SUB-PART 4 — automated backup RECOVERY DRILL (W7-1 objectives + W7-3 coverage).
# =====================================================================
# A backup you have never restored is a hope, not a backup. This drill proves the
# round-trip end to end: it takes a real `vigil backup`, restores it into FRESH
# throwaway dirs, and leans on the EXISTING restore re-verification (the offense
# leg re-checks every restored *.spine chain/signatures, the segment view, and
# every self-contained evidence bundle; the sovereign leg re-checks its spine
# chain) — a non-zero restore exit means the drill FAILS. On success it asserts
# the restored offense spine actually landed, prints PASS, and cleans up.
#
# W7-1 — it also MEASURES and ASSERTS the DR objectives: it times the real restore
# (the RTO metric) and computes the age of the backup it restored (the RPO / data-loss
# metric), then fails the drill when EITHER exceeds the stated objective
# (tools/backup/objectives.py — RTO 30m, RPO 24h). "The round-trip works" is not
# enough; it must work FAST ENOUGH and recover FRESH ENOUGH data.
#
# W7-3 — with VIGIL_DRILL_PUSH_DIR set it ALSO drills the OFF-HOST copy: the backup is
# pushed to that destination and then restored FROM the pushed copy into fresh dirs and
# re-verified, so the drill proves the replicated copy (not only the freshly minted
# local one) restores. (Restoring a backup that has been through RETENTION/PRUNING and a
# CORRUPTED-backup negative control are drilled in the CI suites —
# integration/tests/test_backup_dr_drill_coverage.py and, for the sovereign plane,
# apps/sigil/tests/test_backup_recovery_drill_sovereign.py.)
#
# It changes NOTHING real: it restores into a mktemp dir and deletes it on exit.
#
# Usage (real host, both planes):
#   VIGIL_BACKUP_PASSPHRASE=… tools/backup/recovery_drill.sh
#
# Env knobs (all optional except the passphrase, which the vigil CLI itself reads):
#   VIGIL_CMD              command prefix for the CLI            (default: vigil)
#   VIGIL_PYTHON          python for the objective check        (default: python3)
#   VIGIL_BASE_DIR        offense engine home to back up        (default: .vigil-live)
#   VIGIL_CRUCIBLE_ROOT   CRUCIBLE root to back up (--crucible-root); unset ⇒ CLI auto-resolves
#   VIGIL_DRILL_SCOPE     --offense-only | --sovereign-only     (default: both planes)
#   VIGIL_DRILL_PUSH_DIR  if set, --push here AND restore the pushed copy too (drills the off-host copy)
#   VIGIL_WORK_DIR        parent for the throwaway work dir      (default: mktemp under $TMPDIR)
#   VIGIL_RTO_SECONDS     override the RTO bound (default 1800)  — the drill FAILS if the restore is slower
#   VIGIL_RPO_SECONDS     override the RPO bound (default 86400) — the drill FAILS if the backup is staler
#   VIGIL_DRILL_INJECT_DELAY_S  add a real delay to the timed restore (self-test of the RTO gate; default 0)
#
# Exit 0 = a clean, re-verified round-trip WITHIN the DR objectives. Non-zero = FAILED (surfaced loudly).
set -euo pipefail

VIGIL_CMD="${VIGIL_CMD:-vigil}"
VIGIL_PYTHON="${VIGIL_PYTHON:-python3}"
BASE_DIR="${VIGIL_BASE_DIR:-.vigil-live}"
SCOPE="${VIGIL_DRILL_SCOPE:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OBJECTIVES="$SCRIPT_DIR/objectives.py"

if [ -z "${VIGIL_BACKUP_PASSPHRASE:-}" ]; then
  echo "recovery_drill: VIGIL_BACKUP_PASSPHRASE is required (the vigil CLI reads it; never on argv)" >&2
  exit 2
fi

WORK="$(mktemp -d "${VIGIL_WORK_DIR:-${TMPDIR:-/tmp}}/vigil-drill.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

echo "recovery_drill: work dir $WORK"

# W7-6 (PR #630): the drill exercises the FULL trust-anchor round-trip (backup establishes the anchor →
# restore pins the recorded governance key), but against a THROWAWAY anchor under $WORK so it changes nothing
# real (~/.vigil is untouched). The backup below establishes it (trust-on-first-use); the restore then
# authenticates against it by default — no --expect-governance-pubkey needed on this same-host round-trip.
export VIGIL_BACKUP_TRUST_ANCHOR="$WORK/trust-anchor.json"

# 1) BACK UP into the throwaway dir. Pass --crucible-root only if the operator set one; --push only when the
#    operator wants the off-host copy drilled too.
bk_args=(backup --out "$WORK/bk" --base-dir "$BASE_DIR")
[ -n "${VIGIL_CRUCIBLE_ROOT:-}" ] && bk_args+=(--crucible-root "$VIGIL_CRUCIBLE_ROOT")
[ -n "$SCOPE" ] && bk_args+=("$SCOPE")
[ -n "${VIGIL_DRILL_PUSH_DIR:-}" ] && bk_args+=(--push "$VIGIL_DRILL_PUSH_DIR")
echo "recovery_drill: backup → $WORK/bk"
$VIGIL_CMD "${bk_args[@]}"

# 2) locate the single timestamped backup subdir (holding MANIFEST.json + MANIFEST.sig.json + the parts).
subdir="$(find "$WORK/bk" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
if [ -z "$subdir" ] || [ ! -f "$subdir/MANIFEST.json" ]; then
  echo "recovery_drill: FAIL — no backup dir with MANIFEST.json under $WORK/bk" >&2
  exit 1
fi
# W7-6: the manifest must be SIGNED (restore refuses an unsigned one, but assert it up front so a drop of the
# signer surfaces as a clear drill failure, not an opaque restore refusal).
if [ ! -f "$subdir/MANIFEST.sig.json" ]; then
  echo "recovery_drill: FAIL — backup dir $subdir has no MANIFEST.sig.json (unsigned manifest)" >&2
  exit 1
fi
backup_name="$(basename "$subdir")"

# 3) RESTORE into FRESH dirs, TIMED (the RTO metric). `vigil restore` performs the full re-verification; a
#    non-zero exit fails here. VIGIL_DRILL_INJECT_DELAY_S adds a real delay to the timed restore — the drill's
#    own negative control that proves the RTO assertion below is live (a slow restore FAILS the drill).
rs_args=(restore "$subdir" --base-dir "$WORK/restored-base"
         --crucible-root "$WORK/restored-crucible" --sigil-home "$WORK/restored-sigil-home")
[ -n "$SCOPE" ] && rs_args+=("$SCOPE")
echo "recovery_drill: restore ← $subdir (into fresh dirs, re-verifying)"
_t0="$(date +%s.%N)"
if [ "${VIGIL_DRILL_INJECT_DELAY_S:-0}" != "0" ]; then
  echo "recovery_drill: (self-test) injecting a ${VIGIL_DRILL_INJECT_DELAY_S}s restore delay"
  sleep "$VIGIL_DRILL_INJECT_DELAY_S"
fi
$VIGIL_CMD "${rs_args[@]}"
_t1="$(date +%s.%N)"
restore_seconds="$(awk "BEGIN{printf \"%.3f\", ${_t1} - ${_t0}}")"

# 4) concrete artifact check for the offense plane (unless the drill was sovereign-only): a *.spine must have
#    landed in the restored base — the restore re-verify already proved it verifies.
if [ "$SCOPE" != "--sovereign-only" ]; then
  if ! find "$WORK/restored-base" -maxdepth 1 -name '*.spine' -type f | grep -q .; then
    echo "recovery_drill: FAIL — no restored *.spine under $WORK/restored-base" >&2
    exit 1
  fi
fi

# 5) W7-3 — DRILL THE OFF-HOST COPY. If the backup was pushed, restore FROM the pushed copy into fresh dirs
#    and re-verify, so the drill proves the REPLICATED copy restores, not just the freshly minted local one.
if [ -n "${VIGIL_DRILL_PUSH_DIR:-}" ]; then
  pushed="$VIGIL_DRILL_PUSH_DIR/$backup_name"
  if [ ! -f "$pushed/MANIFEST.json" ] || [ ! -f "$pushed/MANIFEST.sig.json" ]; then
    echo "recovery_drill: FAIL — pushed off-host copy $pushed is missing its (signed) manifest" >&2
    exit 1
  fi
  ph_args=(restore "$pushed" --base-dir "$WORK/pushed-base"
           --crucible-root "$WORK/pushed-crucible" --sigil-home "$WORK/pushed-sigil-home")
  [ -n "$SCOPE" ] && ph_args+=("$SCOPE")
  echo "recovery_drill: restore ← $pushed (off-host copy, into fresh dirs, re-verifying)"
  $VIGIL_CMD "${ph_args[@]}"
  if [ "$SCOPE" != "--sovereign-only" ]; then
    if ! find "$WORK/pushed-base" -maxdepth 1 -name '*.spine' -type f | grep -q .; then
      echo "recovery_drill: FAIL — no restored *.spine from the off-host copy under $WORK/pushed-base" >&2
      exit 1
    fi
  fi
  echo "recovery_drill: off-host copy restored + re-verified"
fi

# 6) W7-1 — ASSERT THE DR OBJECTIVES. Fail the drill if the restore was slower than the RTO, or the backup we
#    restored is staler than the RPO. This is what turns "the round-trip works" into "it meets the objectives".
obj_args=(check --recovery-seconds "$restore_seconds" --backup-name "$backup_name")
[ -n "${VIGIL_RTO_SECONDS:-}" ] && obj_args+=(--rto-seconds "$VIGIL_RTO_SECONDS")
[ -n "${VIGIL_RPO_SECONDS:-}" ] && obj_args+=(--rpo-seconds "$VIGIL_RPO_SECONDS")
if ! "$VIGIL_PYTHON" "$OBJECTIVES" "${obj_args[@]}"; then
  echo "recovery_drill: FAIL — the restore round-trip did NOT meet the DR objectives (RPO/RTO)" >&2
  exit 1
fi

echo "recovery_drill: PASS — clean, re-verified backup→restore round-trip within the DR objectives"
