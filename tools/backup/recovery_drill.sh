#!/usr/bin/env bash
# SUB-PART 4 — automated backup RECOVERY DRILL.
# =====================================================================
# A backup you have never restored is a hope, not a backup. This drill proves the
# round-trip end to end: it takes a real `vigil backup`, restores it into FRESH
# throwaway dirs, and leans on the EXISTING restore re-verification (the offense
# leg re-checks every restored *.spine chain/signatures, the segment view, and
# every self-contained evidence bundle; the sovereign leg re-checks its spine
# chain) — a non-zero restore exit means the drill FAILS. On success it asserts
# the restored offense spine actually landed, prints PASS, and cleans up.
#
# It changes NOTHING real: it restores into a mktemp dir and deletes it on exit.
#
# Usage (real host, both planes):
#   VIGIL_BACKUP_PASSPHRASE=… tools/backup/recovery_drill.sh
#
# Env knobs (all optional except the passphrase, which the vigil CLI itself reads):
#   VIGIL_CMD            command prefix for the CLI            (default: vigil)
#   VIGIL_BASE_DIR       offense engine home to back up        (default: .vigil-live)
#   VIGIL_CRUCIBLE_ROOT  CRUCIBLE root to back up (--crucible-root); unset ⇒ CLI auto-resolves
#   VIGIL_DRILL_SCOPE    --offense-only | --sovereign-only     (default: both planes)
#   VIGIL_WORK_DIR       parent for the throwaway work dir     (default: mktemp under $TMPDIR)
#
# Exit 0 = a clean, re-verified round-trip. Non-zero = the drill FAILED (surfaced loudly).
set -euo pipefail

VIGIL_CMD="${VIGIL_CMD:-vigil}"
BASE_DIR="${VIGIL_BASE_DIR:-.vigil-live}"
SCOPE="${VIGIL_DRILL_SCOPE:-}"

if [ -z "${VIGIL_BACKUP_PASSPHRASE:-}" ]; then
  echo "recovery_drill: VIGIL_BACKUP_PASSPHRASE is required (the vigil CLI reads it; never on argv)" >&2
  exit 2
fi

WORK="$(mktemp -d "${VIGIL_WORK_DIR:-${TMPDIR:-/tmp}}/vigil-drill.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

echo "recovery_drill: work dir $WORK"

# 1) BACK UP into the throwaway dir. Pass --crucible-root only if the operator set one.
bk_args=(backup --out "$WORK/bk" --base-dir "$BASE_DIR")
[ -n "${VIGIL_CRUCIBLE_ROOT:-}" ] && bk_args+=(--crucible-root "$VIGIL_CRUCIBLE_ROOT")
[ -n "$SCOPE" ] && bk_args+=("$SCOPE")
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

# 3) RESTORE into FRESH dirs. `vigil restore` performs the full re-verification; a non-zero exit fails here.
rs_args=(restore "$subdir" --base-dir "$WORK/restored-base"
         --crucible-root "$WORK/restored-crucible" --sigil-home "$WORK/restored-sigil-home")
[ -n "$SCOPE" ] && rs_args+=("$SCOPE")
echo "recovery_drill: restore ← $subdir (into fresh dirs, re-verifying)"
$VIGIL_CMD "${rs_args[@]}"

# 4) concrete artifact check for the offense plane (unless the drill was sovereign-only): a *.spine must have
#    landed in the restored base — the restore re-verify already proved it verifies.
if [ "$SCOPE" != "--sovereign-only" ]; then
  if ! find "$WORK/restored-base" -maxdepth 1 -name '*.spine' -type f | grep -q .; then
    echo "recovery_drill: FAIL — no restored *.spine under $WORK/restored-base" >&2
    exit 1
  fi
fi

echo "recovery_drill: PASS — clean, re-verified backup→restore round-trip"
