#!/usr/bin/env bash
# VIGIL HA — out-of-band ~/.sigil MIRROR SYNC to a PASSIVE standby.
# =============================================================================
# Claim 6, Piece B (Slice S6). Keeps a PASSIVE sovereign standby's mirror of
# ~/.sigil current so an active-passive FAILOVER (docs/architecture/HA-PROFILE.md
# §3) has a fresh, promotable copy. It automates the two syncs the HA profile
# ASSUMES but shipped nothing to perform (compose + statefulset both say the
# ~/.sigil mirror is "synced out-of-band"; §5 lists no tool for it):
#
#   seed   — the BULK, crash-consistent transfer, via the EXISTING signed
#            backup-as-state-transfer: `sigil restore` of a `sigil backup`
#            (apps/sigil/sigil/backup.py create_backup/restore_backup). ONE
#            verified, owner-signed archive → a fresh mirror home.
#   delta  — the ONGOING catch-up, via an rsync snapshot of the active's ~/.sigil
#            into the mirror home. Cheap, frequent, best-effort.
#
# ── THE LOAD-BEARING INVARIANT: THE PASSIVE IS READ-ONLY ─────────────────────
# This script NEVER runs `sigil serve`, `sigil sign`, `sigil consolidate`, or
# `sigil checkpoint`, and it MUST NOT turn the passive into a second writer. Two
# live writers = two owner-signed heads at one entry_count = a DETECTABLE FORK,
# not scale (HA-PROFILE.md §2). So BEFORE any sync it REFUSES (exit 2) if a
# sovereign WRITER is active on THIS host, and it refuses to sync onto a live
# writer's SIGIL_HOME. `sigil restore` transfers STATE (verify-before-write,
# atomic swap); it does not advance or sign the head.
#
# Promotion of the mirror to a live writer is a SEPARATE, GATED step — NEVER this
# script — via the witnessed-floor interlock (HA-PROFILE.md §3.2):
#     sigil floor promote-passive --witnessed /retained/off-box/checkpoint.witnessed.json
#     # (or: python3 tools/ha/spine_failover_guard.py --witnessed <...>)
#
# ── RUN IT ON THE PASSIVE ────────────────────────────────────────────────────
#   SIGIL_BACKUP_PASSPHRASE=… VIGIL_SEED_BACKUP=/transport/seed.sglbk \
#       tools/ha/mirror-sync.sh seed          # one-time BULK seed
#   VIGIL_ACTIVE_SIGIL=user@active:~/.sigil/ \
#       tools/ha/mirror-sync.sh delta         # repeated catch-up (the systemd default)
#
# The seed backup (`sigil backup /transport/seed.sglbk`, run ON THE ACTIVE) is
# transported here out-of-band (the vigil-backup-push transport, a removable
# disk, scp…). Only CIPHERTEXT + the passphrase (never on argv) restore it.
#
# Env:
#   VIGIL_MIRROR_HOME    the passive's mirror dir      (default: ~/.sigil-mirror)
#   VIGIL_ACTIVE_SIGIL   rsync SOURCE for `delta`      (e.g. user@active:~/.sigil/ or a local mount)
#   VIGIL_SEED_BACKUP    a `sigil backup` file for `seed`
#   SIGIL_BACKUP_PASSPHRASE  restore passphrase (sigil reads it from the ENV; NEVER on argv)
#   SIGIL_CMD            sovereign CLI                 (default: sigil; e.g. ~/vigil/.venv-sovereign/bin/sigil)
#   SIGIL_HOME           the LIVE writer home to protect (default: ~/.sigil) — the mirror MUST differ
#   VIGIL_WRITER_UNIT    optional systemd --user unit whose active state ALSO means "this host is a writer"
#
# Exit 0 = mirror synced (still READ-ONLY). Exit 2 = REFUSED (a writer is active / misconfig).
set -euo pipefail

MODE="${1:-delta}"
SIGIL_CMD="${SIGIL_CMD:-sigil}"
LIVE_SIGIL_HOME="${SIGIL_HOME:-$HOME/.sigil}"
MIRROR_HOME="${VIGIL_MIRROR_HOME:-$HOME/.sigil-mirror}"
SENTINEL="MIRROR-READONLY"

log() { echo "mirror-sync: $*"; }
die() { echo "mirror-sync: $*" >&2; exit 2; }

# realpath that tolerates a not-yet-existing target (compare intended paths, not just literals).
_abs() { python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$1" 2>/dev/null || echo "$1"; }

# The read-only INVARIANT gate. Runs before ANY sync; fails closed.
assert_passive_readonly() {
  # (1) NEVER run where a sovereign writer (`sigil serve`) is live — that host is an ACTIVE, not a passive.
  #     Syncing there would either clobber the live writer or seed a second writer (a fork; HA-PROFILE.md §2).
  #     Match the `sigil serve` DAEMON specifically (literal "sigil serve" + a following space or EOL) — NOT the
  #     read-only `sigil.mcp.server` or other transient sigil subcommands, which a broad `sigil.*serve` would
  #     falsely trip on.
  if pgrep -f 'sigil serve( |$)' >/dev/null 2>&1; then
    die "REFUSING — a 'sigil serve' writer is running on this host. A passive must never sync (a second writer is a fork, HA-PROFILE.md §2). Fence/stop the writer first."
  fi
  # (2) optional: a named writer systemd --user unit being active also means "this is a writer".
  if [ -n "${VIGIL_WRITER_UNIT:-}" ] && systemctl --user is-active --quiet "$VIGIL_WRITER_UNIT" 2>/dev/null; then
    die "REFUSING — writer unit '$VIGIL_WRITER_UNIT' is active on this host; it is not a passive."
  fi
  # (3) NEVER sync onto the live writer's SIGIL_HOME. The mirror MUST be a separate dir.
  if [ "$(_abs "$MIRROR_HOME")" = "$(_abs "$LIVE_SIGIL_HOME")" ]; then
    die "REFUSING — VIGIL_MIRROR_HOME ($MIRROR_HOME) resolves to the live SIGIL_HOME ($LIVE_SIGIL_HOME). The mirror MUST be a SEPARATE dir; syncing onto the live home risks a second writer / clobber."
  fi
}

# Label the mirror read-only so its nature is self-describing on disk (the passive also consumes it :ro —
# see infra/ha/docker-compose.ha.yml `sovereign-passive`).
label_readonly() {
  mkdir -p "$MIRROR_HOME"
  cat > "$MIRROR_HOME/$SENTINEL" <<EOF
VIGIL PASSIVE MIRROR — READ-ONLY. Do not write.
This is an out-of-band mirror of a sovereign ~/.sigil. It is NOT a live writer.
NEVER run 'sigil serve' / 'sign' / 'consolidate' / 'checkpoint' against this dir.
Promote to a writer ONLY via the gated witnessed-floor interlock (HA-PROFILE.md §3.2):
  sigil floor promote-passive --witnessed /retained/off-box/checkpoint.witnessed.json
Last synced (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)  mode: ${MODE}
EOF
}

do_seed() {
  [ -n "${VIGIL_SEED_BACKUP:-}" ] || die "seed: set VIGIL_SEED_BACKUP to a 'sigil backup' file transported from the active."
  [ -f "$VIGIL_SEED_BACKUP" ] || die "seed: VIGIL_SEED_BACKUP '$VIGIL_SEED_BACKUP' not found."
  [ -n "${SIGIL_BACKUP_PASSPHRASE:-}" ] || die "seed: SIGIL_BACKUP_PASSPHRASE required (sigil reads it from the env; never on argv)."
  command -v "${SIGIL_CMD%% *}" >/dev/null 2>&1 || die "seed: sovereign CLI '$SIGIL_CMD' not found (set SIGIL_CMD to .venv-sovereign/bin/sigil)."
  log "seed: restoring signed backup → $MIRROR_HOME (verify-before-write, atomic swap; STATE transfer, NOT a writer)"
  # `sigil restore <src> <home>` re-verifies the chain + signatures BEFORE writing; --force replaces a prior mirror.
  local force=()
  if [ -e "$MIRROR_HOME" ] && [ -n "$(ls -A "$MIRROR_HOME" 2>/dev/null || true)" ]; then force=(--force); fi
  $SIGIL_CMD restore "$VIGIL_SEED_BACKUP" "$MIRROR_HOME" "${force[@]}"
}

do_delta() {
  [ -n "${VIGIL_ACTIVE_SIGIL:-}" ] || die "delta: set VIGIL_ACTIVE_SIGIL to the active's ~/.sigil rsync source (user@host:~/.sigil/ or a local mount)."
  command -v rsync >/dev/null 2>&1 || die "delta: rsync not found."
  mkdir -p "$MIRROR_HOME"
  log "delta: rsync ${VIGIL_ACTIVE_SIGIL} → $MIRROR_HOME (file copy ONLY; never runs the writer)"
  # -a preserve; --delete keep the mirror faithful; NEVER delete our read-only sentinel.
  # A LIVE source can yield a TORN read; that is SAFE — the failover guard re-authenticates the head and the
  # floor interlock refuses a torn/stale/forked head (HA-PROFILE.md §3.2), so a bad delta only fails PROMOTION,
  # never activates a bad head. The signed-backup `seed` is the crash-consistent bulk.
  rsync -a --delete --exclude "$SENTINEL" -- "$VIGIL_ACTIVE_SIGIL" "$MIRROR_HOME/"
}

assert_passive_readonly
case "$MODE" in
  seed)  do_seed ;;
  delta) do_delta ;;
  *)     die "unknown mode '$MODE' (use: seed | delta)" ;;
esac
label_readonly
log "OK — mirror at $MIRROR_HOME is READ-ONLY. Promote ONLY via: sigil floor promote-passive --witnessed <off-box checkpoint>"
