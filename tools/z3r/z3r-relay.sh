#!/usr/bin/env bash
# AEGIS AS-26 (OPS-1) — the Z3R KEYLESS relay (spec §4.1 zone Z3R, §5, R3, B-1).
# =============================================================================
# Z3 moves files with a PINNED rsync client, REGULAR FILES ONLY, into FIXED landing dirs. It initiates
# every transfer (B-1: Z2 never connects to Z3). It holds NOTHING (R3): it never reads the owner vault.
#
#   pull   reports: remote outbound dir  ->  fixed landing dir  (then the drain picks them up)
#   push   grants/leases/releases/overrides: local staging dir  ->  read-only per-tenant dir on the unit
#
# Before a single byte moves, this wrapper asks the Python guard
# (integration/vigil_integration/aegis_relay_guard.py) to:
#   * refuse a vault/forbidden SOURCE (relay EACCES-on-vault posture),
#   * refuse an UNAUTHENTICATED transport (ssh with a pinned known_hosts + identity only),
#   * validate the PINNED rsync flag set (--no-links present; link/-a/-e forbidden),
#   * refuse an rsync OLDER than 3.2.5 (fail-closed), because hostile file NAME containment is a
#     RECEIVER-SIDE job that pre-3.2.5 rsync does not do.
# TWO distinct threats, TWO distinct controls (they are not the same):
#   * a hostile SYMLINK in the set is handled by --no-links (symlinks skipped, never followed), plus
#     --safe-links as belt-and-braces;
#   * a hostile file NAME (path-traversal, ../../x) is handled by rsync >= 3.2.5's client-side
#     received-name sanitization (the version gate below, fail-closed) and the fixed landing dir.
#   --no-links alone does NOT make a hostile NAME harmless.
#
# No long-lived key is minted here. The transport identity is an ssh key the operator provisions on the
# relay host; the relay role (30-ops-relay-paging-drift.cfn.yaml) grants only heartbeat/log writes and
# explicitly DENIES kms:Decrypt / secretsmanager:GetSecretValue.
#
#   Z3R_RSYNC            pinned rsync binary           (default: /usr/bin/rsync)
#   Z3R_PY               python for the guard          (default: python3)
#   Z3R_KNOWN_HOSTS      pinned ssh known_hosts file   (required for a remote transport)
#   Z3R_IDENTITY         ssh identity (key) file       (required for a remote transport)
#   Z3R_LANDING_DIR      fixed landing dir for `pull`  (default: /srv/aegis/landing/reports)
#   Z3R_TENANT_DIR       read-only per-tenant dir root for `push` (default: /srv/aegis/authority)
#
# Usage:
#   Z3R_KNOWN_HOSTS=/etc/vigil/known_hosts Z3R_IDENTITY=/etc/vigil/relay_id \
#     tools/z3r/z3r-relay.sh pull  user@report-host:/srv/aegis/outbound/reports/
#   tools/z3r/z3r-relay.sh push  /srv/aegis/stage/grants/tenant-a  user@unit:/srv/aegis/authority/tenant-a
#
# Exit 0 = transfer ran (or dry-run validated). Exit 2 = REFUSED by a guard / misconfig.
set -euo pipefail

Z3R_RSYNC="${Z3R_RSYNC:-/usr/bin/rsync}"
Z3R_PY="${Z3R_PY:-python3}"
Z3R_LANDING_DIR="${Z3R_LANDING_DIR:-/srv/aegis/landing/reports}"
Z3R_TENANT_DIR="${Z3R_TENANT_DIR:-/srv/aegis/authority}"
Z3R_KNOWN_HOSTS="${Z3R_KNOWN_HOSTS:-}"
Z3R_IDENTITY="${Z3R_IDENTITY:-}"
# Dry-run: validate the guards + print the pinned rsync argv, but do not transfer. The offline tests and
# the aegis-infra advisory job run in this mode (no live rsync/network needed).
Z3R_DRY_RUN="${Z3R_DRY_RUN:-0}"

# The pinned rsync flag set. --no-links skips symlinks (never follows them); --safe-links is belt-and-
# braces for the same threat. Hostile NAME containment is the rsync >= 3.2.5 version gate, not these flags.
PINNED_FLAGS=(--no-links --safe-links --recursive --times --prune-empty-dirs --chmod=F0640,D0750)

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." >/dev/null 2>&1 && pwd -P)"

log()  { printf 'z3r-relay: %s\n' "$*"; }
die()  { printf 'z3r-relay: %s\n' "$*" >&2; exit 2; }

guard() {
  # Run the Python guard CLI with the integration package on PYTHONPATH. A non-zero exit is a REFUSAL.
  PYTHONPATH="${REPO_ROOT}/integration${PYTHONPATH:+:${PYTHONPATH}}" \
    "${Z3R_PY}" -m vigil_integration.aegis_relay_guard "$@"
}

# The remote side of a transport spec, '' for a local path. Mirrors rsync's OWN rule: a spec is REMOTE
# whenever a ':' appears BEFORE the first '/' (so `host:relpath`, `1.2.3.4:reports`, `unit:authority/x` and
# `user@host:/abs` are all remote), EXCEPT a leading-'/' path (always local) and the daemon forms
# (`host::module`, `rsync://...`) which are returned whole so the guard refuses them. The earlier classifier
# only matched `*@*:*`/`*:/*`/`*:[0-9]*`, so a bare `host:relpath` fell through to LOCAL — skipping the
# transport guard AND the pinned `-e ssh` options (TOFU over the ambient ssh config). This is that fix.
transport_of() {
  local spec="$1" pre
  case "${spec}" in
    *"::"*)    printf '%s' "${spec}"; return ;;          # rsync daemon module (the guard refuses it)
    rsync://*) printf '%s' "${spec}"; return ;;          # rsync daemon URL (the guard refuses it)
  esac
  [ "${spec:0:1}" = "/" ] && { printf ''; return; }      # absolute path -> always local
  pre="${spec%%/*}"                                       # the segment before the first '/'
  if [ "${pre}" != "${pre%%:*}" ]; then                  # a ':' appears before the first '/': remote
    printf '%s' "${spec%%:*}"                             # emit the host (everything before the ':')
  else
    printf ''                                             # no ':' before the first '/': local path
  fi
}

check_transport() {
  local spec="$1" host
  host="$(transport_of "${spec}")"
  [ -z "${host}" ] && return 0                          # local path: no transport to authenticate
  case "${spec}" in
    rsync://*|*"::"*)
      guard check-transport --spec "${spec}" ;;         # daemon forms: the guard refuses them
    *)
      [ -n "${Z3R_KNOWN_HOSTS}" ] || die "set Z3R_KNOWN_HOSTS for a remote transport"
      [ -n "${Z3R_IDENTITY}" ]    || die "set Z3R_IDENTITY for a remote transport"
      guard check-transport --spec "${spec}" --strict-host-key-checking \
            --known-hosts "${Z3R_KNOWN_HOSTS}" --identity "${Z3R_IDENTITY}" ;;
  esac
}

run_rsync() {
  local src="$1" dst="$2"
  local -a flags=("${PINNED_FLAGS[@]}")
  # Validate the pinned flag set through the guard before invoking rsync.
  local joined
  joined="$(IFS=,; printf '%s' "${flags[*]}")"
  guard check-rsync-flags --flags="${joined}" >/dev/null
  local -a sshopt=()
  # Pin the ssh transport whenever EITHER side is remote (checked separately — concatenating src+dst would
  # miss a local-source -> remote-dest push, since the leading '/' would read as local).
  if [ -n "$(transport_of "${src}")" ] || [ -n "$(transport_of "${dst}")" ]; then
    sshopt=(-e "ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=${Z3R_KNOWN_HOSTS} -i ${Z3R_IDENTITY}")
  fi
  if [ "${Z3R_DRY_RUN}" = "1" ]; then
    # Validation-only: no live rsync/network needed (the advisory job + offline tests run in this mode).
    log "DRY-RUN rsync argv: ${Z3R_RSYNC} ${flags[*]} ${sshopt[*]:-} ${src} ${dst}"
    return 0
  fi
  [ -x "${Z3R_RSYNC}" ] || die "pinned rsync not found/executable: ${Z3R_RSYNC}"
  # FAIL CLOSED below rsync 3.2.5 — older rsync does not sanitize sender-chosen file NAMES (hostile-name
  # containment). The guard refuses an old/unparseable version string.
  local ver_line
  ver_line="$("${Z3R_RSYNC}" --version 2>/dev/null | head -1 || true)"
  guard check-rsync-version --line "${ver_line}" >/dev/null
  "${Z3R_RSYNC}" "${flags[@]}" "${sshopt[@]}" -- "${src}" "${dst}"
}

cmd_pull() {
  local src="${1:-}"
  [ -n "${src}" ] || die "usage: z3r-relay.sh pull <remote-source>"
  guard check-source --source "${src}" >/dev/null       # refuse a vault/forbidden source
  guard check-source --source "${Z3R_LANDING_DIR}" >/dev/null
  check_transport "${src}"
  mkdir -p -- "${Z3R_LANDING_DIR}"
  log "pull ${src} -> ${Z3R_LANDING_DIR} (keyless; --no-links; fixed landing dir)"
  run_rsync "${src}" "${Z3R_LANDING_DIR}/"
}

cmd_push() {
  local src="${1:-}" dst="${2:-}"
  [ -n "${src}" ] && [ -n "${dst}" ] || die "usage: z3r-relay.sh push <local-source> <per-tenant-dst>"
  guard check-source --source "${src}" >/dev/null        # never push the vault
  check_transport "${dst}"
  case "${dst}" in
    *"${Z3R_TENANT_DIR#/}"*|*:*"${Z3R_TENANT_DIR#/}"*) : ;;
    *) log "note: destination outside the configured per-tenant root ${Z3R_TENANT_DIR}" ;;
  esac
  log "push ${src} -> ${dst} (grants/leases/releases; read-only per-tenant dir)"
  run_rsync "${src}" "${dst}"
}

main() {
  local mode="${1:-}"
  shift || true
  case "${mode}" in
    pull) cmd_pull "$@" ;;
    push) cmd_push "$@" ;;
    *)    die "usage: z3r-relay.sh {pull|push} ..." ;;
  esac
}

main "$@"
