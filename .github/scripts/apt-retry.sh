#!/usr/bin/env bash
# Bounded retry-with-backoff around `apt-get update && apt-get install` (issue #556), with a per-attempt
# HANG timeout (the durable fix for the recurring P5/P6 cancellations), and a signature-checked HTTPS
# MIRROR FALLBACK for when the runner cannot reach the default Ubuntu mirrors.
#
# A transient apt mirror / network blip on a GitHub runner used to fail the whole check on the first try.
# Wrapping the install in a few backed-off retries lets it self-heal WITHIN the job timeout instead. Shared
# by every job that installs Ubuntu packages, so the retry and fallback logic lives in ONE place rather
# than being copy-pasted into each.
#
# WHY THE `timeout` WRAPPERS: retry-on-failure alone does NOT help when `apt-get update` HANGS on a stuck
# mirror connection — it never returns, so the loop never fires and the whole job runs to its timeout and is
# CANCELLED (observed: `apt-get update` stuck ~30m -> "gateway egress gate (P6)" cancelled at its 30m limit,
# and the same class cancelled the two-env boundary job). `timeout` converts a hang into a non-zero exit this
# loop retries; the Acquire::*::Timeout options bound each connection so a single dead mirror fails fast.
#
# WHY THE MIRROR FALLBACK: on 2026-11-11 GitHub-hosted runners could not resolve the Ubuntu mirror hostnames
# (azure.archive.ubuntu.com, archive.ubuntu.com, security.ubuntu.com) for hours while every other host
# resolved, so every apt-installing job failed before running a single test, and retries could not help.
#   * DETECT FAST: before using the default mirrors, resolve the hosts named in the runner's Ubuntu apt
#     sources (a few seconds each). If any cannot be resolved, try the fallback FIRST instead of burning the
#     hang ceilings against a mirror that cannot answer. If the fallback cannot install, the default mirrors
#     are still tried: a partial outage, or a resolver slower than the probe timeout, can leave them working.
#   * FALL BACK: try each mirror in APT_RETRY_FALLBACK_MIRRORS in order, from an apt source list written to
#     a private directory. /etc/apt is left untouched; the fallback's indexes are ADDED to /var/lib/apt/lists
#     (APT::Get::List-Cleanup=0), so the runner's own package lists survive for any later apt step.
#   * INTEGRITY IS UNCHANGED, AND PINNED: a fallback source is HTTPS-only and carries
#     `Signed-By: <the Ubuntu archive keyring>`, so apt accepts its Release files only if they are signed by
#     the Ubuntu archive key — stricter than the default sources, which accept any key apt trusts. This
#     script never passes allow-unauthenticated, allow-insecure, `Trusted: yes` or any other option that
#     weakens apt's checks, and never adds a key. A mirror can make an install fail or serve an older signed
#     index; it cannot change what a package contains. The -security index is held to a maximum age
#     (APT_RETRY_SECURITY_MAX_AGE, Valid-Until-Max), so "older" is bounded where it matters; the release and
#     -updates pockets are not (the release pocket's index is dated release day by design). If no mirror
#     verifies, the step fails (fail closed).
#
# Usage:  apt-retry.sh <package> [<package> ...]
#
# Order: if a default mirror host does not resolve, one attempt per fallback mirror first, then the default
# mirrors; otherwise the default mirrors first, then the fallback. Default mirrors: up to
# APT_RETRY_DEFAULT_ATTEMPTS attempts (default 2), backing off 5s / 15s. Each attempt is itself bounded
# (update <= _UPDATE_TIMEOUT, install <= _INSTALL_TIMEOUT), so a hang is killed at the first ceiling.
# Exits non-zero only after the default mirrors AND every usable fallback mirror have failed, so a genuine,
# persistent breakage still turns the gate RED.
#
# Test seams (all optional): APT_RETRY_UPDATE_TIMEOUT, APT_RETRY_INSTALL_TIMEOUT, APT_RETRY_PROBE_TIMEOUT,
# APT_RETRY_DEFAULT_ATTEMPTS, APT_RETRY_FALLBACK_MIRRORS (space-separated; set it empty to disable the
# fallback), APT_RETRY_SOURCES_FILES (the files whose hosts are probed), APT_RETRY_UBUNTU_KEYRING,
# APT_RETRY_CODENAME, APT_RETRY_SECURITY_MAX_AGE.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "::error::apt-retry.sh needs at least one package name" >&2
  exit 2
fi
pkgs=("$@")

# Per-attempt hang ceilings (seconds). Overridable for tests. Kept well under the smallest job timeout.
_UPDATE_TIMEOUT="${APT_RETRY_UPDATE_TIMEOUT:-180}"
_INSTALL_TIMEOUT="${APT_RETRY_INSTALL_TIMEOUT:-300}"
_PROBE_TIMEOUT="${APT_RETRY_PROBE_TIMEOUT:-5}"
_DEFAULT_ATTEMPTS="${APT_RETRY_DEFAULT_ATTEMPTS:-2}"
# `-` not `:-`: an explicitly EMPTY value disables the fallback (the tests rely on this).
# The oldest -security index a fallback mirror may serve (seconds; default 14 days). Ubuntu's InRelease
# files carry no Valid-Until, so without this a mirror could serve an old, validly-signed security index
# indefinitely (a freeze). apt enforces it AFTER verifying the signature, so the bound cannot be forged.
# Ubuntu republishes -security for a supported release several times a week; 14 days leaves room for a
# holiday lull without failing a healthy mirror closed.
_SECURITY_MAX_AGE_DEFAULT=1209600
_SECURITY_MAX_AGE="${APT_RETRY_SECURITY_MAX_AGE:-${_SECURITY_MAX_AGE_DEFAULT}}"
case "$_SECURITY_MAX_AGE" in ''|*[!0-9]*) _SECURITY_MAX_AGE="${_SECURITY_MAX_AGE_DEFAULT}" ;; esac
# Normalise leading zeros (apt reads "00" as 0, which means NO bound) and cap the width so the arithmetic
# cannot overflow; anything that is not a positive number of seconds falls back to the default.
if [ "${#_SECURITY_MAX_AGE}" -gt 9 ] || [ "$((10#${_SECURITY_MAX_AGE}))" -le 0 ]; then
  _SECURITY_MAX_AGE="${_SECURITY_MAX_AGE_DEFAULT}"
else
  _SECURITY_MAX_AGE="$((10#${_SECURITY_MAX_AGE}))"
fi
_FALLBACK_MIRRORS="${APT_RETRY_FALLBACK_MIRRORS-https://mirrors.edge.kernel.org/ubuntu/ https://mirror.us.leaseweb.net/ubuntu/ https://mirrors.mit.edu/ubuntu/}"
_SOURCES_FILES="${APT_RETRY_SOURCES_FILES:-/etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list}"
# The distro-owned Ubuntu archive keyring (package ubuntu-keyring). Newer releases may ship it as .pgp, so
# take the first that exists; an explicit APT_RETRY_UBUNTU_KEYRING is used as-is (tests point it elsewhere).
if [ -n "${APT_RETRY_UBUNTU_KEYRING:-}" ]; then
  _KEYRING="${APT_RETRY_UBUNTU_KEYRING}"
else
  _KEYRING=/usr/share/keyrings/ubuntu-archive-keyring.gpg
  for _k in /usr/share/keyrings/ubuntu-archive-keyring.gpg /usr/share/keyrings/ubuntu-archive-keyring.pgp; do
    if [ -s "$_k" ]; then _KEYRING="$_k"; break; fi
  done
fi

# The fallback's private source-list directory, removed on exit whatever the outcome.
_FALLBACK_DIR=""
trap 'if [ -n "${_FALLBACK_DIR}" ]; then rm -rf "${_FALLBACK_DIR}"; fi' EXIT

# Connection-level bounds so a single dead mirror fails fast instead of stalling the whole operation.
_apt_opts=(-o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30
           -o Acquire::ForceIPv4=true)

backoffs=(5 15 45)

# One bounded update + install. Extra apt options (the fallback's source list) go in "$@".
_attempt() {
  local rc=0
  sudo timeout "${_UPDATE_TIMEOUT}" apt-get update "${_apt_opts[@]}" "$@" \
    && sudo timeout "${_INSTALL_TIMEOUT}" apt-get install -y "${_apt_opts[@]}" "$@" "${pkgs[@]}" \
    || rc=$?
  return "$rc"
}

_resolves() {
  timeout "${_PROBE_TIMEOUT}" getent hosts "$1" >/dev/null 2>&1
}

# The non-comment lines of the given files (apt ignores lines whose first non-blank character is `#`).
_source_lines() {
  local f
  for f in "$@"; do
    [ -r "$f" ] || continue
    grep -vE '^[[:space:]]*#' "$f" 2>/dev/null || true
  done
}

# The hosts named by the runner's Ubuntu apt sources (deb822 `URIs:` lines and one-line `deb` entries).
#   * COMMENTS ARE NOT SOURCES. Ubuntu's stock ubuntu.sources opens with a comment that carries a URL
#     (`# See http://help.ubuntu.com/community/UpgradeNotes ...`); probing it would decide the fallback on a
#     host apt never contacts.
#   * `mirror+file:<path>` IS FOLLOWED. The GitHub runner image points its Ubuntu sources at
#     `mirror+file:/etc/apt/apt-mirrors.txt`, a file of mirror URIs; the hosts apt really uses are in THAT
#     file, so it is read too (one level, which is all apt itself supports).
_default_hosts() {
  local lines lists
  # shellcheck disable=SC2086  # _SOURCES_FILES is a space-separated list by contract
  lines="$(_source_lines ${_SOURCES_FILES})"
  lists="$( { printf '%s\n' "$lines" | grep -oE 'mirror\+file:(//)?/[^[:space:]]+' || true; } \
              | sed -E 's#^mirror\+file:(//)?##' | sort -u)"
  # shellcheck disable=SC2086  # one path per word; the image's mirror-list paths contain no spaces
  { printf '%s\n' "$lines"; _source_lines ${lists}; } \
    | { grep -oE '(https?|ftp)://[^/[:space:]]+' || true; } \
    | sed -E 's#^[a-z]+://##; s#^[^@]*@##; s#:[0-9]+$##' | sort -u
}

# Prints the default mirror hosts that do NOT resolve (empty output: every one resolves, or none is named).
_unresolved_default_hosts() {
  local h
  for h in $(_default_hosts); do
    _resolves "$h" || printf '%s ' "$h"
  done
}

_codename() {
  if [ -n "${APT_RETRY_CODENAME:-}" ]; then
    printf '%s' "${APT_RETRY_CODENAME}"
    return
  fi
  # shellcheck disable=SC1091
  ( . /etc/os-release 2>/dev/null && printf '%s' "${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}" )
}

# Try every fallback mirror once. Returns 0 on the first that installs, 1 when none can (it never exits, so
# the caller can still try the default mirrors). It is always called as an `if` condition, where errexit is
# off, so every step that could fail is checked explicitly.
_try_fallback() {
  local why="$1" codename dir m
  if [ -z "${_FALLBACK_MIRRORS// /}" ]; then
    echo "::warning::apt fallback unavailable (${why}): no fallback mirror is configured" >&2
    return 1
  fi
  codename="$(_codename || true)"
  # [[ =~ ]] tests the WHOLE string: a value with a newline (e.g. "resolute<LF>Trusted: yes") cannot pass,
  # so nothing can be smuggled into the generated source file.
  if ! [[ "$codename" =~ ^[a-z][a-z0-9-]*$ ]]; then
    echo "::warning::apt fallback refused: cannot determine a valid Ubuntu codename (got '${codename}')" >&2
    return 1
  fi
  if ! [[ "$_KEYRING" =~ ^/[A-Za-z0-9._/-]+$ ]] || [ ! -r "${_KEYRING}" ] || [ ! -s "${_KEYRING}" ]; then
    echo "::warning::apt fallback refused: the Ubuntu archive keyring '${_KEYRING}' is missing or not a plain absolute path, so a fallback mirror's signatures could not be checked" >&2
    return 1
  fi
  dir="$(mktemp -d)" || return 1
  [ -n "$dir" ] && [ -d "$dir" ] || return 1
  _FALLBACK_DIR="$dir"
  for m in ${_FALLBACK_MIRRORS}; do
    case "$m" in
      https://*/) ;;
      *)
        echo "::warning::apt fallback: refusing mirror '${m}' (fallback mirrors must be https:// and end in /)" >&2
        continue ;;
    esac
    # No DNS pre-check here: a resolver slower than the probe timeout must not skip a working mirror. The
    # bounded apt attempt decides, and an unresolvable mirror fails it within seconds.
    # Replace (not append) the list: only this mirror is in play for this attempt.
    rm -f "${dir}"/*.sources
    if ! cat > "${dir}/vigil-apt-fallback.sources" <<EOF
Types: deb
URIs: ${m}
Suites: ${codename} ${codename}-updates
Components: main restricted universe multiverse
Signed-By: ${_KEYRING}

Types: deb
URIs: ${m}
Suites: ${codename}-security
Components: main restricted universe multiverse
Signed-By: ${_KEYRING}
Valid-Until-Max: ${_SECURITY_MAX_AGE}
EOF
    then
      echo "::warning::apt fallback: could not write the source list in ${dir}" >&2
      return 1
    fi
    chmod 0644 "${dir}/vigil-apt-fallback.sources" || return 1
    echo "::notice::apt fallback (${why}): installing ${pkgs[*]} from ${m}; Release signatures are checked against ${_KEYRING}" >&2
    if _attempt -o "Dir::Etc::SourceList=/dev/null" -o "Dir::Etc::SourceParts=${dir}" \
                -o "APT::Get::List-Cleanup=0"; then
      echo "apt fallback: installed ${pkgs[*]} from ${m}" >&2
      return 0
    fi
    echo "apt fallback: mirror ${m} failed; trying the next one" >&2
  done
  echo "::warning::apt fallback (${why}): every fallback mirror failed or was refused: ${_FALLBACK_MIRRORS}" >&2
  return 1
}

case "$_DEFAULT_ATTEMPTS" in
  ''|*[!0-9]*) _DEFAULT_ATTEMPTS=2 ;;
esac
fallback_tried=0
unresolved="$(_unresolved_default_hosts || true)"
if [ -n "$unresolved" ]; then
  echo "::warning::apt: this runner cannot resolve the default Ubuntu mirror host(s): ${unresolved}— trying the fallback mirrors first" >&2
  fallback_tried=1
  if _try_fallback "default mirror host(s) do not resolve: ${unresolved% }"; then
    exit 0
  fi
  echo "::warning::apt: the fallback mirrors did not install ${pkgs[*]}; trying the default mirrors anyway (a partial outage or a slow resolver can still leave them working)" >&2
fi
rc=0
attempt=1
while [ "$attempt" -le "$_DEFAULT_ATTEMPTS" ]; do
  rc=0
  _attempt || rc=$?
  if [ "$rc" -eq 0 ]; then
    exit 0
  fi
  if [ "$attempt" -ge "$_DEFAULT_ATTEMPTS" ]; then
    break
  fi
  delay="${backoffs[$(( attempt - 1 ))]:-45}"
  echo "apt-get attempt ${attempt}/${_DEFAULT_ATTEMPTS} on the default mirrors failed (rc=${rc}; 124=hang-timeout); retrying in ${delay}s..." >&2
  sleep "$delay"
  attempt=$(( attempt + 1 ))
done
if [ "$fallback_tried" -eq 0 ]; then
  echo "::warning::apt-get failed ${_DEFAULT_ATTEMPTS} time(s) on the default mirrors (last rc=${rc}; 124=hang-timeout) — trying the fallback mirrors" >&2
  if _try_fallback "default mirrors failed after ${_DEFAULT_ATTEMPTS} attempt(s), last rc=${rc}"; then
    exit 0
  fi
fi
echo "::error::apt-get failed installing: ${pkgs[*]} (default mirrors: ${_DEFAULT_ATTEMPTS} attempt(s), last rc=${rc}, 124=hang-timeout; fallback mirrors: failed, refused or not configured)" >&2
exit 1
