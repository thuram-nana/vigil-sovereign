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
#     sources (a few seconds each). If any cannot be resolved, skip straight to the fallback instead of
#     burning the hang ceilings against a mirror that cannot answer.
#   * FALL BACK: try each mirror in APT_RETRY_FALLBACK_MIRRORS in order, from an apt source list written to
#     a private directory (the runner's own apt configuration is left untouched).
#   * INTEGRITY IS UNCHANGED, AND PINNED: a fallback source is HTTPS-only and carries
#     `Signed-By: <the Ubuntu archive keyring>`, so apt accepts its Release files only if they are signed by
#     the Ubuntu archive key — stricter than the default sources, which accept any key apt trusts. This
#     script never passes allow-unauthenticated, allow-insecure, `Trusted: yes` or any other option that
#     weakens apt's checks, and never adds a key. A mirror can make an install fail or serve an older signed
#     index; it cannot change what a package contains. If no mirror verifies, the step fails (fail closed).
#
# Usage:  apt-retry.sh <package> [<package> ...]
#
# Default mirrors: up to APT_RETRY_DEFAULT_ATTEMPTS attempts (default 2), backing off 5s / 15s. Then, or at
# once if the default mirror hosts do not resolve, one attempt per fallback mirror. Each attempt is itself
# bounded (update <= _UPDATE_TIMEOUT, install <= _INSTALL_TIMEOUT), so a hang is killed at the first ceiling.
# Exits non-zero only after the default mirrors and every fallback mirror have failed, so a genuine,
# persistent breakage still turns the gate RED.
#
# Test seams (all optional): APT_RETRY_UPDATE_TIMEOUT, APT_RETRY_INSTALL_TIMEOUT, APT_RETRY_PROBE_TIMEOUT,
# APT_RETRY_DEFAULT_ATTEMPTS, APT_RETRY_FALLBACK_MIRRORS (space-separated; set it empty to disable the
# fallback), APT_RETRY_SOURCES_FILES (the files whose hosts are probed), APT_RETRY_UBUNTU_KEYRING,
# APT_RETRY_CODENAME.
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

# The hosts named by the runner's Ubuntu apt sources (deb822 `URIs:` lines and one-line `deb` entries).
_default_hosts() {
  local f
  for f in ${_SOURCES_FILES}; do
    [ -r "$f" ] || continue
    grep -hoE '(https?|ftp)://[^/[:space:]]+' "$f" 2>/dev/null || true
  done | sed -E 's#^[a-z]+://##; s#^[^@]*@##; s#:[0-9]+$##' | sort -u
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

# Try every fallback mirror once; exits 0 on the first that installs, 1 when none does.
_fallback_or_fail() {
  local why="$1" codename dir m host
  if [ -z "${_FALLBACK_MIRRORS// /}" ]; then
    echo "::error::apt-get failed installing: ${pkgs[*]} (${why}; no fallback mirror is configured)" >&2
    exit 1
  fi
  codename="$(_codename)"
  if ! printf '%s' "$codename" | grep -qE '^[a-z][a-z0-9-]*$'; then
    echo "::error::apt fallback refused: cannot determine a valid Ubuntu codename (got '${codename}')" >&2
    exit 1
  fi
  if [ ! -r "${_KEYRING}" ] || [ ! -s "${_KEYRING}" ]; then
    echo "::error::apt fallback refused: the Ubuntu archive keyring ${_KEYRING} is missing, so a fallback mirror's signatures could not be checked" >&2
    exit 1
  fi
  dir="$(mktemp -d)"
  _FALLBACK_DIR="$dir"
  for m in ${_FALLBACK_MIRRORS}; do
    case "$m" in
      https://*/) ;;
      *)
        echo "::warning::apt fallback: refusing mirror '${m}' (fallback mirrors must be https:// and end in /)" >&2
        continue ;;
    esac
    host="${m#https://}"
    host="${host%%/*}"
    if ! _resolves "$host"; then
      echo "apt fallback: mirror host ${host} does not resolve either; skipping it" >&2
      continue
    fi
    # Replace (not append) the list: only this mirror is in play for this attempt.
    rm -f "${dir}"/*.sources
    cat > "${dir}/vigil-apt-fallback.sources" <<EOF
Types: deb
URIs: ${m}
Suites: ${codename} ${codename}-updates ${codename}-security
Components: main restricted universe multiverse
Signed-By: ${_KEYRING}
EOF
    chmod 0644 "${dir}/vigil-apt-fallback.sources"
    echo "::notice::apt fallback (${why}): installing ${pkgs[*]} from ${m}; Release signatures are checked against ${_KEYRING}" >&2
    if _attempt -o "Dir::Etc::SourceList=/dev/null" -o "Dir::Etc::SourceParts=${dir}"; then
      echo "apt fallback: installed ${pkgs[*]} from ${m}" >&2
      exit 0
    fi
    echo "apt fallback: mirror ${m} failed; trying the next one" >&2
  done
  echo "::error::apt-get failed installing: ${pkgs[*]} (${why}; every fallback mirror failed or was unreachable: ${_FALLBACK_MIRRORS}; rc=124 = a step hit its hang timeout)" >&2
  exit 1
}

case "$_DEFAULT_ATTEMPTS" in
  ''|*[!0-9]*) _DEFAULT_ATTEMPTS=2 ;;
esac
rc=0
attempt=1
while [ "$attempt" -le "$_DEFAULT_ATTEMPTS" ]; do
  unresolved="$(_unresolved_default_hosts)"
  if [ -n "$unresolved" ]; then
    echo "::warning::apt: this runner cannot resolve the default Ubuntu mirror host(s): ${unresolved}— switching to the fallback mirrors" >&2
    _fallback_or_fail "default mirror host(s) do not resolve: ${unresolved% }"
  fi
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
echo "::warning::apt-get failed ${_DEFAULT_ATTEMPTS} time(s) on the default mirrors (last rc=${rc}; 124=hang-timeout) — trying the fallback mirrors" >&2
_fallback_or_fail "default mirrors failed after ${_DEFAULT_ATTEMPTS} attempt(s), last rc=${rc}"
