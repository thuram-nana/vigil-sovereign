#!/usr/bin/env bash
# Bounded retry-with-backoff around `apt-get update && apt-get install` (issue #556), with a per-attempt
# HANG timeout (the durable fix for the recurring P5/P6 cancellations).
#
# A transient apt mirror / network blip on a GitHub runner used to fail the whole check on the first try.
# Wrapping the install in a few backed-off retries lets it self-heal WITHIN the job timeout instead. Shared
# by the gateway (nftables) and integration (bubblewrap) jobs so the retry logic lives in ONE place rather
# than being copy-pasted into each.
#
# WHY THE `timeout` WRAPPERS: retry-on-failure alone does NOT help when `apt-get update` HANGS on a stuck
# mirror connection — it never returns, so the loop never fires and the whole job runs to its timeout and is
# CANCELLED (observed: `apt-get update` stuck ~30m -> "gateway egress gate (P6)" cancelled at its 30m limit,
# and the same class cancelled the two-env boundary job). `timeout` converts a hang into a non-zero exit this
# loop retries; the Acquire::*::Timeout options bound each connection so a single dead mirror fails fast.
#
# Usage:  apt-retry.sh <package> [<package> ...]
#
# Up to 4 attempts (1 initial + 3 retries), backing off 5s / 15s / 45s. Each attempt is itself bounded
# (update <= _UPDATE_TIMEOUT, install <= _INSTALL_TIMEOUT), so a HANG is killed at the first ceiling and
# retried (a single stuck mirror costs <= _UPDATE_TIMEOUT, not the whole job timeout). Exits non-zero only
# after the final attempt fails, so a genuine, persistent breakage still turns the gate RED.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "::error::apt-retry.sh needs at least one package name" >&2
  exit 2
fi

# Per-attempt hang ceilings (seconds). Overridable for tests. Kept well under the smallest job timeout.
_UPDATE_TIMEOUT="${APT_RETRY_UPDATE_TIMEOUT:-180}"
_INSTALL_TIMEOUT="${APT_RETRY_INSTALL_TIMEOUT:-300}"

# Connection-level bounds so a single dead mirror fails fast instead of stalling the whole operation.
_apt_opts=(-o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30
           -o Acquire::ForceIPv4=true)

backoffs=(5 15 45)
max=$(( ${#backoffs[@]} + 1 ))
attempt=1
while true; do
  rc=0
  sudo timeout "${_UPDATE_TIMEOUT}" apt-get update "${_apt_opts[@]}" \
    && sudo timeout "${_INSTALL_TIMEOUT}" apt-get install -y "${_apt_opts[@]}" "$@" \
    || rc=$?
  if [ "$rc" -eq 0 ]; then
    exit 0
  fi
  if [ "$attempt" -ge "$max" ]; then
    echo "::error::apt-get failed after ${max} attempts installing: $* (last rc=${rc}; rc=124 = a step hit its hang timeout)" >&2
    exit 1
  fi
  delay="${backoffs[$(( attempt - 1 ))]}"
  echo "apt-get attempt ${attempt}/${max} failed (rc=${rc}; 124=hang-timeout); retrying in ${delay}s..." >&2
  sleep "$delay"
  attempt=$(( attempt + 1 ))
done
