#!/usr/bin/env bash
# Bounded retry-with-backoff around `apt-get update && apt-get install` (issue #556).
#
# A transient apt mirror / network blip on a GitHub runner used to fail the whole check on the first try.
# Wrapping the install in a few backed-off retries lets it self-heal WITHIN the job timeout instead. Shared
# by the gateway (nftables) and integration (bubblewrap) jobs so the retry logic lives in ONE place rather
# than being copy-pasted into each.
#
# Usage:  apt-retry.sh <package> [<package> ...]
#
# Up to 4 attempts (1 initial + 3 retries), backing off 5s / 15s / 45s between them — worst-case ~65s of
# sleeps, comfortably inside every job's timeout. Exits non-zero (failing the step) only after the final
# attempt fails, so a genuine, persistent breakage still turns the gate RED.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "::error::apt-retry.sh needs at least one package name" >&2
  exit 2
fi

backoffs=(5 15 45)
max=$(( ${#backoffs[@]} + 1 ))
attempt=1
while true; do
  if sudo apt-get update && sudo apt-get install -y "$@"; then
    exit 0
  fi
  if [ "$attempt" -ge "$max" ]; then
    echo "::error::apt-get failed after ${max} attempts installing: $*" >&2
    exit 1
  fi
  delay="${backoffs[$(( attempt - 1 ))]}"
  echo "apt-get attempt ${attempt}/${max} failed; retrying in ${delay}s..." >&2
  sleep "$delay"
  attempt=$(( attempt + 1 ))
done
