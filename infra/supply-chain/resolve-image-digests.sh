#!/usr/bin/env bash
# A14 — re-resolve every pinned container base image against its registry and report drift.
#
# Thin wrapper over infra/supply-chain/image_pins.py so the one-line hint in each Dockerfile
# stays copy-pasteable. Stdlib Python only; no curl/jq needed.
#
#   bash infra/supply-chain/resolve-image-digests.sh            # drift report (advisory)
#   bash infra/supply-chain/resolve-image-digests.sh --check    # offline: are all images pinned?
#
# Drift is INFORMATIONAL. A tag moving upstream is not a defect in whatever change you are
# making; re-pin deliberately, after reading the upstream changelog. See docs/SUPPLY-CHAIN.md.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ "${1:-}" == "--check" ]]; then
    exec python3 "${REPO_ROOT}/infra/supply-chain/image_pins.py" --root "${REPO_ROOT}" --check
fi
exec python3 "${REPO_ROOT}/infra/supply-chain/image_pins.py" --root "${REPO_ROOT}" --drift "$@"
