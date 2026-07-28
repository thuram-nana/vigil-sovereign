#!/usr/bin/env bash
# =============================================================================
# knowledge/sync.sh — regenerate the committed knowledge artifacts, deterministically.
#
# NO network, NO API cost: it re-runs the S1 system-map generator so the committed
# knowledge/system-map/system-map.json is byte-identical to what screens.yaml + the
# unified UI's NAV/route() describe. Re-runnable; a clean tree after a run means the
# manifest was already current.
#
# This ONLY regenerates. Committing + pushing the knowledge/ folder is a SEPARATE,
# operator-invoked step (`vigil knowledge sync` then `vigil knowledge push`) — the
# outward-facing act is never automatic, and no agent tool runs git here.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."                       # repo root (knowledge/.. == repo root)

python3 tools/system-map/generate.py --write

echo "knowledge/sync.sh: regenerated knowledge/system-map/system-map.json"
